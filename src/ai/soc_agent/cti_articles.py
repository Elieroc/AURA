"""CTI: extracting the IOCs of public security articles into MISP.

The MISP feeds (see cti.py) deliver ALREADY structured intelligence. Most of
what gets published is not: a BleepingComputer report, a The Hacker News article
or an RST Cloud post describes a campaign's infrastructure in prose, with the
indicators in the middle of the text, sometimes "defanged"
(hxxp://evil[.]com), sometimes in a table, sometimes in an appendix. No common
format, no API.

This module fills that gap in three stages, and the split is the important part:

  1. FETCHING (deterministic) — RSS or directory, then the article text.
  2. CANDIDATES (deterministic) — defanging plus regular expressions. Finds
     everything that LOOKS LIKE an IOC, without trying to judge.
  3. ARBITRATION (LLM) — decides which ones are indicators of the threat, and
     their role.

Why the LLM at the third stage, and not one more regex. A press article
constantly quotes perfectly legitimate domains: the outlet itself, its sources,
the vendor that published the report, the platforms mentioned, the victim, the
tools abused. A purely regular extraction therefore produces mostly false
indicators — and a false IOC costs more here than a missed one: it makes level 12
alerts fire on normal traffic, and if it ends up in autonomous remediation it
cuts off a healthy machine. Only reading the CONTEXT tells "evil-c2[.]com" from
"microsoft.com quoted as the victim", and that is precisely what the model can
do.

But the LLM is NOT a security boundary (see README): its output is therefore
re-checked by code, in this order —

  - LITERAL presence of every value among the candidates (anti-hallucination: an
    invented indicator is rejected, not discussed);
  - hard exclusions: private IPs, SOC infrastructure, our networks, the domains
    of the source outlets themselves;
  - MISP warninglists (`/warninglists/checkValue`), which know the domains and
    IPs never to treat as IOCs;
  - a cap on indicators per article.

The retained IOCs become a MISP EVENT, not a direct entry into the detection
cache: that is what gives them a consultable existence (link to the article,
malware family, correlation with the rest of the intelligence), and what makes
`cti.py` pick them up afterwards through the same path as every other feed. They
are tagged `aura:source:extracted`, which makes them match rule 100957 (level 12)
and not 100951/100952 (level 12-14): an automatic extraction from a press article
is not worth an IOC published by CERT-FR, and the ruleset must say so.

    python -m soc_agent.cti_articles                  # one pass over every source
    python -m soc_agent.cti_articles --bootstrap      # marks what exists as seen, without processing
    python -m soc_agent.cti_articles --source thehackernews --max 3
    python -m soc_agent.cti_articles --simulation     # extracts and prints, writes neither MISP nor database
    python -m soc_agent.cti_articles --url https://...  # one specific article, on demand
"""

from __future__ import annotations

import argparse
import html
import ipaddress
import json
import logging
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import psycopg
import requests
import urllib3

from . import config, cti, llm

log = logging.getLogger("cti_articles")

if not config.MISP_VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROMPTS = Path(__file__).parent / "prompts"
TIMEOUT = 60

# Confidence and tag live in cti.py, with the other two levels: cti.py is what
# reads this tag back to classify the IOC, so both must move together or not at
# all.
TAG_SOURCE = cti.TAG_EXTRACTION

# Cap on IOCs published for ONE article, overridable per source (`max_iocs` in
# the catalog). Past it we publish nothing and we say so: either the article is a
# blocklist dump, or the extraction went wrong, and an event with several
# thousand attributes pollutes MISP durably.
#
# 300 and not 60: measured on an "RST TI Report Digest", a single post carries
# 400 candidates most of which are real indicators — that is the very format of
# the source. A tight cap therefore rejected the richest article of the four
# sources, which is the opposite of the goal.
MAX_IOC_ARTICLE = 300

# Candidates submitted to the model per call, and output budget.
#
# A digest produces several hundred. Sending them in one block exhausts the
# budget and the call fails on `finish_reason=length` RETURNING NOTHING: the
# model is a reasoning one, and its reasoning is charged against the same budget
# as the answer (trap documented in llm.py). Measured on an RST Cloud digest of
# 403 candidates: 60 candidates / 3,000 tokens fails, 40 / 4,000 fails too.
#
# The overhead of the split is small because the system prompt and the article
# are IDENTICAL from one batch to the next: DeepSeek serves them from its prefix
# cache (50x cheaper, see LLM_COST_USD_PER_MTOKEN_IN_CACHE). What changes are the
# candidates, at the end of the prompt.
BATCH_CANDIDATES = int(os.environ.get("CTI_ARTICLES_BATCH", "20"))
MAX_TOKENS = int(os.environ.get("CTI_ARTICLES_MAX_TOKENS", "12000"))

# Last-resort guardrail on the number of calls per article. What exceeds it is
# dropped, but NEVER silently (see `arbitrate`): a silent cap would give the
# illusion of an article fully covered.
MAX_BATCHES = int(os.environ.get("CTI_ARTICLES_MAX_BATCHES", "16"))

# Volume of text sent to the model. Useful articles are 5 to 20 k characters;
# past that it is comments, navigation and related articles. Truncating bounds
# the cost without losing the "Indicators of Compromise" section, which is almost
# always at the end of the body but before the comments — hence keeping the
# BEGINNING and the END.
MAX_TEXT = 24000


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

def sources(catalogue: dict | None = None) -> list[dict]:
    cat = catalogue or cti.load_catalog()
    return [s for s in (cat.get("articles") or []) if s.get("active", True)]


def _http(url: str) -> requests.Response:
    # Explicit User-Agent: several outlets return 403 to a client without one,
    # and a lying agent would be a poor way to introduce oneself to sites we read
    # for free.
    response = requests.get(
        url, timeout=TIMEOUT,
        headers={"User-Agent": "AURA-SOC CTI collector (+threat intel, contact SOC)"})
    response.raise_for_status()
    return response


def rss_entries(source: dict, since: datetime) -> list[dict]:
    """Articles of an RSS/Atom feed, more recent than `since`.

    The full content is taken from the feed when it is there (Medium provides it
    in full): that many articles not to download again, and one less HTML page to
    clean.
    """
    root = ET.fromstring(_http(source["url"]).content)
    entries = []
    for item in root.findall(".//item") or root.findall(
            ".//{http://www.w3.org/2005/Atom}entry"):
        def text(*names):
            for name in names:
                el = item.find(name)
                if el is not None and el.text:
                    return el.text.strip()
            return ""

        link = text("link", "{http://www.w3.org/2005/Atom}id") or ""
        if not link.startswith("http"):
            el = item.find("{http://www.w3.org/2005/Atom}link")
            link = el.get("href", "") if el is not None else ""
        if not link:
            continue

        published = _rss_date(text("pubDate", "{http://purl.org/dc/elements/1.1/}date",
                                 "{http://www.w3.org/2005/Atom}published"))
        if published and published < since:
            continue
        entries.append({
            "url": link,
            "title": text("title", "{http://www.w3.org/2005/Atom}title"),
            "published": published,
            "content": text("{http://purl.org/rss/1.0/modules/content/}encoded",
                             "description",
                             "{http://www.w3.org/2005/Atom}content"),
            "context": "",
        })
    return entries


def _rss_date(raw: str) -> datetime | None:
    if not raw:
        return None
    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S %Z",
                "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            d = datetime.strptime(raw.strip(), fmt)
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def malpedia_entries(source: dict, already_seen: set[str]) -> list[dict]:
    """New reports of the Malpedia bibliography, with their attribution.

    Malpedia exposes no IOC without an API key (`/api/list/samples` answers 403),
    but `/api/get/references` is a report -> malware families and actors
    directory. By remembering the URLs already seen it becomes a stream of NEW
    ITEMS, and it brings what no article gives on its own: attribution, made by
    researchers.

    A corollary to know: the full bibliography counts tens of thousands of
    entries, the vast majority of them old. The first pass must therefore be a
    BOOTSTRAP (`--bootstrap`), which marks everything as seen without processing
    anything. Without it, the first run would try to download and have the model
    read the entire literature of the field.
    """
    data = _http(source["url"]).json()
    references = data.get("references", data) or {}
    entries = []
    for url, targets in references.items():
        if not url.startswith("http") or url in already_seen:
            continue
        families = [c.get("common_name") or c.get("id", "")
                    for c in (targets or []) if isinstance(c, dict)]
        entries.append({
            "url": url,
            "title": "",          # the bibliography carries no title
            "published": None,    # nor a date: the cursor plays that role
            "content": "",
            "context": ", ".join(f for f in families if f)[:300],
        })
    return entries


# ---------------------------------------------------------------------------
# Texte
# ---------------------------------------------------------------------------

_BLOCKS_USELESS = re.compile(
    r"<(script|style|noscript|nav|footer|header|form)\b.*?</\1>", re.S | re.I)
_TAGS = re.compile(r"<[^>]+>")
_SPACES = re.compile(r"[ \t\r\f\v]+")
_LINES = re.compile(r"\n{3,}")


def plain_text(html_source: str) -> str:
    """Readable text of a page, with no HTML parsing dependency.

    A real content extractor (readability, trafilatura) would do better, but
    would add a dependency for no gain here: we are not trying to reproduce the
    layout, only to give the model a sequence of sentences containing the
    indicators. The navigation and script blocks are removed because they are
    full of third-party domains — hence of false candidates.
    """
    without_blocks = _BLOCKS_USELESS.sub(" ", html_source or "")
    # Tags become line breaks: without that, an IOC table comes out glued into
    # a single word and no value is recognisable any more.
    text = _TAGS.sub("\n", without_blocks)
    text = html.unescape(text)
    text = _SPACES.sub(" ", text)
    return _LINES.sub("\n\n", text).strip()


def truncate(text: str, cap: int = MAX_TEXT) -> str:
    if len(text) <= cap:
        return text
    half = cap // 2
    return f"{text[:half]}\n\n[...]\n\n{text[-half:]}"


# ---------------------------------------------------------------------------
# Candidats
# ---------------------------------------------------------------------------

# Defanging: publications neutralise the indicators so they are not clickable.
# Without this rewriting, nearly every IOC actually present in an article goes
# unnoticed — that is THE reason a naive extraction finds nothing on these
# sources.
DEFANG = [
    (re.compile(r"\bh(?:xx|XX|tt)p(s?)\s*(?::|\[:\])//", re.I), r"http\1://"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}"), "."),
    (re.compile(r"\[\s*dot\s*\]", re.I), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*(?:@|at)\s*\]", re.I), "@"),
    (re.compile(r"\bmeow\b|\bhxxp\b", re.I), "http"),
]

PATTERN_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PATTERN_URL = re.compile(r"https?://[^\s\"'<>\)\]]{4,300}")
PATTERN_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|info|biz|ru|cn|top|xyz|club|online|site|shop|icu|vip|cc|io|"
    r"co|me|tv|pw|su|ws|link|live|fun|store|space|website|host|press|tech|app|dev|"
    r"cloud|de|fr|uk|nl|eu|br|in|ir|kr|jp|pl|tk|ml|ga|cf|gq|zip|mov)\b", re.I)
PATTERN_HASH = re.compile(r"\b[0-9a-fA-F]{64}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{32}\b")

# Domains never to keep: those of the source outlets and of the platforms they
# quote over and over. The model already drops them (the prompt asks it to), but
# an exclusion in code does not depend on its mood. An IOC legitimately hosted on
# one of those domains is lost — that is the price, and it is small next to a
# level 12 alert on github.com.
DOMAINS_EXCLUDED = {
    "thehackernews.com", "bleepingcomputer.com", "medium.com", "malpedia.caad.fkie.fraunhofer.de",
    "twitter.com", "x.com", "linkedin.com", "facebook.com", "youtube.com", "reddit.com",
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
    "google.com", "googleapis.com", "gstatic.com", "microsoft.com", "windows.com",
    "office.com", "live.com", "azure.com", "apple.com", "icloud.com", "amazon.com",
    "aws.amazon.com", "cloudflare.com", "akamai.com", "fastly.net",
    "mitre.org", "nist.gov", "cisa.gov", "cve.org", "first.org", "virustotal.com",
    "wikipedia.org", "archive.org", "blogspot.com", "wordpress.com", "substack.com",
    "cisco.com", "talosintelligence.com", "crowdstrike.com", "mandiant.com",
    "sentinelone.com", "sophos.com", "trendmicro.com", "kaspersky.com", "eset.com",
    "paloaltonetworks.com", "unit42.paloaltonetworks.com", "checkpoint.com",
    "welivesecurity.com", "securelist.com", "symantec.com", "fortinet.com",
    "proofpoint.com", "recordedfuture.com", "intezer.com", "any.run", "joesandbox.com",
    "hybrid-analysis.com", "abuse.ch", "circl.lu", "botvrij.eu", "shodan.io", "censys.io",
    "example.com", "example.org", "localhost", "schema.org", "w3.org",
}

# Documentation and test networks (RFC 5737, RFC 3849, TEST-NET): articles use
# them to illustrate without exposing a real target.
NETWORKS_DOC = [ipaddress.ip_network(r) for r in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "233.252.0.0/24")]


def defanger(text: str) -> str:
    for pattern, replacement in DEFANG:
        text = pattern.sub(replacement, text)
    return text


def _domain_excluded(value: str) -> bool:
    host = (urlparse(value).hostname if value.startswith("http") else value) or ""
    host = host.lower().rstrip(".")
    # Suffix comparison: `cdn.microsoft.com` must fall with `microsoft.com`,
    # otherwise the exclusion only holds on the bare domain.
    return any(host == d or host.endswith("." + d) for d in DOMAINS_EXCLUDED)


def _ip_to_ignore(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return True
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast \
            or ip.is_reserved or ip.is_unspecified:
        return True
    if any(ip in network for network in NETWORKS_DOC):
        return True
    # The SOC infrastructure and our own networks cannot be IOCs published by a
    # third party. If that happens it is an error of the article or of the
    # extraction, and the consequence would be to make the SOC alert — or even
    # act — against itself.
    if str(ip) in config.SOC_INFRA_IPS:
        return True
    return any(ip in network for network in _internal_networks())


def _internal_networks() -> list:
    """`config.NETWORKS_INTERNAL` converted into comparable networks.

    The configuration delivers them as STRINGS ("192.168.1.0/24, ..."), and
    `ip in "192.168.1.0/24"` raises a TypeError — seen in production on
    2026-08-12, it took down the whole The Hacker News source in the middle of a
    pass. A badly written entry is ignored rather than fatal: it must not decide
    the availability of the intelligence watch.
    """
    networks = []
    for raw in getattr(config, "NETWORKS_INTERNAL", None) or []:
        if isinstance(raw, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            networks.append(raw)
            continue
        try:
            networks.append(ipaddress.ip_network(str(raw).strip(), strict=False))
        except ValueError:
            log.debug("NETWORKS_INTERNAL: entry ignored %r", raw)
    return networks


def candidates(text: str) -> dict[str, list[str]]:
    """Values that look like an IOC, by type, already filtered of hard noise.

    Does NOT judge maliciousness: that is the next stage's job. Here it only
    removes what structurally cannot be an indicator.
    """
    plain = defanger(text)
    found = {"ip": [], "domain": [], "url": [], "hash": []}
    seen = set()

    def add(type_, raw):
        value = cti.normalize(type_, raw)
        if not value or value in seen:
            return
        if type_ == "ip" and _ip_to_ignore(value):
            return
        if type_ in ("domain", "url") and _domain_excluded(value):
            return
        seen.add(value)
        found[type_].append(value)

    for raw in PATTERN_URL.findall(plain):
        add("url", raw.rstrip(".,;:)"))
    for raw in PATTERN_IP.findall(plain):
        add("ip", raw)
    for raw in PATTERN_DOMAIN.findall(plain):
        add("domain", raw)
    for raw in PATTERN_HASH.findall(plain):
        add("hash", raw)
    return found


# ---------------------------------------------------------------------------
# Arbitration by the model
# ---------------------------------------------------------------------------

def _batches(found: dict[str, list[str]]) -> list[list[tuple[str, str]]]:
    """Candidates split into bounded batches, all types mixed."""
    plat = [(type_, v) for type_, values in found.items() for v in values]
    return [plat[i:i + BATCH_CANDIDATES]
            for i in range(0, len(plat), BATCH_CANDIDATES)][:MAX_BATCHES]


def arbitrate(article: dict, found: dict[str, list[str]]) -> dict:
    """Asks the model which of the candidates are IOCs of the threat.

    No pseudonymisation here, unlike triage (see anonymize.py): what leaves is
    the text of a PUBLIC article and indicators published by its author. There is
    nothing of our infrastructure in this prompt — and that is a property to
    preserve if this module evolves.

    The text is sent whole with EVERY batch of candidates, and that is
    deliberate: the context is what allows deciding, chopping it would have
    values judged without the story that qualifies them. The prefix being
    identical from one call to the next, it is served from the provider's cache.
    """
    system = (PROMPTS / "cti_extraction.md").read_text()
    header = (
        f"TITRE : {article.get('title') or '(inconnu)'}\n"
        f"URL : {article['url']}\n"
        + (f"FAMILLES ASSOCIÉES (attribution Malpedia) : {article['context']}\n"
           if article.get("context") else ""))
    article_body = f"\nARTICLE :\n{truncate(article['text'])}\n"

    def request(batch: list[tuple[str, str]], label: str) -> dict | None:
        """One call to the model on a batch of candidates. None if it fails.

        Replays once in TWO HALVES when the budget has been exhausted: the model
        is a reasoning one and the length of its reasoning is not predictable
        (measured: the same budget is enough for one batch and not for the next).
        Splitting the batch is the only answer that does not consist of
        oversizing the budget of every call for the rare ones that overflow.
        """
        by_type: dict[str, list[str]] = {}
        for type_, value in batch:
            by_type.setdefault(type_, []).append(value)
        listing = "\n".join(f"{t} : " + ", ".join(v) for t, v in by_type.items())
        try:
            response, _ = llm.completion(
                system, header + article_body + f"\nCANDIDATS ({label}) :\n{listing}\n",
                usage="cti_extraction", max_tokens=MAX_TOKENS)
            return response
        except Exception as exc:                              # noqa: BLE001
            budget_exhausted = "finish_reason=length" in str(exc) or "Unterminated" in str(exc)
            if budget_exhausted and len(batch) > 4:
                middle = len(batch) // 2
                log.info("batch %s too heavy for the budget, split in two",
                         label)
                left = request(batch[:middle], f"{label}a")
                right = request(batch[middle:], f"{label}b")
                if left is None and right is None:
                    return None
                return {"iocs": (left or {}).get("iocs", [])
                                + (right or {}).get("iocs", []),
                        "threat": (left or right or {}).get("threat", ""),
                        "summary": (left or right or {}).get("summary", ""),
                        "confidence": (left or right or {}).get("confidence", "")}
            # A lost batch must not take the article down: the others may have
            # delivered real indicators, and dropping them over an API accident
            # would be paying twice.
            log.warning("batch %s failed on %s: %s", label, article["url"], exc)
            return None

    merge = {"iocs": [], "threat": "", "summary": "", "confidence": ""}
    batches = _batches(found)
    total = sum(len(v) for v in found.values())
    covered = sum(len(batch) for batch in batches)
    if covered < total:
        log.warning("%s: %d candidates out of %d submitted to the model (cap "
                    "of %d batches) — %d NOT examined", article["url"], covered,
                    total, MAX_BATCHES, total - covered)
    for number, batch in enumerate(batches, 1):
        response = request(batch, f"{number}/{len(batches)}")
        if response is None:
            continue
        merge["iocs"].extend(response.get("iocs") or [])
        # Threat, summary and confidence are properties of the ARTICLE, not of
        # the batch: we keep the first non-empty answer rather than overwriting
        # on every round, a batch sometimes containing no IOC and hence no
        # context.
        for key in ("threat", "summary", "confidence"):
            if not merge[key] and response.get(key):
                merge[key] = str(response[key])
    return merge


def validate(response: dict, found: dict[str, list[str]]) -> list[dict]:
    """Deterministic guardrail on the model output.

    Three rejections, in this order, and none is negotiable:

    1. value absent from the candidates -> HALLUCINATION. The model is not
       allowed to produce an indicator the text does not contain; that is the one
       failure mode that would manufacture IOCs out of thin air.
    2. type inconsistent with the value -> we reclassify from the value, never
       from what the model announces.
    3. hard exclusions replayed. The prompt already asks for them, but a prompt
       is not a control.
    """
    allowed = {v: t for t, values in found.items() for v in values}
    kept, seen = [], set()
    for raw in (response.get("iocs") or [])[:MAX_IOC_ARTICLE * 2]:
        if not isinstance(raw, dict):
            continue
        value = str(raw.get("value", "")).strip()
        announced_type = str(raw.get("type", "")).strip().lower()
        # Normalise with the announced type when it is plausible, otherwise
        # with the one the candidate was actually found under.
        value = cti.normalize(announced_type, value) or cti.normalize(
            allowed.get(value, ""), value) or value
        real_type = allowed.get(value)
        if not real_type:
            log.warning("IOC rejected (absent from the candidates): %r", raw.get("value"))
            continue
        if value in seen:
            continue
        if real_type == "ip" and _ip_to_ignore(value):
            continue
        if real_type in ("domain", "url") and _domain_excluded(value):
            continue
        seen.add(value)
        kept.append({"value": value, "type": real_type,
                        "role": str(raw.get("role", ""))[:100]})
    return kept


# ---------------------------------------------------------------------------
# MISP
# ---------------------------------------------------------------------------

# Cache type -> MISP attribute type. `ip-dst` and not `ip-src`: an IOC from an
# article names attacker infrastructure, hence a DESTINATION seen from our side.
# The cache falls back onto "ip" anyway (see cti.TYPES), the distinction only
# serves readability in MISP.
TYPE_MISP = {"ip": "ip-dst", "domain": "domain", "url": "url"}


def _type_hash(value: str) -> str:
    return {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]


def filter_warninglists(values: list[str]) -> set[str]:
    """Values MISP knows as NOT SUPPOSED to be IOCs.

    The MISP warninglists list what an indicator should never be: top-1000
    domains, public DNS resolvers, cloud provider ranges, documentation
    addresses... Exactly the population of false positives a press article
    generates. Querying them here avoids publishing what `cti.py` would then
    silently drop on reading (`enforceWarninglist`) — publishing an unusable IOC
    is worse than not publishing it: it gives the illusion of coverage.

    If the call fails we filter nothing rather than drop everything: the loss
    would be invisible.
    """
    if not values:
        return set()
    try:
        response = cti._misp("POST", "/warninglists/checkValue", values)
    except Exception as exc:                                  # noqa: BLE001
        log.warning("MISP warninglists unreachable (%s): no filtering", exc)
        return set()
    if isinstance(response, dict):
        return {v for v, lists in response.items() if lists}
    return set()


def create_event(article: dict, iocs: list[dict], response: dict,
                    source: dict) -> int | None:
    """Publishes a MISP event carrying the article's IOCs.

    The event is the RIGHT granularity: one article = one threat = a set of
    indicators that correlate with each other. An isolated attribute in a
    catch-all event would lose the context, hence the essential part.

    `to_ids` is true (these are detection indicators) but the
    `aura:source:extracted` tag distinguishes them from curated intelligence all
    the way to the Wazuh rule level. `analysis: 2` (complete) and immediate
    publication: without publishing, `cti.py` would never see them (it filters
    `published=1`).
    """
    threat = str(response.get("threat") or "").strip()
    summary = str(response.get("summary") or "").strip()
    title = (article.get("title") or article["url"])[:200]
    info = f"[AURA/{source['name']}] {threat + ' — ' if threat else ''}{title}"

    attributes = [{
        "type": "link", "category": "External analysis", "value": article["url"],
        "to_ids": False, "comment": "Source article",
    }]
    for ioc in iocs:
        type_misp = TYPE_MISP.get(ioc["type"]) or _type_hash(ioc["value"])
        attributes.append({
            "type": type_misp,
            "category": "Payload delivery" if ioc["type"] == "hash"
                        else "Network activity",
            "value": ioc["value"],
            "to_ids": True,
            "comment": ioc["role"] or summary[:100],
        })

    tags = [{"name": TAG_SOURCE}, {"name": f"aura:feed:{source['name']}"},
            {"name": "tlp:clear"}]
    confidence = str(response.get("confidence") or "").lower()
    if confidence in ("haute", "moyenne", "basse"):
        tags.append({"name": f"aura:extraction-confidence:{confidence}"})
    if article.get("context"):
        tags.append({"name": "aura:attribution:malpedia"})

    body = {"Event": {
        "info": info[:255],
        "date": (article.get("published") or datetime.now(timezone.utc)).strftime("%Y-%m-%d"),
        "analysis": "2",
        "threat_level_id": "2",
        "distribution": "0",
        "published": True,
        "Attribute": attributes,
        "Tag": tags,
    }}
    misp_response = cti._misp("POST", "/events/add", body)
    event = (misp_response or {}).get("Event") or {}
    return int(event["id"]) if event.get("id") else None


# ---------------------------------------------------------------------------
# Cursor
# ---------------------------------------------------------------------------

def _connection():
    return psycopg.connect(config.PG_DSN)


def already_seen(conn, source: str) -> set[str]:
    return {u for (u,) in conn.execute(
        "SELECT url FROM cti_articles WHERE source = %s", (source,))}


def mark(conn, source: str, url: str, nb_iocs: int, event_id: int | None,
            threat: str = "", pattern: str = "") -> None:
    conn.execute(
        "INSERT INTO cti_articles (source, url, iocs_kept, misp_event_id, "
        "threat, pattern) VALUES (%s, %s, %s, %s, %s, %s) "
        "ON CONFLICT (url) DO UPDATE SET iocs_kept = EXCLUDED.iocs_kept, "
        "misp_event_id = COALESCE(EXCLUDED.misp_event_id, cti_articles.misp_event_id), "
        "threat = EXCLUDED.threat, pattern = EXCLUDED.pattern",
        (source, url, nb_iocs, event_id, threat[:200], pattern[:200]))
    conn.commit()


# ---------------------------------------------------------------------------
# Processing
# ---------------------------------------------------------------------------

def load_text(article: dict) -> str:
    """Text of the article: the feed's when it is complete, otherwise the page."""
    from_feed = plain_text(article.get("content") or "")
    # An RSS excerpt is a few hundred characters: it never contains the IOC
    # section. We only settle for it when it is substantial.
    if len(from_feed) > 3000:
        return from_feed
    return plain_text(_http(article["url"]).text)


def process(article: dict, source: dict, simulation: bool = False) -> dict:
    """One article, from fetching to the MISP event.

    Returns a report, including when nothing is kept: "no IOC" is the normal
    result for most press articles, and recording it avoids reprocessing the same
    text on every pass.
    """
    result = {"url": article["url"], "iocs": [], "event_id": None,
                "threat": "", "pattern": ""}
    try:
        article["text"] = load_text(article)
    except Exception as exc:                                  # noqa: BLE001
        result["pattern"] = f"unreadable article: {exc}"
        return result
    if len(article["text"]) < 500:
        result["pattern"] = "text too short to be a report"
        return result

    found = candidates(article["text"])
    if not any(found.values()):
        result["pattern"] = "no candidate in the text"
        return result

    response = arbitrate(article, found)
    iocs = validate(response, found)
    result["threat"] = str(response.get("threat") or "")[:200]
    if not iocs:
        result["pattern"] = "no IOC kept by the arbitration"
        return result
    cap = int(source.get("max_iocs") or MAX_IOC_ARTICLE)
    if len(iocs) > cap:
        # Not publishing rather than publishing anything, and SAYING so: a
        # silent truncation would suggest full coverage.
        result["pattern"] = (f"{len(iocs)} IOCs extracted, past the cap of "
                             f"{cap}: article not published)")
        log.warning("%s : %s", article["url"], result["pattern"])
        return result

    known = filter_warninglists([i["value"] for i in iocs])
    if known:
        log.info("%d IOCs dropped by the MISP warninglists", len(known))
    iocs = [i for i in iocs if i["value"] not in known]
    result["iocs"] = iocs
    if not iocs:
        result["pattern"] = "every IOC dropped by the MISP warninglists"
        return result

    if not simulation:
        result["event_id"] = create_event(article, iocs, response, source)
    return result


# Sources with neither a date nor a stream of new items: the cursor of seen
# URLs stands in for it, so they MUST be bootstrapped before the first pass. The
# RSS feeds are already bounded by their freshness window.
TYPES_TO_BOOTSTRAP = {"malpedia_references"}


def collect(source: dict, already: set[str], since: datetime,
              maximum: int, bootstrap: bool, simulation: bool,
              ledger=None) -> list[dict]:
    if bootstrap and source.get("type") not in TYPES_TO_BOOTSTRAP:
        # Do NOT mark the RSS feeds during a bootstrap: it would burn the
        # recent articles, which are precisely the ones we want to process on the
        # first real pass. Bootstrapping only exists for sources with no date
        # (see TYPES_TO_BOOTSTRAP).
        log.info("%s: nothing to bootstrap (dated source)", source["name"])
        return []

    if source.get("type") == "malpedia_references":
        entries = malpedia_entries(source, already)
    else:
        entries = [e for e in rss_entries(source, since) if e["url"] not in already]
    log.info("%s: %d new entry/entries", source["name"], len(entries))

    if bootstrap:
        # Marking without processing: that is what makes the first run possible
        # on a bibliography of several tens of thousands of reports.
        return [{"url": e["url"], "iocs": [], "event_id": None, "threat": "",
                 "pattern": "bootstrap"} for e in entries]

    results = []
    for entry in entries[:maximum]:
        log.info("→ %s", entry["url"])
        result = process(entry, source, simulation=simulation)
        results.append(result)
        # IMMEDIATE marking, article by article, and not at the end of the
        # source: an outage in the middle of a pass (or the container stopping)
        # would otherwise lose the work already done, model calls included. Seen
        # in production on 2026-08-12 on a type error — the article processed
        # just before was paid for then forgotten.
        if ledger is not None and not simulation:
            mark(ledger, source["name"], result["url"],
                    len(result["iocs"]), result["event_id"],
                    result["threat"], result["pattern"])
    return results


def pass_(source_name: str | None = None, maximum: int = 10,
          hours: int = 48, bootstrap: bool = False,
          simulation: bool = False) -> list[dict]:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    everything = []
    with _connection() as conn:
        for source in sources():
            if source_name and source["name"] != source_name:
                continue
            already = already_seen(conn, source["name"])
            try:
                results = collect(source, already, since, maximum, bootstrap,
                                      simulation, ledger=conn)
            except Exception as exc:                          # noqa: BLE001
                # A broken source must not take the others down: they are
                # independent, and the intelligence lost would be everyone's.
                # The articles of that source already processed are already
                # recorded (marked as we go).
                log.warning("source %s failed: %s", source["name"], exc)
                continue
            for r in results:
                if bootstrap and not simulation:
                    mark(conn, source["name"], r["url"], 0, None, "", "bootstrap")
                if r["iocs"]:
                    log.info("%d IOCs published (event %s) — %s", len(r["iocs"]),
                             r["event_id"], r["threat"] or "unnamed threat")
            everything.extend(results)
    return everything


def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", help="process one source only (catalog name)")
    p.add_argument("--max", type=int, default=10,
                   help="articles processed per source and per pass (default 10)")
    p.add_argument("--hours", type=int, default=48,
                   help="freshness window of the RSS feeds (default 48)")
    p.add_argument("--bootstrap", action="store_true",
                   help="marks what exists as seen WITHOUT processing anything "
                        "(mandatory on the first run, see Malpedia)")
    p.add_argument("--simulation", action="store_true",
                   help="extracts and prints, writes neither MISP nor database")
    p.add_argument("--url", help="process one specific article, outside the feeds")
    args = p.parse_args()

    if args.url:
        source = {"name": args.source or "manuel"}
        r = process({"url": args.url, "title": "", "published": None,
                     "content": "", "context": ""}, source,
                    simulation=args.simulation)
        print(json.dumps(r, indent=2, ensure_ascii=False))
        return

    results = pass_(args.source, args.max, args.hours, args.bootstrap,
                      args.simulation)
    published = sum(len(r["iocs"]) for r in results)
    log.info("%d article(s) processed, %d IOC%s", len(results), published,
             " (simulation)" if args.simulation else " published into MISP")
    if args.simulation:
        print(json.dumps([r for r in results if r["iocs"] or r["pattern"]],
                         indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
