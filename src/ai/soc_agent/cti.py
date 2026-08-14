"""CTI: feeds MISP, and feeds Wazuh with detectable IOCs.

The CTI part of Aura-SOC has three pieces, two of which live here:

  1. MISP (docker-compose.yml) — the MEMORY: events, campaigns, tags,
     correlations, investigation context. That is what we open when we want to
     understand.
  2. `cti.py` — the BRIDGE: it declares the feeds to MISP (`--feeds`), then
     periodically extracts the usable IOCs into a SQLite cache (`--sync`).
  3. `src/wazuh/integrations/custom-misp.py` — the DETECTION: on every alert it
     looks the alert's IOCs up in that cache and re-injects an enriched event
     into the analyser, which matches rules 100950-100956.

Why a cache rather than one MISP call per alert — the structuring choice of this
module. The Wazuh integration is called by `wazuh-integratord`, serially, for
every retained alert. An HTTP request to MISP at that point puts the detection of
the whole fleet behind the latency, availability and load of a PHP service: MISP
down or slow, and the entire alert pipeline falls behind without anything saying
so. The cache inverts the dependency — detection reads a local file, MISP can go
down without breaking anything, and the cache going stale is itself detected
(rule 100956).

The cache holds ONLY what serves the decision: the value, its type, its source,
its short context. The investigation happens in MISP.

    python -m soc_agent.cti --feeds       # declares/enables the feeds (idempotent)
    python -m soc_agent.cti               # synchronises the IOC cache
    python -m soc_agent.cti --state       # what the cache holds, and its age
    python -m soc_agent.cti --test IOC    # queries the cache on a value
    python -m soc_agent.cti --simulation  # counts without writing the cache
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone

import requests
import urllib3
import yaml

from . import config

log = logging.getLogger("cti")

if not config.MISP_VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 120

# Confidence carried by the SOURCE, not by the IOC. It decides the Wazuh rule
# level, hence what becomes an incident:
#   curated   -> contextualised intelligence, published by a CERT or a recognised
#                project (MISP)                    -> 100951/100952, level 12-14
#   extracted -> IOC pulled from a public article by the model (see
#                cti_articles.py). The threat is real, the extraction is
#                automatic and the outlet is not a CERT -> 100957, level 12
#   bulk      -> volume reputation (blocklists)     -> 100953, level 10
CONFIDENCE_CURATED = "curated"
CONFIDENCE_EXTRACTED = "extracted"
CONFIDENCE_BULK = "bulk"

# Tag set by cti_articles.py on the events it creates. It is what carries the
# confidence distinction from MISP down to the Wazuh rule: without that marking,
# an IOC guessed from a press article would be indistinguishable from an IOC
# signed CERT-FR, and would fire at the same level.
TAG_EXTRACTION = "aura:source:extracted"

# MISP taxonomy marking for an event produced by an automaton, with no human
# verification. Those events are treated as BULK REPUTATION, not as curated
# intelligence.
#
# This is not a principle, it is a measurement: the CIRCL OSINT feed relays the
# daily publications of Maltrail (an aggregation of blacklists), that is 255,361
# of the 692,543 "curated" IOCs in the cache on 2026-08-12 — 37 %, all with
# to_ids=1. Leaving them as `curated` made them match at levels 12 to 14, hence
# open an incident and pay for an LLM triage on what is, by construction, the
# same thing as a blocklist. The MISP taxonomy announces it itself; it only had
# to be read.
TAG_NON_SUPERVISED = 'misp:automation-level="unsupervised"'


# ---------------------------------------------------------------------------
# Normalisation
#
# WARNING: these rules are REIMPLEMENTED identically in
# src/wazuh/integrations/custom-misp.py. The manager runs Wazuh's embedded
# interpreter and does not have the soc_agent package: sharing the code is
# impossible. The symmetry is therefore checked by a test
# (tests/test_cti.py), which loads the integration script by its path and
# compares the two functions. Any change here must be carried over there,
# otherwise the cache is written in a form detection never looks for — and
# nothing matches, silently.
# ---------------------------------------------------------------------------

# MISP types -> cache type. Several MISP types fall back onto the same one: a
# Wazuh alert does not know whether the IP it carries was published as a source
# or as a destination.
TYPES = {
    "ip-src": "ip",
    "ip-dst": "ip",
    "ip-src|port": "ip",
    "ip-dst|port": "ip",
    "domain": "domain",
    "hostname": "domain",
    "domain|ip": "domain",
    "url": "url",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "filename|md5": "hash",
    "filename|sha1": "hash",
    "filename|sha256": "hash",
}


def normalize(type_cache: str, value: str) -> str | None:
    """Canonical form of an IOC, or None when it is unusable.

    Deliberately conservative: we do not "repair" a doubtful value, we drop it.
    A badly normalised IOC does not raise an error, it makes a permanent false
    negative.
    """
    v = (value or "").strip()
    if not v:
        return None

    if type_cache == "ip":
        # The port is sometimes glued to the value (`ip-dst|port` types), and
        # some feeds deliver the IP in brackets to "defang" it.
        v = v.split("|", 1)[0].strip().strip("[]")
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            return None

    if type_cache == "domain":
        v = v.split("|", 1)[0].strip().lower().rstrip(".")
        # A domain with no dot is not one: it is an internal machine name, and
        # it would match the hostname of our own agents.
        return v if "." in v and " " not in v else None

    if type_cache == "url":
        v = v.strip().rstrip("/")
        # Without a scheme we are not comparing the same thing on both sides:
        # Wazuh web alerts often carry a plain path (`/wp-login`), which would
        # match any IOC with the same path, across all domains.
        return v.lower() if v.lower().startswith(("http://", "https://")) else None

    if type_cache == "hash":
        v = v.split("|")[-1].strip().lower()
        return v if len(v) in (32, 40, 64) and all(
            c in "0123456789abcdef" for c in v) else None

    return None


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------

def load_catalog(path: str | None = None) -> dict:
    with open(path or config.CTI_CATALOG) as f:
        cat = yaml.safe_load(f) or {}
    return {"misp_feeds": cat.get("misp_feeds") or [],
            "blocklists": cat.get("blocklists") or [],
            # Article sources, used by cti_articles.py. They are NOT MISP
            # feeds: nothing to declare on the MISP side, we are the ones writing
            # the events there after extraction.
            "articles": cat.get("articles") or []}


# ---------------------------------------------------------------------------
# API MISP
# ---------------------------------------------------------------------------

def _misp(method: str, path: str, body: dict | None = None) -> dict | list:
    if not config.MISP_KEY:
        sys.exit("MISP_KEY missing: the MISP API key is required (see .env.example)")
    response = requests.request(
        method,
        f"{config.MISP_URL.rstrip('/')}{path}",
        headers={"Authorization": config.MISP_KEY,
                 "Accept": "application/json",
                 "Content-Type": "application/json"},
        json=body,
        verify=config.MISP_VERIFY_TLS,
        timeout=TIMEOUT,
    )
    response.raise_for_status()
    return response.json()


def _feed_body(feed: dict) -> dict:
    """MISP payload for a catalog feed.

    `cache_only` is the important point: a cached feed is queryable (correlation,
    search) but does NOT create events. It is the only sustainable regime for a
    rotating 100,000-IP blocklist — ingested, it rewrites the MISP database on
    every pass.
    """
    cache = bool(feed.get("cache_only"))
    return {
        "name": feed["name"],
        "provider": feed.get("provider", feed["name"]),
        "url": feed["url"],
        "source_format": feed.get("format", "misp"),
        "input_source": "network",
        "enabled": not cache,
        "caching_enabled": True,
        "distribution": "0",          # own organisation only: this lab pushes nothing
        "fixed_event": cache,
        "delta_merge": cache,
        "publish": False,
        "override_ids": False,
        "tag_id": "0",
    }


def _url_key(url: str) -> str:
    """Comparison form of a feed URL.

    The trailing slash is ignored: MISP ships the CIRCL feed as
    `.../feed-osint` and the catalog writes it `.../feed-osint/`. Without this
    normalisation the bootstrap does not recognise the preinstalled feed and
    creates a second one — measured in production on 2026-08-12, two entries for
    CIRCL and two for Botvrij. With both copies enabled, MISP pulls the same feed
    twice and doubles the events.
    """
    return (url or "").strip().rstrip("/").lower()


def bootstrap_feeds(simulation: bool = False, catalogue: dict | None = None) -> dict:
    """Declares and enables the catalog feeds in MISP. Idempotent.

    Matched on the URL and not on the name: the URL identifies a feed, and it is
    what breaks when a provider moves. A feed already present — including those
    MISP ships by default — is updated, never duplicated: the function can run on
    every startup.
    """
    cat = catalogue or load_catalog()
    wanted = list(cat["misp_feeds"]) + [
        # A blocklist is declared to MISP as cache-only: it stays queryable
        # from the UI ("is this IP known?") without weighing on MariaDB.
        # Detection does not go through it: cti.py pulls those lists directly
        # (see blocklists() below).
        {"name": f"{bl['name']} (cache)", "url": url,
         "provider": bl.get("provider", bl["name"]),
         "format": "freetext", "cache_only": True}
        for bl in cat["blocklists"] for url in bl["urls"]
    ]

    existing = {_url_key(f["Feed"]["url"]): f["Feed"]
                 for f in _misp("GET", "/feeds/index")
                 if isinstance(f, dict) and "Feed" in f} if not simulation else {}

    summary = {"created": [], "updated": [], "unchanged": []}
    for feed in wanted:
        body = _feed_body(feed)
        already = existing.get(_url_key(feed["url"]))
        if simulation:
            summary["created" if not already else "updated"].append(feed["name"])
            continue
        if not already:
            _misp("POST", "/feeds/add", {"Feed": body})
            summary["created"].append(feed["name"])
        elif any(str(already.get(k, "")).lower() != str(v).lower()
                 for k, v in (("enabled", body["enabled"]),
                              ("caching_enabled", body["caching_enabled"]))):
            _misp("POST", f"/feeds/edit/{already['id']}", {"Feed": body})
            summary["updated"].append(feed["name"])
        else:
            summary["unchanged"].append(feed["name"])
    return summary


def refresh_feeds(simulation: bool = False) -> None:
    """Asks MISP to pull its feeds now, without waiting for its cron.

    Both calls are asynchronous (MISP queues jobs): they return immediately, so
    the first useful `--sync` can be a few minutes later. That is normal, not an
    outage.

    `fetchFromAllFeeds` and not `fetchFromFeed/all`: the latter expects a numeric
    identifier and answers 404 on "all" (measured in production on 2026-08-12).
    Only `cacheFeeds` accepts a named scope.
    """
    if simulation:
        return
    _misp("POST", "/feeds/fetchFromAllFeeds")
    _misp("POST", "/feeds/cacheFeeds/all")


# ---------------------------------------------------------------------------
# Extracting the IOCs
# ---------------------------------------------------------------------------

def _confidence(tags: list[str]) -> str:
    """Confidence of a MISP attribute, from the tags of its event.

    The order of the two tests matters: an event produced by OUR extraction
    carries both possible markings in some cases, and the most cautious one must
    win. An unsupervised automaton (Maltrail and the like, relayed by the OSINT
    feeds) is bulk reputation, whatever organisation publishes it.
    """
    if TAG_NON_SUPERVISED in tags:
        return CONFIDENCE_BULK
    if TAG_EXTRACTION in tags:
        return CONFIDENCE_EXTRACTED
    return CONFIDENCE_CURATED


def _ip_expired(type_cache: str, event: dict) -> bool:
    """An IP whose originating event is too old is worth nothing any more.

    `CTI_WINDOW` does NOT filter the age of the intelligence: MISP's `last`
    parameter is about the last MODIFICATION date of the attribute, and
    everything a feed has just imported was modified today. Measured on the first
    production import on 2026-08-12: IPs published as C2 in 2015 (Rocket Kitten
    report) ended up in the cache, ready to fire a level 12 to 14 alert.

    An IP address is the only type of IOC that changes hands: a 2015 C2 IP is
    today, at best, a shared host, at worst somebody's CDN. A HASH never expires
    — the file is the same — and a domain stays attached to whoever registered
    it. Hence an expiry aimed at IPs only, on the EVENT date and not the
    attribute's.
    """
    if type_cache != "ip" or not config.CTI_IP_MAX_DAYS:
        return False
    date = (event or {}).get("date") or ""
    if not date:
        return False   # with no date we do not drop it: we do not know
    try:
        age = (datetime.now(timezone.utc)
               - datetime.fromisoformat(date).replace(tzinfo=timezone.utc)).days
    except ValueError:
        return False
    return age > config.CTI_IP_MAX_DAYS


def misp_attributes(page_size: int = 5000):
    """Curated MISP IOCs: `to_ids` attributes, published, within the window.

    `to_ids=1` is the decisive filter. MISP holds many CONTEXT attributes (a
    sinkhole IP, the domain of a report, a scanner address quoted as an example)
    that are not meant for detection; their authors say so precisely with this
    flag. Ignoring it means manufacturing false positives signed "CERT-FR", that
    is, the most expensive ones to refute.
    """
    page = 1
    total = 0
    while True:
        response = _misp("POST", "/attributes/restSearch", {
            "returnFormat": "json",
            "type": config.CTI_TYPES_MISP,
            "to_ids": 1,
            "deleted": 0,
            "published": 1,
            "enforceWarninglist": 1,   # drops what MISP knows to be benign
            "includeEventTags": 1,
            "last": config.CTI_WINDOW,
            "limit": page_size,
            "page": page,
        })
        batch = (response or {}).get("response", {}).get("Attribute", [])
        if not batch:
            return
        for attr in batch:
            type_cache = TYPES.get(attr.get("type", ""))
            if not type_cache:
                continue
            value = normalize(type_cache, attr.get("value", ""))
            if not value:
                continue
            event = attr.get("Event") or {}
            if _ip_expired(type_cache, event):
                continue
            tags = [t.get("name", "") for t in (attr.get("Tag") or [])]
            yield {
                "value": value,
                "type": type_cache,
                "source": (event.get("Orgc") or {}).get("name") or "MISP",
                "category": attr.get("category", ""),
                "event": (event.get("info") or "")[:200],
                "event_id": str(attr.get("event_id") or ""),
                "tags": ",".join(t for t in tags if t)[:300],
                "threat_level": int(event.get("threat_level_id") or 4),
                # Everything comes back through the same path — deliberately,
                # MISP is the only memory — but not everything is worth the same,
                # and the tags are the only place where the difference survives.
                "confidence": _confidence(tags),
            }
            total += 1
            if total > config.CTI_MAX_IOC:
                raise RuntimeError(
                    f"MISP extraction past CTI_MAX_IOC ({config.CTI_MAX_IOC})")
        page += 1


def blocklists(catalogue: dict | None = None):
    """Bulk IOCs, pulled straight from the provider.

    Short-circuiting MISP is deliberate (see cti_feeds.yaml): those lists have no
    context to correlate, and their volume would make the MISP database unusable
    for what it does best.
    """
    cat = catalogue or load_catalog()
    for bl in cat["blocklists"]:
        type_cache = bl.get("type", "ip")
        for url in bl["urls"]:
            try:
                response = requests.get(url, timeout=TIMEOUT)
                response.raise_for_status()
            except Exception as exc:
                # An unavailable feed must not fail the others: the cache is
                # rebuilt in full on every pass, losing one source means losing
                # its coverage, not the whole CTI.
                log.warning("blocklist %s unreachable (%s): %s", bl["name"], url, exc)
                continue
            count = 0
            for line in response.text.splitlines():
                line = line.strip()
                if not line or line.startswith(("#", ";", "//")):
                    continue
                value = normalize(type_cache, line.split()[0])
                if not value:
                    continue
                count += 1
                if count > config.CTI_MAX_IOC:
                    raise RuntimeError(
                        f"{bl['name']} past CTI_MAX_IOC ({config.CTI_MAX_IOC})")
                yield {
                    "value": value,
                    "type": type_cache,
                    "source": bl["name"],
                    "category": bl.get("category", ""),
                    "event": bl.get("comment", ""),
                    "event_id": "",
                    "tags": ",".join(bl.get("tags") or [])[:300],
                    # No threat level: a bulk list qualifies nothing. 4 =
                    # "undefined" in MISP, and that is exact.
                    "threat_level": 4,
                    "confidence": CONFIDENCE_BULK,
                }
            log.info("blocklist %s: %d IOC (%s)", bl["name"], count, url)


# ---------------------------------------------------------------------------
# Lookup cache
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE ioc (
  value        TEXT NOT NULL,
  type         TEXT NOT NULL,
  source       TEXT NOT NULL,
  category     TEXT,
  event        TEXT,
  event_id     TEXT,
  tags         TEXT,
  threat_level INTEGER,
  confidence   TEXT NOT NULL,
  PRIMARY KEY (value, type, source)
);
CREATE INDEX idx_ioc_value ON ioc(value);
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
"""


def write_cache(iocs, path: str | None = None) -> dict:
    """Rebuilds the cache in full, then substitutes it in one step.

    Written into a temporary file of the SAME directory then `os.replace`: the
    replacement is atomic, so the Wazuh integration can never read a half-written
    cache. A full rebuild (and not a delta) is what makes the IOCs removed from
    the feeds DISAPPEAR — without it, a rehabilitated IP would keep alerting
    forever.
    """
    path = path or config.CTI_CACHE
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=os.path.dirname(path) or ".",
                                      prefix=".ioc-", suffix=".db")
    os.close(fd)
    os.unlink(temporary)

    count = {}
    try:
        conn = sqlite3.connect(temporary)
        try:
            conn.executescript(SCHEMA)
            batch = []
            for ioc in iocs:
                count[ioc["confidence"]] = count.get(ioc["confidence"], 0) + 1
                batch.append((ioc["value"], ioc["type"], ioc["source"],
                            ioc.get("category", ""), ioc.get("event", ""),
                            ioc.get("event_id", ""), ioc.get("tags", ""),
                            ioc.get("threat_level", 4), ioc["confidence"]))
                if len(batch) >= 10000:
                    conn.executemany("INSERT OR REPLACE INTO ioc VALUES (?,?,?,?,?,?,?,?,?)", batch)
                    batch = []
            if batch:
                conn.executemany("INSERT OR REPLACE INTO ioc VALUES (?,?,?,?,?,?,?,?,?)", batch)
            conn.execute("INSERT INTO meta VALUES ('synced_at', ?)",
                         (datetime.now(timezone.utc).isoformat(),))
            conn.execute("INSERT INTO meta VALUES ('count', ?)",
                         (json.dumps(count),))
            # Public URL embedded in the cache: it is what makes the alert links
            # clickable from an analyst workstation. Setting it here avoids
            # redeclaring the MISP configuration on the manager side — the cache
            # is already the only channel between the two.
            conn.execute("INSERT INTO meta VALUES ('base_url', ?)",
                         (config.MISP_BASE_URL.rstrip("/"),))
            conn.commit()
        finally:
            conn.close()
        # Readable by the manager's wazuh user, which is not ours.
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise
    return count


def query(value: str, path: str | None = None) -> list[dict]:
    """Every match for a value, best source first."""
    path = path or config.CTI_CACHE
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        lines = conn.execute(
            "SELECT * FROM ioc WHERE value = ? ORDER BY "
            "CASE confidence WHEN 'curated' THEN 0 WHEN 'extracted' THEN 1 "
            "ELSE 2 END ASC, threat_level ASC",
            (value,)).fetchall()
    finally:
        conn.close()
    return [dict(l) for l in lines]


def state(path: str | None = None) -> dict:
    path = path or config.CTI_CACHE
    if not os.path.exists(path):
        return {"present": False}
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        meta = dict(conn.execute("SELECT key, value FROM meta").fetchall())
        by_type = conn.execute(
            "SELECT type, confidence, COUNT(*) FROM ioc GROUP BY type, confidence"
        ).fetchall()
        by_source = conn.execute(
            "SELECT source, COUNT(*) c FROM ioc GROUP BY source ORDER BY c DESC"
        ).fetchall()
    finally:
        conn.close()
    synced_at = meta.get("synced_at", "")
    age = None
    if synced_at:
        age = (datetime.now(timezone.utc)
               - datetime.fromisoformat(synced_at)).total_seconds() / 3600
    return {"present": True, "synced_at": synced_at,
            "age_hours": age, "stale": age is not None
            and age > config.CTI_EXPIRY_HOURS,
            "by_type": by_type, "by_source": by_source}


# ---------------------------------------------------------------------------

def sync(simulation: bool = False, catalogue: dict | None = None) -> dict:
    cat = catalogue or load_catalog()

    def everything():
        yield from misp_attributes()
        yield from blocklists(cat)

    if simulation:
        count = {}
        for ioc in everything():
            count[ioc["confidence"]] = count.get(ioc["confidence"], 0) + 1
        return count
    return write_cache(everything())


def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--feeds", action="store_true",
                        help="declares/enables the feeds in MISP, then refreshes them")
    parser.add_argument("--state", action="store_true",
                        help="content and freshness of the IOC cache")
    parser.add_argument("--test", metavar="IOC",
                        help="queries the cache on a value")
    parser.add_argument("--simulation", action="store_true",
                        help="counts the IOCs without writing the cache")
    args = parser.parse_args()

    if args.state:
        e = state()
        if not e["present"]:
            sys.exit(f"cache missing: {config.CTI_CACHE} — run `python -m soc_agent.cti`")
        print(f"cache       {config.CTI_CACHE}")
        print(f"synced      {e['synced_at']} ({e['age_hours']:.1f} h)"
              + ("  ** STALE **" if e["stale"] else ""))
        for type_, confidence, n in e["by_type"]:
            print(f"  {type_:8} {confidence:8} {n:>8}")
        print("sources:")
        for source, n in e["by_source"]:
            print(f"  {source:30} {n:>8}")
        return

    if args.test:
        guessed_type = next((t for t in ("ip", "hash", "url", "domain")
                            if normalize(t, args.test)), None)
        if not guessed_type:
            sys.exit(f"unusable value: {args.test}")
        results = query(normalize(guessed_type, args.test))
        print(json.dumps(results, indent=2, ensure_ascii=False)
              if results else "no match")
        return

    if args.feeds:
        summary = bootstrap_feeds(simulation=args.simulation)
        log.info("MISP feeds: %d created, %d updated, %d unchanged",
                 len(summary["created"]), len(summary["updated"]),
                 len(summary["unchanged"]))
        refresh_feeds(simulation=args.simulation)
        return

    count = sync(simulation=args.simulation)
    log.info("IOC cache%s: %s", " (simulation)" if args.simulation else "",
             ", ".join(f"{k}={v}" for k, v in sorted(count.items())) or "empty")


if __name__ == "__main__":
    main()
