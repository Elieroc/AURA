"""Does every log source land in its index? If not, create the index set.

Wazuh has no notion of an "index per agent": routing happens by LOG TYPE, in a
painless script of the indexer's ingest pipeline
(`wazuh/config/wazuh_cluster/alerts-pipeline.json`). A source no branch
recognises lands in `wazuh-alerts-4.x-*` without a single message: no error on
the Wazuh side, no missing alert, just a log type with no index of its own — and,
if `INDEXER_ALERT_INDICES` was forgotten at the same time, an AI blind to that
sensor. That trap struck three times (wazuh-linux/web, then wazuh-yara and
wazuh-firewall on 2026-07-29).

This module turns it into a permanent control, backed onto the watchdog:

    observe   -> what the indexer actually received over 24 h, per source
    classify  -> routed / unrouted / drifting / silent
    name      -> a conventional `wazuh-<suffix>` index (LLM plus validation)
    apply     -> the FIVE pieces of an index set, not just one

An index set is not an index. Creating `wazuh-jellyfin` implies:

  1. the routing branch in the ingest pipeline (otherwise nothing enters it);
  2. the `soc-ai-routing` template (otherwise a default mapping, fields as text);
  3. the `aura-retention` ISM policy (otherwise the index is never purged);
  4. the index list read by ingestion (otherwise the AI does not see it);
  5. the dashboard index pattern (otherwise invisible in Discover).

Point 1 undoes itself: the pipeline file is bind-mounted onto the manager's
filebeat module, and filebeat PUSHES IT BACK on every start. A branch set through
the API therefore disappears on the next `docker compose up`. Hence the principle
of this module: the expected pipeline is RECOMPUTED on every pass from the
`routing_sources` table, compared with the one running, and reapplied as soon as
it diverges. Filebeat overwriting it repairs itself in two minutes.

The IRIS anomalies produced here stay in French: analysts read them.

    python -m soc_agent.routing           # source state, writes nothing
    python -m soc_agent.routing --apply   # creates the missing index sets
"""

from __future__ import annotations

import argparse
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
import requests
from psycopg.rows import dict_row

from . import config, llm

log = logging.getLogger(__name__)

PROMPTS = Path(__file__).parent / "prompts"

# Tags of the pipeline's two routing processors. `routing-static` is set in
# alerts-pipeline.json and serves as the INSERTION POINT: the learned branches go
# RIGHT AFTER it.
#
# The reverse order looked obvious and is wrong — verified on the production
# pipeline on 2026-08-14. The painless `return` only exits the CURRENT SCRIPT,
# not the pipeline: a processor placed before may write `ctx._index`, the static
# script that follows rewrites it behind. A learned branch
# `pam -> wazuh-endpoint` inserted before therefore went back to wazuh-linux,
# without a single error. After the static one, the specific branch wins over the
# catch-all classification by OS, which is precisely what we want; the YARA
# script deliberately keeps the last word.
#
# Fallback on the description when the tag is missing: production may still run a
# pipeline predating this work. If NEITHER is found we refuse to write —
# inserting blindly into the pipeline that carries every SOC alert is not an
# acceptable risk.
TAG_STATIC = "routing-static"
TAG_LEARNED = "routing-learned"
_DESC_STATIC = "routes the agent alerts"

# --------------------------------------------------------------------------
# What is NOT a log source
# --------------------------------------------------------------------------
#
# The SOC constantly produces alerts that come from no log sensor: file
# integrity, configuration audit, rootcheck, agent state, vulnerabilities,
# VirusTotal. They are normal in `wazuh-alerts-4.x-*` — they concern EVERY agent
# and have no log type of their own. Without this allowlist, the module would
# propose creating `wazuh-syscheck` on the very first pass, on 1,800 alerts a
# day.
DECODERS_CROSS_CUTTING = frozenset({
    "ossec", "rootcheck", "sca", "wazuh", "agent-upgrade", "syscollector",
    "vulnerability-detector", "active-response",
})

# FIM does not decode under a single name: `syscheck_deleted`,
# `syscheck_integrity_changed`, `syscheck_registry_value_modified`... Observed in
# production on 2026-08-14, six distinct decoders, 226 alerts in 24 h — that is
# six index-set proposals on the first pass if we only reason on exact names. The
# prefix is the only form that survives a seventh being added.
PREFIXES_CROSS_CUTTING = ("syscheck", "sca_", "rootcheck", "wazuh-", "agent-")


def _cross_cutting(decoder: str) -> bool:
    return (decoder in DECODERS_CROSS_CUTTING
            or decoder.startswith(PREFIXES_CROSS_CUTTING))

GROUPS_CROSS_CUTTING = frozenset({
    "ossec", "rootcheck", "sca", "syscheck", "syscheck_entry_added",
    "syscheck_entry_modified", "syscheck_entry_deleted", "syscheck_file",
    "syscheck_registry", "wazuh", "agent_flooding", "virustotal",
    "vulnerability-detector", "soc_selfcheck", "attacks", "gdpr", "hipaa",
    "nist_800_53", "pci_dss", "tsc", "mitre",
})

# GENERIC decoders: they decode a format, not a source. `json` serves AdGuard,
# Suricata and Wazuh's internal modules all at once — it cannot be a source key.
# For those, the criterion falls back to the rule group, exactly as the static
# routing already does (see its comment: "routed on rule.groups not
# decoder.name").
#
# `windows_eventchannel` is deliberately ABSENT although it is just as generic:
# its alerts carry dozens of groups (sysmon_event1, authentication_failed,
# policy_changed...) which would become as many false "sources" for one and the
# same index. They are already routed by OS.
DECODERS_AMBIGUOUS = frozenset({"json", "syslog"})

# Suffixes we cannot reuse: they are already stack indices, and the
# `wazuh-<suffix>-*` pattern would swallow their content.
SUFFIXES_RESERVED = frozenset({
    "alerts", "archives", "monitoring", "statistics", "states", "ai", "voc",
    "agent", "manager", "indexer", "dashboard", "custom", "all",
})

# CLOSED vocabulary of generic sources. The model picks inside it, or it does
# not pick: that is the only guarantee a Fortinet firewall does not open a
# `fortinet` index next to `firewall`. A generic name outside the list is treated
# as an invalid answer, not as a proposal.
FAMILIES_GENERIC = frozenset({
    "firewall", "ids", "web", "proxy", "dns", "vpn", "mail", "database",
    "auth", "edr", "cloud", "container", "backup", "printer", "voip",
    "wireless", "storage", "iot", "ot", "endpoint",
})

_SUFFIX = re.compile(r"^[a-z]{2,20}$")
# What may enter the generated painless code. Deliberately narrow: these values
# come from the indexed data, and they end up in a single-quoted string in the
# middle of a script executed by the indexer.
_CRITERION = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
# Dated suffix of a Wazuh index: `wazuh-linux-2026.08.14` -> `wazuh-linux`.
_DATE_INDEX = re.compile(r"-\d{4}\.\d{2}\.\d{2}$")


# --------------------------------------------------------------------------
# Indexer
# --------------------------------------------------------------------------

def _indexer(method: str, path: str, body: dict | None = None,
             timeout: int = 60) -> requests.Response:
    return requests.request(
        method, f"{config.INDEXER_URL}{path}",
        auth=(config.INDEXER_USER, config.INDEXER_PASSWORD),
        json=body,
        verify=config.INDEXER_CA if config.INDEXER_VERIFY_TLS else False,
        timeout=timeout)


def _base_index(name: str) -> str:
    """Prefix of a dated index, without its date."""
    return _DATE_INDEX.sub("", name)


def _key(criterion_type: str, value: str) -> str:
    return f"{criterion_type}:{value}"


# --------------------------------------------------------------------------
# Observation
# --------------------------------------------------------------------------

# What we keep of an alert as a witness. The whole document would be needlessly
# heavy in database, but ENOUGH is needed for `simulate` to reproduce the
# routing: the decoder and the groups decide, `timestamp` builds the dated index
# name, `agent` serves the static script's routing by OS.
_FIELDS_WITNESS = ["timestamp", "decoder", "rule.id", "rule.level",
                  "rule.groups", "rule.description", "agent", "location",
                  "data.win"]


def _agg_sources(window_h: int) -> dict:
    """The "who writes where" aggregation over the window.

    Two aggregations in one query: by decoder for the normal case, and by rule
    group for the generic decoders, which do not identify their source. `_index`
    is an aggregatable metadata field — it says where the alert ACTUALLY landed,
    the only truth that counts here.
    """
    under_aggs = {
        "idx": {"terms": {"field": "_index", "size": 20}},
        "ex": {"top_hits": {"size": 1, "_source": {"includes": _FIELDS_WITNESS}}},
    }
    body = {
        "size": 0,
        "query": {"bool": {
            "filter": [{"range": {"@timestamp": {"gte": f"now-{window_h}h"}}}],
            # The manager (agent 000) is excluded from the routing by OS in the
            # static script: its alerts deliberately stay in the default index.
            # Counting them here would make perfectly routed sources look like
            # orphans — measured on `web-accesslog`, whose agent 000 alerts (426
            # over 7 d) outnumbered those of the real web agents.
            "must_not": [{"term": {"agent.id": "000"}}],
        }},
        "aggs": {
            "by_decoder": {
                "terms": {"field": "decoder.name", "size": 300},
                "aggs": {**under_aggs,
                         "grp": {"terms": {"field": "rule.groups", "size": 20}}},
            },
            "by_group": {
                "filter": {"terms": {"decoder.name": sorted(DECODERS_AMBIGUOUS)}},
                "aggs": {"src": {"terms": {"field": "rule.groups", "size": 200},
                                 "aggs": under_aggs}},
            },
        },
    }
    r = _indexer("POST", f"/{read_indices()}/_search", body)
    r.raise_for_status()
    return r.json()["aggregations"]


def observed_sources(window_h: int | None = None) -> list[dict]:
    """The log sources seen over the window, with their majority index.

    A pure function in the useful sense: it reads the indexer and decides
    nothing. The output ordering is deterministic (by key), so two successive
    passes produce the same pipeline rendering — see `_learned_script`.
    """
    aggs = _agg_sources(window_h or config.ROUTING_WINDOW_HOURS)
    sources: dict[str, dict] = {}

    def add(criterion_type: str, value: str, bucket: dict) -> None:
        if not _CRITERION.match(value or ""):
            # A value we could not reinject cleanly into the painless has no
            # business in this table: we log it rather than silently leaving it
            # aside.
            log.warning("source ignored, non-compliant criterion: %s=%r",
                        criterion_type, value)
            return
        index = [(_base_index(b["key"]), b["doc_count"])
                 for b in bucket["idx"]["buckets"]]
        total: dict[str, int] = {}
        for base, n in index:
            total[base] = total.get(base, 0) + n
        if not total:
            return
        majority = max(total.items(), key=lambda kv: kv[1])[0]
        hits = bucket["ex"]["hits"]["hits"]
        sources[_key(criterion_type, value)] = {
            "source_key": _key(criterion_type, value),
            "criterion_type": criterion_type,
            "criterion_value": value,
            "volume": bucket["doc_count"],
            "index_observe": majority,
            "index_repartition": total,
            "groups": [b["key"] for b in bucket.get("grp", {}).get("buckets", [])],
            "example": hits[0]["_source"] if hits else None,
        }

    for bucket in aggs["by_decoder"]["buckets"]:
        name = bucket["key"]
        if _cross_cutting(name) or name in DECODERS_AMBIGUOUS:
            continue
        add("decoder", name, bucket)

    for bucket in aggs["by_group"]["src"]["buckets"]:
        group = bucket["key"]
        if group in GROUPS_CROSS_CUTTING:
            continue
        add("groups", group, bucket)

    return sorted(sources.values(), key=lambda s: s["source_key"])


# --------------------------------------------------------------------------
# Classement
# --------------------------------------------------------------------------

def classify(conn, observed: list[dict]) -> dict[str, list[dict]]:
    """Files every observed source into one of four states.

    - `new`    : nothing routes them, they fall into the default index.
    - `drifts` : a known source no longer landing where it should. That is the
                 signature of an overwritten pipeline (filebeat on manager start)
                 or of a rule that changed groups.
    - `silent` : an established source from which nothing arrives any more.
    - `ok`     : routed where it is meant to be.

    A deliberate side effect: sources ALREADY correctly routed by a static branch
    of the pipeline are recorded along the way (`named_by='static'`). That is the
    bootstrap — it happens by observation rather than through a hand-copied list,
    which would have drifted from the pipeline on its first change.
    """
    known = {r["source_key"]: r for r in conn.execute(
        "SELECT * FROM routing_sources").fetchall()}
    res: dict[str, list[dict]] = {"new": [], "drifts": [], "ok": [],
                                 "silent": []}
    default = config.ROUTING_DEFAULT_INDEX

    for s in observed:
        record = known.get(s["source_key"])
        if record is None:
            if s["index_observe"] != default:
                # Already routed by the static pipeline: we record it as is.
                # Its expected index becomes what we observe, which arms drift
                # detection from then on.
                _record_static(conn, s)
                res["ok"].append(s)
            elif s["volume"] >= config.ROUTING_BASELINE_MIN:
                res["new"].append(s)
            continue

        _view(conn, s)
        if record["status"] == "refused":
            continue
        expected = record["index_base"]
        if s["index_observe"] == expected:
            res["ok"].append({**s, "expected_index": expected})
        elif record["status"] == "proposed" and s["index_observe"] == default:
            # Named but not applied yet: it MUST fall into the default index,
            # that is not a drift.
            res["new"].append({**s, "known": record})
        elif s["volume"] >= config.ROUTING_DRIFT_MIN:
            res["drifts"].append({**s, "expected_index": expected,
                                  "known": record})

    seen = {s["source_key"] for s in observed}
    limit = datetime.now(timezone.utc) - timedelta(
        hours=config.ROUTING_SILENCE_HOURS)
    # One flow is often described by several criteria: Suricata alone carries
    # the groups `suricata`, `ids` and `command_and_control`, all three routed to
    # wazuh-firewall. Reporting them separately would produce three alerts for a
    # single outage. The question the analyst cares about is the INDEX one
    # anyway: "nothing arrives in wazuh-firewall any more". So we keep, per
    # index, only the biggest source — the one whose silence is most
    # significant.
    by_index: dict[str, dict] = {}
    for key, r in known.items():
        if key in seen or r["status"] != "applied":
            continue
        if r["volume_ref"] < config.ROUTING_BASELINE_MIN or r["last_seen"] > limit:
            continue
        if any(s["index_observe"] == r["index_base"] for s in observed):
            # The index still receives, through another source: it is not the
            # index that is silent, it is that criterion that no longer matches.
            # The case of a rule that changed groups, already covered by drift.
            continue
        candidate = {
            "source_key": key, "criterion_type": r["criterion_type"],
            "criterion_value": r["criterion_value"], "expected_index": r["index_base"],
            "volume": r["volume_ref"], "last_seen": r["last_seen"], "known": r,
        }
        guard = by_index.get(r["index_base"])
        if guard is None or candidate["volume"] > guard["volume"]:
            by_index[r["index_base"]] = candidate
    res["silent"] = sorted(by_index.values(), key=lambda m: m["source_key"])
    return res


def _record_static(conn, s: dict) -> None:
    conn.execute(
        """INSERT INTO routing_sources
               (source_key, criterion_type, criterion_value, index_base, kind,
                status, named_by, justification, volume_ref, example,
                applied_at)
           VALUES (%s, %s, %s, %s, 'generic', 'applied', 'static',
                   'Routing already present in alerts-pipeline.json, discovered '
                   'by observation.', %s, %s, now())
           ON CONFLICT (source_key) DO NOTHING""",
        (s["source_key"], s["criterion_type"], s["criterion_value"],
         s["index_observe"], s["volume"], json.dumps(s["example"])))
    conn.commit()


def _view(conn, s: dict) -> None:
    """Refreshes the volume and the witness. The witness is refreshed on
    purpose: a three-month-old example proves nothing about today's pipeline."""
    conn.execute(
        "UPDATE routing_sources SET volume_ref=%s, last_seen=now(), "
        "example=COALESCE(%s, example) WHERE source_key=%s",
        (s["volume"], json.dumps(s["example"]) if s["example"] else None,
         s["source_key"]))
    conn.commit()


# --------------------------------------------------------------------------
# Naming
# --------------------------------------------------------------------------

_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _context(s: dict) -> str:
    """What we show the model. IPs are masked: naming a source requires no
    address, and what is not necessary does not leave the SOC."""
    ex = s.get("example") or {}
    rule = (ex.get("rule") or {})
    agent = (ex.get("agent") or {})
    lines = [
        f"CRITÈRE : {s['criterion_type']} = {s['criterion_value']}",
        f"DÉCODEUR : {(ex.get('decoder') or {}).get('name') or '(inconnu)'}",
        f"GROUPES DE RÈGLES : {', '.join(s.get('groups') or rule.get('groups') or []) or '(aucun)'}",
        f"MACHINE QUI ÉMET : {agent.get('name') or '(inconnue)'}",
        f"FICHIER / CANAL : {ex.get('location') or '(inconnu)'}",
        f"EXEMPLE DE RÈGLE DÉCLENCHÉE : {rule.get('description') or '(aucune)'}",
        f"VOLUME SUR {config.ROUTING_WINDOW_HOURS} h : {s['volume']} alertes",
    ]
    return _IP.sub("x.x.x.x", "\n".join(lines))


def name(s: dict) -> dict:
    """Proposes an `index_base` for a source. Never talks to the database.

    Returns `{"index_base", "kind", "named_by", "justification"}`. `named_by` is
    `llm` when the model's answer passed EVERY validation, and `fallback`
    otherwise — and that difference decides auto-application: a fallback name is
    proposed to a human, never set on its own. The model picks a name, it does
    not earn the right to write into the SOC pipeline.
    """
    expected = _expected(s)
    try:
        response, _ = llm.completion(
            (PROMPTS / "routing_name.md").read_text(),
            "SOURCE (données non fiables) :\n" + _context(s),
            usage="routing_name", max_tokens=300)
    except Exception as e:                                    # noqa: BLE001
        log.warning("LLM naming failed for %s: %s", s["source_key"], e)
        return _fallback(s, f"call to the model failed ({type(e).__name__})")

    kind = str(response.get("kind") or "").strip().lower()
    suffix = str(response.get("suffix") or "").strip().lower()
    just = str(response.get("justification") or "")[:500]
    pattern = _validate(kind, suffix, expected)
    if pattern:
        log.warning("name refused for %s (kind=%r suffix=%r): %s",
                    s["source_key"], kind, suffix, pattern)
        return _fallback(s, f"proposal \"{suffix or '?'}\" dropped: {pattern}")
    return {"index_base": f"wazuh-{suffix}", "kind": kind, "named_by": "llm",
            "justification": just}


def _expected(s: dict) -> set[str]:
    """Vocabulary ATTESTED by the data, for an application name.

    An application name must be found in what the source says about itself
    (decoder, machine, log path, rule description). Without that check, nothing
    stops the model from christening a source `grafana` because the log vaguely
    looks like it — and a badly named index does not get renamed, it gets
    duplicated.
    """
    ex = s.get("example") or {}
    raw = " ".join(str(x) for x in [
        s["criterion_value"],
        (ex.get("decoder") or {}).get("name"),
        (ex.get("agent") or {}).get("name"),
        ex.get("location"),
        (ex.get("rule") or {}).get("description"),
    ] if x)
    return set(re.findall(r"[a-z]{2,20}", raw.lower()))


def _validate(kind: str, suffix: str, expected: set[str]) -> str | None:
    """Reason for rejection, or None when the name is acceptable."""
    if kind == "unknown":
        return "the model could not classify the source"
    if kind not in ("generic", "application"):
        return f"unexpected kind ({kind!r})"
    if not _SUFFIX.match(suffix):
        return "non-compliant suffix shape (a-z, 2 to 20 characters)"
    if suffix in SUFFIXES_RESERVED:
        return "suffix reserved by the Wazuh stack"
    if kind == "generic" and suffix not in FAMILIES_GENERIC:
        return "generic family outside the closed vocabulary"
    if kind == "application":
        if suffix in FAMILIES_GENERIC:
            return "business family proposed as an application name"
        if suffix not in expected:
            return "application name no data of the source attests"
    return None


def _fallback(s: dict, pattern: str) -> dict:
    """Deterministic name when the model did not decide. Stays `proposed`: it is
    a deliberate stopping point, not a silent fallback default."""
    suffix = re.sub(r"[^a-z]", "", s["criterion_value"].lower())[:20] or "misc"
    return {"index_base": f"wazuh-{suffix}", "kind": "generic",
            "named_by": "fallback", "justification": pattern}


def propose(conn, s: dict) -> dict | None:
    """Names a new source and records it. Returns the row created.

    The name is asked of the model ONLY ONCE per source: the uniqueness of
    `source_key` guarantees it, and that is what makes this module free in steady
    state — a stable estate never calls the LLM here again.
    """
    already = conn.execute("SELECT * FROM routing_sources WHERE source_key=%s",
                        (s["source_key"],)).fetchone()
    if already:
        return already
    proposal = name(s)
    if conn.execute("SELECT 1 FROM routing_sources WHERE index_base=%s",
                    (proposal["index_base"],)).fetchone():
        # Collision: two sources sharing a business index is exactly the
        # intended effect (pfSense and Forti in `firewall`). So we reuse the
        # existing index without creating anything on the indexer side.
        log.info("source %s attached to the existing index %s",
                 s["source_key"], proposal["index_base"])
    r = conn.execute(
        """INSERT INTO routing_sources
               (source_key, criterion_type, criterion_value, index_base, kind,
                status, named_by, justification, volume_ref, example)
           VALUES (%s, %s, %s, %s, %s, 'proposed', %s, %s, %s, %s)
           ON CONFLICT (source_key) DO NOTHING
           RETURNING *""",
        (s["source_key"], s["criterion_type"], s["criterion_value"],
         proposal["index_base"], proposal["kind"], proposal["named_by"],
         proposal["justification"],
         s["volume"], json.dumps(s["example"]))).fetchone()
    conn.commit()
    if r:
        log.warning("UNROUTED SOURCE: %s (%d alerts) -> %s proposed by %s — %s",
                    s["source_key"], s["volume"],
                    proposal["index_base"], proposal["named_by"],
                    proposal["justification"])
    return r


# --------------------------------------------------------------------------
# Rendering the pipeline
# --------------------------------------------------------------------------

def learned_routes(conn) -> list[dict]:
    """The routes WE generate. The `static` branches are excluded: they live in
    alerts-pipeline.json and must not be duplicated."""
    return conn.execute(
        "SELECT criterion_type, criterion_value, index_base FROM routing_sources "
        " WHERE status='applied' AND named_by <> 'static' "
        " ORDER BY criterion_type DESC, criterion_value").fetchall()


def _learned_script(routes: list[dict]) -> dict:
    """The generated painless processor.

    Two invariants hold everything else together:

    - the order is DETERMINISTIC (sorted in SQL), so two successive renderings
      are identical to the character. Without that, comparing with the pipeline
      in place would trigger a PUT on every pass, every two minutes;
    - the `decoder` tests come BEFORE the `groups` tests: the decoder identifies
      the source, the group only characterises it. A Suricata alert carrying the
      `dns` group must go to the firewall index, not the DNS one — the trap the
      static routing already documents.
    """
    lines = [
        "def dn = ctx.decoder?.name;",
        "def g = ctx.rule?.groups;",
        "if (ctx.timestamp == null || ctx.timestamp.length() < 10) { return; }",
        "def d = ctx.timestamp.substring(0,10).replace('-','.');",
    ]
    for r in routes:
        if not _CRITERION.match(r["criterion_value"]):
            raise ValueError(f"non-compliant criterion in database: {r!r}")
        if not re.match(r"^wazuh-[a-z]{2,20}$", r["index_base"]):
            raise ValueError(f"non-compliant index_base in database: {r!r}")
        test = (f"dn == '{r['criterion_value']}'" if r["criterion_type"] == "decoder"
                else f"g != null && g.contains('{r['criterion_value']}')")
        lines.append(f"if ({test}) {{ ctx._index = '{r['index_base']}-' + d; "
                      "return; }")
    return {"script": {
        "tag": TAG_LEARNED,
        "description": (
            "AURA routing: branches learned by soc_agent.routing, regenerated "
            "from the routing_sources table. Do not edit by hand — any change is "
            "overwritten on the watchdog's next pass. Placed AFTER the static "
            "routing: the painless `return` only exits the current script, so an "
            "earlier processor gets rewritten by the classification by OS that "
            "follows."),
        "lang": "painless",
        "ignore_failure": True,
        "source": "\n".join(lines),
    }}


def _without_learned(pipeline: dict) -> dict:
    """The pipeline stripped of our processor. That is the BASE.

    We never read alerts-pipeline.json from this container: the base is what
    filebeat actually pushed. The file may have changed on disk without the
    manager restarting; starting from the file would then apply a pipeline that
    is not the one in service.
    """
    return {**pipeline,
            "processors": [p for p in pipeline.get("processors", [])
                           if not _is_learned(p)]}


def _is_learned(processor: dict) -> bool:
    body = next(iter(processor.values()), {})
    return isinstance(body, dict) and body.get("tag") == TAG_LEARNED


def _insert_position(processors: list[dict]) -> int:
    """Right AFTER the static routing — see the TAG_STATIC comment."""
    for i, p in enumerate(processors):
        body = next(iter(p.values()), {})
        if not isinstance(body, dict):
            continue
        if body.get("tag") == TAG_STATIC:
            return i + 1
        if _DESC_STATIC in (body.get("description") or ""):
            return i + 1
    raise RuntimeError(
        "static routing processor not found in pipeline "
        f"\"{config.ROUTING_PIPELINE}\": refusing to insert blindly. Check "
        "alerts-pipeline.json (tag \"routing-static\").")


def render(base: dict, routes: list[dict]) -> dict:
    """Expected pipeline = base plus learned branches, inserted at the right
    place."""
    if not routes:
        return base
    procs = list(base.get("processors", []))
    procs.insert(_insert_position(procs), _learned_script(routes))
    return {**base, "processors": procs}


def _read_pipeline() -> dict:
    r = _indexer("GET", f"/_ingest/pipeline/{config.ROUTING_PIPELINE}")
    if r.status_code == 404:
        raise RuntimeError(
            f"pipeline \"{config.ROUTING_PIPELINE}\" missing from the indexer: "
            "the manager has not pushed it yet.")
    r.raise_for_status()
    return r.json()[config.ROUTING_PIPELINE]


# --------------------------------------------------------------------------
# Simulation: the guardrail before writing
# --------------------------------------------------------------------------

def witnesses(conn) -> list[dict]:
    """One real alert per applied source, with the index it must reach."""
    return conn.execute(
        "SELECT source_key, index_base, example FROM routing_sources "
        " WHERE status='applied' AND example IS NOT NULL "
        " ORDER BY source_key").fetchall()


# What filebeat adds and indexing does NOT keep. The `date_index_name`
# processor reads `fields.index_prefix` to build the default index name, and it
# is the only one of the pipeline with `ignore_failure: false`: without that
# field, every simulated document goes into the `on_failure` `drop` and EVERY
# witness comes back "lost". The field cannot come from the witness itself — a
# `remove` in the pipeline erases it before writing, so it is in no indexed
# document. It has to be set again here.
DEFAULT_PREFIX = f"{config.ROUTING_DEFAULT_INDEX}-"


def _message(example: dict) -> dict:
    if "fields" in example:
        return example
    return {**example, "fields": {"index_prefix": DEFAULT_PREFIX}}


def simulate(pipeline: dict, cases: list[dict]) -> list[str]:
    """Replays real alerts through the candidate pipeline. Returns the failures.

    This is not a comfort precaution. The pipeline ends with
    `on_failure: [{"drop": {}}]`: an invalid painless script raises no error, it
    makes every SOC alert DISAPPEAR. The simulation is therefore mandatory before
    every PUT, and a single failing witness is enough to cancel everything —
    including a witness with nothing to do with the source being added, since
    that is precisely the regression we are looking for.

    The document is presented as filebeat sends it: the whole alert in the
    `message` field, which the first processor unfolds at the root.
    """
    if not cases:
        return []
    docs = [{"_index": config.ROUTING_DEFAULT_INDEX, "_id": str(i),
             "_source": {"message": json.dumps(_message(c["example"]))}}
            for i, c in enumerate(cases)]
    r = _indexer("POST", "/_ingest/pipeline/_simulate",
                 {"pipeline": pipeline, "docs": docs})
    if not r.ok:
        return [f"simulation refused by the indexer ({r.status_code}): "
                f"{r.text[:300]}"]
    failures = []
    for c, res in zip(cases, r.json().get("docs", [])):
        doc = res.get("doc")
        if not doc:
            failures.append(f"{c['source_key']}: document LOST by the pipeline "
                          f"({str(res.get('error'))[:200]})")
            continue
        obtained = _base_index(doc.get("_index", ""))
        if obtained != c["index_base"]:
            failures.append(f"{c['source_key']}: expected {c['index_base']}, "
                          f"got {obtained}")
    return failures


# --------------------------------------------------------------------------
# Application: the five pieces
# --------------------------------------------------------------------------

TEMPLATE = "soc-ai-routing"


def _set_template(index_base: str) -> None:
    """Adds the pattern to the existing template, without rebuilding it.

    Read-mutate-write on purpose: the template carries the mappings and settings
    inherited from the stack. Regenerating it from a hard-coded model here would
    lose, at the first Wazuh version divergence, everything that had not been
    copied into it.
    """
    pattern = f"{index_base}-*"
    r = _indexer("GET", f"/_template/{TEMPLATE}")
    if not r.ok:
        raise RuntimeError(f"template {TEMPLATE} unreadable: {r.text[:200]}")
    body = r.json()[TEMPLATE]
    if pattern in body.get("index_patterns", []):
        return
    body["index_patterns"] = sorted(set(body["index_patterns"]) | {pattern})
    w = _indexer("PUT", f"/_template/{TEMPLATE}", body)
    if not w.ok:
        raise RuntimeError(f"template {TEMPLATE} refused: {w.text[:300]}")
    log.info("template %s: pattern %s added", TEMPLATE, pattern)


def _set_ism() -> None:
    """Reapplies the retention policy, which now reads the learned patterns (see
    retention.ism_patterns). Without this step the new index grows without ever
    being purged — a full disk is the outage that stops the whole SOC."""
    from . import retention
    retention.apply_ism()


def _set_index_pattern(index_base: str) -> None:
    """OpenSearch Dashboards index pattern. Deliberate best-effort.

    A failure here leaves a well-fed index invisible in Discover: annoying, not
    dangerous. We log and carry on — refusing to apply the routing because the
    dashboard did not answer would trade an invisibility for a blindness.
    """
    title = f"{index_base}-*"
    try:
        r = requests.post(
            f"{config.DASHBOARD_URL}/api/saved_objects/index-pattern/{title}",
            headers={"osd-xsrf": "true"},
            auth=(config.INDEXER_USER, config.INDEXER_PASSWORD),
            json={"attributes": {"title": title, "timeFieldName": "timestamp"}},
            verify=False, timeout=30)
        if r.ok:
            log.info("index pattern %s created in the dashboard", title)
        elif r.status_code == 409:
            log.debug("index pattern %s already present", title)
        else:
            log.warning("index pattern %s not created (%s): %s", title,
                        r.status_code, r.text[:200])
    except Exception as e:                                    # noqa: BLE001
        log.warning("dashboard unreachable for index pattern %s: %s",
                    title, e)


def apply(conn, source_key: str, dry_run: bool = False) -> dict:
    """Sets the five pieces of an index set, or explains why it does not.
    Idempotent: replayable with no side effect.

    The order matters. Template and ISM FIRST: they only apply to indices created
    AFTERWARDS, so setting them after the routing would leave the first day of
    alerts in an index with no mapping and no retention. Routing LAST, once
    everything is ready to receive it.
    """
    r = conn.execute("SELECT * FROM routing_sources WHERE source_key=%s",
                     (source_key,)).fetchone()
    if r is None:
        return {"ok": False, "reason": "unknown source"}
    if r["status"] == "applied":
        return {"ok": True, "reason": "already applied"}
    if r["named_by"] == "fallback":
        return {"ok": False, "reason": "fallback name: human arbitration required"}
    # The cap only applies to a GENUINELY new index set. Attaching a second
    # source to `wazuh-firewall` (a Fortinet next to the pfSense) creates
    # nothing: that is the nominal case of generic naming, and capping it would
    # punish exactly the behaviour we are trying to obtain.
    new = not conn.execute(
        "SELECT 1 FROM routing_sources WHERE index_base=%s AND status='applied'"
        "   AND source_key <> %s", (r["index_base"], source_key)).fetchone()
    if new and _cap_reached(conn):
        return {"ok": False, "reason":
                f"cap of {config.ROUTING_MAX_NEW_PER_DAY} creation(s) per 24 h "
                "reached"}

    # The candidate pipeline is computed BEFORE any write, and validated on the
    # witnesses of every source already applied: so we check at the same time
    # that the new branch works and that it breaks nothing.
    base = _without_learned(_read_pipeline())
    routes = list(learned_routes(conn)) + [{
        "criterion_type": r["criterion_type"], "criterion_value": r["criterion_value"],
        "index_base": r["index_base"]}]
    candidate = render(base, routes)
    cases = list(witnesses(conn))
    if r["example"]:
        cases.append({"source_key": r["source_key"], "index_base": r["index_base"],
                    "example": r["example"]})
    failures = simulate(candidate, cases)
    if failures:
        log.error("index set %s NOT applied — the simulation fails: %s",
                  r["index_base"], " | ".join(failures))
        return {"ok": False, "reason": "simulation failed: " + "; ".join(failures)}

    if dry_run:
        return {"ok": True, "reason": "dry-run: simulation passed, nothing written",
                "index_base": r["index_base"]}

    _set_template(r["index_base"])
    conn.execute("UPDATE routing_sources SET status='applied', applied_at=now()"
                 " WHERE source_key=%s", (source_key,))
    conn.commit()
    # ISM after the database switch: `ism_patterns()` reads the table.
    try:
        _set_ism()
    except Exception as e:                                    # noqa: BLE001
        log.warning("ISM policy not reapplied for %s: %s (the retention job "
                    "will set it again)", r["index_base"], e)
    _set_index_pattern(r["index_base"])
    _push_pipeline(candidate)
    _INDICES_CACHE["expire"] = None                       # see read_indices
    log.error("INDEX SET CREATED: %s for source %s (%s) — %s",
              r["index_base"], source_key, r["named_by"], r["justification"])
    return {"ok": True, "index_base": r["index_base"],
            "reason": "index set created"}


def _cap_reached(conn) -> bool:
    n = conn.execute(
        "SELECT count(*) c FROM routing_sources "
        " WHERE applied_at > now() - interval '24 hours' "
        "   AND named_by <> 'static'").fetchone()["c"]
    return n >= config.ROUTING_MAX_NEW_PER_DAY


def _push_pipeline(pipeline: dict) -> None:
    r = _indexer("PUT", f"/_ingest/pipeline/{config.ROUTING_PIPELINE}", pipeline)
    if not r.ok:
        raise RuntimeError(f"pipeline refused ({r.status_code}): {r.text[:300]}")
    log.info("pipeline %s updated (%d processors)", config.ROUTING_PIPELINE,
             len(pipeline.get("processors", [])))


def reconcile_pipeline(conn, dry_run: bool = False) -> str | None:
    """Does the pipeline in service actually carry our branches?

    This is the answer to filebeat overwriting it: on manager start, the filebeat
    module pushes alerts-pipeline.json back and erases everything we added.
    Without this control, the index sets created silently stop being fed — the
    exact outage we claim to watch for.

    Returns a description of the gap corrected, or None if everything was fine.
    """
    routes = list(learned_routes(conn))
    alive = _read_pipeline()
    if not routes:
        # No learned route: the pipeline must be exactly the base. If it still
        # carries our processor (last source refused, base restored from a
        # backup), it routes to indices that no longer have a template nor a
        # retention — we remove it.
        if not any(_is_learned(p) for p in alive.get("processors", [])):
            return None
        if dry_run:
            return "orphan learned processor (dry-run, not removed)"
        _push_pipeline(_without_learned(alive))
        return "orphan learned processor removed"
    expected = render(_without_learned(alive), routes)
    if json.dumps(expected, sort_keys=True) == json.dumps(alive, sort_keys=True):
        return None
    failures = simulate(expected, list(witnesses(conn)))
    if failures:
        log.error("pipeline diverging but NOT reapplied — the simulation "
                  "fails: %s", " | ".join(failures))
        return f"pipeline diverging, correction impossible: {'; '.join(failures)}"
    if dry_run:
        return "pipeline diverging (dry-run, not corrected)"
    _push_pipeline(expected)
    log.warning("PIPELINE REPAIRED: the %d learned branch(es) had disappeared "
                "(manager restart?)", len(routes))
    return f"{len(routes)} learned branch(es) reapplied"


# --------------------------------------------------------------------------
# What the rest of the pipeline consumes
# --------------------------------------------------------------------------

_INDICES_CACHE: dict = {"value": None, "expire": None}
_CACHE_S = 300


def applied_patterns(conn) -> list[str]:
    return [f"{r['index_base']}-*" for r in conn.execute(
        "SELECT DISTINCT index_base FROM routing_sources "
        " WHERE status='applied' ORDER BY index_base").fetchall()]


def read_indices() -> str:
    """Indices queried at ingestion: the static list UNION what has been created
    since.

    This is what closes, by construction, the historical blind spot: an index set
    created without being added to `INDEXER_ALERT_INDICES` is a sensor the AI
    does not see, without any error saying so. It is no longer a list to keep up
    to date, it is a consequence.

    Falls back on the static list at the slightest difficulty (missing table,
    unreachable database): ingestion must carry on even if this module does not
    answer.
    """
    now = datetime.now(timezone.utc)
    if _INDICES_CACHE["expire"] and _INDICES_CACHE["expire"] > now:
        return _INDICES_CACHE["value"]
    static = [p.strip() for p in config.INDEXER_ALERT_INDICES.split(",")
                 if p.strip()]
    try:
        with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
            patterns = applied_patterns(conn)
    except Exception as e:                                    # noqa: BLE001
        log.warning("learned patterns unreadable (%s): falling back on the "
                    "static list", e)
        patterns = []
    # `wazuh-alerts-4.x-*` is already covered by `wazuh-alerts-*` from the
    # static list; deduplicating avoids counting it twice in the search.
    every = list(dict.fromkeys(static + [p for p in patterns
                                         if not p.startswith("wazuh-alerts")]))
    # FINAL NEGATION, non-negotiable: the threat hunting space holds alerts
    # RESTORED from the archives (see hunting.py). Letting them in here would
    # have two consequences, both serious:
    #
    #  - ingestion would take them back, correlation would make incidents of them
    #    and triage would make IRIS cases — on facts ten months old, with
    #    autonomous remediation at the end;
    #  - routing would see their `decoder.name` land somewhere other than its
    #    expected index, hence a DRIFT, hence an IRIS alert for nothing.
    #
    # OpenSearch's `-pattern` syntax excludes afterwards: this line wins even if
    # someone puts `wazuh-*` in INDEXER_ALERT_INDICES. That is deliberate — the
    # protection must not depend on configuration discipline.
    every.append(f"-{config.HUNTING_INDEX_BASE}-*")
    value = ",".join(every)
    _INDICES_CACHE.update({"value": value,
                           "expire": now + timedelta(seconds=_CACHE_S)})
    return value


# --------------------------------------------------------------------------
# Full pass
# --------------------------------------------------------------------------

def reconcile(dry_run: bool | None = None) -> dict:
    """One pass: observe, classify, name, apply, repair.

    Called by the watchdog. Returns a report, and above all the list of ANOMALIES
    that remain afterwards — those become IRIS alerts, just like a silent sensor.
    """
    if dry_run is None:
        dry_run = not config.ROUTING_APPLY
    report: dict = {"new": [], "created": [], "anomalies": [],
                     "pipeline": None}
    if not config.ROUTING_ACTIVE:
        return report

    observed = observed_sources()
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        states = classify(conn, observed)
        report["ok"] = len(states["ok"])

        for s in states["new"]:
            line = propose(conn, s)
            if line is None:
                continue
            report["new"].append(dict(line))
            try:
                r = apply(conn, s["source_key"], dry_run=dry_run)
            except Exception as e:                            # noqa: BLE001
                # One source going wrong must not take the pass down: the
                # drifts and silent sources of the others still have to be
                # reported, and the pipeline still has to be reconciled.
                log.error("applying %s failed: %s", s["source_key"], e)
                r = {"ok": False, "reason": f"{type(e).__name__}: {e}"}
            if r["ok"] and not dry_run:
                report["created"].append(r.get("index_base"))
            else:
                report["anomalies"].append(_anomaly_source(s, line, r))

        for d in states["drifts"]:
            report["anomalies"].append(_anomaly_drift(d))
        for m in states["silent"]:
            report["anomalies"].append(_anomaly_silent(m))

        try:
            report["pipeline"] = reconcile_pipeline(conn, dry_run=dry_run)
        except Exception as e:                                # noqa: BLE001
            log.error("pipeline reconciliation impossible: %s", e)
            report["pipeline"] = f"failed: {e}"
    return report


# The anomalies come out in the SHAPE OF A SILENT SENSOR (same keys): they
# therefore go through the watchdog's open/close loop with no special case, since
# it already knows how to hold a state, create the IRIS alert and close it. Same
# reasoning as for the disk guardrail.
AGENT_SOC = "000"


def _anomaly(sensor: str, title: str, note: str, severity: str,
              volume: int, last: datetime | None = None) -> dict:
    now = datetime.now(timezone.utc)
    return {"agent_id": AGENT_SOC, "agent_name": "wazuh.manager",
            "sensor": sensor, "title": title, "note": note,
            "severity": severity, "volume": volume, "threshold": 0,
            "last": last or now, "horizon": now}


def _anomaly_source(s: dict, line: dict, r: dict) -> dict:
    return _anomaly(
        f"routing:{s['source_key']}",
        f"[ROUTAGE] source {s['source_key']} sans index dédié",
        "\n".join([
            "SOURCE DE LOG NON ROUTÉE",
            "",
            f"La source {s['source_key']} a produit {s['volume']} alertes sur "
            f"{config.ROUTING_WINDOW_HOURS} h et atterrit dans "
            f"{config.ROUTING_DEFAULT_INDEX}, l'index fourre-tout de Wazuh.",
            "",
            f"  Index proposé   : {line['index_base']}",
            f"  Nommé par       : {line['named_by']}",
            f"  Justification   : {line['justification']}",
            f"  Non appliqué    : {r.get('reason')}",
            "",
            "Conséquence : ces alertes sont mélangées à celles de tous les "
            "autres capteurs, sans mapping ni rétention propres, et les "
            "tableaux de bord ne peuvent pas les isoler.",
            "",
            "Pour trancher à la main :",
            "",
            "  python -m soc_agent.routing --appliquer "
            f"--source {s['source_key']}",
            "  python -m soc_agent.routing --refuser "
            f"--source {s['source_key']}",
            "",
            "-- Ouvert par le watchdog AURA. Se referme dès que la source est "
            "routée.",
        ]),
        "Medium", s["volume"])


def _anomaly_drift(d: dict) -> dict:
    distribution = ", ".join(f"{k}={v}" for k, v in
                            sorted(d["index_repartition"].items(),
                                   key=lambda kv: -kv[1]))
    return _anomaly(
        f"routing:{d['source_key']}",
        f"[ROUTAGE] {d['source_key']} n'atterrit plus dans {d['expected_index']}",
        "\n".join([
            "ROUTAGE DÉVIÉ",
            "",
            f"La source {d['source_key']} devrait alimenter "
            f"{d['expected_index']} ; ses alertes partent dans "
            f"{d['index_observe']}.",
            "",
            f"  Répartition observée : {distribution}",
            f"  Volume sur {config.ROUTING_WINDOW_HOURS} h : {d['volume']}",
            "",
            "Deux causes possibles, dans cet ordre de probabilité :",
            "",
            "1. Le pipeline d'ingest a été écrasé. Filebeat repousse "
            "alerts-pipeline.json à chaque démarrage du manager et efface les "
            "branches ajoutées. Le watchdog les réapplique tout seul au "
            "passage suivant — si cette alerte persiste, c'est que la "
            "réapplication échoue (voir les logs de soc-agent-watchdog).",
            "2. Une règle a changé de groupes, ou une règle native sœur gagne "
            "désormais sur la règle locale. Le critère de routage doit alors "
            "être revu : c'est le piège documenté du routage par rule.groups.",
            "",
            "-- Ouvert par le watchdog AURA. Se referme quand la source "
            "retrouve son index.",
        ]),
        "High", d["volume"])


def _anomaly_silent(m: dict) -> dict:
    return _anomaly(
        f"silent-source:{m['source_key']}",
        f"[SOURCE MUETTE] {m['source_key']} n'écrit plus dans "
        f"{m['expected_index']}",
        "\n".join([
            "SOURCE DE LOG MUETTE",
            "",
            f"La source {m['source_key']} alimentait {m['expected_index']} "
            f"({m['volume']} alertes à la dernière observation). Plus rien "
            f"depuis {m['last_seen']:%Y-%m-%d %H:%M} UTC.",
            "",
            f"  Seuil de silence : {config.ROUTING_SILENCE_HOURS} h",
            "",
            "Un index qui cesse d'être alimenté ne produit aucune erreur : "
            "l'index du jour n'est simplement plus créé, et le tableau de bord "
            "correspondant reste vert sur une période vide. Rien d'autre que "
            "ce contrôle ne le signale.",
            "",
            "Où regarder :",
            "",
            "1. Le bloc <localfile> de l'agent lit-il toujours le bon fichier ? "
            "Un conteneur recréé change souvent de chemin de log.",
            "2. L'application écrit-elle encore ? (rotation, niveau de log "
            "abaissé, service arrêté)",
            "3. Le collecteur de l'agent est-il figé ? "
            "(`wazuh-control status`, plusieurs wazuh-logcollector empilés)",
            "",
            "-- Ouvert par le watchdog AURA. Se referme dès que la source "
            "réémet.",
        ]),
        "Medium", m["volume"], m["last_seen"])


# --------------------------------------------------------------------------

def _table(conn) -> None:
    lines = conn.execute(
        "SELECT source_key, index_base, status, named_by, kind, volume_ref, "
        "       last_seen FROM routing_sources ORDER BY status, source_key"
    ).fetchall()
    if not lines:
        print("No source recorded.")
        return
    for r in lines:
        print(f"  {r['source_key']:<34} -> {r['index_base']:<20} "
              f"{r['status']:<9} {r['named_by']:<9} {r['kind']:<11} "
              f"{r['volume_ref']:>7} vue {r['last_seen']:%m-%d %H:%M}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--apply", action="store_true",
                   help="create the missing index sets (otherwise read-only)")
    p.add_argument("--observe", action="store_true",
                   help="who writes where, with no database, model nor write")
    p.add_argument("--source", help="act on this source_key only")
    p.add_argument("--refuse", action="store_true",
                   help="mark --source as refused, stop proposing it")
    p.add_argument("--index", help="force the index_base of --source "
                                   "(human arbitration, bypasses the LLM)")
    args = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.observe:
        # The only mode that touches NEITHER the database NOR the model: run it
        # first on an existing installation, before allowing any write. It
        # answers the only question that matters at the start — who writes where,
        # and who writes nowhere in particular.
        for s in observed_sources():
            default = s["index_observe"] == config.ROUTING_DEFAULT_INDEX
            print(f"  {'!' if default else ' '} {s['source_key']:<34} "
                  f"-> {s['index_observe']:<22} {s['volume']:>7} alertes"
                  + ("   <-- no dedicated index" if default else ""))
        return

    if args.refuse or args.index:
        if not args.source:
            p.error("--refuse and --index require --source")
        with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
            if args.refuse:
                conn.execute("UPDATE routing_sources SET status='refused' "
                             "WHERE source_key=%s", (args.source,))
            else:
                if not re.match(r"^wazuh-[a-z]{2,20}$", args.index):
                    p.error("--index must have the form wazuh-<suffix>")
                conn.execute(
                    "UPDATE routing_sources SET index_base=%s, "
                    "named_by='human', status='proposed' WHERE source_key=%s",
                    (args.index, args.source))
            conn.commit()
            r = apply(conn, args.source) if args.index else None
        print(r or "done")
        return

    if args.apply:
        report = reconcile(dry_run=False)
    else:
        report = reconcile(dry_run=True)
    print(f"{report['ok']} source(s) correctly routed, "
          f"{len(report['new'])} new, "
          f"{len(report['created'])} index set(s) created, "
          f"{len(report['anomalies'])} anomaly/anomalies")
    if report["pipeline"]:
        print(f"  pipeline: {report['pipeline']}")
    for a in report["anomalies"]:
        print(f"  ! {a['title']}")
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        _table(conn)


if __name__ == "__main__":
    main()
