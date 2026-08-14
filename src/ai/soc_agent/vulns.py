"""VOC: life cycle of the estate vulnerabilities, and exposure per machine.

Wazuh knows how to DETECT vulnerabilities (Vulnerability Detection module) but
not how to TRACK their management. Its `wazuh-states-vulnerabilities-*` index is
a state index: when a package is fixed, the document is deleted. So one reads
"where we stand" there permanently, never "are we making progress". The three
questions of a VOC — is the debt going down, how long does a fix take, who is
past the deadline — have no answer in that index, and the 23504+ alerts do not
help: they date the DETECTION, never the resolution.

This module builds the missing history:

  scan  -> `vulnerabilities` table (journal: first_seen / last_seen / fixed_at)
        -> `wazuh-voc-*` index (time series for the VOC dashboard)
        -> `exposure()` (risk score of a machine, for the IRIS cases)

The risk score weights the vulnerability load by the CMDB priority of the
machine (cf. assets.py): counting CVEs with equal weight on the domain
controller and on a lab workstation makes patching happen in the wrong order.

Note on the exported field names: the documents of the `wazuh-voc-*` indices keep
their original French field names (`voc.hors_sla_total`, `voc.niveau`,
`asset.priorite_label`...). They are a data schema, not code: the documents
already indexed carry them, and the VOC dashboard reads them. Renaming them would
cut the panels off from their history.

    python -m soc_agent.vulns                  # scan + export
    python -m soc_agent.vulns --state          # exposure of the estate, no write
    python -m soc_agent.vulns --agent 013      # detail of one machine
    python -m soc_agent.vulns --simulation     # shows the documents, writes nothing
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import re
from datetime import datetime, timezone

import psycopg
import requests
import urllib3
from psycopg.rows import dict_row

from . import assets, config

log = logging.getLogger("vulns")

if not config.INDEXER_VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# --------------------------------------------------------------------------
# Severity and weights
# --------------------------------------------------------------------------

# Official CVSS v3 thresholds, to reclassify a vulnerability whose feed gives NO
# severity but gives a score. Measured on 2026-08-12: 334 CVEs per Debian host
# arrive with an empty `vulnerability.severity`. Leaving them all at the
# "unknown" weight amounts to throwing away information we actually have.
_THRESHOLDS_CVSS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"))


def effective_severity(severity: str | None, score_base: float | None) -> str:
    """Usable severity: the feed's, else the one deduced from the CVSS score."""
    s = (severity or "").strip().lower()
    if s and s not in ("untriaged", "unknown", "none"):
        return s
    if score_base is not None:
        for threshold, name in _THRESHOLDS_CVSS:
            if score_base >= threshold:
                return name
    return ""


def weight(severity: str) -> float:
    return config.VULN_SEVERITY_WEIGHT.get(severity, 0.5)


def sla_days(severity: str, priority: int) -> int | None:
    """Expected patching delay. None if the severity is not classified — we do
    not demand a deadline we were unable to set ourselves."""
    line = config.VOC_SLA_DAYS.get(severity)
    if not line:
        return None
    return line[max(1, min(4, int(priority))) - 1]


def risk_score(charge: float) -> int:
    """Exposure index 0-100 of a machine, from its weighted load.

    Log-compressed (cf. `VOC_MAX_LOAD`). The downside is accepted and must be
    said wherever the score is displayed: past the ceiling it SATURATES — two
    machines at 100 are no longer comparable, only the raw counters exported
    alongside tell them apart.
    """
    if charge <= 0:
        return 0
    return max(0, min(100, round(
        100 * math.log10(1 + charge) / math.log10(1 + config.VOC_MAX_LOAD))))


# Reading bounds of the score. Purely descriptive: they serve to write
# "exposition élevée" in an IRIS case rather than "68", which says nothing to
# someone who does not have the rest of the estate in mind. The values stay
# French: they are displayed in the (French) IRIS notes and exported as
# `voc.niveau`.
def risk_level(score: int) -> str:
    if score >= 80:
        return "critique"
    if score >= 60:
        return "élevée"
    if score >= 35:
        return "modérée"
    if score > 0:
        return "faible"
    return "nulle"


# --------------------------------------------------------------------------
# Reading the Wazuh state index
# --------------------------------------------------------------------------

def _scan() -> list[dict]:
    """Every open vulnerability of the estate, as Wazuh sees them.

    `scroll` API and not `search_after`: the business key (agent, CVE, package)
    already serves as the uniqueness key in the database, but `package.name` is
    absent from some Windows documents — a total ordering on it is therefore not
    guaranteed, and a `search_after` pagination would silently skip rows. The
    volume (a few tens of thousands of documents, one shard) makes the scroll
    cost nothing in practice.
    """
    body = {
        "size": 1000,
        "query": {"match_all": {}},
        "_source": ["agent.id", "agent.name", "package.name", "package.version",
                    "vulnerability.id", "vulnerability.severity",
                    "vulnerability.score.base", "vulnerability.published_at",
                    "vulnerability.detected_at", "host.os.full"],
    }
    verify = config.INDEXER_CA if config.INDEXER_VERIFY_TLS else False
    auth = (config.INDEXER_USER, config.INDEXER_PASSWORD)

    r = requests.post(
        f"{config.INDEXER_URL}/{config.VULN_INDICES}/_search",
        params={"scroll": "2m"}, json=body, auth=auth, verify=verify,
        timeout=120)
    # 404 = the VD module never wrote (not enabled, or first feed in progress).
    # Normal case of a fresh deployment: we return an empty list, the caller then
    # writes NOTHING — above all not a mass closure.
    if r.status_code == 404:
        log.warning("no %s index: Vulnerability Detection module inactive?",
                    config.VULN_INDICES)
        return []
    r.raise_for_status()
    resp_body = r.json()
    scroll_id = resp_body.get("_scroll_id")
    hits = resp_body["hits"]["hits"]
    tout: list[dict] = []

    try:
        while hits:
            tout += [h["_source"] for h in hits]
            r = requests.post(
                f"{config.INDEXER_URL}/_search/scroll",
                json={"scroll": "2m", "scroll_id": scroll_id},
                auth=auth, verify=verify, timeout=120)
            r.raise_for_status()
            resp_body = r.json()
            scroll_id = resp_body.get("_scroll_id")
            hits = resp_body["hits"]["hits"]
    finally:
        if scroll_id:
            requests.delete(f"{config.INDEXER_URL}/_search/scroll",
                            json={"scroll_id": [scroll_id]}, auth=auth,
                            verify=verify, timeout=30)
    return tout


def _flatten(src: dict) -> dict | None:
    """Indexer document -> `vulnerabilities` row. None if unusable."""
    agent = src.get("agent") or {}
    package = src.get("package") or {}
    vuln = src.get("vulnerability") or {}
    cve = vuln.get("id")
    agent_id = agent.get("id")
    if not cve or not agent_id:
        return None
    score = (vuln.get("score") or {}).get("base")
    return {
        "agent_id": str(agent_id),
        "agent_name": agent.get("name"),
        "cve": str(cve),
        # The package is missing on some Windows entries (vulnerability of the
        # OS itself, fixed by a hotfix): we fall back on a stable label rather
        # than on NULL, which would break the uniqueness key.
        "package": package.get("name") or "(système)",
        "version": package.get("version"),
        "severity": effective_severity(vuln.get("severity"), score),
        "base_score": float(score) if score is not None else None,
        "published_at": vuln.get("published_at"),
        "os_name": ((src.get("host") or {}).get("os") or {}).get("full"),
    }


# --------------------------------------------------------------------------
# Synchronisation: the journal
# --------------------------------------------------------------------------

UPSERT = """
INSERT INTO vulnerabilities (agent_id, agent_name, cve, package, version,
                            severity, base_score, published_at, os_name,
                            first_seen, last_seen, status)
VALUES (%(agent_id)s, %(agent_name)s, %(cve)s, %(package)s, %(version)s,
        %(severity)s, %(base_score)s, %(published_at)s, %(os_name)s,
        now(), now(), 'open')
ON CONFLICT (agent_id, cve, package) DO UPDATE SET
    agent_name   = EXCLUDED.agent_name,
    version      = EXCLUDED.version,
    severity     = EXCLUDED.severity,
    base_score   = EXCLUDED.base_score,
    published_at    = EXCLUDED.published_at,
    os_name       = EXCLUDED.os_name,
    last_seen = now(),
    -- `first_seen` is NEVER rewritten: it is what makes the SLA run. A
    -- vulnerability that reappears after being fixed does restart from zero
    -- though — that is a regression, not the continuation of the old one.
    first_seen        = CASE WHEN vulnerabilities.status = 'fixed'
                        THEN now() ELSE vulnerabilities.first_seen END,
    fixed_at   = NULL,
    status       = 'open'
RETURNING (xmax = 0) AS created
"""

# Closure: only on the agents that ANSWERED this scan. A stopped agent, or one
# whose syscollector is broken, leaves the state index with all its
# vulnerabilities — without this filter, the diff would conclude a mass
# remediation. The burn-down would be perfect and the estate invisible: exactly
# the lie this module exists to avoid.
CLOSURE = """
UPDATE vulnerabilities
   SET status = 'fixed', fixed_at = now()
 WHERE status = 'open'
   AND agent_id = ANY(%(agents)s)
   AND last_seen < %(start_ts)s
"""


def sync(conn, lines: list[dict] | None = None) -> dict:
    """Confront the Wazuh inventory with the journal. Returns the scan summary."""
    start = datetime.now(timezone.utc)
    raw = _scan() if lines is None else lines
    seen = [v for v in (_flatten(s) for s in raw) if v]

    # Deduplication on the business key BEFORE insertion: two Wazuh documents
    # can carry the same (machine, CVE, package) for two different versions of
    # the package (cohabiting kernels). `ON CONFLICT` cannot handle the same key
    # twice in a single `executemany` under psycopg — it raises
    # `CardinalityViolation`. We keep the more severe of the two.
    by_key: dict[tuple, dict] = {}
    for v in seen:
        key = (v["agent_id"], v["cve"], v["package"])
        old = by_key.get(key)
        if old is None or weight(v["severity"]) > weight(old["severity"]):
            by_key[key] = v
    seen = list(by_key.values())

    agents_seen = sorted({v["agent_id"] for v in seen})
    if not seen:
        # Nothing at all: empty indexer, VD inactive, or scan in progress. We
        # close nothing and we say so — a scan with no data is not a healthy
        # estate.
        log.warning("empty vulnerability scan: no closure applied")
        with conn.cursor() as cur:
            cur.execute("INSERT INTO vuln_scans (agents_seen, vulns_seen) "
                        "VALUES (0, 0)")
        conn.commit()
        return {"agents_seen": 0, "vulns_seen": 0, "new_count": 0,
                "fixed_count": 0, "silent_agents": []}

    new = 0
    with conn.cursor(row_factory=dict_row) as cur:
        for v in seen:
            r = cur.execute(UPSERT, v).fetchone()
            new += 1 if r["created"] else 0
        cur.execute(CLOSURE, {"agents": agents_seen, "start_ts": start})
        fixed = max(cur.rowcount, 0)

        # Agents known to the CMDB but absent from the scan. Two very different
        # causes that we cannot tell apart here — OS not covered by the feed
        # (pfSense/BSD, the manager image) or broken sensor — hence the raw
        # trace, used by the "coverage" panel of the dashboard.
        known = {r["agent_id"] for r in cur.execute(
            "SELECT agent_id FROM assets").fetchall()}
        silent = sorted(known - set(agents_seen))
        cur.execute(
            "INSERT INTO vuln_scans (agents_seen, vulns_seen, new_count, "
            "                        fixed_count, silent_agents) "
            "VALUES (%s, %s, %s, %s, %s)",
            (len(agents_seen), len(seen), new, fixed, silent))
    conn.commit()
    return {"agents_seen": len(agents_seen), "vulns_seen": len(seen),
            "new_count": new, "fixed_count": fixed,
            "silent_agents": silent}


# --------------------------------------------------------------------------
# Exposure of a machine
# --------------------------------------------------------------------------

SQL_OPEN = """
SELECT cve, package, version, severity, base_score, published_at, first_seen,
       extract(epoch FROM now() - first_seen) / 86400 AS age_days
  FROM vulnerabilities
 WHERE agent_id = %s AND status = 'open'
"""


def exposure(conn, agent_id: str) -> dict:
    """Exposure of a machine: score, distribution, delay, worst CVEs.

    READ function, no side effects: it is what the IRIS section and the MCP
    server consume. Returns a dict even when the machine has no data at all —
    `covered: False` — because "no known vulnerability" and "never inventoried"
    are two opposite statements that a report must never confuse.
    """
    prio = assets.agent_priority(conn, str(agent_id))
    lines = [dict(r) for r in conn.execute(SQL_OPEN, (str(agent_id),))]
    factor = config.VOC_PRIORITY_FACTOR.get(prio["priority"], 1.0)

    by_severity: dict[str, int] = {}
    charge = 0.0
    outside_sla: list[dict] = []
    for v in lines:
        sev = v["severity"] or ""
        by_severity[sev] = by_severity.get(sev, 0) + 1
        charge += weight(sev)
        delay = sla_days(sev, prio["priority"])
        if delay is not None and v["age_days"] > delay:
            outside_sla.append({**v, "sla_days": delay,
                             "overdue_days": round(v["age_days"] - delay, 1)})

    score = risk_score(charge * factor)
    # Sorting the "worst": severity first, then CVSS score, then age. Age
    # deliberately breaks ties last — a critical from yesterday comes before a
    # high from last year.
    worst = sorted(
        lines,
        key=lambda v: (-weight(v["severity"] or ""), -(v["base_score"] or 0),
                       -v["age_days"]))[:config.VOC_MAX_CVE_REPORT]

    fixed = conn.execute(
        "SELECT count(*) AS n, "
        "       avg(extract(epoch FROM fixed_at - first_seen) / 86400) AS mttr "
        "  FROM vulnerabilities "
        " WHERE agent_id = %s AND status = 'fixed' "
        "   AND fixed_at >= now() - interval '90 days'",
        (str(agent_id),)).fetchone()

    return {
        "agent_id": str(agent_id),
        # Name resolved here and not in the caller: the CLI, the export to the
        # indexer and the IRIS note must designate the machine the same way. The
        # CMDB is authoritative (it follows the manager's renames), the name
        # frozen in the journal only serves as a fallback.
        "agent_name": _agent_name(conn, str(agent_id)),
        "covered": bool(lines) or _already_scanned(conn, str(agent_id)),
        "priority": prio["priority"],
        "role": prio["role"],
        "score": score,
        "level": risk_level(score),
        "charge": round(charge, 1),
        "priority_factor": factor,
        "total": len(lines),
        "by_severity": by_severity,
        "critical_count": by_severity.get("critical", 0),
        "high_count": by_severity.get("high", 0),
        "outside_sla": sorted(outside_sla, key=lambda v: -v["overdue_days"]),
        "outside_sla_total": len(outside_sla),
        "oldest_days": round(max((v["age_days"] for v in lines),
                                         default=0), 1),
        "journal_days": log_age(conn),
        "worst": worst,
        "fixed_90d": fixed["n"],
        "mttr_days": round(fixed["mttr"], 1) if fixed["mttr"] else None,
    }


def log_age(conn) -> float | None:
    """Age of the journal in days, or None if it never ran.

    Indispensable to read the age and the delay honestly: both quantities are
    counted from OUR first observation, not from the publication of the CVE. A
    three-day-old journal therefore displays "oldest open: 3 days" and "0 past
    deadline" on an estate dragging CVEs from 2019 — exact figures, conclusion
    opposite to the truth if we do not say since when we have been measuring.
    """
    line = conn.execute(
        "SELECT extract(epoch FROM now() - min(started_at)) / 86400 AS j "
        "  FROM vuln_scans").fetchone()
    return round(line["j"], 1) if line and line["j"] is not None else None


def _agent_name(conn, agent_id: str) -> str | None:
    line = conn.execute(
        "SELECT coalesce(a.name, v.agent_name) AS name "
        "  FROM (SELECT %s::text AS id) x "
        "  LEFT JOIN assets a ON a.agent_id = x.id "
        "  LEFT JOIN LATERAL (SELECT agent_name FROM vulnerabilities "
        "                      WHERE agent_id = x.id LIMIT 1) v ON true",
        (agent_id,)).fetchone()
    return line["name"] if line else None


def _already_scanned(conn, agent_id: str) -> bool:
    """Has this agent EVER appeared in an inventory? Tells "nothing to report"
    from "never seen" when the open list is empty."""
    return bool(conn.execute(
        "SELECT 1 FROM vulnerabilities WHERE agent_id = %s LIMIT 1",
        (agent_id,)).fetchone())


def fleet_exposure(conn) -> list[dict]:
    """Exposure of every machine with at least one known vulnerability."""
    ids = [r["agent_id"] for r in conn.execute(
        "SELECT DISTINCT agent_id FROM vulnerabilities ORDER BY agent_id")]
    return sorted((exposure(conn, a) for a in ids),
                  key=lambda e: -e["score"])


# --------------------------------------------------------------------------
# Matching against an incident
# --------------------------------------------------------------------------

_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# ATT&CK techniques whose success PRESUPPOSES a software vulnerability. Their
# presence in an incident does not prove that a CVE of the machine was exploited
# — it is a lead, and the section says so in plain words. Without that wording
# guardrail, a report would turn a correlation into a cause.
TECHNIQUES_EXPLOIT = {
    "T1190",      # exploitation of a public-facing application
    "T1210",      # exploitation of a remote service
    "T1068",      # privilege escalation through exploitation
    "T1211",      # defence evasion through exploitation
    "T1212",      # exploitation for credential access
    "T1203",      # client-side exploitation for execution
}


def cited_cves(alerts: list[dict]) -> set[str]:
    """CVE identifiers appearing literally in the alerts.

    This is the ONLY certain link between an incident and a vulnerability: a CVE
    written in a command line or in a file name (local rule 100660, "CVE
    identifier in command") says what the attacker was LOOKING FOR. Everything
    else is a hypothesis.
    """
    found: set[str] = set()
    for a in alerts:
        raw = a.get("raw")
        if isinstance(raw, (dict, list)):
            raw = json.dumps(raw)
        for field in (a.get("rule_desc"), raw):
            if field:
                found |= {m.upper() for m in _CVE.findall(str(field))}
    return found


def incident_link(conn, agent_id: str, alerts: list[dict],
                  expo: dict | None = None) -> dict:
    """What ties the exposure of the machine to THIS incident.

    Three degrees of certainty, never mixed:

    - `confirmed`: the CVE is quoted in the alerts AND open on the machine. Fact,
      not deduction.
    - `quoted_not_open`: the CVE is quoted but is not (or no longer) open here.
      Information in its own right — attempt against a non-vulnerable machine, or
      vulnerability already fixed.
    - `possible_vectors`: the incident carries an exploitation technique and the
      machine has serious open vulnerabilities. No proof of any link.
    """
    expo = expo or exposure(conn, agent_id)
    cited = cited_cves(alerts)
    open_by_cve = {v["cve"]: v for v in conn.execute(
        SQL_OPEN, (str(agent_id),))} if cited else {}

    techniques = set()
    for a in alerts:
        techniques |= {str(m).upper() for m in (a.get("mitre_ids") or [])}
    exploit = sorted(techniques & TECHNIQUES_EXPLOIT)

    confirmed = [dict(open_by_cve[c]) for c in sorted(cited) if c in open_by_cve]
    return {
        "confirmed": confirmed,
        "quoted_not_open": sorted(cited - set(open_by_cve)),
        "exploit_techniques": exploit,
        # The vectors are only proposed if the incident really carries an
        # exploitation technique: otherwise the section would list the worst CVEs
        # of the machine next to an unrelated incident, and the analyst would
        # make the link on our behalf.
        "possible_vectors": (
            [v for v in expo["worst"]
             if (v["severity"] or "") in ("critical", "high")][:5]
            if exploit else []),
    }


# --------------------------------------------------------------------------
# Export to the indexer (VOC dashboard)
# --------------------------------------------------------------------------

def _series_index(ts: datetime) -> str:
    """Daily index of the time series (`wazuh-voc-YYYY.MM.DD`)."""
    return f"{config.VOC_INDEX_PREFIX}-{ts.astimezone(timezone.utc):%Y.%m.%d}"


# STABLE, undated index for the life-cycle documents. Their `_id` is
# deterministic (one vulnerability = one document, rewritten on every pass):
# filing it in a dated index would create one copy per day, each frozen on the
# state of its day, and the counters would be multiplied by the retention.
INDEX_VULNS = "vulns"


def _vuln_id(v: dict) -> str:
    key = f"{v['agent_id']}|{v['cve']}|{v['package']}"
    return "vuln-" + hashlib.sha1(key.encode("utf-8")).hexdigest()[:24]


def _vuln_doc(v: dict, priority: int) -> dict:
    """One vulnerability and its life cycle. @timestamp = first observation:
    a document is read at the date the problem appeared, not at the run date."""
    sev = v["severity"] or ""
    delay = sla_days(sev, priority)
    age = (v["age_days"] if v["fixed_at"] is None
           else (v["fixed_at"] - v["first_seen"]).total_seconds() / 86400)
    return {
        "@timestamp": v["first_seen"].astimezone(timezone.utc).isoformat(),
        "timestamp": v["first_seen"].astimezone(timezone.utc).isoformat(),
        "event_type": "voc_vuln",
        "agent": {"id": v["agent_id"], "name": v["agent_name"]},
        "asset": {"priority": priority, "priorite_label": f"P{priority}"},
        "vulnerability": {
            "id": v["cve"],
            "severity": sev or "unknown",
            "base_score": v["base_score"],
            "published_at": (v["published_at"].astimezone(timezone.utc).isoformat()
                             if v["published_at"] else None),
        },
        "package": {"name": v["package"], "version": v["version"]},
        "voc": {
            "status": v["status"],
            "resolue": v["status"] == "fixed",
            "first_seen": v["first_seen"].astimezone(timezone.utc).isoformat(),
            "fixed_at": (v["fixed_at"].astimezone(timezone.utc).isoformat()
                           if v["fixed_at"] else None),
            # One single field with two meanings depending on status, on
            # purpose: it is the age while open, the patching delay once
            # resolved. The MTTR is therefore read by filtering on
            # `voc.resolue: true`.
            "age_jours": round(age, 2),
            "sla_jours": delay,
            "hors_sla": bool(delay is not None and v["status"] == "open"
                             and age > delay),
            "retard_jours": (round(age - delay, 2)
                             if delay is not None and age > delay else 0),
            "poids": weight(sev),
        },
    }


def _asset_doc(e: dict, maintenant: datetime) -> dict:
    """Exposure of a machine at the moment of the run — the point of the curve."""
    return {
        "@timestamp": maintenant.isoformat(),
        "timestamp": maintenant.isoformat(),
        "event_type": "voc_asset",
        "agent": {"id": e["agent_id"], "name": e.get("agent_name")},
        "asset": {"priority": e["priority"], "priorite_label": f"P{e['priority']}",
                  "role": e["role"]},
        "voc": {
            "score": e["score"],
            "niveau": e["level"],
            "charge": e["charge"],
            "ouvertes": e["total"],
            "critical": e["by_severity"].get("critical", 0),
            "high": e["by_severity"].get("high", 0),
            "medium": e["by_severity"].get("medium", 0),
            "low": e["by_severity"].get("low", 0),
            "inconnue": e["by_severity"].get("", 0),
            # `hors_sla_total` and not `hors_sla`: on a `voc_vuln` document,
            # `voc.hors_sla` is a BOOLEAN. Two types under the same field name in
            # the same index get the document rejected by OpenSearch — and a bulk
            # rejection is silent unless the response is read.
            "hors_sla_total": e["outside_sla_total"],
            "plus_ancienne_jours": e["oldest_days"],
            "corrigees_90j": e["fixed_90d"],
            "mttr_jours": e["mttr_days"],
        },
    }


def _fleet_doc(conn, expos: list[dict], scan: dict, maintenant: datetime) -> dict:
    """Fleet view. Carries the COVERAGE first: a debt going down because
    machines stopped answering is not an improvement, and it is the only figure
    that lets one see it."""
    inventories = {r["agent_id"] for r in conn.execute(
        "SELECT DISTINCT agent_id FROM vulnerabilities")}
    total_assets = conn.execute(
        "SELECT count(*) AS n FROM assets").fetchone()["n"]
    total_of = lambda key: sum(e["by_severity"].get(key, 0) for e in expos)  # noqa: E731
    return {
        "@timestamp": maintenant.isoformat(),
        "timestamp": maintenant.isoformat(),
        "event_type": "voc_parc",
        "voc": {
            "machines_inventoriees": len(inventories),
            "machines_scannees": scan["agents_seen"],
            "machines_connues": total_assets,
            "couverture_pct": (round(100 * scan["agents_seen"] / total_assets, 1)
                               if total_assets else None),
            "machines_muettes": len(scan["silent_agents"]),
            "ouvertes": sum(e["total"] for e in expos),
            "critical": total_of("critical"),
            "high": total_of("high"),
            "medium": total_of("medium"),
            "low": total_of("low"),
            "hors_sla_total": sum(e["outside_sla_total"] for e in expos),
            "new_count": scan["new_count"],
            "fixed_count": scan["fixed_count"],
            "score_max": max((e["score"] for e in expos), default=0),
            "score_moyen": (round(sum(e["score"] for e in expos) / len(expos), 1)
                            if expos else 0),
        },
    }


def _bulk(lines: list[str]) -> tuple[int, list[str]]:
    if not lines:
        return 0, []
    r = requests.post(
        f"{config.INDEXER_URL}/_bulk",
        auth=(config.INDEXER_USER, config.INDEXER_PASSWORD),
        headers={"Content-Type": "application/x-ndjson"},
        data="".join(lines).encode("utf-8"),
        verify=config.INDEXER_CA if config.INDEXER_VERIFY_TLS else False,
        timeout=180)
    r.raise_for_status()
    body = r.json()
    errors = []
    if body.get("errors"):
        for item in body.get("items", []):
            info = next(iter(item.values()))
            if info.get("error"):
                errors.append(json.dumps(info["error"])[:300])
    return len(body.get("items", [])) - len(errors), errors


def _line(index: str, doc_id: str, doc: dict) -> list[str]:
    return [json.dumps({"index": {"_index": index, "_id": doc_id}}) + "\n",
            json.dumps(doc, default=str) + "\n"]


SQL_DETAIL = """
SELECT agent_id, agent_name, cve, package, version, severity, base_score,
       published_at, first_seen, fixed_at, status,
       extract(epoch FROM now() - first_seen) / 86400 AS age_days
  FROM vulnerabilities
 WHERE (status = 'open' AND severity = ANY(%(sev)s))
    OR (status = 'fixed' AND fixed_at >= now() - interval '180 days')
"""


def export(conn, scan: dict, simulation: bool = False) -> dict:
    """Write the VOC series to the indexer. Idempotent (`_id` deterministic)."""
    maintenant = datetime.now(timezone.utc)
    expos = fleet_exposure(conn)
    lines: list[str] = []
    summary = {"voc_asset": 0, "voc_parc": 0, "voc_vuln": 0}

    # `_id` at the HOUR: the job runs more often than that (catch-up, manual
    # rerun) and we want neither to overwrite the previous point nor to stack
    # ten points per hour. An hourly curve is largely enough for a debt that
    # moves at day scale.
    hour = f"{maintenant:%Y%m%d%H}"
    for e in expos:
        lines += _line(_series_index(maintenant),
                         f"asset-{e['agent_id']}-{hour}",
                         _asset_doc(e, maintenant))
        summary["voc_asset"] += 1

    lines += _line(_series_index(maintenant), f"parc-{hour}",
                     _fleet_doc(conn, expos, scan, maintenant))
    summary["voc_parc"] = 1

    prios = {e["agent_id"]: e["priority"] for e in expos}
    for v in conn.execute(SQL_DETAIL,
                          {"sev": sorted(config.VOC_SEVERITIES_DETAIL)}):
        prio = prios.get(v["agent_id"], config.DEFAULT_PRIORITY)
        lines += _line(f"{config.VOC_INDEX_PREFIX}-{INDEX_VULNS}",
                         _vuln_id(v), _vuln_doc(dict(v), prio))
        summary["voc_vuln"] += 1

    if simulation:
        for l in lines:
            print(l, end="")
        return summary

    written, errors = _bulk(lines)
    summary["written"] = written
    summary["errors"] = errors
    return summary


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _show_fleet(expos: list[dict]) -> None:
    print(f"{'agent':<6}{'machine':<22}{'P':<4}{'score':>6}  "
          f"{'crit':>5}{'high':>6}{'open':>8}{'outSLA':>9}  level")
    print("-" * 82)
    for e in expos:
        print(f"{e['agent_id']:<6}{(e.get('agent_name') or '?')[:21]:<22}"
              f"P{e['priority']:<3}{e['score']:>6}  "
              f"{e['by_severity'].get('critical', 0):>5}"
              f"{e['by_severity'].get('high', 0):>6}"
              f"{e['total']:>8}{e['outside_sla_total']:>9}  {e['level']}")


def _show_agent(e: dict) -> None:
    print(f"Agent {e['agent_id']} — P{e['priority']} "
          f"({e['role'] or 'role not declared'})")
    if not e["covered"]:
        print("  NEVER INVENTORIED: no vulnerability data. "
              "\"0 CVE\" does not mean \"up to date\".")
        return
    print(f"  exposure score: {e['score']}/100 ({e['level']}) — "
          f"load {e['charge']} x{e['priority_factor']} (priority)")
    print(f"  open: {e['total']} "
          + ", ".join(f"{k or 'no severity'}={v}"
                      for k, v in sorted(e["by_severity"].items())))
    print(f"  past SLA: {e['outside_sla_total']} — oldest: "
          f"{e['oldest_days']} d")
    if e.get("journal_days") is not None and e["journal_days"] < 30:
        print(f"  (only {e['journal_days']:.0f} d of journal: age and delay "
              f"measure how long we have been MEASURING, not the state of "
              f"the estate)")
    if e["mttr_days"] is not None:
        print(f"  fixed over 90 d: {e['fixed_90d']} "
              f"(average delay {e['mttr_days']} d)")
    print("  worst vulnerabilities:")
    for v in e["worst"]:
        print(f"    {v['cve']:<18}{(v['severity'] or '?'):<10}"
              f"{(v['base_score'] or 0):>5}  {v['package'][:32]:<34}"
              f"{v['age_days']:.0f} d")


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", action="store_true",
                    help="exposure of the estate, no scan and no write")
    ap.add_argument("--agent", metavar="AGENT_ID",
                    help="exposure detail of one machine")
    ap.add_argument("--no-export", action="store_true",
                    help="scans and updates the journal, without exporting")
    ap.add_argument("--simulation", action="store_true",
                    help="shows the documents instead of indexing them")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        if args.agent:
            _show_agent(exposure(conn, args.agent))
            return
        if args.state:
            _show_fleet(fleet_exposure(conn))
            return

        scan = sync(conn)
        print(f"{scan['vulns_seen']} vulnerabilit(y/ies) on "
              f"{scan['agents_seen']} machine(s): {scan['new_count']} new, "
              f"{scan['fixed_count']} fixed")
        if scan["silent_agents"]:
            print(f"  {len(scan['silent_agents'])} machine(s) with no inventory: "
                  f"{', '.join(scan['silent_agents'])} — OS not covered by the "
                  f"feed, or silent syscollector. Nothing was closed for them.")
        if args.no_export:
            return
        r = export(conn, scan, args.simulation)
        if args.simulation:
            return
        print(f"  {r['written']} document(s) indexed "
              f"({r['voc_asset']} machines, {r['voc_vuln']} vulnerabilities, "
              f"1 fleet view)")
        for e in r["errors"]:
            print(f"  ERROR {e}")


if __name__ == "__main__":
    main()
