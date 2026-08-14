"""Exporting AI metrics to the Wazuh indexer (`wazuh-ai-*` indices).

Why go through the indexer rather than add a Grafana: the SOC already has one
place where curves are looked at. Putting the metrics in the same indexer, under
the same field conventions, lets them be read in the same Wazuh dashboard as the
alerts — and lets a token spike be lined up with an alert spike on one time axis.

Four document types, told apart by `event_type`:

- `llm_call`  : one call to the model (`llm_calls` table). Carries tokens,
  duration, caller, estimated cost. The source of the consumption metrics.
- `triage`    : one verdict rendered (`triages` table). Carries verdict,
  confidence, actions, inconsistencies, guardrails triggered, injection
  patterns. The source of the QUALITY metrics.
- `snapshot`  : pipeline state counters at the moment of the run (incidents,
  cases, whitelists, remediations). What cannot be derived from the other two.
- `incident_kpi` : one document per incident, carrying the DELAYS (MTTD, MTTR).
  Computed in SQL and not in a visualisation: OpenSearch Dashboards cannot
  subtract two dates from two different documents, and the bounds live in three
  tables (`incidents`, `triages`, `mitigations`).

Idempotent through a deterministic `_id` (`llm-<id>`, `triage-<id>`,
`kpi-<id>`): we re-export a sliding window on every pass rather than keeping a
cursor. A document already present is simply rewritten identically. The cursor
in database would have been one more table, and would have made catching up
impossible after an index purge.

    python -m soc_agent.metrics               # exports the default window
    python -m soc_agent.metrics --since 30d   # wide catch-up
    python -m soc_agent.metrics --simulation  # shows, writes nothing
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone

import psycopg
import requests
from psycopg.rows import dict_row

from . import config

requests.packages.urllib3.disable_warnings()


def _index_of_day(ts: datetime) -> str:
    """`wazuh-ai-YYYY.MM.DD` — same slicing convention as Wazuh.

    One index per day: retention is handled by dropping whole indices, with no
    expensive delete-by-query.
    """
    return f"{config.METRICS_INDEX_PREFIX}-{ts.astimezone(timezone.utc):%Y.%m.%d}"


def _cost(prompt_tokens, completion_tokens, cache_hit, cache_miss) -> float:
    """ESTIMATED cost in USD, from the public pricing (see config).

    An assumed approximation: the rates come from the published grid, not from
    an invoice. Cross-checked against the account's real consumption (671,593
    tokens for 0.09 USD), it gives the right order of magnitude — not something
    to bill on.

    A cache hit is 50x cheaper than a cache miss. When the API splits the input
    we use it; otherwise we count everything as cache miss, which OVERSTATES the
    cost. An overestimate is the only acceptable error here.
    """
    if cache_hit is not None or cache_miss is not None:
        hit, miss = cache_hit or 0, cache_miss or 0
    else:
        hit, miss = 0, prompt_tokens or 0
    entry = (miss / 1_000_000 * config.LLM_COST_USD_PER_MTOKEN_IN
              + hit / 1_000_000 * config.LLM_COST_USD_PER_MTOKEN_IN_CACHE)
    output = (completion_tokens or 0) / 1_000_000 * config.LLM_COST_USD_PER_MTOKEN_OUT
    return round(entry + output, 8)


def _doc_llm(l: dict) -> dict:
    pt, ct = l["prompt_tokens"], l["completion_tokens"]
    return {
        "@timestamp": l["ts"].astimezone(timezone.utc).isoformat(),
        "timestamp": l["ts"].astimezone(timezone.utc).isoformat(),
        "event_type": "llm_call",
        "ai": {
            "usage": l["usage"],
            "model": l["model"],
            "prompt_tokens": pt,
            "completion_tokens": ct,
            # Precomputed total: summing two separate fields in an
            # aggregation is not expressible in a simple OSD visualisation.
            "total_tokens": (pt or 0) + (ct or 0),
            "cache_hit_tokens": l["cache_hit_tokens"],
            "cache_miss_tokens": l["cache_miss_tokens"],
            "max_tokens": l["max_tokens"],
            "duration_ms": l["duration_ms"],
            "cost_usd": _cost(pt, ct, l["cache_hit_tokens"],
                              l["cache_miss_tokens"]),
            "ok": l["ok"],
            "error": l["error"],
        },
        "incident": {"id": l["incident_id"]},
    }


def _doc_triage(t: dict) -> dict:
    return {
        "@timestamp": t["created_at"].astimezone(timezone.utc).isoformat(),
        "timestamp": t["created_at"].astimezone(timezone.utc).isoformat(),
        "event_type": "triage",
        "ai": {
            "usage": "triage",
            "model": t["model"],
            "prompt_tokens": t["prompt_tokens"],
            "duration_ms": t["duration_ms"],
            "prompt_sha": t["prompt_sha"],
            "mode": t["mode"],
        },
        "triage": {
            "verdict": t["verdict"],
            "confidence": t["confidence"],
            "mitre": t["mitre"],
            "actions": t["actions"] or [],
            "action_count": len(t["actions"] or []),
            # Three quality indicators measurable WITHOUT a labelled set: a
            # rising rate flags a degraded prompt or an attack.
            "inconsistencies": t["inconsistencies"] or [],
            "inconsistency_count": len(t["inconsistencies"] or []),
            "guardrails": t["guardrails"] or [],
            "guardrail_count": len(t["guardrails"] or []),
            "injection_patterns": t["injection_patterns"] or [],
            "injection_detected": bool(t["injection_patterns"]),
        },
        "incident": {
            "id": t["incident_id"],
            "agent_name": t["agent_name"],
            "max_level": t["max_level"],
            "alert_count": t["alert_count"],
        },
    }


# Remediation statuses that count as a RESPONSE actually applied on the target,
# and which therefore stop the MTTR clock:
#   executed / confirmed : the action went through, the agent confirmed it.
#   no_effect            : the action went through and there was nothing to do
#                          (target absent, already in that state) — that is an
#                          outcome, not a failure.
# Deliberately excluded: 'dry_run' (simulated, the action is still pending),
# 'failed', 'agent_refused', 'canceled', and 'sent' — an action sent with no
# agent report is NOT proof of remediation (see the 2026-08-02 report which
# announced 26 successful quarantines, all of them refused in reality).
REMEDIED_STATUSES = ("executed", "confirmed", "no_effect")

# `created_at OR a remediation inside the window`: an incident's MTTR lands
# AFTER its detection, sometimes hours later. Without the second branch, the KPI
# document of an incident detected outside the window would keep an empty MTTR
# forever. The deterministic `_id` means the re-export fixes it in place.
SQL_KPI = f"""
    SELECT i.id, i.agent_name, i.max_level, i.alert_count, i.status,
           i.priority, i.severity, i.first_seen, i.created_at,
           (SELECT min(t.created_at) FROM triages t
             WHERE t.incident_id = i.id) AS triage_at,
           (SELECT min(m.executed_at) FROM mitigations m
             WHERE m.incident_id = i.id
               AND m.status IN {REMEDIED_STATUSES}) AS remediated_at
      FROM incidents i
     WHERE i.created_at >= %(start)s
        OR EXISTS (SELECT 1 FROM mitigations m
                    WHERE m.incident_id = i.id
                      AND m.status IN {REMEDIED_STATUSES}
                      AND m.executed_at >= %(start)s)
     ORDER BY i.id
"""


def _minutes(end, start) -> float | None:
    """Gap in minutes, rounded to the second. None if a bound is missing."""
    if end is None or start is None:
        return None
    return round((end - start).total_seconds() / 60, 4)


def _doc_kpi(k: dict) -> dict:
    """End-to-end delays of an incident.

    Three bounds, three delays:

    - MTTD: `first_seen` (the oldest EVENT of the incident, timestamped on the
      machine) -> `created_at` (the moment correlation created the incident,
      that is, when AURA detected). Measures the sensor -> indexer -> ingest ->
      correlation chain, cycle cadence included.
    - MTTR: `created_at` -> first remediation applied. Detection -> action, the
      usual SOC definition. MTTD + MTTR = total end-to-end delay, also exported
      (`mttr_total_minutes`) so nobody has to add two averages — which would be
      wrong as soon as the two populations differ (not every detected incident
      ends in a remediation).
    - Triage: `created_at` -> first verdict from the model. A sub-part of the
      MTTR, useful to tell whether a drifting MTTR comes from the AI or from the
      action channel.

    The document is timestamped on `created_at`: a KPI is read at the date of
    the detection it describes, not at the date of the export.
    """
    return {
        "@timestamp": k["created_at"].astimezone(timezone.utc).isoformat(),
        "timestamp": k["created_at"].astimezone(timezone.utc).isoformat(),
        "event_type": "incident_kpi",
        "kpi": {
            "mttd_minutes": _minutes(k["created_at"], k["first_seen"]),
            "mttr_minutes": _minutes(k["remediated_at"], k["created_at"]),
            "mttr_total_minutes": _minutes(k["remediated_at"], k["first_seen"]),
            "triage_minutes": _minutes(k["triage_at"], k["created_at"]),
            "first_seen": k["first_seen"].astimezone(timezone.utc).isoformat(),
            "detected_at": k["created_at"].astimezone(timezone.utc).isoformat(),
            "remediated_at": (k["remediated_at"].astimezone(timezone.utc).isoformat()
                              if k["remediated_at"] else None),
            "remediated": k["remediated_at"] is not None,
        },
        "incident": {
            "id": k["id"],
            "agent_name": k["agent_name"],
            "max_level": k["max_level"],
            "alert_count": k["alert_count"],
            "status": k["status"],
            # Asset priority: an average MTTD means nothing while it mixes the
            # domain controller with the test boxes. It is the P1 MTTD that
            # holds up in front of an auditor.
            "priority": k["priority"],
            "severity": k["severity"],
        },
    }


def _doc_snapshot(conn, now: datetime) -> dict:
    """State counters. One document per run — this is a gauge, not a stream."""
    def un(sql, *args):
        return conn.execute(sql, args).fetchone()["n"]

    return {
        "@timestamp": now.isoformat(),
        "timestamp": now.isoformat(),
        "event_type": "snapshot",
        "pipeline": {
            "alerts_total": un("SELECT count(*) AS n FROM alerts"),
            "alerts_suppressed": un(
                "SELECT count(*) AS n FROM alerts WHERE suppressed"),
            "incidents_total": un("SELECT count(*) AS n FROM incidents"),
            "incidents_open": un(
                "SELECT count(*) AS n FROM incidents WHERE status = 'case_open'"),
            "triages_total": un("SELECT count(*) AS n FROM triages"),
            "whitelist_rules_active": un(
                "SELECT count(*) AS n FROM whitelist_rules WHERE active"),
            # Three counters, not one: "the command went out" and "the agent
            # confirms it is done" are two different things, and conflating them
            # is what let the 2026-08-02 report announce 26 successful
            # quarantines that had all been refused.
            "mitigations_sent": un(
                "SELECT count(*) AS n FROM mitigations WHERE status = 'sent'"),
            "mitigations_confirmed": un(
                "SELECT count(*) AS n FROM mitigations WHERE status = 'confirmed'"),
            "mitigations_refused": un(
                "SELECT count(*) AS n FROM mitigations "
                "WHERE status = 'agent_refused'"),
            "labels_total": un("SELECT count(*) AS n FROM labels"),
        },
    }


def _bulk(lines: list[str]) -> tuple[int, list[str]]:
    """Bulk send to the indexer. Returns (number written, errors)."""
    if not lines:
        return 0, []
    r = requests.post(
        f"{config.INDEXER_URL}/_bulk",
        auth=(config.INDEXER_USER, config.INDEXER_PASSWORD),
        headers={"Content-Type": "application/x-ndjson"},
        data="".join(lines).encode("utf-8"),
        verify=config.INDEXER_CA or config.INDEXER_VERIFY_TLS,
        timeout=60)
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


def export(since: str, simulation: bool) -> dict:
    """Exports the requested window. Returns a summary."""
    unit = {"m": "minutes", "h": "hours", "d": "days"}[since[-1]]
    delta = timedelta(**{unit: int(since[:-1])})
    start = datetime.now(timezone.utc) - delta
    now = datetime.now(timezone.utc)

    lines: list[str] = []
    summary = {"llm_call": 0, "triage": 0, "incident_kpi": 0, "snapshot": 0}

    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        for l in conn.execute(
                "SELECT * FROM llm_calls WHERE ts >= %s ORDER BY ts", (start,)):
            lines += _line(_index_of_day(l["ts"]), f"llm-{l['id']}", _doc_llm(l))
            summary["llm_call"] += 1

        # Joined on incidents: a verdict without its incident's context
        # (agent, level, volume) is not usable in a dashboard.
        for t in conn.execute("""
                SELECT t.*, i.agent_name, i.max_level, i.alert_count
                  FROM triages t JOIN incidents i ON i.id = t.incident_id
                 WHERE t.created_at >= %s ORDER BY t.created_at""", (start,)):
            lines += _line(_index_of_day(t["created_at"]),
                             f"triage-{t['id']}", _doc_triage(t))
            summary["triage"] += 1

        for k in conn.execute(SQL_KPI, {"start": start}):
            lines += _line(_index_of_day(k["created_at"]),
                             f"kpi-{k['id']}", _doc_kpi(k))
            summary["incident_kpi"] += 1

        snap = _doc_snapshot(conn, now)

    # _id timestamped to the minute: one run every 5 min does not overwrite
    # the previous one, and two close runs (manual re-run) do not create two.
    lines += _line(_index_of_day(now),
                     f"snapshot-{now:%Y%m%d%H%M}", snap)
    summary["snapshot"] = 1

    if simulation:
        for l in lines:
            print(l, end="")
        return summary

    written, errors = _bulk(lines)
    summary["written"] = written
    summary["errors"] = errors
    return summary


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--since", default=config.METRICS_WINDOW,
                    help="window re-exported (e.g. 2h, 30d). Idempotent: "
                         "re-exporting duplicates nothing.")
    ap.add_argument("--simulation", action="store_true")
    args = ap.parse_args()

    r = export(args.since, args.simulation)
    if args.simulation:
        return
    print(f"  {r['written']} document(s) indexed "
          f"({r['llm_call']} LLM calls, {r['triage']} triages, "
          f"{r['incident_kpi']} incident KPIs, 1 snapshot)")
    for e in r["errors"]:
        print(f"  ERROR {e}")


if __name__ == "__main__":
    main()
