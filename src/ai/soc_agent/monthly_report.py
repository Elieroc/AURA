"""Monthly SOC report for the client.

Aggregates over a calendar period (default: the previous month) what the
pipeline already tracks — no new ingestion, no new table. Six sections:

  alerting      -- volume, severity breakdown, top rules/MITRE, TP/FP rate
                   (AFTER soc-agent's noise filter)
  global_kpi    -- same metrics mirroring the Wazuh "Global" OSD dashboard,
                   BEFORE the noise filter — the numbers the client already
                   sees there, so the report and the dashboard agree
  performance   -- MTTD/MTTR, same formula as the dashboard's KPI tiles
  hosts         -- machines touched, ranked by CMDB priority
  remediation   -- mitigation actions executed vs dry-run vs failed
  vulnerability -- VOC snapshot (open by severity, past-SLA, MTTR, burn-down)

`report()` returns a dict (period + the four sections), `render_markdown()`
turns it into the Jinja report. `push_to_iris()` posts that Markdown as a note
on a dedicated case ("Rapport mensuel SOC — AAAA-MM", one per period,
idempotent on `case_soc_id`) — the same place an analyst already reads
per-incident reports, so a monthly report needs no new tool to consult. Same
split as `report.py`: the MCP server and any other caller consume the dict,
never a parsed table.

    python -m soc_agent.monthly_report                     # previous month, console
    python -m soc_agent.monthly_report --month 2026-07
    python -m soc_agent.monthly_report --month 2026-07 --out /tmp/rapport.md
    python -m soc_agent.monthly_report --month 2026-07 --iris
"""

from __future__ import annotations

import argparse
import logging
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import psycopg
from jinja2 import Environment, FileSystemLoader
from psycopg.rows import dict_row

from . import config, metrics, vulns

log = logging.getLogger("monthly_report")

# Inside soc_agent/, NOT in src/iris/report-templates/: the Docker build
# context of this image is src/ai (see Dockerfile, `COPY soc_agent/
# soc_agent/`) — src/iris never ships in the container. Unlike
# incident-technique-fr.md, which IRIS renders server-side after upload, this
# template is rendered by THIS code, so it has to travel with it.
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
TEMPLATE_NAME = "rapport-mensuel-fr.md"


def _period(month: str | None) -> tuple[date, date, str]:
    """(start, end_exclusive, label) of the requested month.

    Default: the PREVIOUS calendar month — a report for August is generated
    once August is over, not mid-way through it. `end` is exclusive so every
    query below stays a plain `>= start AND < end`, with no month-length
    arithmetic repeated at each call site.
    """
    if month:
        y, m = (int(x) for x in month.split("-", 1))
    else:
        today = date.today()
        y, m = (today.year, today.month - 1) if today.month > 1 else (today.year - 1, 12)
    start = date(y, m, 1)
    end = date(y + 1, 1, 1) if m == 12 else date(y, m + 1, 1)
    return start, end, f"{y:04d}-{m:02d}"


def _section_alerting(conn, start: date, end: date) -> dict:
    total = conn.execute(
        "SELECT count(*) n FROM alerts WHERE ts >= %s AND ts < %s",
        (start, end)).fetchone()["n"]
    suppressed = conn.execute(
        "SELECT count(*) n FROM alerts WHERE ts >= %s AND ts < %s AND suppressed",
        (start, end)).fetchone()["n"]

    by_severity = [
        {"level": r["level_bucket"], "n": r["n"]}
        for r in conn.execute(
            "SELECT CASE WHEN rule_level >= 15 THEN 'critical' "
            "            WHEN rule_level >= 12 THEN 'high' "
            "            WHEN rule_level >= 8  THEN 'medium' "
            "            ELSE 'low' END AS level_bucket, "
            "       count(*) n "
            "  FROM alerts WHERE ts >= %s AND ts < %s AND NOT suppressed "
            " GROUP BY 1 ORDER BY 1", (start, end))]

    top_rules = [dict(r) for r in conn.execute(
        "SELECT rule_id, rule_desc, count(*) n "
        "  FROM alerts WHERE ts >= %s AND ts < %s AND NOT suppressed "
        " GROUP BY rule_id, rule_desc ORDER BY n DESC LIMIT 10",
        (start, end))]

    top_tactics = [dict(r) for r in conn.execute(
        "SELECT tactic, count(*) n FROM ("
        "  SELECT unnest(mitre_tactics) tactic FROM alerts "
        "   WHERE ts >= %s AND ts < %s AND NOT suppressed) t "
        " WHERE tactic <> '' GROUP BY tactic ORDER BY n DESC LIMIT 10",
        (start, end))]

    incidents = conn.execute(
        "SELECT count(*) n FROM incidents "
        " WHERE first_seen >= %s AND first_seen < %s", (start, end)).fetchone()["n"]

    # TP/FP: joined on `labels`, which only exists for incidents an analyst
    # actually reviewed. Absence of a label is reported as its own bucket
    # rather than folded into one side or the other — silently assuming
    # "unlabeled = false positive" (or the reverse) would fabricate an accuracy
    # figure nobody measured.
    verdicts = [dict(r) for r in conn.execute(
        "SELECT coalesce(l.verdict, 'non_labellise') verdict, count(*) n "
        "  FROM incidents i LEFT JOIN labels l ON l.incident_id = i.id "
        " WHERE i.first_seen >= %s AND i.first_seen < %s "
        " GROUP BY 1 ORDER BY 2 DESC", (start, end))]

    return {
        "total": total, "suppressed": suppressed,
        "kept_pct": round(100 * (total - suppressed) / total, 1) if total else 0,
        "by_severity": by_severity, "top_rules": top_rules,
        "top_tactics": top_tactics, "incidents": incidents,
        "verdicts": verdicts,
    }


def _section_global_kpi(conn, start: date, end: date) -> dict:
    """KPI mirroring the Wazuh "Global" OSD dashboard (soc-ai-global), on the
    SAME population: every ingested alert, suppressed ones INCLUDED — the
    indexer this dashboard reads from has no notion of soc-agent's
    post-retrieval noise filter. Read `_section_alerting` for the filtered
    view instead; the two intentionally disagree, and both numbers are real.

    Severity buckets mirror `rule.severity` as computed by the ingest
    pipeline (Low/Medium/High/Critical), themselves aligned on the same
    thresholds as `iris.THRESHOLDS_SEVERITY` (12=high, 15=critical).
    """
    total = conn.execute(
        "SELECT count(*) n FROM alerts WHERE ts >= %s AND ts < %s",
        (start, end)).fetchone()["n"]
    actionable = conn.execute(
        "SELECT count(*) n FROM alerts WHERE ts >= %s AND ts < %s "
        "   AND rule_level >= 8", (start, end)).fetchone()["n"]
    highcrit = conn.execute(
        "SELECT count(*) n FROM alerts WHERE ts >= %s AND ts < %s "
        "   AND rule_level >= 12", (start, end)).fetchone()["n"]
    active_machines = conn.execute(
        "SELECT count(DISTINCT agent_id) n FROM alerts "
        " WHERE ts >= %s AND ts < %s", (start, end)).fetchone()["n"]

    top_rules = [dict(r) for r in conn.execute(
        "SELECT rule_id, rule_desc, count(*) n "
        "  FROM alerts WHERE ts >= %s AND ts < %s "
        " GROUP BY rule_id, rule_desc ORDER BY n DESC LIMIT 10", (start, end))]

    top_tactics = [dict(r) for r in conn.execute(
        "SELECT tactic, count(*) n FROM ("
        "  SELECT unnest(mitre_tactics) tactic FROM alerts "
        "   WHERE ts >= %s AND ts < %s AND rule_level >= 8) t "
        " WHERE tactic <> '' GROUP BY tactic ORDER BY n DESC LIMIT 10",
        (start, end))]

    top_srcips = [dict(r) for r in conn.execute(
        "SELECT srcip, count(*) n FROM alerts "
        " WHERE ts >= %s AND ts < %s AND rule_level >= 8 AND srcip IS NOT NULL "
        " GROUP BY srcip ORDER BY n DESC LIMIT 15", (start, end))]

    return {
        "total_events": total, "actionable_events": actionable,
        "highcrit_events": highcrit, "active_machines": active_machines,
        "top_rules": top_rules, "top_tactics": top_tactics,
        "top_srcips": top_srcips,
    }


def _section_performance(conn, start: date, end: date) -> dict:
    """MTTD/MTTR of incidents OPENED this period — same formula as the
    `soc-ai-mttd`/`soc-ai-mttr` dashboard tiles (`metrics._doc_kpi`): MTTD is
    `created_at - first_seen` (sensor -> detection), MTTR is
    `first remediation applied - created_at` (detection -> action). Reusing
    `metrics.REMEDIED_STATUSES` keeps a single definition of "remediated" —
    a `sent`-but-unconfirmed action must not stop this clock (cf.
    metrics.py's own comment on the 2026-08-02 false "26 quarantines").
    """
    row = conn.execute(f"""
        SELECT
            avg(extract(epoch FROM i.created_at - i.first_seen) / 60) mttd_avg,
            percentile_cont(0.5) WITHIN GROUP (
                ORDER BY extract(epoch FROM i.created_at - i.first_seen) / 60
            ) mttd_median,
            avg(extract(epoch FROM rem.remediated_at - i.created_at) / 60) mttr_avg,
            percentile_cont(0.5) WITHIN GROUP (
                ORDER BY extract(epoch FROM rem.remediated_at - i.created_at) / 60
            ) mttr_median,
            count(*) total_incidents,
            count(rem.remediated_at) remediated_count
          FROM incidents i
          LEFT JOIN LATERAL (
              SELECT min(m.executed_at) remediated_at FROM mitigations m
               WHERE m.incident_id = i.id
                 AND m.status IN {metrics.REMEDIED_STATUSES}
          ) rem ON true
         WHERE i.created_at >= %s AND i.created_at < %s
        """, (start, end)).fetchone()

    def _round(v):
        return round(v, 1) if v is not None else None

    return {
        "mttd_avg_minutes": _round(row["mttd_avg"]),
        "mttd_median_minutes": _round(row["mttd_median"]),
        "mttr_avg_minutes": _round(row["mttr_avg"]),
        "mttr_median_minutes": _round(row["mttr_median"]),
        "total_incidents": row["total_incidents"],
        "remediated_count": row["remediated_count"],
        "remediated_pct": (round(100 * row["remediated_count"] /
                                 row["total_incidents"], 1)
                          if row["total_incidents"] else None),
    }


def _section_hosts(conn, start: date, end: date) -> dict:
    top_hosts = [dict(r) for r in conn.execute(
        "SELECT i.agent_id, i.agent_name, count(*) incidents, "
        "       max(i.max_level) max_level, "
        "       coalesce(a.priority, %s) priority, a.role "
        "  FROM incidents i LEFT JOIN assets a ON a.agent_id = i.agent_id "
        " WHERE i.first_seen >= %s AND i.first_seen < %s "
        " GROUP BY i.agent_id, i.agent_name, a.priority, a.role "
        " ORDER BY incidents DESC, max_level DESC LIMIT 15",
        (config.DEFAULT_PRIORITY, start, end))]

    distinct = conn.execute(
        "SELECT count(DISTINCT agent_id) n FROM incidents "
        " WHERE first_seen >= %s AND first_seen < %s", (start, end)).fetchone()["n"]

    by_priority = [dict(r) for r in conn.execute(
        "SELECT coalesce(a.priority, %s) priority, count(*) incidents "
        "  FROM incidents i LEFT JOIN assets a ON a.agent_id = i.agent_id "
        " WHERE i.first_seen >= %s AND i.first_seen < %s "
        " GROUP BY 1 ORDER BY 1", (config.DEFAULT_PRIORITY, start, end))]

    return {"distinct_agents": distinct, "top_hosts": top_hosts,
            "by_priority": by_priority}


def _section_remediation(conn, start: date, end: date) -> dict:
    by_status = [dict(r) for r in conn.execute(
        "SELECT status, count(*) n FROM mitigations "
        " WHERE executed_at >= %s AND executed_at < %s "
        " GROUP BY status ORDER BY n DESC", (start, end))]
    by_action = [dict(r) for r in conn.execute(
        "SELECT action, count(*) n FROM mitigations "
        " WHERE executed_at >= %s AND executed_at < %s AND status = 'executed' "
        " GROUP BY action ORDER BY n DESC", (start, end))]
    cases = conn.execute(
        "SELECT count(*) n FROM incidents "
        " WHERE first_seen >= %s AND first_seen < %s AND iris_case_id IS NOT NULL",
        (start, end)).fetchone()["n"]
    return {"by_status": by_status, "by_action": by_action, "iris_cases": cases}


def _section_vulnerability(conn) -> dict:
    """Current VOC state, not a period slice: `vulnerabilities` is a live
    journal (open/fixed), not an event log — "vulnerabilities open on
    2026-07-31" is the meaningful reading, not "opened during July"."""
    expos = vulns.fleet_exposure(conn)
    total_assets = conn.execute("SELECT count(*) n FROM assets").fetchone()["n"]
    scanned = conn.execute(
        "SELECT count(DISTINCT agent_id) n FROM vulnerabilities").fetchone()["n"]
    open_by_sev = conn.execute(
        "SELECT severity, count(*) n FROM vulnerabilities "
        " WHERE status = 'open' GROUP BY severity ORDER BY n DESC").fetchall()
    fixed_30d = conn.execute(
        "SELECT count(*) n, "
        "       avg(extract(epoch FROM fixed_at - first_seen) / 86400) mttr "
        "  FROM vulnerabilities "
        " WHERE status = 'fixed' AND fixed_at >= now() - interval '30 days'"
    ).fetchone()
    new_30d = conn.execute(
        "SELECT count(*) n FROM vulnerabilities "
        " WHERE first_seen >= now() - interval '30 days'").fetchone()["n"]

    return {
        "coverage_pct": round(100 * scanned / total_assets, 1) if total_assets else None,
        "scanned": scanned, "total_assets": total_assets,
        "open_by_severity": [dict(r) for r in open_by_sev],
        "outside_sla_total": sum(e["outside_sla_total"] for e in expos),
        "new_30d": new_30d, "fixed_30d": fixed_30d["n"],
        "mttr_days": round(fixed_30d["mttr"], 1) if fixed_30d["mttr"] else None,
        "top_exposed": [
            {"agent_id": e["agent_id"], "agent_name": e["agent_name"],
             "priority": e["priority"], "score": e["score"], "level": e["level"],
             "critical": e["critical_count"], "high": e["high_count"],
             "outside_sla": e["outside_sla_total"]}
            for e in expos[:10]],
    }


def report(month: str | None = None) -> dict:
    start, end, label = _period(month)
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        return {
            "period": label, "start": start.isoformat(),
            "end": (end - timedelta(days=1)).isoformat(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "alerting": _section_alerting(conn, start, end),
            "global_kpi": _section_global_kpi(conn, start, end),
            "performance": _section_performance(conn, start, end),
            "hosts": _section_hosts(conn, start, end),
            "remediation": _section_remediation(conn, start, end),
            "vulnerability": _section_vulnerability(conn),
        }


def render_markdown(r: dict) -> str:
    # Markdown output, not HTML: autoescape would mangle `<` and `&` that
    # appear legitimately in rule descriptions and MITRE technique names.
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=False, trim_blocks=True, lstrip_blocks=True)
    return env.get_template(TEMPLATE_NAME).render(**r)


# Directory of the monthly notes, separate from `iris.DIR_ANALYSIS` /
# `iris.EXPOSURE_DIR`: those are per-incident, this one is per-period. A shared
# directory lets an analyst find every monthly report of the client in one
# place in the case, regardless of how many periods have accumulated.
DIR_REPORT = "Rapport mensuel"

# IRIS classification id, read once from the server the same way iris.py reads
# severities (`/manage/case-classifications/list`): the numbering is a
# per-deployment taxonomy, not a stable contract. "other:other" is the closest
# fit — a monthly report is not an incident, it has no attack classification.
_CLASSIF_OTHER_NAME = "other:other"
_CLASSIF_OTHER_FALLBACK = 36  # observed on this deployment's IRIS 2.4.27


def _classification_other(case) -> int:
    try:
        items = case._s.pi_get("/manage/case-classifications/list").get_data() or []
        for c in items:
            if str(c.get("name", "")).lower() == _CLASSIF_OTHER_NAME:
                return c["id"]
    except Exception as e:  # noqa: BLE001 — a wrong classification never blocks
        log.warning("classification IRIS illisible (%s), repli sur %d", e,
                    _CLASSIF_OTHER_FALLBACK)
    return _CLASSIF_OTHER_FALLBACK


def _find_case(case, soc_id: str) -> int | None:
    """Existing case carrying this `soc_id`, or None.

    `list_cases` has no server-side filter: it returns every case of the
    instance (a few dozen here) and we filter client-side. Fine at this
    volume — one call per push, not per incident.
    """
    try:
        for c in case.list_cases().get_data() or []:
            if c.get("case_soc_id") == soc_id:
                return c["case_id"]
    except Exception as e:  # noqa: BLE001
        log.warning("liste des cases IRIS illisible (%s) : nouvelle création "
                    "tentée, un doublon est possible", e)
    return None


def push_to_iris(r: dict) -> int:
    """Create (or reuse) the case of the period and post the report as a note.

    Idempotent on `soc_id = Aura-SOC-rapport-<period>`: replaying the same
    month updates the existing note instead of stacking a case per run — same
    reasoning as `iris._set_note` for a re-triaged incident.
    """
    from . import iris as iris_mod  # deferred: iris.py pulls in the LLM chain

    case = iris_mod._client()
    soc_id = f"Aura-SOC-rapport-{r['period']}"
    case_id = _find_case(case, soc_id)

    if case_id is None:
        resp = case.add_case(
            case_name=f"Rapport mensuel SOC — {r['period']}",
            case_description=(
                f"Rapport mensuel généré automatiquement par "
                f"soc_agent.monthly_report — période {r['start']} → {r['end']}."),
            case_customer=config.IRIS_CUSTOMER,
            case_classification=_classification_other(case),
            soc_id=soc_id,
        )
        if not resp.is_success():
            raise RuntimeError(f"création du case échouée : {resp.get_msg()}")
        case_id = resp.get_data()["case_id"]
        log.info("case IRIS #%s créé pour %s", case_id, r["period"])
    else:
        log.info("case IRIS #%s réutilisé pour %s", case_id, r["period"])

    iris_mod._set_note(case, case_id, f"Rapport — {r['period']}",
                       render_markdown(r), directory=DIR_REPORT)
    return case_id


def show(r: dict) -> None:
    a, g, p = r["alerting"], r["global_kpi"], r["performance"]
    h, m, v = r["hosts"], r["remediation"], r["vulnerability"]
    print("=" * 70)
    print(f"RAPPORT MENSUEL SOC — {r['period']}")
    print("=" * 70)
    print(f"\nGlobal (brut, comme le dashboard Wazuh) : {g['total_events']} "
          f"evenements, {g['actionable_events']} actionnables (>=Medium), "
          f"{g['highcrit_events']} High+Critical, {g['active_machines']} "
          f"machines emettrices")
    print(f"MTTD moyen {p['mttd_avg_minutes']} min (median "
          f"{p['mttd_median_minutes']})  MTTR moyen {p['mttr_avg_minutes']} min "
          f"(median {p['mttr_median_minutes']})  remedies {p['remediated_pct']}%")
    print(f"\nAlerting (apres filtrage bruit) : {a['total']} alertes "
          f"({a['suppressed']} filtrees, {a['kept_pct']}% retenues), "
          f"{a['incidents']} incidents")
    for s in a["by_severity"]:
        print(f"  {s['level']:<10} {s['n']:6d}")
    print("  Verdicts :", ", ".join(f"{v_['verdict']}={v_['n']}" for v_ in a["verdicts"]))

    print(f"\nMachines : {h['distinct_agents']} distinctes touchees")
    for host in h["top_hosts"][:5]:
        print(f"  {host['agent_name'] or host['agent_id']:<20} "
              f"P{host['priority']}  {host['incidents']} incident(s)")

    print(f"\nRemediation : {m['iris_cases']} cases IRIS")
    for s in m["by_status"]:
        print(f"  {s['status']:<12} {s['n']:4d}")

    print(f"\nVulnerabilites : couverture {v['coverage_pct']}% "
          f"({v['scanned']}/{v['total_assets']} machines)")
    print(f"  hors SLA : {v['outside_sla_total']}  nouvelles (30j) : {v['new_30d']}  "
          f"corrigees (30j) : {v['fixed_30d']}  MTTR : {v['mttr_days']} j")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--month", metavar="AAAA-MM",
                    help="mois cible (defaut : le mois precedent)")
    ap.add_argument("--out", metavar="FICHIER",
                    help="ecrit le rendu Markdown dans ce fichier au lieu du resume console")
    ap.add_argument("--iris", action="store_true",
                    help="pousse le rapport en note sur le case IRIS du mois "
                         "(cree ou reutilise 'Rapport mensuel SOC - AAAA-MM')")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    r = report(args.month)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(render_markdown(r))
        print(f"rapport ecrit : {args.out}")
    if args.iris:
        case_id = push_to_iris(r)
        print(f"rapport poussé sur le case IRIS #{case_id}")
    if not args.out and not args.iris:
        show(r)


if __name__ == "__main__":
    main()
