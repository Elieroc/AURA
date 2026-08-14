"""The report that justifies phase 1.

It answers the one question that decides what comes next: how many incidents
per day will the LLM actually have to handle, and does the architecture hold on
this CPU?

    python -m soc_agent.report

The computation lives in `report()`, which returns a dict; `show()` only formats
it. The split is deliberate: the MCP server serves the dict as-is, without
replaying the queries or parsing tabulated text.
"""

import psycopg
from psycopg.rows import dict_row

from . import config

# 15 to 25 s per triage, measured on DeepSeek. We take the high end.
SECONDS_PER_TRIAGE = 25


def report() -> dict:
    """Filtering funnel and induced LLM load, as raw data.

    `{"empty": True}` if no alert has been ingested yet — the caller must test
    that case before reading the other keys, which are then absent.
    """
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        total = conn.execute("SELECT count(*) n FROM alerts").fetchone()["n"]
        if not total:
            return {"empty": True}

        days = float(conn.execute(
            "SELECT greatest(extract(epoch FROM max(ts) - min(ts)) / 86400, 1) j "
            "FROM alerts").fetchone()["j"])
        deleted = conn.execute(
            "SELECT count(*) n FROM alerts WHERE suppressed").fetchone()["n"]
        kept = conn.execute(
            "SELECT count(*) n FROM alerts "
            "WHERE rule_level >= %s AND NOT suppressed",
            (config.MIN_LEVEL,)).fetchone()["n"]
        incidents = conn.execute("SELECT count(*) n FROM incidents").fetchone()["n"]

        by_level = [
            {"level": r["rule_level"], "n": r["n"],
             "processed": r["rule_level"] >= config.MIN_LEVEL}
            for r in conn.execute(
                "SELECT rule_level, count(*) n FROM alerts "
                "GROUP BY rule_level ORDER BY rule_level")
        ]

        top = [
            {"id": r["id"], "agent_name": r["agent_name"],
             "first_seen": r["first_seen"].isoformat(),
             "alert_count": r["alert_count"], "max_level": r["max_level"],
             "rule_ids": r["rule_ids"], "mitre_tactics": r["mitre_tactics"]}
            for r in conn.execute("""
                SELECT i.id, i.agent_name, i.first_seen, i.alert_count,
                       i.max_level, i.rule_ids, i.mitre_tactics
                  FROM incidents i ORDER BY i.max_level DESC, i.alert_count DESC
                 LIMIT 15""")
        ]

    per_day = incidents / days
    seconds = per_day * SECONDS_PER_TRIAGE
    # Without correlation every alert would go to triage. That is the measure of
    # what phase 1 actually buys.
    without = kept / days * SECONDS_PER_TRIAGE

    if seconds > 8 * 3600:
        verdict = "untenable"
    elif seconds > 2 * 3600:
        verdict = "tight"
    else:
        verdict = "comfortable"

    return {
        "empty": False,
        "funnel": {
            "total": total,
            "days": days,
            "per_day": total / days,
            "suppressed": deleted,
            "kept": kept,
            "min_level": config.MIN_LEVEL,
            "kept_pct": 100 * kept / total,
            "incidents": incidents,
            "factor": (kept / incidents) if incidents else None,
        },
        "by_level": by_level,
        "incidents": top,
        "llm_load": {
            "incidents_per_day": per_day,
            "seconds_per_triage": SECONDS_PER_TRIAGE,
            "minutes_per_day": seconds / 60,
            "minutes_per_day_without_correlation": without / 60,
            "correlation_gain": without / max(seconds, 1),
            "verdict": verdict,
        },
    }


VERDICTS_TEXT = {
    "untenable": "untenable. Filter harder before going any further.",
    "tight": "tight. Viable, but with no margin — watch for drift.",
    "comfortable": "comfortable. We can afford more context per triage.",
}


def show(r: dict) -> None:
    if r["empty"]:
        print("Empty database — run the ingestion first.")
        return

    f, c = r["funnel"], r["llm_load"]
    print("=" * 66)
    print("FILTERING FUNNEL")
    print("=" * 66)
    print(f"  Alerts ingested             {f['total']:6d}   "
          f"over {f['days']:.1f} days ({f['per_day']:.0f}/day)")
    print(f"  Dropped (noise filter)      {f['suppressed']:6d}   "
          f"post-retrieval, kept for audit")
    print(f"  Kept (level >= {f['min_level']:2d})          {f['kept']:6d}   "
          f"{f['kept_pct']:.1f} % of the total")
    print(f"  Incidents after correlation {f['incidents']:6d}", end="")
    print(f"   factor {f['factor']:.1f}x" if f["factor"] else "")

    print()
    print("-" * 66)
    print("BREAKDOWN BY LEVEL")
    print("-" * 66)
    for n in r["by_level"]:
        mark = " <- processed" if n["processed"] else ""
        print(f"  level {n['level']:2d}  {n['n']:6d}{mark}")

    print()
    print("-" * 66)
    print("INCIDENTS")
    print("-" * 66)
    for i in r["incidents"]:
        tac = ",".join(i["mitre_tactics"]) or "-"
        print(f"  #{i['id']:<4} {i['first_seen'][5:16].replace('T', ' ')} "
              f"{i['agent_name'] or '?':<14} lvl {i['max_level']:2d}  "
              f"{i['alert_count']:3d} alerts  "
              f"rules {','.join(i['rule_ids'])[:32]:<32} [{tac}]")

    print()
    print("=" * 66)
    print("LLM LOAD")
    print("=" * 66)
    print(f"  {c['incidents_per_day']:.1f} incidents/day x "
          f"{c['seconds_per_triage']} s = {c['minutes_per_day']:.1f} min "
          f"of CPU per day")
    print(f"  Without correlation: {c['minutes_per_day_without_correlation']:.1f} "
          f"min/day ({c['correlation_gain']:.1f}x more)")
    print(f"\n  VERDICT: {VERDICTS_TEXT[c['verdict']]}")


def main() -> None:
    show(report())


if __name__ == "__main__":
    main()
