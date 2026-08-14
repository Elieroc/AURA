"""Ground truth entered by an analyst.

Without a labelled set we know the model answers, not whether it is right. That
is the only prerequisite to leaving shadow mode, and there is no shortcut: the
label must come from a human who looked at the incident.

    python -m soc_agent.label --list
    python -m soc_agent.label 4 --show
    python -m soc_agent.label 4 --verdict true_positive \\
        --actions propose_isolate_host,propose_block_ip \\
        --comment "simulated ransomware, internal exercise of 2026-07-22"
"""

import argparse

import psycopg
from psycopg.rows import dict_row

from . import config
from .render import render

VERDICTS = ("true_positive", "false_positive", "needs_investigation")


def labels_state() -> list[dict]:
    """One incident per row, with its human label and the model's verdict."""
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        lines = conn.execute("""
            SELECT i.id, i.agent_name, i.first_seen, i.alert_count, i.max_level,
                   l.verdict AS label, t.verdict AS model
              FROM incidents i
              LEFT JOIN labels l ON l.incident_id = i.id
              LEFT JOIN LATERAL (
                    SELECT verdict FROM triages
                     WHERE incident_id = i.id ORDER BY created_at DESC LIMIT 1
              ) t ON true
             ORDER BY l.verdict IS NOT NULL, i.max_level DESC, i.first_seen DESC
        """).fetchall()
    return [{"id": r["id"], "agent_name": r["agent_name"],
             "first_seen": r["first_seen"].isoformat(),
             "alert_count": r["alert_count"], "max_level": r["max_level"],
             "label": r["label"], "model_verdict": r["model"]}
            for r in lines]


def list_incidents() -> None:
    lines = labels_state()
    if not lines:
        print("No incident.")
        return

    print(f"{'#':<5} {'date':<12} {'host':<14} {'lvl':<4} {'alerts':<8} "
          f"{'human label':<20} {'model verdict'}")
    for r in lines:
        print(f"{r['id']:<5} {r['first_seen'][5:16].replace('T', ' ')}  "
              f"{r['agent_name'] or '?':<14} {r['max_level']:<4} "
              f"{r['alert_count']:<8} {r['label'] or '— TO LABEL':<20} "
              f"{r['model_verdict'] or '-'}")

    missing = sum(1 for r in lines if not r["label"])
    print(f"\n{missing} incident(s) without a label.")


def incident_view(incident_id: int) -> dict | None:
    """The incident **as the model sees it** (prompt rendering) plus its triage.

    `None` if the incident does not exist. The rendering is the exact text sent
    to the LLM: that is what allows judging on evidence, not a paraphrase.
    """
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        inc = conn.execute(
            "SELECT * FROM incidents WHERE id = %s", (incident_id,)).fetchone()
        if not inc:
            return None
        alerts = conn.execute(
            "SELECT id, ts, rule_id, rule_level, rule_desc, srcip, srcuser, "
            "entity, raw FROM alerts WHERE incident_id = %s ORDER BY ts",
            (incident_id,)).fetchall()
        t = conn.execute(
            "SELECT * FROM triages WHERE incident_id = %s "
            "ORDER BY created_at DESC LIMIT 1", (incident_id,)).fetchone()

    return {
        "incident_id": incident_id,
        "rendering": render(inc, alerts),
        "triage": None if not t else {
            "model": t["model"], "verdict": t["verdict"],
            "confidence": t["confidence"], "actions": t["actions"],
            "reason": t["reason"], "created_at": t["created_at"].isoformat(),
            "inconsistencies": t["inconsistencies"],
            "injection_patterns": t["injection_patterns"],
            "guardrails": t["guardrails"],
        },
    }


def show(incident_id: int) -> None:
    """Prints the incident as the model sees it, to judge on evidence."""
    v = incident_view(incident_id)
    if not v:
        print(f"Unknown incident {incident_id}.")
        return
    print(v["rendering"])
    t = v["triage"]
    if t:
        print(f"\n-- model verdict ({t['model']}) --")
        print(f"   {t['verdict']} / {t['confidence']} -> "
              f"{', '.join(t['actions'])}")
        print(f"   {t['reason']}")


def register(incident_id: int, verdict: str, actions: list[str],
                comment: str | None, by: str) -> None:
    with psycopg.connect(config.PG_DSN) as conn:
        conn.execute("""
            INSERT INTO labels (incident_id, verdict, actions, comment,
                                origin, labeled_by)
            VALUES (%s, %s, %s, %s, 'human', %s)
            ON CONFLICT (incident_id) DO UPDATE
              SET verdict = EXCLUDED.verdict, actions = EXCLUDED.actions,
                  comment = EXCLUDED.comment,
                  labeled_by = EXCLUDED.labeled_by
        """, (incident_id, verdict, actions, comment, by))
        conn.commit()
    print(f"Incident {incident_id} labelled: {verdict}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("incident", type=int, nargs="?")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--show", action="store_true",
                    help="print the incident as the model sees it")
    ap.add_argument("--verdict", choices=VERDICTS)
    ap.add_argument("--actions", default="",
                    help="comma-separated list")
    ap.add_argument("--comment")
    ap.add_argument("--by", default="analyst")
    args = ap.parse_args()

    if args.list or args.incident is None:
        list_incidents()
        return
    if args.show:
        show(args.incident)
        return
    if not args.verdict:
        ap.error("--verdict is required to label (or --show / --list)")

    actions = [a.strip() for a in args.actions.split(",") if a.strip()]
    register(args.incident, args.verdict, actions, args.comment, args.by)


if __name__ == "__main__":
    main()
