"""Saisie de la vérité terrain par un analyste.

Sans jeu labellisé, on sait que le modèle répond, pas s'il a raison. C'est le
seul prérequis à la sortie du mode shadow, et il n'y a pas de raccourci : le
label doit venir d'un humain qui a regardé l'incident.

    python -m soc_agent.label --lister
    python -m soc_agent.label 4 --montrer
    python -m soc_agent.label 4 --verdict true_positive \\
        --actions propose_isolate_host,propose_block_ip \\
        --commentaire "ransomware simulé, exercice interne du 22/07"
"""

import argparse

import psycopg
from psycopg.rows import dict_row

from . import config
from .render import render

VERDICTS = ("true_positive", "false_positive", "needs_investigation")


def labels_state() -> list[dict]:
    """Un incident par ligne, avec son label humain et le verdict du modèle."""
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
             "label": r["label"], "verdict_modele": r["model"]}
            for r in lines]


def list() -> None:
    lines = labels_state()
    if not lines:
        print("Aucun incident.")
        return

    print(f"{'#':<5} {'date':<12} {'hôte':<14} {'lvl':<4} {'alertes':<8} "
          f"{'label humain':<20} {'verdict modèle'}")
    for r in lines:
        print(f"{r['id']:<5} {r['first_seen'][5:16].replace('T', ' ')}  "
              f"{r['agent_name'] or '?':<14} {r['max_level']:<4} "
              f"{r['alert_count']:<8} {r['label'] or '— À LABELLISER':<20} "
              f"{r['verdict_modele'] or '-'}")

    missing = sum(1 for r in lines if not r["label"])
    print(f"\n{missing} incident(s) sans label.")


def incident_view(incident_id: int) -> dict | None:
    """L'incident **tel que le modèle le voit** (rendu du prompt) + son triage.

    `None` si l'incident n'existe pas. Le rendu est le texte exact envoyé au
    LLM : c'est ce qui permet de juger sur pièces, pas une reformulation.
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
        "rendu": render(inc, alerts),
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
    """Affiche l'incident tel que le modèle le voit, pour juger sur pièces."""
    v = incident_view(incident_id)
    if not v:
        print(f"Incident {incident_id} inconnu.")
        return
    print(v["rendu"])
    t = v["triage"]
    if t:
        print(f"\n-- verdict du modèle ({t['model']}) --")
        print(f"   {t['verdict']} / {t['confidence']} -> "
              f"{', '.join(t['actions'])}")
        print(f"   {t['reason']}")


def register(incident_id: int, verdict: str, actions: list[str],
                comment: str | None, by: str) -> None:
    with psycopg.connect(config.PG_DSN) as conn:
        conn.execute("""
            INSERT INTO labels (incident_id, verdict, actions, comment,
                                origin, labeled_by)
            VALUES (%s, %s, %s, %s, 'humain', %s)
            ON CONFLICT (incident_id) DO UPDATE
              SET verdict = EXCLUDED.verdict, actions = EXCLUDED.actions,
                  comment = EXCLUDED.comment,
                  labeled_by = EXCLUDED.labeled_by
        """, (incident_id, verdict, actions, comment, by))
        conn.commit()
    print(f"Incident {incident_id} labellisé : {verdict}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("incident", type=int, nargs="?")
    ap.add_argument("--lister", action="store_true")
    ap.add_argument("--montrer", action="store_true",
                    help="affiche l'incident tel que le modèle le voit")
    ap.add_argument("--verdict", choices=VERDICTS)
    ap.add_argument("--actions", default="",
                    help="liste séparée par des virgules")
    ap.add_argument("--commentaire")
    ap.add_argument("--par", default="analyste")
    args = ap.parse_args()

    if args.list or args.incident is None:
        list()
        return
    if args.show:
        show(args.incident)
        return
    if not args.verdict:
        ap.error("--verdict requis pour labelliser (ou --montrer / --lister)")

    actions = [a.strip() for a in args.actions.split(",") if a.strip()]
    register(args.incident, args.verdict, actions, args.comment, args.by)


if __name__ == "__main__":
    main()
