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
from .render import rendre

VERDICTS = ("true_positive", "false_positive", "needs_investigation")


def lister() -> None:
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        lignes = conn.execute("""
            SELECT i.id, i.agent_name, i.first_seen, i.alert_count, i.max_level,
                   l.verdict AS label, t.verdict AS modele
              FROM incidents i
              LEFT JOIN labels l ON l.incident_id = i.id
              LEFT JOIN LATERAL (
                    SELECT verdict FROM triages
                     WHERE incident_id = i.id ORDER BY created_at DESC LIMIT 1
              ) t ON true
             ORDER BY l.verdict IS NOT NULL, i.max_level DESC, i.first_seen DESC
        """).fetchall()

        if not lignes:
            print("Aucun incident.")
            return

        print(f"{'#':<5} {'date':<12} {'hôte':<14} {'lvl':<4} {'alertes':<8} "
              f"{'label humain':<20} {'verdict modèle'}")
        for r in lignes:
            print(f"{r['id']:<5} {r['first_seen']:%m-%d %H:%M}  "
                  f"{r['agent_name'] or '?':<14} {r['max_level']:<4} "
                  f"{r['alert_count']:<8} {r['label'] or '— À LABELLISER':<20} "
                  f"{r['modele'] or '-'}")

        manquants = sum(1 for r in lignes if not r["label"])
        print(f"\n{manquants} incident(s) sans label.")


def montrer(incident_id: int) -> None:
    """Affiche l'incident tel que le modèle le voit, pour juger sur pièces."""
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        inc = conn.execute(
            "SELECT * FROM incidents WHERE id = %s", (incident_id,)).fetchone()
        if not inc:
            print(f"Incident {incident_id} inconnu.")
            return
        alertes = conn.execute(
            "SELECT id, ts, rule_id, rule_level, rule_desc, srcip, srcuser, "
            "entity, raw FROM alerts WHERE incident_id = %s ORDER BY ts",
            (incident_id,)).fetchall()

        print(rendre(inc, alertes))

        t = conn.execute(
            "SELECT * FROM triages WHERE incident_id = %s "
            "ORDER BY created_at DESC LIMIT 1", (incident_id,)).fetchone()
        if t:
            print(f"\n-- verdict du modèle ({t['modele']}) --")
            print(f"   {t['verdict']} / {t['confidence']} -> "
                  f"{', '.join(t['actions'])}")
            print(f"   {t['reason']}")


def enregistrer(incident_id: int, verdict: str, actions: list[str],
                commentaire: str | None, par: str) -> None:
    with psycopg.connect(config.PG_DSN) as conn:
        conn.execute("""
            INSERT INTO labels (incident_id, verdict, actions, commentaire,
                                origine, labellise_par)
            VALUES (%s, %s, %s, %s, 'humain', %s)
            ON CONFLICT (incident_id) DO UPDATE
              SET verdict = EXCLUDED.verdict, actions = EXCLUDED.actions,
                  commentaire = EXCLUDED.commentaire,
                  labellise_par = EXCLUDED.labellise_par
        """, (incident_id, verdict, actions, commentaire, par))
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

    if args.lister or args.incident is None:
        lister()
        return
    if args.montrer:
        montrer(args.incident)
        return
    if not args.verdict:
        ap.error("--verdict requis pour labelliser (ou --montrer / --lister)")

    actions = [a.strip() for a in args.actions.split(",") if a.strip()]
    enregistrer(args.incident, args.verdict, actions, args.commentaire, args.par)


if __name__ == "__main__":
    main()
