"""Le rapport qui justifie la phase 1.

Répond à la seule question qui décide de la suite : combien d'incidents par
jour le LLM aura-t-il réellement à traiter, et donc l'architecture tient-elle
sur ce CPU ?

    python -m soc_agent.report
"""

import psycopg
from psycopg.rows import dict_row

from . import config

# 15 à 25 s par triage, mesurées sur DeepSeek. On prend le haut de la fourchette.
SECONDES_PAR_TRIAGE = 25


def main() -> None:
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        total = conn.execute("SELECT count(*) n FROM alerts").fetchone()["n"]
        if not total:
            print("Base vide — lancer l'ingestion d'abord.")
            return

        print("=" * 66)
        print("ENTONNOIR DE FILTRAGE")
        print("=" * 66)

        jours = conn.execute(
            "SELECT greatest(extract(epoch FROM max(ts) - min(ts)) / 86400, 1) j "
            "FROM alerts").fetchone()["j"]
        supprimees = conn.execute(
            "SELECT count(*) n FROM alerts WHERE suppressed").fetchone()["n"]
        retenues = conn.execute(
            "SELECT count(*) n FROM alerts "
            "WHERE rule_level >= %s AND NOT suppressed",
            (config.MIN_LEVEL,)).fetchone()["n"]
        incidents = conn.execute("SELECT count(*) n FROM incidents").fetchone()["n"]

        print(f"  Alertes ingérées            {total:6d}   sur {jours:.1f} jours "
              f"({total / jours:.0f}/jour)")
        print(f"  Écartées (noise filter)     {supprimees:6d}   "
              f"post-retrieval, conservées pour l'audit")
        print(f"  Retenues (niveau >= {config.MIN_LEVEL:2d})     {retenues:6d}   "
              f"{100 * retenues / total:.1f} % du total")
        print(f"  Incidents après corrélation {incidents:6d}", end="")
        if incidents:
            print(f"   facteur {retenues / incidents:.1f}x")
        else:
            print()

        print()
        print("-" * 66)
        print("RÉPARTITION PAR NIVEAU")
        print("-" * 66)
        for r in conn.execute(
                "SELECT rule_level, count(*) n FROM alerts "
                "GROUP BY rule_level ORDER BY rule_level"):
            marque = " <- traité" if r["rule_level"] >= config.MIN_LEVEL else ""
            print(f"  niveau {r['rule_level']:2d}  {r['n']:6d}{marque}")

        print()
        print("-" * 66)
        print("INCIDENTS")
        print("-" * 66)
        for r in conn.execute("""
                SELECT i.id, i.agent_name, i.first_seen, i.alert_count,
                       i.max_level, i.rule_ids, i.mitre_tactics
                  FROM incidents i ORDER BY i.max_level DESC, i.alert_count DESC
                 LIMIT 15"""):
            tac = ",".join(r["mitre_tactics"]) or "-"
            print(f"  #{r['id']:<4} {r['first_seen']:%m-%d %H:%M} "
                  f"{r['agent_name'] or '?':<14} lvl {r['max_level']:2d}  "
                  f"{r['alert_count']:3d} alertes  "
                  f"règles {','.join(r['rule_ids'])[:32]:<32} [{tac}]")

        print()
        print("=" * 66)
        print("CHARGE LLM")
        print("=" * 66)
        par_jour = incidents / jours
        secondes = par_jour * SECONDES_PAR_TRIAGE
        print(f"  {par_jour:.1f} incidents/jour x {SECONDES_PAR_TRIAGE} s "
              f"= {secondes / 60:.1f} min de CPU par jour")

        # Sans corrélation, chaque alerte partirait au triage. C'est la mesure
        # de ce que la phase 1 rapporte réellement.
        sans = retenues / jours * SECONDES_PAR_TRIAGE
        print(f"  Sans corrélation : {sans / 60:.1f} min/jour "
              f"({sans / max(secondes, 1):.1f}x plus)")

        if secondes > 8 * 3600:
            print("\n  VERDICT : intenable. Filtrer davantage avant d'aller plus loin.")
        elif secondes > 2 * 3600:
            print("\n  VERDICT : tendu. Viable, mais sans marge — surveiller la dérive.")
        else:
            print("\n  VERDICT : large. On peut se permettre plus de contexte par triage.")


if __name__ == "__main__":
    main()
