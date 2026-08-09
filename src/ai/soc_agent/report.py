"""Le rapport qui justifie la phase 1.

Répond à la seule question qui décide de la suite : combien d'incidents par
jour le LLM aura-t-il réellement à traiter, et donc l'architecture tient-elle
sur ce CPU ?

    python -m soc_agent.report

Le calcul vit dans `rapport()`, qui rend un dict ; `afficher()` ne fait que le
mettre en forme. Séparation voulue : le serveur MCP sert le dict tel quel, sans
avoir à rejouer les requêtes ni à parser du texte tabulé.
"""

import psycopg
from psycopg.rows import dict_row

from . import config

# 15 à 25 s par triage, mesurées sur DeepSeek. On prend le haut de la fourchette.
SECONDES_PAR_TRIAGE = 25


def rapport() -> dict:
    """Entonnoir de filtrage et charge LLM induite, en données brutes.

    `{"vide": True}` si aucune alerte n'a encore été ingérée — l'appelant doit
    tester ce cas avant de lire les autres clés, qui sont alors absentes.
    """
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        total = conn.execute("SELECT count(*) n FROM alerts").fetchone()["n"]
        if not total:
            return {"vide": True}

        jours = float(conn.execute(
            "SELECT greatest(extract(epoch FROM max(ts) - min(ts)) / 86400, 1) j "
            "FROM alerts").fetchone()["j"])
        supprimees = conn.execute(
            "SELECT count(*) n FROM alerts WHERE suppressed").fetchone()["n"]
        retenues = conn.execute(
            "SELECT count(*) n FROM alerts "
            "WHERE rule_level >= %s AND NOT suppressed",
            (config.MIN_LEVEL,)).fetchone()["n"]
        incidents = conn.execute("SELECT count(*) n FROM incidents").fetchone()["n"]

        par_niveau = [
            {"niveau": r["rule_level"], "n": r["n"],
             "traite": r["rule_level"] >= config.MIN_LEVEL}
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

    par_jour = incidents / jours
    secondes = par_jour * SECONDES_PAR_TRIAGE
    # Sans corrélation, chaque alerte partirait au triage. C'est la mesure de ce
    # que la phase 1 rapporte réellement.
    sans = retenues / jours * SECONDES_PAR_TRIAGE

    if secondes > 8 * 3600:
        verdict = "intenable"
    elif secondes > 2 * 3600:
        verdict = "tendu"
    else:
        verdict = "large"

    return {
        "vide": False,
        "entonnoir": {
            "total": total,
            "jours": jours,
            "par_jour": total / jours,
            "supprimees": supprimees,
            "retenues": retenues,
            "min_level": config.MIN_LEVEL,
            "part_retenues_pct": 100 * retenues / total,
            "incidents": incidents,
            "facteur": (retenues / incidents) if incidents else None,
        },
        "par_niveau": par_niveau,
        "incidents": top,
        "charge_llm": {
            "incidents_par_jour": par_jour,
            "secondes_par_triage": SECONDES_PAR_TRIAGE,
            "minutes_par_jour": secondes / 60,
            "minutes_par_jour_sans_correlation": sans / 60,
            "gain_correlation": sans / max(secondes, 1),
            "verdict": verdict,
        },
    }


VERDICTS_TEXTE = {
    "intenable": "intenable. Filtrer davantage avant d'aller plus loin.",
    "tendu": "tendu. Viable, mais sans marge — surveiller la dérive.",
    "large": "large. On peut se permettre plus de contexte par triage.",
}


def afficher(r: dict) -> None:
    if r["vide"]:
        print("Base vide — lancer l'ingestion d'abord.")
        return

    e, c = r["entonnoir"], r["charge_llm"]
    print("=" * 66)
    print("ENTONNOIR DE FILTRAGE")
    print("=" * 66)
    print(f"  Alertes ingérées            {e['total']:6d}   "
          f"sur {e['jours']:.1f} jours ({e['par_jour']:.0f}/jour)")
    print(f"  Écartées (noise filter)     {e['supprimees']:6d}   "
          f"post-retrieval, conservées pour l'audit")
    print(f"  Retenues (niveau >= {e['min_level']:2d})     {e['retenues']:6d}   "
          f"{e['part_retenues_pct']:.1f} % du total")
    print(f"  Incidents après corrélation {e['incidents']:6d}", end="")
    print(f"   facteur {e['facteur']:.1f}x" if e["facteur"] else "")

    print()
    print("-" * 66)
    print("RÉPARTITION PAR NIVEAU")
    print("-" * 66)
    for n in r["par_niveau"]:
        marque = " <- traité" if n["traite"] else ""
        print(f"  niveau {n['niveau']:2d}  {n['n']:6d}{marque}")

    print()
    print("-" * 66)
    print("INCIDENTS")
    print("-" * 66)
    for i in r["incidents"]:
        tac = ",".join(i["mitre_tactics"]) or "-"
        print(f"  #{i['id']:<4} {i['first_seen'][5:16].replace('T', ' ')} "
              f"{i['agent_name'] or '?':<14} lvl {i['max_level']:2d}  "
              f"{i['alert_count']:3d} alertes  "
              f"règles {','.join(i['rule_ids'])[:32]:<32} [{tac}]")

    print()
    print("=" * 66)
    print("CHARGE LLM")
    print("=" * 66)
    print(f"  {c['incidents_par_jour']:.1f} incidents/jour x "
          f"{c['secondes_par_triage']} s = {c['minutes_par_jour']:.1f} min "
          f"de CPU par jour")
    print(f"  Sans corrélation : {c['minutes_par_jour_sans_correlation']:.1f} "
          f"min/jour ({c['gain_correlation']:.1f}x plus)")
    print(f"\n  VERDICT : {VERDICTS_TEXTE[c['verdict']]}")


def main() -> None:
    afficher(rapport())


if __name__ == "__main__":
    main()
