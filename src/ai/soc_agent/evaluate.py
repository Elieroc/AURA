"""Mesure de la justesse du triage, face aux labels humains.

C'est ce rapport qui autorise — ou non — la sortie du mode shadow. Tant que le
nombre d'incidents labellisés reste faible, il le dit explicitement plutôt que
d'afficher un pourcentage flatteur calculé sur trois cas.

Deux mesures, de nature différente :

- **Justesse** : le verdict correspond-il au label humain ? Nécessite des
  labels, donc du travail d'analyste.
- **Cohérence** : le modèle se contredit-il entre son verdict et ses actions ?
  Se mesure **sans label**, sur tous les triages. C'est le signal d'alerte
  disponible immédiatement, notamment après un changement de prompt.

    python -m soc_agent.evaluate

Le calcul vit dans `rapport()`, qui rend un dict ; `afficher()` ne fait que le
mettre en forme (voir report.py, même découpage, mêmes raisons).
"""

import psycopg
from psycopg.rows import dict_row

from . import config

# En dessous, un taux de justesse n'a pas de sens statistique. Le seuil est
# arbitraire mais explicite : mieux vaut refuser de conclure que produire un
# « 100 % » calculé sur quatre incidents.
MINIMUM_USEFUL = 30

# Dernier triage par incident : les passages précédents reflètent des prompts
# abandonnés.
LAST = """
    SELECT DISTINCT ON (incident_id) *
      FROM triages ORDER BY incident_id, created_at DESC
"""


def report() -> dict:
    """Cohérence et justesse du triage, en données brutes.

    Clés toujours présentes : `n_triages`, `coherence`, `justesse`. `coherence`
    et `justesse` valent `None` quand la mesure n'a pas de sens (aucun triage,
    aucun label) — c'est un refus de conclure, pas un zéro.
    """
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        n_triages = conn.execute("SELECT count(*) n FROM triages").fetchone()["n"]
        if not n_triages:
            return {"n_triages": 0, "coherence": None, "justesse": None}

        lines = conn.execute(LAST).fetchall()
        inconsistent = [r for r in lines if r["inconsistencies"]]
        coherence = {
            "n_derniers_triages": len(lines),
            "n_incoherents": len(inconsistent),
            "part_incoherents_pct": 100 * len(inconsistent) / len(lines),
            "incoherents": [
                {"incident_id": r["incident_id"], "patterns": r["inconsistencies"]}
                for r in inconsistent
            ],
            "modeles": [
                {"model": m["model"], "n": m["n"],
                 "duree_moyenne_s": float(m["s"]),
                 "prompt_tokens_moyen": float(m["tok"])}
                for m in conn.execute(
                    f"SELECT modele, count(*) n, avg(duree_ms)/1000 s, "
                    f"avg(prompt_tokens) tok FROM ({LAST}) d GROUP BY modele")
            ],
        }

        matched = conn.execute(f"""
            SELECT d.incident_id, d.verdict AS modele, d.actions AS act_modele,
                   l.verdict AS humain, l.actions AS act_humain, l.origine
              FROM ({LAST}) d
              JOIN labels l ON l.incident_id = d.incident_id
        """).fetchall()
        n_incidents = conn.execute(
            "SELECT count(*) n FROM incidents").fetchone()["n"]

    if not matched:
        return {"n_triages": n_triages, "coherence": coherence,
                "justesse": {"n_labellises": 0, "n_incidents": n_incidents,
                             "taux_pct": None, "desaccords": [],
                             "tp_classes_fp": 0, "conclusion": "sans_label"}}

    fair = [r for r in matched if r["model"] == r["humain"]]
    rate = len(fair) / len(matched)
    # Un faux positif classé vrai positif fait perdre du temps ; l'inverse
    # laisse passer une intrusion. Les deux erreurs n'ont pas le même coût.
    gaps = [r for r in matched
               if r["humain"] == "true_positive" and r["model"] == "false_positive"]

    if len(matched) < MINIMUM_USEFUL:
        conclusion = "echantillon_insuffisant"
    elif rate < 0.9:
        conclusion = "shadow"
    else:
        conclusion = "automatisable"

    return {
        "n_triages": n_triages,
        "coherence": coherence,
        "justesse": {
            "n_labellises": len(matched),
            "n_incidents": n_incidents,
            "n_corrects": len(fair),
            "taux_pct": 100 * rate,
            "minimum_utile": MINIMUM_USEFUL,
            "desaccords": [
                {"incident_id": r["incident_id"], "model": r["model"],
                 "humain": r["humain"]}
                for r in matched if r["model"] != r["humain"]
            ],
            "tp_classes_fp": len(gaps),
            "conclusion": conclusion,
        },
    }


CONCLUSIONS = {
    "sans_label": None,  # traité à part : il faut le décompte d'incidents
    "echantillon_insuffisant":
        "  ÉCHANTILLON INSUFFISANT ({n} < {mini}). Le pourcentage ci-dessus "
        "n'a pas de valeur statistique.\n  Rester en mode shadow.",
    "shadow": "  Justesse en dessous de 90 % : rester en mode shadow.",
    "automatisable":
        "  Justesse suffisante sur un échantillon utilisable.\n"
        "  L'automatisation peut être activée, par niveau d'autonomie "
        "configurable — une fois active, les actions partent seules (pas de "
        "validation humaine par action).",
}


def show(r: dict) -> None:
    if not r["n_triages"]:
        print("Aucun triage enregistré — lancer soc_agent.triage.")
        return

    c = r["coherence"]
    print("=" * 68)
    print("COHÉRENCE  (sans label — disponible immédiatement)")
    print("=" * 68)
    print(f"  Triages (dernier par incident) : {c['n_derniers_triages']}")
    print(f"  Sorties incohérentes           : {c['n_incoherents']} "
          f"({c['part_incoherents_pct']:.0f} %)")
    for i in c["incoherents"]:
        print(f"    #{i['incident_id']} : {'; '.join(i['patterns'])}")
    print()
    for m in c["modeles"]:
        print(f"  {m['model']} : {m['n']} triages, "
              f"{m['duree_moyenne_s']:.1f} s en moyenne, "
              f"{m['prompt_tokens_moyen']:.0f} tokens de prompt")

    j = r["justesse"]
    print()
    print("=" * 68)
    print("JUSTESSE  (face aux labels humains)")
    print("=" * 68)

    if j["conclusion"] == "sans_label":
        print(f"  Aucun incident labellisé (sur {j['n_incidents']}).")
        print()
        print("  Impossible de mesurer la justesse. Labelliser avec :")
        print("    python -m soc_agent.label --lister")
        print("    python -m soc_agent.label <id> --montrer")
        print("    python -m soc_agent.label <id> --verdict true_positive")
        return

    print(f"  Incidents labellisés : {j['n_labellises']} / {j['n_incidents']}")
    print(f"  Verdicts corrects    : {j['n_corrects']}/{j['n_labellises']} "
          f"({j['taux_pct']:.0f} %)")
    if j["desaccords"]:
        print("\n  Désaccords :")
        for d in j["desaccords"]:
            print(f"    #{d['incident_id']} : modèle {d['model']}, "
                  f"humain {d['humain']}")
    if j["tp_classes_fp"]:
        print(f"\n  /!\\ {j['tp_classes_fp']} vrai(s) positif(s) classé(s) faux "
              f"positif(s) — c'est l'erreur qui laisse passer une intrusion.")
    print()
    print(CONCLUSIONS[j["conclusion"]].format(
        n=j["n_labellises"], mini=j["minimum_utile"]))


def main() -> None:
    show(report())


if __name__ == "__main__":
    main()
