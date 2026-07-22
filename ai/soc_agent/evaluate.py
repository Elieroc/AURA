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
"""

import psycopg
from psycopg.rows import dict_row

from . import config

# En dessous, un taux de justesse n'a pas de sens statistique. Le seuil est
# arbitraire mais explicite : mieux vaut refuser de conclure que produire un
# « 100 % » calculé sur quatre incidents.
MINIMUM_UTILE = 30


def main() -> None:
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        n_triages = conn.execute(
            "SELECT count(*) n FROM triages").fetchone()["n"]
        if not n_triages:
            print("Aucun triage enregistré — lancer soc_agent.triage.")
            return

        print("=" * 68)
        print("COHÉRENCE  (sans label — disponible immédiatement)")
        print("=" * 68)

        # Dernier triage par incident : les passages précédents reflètent des
        # prompts abandonnés.
        derniers = """
            SELECT DISTINCT ON (incident_id) *
              FROM triages ORDER BY incident_id, created_at DESC
        """
        lignes = conn.execute(derniers).fetchall()
        incoherents = [r for r in lignes if r["incoherences"]]
        print(f"  Triages (dernier par incident) : {len(lignes)}")
        print(f"  Sorties incohérentes           : {len(incoherents)} "
              f"({100 * len(incoherents) / len(lignes):.0f} %)")
        for r in incoherents:
            print(f"    #{r['incident_id']} : {'; '.join(r['incoherences'])}")

        modeles = conn.execute(
            f"SELECT modele, count(*) n, avg(duree_ms)/1000 s, "
            f"avg(prompt_tokens) tok FROM ({derniers}) d GROUP BY modele"
        ).fetchall()
        print()
        for m in modeles:
            print(f"  {m['modele']} : {m['n']} triages, "
                  f"{m['s']:.1f} s en moyenne, {m['tok']:.0f} tokens de prompt")

        print()
        print("=" * 68)
        print("JUSTESSE  (face aux labels humains)")
        print("=" * 68)

        apparies = conn.execute(f"""
            SELECT d.incident_id, d.verdict AS modele, d.actions AS act_modele,
                   l.verdict AS humain, l.actions AS act_humain, l.origine
              FROM ({derniers}) d
              JOIN labels l ON l.incident_id = d.incident_id
        """).fetchall()

        n_incidents = conn.execute(
            "SELECT count(*) n FROM incidents").fetchone()["n"]

        if not apparies:
            print(f"  Aucun incident labellisé (sur {n_incidents}).")
            print()
            print("  Impossible de mesurer la justesse. Labelliser avec :")
            print("    python -m soc_agent.label --lister")
            print("    python -m soc_agent.label <id> --montrer")
            print("    python -m soc_agent.label <id> --verdict true_positive")
            return

        justes = [r for r in apparies if r["modele"] == r["humain"]]
        print(f"  Incidents labellisés : {len(apparies)} / {n_incidents}")
        print(f"  Verdicts corrects    : {len(justes)}/{len(apparies)} "
              f"({100 * len(justes) / len(apparies):.0f} %)")

        faux = [r for r in apparies if r["modele"] != r["humain"]]
        if faux:
            print("\n  Désaccords :")
            for r in faux:
                print(f"    #{r['incident_id']} : modèle {r['modele']}, "
                      f"humain {r['humain']}")

        # Un faux positif classé vrai positif fait perdre du temps ; l'inverse
        # laisse passer une intrusion. Les deux erreurs n'ont pas le même coût.
        manques = [r for r in apparies
                   if r["humain"] == "true_positive"
                   and r["modele"] == "false_positive"]
        if manques:
            print(f"\n  /!\\ {len(manques)} vrai(s) positif(s) classé(s) faux "
                  f"positif(s) — c'est l'erreur qui laisse passer une intrusion.")

        print()
        if len(apparies) < MINIMUM_UTILE:
            print(f"  ÉCHANTILLON INSUFFISANT ({len(apparies)} < {MINIMUM_UTILE}). "
                  f"Le pourcentage ci-dessus n'a pas de valeur statistique.")
            print("  Rester en mode shadow.")
        elif len(justes) / len(apparies) < 0.9:
            print("  Justesse en dessous de 90 % : rester en mode shadow.")
        else:
            print("  Justesse suffisante sur un échantillon utilisable.")
            print("  Une sortie du mode shadow reste une décision humaine, "
                  "et par niveau d'autonomie.")


if __name__ == "__main__":
    main()
