"""Regroupement des alertes en incidents.

Le cœur de la phase 1 : 25 alertes « canari altéré » sur le même hôte à la même
seconde sont un incident ransomware, pas 25 incidents. C'est ce qui rend le
triage LLM abordable — on paye ~20 s par incident, pas par alerte.

Méthode : chaînage par proximité, agent par agent, en ordre chronologique. Deux
alertes voisines dans le temps ET ayant un point commun rejoignent le même
incident. Aucun modèle, aucun seuil appris — des règles qu'on peut expliquer à
un analyste et qu'il peut contester.

    python -m soc_agent.correlate
"""

import argparse
from datetime import timedelta

import psycopg
from psycopg.rows import dict_row

from . import config

# Groupes présents sur la moitié des règles Wazuh : les retenir comme point
# commun fusionnerait des alertes sans aucun rapport entre elles.
GROUPES_GENERIQUES = {
    "syscheck", "ossec", "linux", "windows", "syslog", "authentication_failed",
    "pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc", "gpg13",
}


def point_commun(a: dict, b: dict) -> tuple[str, bool] | None:
    """Ce qui rattache deux alertes du même agent : (libellé, lien_fort).

    La proximité temporelle seule ne suffit pas : sur un hôte actif, deux
    événements sans rapport tombent constamment dans la même fenêtre. Il faut
    un lien explicite, et pouvoir le nommer dans le rapport.

    Un lien est dit FORT quand il désigne le même objet concret — la même IP
    source, le même fichier, le même compte. Ces liens-là supportent une
    fenêtre bien plus large : une IP hostile qui revient trois fois dans la
    journée est une seule campagne, pas trois incidents. Les liens faibles
    (tactique MITRE, groupe de règle) sont des indices de parenté, pas des
    identités : leur accorder la même largeur fusionnerait tout et n'importe
    quoi.
    """
    if a["srcip"] and a["srcip"] == b["srcip"]:
        return "même IP source", True
    if a["entity"] and a["entity"] == b["entity"]:
        return "même objet", True
    if a["srcuser"] and a["srcuser"] == b["srcuser"]:
        return "même compte", True
    if a["mitre_tactics"] and set(a["mitre_tactics"]) & set(b["mitre_tactics"]):
        return "tactique MITRE", False
    communs = (set(a["rule_groups"]) & set(b["rule_groups"])) - GROUPES_GENERIQUES
    if communs:
        return f"groupe {sorted(communs)[0]}", False
    return None


SELECT_NON_RATTACHEES = """
SELECT id, ts, agent_id, agent_name, rule_id, rule_level, rule_groups,
       mitre_tactics, srcip, srcuser, entity
  FROM alerts
 WHERE incident_id IS NULL AND rule_level >= %s AND NOT suppressed
 ORDER BY agent_id, ts, id
"""

INSERT_INCIDENT = """
INSERT INTO incidents (agent_id, agent_name, first_seen, last_seen,
                       alert_count, max_level, rule_ids, mitre_tactics, entities)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
RETURNING id
"""


def _grouper(alertes: list[dict]) -> list[list[dict]]:
    """Chaîne les alertes en incidents. Fonction pure, donc testable seule."""
    ecart_faible = timedelta(minutes=config.CORRELATION_GAP_MINUTES)
    ecart_fort = timedelta(minutes=config.ENTITY_GAP_MINUTES)
    duree_max = timedelta(hours=config.MAX_INCIDENT_HOURS)

    incidents: list[list[dict]] = []

    # PLUSIEURS incidents ouverts simultanément par agent, et non un seul.
    # Avec un seul, une alerte sans rapport qui s'intercale referme l'incident
    # en cours : deux alertes de la même IP hostile séparées par un événement
    # étranger repartaient dans deux incidents distincts. Sur un hôte actif,
    # l'entrelacement est le cas normal, pas l'exception.
    #
    # Les agents restent cloisonnés : une alerte sur debian-vm n'a pas à
    # rejoindre un incident du manager.
    ouverts: dict[str, list[list[dict]]] = {}
    fenetre_max = max(ecart_fort, ecart_faible)

    for a in alertes:
        groupes = ouverts.setdefault(a["agent_id"], [])

        # Fermeture des incidents hors d'atteinte. Les alertes étant triées par
        # date, ils ne pourront plus rien accueillir.
        groupes[:] = [
            g for g in groupes
            if a["ts"] - g[-1]["ts"] <= fenetre_max
            and a["ts"] - g[0]["ts"] <= duree_max
        ]

        cible = None
        for g in groupes:
            depuis_derniere = a["ts"] - g[-1]["ts"]
            # On ne compare qu'aux 20 dernières : au-delà le coût devient
            # quadratique sans rien changer, le chaînage étant de proche en
            # proche.
            for membre in g[-20:]:
                lien = point_commun(a, membre)
                if lien is None:
                    continue
                _, fort = lien
                if depuis_derniere <= (ecart_fort if fort else ecart_faible):
                    cible = g
                    break
            if cible is not None:
                break

        if cible is None:
            cible = []
            groupes.append(cible)
            incidents.append(cible)
        cible.append(a)

    return incidents


def correler(min_level: int) -> tuple[int, int]:
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        alertes = conn.execute(SELECT_NON_RATTACHEES, (min_level,)).fetchall()
        if not alertes:
            return 0, 0

        incidents = _grouper(alertes)

        # Une seule transaction : en cas d'échec, les alertes restent
        # simplement non rattachées et un nouveau passage reprend le travail.
        for groupe in incidents:
            tactiques = sorted({t for a in groupe for t in a["mitre_tactics"]})
            entites = sorted({a["entity"] for a in groupe if a["entity"]})
            inc_id = conn.execute(INSERT_INCIDENT, (
                groupe[0]["agent_id"],
                groupe[0]["agent_name"],
                groupe[0]["ts"],
                groupe[-1]["ts"],
                len(groupe),
                max(a["rule_level"] for a in groupe),
                sorted({a["rule_id"] for a in groupe}),
                tactiques,
                entites[:50],   # bornage : un ransomware touche des milliers de fichiers
            )).fetchone()["id"]

            conn.execute(
                "UPDATE alerts SET incident_id = %s WHERE id = ANY(%s)",
                (inc_id, [a["id"] for a in groupe]),
            )
        conn.commit()

    return len(incidents), len(alertes)


def recommencer() -> None:
    """Détache toutes les alertes et supprime les incidents.

    Sert à rejouer la corrélation après un changement de paramètres. Passe par
    un DELETE et pas un TRUNCATE : `TRUNCATE incidents CASCADE` viderait aussi
    `alerts`, à cause de la clé étrangère — ce qui oblige à tout réingérer.
    """
    with psycopg.connect(config.PG_DSN) as conn:
        conn.execute("UPDATE alerts SET incident_id = NULL")
        conn.execute("DELETE FROM incidents")
        conn.commit()
    print("Incidents supprimés, alertes détachées.")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--min-level", type=int, default=config.MIN_LEVEL,
                    help="niveau Wazuh minimal à corréler")
    ap.add_argument("--recommencer", action="store_true",
                    help="repart de zéro (conserve les alertes)")
    args = ap.parse_args()

    if args.recommencer:
        recommencer()

    n_inc, n_alertes = correler(args.min_level)
    if n_alertes:
        print(f"{n_alertes} alertes -> {n_inc} incidents "
              f"(facteur {n_alertes / n_inc:.1f})")
    else:
        print("Aucune alerte à corréler.")


if __name__ == "__main__":
    main()
