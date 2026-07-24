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


def _enrichir(incidents: list[list[dict]], candidats: list[dict]) -> int:
    """Rattache les alertes de sévérité intermédiaire aux incidents formés.

    Une graine HIGH a déjà confirmé l'incident ; on lui recolle les alertes
    du même agent (ATTACH_MIN_LEVEL <= niveau < MIN_LEVEL) qui appartiennent
    manifestement à la même intrusion — sinon le reverse shell est vu seul et
    la privesc/persistence, plus discrètes, restent invisibles au triage.

    Deux titres d'attachement, du plus fort au plus faible :
      - inclusion dans la fenêtre [first, last] de l'incident élargie de la
        marge de chaînage faible (± CORRELATION_GAP_MINUTES). Ce lien purement
        temporel serait trop laxiste pour FORMER un incident (d'où son
        interdiction comme graine), mais il est légitime pour ENRICHIR un
        incident déjà avéré : sur un hôte au repos, une alerte de niveau >= 6
        pile pendant (ou juste après) une intrusion confirmée en fait partie,
        même si elle ne partage aucun objet nommable avec le pic (la privesc
        et la persistence touchent d'autres binaires que le reverse shell) ;
      - à défaut, un point commun nommable avec un membre (même IP/objet/
        compte/tactique), qui étend la portée à la fenêtre forte : une même IP
        hostile qui revient des heures plus tard reste le même incident.

    Une alerte candidate qui ne trouve pas preneur reste non rattachée.
    """
    ecart_faible = timedelta(minutes=config.CORRELATION_GAP_MINUTES)
    ecart_fort = timedelta(minutes=config.ENTITY_GAP_MINUTES)
    rattaches = 0

    for c in candidats:
        meilleur = None
        meilleur_dist = None
        for inc in incidents:
            if inc[0]["agent_id"] != c["agent_id"]:
                continue
            debut = min(m["ts"] for m in inc)
            fin = max(m["ts"] for m in inc)

            # Inclusion temporelle élargie de la marge faible.
            titre = (debut - ecart_faible) <= c["ts"] <= (fin + ecart_faible)
            if not titre:
                for membre in inc:
                    lien = point_commun(c, membre)
                    if lien is None:
                        continue
                    _, fort = lien
                    ecart = ecart_fort if fort else ecart_faible
                    if min(abs(c["ts"] - debut), abs(c["ts"] - fin)) <= ecart:
                        titre = True
                        break
            if not titre:
                continue

            # Départage : l'incident temporellement le plus proche.
            if debut <= c["ts"] <= fin:
                dist = timedelta(0)
            else:
                dist = min(abs(c["ts"] - debut), abs(c["ts"] - fin))
            if meilleur_dist is None or dist < meilleur_dist:
                meilleur, meilleur_dist = inc, dist

        if meilleur is not None:
            meilleur.append(c)
            rattaches += 1

    return rattaches


def correler(min_level: int, attach_min_level: int | None = None) -> tuple[int, int]:
    if attach_min_level is None:
        attach_min_level = config.ATTACH_MIN_LEVEL
    # On ne peut rattacher qu'en dessous du seuil de graine ; au-dessus,
    # l'alerte est déjà une graine à part entière.
    plancher = min(attach_min_level, min_level) if attach_min_level else min_level

    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        alertes = conn.execute(SELECT_NON_RATTACHEES, (plancher,)).fetchall()
        if not alertes:
            return 0, 0

        graines = [a for a in alertes if a["rule_level"] >= min_level]
        candidats = [a for a in alertes if a["rule_level"] < min_level]

        incidents = _grouper(graines)
        if candidats and incidents:
            _enrichir(incidents, candidats)

        # Une seule transaction : en cas d'échec, les alertes restent
        # simplement non rattachées et un nouveau passage reprend le travail.
        for groupe in incidents:
            tactiques = sorted({t for a in groupe for t in a["mitre_tactics"]})
            entites = sorted({a["entity"] for a in groupe if a["entity"]})
            # min/max explicites : l'enrichissement ajoute des membres en fin
            # de liste sans garantie d'ordre chronologique.
            inc_id = conn.execute(INSERT_INCIDENT, (
                groupe[0]["agent_id"],
                groupe[0]["agent_name"],
                min(a["ts"] for a in groupe),
                max(a["ts"] for a in groupe),
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

    correlees = sum(len(g) for g in incidents)
    return len(incidents), correlees


def recommencer() -> None:
    """Détache toutes les alertes et supprime les incidents.

    Sert à rejouer la corrélation après un changement de paramètres. Passe par
    un DELETE et pas un TRUNCATE : `TRUNCATE incidents CASCADE` viderait aussi
    `alerts`, à cause de la clé étrangère — ce qui oblige à tout réingérer.
    """
    with psycopg.connect(config.PG_DSN) as conn:
        # Un incident déjà versé dans IRIS y a laissé un case. Le supprimer ici
        # rompt le lien iris_case_id : le prochain passage IRIS recréerait un
        # case en double. On prévient plutôt que de nettoyer côté IRIS à
        # l'aveugle — la décision revient à l'analyste.
        orphelins = conn.execute(
            "SELECT count(*) FROM incidents WHERE iris_case_id IS NOT NULL"
        ).fetchone()[0]
        if orphelins:
            print(f"ATTENTION : {orphelins} incident(s) ont un case IRIS. Les "
                  "supprimer ici orpheline ces cases (doublons au prochain "
                  "cycle). Les retirer d'IRIS à la main si besoin.")
        conn.execute("UPDATE alerts SET incident_id = NULL")
        conn.execute("DELETE FROM incidents")
        conn.commit()
    print("Incidents supprimés, alertes détachées.")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--min-level", type=int, default=config.MIN_LEVEL,
                    help="niveau Wazuh minimal pour OUVRIR un incident (graine)")
    ap.add_argument("--attach-min-level", type=int, default=config.ATTACH_MIN_LEVEL,
                    help="niveau minimal des alertes rattachées à un incident "
                         "existant (0 pour désactiver l'enrichissement)")
    ap.add_argument("--recommencer", action="store_true",
                    help="repart de zéro (conserve les alertes)")
    args = ap.parse_args()

    if args.recommencer:
        recommencer()

    n_inc, n_alertes = correler(args.min_level, args.attach_min_level)
    if n_alertes:
        print(f"{n_alertes} alertes -> {n_inc} incidents "
              f"(facteur {n_alertes / n_inc:.1f})")
    else:
        print("Aucune alerte à corréler.")


if __name__ == "__main__":
    main()
