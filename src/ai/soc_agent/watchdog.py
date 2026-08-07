"""Détection de capteur muet, côté pipeline.

Une règle de corrélation ne détecte jamais une ABSENCE : elle ne raisonne que
sur des événements présents (cf. rules/README, heartbeat auditd 100800-806). Le
heartbeat couvre l'audit noyau, mais deux coupures réelles lui échappent :

- 2026-07-29 : le flux Suricata s'est tu pendant ~26 h (logcollector noyé par un
  flood stream-events). Aucune alerte : le capteur ne produisait plus rien.
- 2026-07-29 : le lecteur journald d'un agent Wazuh 4.9.2 (bookstack) était figé
  — 0 event sshd/pam remonté, donc brute-force SSH invisible. Un restart d'agent
  l'a relancé.

Ces deux cas ont la même forme : un capteur qui PARLAIT s'est tu. On le détecte
au niveau de la base d'alertes (donc côté indexer, PAS soumis au backlog du
logcollector de l'agent) : un groupe de règles établi sur la fenêtre de
référence, mais sans le moindre événement depuis SILENCE_MINUTES.

Le seuil de silence est réglable PAR CAPTEUR (WATCHDOG_SILENCE_PAR_CAPTEUR) :
tous n'émettent pas en continu. syscheck n'alerte que sur un changement et son
scan planifié tourne toutes les 12 h — au seuil commun de 90 min, il était
déclaré muet tous les jours sur tous les agents.

    python -m soc_agent.watchdog        # liste les capteurs muets

Volontairement en LECTURE SEULE + log : escalader en case IRIS autonome est une
décision d'architecture à part (cf. politique d'autonomie), pas un effet de bord
de ce module. `cycle.py` l'appelle et journalise ; le branchement IRIS viendra
avec sa propre revue.
"""

import json
import logging

import psycopg
from psycopg.rows import dict_row

from . import config

log = logging.getLogger("watchdog")

# Un capteur muet = un groupe de règles vu >= BASELINE_MIN fois sur la fenêtre de
# référence, mais dont la dernière alerte remonte à plus de SILENCE_MINUTES.
_SQL = """
WITH grp AS (
    SELECT agent_id, agent_name, unnest(rule_groups) AS g, ts
      FROM alerts
     WHERE ts >= now() - (%(ref)s || ' hours')::interval
)
SELECT agent_id, agent_name, g AS capteur,
       count(*) AS volume, max(ts) AS dernier
  FROM grp
 WHERE g = ANY(%(capteurs)s)
 GROUP BY agent_id, agent_name, g
HAVING count(*) >= %(baseline)s
   AND max(ts) < now() - (COALESCE(%(par_capteur)s::jsonb ->> g,
                                   %(silence)s::text) || ' minutes')::interval
 ORDER BY dernier
"""


def capteurs_muets(conn) -> list[dict]:
    """Capteurs établis devenus silencieux. Fonction pure (une requête), donc
    testable seule et sans effet de bord."""
    return conn.execute(_SQL, {
        "ref": config.WATCHDOG_REF_HEURES,
        "capteurs": list(config.WATCHDOG_CAPTEURS),
        "baseline": config.WATCHDOG_BASELINE_MIN,
        "silence": config.WATCHDOG_SILENCE_MINUTES,
        # Seuil propre à certains capteurs (syscheck n'émet que sur changement,
        # scan planifié toutes les 12 h) ; le défaut s'applique aux autres.
        "par_capteur": json.dumps(config.WATCHDOG_SILENCE_PAR_CAPTEUR),
    }).fetchall()


def verifier() -> list[dict]:
    """Appelée par le cycle. Ouvre sa propre connexion (lecture seule, dict_row —
    la connexion de verrou du cycle est en tuples), journalise chaque capteur
    muet en WARNING (visible dans `docker compose logs soc-agent-cycle`) et
    renvoie les constats."""
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        muets = capteurs_muets(conn)
    for m in muets:
        log.warning(
            "CAPTEUR MUET : '%s' sur %s (agent %s) — %d events de référence, "
            "rien depuis %s. Angle mort : les règles adossées à ce capteur sont "
            "inertes.", m["capteur"], m["agent_name"] or "?", m["agent_id"],
            m["volume"], m["dernier"])
    return muets


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    muets = verifier()
    if not muets:
        print("Aucun capteur muet.")
        return
    print(f"{len(muets)} capteur(s) muet(s) :")
    for m in muets:
        print(f"  {m['agent_name'] or '?':<20} {m['capteur']:<14} "
              f"muet depuis {m['dernier']:%Y-%m-%d %H:%M} "
              f"({m['volume']} events de référence)")


if __name__ == "__main__":
    main()
