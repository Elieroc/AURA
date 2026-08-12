"""Détection de capteur muet, côté pipeline, et ouverture du dossier associé.

Une règle de corrélation ne détecte jamais une ABSENCE : elle ne raisonne que
sur des événements présents (cf. rules/README, heartbeat auditd 100800-806). Le
heartbeat couvre l'audit noyau, mais trois coupures réelles lui ont échappé :

- 2026-07-29 : le flux Suricata s'est tu pendant ~26 h (logcollector noyé par un
  flood stream-events). Aucune alerte : le capteur ne produisait plus rien.
- 2026-07-29 : le lecteur journald d'un agent Wazuh 4.9.2 (bookstack) était figé
  — 0 event sshd/pam remonté, donc brute-force SSH invisible. Un restart d'agent
  l'a relancé.
- 2026-08-11 : le logcollector de la pfSense était bloqué depuis le 2 août
  (quatre processus empilés, un seul thread sur un mutex). Cinq interfaces
  Suricata et tous les syslogs de la passerelle muets pendant neuf jours,
  agent `active` et tableau de bord vert.

Ces cas ont la même forme : un capteur qui PARLAIT s'est tu. On le détecte au
niveau de la base d'alertes (donc côté indexer, PAS soumis au backlog du
logcollector de l'agent) : un groupe de règles établi sur la fenêtre de
référence, mais sans le moindre événement depuis le seuil de silence.

Le seuil est réglable PAR CAPTEUR (WATCHDOG_SILENCE_PAR_CAPTEUR) et c'est
essentiel : un capteur CONTINU (audit, suricata) se juge en minutes, un capteur
ÉVÉNEMENTIEL (sshd, syscheck) n'émet que quand il se passe quelque chose et son
silence est l'état normal. Les valeurs sont calées sur la distribution réelle
des écarts entre événements, mesurée en base (cf. config).

    python -m soc_agent.watchdog            # liste les capteurs muets
    python -m soc_agent.watchdog --surveiller   # + ouvre/ferme les cases IRIS

La panne est un ÉTAT, suivi dans `capteur_pannes` : ouverture unique par
(agent, capteur) garantie par un index unique partiel, case IRIS créé une seule
fois, fermé automatiquement quand le capteur reparle.
"""

import argparse
import json
import logging
from datetime import datetime, timezone

import psycopg
from psycopg.rows import dict_row

from . import config

log = logging.getLogger("watchdog")

# availability:outage — une panne de capteur est une perte de disponibilité de
# la détection, pas une intrusion.
CLASSIF_PANNE = 25

# Ce que la panne de chaque capteur rend inerte. Sert au dossier : un analyste
# qui lit « suricata muet » doit savoir CE QU'IL NE VOIT PLUS, sans aller
# fouiller le ruleset.
_PORTEE = {
    "audit": "toute la détection d'exécution Linux (règles 1006xx/1007xx : "
             "reverse shell, rootkit, découverte système, accès /etc/shadow, "
             "exécution depuis un répertoire temporaire)",
    "suricata": "toute la détection réseau (règles 866xx et 10094x : malware, "
                "C2, exploit, scan, SNI de C2 serverless)",
    "sshd": "la détection d'authentification (règles 57xx : brute-force, "
            "connexion réussie après énumération, login root)",
    "syscheck": "la surveillance d'intégrité des fichiers (règles 55x : "
                "canaris ransomware, modification de binaire, persistance)",
}

# Un capteur muet = un groupe de règles vu >= BASELINE_MIN fois sur la fenêtre de
# référence, mais dont la dernière alerte remonte à plus de son seuil de silence.
#
# Le silence se mesure contre l'HORIZON D'INGESTION, jamais contre l'horloge.
# Cette base n'est pas alimentée en continu : le cycle ingère toutes les 5 min,
# donc entre deux passages TOUT capteur paraît muet, et d'autant plus longtemps
# que le cycle vient d'être redémarré. Mesuré le 2026-08-11 en mettant ce module
# en service : quatre minutes après un redémarrage des conteneurs, `audit` sur
# home-s-pve01 et `suricata` sur la pfSense étaient déclarés en panne pour
# « 15 min de silence » alors que les deux émettaient normalement — la base
# n'avait simplement pas encore été rafraîchie. Comparé à l'horizon, un retard
# d'ingestion décale tous les capteurs du même montant et ne peut plus fabriquer
# de panne.
#
# Le corollaire est que le watchdog devient aveugle si l'ingestion elle-même
# s'arrête : c'est un autre mode de panne, couvert par `horizon_ingestion()`.
_SQL = """
WITH horizon AS (
    SELECT COALESCE((SELECT last_ts FROM ingest_cursor LIMIT 1),
                    (SELECT max(ts) FROM alerts)) AS h
), grp AS (
    SELECT agent_id, agent_name, unnest(rule_groups) AS g, ts
      FROM alerts
     WHERE ts >= (SELECT h FROM horizon) - (%(ref)s || ' hours')::interval
)
SELECT agent_id, agent_name, g AS capteur,
       count(*) AS volume, max(ts) AS dernier,
       (SELECT h FROM horizon) AS horizon,
       COALESCE((%(par_capteur)s::jsonb ->> g)::int, %(silence)s) AS seuil
  FROM grp
 WHERE g = ANY(%(capteurs)s)
 GROUP BY agent_id, agent_name, g
HAVING count(*) >= %(baseline)s
   AND max(ts) < (SELECT h FROM horizon)
                 - (COALESCE(%(par_capteur)s::jsonb ->> g,
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
        # Seuil propre à certains capteurs (sshd et syscheck n'émettent que sur
        # évènement) ; le défaut s'applique aux autres.
        "par_capteur": json.dumps(config.WATCHDOG_SILENCE_PAR_CAPTEUR),
    }).fetchall()


def _minutes(depuis, reference=None) -> int:
    """Minutes écoulées depuis `depuis`, mesurées contre l'horizon d'ingestion
    quand il est fourni — cf. le commentaire de `_SQL`. L'horloge n'est le bon
    repère que pour l'ingestion elle-même."""
    fin = reference or datetime.now(timezone.utc)
    return int((fin - depuis).total_seconds() // 60)


def horizon_ingestion(conn):
    """Jusqu'où la base est à jour, et depuis combien de temps elle ne l'est plus.

    Le watchdog raisonne sur ce que le pipeline a ingéré ; si l'ingestion cale,
    il ne voit plus rien passer et se tairait — panne silencieuse de l'outil qui
    surveille les pannes. On mesure donc aussi ce retard-là, contre l'horloge.
    """
    r = conn.execute(
        "SELECT COALESCE((SELECT last_ts FROM ingest_cursor LIMIT 1),"
        "                (SELECT max(ts) FROM alerts)) AS h").fetchone()
    h = r["h"] if r else None
    return h, (_minutes(h) if h else None)


def _duree(minutes: int) -> str:
    if minutes < 90:
        return f"{minutes} min"
    if minutes < 60 * 48:
        return f"{minutes // 60} h {minutes % 60:02d}"
    return f"{minutes // 1440} j {(minutes % 1440) // 60} h"


def _note_panne(m: dict, minutes: int) -> str:
    portee = _PORTEE.get(m["capteur"], "les règles adossées à ce capteur")
    return "\n".join([
        "# Panne de capteur",
        "",
        f"Le capteur **{m['capteur']}** de **{m['agent_name'] or m['agent_id']}** "
        f"(agent {m['agent_id']}) n'émet plus depuis **{_duree(minutes)}**.",
        "",
        "| | |",
        "|---|---|",
        f"| Capteur | `{m['capteur']}` |",
        f"| Agent | {m['agent_name'] or '?'} (`{m['agent_id']}`) |",
        f"| Dernier événement | {m['dernier']:%Y-%m-%d %H:%M:%S} UTC |",
        f"| Silence | {_duree(minutes)} |",
        f"| Seuil de panne | {m['seuil']} min |",
        f"| Volume de référence | {m['volume']} événements sur "
        f"{config.WATCHDOG_REF_HEURES} h |",
        "",
        "## Ce qui n'est plus détecté",
        "",
        f"Tant que ce capteur est muet, {portee} ne peut plus se déclencher sur "
        "cet hôte. Aucune alerte ne le signalera : une règle de corrélation ne "
        "détecte pas une absence.",
        "",
        "## Pistes",
        "",
        "1. L'agent est-il réellement connecté, et **émet-il** ? Un agent "
        "`active` dont le collecteur est figé est indiscernable d'un agent sain.",
        "2. `wazuh-control status` sur l'hôte, puis vérifier qu'il n'y a pas "
        "**plusieurs** processus `wazuh-logcollector` empilés : un redémarrage "
        "ne tue pas un collecteur bloqué, il en ajoute un.",
        "3. Le capteur sous-jacent tourne-t-il ? (`auditctl -s` pour audit, "
        "l'instance Suricata pour le réseau, le lecteur journald pour sshd)",
        "4. L'hôte est-il **isolé** ? Une machine confinée n'accepte plus que le "
        "manager : ses capteurs d'authentification se taisent par construction, "
        "sans panne réelle.",
        "",
        "*Dossier ouvert automatiquement par le watchdog AURA. Il se ferme seul "
        "dès que le capteur réémet.*",
    ])


def _ouvrir_case(m: dict, minutes: int) -> int | None:
    """Case IRIS pour une panne. Best-effort : un IRIS injoignable ne doit pas
    empêcher d'enregistrer la panne en base ni de la journaliser."""
    from .iris import _client, _poser_note, _taguer
    nom = (f"[CAPTEUR MUET] {m['capteur']} sur "
           f"{m['agent_name'] or m['agent_id']}")
    desc = (f"Le capteur {m['capteur']} de l'agent {m['agent_id']} "
            f"({m['agent_name'] or '?'}) n'émet plus depuis {_duree(minutes)} "
            f"(dernier événement {m['dernier']:%Y-%m-%d %H:%M} UTC, seuil "
            f"{m['seuil']} min). La détection adossée à ce capteur est inerte.")
    case = _client()
    r = case.add_case(
        case_name=nom,
        case_description=desc,
        case_customer=config.IRIS_CUSTOMER,
        case_classification=CLASSIF_PANNE,
        soc_id=f"Aura-SOC-capteur-{m['agent_id']}-{m['capteur']}",
    )
    if not r.is_success():
        log.error("case panne %s/%s : %s", m["agent_id"], m["capteur"],
                  r.get_msg())
        return None
    case_id = r.get_data()["case_id"]
    _taguer(case, case_id, m["agent_name"])
    _poser_note(case, case_id, "Détail de la panne", _note_panne(m, minutes))
    return case_id


def _fermer_case(case_id: int, p: dict, minutes: int) -> None:
    """Note de rétablissement puis clôture. Best-effort, comme l'ouverture."""
    from .iris import _client, _poser_note
    case = _client()
    _poser_note(case, case_id, "Rétablissement", "\n".join([
        "# Capteur rétabli",
        "",
        f"Le capteur **{p['capteur']}** de **{p['agent_name'] or p['agent_id']}** "
        "réémet.",
        "",
        f"- Panne détectée le {p['detectee_a']:%Y-%m-%d %H:%M} UTC",
        f"- Dernier événement avant la panne : {p['dernier_event']:%Y-%m-%d %H:%M} UTC",
        f"- Durée totale du silence : {_duree(minutes)}",
        "",
        "**Les événements de la période de silence sont définitivement perdus** "
        "si le capteur ne tamponnait pas : ce qui s'est produit sur cet hôte "
        "pendant la panne n'a jamais été analysé.",
        "",
        "*Clôturé automatiquement par le watchdog AURA.*",
    ]))
    case.close_case(case_id)


def surveiller() -> dict:
    """Un passage complet : détecter, ouvrir, fermer. Renvoie le compte rendu.

    Idempotent par construction — l'index unique partiel de `capteur_pannes`
    interdit deux pannes ouvertes pour le même (agent, capteur), donc deux
    passages concurrents ne peuvent pas ouvrir deux cases.
    """
    ouvertes, fermees = [], []
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        horizon, retard = horizon_ingestion(conn)
        # Ingestion à l'arrêt : tous les capteurs vont paraître muets au même
        # instant. Ce n'est pas une panne de capteur, c'est une panne du
        # pipeline — on le dit et on ne fabrique pas six dossiers pour un seul
        # problème.
        if retard is not None and retard > config.WATCHDOG_RETARD_INGEST_MAX:
            log.error("INGESTION EN RETARD de %s (horizon %s) — surveillance "
                      "des capteurs suspendue : tout paraîtrait muet.",
                      _duree(retard), horizon)
            return {"muets": [], "ouvertes": [], "fermees": [],
                    "retard_ingest": retard}

        muets = capteurs_muets(conn)
        vus = {(m["agent_id"], m["capteur"]) for m in muets}

        for m in muets:
            minutes = _minutes(m["dernier"], m["horizon"])
            log.warning(
                "CAPTEUR MUET : '%s' sur %s (agent %s) — %d events de "
                "référence, rien depuis %s (%s). Angle mort : les règles "
                "adossées à ce capteur sont inertes.",
                m["capteur"], m["agent_name"] or "?", m["agent_id"],
                m["volume"], m["dernier"], _duree(minutes))
            r = conn.execute(
                """INSERT INTO capteur_pannes
                       (agent_id, agent_name, capteur, dernier_event,
                        volume_ref, seuil_minutes)
                   VALUES (%s, %s, %s, %s, %s, %s)
                   ON CONFLICT (agent_id, capteur) WHERE statut = 'ouverte'
                   DO NOTHING
                   RETURNING id""",
                (m["agent_id"], m["agent_name"], m["capteur"], m["dernier"],
                 m["volume"], m["seuil"])).fetchone()
            conn.commit()
            if not r:
                continue  # panne déjà ouverte : rien à refaire
            case_id = None
            if config.WATCHDOG_CASE_IRIS:
                try:
                    case_id = _ouvrir_case(m, minutes)
                except Exception as e:  # noqa: BLE001 — IRIS ne bloque pas
                    log.warning("case panne non créé (%s/%s) : %s",
                                m["agent_id"], m["capteur"], e)
            if case_id:
                conn.execute(
                    "UPDATE capteur_pannes SET iris_case_id=%s WHERE id=%s",
                    (case_id, r["id"]))
                conn.commit()
            log.error("PANNE OUVERTE : %s sur %s — case IRIS %s",
                      m["capteur"], m["agent_name"] or m["agent_id"],
                      case_id or "non créé")
            ouvertes.append({**m, "iris_case_id": case_id})

        for p in conn.execute(
                "SELECT * FROM capteur_pannes WHERE statut='ouverte'").fetchall():
            if (p["agent_id"], p["capteur"]) in vus:
                continue
            minutes = _minutes(p["dernier_event"], horizon)
            if p["iris_case_id"] and config.WATCHDOG_CASE_IRIS:
                try:
                    _fermer_case(p["iris_case_id"], p, minutes)
                except Exception as e:  # noqa: BLE001
                    # On laisse la panne OUVERTE en base pour retenter au tour
                    # suivant. La marquer rétablie ici alors que le dossier
                    # reste ouvert dans IRIS laisserait un case fantôme que
                    # plus rien ne referme — arrivé le 2026-08-12, IRIS
                    # OOM-killé pile au moment où debian2 réémettait.
                    log.warning("clôture case %s impossible (%s) — panne "
                                "laissée ouverte, nouvelle tentative au "
                                "prochain passage", p["iris_case_id"], e)
                    continue
            conn.execute(
                "UPDATE capteur_pannes SET statut='retablie', retablie_a=now() "
                "WHERE id=%s", (p["id"],))
            conn.commit()
            log.info("CAPTEUR RÉTABLI : %s sur %s (silence %s)",
                     p["capteur"], p["agent_name"] or p["agent_id"],
                     _duree(minutes))
            fermees.append(p)

    return {"muets": muets, "ouvertes": ouvertes, "fermees": fermees}


def verifier() -> list[dict]:
    """Appelée par le cycle. Lecture seule + log : la gestion d'état et les
    cases IRIS appartiennent au service dédié (`--surveiller`), qui tourne à sa
    propre cadence — un capteur muet doit être vu en minutes, pas au rythme du
    cycle de triage."""
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
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--surveiller", action="store_true",
                   help="ouvrir/fermer les pannes et leurs cases IRIS")
    args = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.surveiller:
        r = surveiller()
        print(f"{len(r['muets'])} capteur(s) muet(s), "
              f"{len(r['ouvertes'])} panne(s) ouverte(s), "
              f"{len(r['fermees'])} rétablie(s)")
        return

    muets = verifier()
    if not muets:
        print("Aucun capteur muet.")
        return
    print(f"{len(muets)} capteur(s) muet(s) :")
    for m in muets:
        print(f"  {m['agent_name'] or '?':<20} {m['capteur']:<14} "
              f"muet depuis {m['dernier']:%Y-%m-%d %H:%M} "
              f"({m['volume']} events de référence, seuil {m['seuil']} min)")


if __name__ == "__main__":
    main()
