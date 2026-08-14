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
    python -m soc_agent.watchdog --surveiller   # + ouvre/ferme les traces IRIS

La panne est un ÉTAT, suivi dans `capteur_pannes` : ouverture unique par
(agent, capteur) garantie par un index unique partiel, trace IRIS créée une
seule fois, refermée automatiquement quand le capteur reparle.

Cette trace est une ALERTE IRIS, pas un case (cf. WATCHDOG_IRIS_CANAL). Un case
est un dossier d'investigation ; une panne de capteur n'a rien à investiguer,
elle a un état et un geste — l'onglet Alerts porte exactement ce cycle de vie,
et laisse à l'analyste le bouton « Escalate to case » quand il juge que ça
mérite un dossier. Le canal `case`, historique, reste disponible.
"""

import argparse
import json
import logging
import shutil
import socket
from datetime import datetime, timezone

import psycopg
from psycopg.rows import dict_row

from . import config

log = logging.getLogger("watchdog")

# availability:outage — une panne de capteur est une perte de disponibilité de
# la détection, pas une intrusion.
CLASSIF_OUTAGE = 25

# Ce que la panne de chaque capteur rend inerte. Sert au dossier : un analyste
# qui lit « suricata muet » doit savoir CE QU'IL NE VOIT PLUS, sans aller
# fouiller le ruleset.
_SCOPE = {
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
SELECT agent_id, agent_name, g AS sensor,
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


def silent_sensors(conn) -> list[dict]:
    """Capteurs établis devenus silencieux. Fonction pure (une requête), donc
    testable seule et sans effet de bord."""
    return conn.execute(_SQL, {
        "ref": config.WATCHDOG_REF_HOURS,
        "capteurs": list(config.WATCHDOG_SENSORS),
        "baseline": config.WATCHDOG_BASELINE_MIN,
        "silence": config.WATCHDOG_SILENCE_MINUTES,
        # Seuil propre à certains capteurs (sshd et syscheck n'émettent que sur
        # évènement) ; le défaut s'applique aux autres.
        "par_capteur": json.dumps(config.WATCHDOG_SILENCE_PER_SENSOR),
    }).fetchall()


def _minutes(since, reference=None) -> int:
    """Minutes écoulées depuis `depuis`, mesurées contre l'horizon d'ingestion
    quand il est fourni — cf. le commentaire de `_SQL`. L'horloge n'est le bon
    repère que pour l'ingestion elle-même."""
    end = reference or datetime.now(timezone.utc)
    return int((end - since).total_seconds() // 60)


def ingest_horizon(conn):
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


def _duration(minutes: int) -> str:
    if minutes < 90:
        return f"{minutes} min"
    if minutes < 60 * 48:
        return f"{minutes // 60} h {minutes % 60:02d}"
    return f"{minutes // 1440} j {(minutes % 1440) // 60} h"


# --------------------------------------------------------------------------
# Garde-fou disque
# --------------------------------------------------------------------------
#
# Le 2026-08-14, le disque de prod avait pris 6 Go dans la journée (journal
# d'audit MISP, pièces Evidence reposées en boucle) sans que rien ne le
# signale. Un SOC dont le disque se remplit ne tombe pas en panne bruyamment :
# l'indexer bascule en lecture seule, Postgres refuse d'écrire, et plus une
# alerte n'entre — c'est-à-dire exactement la même conséquence qu'un capteur
# muet, à l'échelle de tout le pipeline.
#
# D'où le traitement comme un capteur : même table d'état (`capteur_pannes`),
# même canal (alerte IRIS), même clôture automatique au retour sous le seuil.
# Un disque plein est un ÉTAT à acquitter, pas une investigation à mener — le
# raisonnement qui a fait choisir l'onglet Alerts pour les pannes de capteur
# vaut mot pour mot ici.
SENSOR_DISK = "disque"

# Préfixes des pseudo-capteurs posés par `routage.py`. Une source de log qui
# n'atterrit pas dans son index est un angle mort de la même nature qu'un
# capteur muet — les alertes existent, mais personne ne les regarde là où elles
# sont — et se suit donc dans la même table d'état, avec la même clôture
# automatique.
PREFIXES_ROUTING = ("routage:", "source-muette:")

# Pseudo-capteurs posés par `archive.py`. Une archive manquante est une perte de
# visibilité FUTURE : la donnée est là aujourd'hui, elle ne sera plus là quand on
# la cherchera. Même table d'état, même canal, même clôture automatique — et
# comme le disque et le routage, ça se mesure contre l'HORLOGE et non contre
# l'horizon d'ingestion.
PREFIX_ARCHIVING = "archivage:"


def _is_routing(sensor: str) -> bool:
    return sensor.startswith(PREFIXES_ROUTING)


def _is_archiving(sensor: str) -> bool:
    return sensor.startswith(PREFIX_ARCHIVING)


def _outside_pipeline(sensor: str) -> bool:
    """Ce capteur se mesure-t-il contre l'horloge plutôt que contre l'horizon
    d'ingestion ?

    Trois familles ne se déduisent pas des alertes ingérées : le disque, le
    routage (mesuré sur l'indexer) et l'archivage (mesuré sur S3 et en base).
    Les rapporter à un horizon en retard donnait des durées fausses, voire
    négatives (« saturé pendant -2 min ») dans les alertes de rétablissement.
    """
    return (sensor == SENSOR_DISK or _is_routing(sensor)
            or _is_archiving(sensor))

# L'hôte du SOC n'est pas un agent surveillé comme un autre : c'est le manager
# lui-même. Son id d'agent Wazuh est 000 par construction.
AGENT_SOC = "000"


def disk_saturated() -> list[dict]:
    """Le disque du SOC est-il au-delà du seuil ? Zéro ou une entrée.

    Rendue au format d'un capteur muet (mêmes clés) pour traverser sans cas
    particulier la boucle d'ouverture/clôture de `surveiller`.
    """
    try:
        u = shutil.disk_usage(config.DISK_MONITORED)
    except OSError as e:
        log.warning("disque %s illisible : %s", config.DISK_MONITORED, e)
        return []
    pct = round(100 * u.used / u.total)
    if pct < config.DISK_THRESHOLD_ALERT:
        log.debug("disque %s à %d%% (seuil %d%%)", config.DISK_MONITORED,
                  pct, config.DISK_THRESHOLD_ALERT)
        return []
    maintenant = datetime.now(timezone.utc)
    return [{
        "agent_id": AGENT_SOC,
        "agent_name": socket.gethostname(),
        "sensor": SENSOR_DISK,
        # `dernier` et `horizon` valent l'instant de la mesure : un disque plein
        # n'a pas de « dernier événement », il a un état constaté maintenant.
        "dernier": maintenant,
        "horizon": maintenant,
        "volume": pct,
        "seuil": config.DISK_THRESHOLD_ALERT,
        "libre_go": u.free / 1073741824,
        "total_go": u.total / 1073741824,
        "pct": pct,
    }]


def _disk_note(m: dict, markdown: bool = True) -> str:
    """Diagnostic du disque saturé. Même double rendu que `_note_panne` : les
    notes de case sont en markdown, les descriptions d'alerte en texte brut."""
    t = (lambda s: f"# {s}") if markdown else (lambda s: s.upper())
    g = (lambda s: f"**{s}**") if markdown else (lambda s: str(s))
    c = (lambda s: f"`{s}`") if markdown else (lambda s: str(s))
    critical = m["pct"] >= config.DISK_THRESHOLD_CRITICAL
    return "\n".join([
        t("Disque du SOC saturé"),
        "",
        f"Le système de fichiers {c(config.DISK_MONITORED)} de "
        f"{g(m['agent_name'])} est occupé à {g(str(m['pct']) + ' %')} "
        f"({m['libre_go']:.1f} Go libres sur {m['total_go']:.0f} Go).",
        "",
        f"  Seuil d'alerte   : {config.DISK_THRESHOLD_ALERT} %",
        f"  Seuil critique   : {config.DISK_THRESHOLD_CRITICAL} %",
        f"  Occupation       : {m['pct']} %"
        + ("  <-- CRITIQUE" if critical else ""),
        "",
        "Ce qui se produit si le disque se remplit : l'indexer bascule ses "
        "index en lecture seule, Postgres refuse d'écrire, et le pipeline "
        "cesse d'ingérer. Aucune alerte ne le signalera — c'est la mécanique "
        "d'alerte elle-même qui s'arrête. La détection est alors aveugle sur "
        "TOUT le parc, pas sur un hôte.",
        "",
        "Où regarder en premier (retour d'expérience du 2026-08-14, où trois "
        "boucles avaient pris 29 Go) :",
        "",
        f"1. {c('du -xhd1 / | sort -h')} puis "
        f"{c('docker system df')} — vue d'ensemble.",
        "2. Bases de données : journaux d'audit (MISP), pièces jointes (IRIS), "
        "tables d'alertes (soc-agent).",
        "3. Résidus de mise à jour du feed CVE de Wazuh "
        f"({c('queue/vd_updater/tmp')}).",
        f"4. Images docker orphelines : {c('docker image prune -f')}.",
        "",
        f"Le job de rétention ({c('soc-agent-retention')}) traite le "
        "vieillissement normal ; il ne rattrape pas une boucle d'écriture. Si "
        "le disque monte vite, chercher ce qui ÉCRIT, pas ce qui est vieux.",
        "",
        _italic("Alerte ouverte par le watchdog AURA. Elle se referme seule "
                  "dès que l'occupation repasse sous le seuil.", markdown),
    ])


def _rendered(m: dict, minutes: int, markdown: bool = True) -> str:
    """Le diagnostic d'une entrée, quelle que soit sa nature.

    Trois familles cohabitent maintenant dans la même table d'état : les
    capteurs muets, le disque saturé, et les anomalies de routage
    (`routage.py`). Les deux premières composent leur texte ici ; la troisième
    l'apporte déjà rédigé, parce que c'est le module qui connaît le pipeline
    d'ingest qui sait quoi en dire. D'où ce point de dispatch unique, plutôt
    qu'un `if` répété dans chaque appelant.
    """
    if m.get("note"):
        return m["note"]
    if m["sensor"] == SENSOR_DISK:
        return _disk_note(m, markdown)
    return _outage_note(m, minutes, markdown)


def _title(m: dict) -> str:
    if m.get("titre"):
        return m["titre"]
    name = m["agent_name"] or m["agent_id"]
    if m["sensor"] == SENSOR_DISK:
        return f"[DISQUE SATURÉ] {m['pct']} % sur {name}"
    return f"[CAPTEUR MUET] {m['sensor']} sur {name}"


def _outage_note(m: dict, minutes: int, markdown: bool = True) -> str:
    """Le diagnostic de la panne, dans le seul dialecte que la destination sait
    rendre.

    Les NOTES de case sont rendues en markdown par IRIS ; les DESCRIPTIONS
    D'ALERTE ne le sont pas — vérifié sur l'onglet Alerts le 2026-08-13, où
    `# titre`, `**gras**`, les backticks et les tableaux s'affichaient
    littéralement, tuyaux et dièses compris. Un tableau markdown y devient six
    lignes de ferraille au milieu du texte utile, exactement là où l'analyste
    cherche l'heure du dernier événement.

    D'où deux rendus du MÊME contenu, et pas deux contenus : ce qui doit être
    lu ne dépend pas de l'onglet où on le lit.
    """
    scope = _SCOPE.get(m["sensor"], "les règles adossées à ce capteur")
    agent = m["agent_name"] or m["agent_id"]

    def t(title: str, level: int = 1) -> str:      # titre
        return f"{'#' * level} {title}" if markdown else title.upper()

    def g(txt: str) -> str:                          # emphase
        return f"**{txt}**" if markdown else txt

    def c(txt: str) -> str:                          # littéral (code)
        return f"`{txt}`" if markdown else txt

    faits = [
        ("Capteur", c(m["sensor"])),
        ("Agent", f"{m['agent_name'] or '?'} ({c(m['agent_id'])})"),
        ("Dernier événement", f"{m['dernier']:%Y-%m-%d %H:%M:%S} UTC"),
        ("Silence", _duration(minutes)),
        ("Seuil de panne", f"{m['seuil']} min"),
        ("Volume de référence",
         f"{m['volume']} événements sur {config.WATCHDOG_REF_HOURS} h"),
    ]
    if markdown:
        array = ["| | |", "|---|---|"] + [f"| {k} | {v} |" for k, v in faits]
    else:
        # Alignement à la main : sans tableau, c'est la seule chose qui rend
        # ces six lignes lisibles en un coup d'œil.
        large = max(len(k) for k, _ in faits)
        array = [f"  {k.ljust(large)} : {v}" for k, v in faits]

    return "\n".join([
        t("Panne de capteur"),
        "",
        f"Le capteur {g(m['sensor'])} de {g(agent)} (agent {m['agent_id']}) "
        f"n'émet plus depuis {g(_duration(minutes))}.",
        "",
        *array,
        "",
        t("Ce qui n'est plus détecté", 2),
        "",
        f"Tant que ce capteur est muet, {scope} ne peut plus se déclencher sur "
        "cet hôte. Aucune alerte ne le signalera : une règle de corrélation ne "
        "détecte pas une absence.",
        "",
        t("Pistes", 2),
        "",
        f"1. L'agent est-il réellement connecté, et {g('émet-il')} ? Un agent "
        f"{c('active')} dont le collecteur est figé est indiscernable d'un "
        "agent sain.",
        f"2. {c('wazuh-control status')} sur l'hôte, puis vérifier qu'il n'y a "
        f"pas {g('plusieurs')} processus {c('wazuh-logcollector')} empilés : "
        "un redémarrage ne tue pas un collecteur bloqué, il en ajoute un.",
        f"3. Le capteur sous-jacent tourne-t-il ? ({c('auditctl -s')} pour "
        "audit, l'instance Suricata pour le réseau, le lecteur journald pour "
        "sshd)",
        f"4. L'hôte est-il {g('isolé')} ? Une machine confinée n'accepte plus "
        "que le manager : ses capteurs d'authentification se taisent par "
        "construction, sans panne réelle.",
        "",
        _italic("Ouvert automatiquement par le watchdog AURA. Se referme "
                  "seul dès que le capteur réémet.", markdown),
    ])


def _italic(txt: str, markdown: bool) -> str:
    return f"*{txt}*" if markdown else f"-- {txt}"


# --------------------------------------------------------------------------
# Canal ALERTE (défaut) — cf. config.WATCHDOG_IRIS_CANAL
# --------------------------------------------------------------------------
#
# `alert_source` : c'est par là qu'on filtre l'onglet Alerts pour ne voir que
# la santé des capteurs. Valeur stable, jamais dérivée du capteur.
SOURCE_ALERT = "AURA watchdog"

# Statuts d'alerte IRIS. MÊME PIÈGE que la sévérité des cases (cf. iris.py) :
# les ids ne suivent aucun ordre logique — relevé sur l'IRIS de prod le
# 2026-08-13, New=2 mais Unspecified=1, Closed=6, Merged=7, Escalated=8. Toute
# valeur écrite en dur ici serait juste par hasard, donc on résout par NOM et
# ce dictionnaire n'est qu'un repli journalisé.
_STATUSES_FALLBACK = {"unspecified": 1, "new": 2, "assigned": 3, "in progress": 4,
                  "pending": 5, "closed": 6, "merged": 7, "escalated": 8}
_STATUSES_ID: dict[str, int] | None = None

# Statuts qui signifient qu'un HUMAIN a pris la main : il a jugé que la panne
# méritait un dossier et l'a escaladée. Le watchdog ne repasse pas derrière lui
# pour forcer « Closed » au rétablissement — il se contente d'écrire que le
# capteur réémet. C'est la différence de fond avec le canal `case`, où la
# clôture automatique écrasait le geste de l'analyste.
STATUSES_HUMAN = {"escalated", "merged"}

# Types d'asset IRIS (`/manage/asset-type/list`, relevé le 2026-08-13). L'asset
# sert à deux choses : regrouper les alertes d'une même machine, et suivre
# celle-ci dans le case si l'analyste escalade.
ASSET_LINUX_SERVER, ASSET_FIREWALL = 3, 2
ASSET_WIN_POSTE, ASSET_WIN_SERVER = 9, 10


def _type_asset(os_txt: str | None) -> int:
    """Type IRIS déduit de l'OS connu par la CMDB. Best-effort assumé : se
    tromper de pictogramme ne coûte rien, ne pas créer l'asset ferait perdre le
    regroupement par machine."""
    o = (os_txt or "").lower()
    if "pfsense" in o or "freebsd" in o or "opnsense" in o:
        return ASSET_FIREWALL
    if "windows" in o:
        return ASSET_WIN_SERVER if "server" in o else ASSET_WIN_POSTE
    return ASSET_LINUX_SERVER


def _alert():
    from dfir_iris_client.alert import Alert
    from dfir_iris_client.session import ClientSession
    return Alert(ClientSession(apikey=config.IRIS_API_KEY,
                               host=config.IRIS_URL,
                               ssl_verify=config.IRIS_VERIFY_TLS))


def _status_id(alert, name: str) -> int:
    global _STATUSES_ID
    if _STATUSES_ID is None:
        try:
            items = alert._s.pi_get("/manage/alert-status/list").get_data()
            _STATUSES_ID = {str(s["status_name"]).lower(): s["status_id"]
                           for s in items}
        except Exception as e:  # noqa: BLE001
            log.warning("liste des statuts d'alerte IRIS illisible (%s) : "
                        "repli sur les ids par défaut", e)
            _STATUSES_ID = dict(_STATUSES_FALLBACK)
    return _STATUSES_ID.get(name.lower()) or _STATUSES_FALLBACK[name.lower()]


def _outage_severity(sensor: str, m: dict | None = None) -> str:
    """Un capteur CONTINU muet est une perte de visibilité immédiate et
    certaine ; un capteur ÉVÉNEMENTIEL, dont le silence est l'état normal, sort
    sur un seuil de plusieurs heures et se trompe plus souvent (cf. le seuil
    syscheck dans config). La sévérité dit cette différence de confiance.

    Le disque suit la même logique : au seuil d'alerte il reste du temps pour
    agir (Medium), au seuil critique il n'y en a plus (High).
    """
    if (m or {}).get("severity"):
        return m["severity"]
    if sensor == SENSOR_DISK:
        return ("High" if (m or {}).get("pct", 0) >= config.DISK_THRESHOLD_CRITICAL
                else "Medium")
    return ("Medium" if sensor in config.WATCHDOG_SILENCE_PER_SENSOR
            else "High")


def _open_alert(m: dict, minutes: int) -> int | None:
    """Alerte IRIS pour une panne. Best-effort, comme le canal `case`.

    Une alerte n'a pas de notes : tout le diagnostic tient dans la description,
    que l'onglet Alerts affiche en TEXTE BRUT (cf. `_note_panne`).
    """
    alert = _alert()
    agent_name = m["agent_name"] or m["agent_id"]
    disk = m["sensor"] == SENSOR_DISK
    family = ("disque-sature" if disk
               else "archivage" if _is_archiving(m["sensor"])
               else "routage" if m.get("note") else "capteur-muet")
    tags = ["aura", family, m["sensor"]]
    if m["agent_name"]:
        tags.append(m["agent_name"])
    r = alert.add_alert({
        "alert_title": _title(m),
        "alert_description": _rendered(m, minutes, markdown=False),
        "alert_source": SOURCE_ALERT,
        # Ce que le watchdog reconnaît comme « sa » ligne pour ce couple
        # (agent, capteur) : l'idempotence est garantie en base par l'index
        # partiel, cette référence sert à retrouver l'alerte côté IRIS.
        "alert_source_ref": f"capteur-{m['agent_id']}-{m['sensor']}",
        # Début RÉEL de la panne (dernier événement vu), pas l'instant de
        # détection : c'est ce que l'analyste doit lire dans la timeline.
        "alert_source_event_time": m["dernier"].strftime("%Y-%m-%dT%H:%M:%S"),
        "alert_severity_id": _alert_severity_id(
            alert, _outage_severity(m["sensor"], m)),
        "alert_status_id": _status_id(alert, "New"),
        "alert_customer_id": config.IRIS_CUSTOMER,
        "alert_classification_id": CLASSIF_OUTAGE,
        "alert_tags": ",".join(tags),
        "alert_assets": [{"asset_name": agent_name,
                          "asset_type_id": _type_asset(m.get("os"))}],
    })
    if not r.is_success():
        log.error("alerte panne %s/%s : %s", m["agent_id"], m["sensor"],
                  r.get_msg())
        return None
    return r.get_data()["alert_id"]


def _alert_severity_id(alert, name: str) -> int:
    """Même échelle que les cases, donc même résolution par nom : `iris.py`
    sait déjà lire `/manage/severities/list` et retomber sur ses ids."""
    from .iris import _SEVERITIES_FALLBACK, _severity_id
    return _severity_id(alert, name) or _SEVERITIES_FALLBACK[name.lower()]


def _close_alert(alert_id: int, p: dict, minutes: int) -> None:
    """Rétablissement : on complète la description et on referme.

    Sauf si un humain a escaladé l'alerte — dans ce cas le dossier qu'il a
    ouvert lui appartient, on l'informe sans toucher au statut.
    """
    alert = _alert()
    lu = alert.get_alert(alert_id)
    if not lu.is_success():
        # Alerte supprimée à la main, par exemple. On ne peut plus rien écrire
        # dessus, mais la panne est bien rétablie : ne pas propager l'échec.
        log.warning("alerte %s illisible (%s) : panne marquée rétablie sans "
                    "mise à jour IRIS", alert_id, lu.get_msg())
        return
    data = lu.get_data()
    status = str((data.get("status") or {}).get("status_name") or "").lower()
    # Texte brut, comme la description d'ouverture : l'onglet Alerts ne rend
    # pas le markdown.
    if _is_routing(p["sensor"]):
        header = [
            "ROUTAGE RÉTABLI",
            "",
            f"L'anomalie de routage {p['sensor']} n'est plus constatée : la "
            "source est routée vers son index, ou elle a cessé d'émettre.",
            "",
            f"  Anomalie détectée le : {p['detected_at']:%Y-%m-%d %H:%M} UTC",
            f"  Durée                : {_duration(minutes)}",
            "",
            "Vérifier que la résolution vient bien d'une correction du routage "
            "et non de la disparition de la source : une source qui se tait "
            "referme cette alerte sans que rien n'ait été réparé.",
        ]
    elif _is_archiving(p["sensor"]):
        header = [
            "ARCHIVAGE RÉTABLI",
            "",
            f"L'anomalie d'archivage {p['sensor']} n'est plus constatée.",
            "",
            f"  Anomalie détectée le : {p['detected_at']:%Y-%m-%d %H:%M} UTC",
            f"  Durée                : {_duration(minutes)}",
            "",
            "Attention au sens de cette clôture selon l'anomalie : un péril de "
            "purge se referme parce que la copie EXISTE désormais, mais un trou "
            "de couverture se referme aussi si les mois qui l'encadraient ont "
            "quitté la fenêtre de rétention des archives. Dans le second cas "
            "rien n'a été réparé — la donnée manquante manque toujours.",
        ]
    elif p["sensor"] == SENSOR_DISK:
        header = [
            "DISQUE REVENU SOUS LE SEUIL",
            "",
            f"L'occupation de {config.DISK_MONITORED} sur "
            f"{p['agent_name'] or p['agent_id']} est repassée sous "
            f"{config.DISK_THRESHOLD_ALERT} %.",
            "",
            f"  Saturation détectée le : {p['detected_at']:%Y-%m-%d %H:%M} UTC",
            f"  Occupation au pic      : {p['volume_ref']} %",
            f"  Durée de la saturation : {_duration(minutes)}",
            "",
            "Vérifier que la place a été rendue par un ménage VOLONTAIRE et "
            "non par une purge subie (index supprimés par l'ISM, rotation "
            "d'un journal) : dans le second cas, la cause de la saturation "
            "est toujours là et reviendra.",
        ]
    else:
        header = [
            "CAPTEUR RÉTABLI",
            "",
            f"Le capteur {p['sensor']} de {p['agent_name'] or p['agent_id']} "
            "réémet.",
            "",
            f"  Panne détectée le       : {p['detected_at']:%Y-%m-%d %H:%M} UTC",
            f"  Dernier événement avant : "
            f"{p['last_event']:%Y-%m-%d %H:%M} UTC",
            f"  Durée totale du silence : {_duration(minutes)}",
            "",
            "Les événements de la période de silence sont définitivement "
            "perdus si le capteur ne tamponnait pas : ce qui s'est produit sur "
            "cet hôte pendant la panne n'a jamais été analysé.",
        ]
    body = "\n".join([
        data.get("alert_description") or "",
        "",
        "-" * 60,
        "",
        *header,
        "",
    ])
    update = {"alert_description": body}
    if status in STATUSES_HUMAN:
        log.info("alerte %s en statut « %s » : rétablissement noté, statut "
                 "laissé à l'analyste", alert_id, status)
        update["alert_description"] = body + (
            "-- Rétablissement constaté par le watchdog AURA. Le statut de "
            "cette alerte est laissé tel quel : elle a été escaladée.")
    else:
        update["alert_status_id"] = _status_id(alert, "Closed")
        update["alert_description"] = body + (
            "-- Clôturée automatiquement par le watchdog AURA.")
    r = alert.update_alert(alert_id, update)
    if not r.is_success():
        # Remonté à l'appelant : la panne reste OUVERTE en base et sera
        # retentée, exactement comme pour un case (cf. surveiller).
        raise RuntimeError(f"update_alert {alert_id} : {r.get_msg()}")


def _open_case(m: dict, minutes: int) -> int | None:
    """Case IRIS pour une panne. Best-effort : un IRIS injoignable ne doit pas
    empêcher d'enregistrer la panne en base ni de la journaliser."""
    from .iris import _client, _set_note, _tag
    name = _title(m)
    desc = (f"Le capteur {m['sensor']} de l'agent {m['agent_id']} "
            f"({m['agent_name'] or '?'}) n'émet plus depuis {_duration(minutes)} "
            f"(dernier événement {m['dernier']:%Y-%m-%d %H:%M} UTC, seuil "
            f"{m['seuil']} min). La détection adossée à ce capteur est inerte.")
    case = _client()
    r = case.add_case(
        case_name=name,
        case_description=desc,
        case_customer=config.IRIS_CUSTOMER,
        case_classification=CLASSIF_OUTAGE,
        soc_id=f"Aura-SOC-capteur-{m['agent_id']}-{m['sensor']}",
    )
    if not r.is_success():
        log.error("case panne %s/%s : %s", m["agent_id"], m["sensor"],
                  r.get_msg())
        return None
    case_id = r.get_data()["case_id"]
    _tag(case, case_id, m["agent_name"])
    _set_note(case, case_id, "Détail de la panne", _rendered(m, minutes))
    return case_id


def _close_case(case_id: int, p: dict, minutes: int) -> None:
    """Note de rétablissement puis clôture. Best-effort, comme l'ouverture."""
    from .iris import _client, _set_note
    case = _client()
    _set_note(case, case_id, "Rétablissement", "\n".join([
        "# Capteur rétabli",
        "",
        f"Le capteur **{p['sensor']}** de **{p['agent_name'] or p['agent_id']}** "
        "réémet.",
        "",
        f"- Panne détectée le {p['detected_at']:%Y-%m-%d %H:%M} UTC",
        f"- Dernier événement avant la panne : {p['last_event']:%Y-%m-%d %H:%M} UTC",
        f"- Durée totale du silence : {_duration(minutes)}",
        "",
        "**Les événements de la période de silence sont définitivement perdus** "
        "si le capteur ne tamponnait pas : ce qui s'est produit sur cet hôte "
        "pendant la panne n'a jamais été analysé.",
        "",
        "*Clôturé automatiquement par le watchdog AURA.*",
    ]))
    case.close_case(case_id)


def _routing() -> list[dict]:
    """Passage du contrôle de routage, rendu au format des capteurs muets.

    Le contrôle est actif : il crée les index sets manquants au passage (cf.
    `routage.reconcilier`). Ce qui remonte ici est ce qu'il n'a PAS su régler
    tout seul — source qu'il n'a pas su nommer, plafond de créations atteint,
    routage dévié, source établie devenue muette.

    Best-effort assumé : un indexer qui ne répond pas ne doit pas empêcher la
    surveillance des capteurs, qui est le cœur du watchdog.
    """
    if not config.ROUTING_ACTIVE:
        return []
    try:
        from . import routing
        report = routing.reconcile()
    except Exception as e:                                    # noqa: BLE001
        log.warning("contrôle de routage impossible : %s", e)
        return []
    for base in report.get("creees") or []:
        log.error("INDEX SET CRÉÉ : %s — une source de log nouvelle a son "
                  "index, son mapping, sa rétention et son index pattern.",
                  base)
    if report.get("pipeline"):
        log.warning("pipeline d'ingest : %s", report["pipeline"])
    return report.get("anomalies") or []


def _archiving(conn) -> list[dict]:
    """État de l'archivage à froid, rendu au format des capteurs muets.

    LECTURE SEULE, contrairement à `_routage()` : l'archivage lui-même est fait
    par `soc-agent-archive`, à sa cadence. Un export de plusieurs centaines de
    mégaoctets n'a rien à faire dans un passage de watchdog qui tourne toutes les
    deux minutes.

    Ce qui remonte ici, c'est ce qu'un archivage « qui tourne » ne dit pas de
    lui-même : de la donnée qui va être purgée sans copie, un mois manquant au
    milieu d'une série, une archive qui ne se relit plus.
    """
    if not config.ARCHIVING_ENABLED:
        return []
    try:
        from . import archive
        return archive.anomalies(conn)
    except Exception as e:                                        # noqa: BLE001
        # Best-effort, comme le routage : un S3 injoignable ou une table absente
        # ne doit pas emporter la surveillance des capteurs, qui est le cœur du
        # watchdog.
        log.warning("état de l'archivage illisible : %s", e)
        return []


def monitor() -> dict:
    """Un passage complet : détecter, ouvrir, fermer. Renvoie le compte rendu.

    Idempotent par construction — l'index unique partiel de `capteur_pannes`
    interdit deux pannes ouvertes pour le même (agent, capteur), donc deux
    passages concurrents ne peuvent pas ouvrir deux cases.
    """
    opened, closed = [], []
    channel = config.WATCHDOG_IRIS_CHANNEL
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        horizon, lag = ingest_horizon(conn)
        # Ingestion à l'arrêt : tous les capteurs vont paraître muets au même
        # instant. Ce n'est pas une panne de capteur, c'est une panne du
        # pipeline — on le dit et on ne fabrique pas six dossiers pour un seul
        # problème.
        if lag is not None and lag > config.WATCHDOG_LAG_INGEST_MAX:
            log.error("INGESTION EN RETARD de %s (horizon %s) — surveillance "
                      "des capteurs suspendue : tout paraîtrait muet.",
                      _duration(lag), horizon)
            # Le disque, lui, reste surveillé : il ne se déduit pas des alertes
            # ingérées, et une ingestion à l'arrêt est précisément ce que
            # produit un disque plein. S'en taire ici, c'est se taire au seul
            # moment qui compte.
            # L'archivage est surveillé pour la même raison que le disque : son
            # état ne se déduit pas des alertes ingérées, et une purge ISM
            # continue de tourner pendant que l'ingestion est à l'arrêt. Se
            # taire ici, c'est laisser partir de la donnée sans copie.
            silent = disk_saturated() + _archiving(conn)
            ingest_ok = False
        else:
            ingest_ok = True
            # Le disque du SOC entre dans la même liste que les capteurs muets :
            # même état, même canal, même clôture automatique (cf. disque_sature).
            silent = (silent_sensors(conn) + disk_saturated() + _routing()
                     + _archiving(conn))
        seen = {(m["agent_id"], m["sensor"]) for m in silent}
        # OS connu de la CMDB, pour typer l'asset IRIS. Une seule requête, et
        # son absence n'empêche rien : `_type_asset` a un défaut.
        oses = {a["agent_id"]: a["os"] for a in conn.execute(
            "SELECT agent_id, os FROM assets").fetchall()}

        for m in silent:
            minutes = _minutes(m["dernier"], m["horizon"])
            if _is_routing(m["sensor"]):
                log.warning("ANOMALIE DE ROUTAGE : %s", m["titre"])
            elif _is_archiving(m["sensor"]):
                log.error("ARCHIVAGE : %s", m["titre"])
            elif m["sensor"] == SENSOR_DISK:
                log.error(
                    "DISQUE SATURÉ : %s à %d%% sur %s (%.1f Go libres, seuil "
                    "%d%%). Un disque plein arrête l'ingestion sans qu'aucune "
                    "alerte ne le dise.", config.DISK_MONITORED, m["pct"],
                    m["agent_name"], m["libre_go"], m["seuil"])
            else:
                log.warning(
                    "CAPTEUR MUET : '%s' sur %s (agent %s) — %d events de "
                    "référence, rien depuis %s (%s). Angle mort : les règles "
                    "adossées à ce capteur sont inertes.",
                    m["sensor"], m["agent_name"] or "?", m["agent_id"],
                    m["volume"], m["dernier"], _duration(minutes))
            r = conn.execute(
                """INSERT INTO sensor_outages
                       (agent_id, agent_name, sensor, last_event,
                        volume_ref, threshold_minutes)
                   VALUES (%s, %s, %s, %s, %s, %s)
                   ON CONFLICT (agent_id, sensor) WHERE status = 'ouverte'
                   DO NOTHING
                   RETURNING id""",
                (m["agent_id"], m["agent_name"], m["sensor"], m["dernier"],
                 m["volume"], m["seuil"])).fetchone()
            conn.commit()
            if not r:
                continue  # panne déjà ouverte : rien à refaire
            trace_id, column = None, None
            if channel != "off":
                column = ("iris_alert_id" if channel == "alert"
                           else "iris_case_id")
                try:
                    trace_id = (_open_alert({**m, "os": oses.get(m["agent_id"])},
                                               minutes)
                                if channel == "alert"
                                else _open_case(m, minutes))
                except Exception as e:  # noqa: BLE001 — IRIS ne bloque pas
                    log.warning("trace IRIS (%s) non créée (%s/%s) : %s",
                                channel, m["agent_id"], m["sensor"], e)
            if trace_id:
                conn.execute(
                    f"UPDATE capteur_pannes SET {column}=%s WHERE id=%s",
                    (trace_id, r["id"]))
                conn.commit()
            log.error("PANNE OUVERTE : %s sur %s — %s IRIS %s",
                      m["sensor"], m["agent_name"] or m["agent_id"], channel,
                      trace_id or "non créée")
            opened.append({**m, "iris_case_id": trace_id if channel == "case"
                             else None,
                             "iris_alert_id": trace_id if channel == "alert"
                             else None})

        for p in conn.execute(
                "SELECT * FROM sensor_outages WHERE status='ouverte'").fetchall():
            if (p["agent_id"], p["sensor"]) in seen:
                continue
            # Ingestion en retard : `capteurs_muets` n'a pas tourné, donc
            # l'absence d'un capteur de `vus` ne prouve RIEN. Le refermer ici
            # annoncerait un rétablissement qu'on n'a pas constaté. Seul le
            # disque, mesuré hors pipeline, peut se refermer dans cet état.
            if not ingest_ok and not (p["sensor"] == SENSOR_DISK
                                      or _is_archiving(p["sensor"])):
                continue
            outside_horizon = _outside_pipeline(p["sensor"])
            # Le disque se mesure contre l'HORLOGE, pas contre l'horizon
            # d'ingestion : il ne se déduit pas des alertes ingérées. Mesurer sa
            # saturation contre un horizon en retard donnait une durée négative
            # (« -2 min ») dans l'alerte de rétablissement.
            minutes = _minutes(p["last_event"],
                               None if outside_horizon else horizon)
            # On ferme dans le canal où la panne a été OUVERTE, lu sur la ligne
            # et jamais sur la configuration courante : basculer `case` ->
            # `alert` ne doit pas abandonner les cases déjà ouverts.
            #
            # `off` ne tente rien : c'est le réglage qu'on pose justement quand
            # IRIS est indisponible, et échouer ici bloquerait le passage en
            # « rétablie » pour toujours.
            try:
                if channel == "off":
                    pass
                elif p["iris_alert_id"]:
                    _close_alert(p["iris_alert_id"], p, minutes)
                elif p["iris_case_id"]:
                    _close_case(p["iris_case_id"], p, minutes)
            except Exception as e:  # noqa: BLE001
                # On laisse la panne OUVERTE en base pour retenter au tour
                # suivant. La marquer rétablie ici alors que le dossier
                # reste ouvert dans IRIS laisserait un case fantôme que
                # plus rien ne referme — arrivé le 2026-08-12, IRIS
                # OOM-killé pile au moment où debian2 réémettait.
                log.warning("clôture IRIS impossible (%s) — panne %s laissée "
                            "ouverte, nouvelle tentative au prochain passage",
                            e, p["id"])
                continue
            conn.execute(
                "UPDATE sensor_outages SET status='retablie', recovered_at=now() "
                "WHERE id=%s", (p["id"],))
            conn.commit()
            if _is_routing(p["sensor"]):
                log.info("ROUTAGE RÉTABLI : %s (anomalie ouverte pendant %s)",
                         p["sensor"], _duration(minutes))
            elif _is_archiving(p["sensor"]):
                log.info("ARCHIVAGE RÉTABLI : %s (anomalie ouverte pendant %s)",
                         p["sensor"], _duration(minutes))
            elif p["sensor"] == SENSOR_DISK:
                log.info("DISQUE REVENU SOUS LE SEUIL : %s sur %s (saturé "
                         "pendant %s, pic à %d%%)", config.DISK_MONITORED,
                         p["agent_name"] or p["agent_id"], _duration(minutes),
                         p["volume_ref"])
            else:
                log.info("CAPTEUR RÉTABLI : %s sur %s (silence %s)",
                         p["sensor"], p["agent_name"] or p["agent_id"],
                         _duration(minutes))
            closed.append(p)

    return {"muets": silent, "ouvertes": opened, "fermees": closed,
            **({} if ingest_ok else {"retard_ingest": lag})}


def check() -> list[dict]:
    """Appelée par le cycle. Lecture seule + log : la gestion d'état et les
    cases IRIS appartiennent au service dédié (`--surveiller`), qui tourne à sa
    propre cadence — un capteur muet doit être vu en minutes, pas au rythme du
    cycle de triage."""
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        silent = silent_sensors(conn)
    for m in silent:
        log.warning(
            "CAPTEUR MUET : '%s' sur %s (agent %s) — %d events de référence, "
            "rien depuis %s. Angle mort : les règles adossées à ce capteur sont "
            "inertes.", m["sensor"], m["agent_name"] or "?", m["agent_id"],
            m["volume"], m["dernier"])
    # Le disque est mesuré ici aussi : le cycle tourne toutes les 5 minutes et
    # c'est LUI qui s'arrêtera en premier si le disque se remplit. Lecture
    # seule, comme le reste de `verifier` — l'alerte appartient à `surveiller`.
    for d in disk_saturated():
        log.error("DISQUE SATURÉ : %s à %d%% (%.1f Go libres, seuil %d%%)",
                  config.DISK_MONITORED, d["pct"], d["libre_go"], d["seuil"])
    return silent


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--surveiller", action="store_true",
                   help="ouvrir/fermer les pannes et leurs cases IRIS")
    args = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.monitor:
        r = monitor()
        print(f"{len(r['muets'])} capteur(s) muet(s), "
              f"{len(r['ouvertes'])} panne(s) ouverte(s), "
              f"{len(r['fermees'])} rétablie(s)")
        return

    silent = check()
    if not silent:
        print("Aucun capteur muet.")
        return
    print(f"{len(silent)} capteur(s) muet(s) :")
    for m in silent:
        print(f"  {m['agent_name'] or '?':<20} {m['sensor']:<14} "
              f"muet depuis {m['dernier']:%Y-%m-%d %H:%M} "
              f"({m['volume']} events de référence, seuil {m['seuil']} min)")


if __name__ == "__main__":
    main()
