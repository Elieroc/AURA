"""Silent-sensor detection, pipeline side, and opening the matching record.

A correlation rule never detects an ABSENCE: it only reasons on events that are
present (see rules/README, auditd heartbeat 100800-806). The heartbeat covers
kernel auditing, but three real outages escaped it:

- 2026-07-29: the Suricata feed went quiet for ~26 h (logcollector drowned by a
  stream-events flood). No alert: the sensor produced nothing any more.
- 2026-07-29: the journald reader of a Wazuh 4.9.2 agent (bookstack) was stuck —
  0 sshd/pam events reported, hence invisible SSH brute-force. An agent restart
  brought it back.
- 2026-08-11: the pfSense logcollector had been blocked since 2 August (four
  stacked processes, a single thread on a mutex). Five Suricata interfaces and
  all the gateway syslogs silent for nine days, agent `active` and the dashboard
  green.

These cases share one shape: a sensor that WAS TALKING went quiet. We detect it
at the alert database level (hence indexer side, NOT subject to the agent
logcollector backlog): a rule group established over the reference window, but
without a single event since its silence threshold.

The threshold is tunable PER SENSOR (WATCHDOG_SILENCE_PER_SENSOR) and that is
essential: a CONTINUOUS sensor (audit, suricata) is judged in minutes, an
EVENT-DRIVEN sensor (sshd, syscheck) only emits when something happens and its
silence is the normal state. The values are calibrated on the real distribution
of gaps between events, measured in database (see config).

    python -m soc_agent.watchdog             # lists the silent sensors
    python -m soc_agent.watchdog --monitor   # + opens/closes the IRIS records

The outage is a STATE, tracked in `sensor_outages`: a single opening per
(agent, sensor) guaranteed by a partial unique index, IRIS record created once,
closed automatically when the sensor speaks again.

That record is an IRIS ALERT, not a case (see WATCHDOG_IRIS_CHANNEL). A case is
an investigation file; a sensor outage has nothing to investigate, it has a state
and a gesture — the Alerts tab carries exactly that life cycle, and leaves the
analyst the "Escalate to case" button when they judge it deserves a file. The
historical `case` channel stays available.

The IRIS content stays in French: analysts read it.
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

# availability:outage — a sensor outage is a loss of detection availability, not
# an intrusion.
CLASSIF_OUTAGE = 25

# What each sensor's outage makes inert. Used by the record: an analyst reading
# "suricata silent" must know WHAT THEY NO LONGER SEE, without digging through
# the ruleset. French, like the rest of the IRIS content.
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

# A silent sensor = a rule group seen >= BASELINE_MIN times over the reference
# window, but whose last alert is older than its silence threshold.
#
# Silence is measured against the INGESTION HORIZON, never against the clock.
# This database is not fed continuously: the cycle ingests every 5 min, so
# between two passes EVERY sensor looks silent, and all the longer when the cycle
# has just been restarted. Measured on 2026-08-11 while commissioning this
# module: four minutes after a container restart, `audit` on home-s-pve01 and
# `suricata` on the pfSense were declared down for "15 min of silence" while both
# were emitting normally — the database simply had not been refreshed yet.
# Compared to the horizon, an ingestion lag shifts every sensor by the same
# amount and can no longer manufacture an outage.
#
# The corollary is that the watchdog goes blind if ingestion itself stops: that
# is another failure mode, covered by `ingest_horizon()`.
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
       count(*) AS volume, max(ts) AS last,
       (SELECT h FROM horizon) AS horizon,
       COALESCE((%(per_sensor)s::jsonb ->> g)::int, %(silence)s) AS threshold
  FROM grp
 WHERE g = ANY(%(sensors)s)
 GROUP BY agent_id, agent_name, g
HAVING count(*) >= %(baseline)s
   AND max(ts) < (SELECT h FROM horizon)
                 - (COALESCE(%(per_sensor)s::jsonb ->> g,
                             %(silence)s::text) || ' minutes')::interval
 ORDER BY last
"""


def silent_sensors(conn) -> list[dict]:
    """Established sensors gone silent. A pure function (one query), hence
    testable alone and with no side effect."""
    return conn.execute(_SQL, {
        "ref": config.WATCHDOG_REF_HOURS,
        "sensors": list(config.WATCHDOG_SENSORS),
        "baseline": config.WATCHDOG_BASELINE_MIN,
        "silence": config.WATCHDOG_SILENCE_MINUTES,
        # Threshold specific to some sensors (sshd and syscheck only emit on
        # events); the default applies to the others.
        "per_sensor": json.dumps(config.WATCHDOG_SILENCE_PER_SENSOR),
    }).fetchall()


def _minutes(since, reference=None) -> int:
    """Minutes elapsed since `since`, measured against the ingestion horizon
    when it is given — see the `_SQL` comment. The clock is only the right
    reference for ingestion itself."""
    end = reference or datetime.now(timezone.utc)
    return int((end - since).total_seconds() // 60)


def ingest_horizon(conn):
    """How far the database is up to date, and for how long it has not been.

    The watchdog reasons on what the pipeline ingested; if ingestion stalls it
    sees nothing go by and would stay quiet — a silent failure of the tool that
    watches for failures. So we measure that lag too, against the clock.
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
# Disk guardrail
# --------------------------------------------------------------------------
#
# On 2026-08-14 the production disk had taken 6 GB in the day (MISP audit log,
# Evidence pieces re-posted in a loop) without anything saying so. A SOC whose
# disk fills up does not fail loudly: the indexer flips to read-only, Postgres
# refuses to write, and no alert enters any more — that is, exactly the same
# consequence as a silent sensor, at the scale of the whole pipeline.
#
# Hence treating it as a sensor: same state table (`sensor_outages`), same
# channel (IRIS alert), same automatic closure on returning below the threshold.
# A full disk is a STATE to acknowledge, not an investigation to run — the
# reasoning that made the Alerts tab the choice for sensor outages applies word
# for word here.
SENSOR_DISK = "disk"

# Prefixes of the pseudo-sensors set by `routing.py`. A log source that does not
# land in its index is a blind spot of the same nature as a silent sensor — the
# alerts exist, but nobody looks at them where they are — and is therefore
# tracked in the same state table, with the same automatic closure.
PREFIXES_ROUTING = ("routing:", "silent-source:")

# Pseudo-sensors set by `archive.py`. A missing archive is a FUTURE loss of
# visibility: the data is there today, it will not be there when we look for it.
# Same state table, same channel, same automatic closure — and like the disk and
# routing, it is measured against the CLOCK and not against the ingestion
# horizon.
PREFIX_ARCHIVING = "archiving:"


def _is_routing(sensor: str) -> bool:
    return sensor.startswith(PREFIXES_ROUTING)


def _is_archiving(sensor: str) -> bool:
    return sensor.startswith(PREFIX_ARCHIVING)


def _outside_pipeline(sensor: str) -> bool:
    """Is this sensor measured against the clock rather than the ingestion
    horizon?

    Three families are not derived from the ingested alerts: the disk, routing
    (measured on the indexer) and archiving (measured on S3 and in database).
    Relating them to a lagging horizon gave wrong, even negative durations
    ("saturated for -2 min") in the recovery alerts.
    """
    return (sensor == SENSOR_DISK or _is_routing(sensor)
            or _is_archiving(sensor))

# The SOC host is not a monitored agent like the others: it is the manager
# itself. Its Wazuh agent id is 000 by construction.
AGENT_SOC = "000"


def disk_saturated() -> list[dict]:
    """Is the SOC disk past the threshold? Zero or one entry.

    Returned in the shape of a silent sensor (same keys) so it goes through the
    open/close loop of `monitor` with no special case.
    """
    try:
        u = shutil.disk_usage(config.DISK_MONITORED)
    except OSError as e:
        log.warning("disk %s unreadable: %s", config.DISK_MONITORED, e)
        return []
    pct = round(100 * u.used / u.total)
    if pct < config.DISK_THRESHOLD_ALERT:
        log.debug("disk %s at %d%% (threshold %d%%)", config.DISK_MONITORED,
                  pct, config.DISK_THRESHOLD_ALERT)
        return []
    now = datetime.now(timezone.utc)
    return [{
        "agent_id": AGENT_SOC,
        "agent_name": socket.gethostname(),
        "sensor": SENSOR_DISK,
        # `last` and `horizon` are the moment of the measurement: a full disk
        # has no "last event", it has a state observed now.
        "last": now,
        "horizon": now,
        "volume": pct,
        "threshold": config.DISK_THRESHOLD_ALERT,
        "free_gb": u.free / 1073741824,
        "total_gb": u.total / 1073741824,
        "pct": pct,
    }]


def _disk_note(m: dict, markdown: bool = True) -> str:
    """Diagnosis of the saturated disk. Same double rendering as `_outage_note`:
    case notes are markdown, alert descriptions are plain text."""
    t = (lambda s: f"# {s}") if markdown else (lambda s: s.upper())
    g = (lambda s: f"**{s}**") if markdown else (lambda s: str(s))
    c = (lambda s: f"`{s}`") if markdown else (lambda s: str(s))
    critical = m["pct"] >= config.DISK_THRESHOLD_CRITICAL
    return "\n".join([
        t("Disque du SOC saturé"),
        "",
        f"Le système de fichiers {c(config.DISK_MONITORED)} de "
        f"{g(m['agent_name'])} est occupé à {g(str(m['pct']) + ' %')} "
        f"({m['free_gb']:.1f} Go libres sur {m['total_gb']:.0f} Go).",
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
    """The diagnosis of one entry, whatever its nature.

    Three families now share the same state table: silent sensors, the saturated
    disk, and routing anomalies (`routing.py`). The first two compose their text
    here; the third brings it already written, because the module that knows the
    ingest pipeline is the one that knows what to say about it. Hence this single
    dispatch point, rather than an `if` repeated in every caller.
    """
    if m.get("note"):
        return m["note"]
    if m["sensor"] == SENSOR_DISK:
        return _disk_note(m, markdown)
    return _outage_note(m, minutes, markdown)


def _title(m: dict) -> str:
    if m.get("title"):
        return m["title"]
    name = m["agent_name"] or m["agent_id"]
    if m["sensor"] == SENSOR_DISK:
        return f"[DISQUE SATURÉ] {m['pct']} % sur {name}"
    return f"[CAPTEUR MUET] {m['sensor']} sur {name}"


def _outage_note(m: dict, minutes: int, markdown: bool = True) -> str:
    """The outage diagnosis, in the only dialect the destination can render.

    Case NOTES are rendered as markdown by IRIS; ALERT DESCRIPTIONS are not —
    verified on the Alerts tab on 2026-08-13, where `# title`, `**bold**`,
    backticks and tables displayed literally, pipes and hashes included. A
    markdown table becomes six lines of scrap in the middle of the useful text,
    exactly where the analyst is looking for the time of the last event.

    Hence two renderings of the SAME content, and not two contents: what must be
    read does not depend on the tab it is read in.
    """
    scope = _SCOPE.get(m["sensor"], "les règles adossées à ce capteur")
    agent = m["agent_name"] or m["agent_id"]

    def t(title: str, level: int = 1) -> str:      # heading
        return f"{'#' * level} {title}" if markdown else title.upper()

    def g(txt: str) -> str:                          # emphasis
        return f"**{txt}**" if markdown else txt

    def c(txt: str) -> str:                          # literal (code)
        return f"`{txt}`" if markdown else txt

    facts = [
        ("Capteur", c(m["sensor"])),
        ("Agent", f"{m['agent_name'] or '?'} ({c(m['agent_id'])})"),
        ("Dernier événement", f"{m['last']:%Y-%m-%d %H:%M:%S} UTC"),
        ("Silence", _duration(minutes)),
        ("Seuil de panne", f"{m['threshold']} min"),
        ("Volume de référence",
         f"{m['volume']} événements sur {config.WATCHDOG_REF_HOURS} h"),
    ]
    if markdown:
        array = ["| | |", "|---|---|"] + [f"| {k} | {v} |" for k, v in facts]
    else:
        # Hand alignment: without a table it is the only thing that makes these
        # six lines readable at a glance.
        width = max(len(k) for k, _ in facts)
        array = [f"  {k.ljust(width)} : {v}" for k, v in facts]

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
# ALERT channel (default) — see config.WATCHDOG_IRIS_CHANNEL
# --------------------------------------------------------------------------
#
# `alert_source`: that is how the Alerts tab is filtered to see only sensor
# health. A stable value, never derived from the sensor.
SOURCE_ALERT = "AURA watchdog"

# IRIS alert statuses. THE SAME TRAP as case severity (see iris.py): the ids
# follow no logical order — observed on the production IRIS on 2026-08-13, New=2
# but Unspecified=1, Closed=6, Merged=7, Escalated=8. Any value hard-coded here
# would be right by accident, so we resolve by NAME and this dictionary is only a
# logged fallback.
_STATUSES_FALLBACK = {"unspecified": 1, "new": 2, "assigned": 3, "in progress": 4,
                  "pending": 5, "closed": 6, "merged": 7, "escalated": 8}
_STATUSES_ID: dict[str, int] | None = None

# Statuses meaning a HUMAN took over: they judged the outage deserved a file and
# escalated it. The watchdog does not come back after them to force "Closed" on
# recovery — it merely writes that the sensor emits again. That is the deep
# difference with the `case` channel, where automatic closure overwrote the
# analyst's gesture.
STATUSES_HUMAN = {"escalated", "merged"}

# IRIS asset types (`/manage/asset-type/list`, observed on 2026-08-13). The
# asset serves two purposes: grouping the alerts of one machine, and following
# that machine into the case if the analyst escalates.
ASSET_LINUX_SERVER, ASSET_FIREWALL = 3, 2
ASSET_WIN_POSTE, ASSET_WIN_SERVER = 9, 10


def _type_asset(os_txt: str | None) -> int:
    """IRIS type inferred from the OS known to the CMDB. Deliberate best-effort:
    picking the wrong pictogram costs nothing, not creating the asset would lose
    the grouping per machine."""
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
            log.warning("IRIS alert status list unreadable (%s): falling back "
                        "on the default ids", e)
            _STATUSES_ID = dict(_STATUSES_FALLBACK)
    return _STATUSES_ID.get(name.lower()) or _STATUSES_FALLBACK[name.lower()]


def _outage_severity(sensor: str, m: dict | None = None) -> str:
    """A silent CONTINUOUS sensor is an immediate and certain loss of
    visibility; an EVENT-DRIVEN sensor, whose silence is the normal state, fires
    on a threshold of several hours and is wrong more often (see the syscheck
    threshold in config). The severity states that difference in confidence.

    The disk follows the same logic: at the alert threshold there is still time
    to act (Medium), at the critical threshold there is none (High).
    """
    if (m or {}).get("severity"):
        return m["severity"]
    if sensor == SENSOR_DISK:
        return ("High" if (m or {}).get("pct", 0) >= config.DISK_THRESHOLD_CRITICAL
                else "Medium")
    return ("Medium" if sensor in config.WATCHDOG_SILENCE_PER_SENSOR
            else "High")


def _open_alert(m: dict, minutes: int) -> int | None:
    """IRIS alert for an outage. Best-effort, like the `case` channel.

    An alert has no notes: the whole diagnosis sits in the description, which the
    Alerts tab displays as PLAIN TEXT (see `_outage_note`).
    """
    alert = _alert()
    agent_name = m["agent_name"] or m["agent_id"]
    disk = m["sensor"] == SENSOR_DISK
    family = ("disk-saturated" if disk
               else "archiving" if _is_archiving(m["sensor"])
               else "routing" if m.get("note") else "silent-sensor")
    tags = ["aura", family, m["sensor"]]
    if m["agent_name"]:
        tags.append(m["agent_name"])
    r = alert.add_alert({
        "alert_title": _title(m),
        "alert_description": _rendered(m, minutes, markdown=False),
        "alert_source": SOURCE_ALERT,
        # What the watchdog recognises as "its" row for this (agent, sensor)
        # pair: idempotence is guaranteed in database by the partial index, this
        # reference serves to find the alert again on the IRIS side.
        "alert_source_ref": f"sensor-{m['agent_id']}-{m['sensor']}",
        # REAL start of the outage (last event seen), not the moment of
        # detection: that is what the analyst must read in the timeline.
        "alert_source_event_time": m["last"].strftime("%Y-%m-%dT%H:%M:%S"),
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
        log.error("outage alert %s/%s: %s", m["agent_id"], m["sensor"],
                  r.get_msg())
        return None
    return r.get_data()["alert_id"]


def _alert_severity_id(alert, name: str) -> int:
    """Same scale as the cases, hence the same resolution by name: `iris.py`
    already knows how to read `/manage/severities/list` and fall back on its
    ids."""
    from .iris import _SEVERITIES_FALLBACK, _severity_id
    return _severity_id(alert, name) or _SEVERITIES_FALLBACK[name.lower()]


def _close_alert(alert_id: int, p: dict, minutes: int) -> None:
    """Recovery: we complete the description and close.

    Unless a human escalated the alert — in that case the file they opened
    belongs to them, we inform without touching the status.
    """
    alert = _alert()
    lu = alert.get_alert(alert_id)
    if not lu.is_success():
        # Alert deleted by hand, for instance. We cannot write on it any more,
        # but the outage really has recovered: do not propagate the failure.
        log.warning("alert %s unreadable (%s): outage marked recovered without "
                    "an IRIS update", alert_id, lu.get_msg())
        return
    data = lu.get_data()
    status = str((data.get("status") or {}).get("status_name") or "").lower()
    # Plain text, like the opening description: the Alerts tab does not render
    # markdown.
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
        log.info("alert %s in status \"%s\": recovery noted, status left to "
                 "the analyst", alert_id, status)
        update["alert_description"] = body + (
            "-- Rétablissement constaté par le watchdog AURA. Le statut de "
            "cette alerte est laissé tel quel : elle a été escaladée.")
    else:
        update["alert_status_id"] = _status_id(alert, "Closed")
        update["alert_description"] = body + (
            "-- Clôturée automatiquement par le watchdog AURA.")
    r = alert.update_alert(alert_id, update)
    if not r.is_success():
        # Propagated to the caller: the outage stays OPEN in database and will
        # be retried, exactly as for a case (see monitor).
        raise RuntimeError(f"update_alert {alert_id}: {r.get_msg()}")


def _open_case(m: dict, minutes: int) -> int | None:
    """IRIS case for an outage. Best-effort: an unreachable IRIS must not
    prevent recording the outage in database nor logging it."""
    from .iris import _client, _set_note, _tag
    name = _title(m)
    desc = (f"Le capteur {m['sensor']} de l'agent {m['agent_id']} "
            f"({m['agent_name'] or '?'}) n'émet plus depuis {_duration(minutes)} "
            f"(dernier événement {m['last']:%Y-%m-%d %H:%M} UTC, seuil "
            f"{m['threshold']} min). La détection adossée à ce capteur est inerte.")
    case = _client()
    r = case.add_case(
        case_name=name,
        case_description=desc,
        case_customer=config.IRIS_CUSTOMER,
        case_classification=CLASSIF_OUTAGE,
        soc_id=f"Aura-SOC-sensor-{m['agent_id']}-{m['sensor']}",
    )
    if not r.is_success():
        log.error("outage case %s/%s: %s", m["agent_id"], m["sensor"],
                  r.get_msg())
        return None
    case_id = r.get_data()["case_id"]
    _tag(case, case_id, m["agent_name"])
    _set_note(case, case_id, "Détail de la panne", _rendered(m, minutes))
    return case_id


def _close_case(case_id: int, p: dict, minutes: int) -> None:
    """Recovery note then closure. Best-effort, like the opening."""
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
    """One routing-control pass, returned in the silent-sensor shape.

    The control is active: it creates the missing index sets along the way (see
    `routing.reconcile`). What comes back here is what it could NOT fix on its
    own — a source it could not name, the creation cap reached, deviated routing,
    an established source gone silent.

    Deliberate best-effort: an indexer that does not answer must not prevent
    watching the sensors, which is the heart of the watchdog.
    """
    if not config.ROUTING_ACTIVE:
        return []
    try:
        from . import routing
        report = routing.reconcile()
    except Exception as e:                                    # noqa: BLE001
        log.warning("routing control impossible: %s", e)
        return []
    for base in report.get("created") or []:
        log.error("INDEX SET CREATED: %s — a new log source has its index, its "
                  "mapping, its retention and its index pattern.", base)
    if report.get("pipeline"):
        log.warning("ingest pipeline: %s", report["pipeline"])
    return report.get("anomalies") or []


def _archiving(conn) -> list[dict]:
    """State of the cold archiving, returned in the silent-sensor shape.

    READ-ONLY, unlike `_routing()`: archiving itself is done by
    `soc-agent-archive`, at its own pace. An export of several hundred megabytes
    has no business in a watchdog pass running every two minutes.

    What comes back here is what an archiving that "runs" does not say about
    itself: data about to be purged without a copy, a month missing in the middle
    of a series, an archive that no longer reads back.
    """
    if not config.ARCHIVING_ENABLED:
        return []
    try:
        from . import archive
        return archive.anomalies(conn)
    except Exception as e:                                        # noqa: BLE001
        # Best-effort, like routing: an unreachable S3 or a missing table must
        # not take down the sensor watch, which is the heart of the watchdog.
        log.warning("archiving state unreadable: %s", e)
        return []


def monitor() -> dict:
    """One full pass: detect, open, close. Returns the report.

    Idempotent by construction — the partial unique index of `sensor_outages`
    forbids two open outages for the same (agent, sensor), so two concurrent
    passes cannot open two cases.
    """
    opened, closed = [], []
    channel = config.WATCHDOG_IRIS_CHANNEL
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        horizon, lag = ingest_horizon(conn)
        # Ingestion stopped: every sensor will look silent at the same instant.
        # That is not a sensor outage, it is a pipeline outage — we say so and we
        # do not manufacture six files for a single problem.
        if lag is not None and lag > config.WATCHDOG_INGEST_LAG_MAX:
            log.error("INGESTION LAGGING by %s (horizon %s) — sensor watch "
                      "suspended: everything would look silent.",
                      _duration(lag), horizon)
            # The disk stays watched: it is not derived from the ingested
            # alerts, and stopped ingestion is precisely what a full disk
            # produces. Staying quiet here means staying quiet at the only moment
            # that counts.
            # Archiving is watched for the same reason as the disk: its state is
            # not derived from the ingested alerts, and an ISM purge keeps
            # running while ingestion is stopped. Staying quiet here means
            # letting data go without a copy.
            silent = disk_saturated() + _archiving(conn)
            ingest_ok = False
        else:
            ingest_ok = True
            # The SOC disk enters the same list as the silent sensors: same
            # state, same channel, same automatic closure (see disk_saturated).
            silent = (silent_sensors(conn) + disk_saturated() + _routing()
                     + _archiving(conn))
        seen = {(m["agent_id"], m["sensor"]) for m in silent}
        # OS known to the CMDB, to type the IRIS asset. A single query, and its
        # absence blocks nothing: `_type_asset` has a default.
        oses = {a["agent_id"]: a["os"] for a in conn.execute(
            "SELECT agent_id, os FROM assets").fetchall()}

        for m in silent:
            minutes = _minutes(m["last"], m["horizon"])
            if _is_routing(m["sensor"]):
                log.warning("ROUTING ANOMALY: %s", m["title"])
            elif _is_archiving(m["sensor"]):
                log.error("ARCHIVING: %s", m["title"])
            elif m["sensor"] == SENSOR_DISK:
                log.error(
                    "DISK SATURATED: %s at %d%% on %s (%.1f GB free, threshold "
                    "%d%%). A full disk stops ingestion without any alert saying "
                    "so.", config.DISK_MONITORED, m["pct"], m["agent_name"],
                    m["free_gb"], m["threshold"])
            else:
                log.warning(
                    "SILENT SENSOR: '%s' on %s (agent %s) — %d reference "
                    "events, nothing since %s (%s). Blind spot: the rules backed "
                    "by this sensor are inert.",
                    m["sensor"], m["agent_name"] or "?", m["agent_id"],
                    m["volume"], m["last"], _duration(minutes))
            r = conn.execute(
                """INSERT INTO sensor_outages
                       (agent_id, agent_name, sensor, last_event,
                        volume_ref, threshold_minutes)
                   VALUES (%s, %s, %s, %s, %s, %s)
                   ON CONFLICT (agent_id, sensor) WHERE status = 'open'
                   DO NOTHING
                   RETURNING id""",
                (m["agent_id"], m["agent_name"], m["sensor"], m["last"],
                 m["volume"], m["threshold"])).fetchone()
            conn.commit()
            if not r:
                continue  # outage already open: nothing to do
            trace_id, column = None, None
            if channel != "off":
                column = ("iris_alert_id" if channel == "alert"
                           else "iris_case_id")
                try:
                    trace_id = (_open_alert({**m, "os": oses.get(m["agent_id"])},
                                               minutes)
                                if channel == "alert"
                                else _open_case(m, minutes))
                except Exception as e:  # noqa: BLE001 — IRIS never blocks
                    log.warning("IRIS record (%s) not created (%s/%s): %s",
                                channel, m["agent_id"], m["sensor"], e)
            if trace_id:
                conn.execute(
                    f"UPDATE sensor_outages SET {column}=%s WHERE id=%s",
                    (trace_id, r["id"]))
                conn.commit()
            log.error("OUTAGE OPENED: %s on %s — IRIS %s %s",
                      m["sensor"], m["agent_name"] or m["agent_id"], channel,
                      trace_id or "not created")
            opened.append({**m, "iris_case_id": trace_id if channel == "case"
                             else None,
                             "iris_alert_id": trace_id if channel == "alert"
                             else None})

        for p in conn.execute(
                "SELECT * FROM sensor_outages WHERE status='open'").fetchall():
            if (p["agent_id"], p["sensor"]) in seen:
                continue
            # Ingestion lagging: `silent_sensors` did not run, so the absence
            # of a sensor from `seen` proves NOTHING. Closing it here would
            # announce a recovery we did not observe. Only the disk, measured
            # outside the pipeline, can close in that state.
            if not ingest_ok and not (p["sensor"] == SENSOR_DISK
                                      or _is_archiving(p["sensor"])):
                continue
            outside_horizon = _outside_pipeline(p["sensor"])
            # The disk is measured against the CLOCK, not against the ingestion
            # horizon: it is not derived from the ingested alerts. Measuring its
            # saturation against a lagging horizon gave a negative duration
            # ("-2 min") in the recovery alert.
            minutes = _minutes(p["last_event"],
                               None if outside_horizon else horizon)
            # We close in the channel where the outage was OPENED, read from
            # the row and never from the current configuration: switching `case`
            # -> `alert` must not abandon the cases already open.
            #
            # `off` attempts nothing: it is precisely the setting used when IRIS
            # is unavailable, and failing here would block the move to
            # "recovered" forever.
            try:
                if channel == "off":
                    pass
                elif p["iris_alert_id"]:
                    _close_alert(p["iris_alert_id"], p, minutes)
                elif p["iris_case_id"]:
                    _close_case(p["iris_case_id"], p, minutes)
            except Exception as e:  # noqa: BLE001
                # We leave the outage OPEN in database to retry next round.
                # Marking it recovered here while the file stays open in IRIS
                # would leave a ghost case nothing ever closes — happened on
                # 2026-08-12, IRIS OOM-killed exactly when debian2 started
                # emitting again.
                log.warning("IRIS closure impossible (%s) — outage %s left open, "
                            "retrying on the next pass", e, p["id"])
                continue
            conn.execute(
                "UPDATE sensor_outages SET status='recovered', recovered_at=now() "
                "WHERE id=%s", (p["id"],))
            conn.commit()
            if _is_routing(p["sensor"]):
                log.info("ROUTING RECOVERED: %s (anomaly open for %s)",
                         p["sensor"], _duration(minutes))
            elif _is_archiving(p["sensor"]):
                log.info("ARCHIVING RECOVERED: %s (anomaly open for %s)",
                         p["sensor"], _duration(minutes))
            elif p["sensor"] == SENSOR_DISK:
                log.info("DISK BACK BELOW THRESHOLD: %s on %s (saturated for "
                         "%s, peak at %d%%)", config.DISK_MONITORED,
                         p["agent_name"] or p["agent_id"], _duration(minutes),
                         p["volume_ref"])
            else:
                log.info("SENSOR RECOVERED: %s on %s (silence %s)",
                         p["sensor"], p["agent_name"] or p["agent_id"],
                         _duration(minutes))
            closed.append(p)

    return {"silent": silent, "opened": opened, "closed": closed,
            **({} if ingest_ok else {"ingest_lag": lag})}


def check() -> list[dict]:
    """Called by the cycle. Read-only plus logs: state management and the IRIS
    cases belong to the dedicated service (`--monitor`), which runs at its own
    pace — a silent sensor must be seen in minutes, not at the rhythm of the
    triage cycle."""
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        silent = silent_sensors(conn)
    for m in silent:
        log.warning(
            "SILENT SENSOR: '%s' on %s (agent %s) — %d reference events, "
            "nothing since %s. Blind spot: the rules backed by this sensor are "
            "inert.", m["sensor"], m["agent_name"] or "?", m["agent_id"],
            m["volume"], m["last"])
    # The disk is measured here too: the cycle runs every 5 minutes and IT is
    # what will stop first if the disk fills up. Read-only, like the rest of
    # `check` — the alert belongs to `monitor`.
    for d in disk_saturated():
        log.error("DISK SATURATED: %s at %d%% (%.1f GB free, threshold %d%%)",
                  config.DISK_MONITORED, d["pct"], d["free_gb"], d["threshold"])
    return silent


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--monitor", action="store_true",
                   help="open/close the outages and their IRIS records")
    args = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.monitor:
        r = monitor()
        print(f"{len(r['silent'])} silent sensor(s), "
              f"{len(r['opened'])} outage(s) opened, "
              f"{len(r['closed'])} recovered")
        return

    silent = check()
    if not silent:
        print("No silent sensor.")
        return
    print(f"{len(silent)} silent sensor(s):")
    for m in silent:
        print(f"  {m['agent_name'] or '?':<20} {m['sensor']:<14} "
              f"silent since {m['last']:%Y-%m-%d %H:%M} "
              f"({m['volume']} reference events, threshold {m['threshold']} min)")


if __name__ == "__main__":
    main()
