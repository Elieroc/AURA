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
import json
import re
from datetime import timedelta

import psycopg
from psycopg.rows import dict_row

from . import assets, config

# Groupes présents sur la moitié des règles Wazuh : les retenir comme point
# commun fusionnerait des alertes sans aucun rapport entre elles.
GROUPS_GENERIC = {
    "syscheck", "ossec", "linux", "windows", "syslog", "authentication_failed",
    "pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc", "gpg13",
}

# Groupes qui ne caractérisent JAMAIS une intrusion à eux seuls : posture de
# conformité (SCA/CIS), vérif d'intégrité de l'hôte (rootcheck), inventaire de
# vulnérabilités, login réussi. Une alerte purement de ce type ne doit pas
# OUVRIR un incident — même si un passage bas niveau la remonte au-dessus du
# seuil de graine. Elle reste éligible comme alerte RATTACHÉE (contexte d'une
# intrusion réelle : un login réussi au milieu d'un reverse shell compte).
GROUPS_NON_SEED = {
    "sca", "rootcheck", "vulnerability-detector", "cis",
    "authentication_success", "policy_monitoring",
}
# Changements d'état d'un agent Wazuh (connecté/démarré/arrêté/déconnecté) :
# opérationnel, jamais une graine d'incident. Repéré sur la description, les
# groupes de ces règles étant trop génériques (« ossec ») pour discriminer.
_RE_STATUS_AGENT = re.compile(
    r"\bagent (?:connected|started|stopped|disconnected|removed|restarted)\b",
    re.I)

# Exception à _RE_STATUT_AGENT : nos règles d'auto-surveillance (100803/100804)
# décrivent le MÊME événement, mais volontairement comme une altération possible
# du SOC (T1562.001) — arrêter l'agent est la première action d'un attaquant qui
# a obtenu root. Elles doivent pouvoir amorcer un incident.
# Le filtre ci-dessus est écrit en anglais parce qu'il vise les descriptions du
# ruleset natif ; depuis que nos règles locales sont elles aussi en anglais, il
# les capturait par effet de bord et les rendait inaptes à ouvrir un case, sans
# rien signaler. D'où cette liste explicite, par identifiant et non par texte.
SIDS_STATUS_AGENT_SEED = {"100803", "100804"}


def _is_valid_seed(a: dict) -> bool:
    """Une alerte peut-elle OUVRIR un incident (être une graine) ?

    Faux pour le bruit structurel (SCA/CIS, rootcheck, inventaire de vulns,
    login réussi, statut d'agent) : ces alertes ne sont pas des intrusions,
    elles ne doivent pas fonder un case. Elles restent rattachables à un
    incident réel voisin (contexte), mais ne l'amorcent pas.
    """
    if set(a.get("rule_groups") or []) & GROUPS_NON_SEED:
        return False
    if (str(a.get("rule_id")) not in SIDS_STATUS_AGENT_SEED
            and _RE_STATUS_AGENT.search(a.get("rule_desc") or "")):
        return False
    return True

# Binaires shell omniprésents : les retenir comme « même objet » fusionnerait
# deux intrusions distinctes (ou une intrusion et de l'activité shell normale)
# sur le simple fait qu'elles passent toutes par bash. L'uid et les vrais objets
# (fichiers déposés, IP) restent des liens valides.
ENTITIES_GENERIC = {
    "/usr/bin/bash", "/bin/bash", "/usr/bin/sh", "/bin/sh",
    "/usr/bin/dash", "/bin/dash",
}

# Exécutables trop communs pour lier deux alertes ou fusionner deux hôtes : un
# rebond d'administration (powershell, cmd, net) ou un shell relierait sinon
# tout le parc. La campagne #4 a fusionné à tort deux hôtes sur
# `...\WindowsPowerShell\v1.0\powershell.exe`. On compare sur le NOM de fichier,
# backslashes doublés de l'eventchannel repliés — un vrai marqueur d'attaquant
# (mimikatz.exe, un compte créé, une IP C2) reste, lui, discriminant.
NAMES_GENERIC = {
    "bash", "sh", "dash", "zsh",
    "powershell.exe", "pwsh.exe", "cmd.exe", "conhost.exe", "net.exe",
    "net1.exe", "wsmprovhost.exe", "svchost.exe", "explorer.exe",
    "rundll32.exe", "wmiprvse.exe", "reg.exe", "dllhost.exe",
}


def generic_entity(entity: str | None) -> bool:
    """Vrai si l'entité est trop générique pour lier/fusionner (basename)."""
    if not entity:
        return True
    e = entity.replace("\\\\", "\\").replace("\\", "/").lower().rstrip("/")
    if e in ENTITIES_GENERIC:
        return True
    return e.rsplit("/", 1)[-1] in NAMES_GENERIC


def common_ground(a: dict, b: dict) -> tuple[str, bool] | None:
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
    # Même signal UEBA : le lien le plus fort du lot, et le premier examiné. Le
    # moteur comportemental a DÉJÀ tranché que ces alertes forment un tout ; les
    # laisser se redécouper ici sur les critères génériques les émiette. Mesuré
    # à la mise en service : un signal de 239 alertes ressortait en 8 incidents,
    # donc 8 triages LLM au lieu d'un, chacun amputé du contexte des autres et
    # portant un score sans rapport avec celui du signal (115, puis 2,5 et 3,3).
    # Les fenêtres se correspondent déjà : UEBA_SIGNAL_MAX_HEURES = 6 =
    # MAX_INCIDENT_HOURS, et le lien fort porte jusqu'à ENTITY_GAP_MINUTES.
    if a.get("ueba_signal_id") and a["ueba_signal_id"] == b.get("ueba_signal_id"):
        return "même signal UEBA", True
    if a["srcip"] and a["srcip"] == b["srcip"]:
        return "même IP source", True
    if (a["entity"] and a["entity"] == b["entity"]
            and not generic_entity(a["entity"])):
        return "même objet", True
    if a["srcuser"] and a["srcuser"] == b["srcuser"]:
        return "même compte", True
    if a["mitre_tactics"] and set(a["mitre_tactics"]) & set(b["mitre_tactics"]):
        return "tactique MITRE", False
    common = (set(a["rule_groups"]) & set(b["rule_groups"])) - GROUPS_GENERIC
    if common:
        return f"groupe {sorted(common)[0]}", False
    return None


SELECT_NON_ATTACHED = """
SELECT id, ts, agent_id, agent_name, container, rule_id, rule_level, rule_desc,
       rule_groups, mitre_tactics, srcip, srcuser, entity, audit_uid,
       ueba_seed, ueba_score, ueba_traits, ueba_signal_id
  FROM alerts
 WHERE incident_id IS NULL AND NOT suppressed
   AND (rule_level >= %s OR ueba_seed)
 ORDER BY agent_id, ts, id
"""

# Incidents encore « ouvrables » d'un agent : leur dernière alerte n'est pas
# trop ancienne pour accueillir une nouvelle salve. On charge aussi leurs
# agrégats, mis à jour en Python au rattachement.
SELECT_INCIDENTS_OPENABLE = """
SELECT id, agent_id, first_seen, last_seen, alert_count, max_level,
       rule_ids, mitre_tactics, entities, priority
  FROM incidents
 WHERE agent_id = ANY(%s) AND last_seen >= %s
 ORDER BY last_seen DESC
"""

# Membres d'un incident ouvrable, BORNÉS aux MEMBRES_RECENTS derniers de chaque
# incident. `_rattacher` ne regarde de toute façon que la queue (`membres[-20:]`)
# pour chercher un point commun, et la date de DÉBUT vient de l'incident
# (`first_seen`), pas de la première ligne chargée.
#
# Sans cette borne, chaque cycle relisait TOUTES les alertes de chaque incident
# ouvrable — 126 508 lignes pour un seul incident pfSense le 2026-08-14, toutes
# les 5 minutes, pour n'en exploiter que 20.
MEMBERS_RECENT = 50

SELECT_MEMBERS = """
SELECT id, ts, agent_id, rule_id, rule_level, rule_groups, mitre_tactics,
       srcip, srcuser, entity, audit_uid, incident_id, ueba_signal_id
  FROM (SELECT *, row_number() OVER (PARTITION BY incident_id
                                         ORDER BY ts DESC, id DESC) rang
          FROM alerts WHERE incident_id = ANY(%s)) t
 WHERE rang <= %s
 ORDER BY ts
"""

INSERT_INCIDENT = """
INSERT INTO incidents (agent_id, agent_name, first_seen, last_seen,
                       alert_count, max_level, rule_ids, mitre_tactics, entities,
                       ueba, ueba_score, ueba_patterns, priority, severity,
                       asset_role)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
RETURNING id
"""


def _group(alerts: list[dict]) -> list[list[dict]]:
    """Chaîne les alertes en incidents. Fonction pure, donc testable seule."""
    small_gap = timedelta(minutes=config.CORRELATION_GAP_MINUTES)
    large_gap = timedelta(minutes=config.ENTITY_GAP_MINUTES)
    max_duration = timedelta(hours=config.MAX_INCIDENT_HOURS)

    incidents: list[list[dict]] = []

    # PLUSIEURS incidents ouverts simultanément par agent, et non un seul.
    # Avec un seul, une alerte sans rapport qui s'intercale referme l'incident
    # en cours : deux alertes de la même IP hostile séparées par un événement
    # étranger repartaient dans deux incidents distincts. Sur un hôte actif,
    # l'entrelacement est le cas normal, pas l'exception.
    #
    # Les agents restent cloisonnés : une alerte sur un endpoint n'a pas à
    # rejoindre un incident d'un autre agent.
    open_incidents: dict[str, list[list[dict]]] = {}
    max_window = max(large_gap, small_gap)

    for a in alerts:
        groups = open_incidents.setdefault(a["agent_id"], [])

        # Fermeture des incidents hors d'atteinte. Les alertes étant triées par
        # date, ils ne pourront plus rien accueillir.
        groups[:] = [
            g for g in groups
            if a["ts"] - g[-1]["ts"] <= max_window
            and a["ts"] - g[0]["ts"] <= max_duration
        ]

        target = None
        for g in groups:
            since_last = a["ts"] - g[-1]["ts"]
            # On ne compare qu'aux 20 dernières : au-delà le coût devient
            # quadratique sans rien changer, le chaînage étant de proche en
            # proche.
            for member in g[-20:]:
                link = common_ground(a, member)
                if link is None:
                    continue
                _, high = link
                if since_last <= (large_gap if high else small_gap):
                    target = g
                    break
            if target is not None:
                break

        if target is None:
            target = []
            groups.append(target)
            incidents.append(target)
        target.append(a)

    return incidents


def _uids_incident(inc: list[dict]) -> set[str]:
    """UID auditd sous lesquels la graine de l'incident a tiré.

    C'est l'uid du compte compromis. Une privesc par SUID garde l'uid réel du
    compte (seul l'euid passe à 0), donc les actions root de l'attaquant restent
    taguées à cet uid. On écarte root (0) si un compte non-root est présent :
    garder 0 ferait rentrer tous les démons root et le bruit système.
    """
    uids = {str(m["audit_uid"]) for m in inc if m.get("audit_uid") is not None}
    non_root = uids - {"0"}
    return non_root or uids


def _enrich(incidents: list[list[dict]], candidates: list[dict]) -> int:
    """Rattache les alertes de sévérité intermédiaire aux incidents formés.

    Une graine HIGH a déjà confirmé l'incident ; on lui recolle les alertes
    du même agent qui appartiennent RÉELLEMENT à la même intrusion — sinon le
    reverse shell est vu seul et la privesc/persistence restent invisibles.

    Le rattachement exige un lien réel, jamais la seule coïncidence temporelle
    (qui aspirerait le bruit légitime de l'hôte — démons, sessions de login,
    activité admin). Deux titres, dans la fenêtre temporelle :
      - MÊME UID auditd que la graine : le compte compromis et ses descendants
        (privesc SUID compris) exécutent sous cet uid ; c'est ce qui isole
        l'énumération/exploitation (audit niv. 3) du bruit de fond ;
      - POINT COMMUN nommable avec un membre (même IP/objet/compte/tactique),
        qui étend la portée à la fenêtre forte (une IP hostile qui revient des
        heures plus tard reste le même incident).

    Une candidate sans lien reste non rattachée : le case ne contient que les
    alertes de l'intrusion, pas les faux positifs légitimes de la machine.
    """
    small_gap = timedelta(minutes=config.CORRELATION_GAP_MINUTES)
    large_gap = timedelta(minutes=config.ENTITY_GAP_MINUTES)
    attached = 0
    uids_by_inc = [_uids_incident(inc) for inc in incidents]

    for c in candidates:
        best = None
        best_dist = None
        for inc, uids in zip(incidents, uids_by_inc):
            if inc[0]["agent_id"] != c["agent_id"]:
                continue
            start = min(m["ts"] for m in inc)
            end = max(m["ts"] for m in inc)
            in_window = (start - small_gap) <= c["ts"] <= (end + small_gap)

            title = False
            # Lien par uid : dans la fenêtre et même compte compromis.
            if (in_window and uids and c.get("audit_uid") is not None
                    and str(c["audit_uid"]) in uids):
                title = True
            # Lien par IDENTITÉ FORTE seulement (même IP source, ou même objet
            # concret non générique — fichier déposé). On EXCLUT ici les liens
            # faibles (tactique MITRE, groupe de règle) et le compte : ils
            # chaînent l'activité légitime de l'hôte (sessions sudo de l'admin,
            # règles partageant « Privilege Escalation »…) dans l'incident. Le
            # case ne doit contenir que l'intrusion, pas les FP de la machine.
            if not title and min(abs(c["ts"] - start),
                                 abs(c["ts"] - end)) <= large_gap:
                for member in inc:
                    meme_ip = c["srcip"] and c["srcip"] == member["srcip"]
                    same_object = (c["entity"] and c["entity"] == member["entity"]
                                  and not generic_entity(c["entity"]))
                    if meme_ip or same_object:
                        title = True
                        break
            if not title:
                continue

            # Départage : l'incident temporellement le plus proche.
            if start <= c["ts"] <= end:
                dist = timedelta(0)
            else:
                dist = min(abs(c["ts"] - start), abs(c["ts"] - end))
            if best_dist is None or dist < best_dist:
                best, best_dist = inc, dist

        if best is not None:
            best.append(c)
            attached += 1

    return attached


def _attach_existing(conn, alerts: list[dict]) -> tuple[list[dict], dict[int, list[dict]]]:
    """Recolle les alertes non rattachées aux incidents DÉJÀ en base.

    C'est le correctif du doublon de case. Le cycle tourne toutes les 5 min et
    ne voit à chaque tour que les alertes fraîchement ingérées : sans ce
    rattrapage, chaque salve d'une intrusion EN COURS rouvre un incident neuf,
    donc un case IRIS de plus — neuf cases « reverse shell » pour une seule
    attaque. On rattache donc d'abord chaque nouvelle alerte à un incident
    récent du même agent, avec EXACTEMENT les règles de proximité de `_grouper`
    (le seul écart entre les deux, c'était la frontière de lot).

    Retourne (restantes, {incident_id: [alertes ajoutées]}, {incident_id: inc}).
    Ne persiste rien : l'appelant écrit dans la même transaction que le reste.
    """
    if not alerts:
        return alerts, {}, {}

    small_gap = timedelta(minutes=config.CORRELATION_GAP_MINUTES)
    large_gap = timedelta(minutes=config.ENTITY_GAP_MINUTES)
    max_duration = timedelta(hours=config.MAX_INCIDENT_HOURS)
    max_window = max(large_gap, small_gap)

    agents = list({a["agent_id"] for a in alerts})
    ts_min = min(a["ts"] for a in alerts)
    incs = conn.execute(SELECT_INCIDENTS_OPENABLE,
                        (agents, ts_min - max_window)).fetchall()
    incs_by_id = {i["id"]: i for i in incs}
    if not incs:
        return alerts, {}, incs_by_id

    members = conn.execute(SELECT_MEMBERS,
                           ([i["id"] for i in incs], MEMBERS_RECENT)).fetchall()
    by_inc: dict[int, dict] = {i["id"]: {"inc": i, "membres": []} for i in incs}
    for m in members:
        by_inc[m["incident_id"]]["membres"].append(m)

    remaining: list[dict] = []
    additions: dict[int, list[dict]] = {}
    # Ordre chronologique : une alerte rattachée devient membre pour la
    # suivante, ce qui chaîne une salve de proche en proche à travers le lot.
    for a in sorted(alerts, key=lambda x: (x["ts"], x["id"])):
        target = None
        target_dist = None
        for iid, e in by_inc.items():
            if e["inc"]["agent_id"] != a["agent_id"] or not e["membres"]:
                continue
            # Début lu sur l'INCIDENT, pas sur la première ligne chargée : les
            # membres sont bornés aux plus récents (cf. SELECT_MEMBRES), leur
            # tête n'est donc plus le début de l'incident.
            start = e["inc"]["first_seen"]
            last = e["membres"][-1]["ts"]
            if a["ts"] - start > max_duration:
                continue
            since = abs(a["ts"] - last)
            for m in e["membres"][-20:]:
                link = common_ground(a, m)
                if link is None:
                    continue
                _, high = link
                if since <= (large_gap if high else small_gap):
                    if target_dist is None or since < target_dist:
                        target, target_dist = iid, since
                    break
        if target is None:
            remaining.append(a)
        else:
            by_inc[target]["membres"].append(a)
            additions.setdefault(target, []).append(a)

    return remaining, additions, incs_by_id


def _signal_decisive(old_rules: set, new: list[dict],
                    max_old: int) -> bool:
    """Une salve rattachée apporte-t-elle un signal décisif nouveau ?

    Vrai si le niveau max monte, OU si une règle inédite NON structurelle
    apparaît. Faux pour une répétition de bruit (mêmes règles déjà présentes,
    ou alertes structurelles SCA/rootcheck/statut d'agent — cf. _graine_valide) :
    ne re-déclenche alors PAS le triage + le rapport LLM (correctif #2, boucle
    de régénération à l'origine de l'explosion de tokens du 2026-07-30)."""
    if max([max_old] + [a["rule_level"] for a in new]) > max_old:
        return True
    return any(a["rule_id"] not in old_rules and _is_valid_seed(a)
               for a in new)


def _apply_additions(conn, incs_by_id: dict[int, dict],
                      additions: dict[int, list[dict]]) -> None:
    """Persiste les rattachements aux incidents existants et pose needs_refresh.

    Met à jour les agrégats de l'incident (fenêtre, compte, niveau max, unions
    de règles/tactiques/objets). `needs_refresh` n'est posé que si la salve
    apporte un SIGNAL DÉCISIF NOUVEAU (correctif #2, explosion tokens du
    2026-07-30) : une règle inédite NON structurelle, ou une hausse du niveau
    max. Une répétition de bruit (mêmes règles, ou alertes structurelles
    SCA/rootcheck/statut d'agent) ne re-déclenche PLUS triage + rapport LLM —
    c'était la boucle qui régénérait le rapport à vide à chaque cycle (5 min).
    On ne rétrograde jamais un refresh déjà en attente (`OR` en SQL).
    """
    for iid, new in additions.items():
        inc = incs_by_id[iid]
        conn.execute("UPDATE alerts SET incident_id = %s WHERE id = ANY(%s)",
                     (iid, [a["id"] for a in new]))
        old_rules = set(inc["rule_ids"])
        rules = sorted(old_rules | {a["rule_id"] for a in new})
        tacs = sorted(set(inc["mitre_tactics"])
                      | {t for a in new for t in (a["mitre_tactics"] or [])})
        ents = sorted(set(inc["entities"])
                      | {a["entity"] for a in new if a["entity"]})[:50]
        new_max = max([inc["max_level"]] + [a["rule_level"] for a in new])
        signal = _signal_decisive(old_rules, new, inc["max_level"])
        # La priorité de l'incident ne bouge PAS (elle est celle de l'asset au
        # moment de l'ouverture, cf. schema.sql) ; la sévérité, si — elle suit
        # le niveau max. Priorité absente sur les incidents antérieurs à la
        # CMDB : on retombe sur le défaut plutôt que d'écrire NULL.
        priority = inc.get("priority") or config.DEFAULT_PRIORITY
        conn.execute(
            "UPDATE incidents SET last_seen = %s, first_seen = %s, "
            "alert_count = alert_count + %s, max_level = %s, rule_ids = %s, "
            "mitre_tactics = %s, entities = %s, severite = %s, "
            "needs_refresh = needs_refresh OR %s WHERE id = %s",
            (max([inc["last_seen"]] + [a["ts"] for a in new]),
             min([inc["first_seen"]] + [a["ts"] for a in new]),
             len(new), new_max,
             rules, tacs, ents, assets.severity(new_max, priority),
             signal, iid))


def correlate(min_level: int, attach_min_level: int | None = None) -> tuple[int, int]:
    if attach_min_level is None:
        attach_min_level = config.ATTACH_MIN_LEVEL
    # On ne peut rattacher qu'en dessous du seuil de graine ; au-dessus,
    # l'alerte est déjà une graine à part entière.
    floor = min(attach_min_level, min_level) if attach_min_level else min_level

    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        alerts = conn.execute(SELECT_NON_ATTACHED, (floor,)).fetchall()
        if not alerts:
            return 0, 0

        # 1) Rattrapage : recoller aux incidents déjà en base (anti-doublon de
        # case). Ce qui reste sera groupé en incidents neufs ci-dessous.
        alerts, additions, incs_by_id = _attach_existing(conn, alerts)
        _apply_additions(conn, incs_by_id, additions)

        # 2) Nouveaux incidents à partir du reste. Le bruit structurel
        # (SCA/rootcheck/statut d'agent/login réussi) ne peut PAS être une
        # graine, même remonté au-dessus du seuil : il n'ouvre pas de case.
        # Deux titres pour être graine : le niveau Wazuh (>= min_level), ou la
        # promotion par le moteur UEBA (`ueba_seed`, posé par ueba.evaluer sur
        # une concentration comportementale anormale). Le filtre structurel
        # `_graine_valide` s'applique aux DEUX : un SCA ou un statut d'agent ne
        # fonde pas un case, même statistiquement rare.
        seed_ids = {a["id"] for a in alerts
                       if (a["rule_level"] >= min_level or a.get("ueba_seed"))
                       and _is_valid_seed(a)}
        seeds = [a for a in alerts if a["id"] in seed_ids]
        candidates = [a for a in alerts if a["id"] not in seed_ids]

        incidents = _group(seeds)
        if candidates and incidents:
            _enrich(incidents, candidates)

        # Une seule transaction : en cas d'échec, les alertes restent
        # simplement non rattachées et un nouveau passage reprend le travail.
        created: list[list[dict]] = []
        for group in incidents:
            tactics = sorted({t for a in group for t in a["mitre_tactics"]})
            entities = sorted({a["entity"] for a in group if a["entity"]})
            # min/max explicites : l'enrichissement ajoute des membres en fin
            # de liste sans garantie d'ordre chronologique.
            # Origine UEBA : l'incident n'a pas été ouvert par une règle de
            # niveau >= 12 mais par un score comportemental. Le triage doit le
            # savoir (son max_level est bas, il serait autrement hors du lot),
            # le prompt doit l'expliquer, et la remédiation autonome est bornée
            # dessus (UEBA_MITIGATE).
            # Le score et les motifs sont recalculés par la MÊME fonction que
            # celle du moteur (`ueba.scorer_groupe`) et non ré-agrégés ici : le
            # découpage de correlate n'est pas celui du signal, et deux formules
            # pour la même grandeur finiraient par diverger — l'incident
            # afficherait un score que rien ne permettrait de relier à celui du
            # signal d'origine. Import différé : ueba n'a pas besoin de
            # correlate, mais on garde le module chargeable sans lui.
            ueba_alerts = [a for a in group if a.get("ueba_seed")]
            score_ueba, patterns = (0.0, [])
            if ueba_alerts:
                from . import ueba as _ueba
                score_ueba, patterns = _ueba.score_group(ueba_alerts)

            # Plancher de score sur l'INCIDENT, et pas seulement sur le signal.
            # Le moteur UEBA promeut un signal entier ; le découpage d'ici peut
            # en détacher un fragment dont le score propre n'a plus rien à voir
            # avec celui qui a justifié la promotion. Sans ce garde-fou, un
            # fragment de 2 alertes à 3,3 bits ouvrait un incident, un triage
            # LLM et un case IRIS complets — c'est l'origine du case #192
            # (« PHANTOM ALERT », planification du service Software Protection).
            #
            # Ne s'applique qu'aux groupes fondés UNIQUEMENT par UEBA : dès
            # qu'une alerte de niveau >= min_level est présente, l'incident
            # tient par son propre titre et le score comportemental n'est plus
            # qu'un enrichissement.
            #
            # Les alertes écartées perdent `ueba_seed` : sans ça elles restent
            # éligibles comme graine à CHAQUE cycle (SELECT_NON_RATTACHEES lit
            # `rule_level >= plancher OR ueba_seed`) et le même groupe se
            # représente indéfiniment. Elles gardent `ueba_signal_id`, qui est
            # ce sur quoi `ueba.SELECT_CANDIDATES` s'appuie pour ne jamais les
            # repromouvoir : consommées par le budget une fois, pour de bon.
            if (ueba_alerts and score_ueba < config.UEBA_SCORE_FLOOR
                    and max(a["rule_level"] for a in group) < min_level):
                conn.execute(
                    "UPDATE alerts SET ueba_seed = false WHERE id = ANY(%s)",
                    ([a["id"] for a in ueba_alerts],))
                print(f"  UEBA : groupe de {len(group)} alertes écarté "
                      f"(score {score_ueba:.1f} < plancher "
                      f"{config.UEBA_SCORE_FLOOR:.0f}) — pas d'incident")
                continue

            # Priorité de l'asset touché. Le conteneur d'origine prime sur
            # l'agent quand l'alerte vient d'un capteur d'hôte : c'est le LXC
            # qui est la vraie machine, pas l'hyperviseur qui l'observe (cf.
            # assets.priorite_agent).
            max_level = max(a["rule_level"] for a in group)
            container = next((a.get("container") for a in group
                              if a.get("container")), None)
            prio = assets.agent_priority(conn, group[0]["agent_id"], container)

            inc_id = conn.execute(INSERT_INCIDENT, (
                group[0]["agent_id"],
                group[0]["agent_name"],
                min(a["ts"] for a in group),
                max(a["ts"] for a in group),
                len(group),
                max_level,
                sorted({a["rule_id"] for a in group}),
                tactics,
                entities[:50],   # bornage : un ransomware touche des milliers de fichiers
                bool(ueba_alerts),
                round(score_ueba, 2) or None,
                json.dumps(patterns, ensure_ascii=False) if patterns else None,
                prio["priority"],
                assets.severity(max_level, prio["priority"]),
                # Le rôle TEL QU'IL A COMPTÉ, et pas celui de la CMDB : sur un
                # capteur, la priorité est rabattue et le rôle vaut « capteur ».
                prio["role"],
            )).fetchone()["id"]

            conn.execute(
                "UPDATE alerts SET incident_id = %s WHERE id = ANY(%s)",
                (inc_id, [a["id"] for a in group]),
            )
            created.append(group)
        conn.commit()

    attached = sum(len(v) for v in additions.values())
    correlated = sum(len(g) for g in created) + attached
    return len(created), correlated


def restart() -> None:
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
        orphans = conn.execute(
            "SELECT count(*) FROM incidents WHERE iris_case_id IS NOT NULL"
        ).fetchone()[0]
        if orphans:
            print(f"ATTENTION : {orphans} incident(s) ont un case IRIS. Les "
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

    if args.restart:
        restart()

    n_inc, n_alerts = correlate(args.min_level, args.attach_min_level)
    if n_alerts and n_inc:
        print(f"{n_alerts} alertes -> {n_inc} incidents neufs "
              f"(facteur {n_alerts / n_inc:.1f}), rattachements aux existants inclus")
    elif n_alerts:
        print(f"{n_alerts} alertes rattachées à des incidents existants, "
              "aucun incident neuf.")
    else:
        print("Aucune alerte à corréler.")


if __name__ == "__main__":
    main()
