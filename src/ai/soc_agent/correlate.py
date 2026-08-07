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

from . import config

# Groupes présents sur la moitié des règles Wazuh : les retenir comme point
# commun fusionnerait des alertes sans aucun rapport entre elles.
GROUPES_GENERIQUES = {
    "syscheck", "ossec", "linux", "windows", "syslog", "authentication_failed",
    "pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc", "gpg13",
}

# Groupes qui ne caractérisent JAMAIS une intrusion à eux seuls : posture de
# conformité (SCA/CIS), vérif d'intégrité de l'hôte (rootcheck), inventaire de
# vulnérabilités, login réussi. Une alerte purement de ce type ne doit pas
# OUVRIR un incident — même si un passage bas niveau la remonte au-dessus du
# seuil de graine. Elle reste éligible comme alerte RATTACHÉE (contexte d'une
# intrusion réelle : un login réussi au milieu d'un reverse shell compte).
GROUPES_NON_GRAINE = {
    "sca", "rootcheck", "vulnerability-detector", "cis",
    "authentication_success", "policy_monitoring",
}
# Changements d'état d'un agent Wazuh (connecté/démarré/arrêté/déconnecté) :
# opérationnel, jamais une graine d'incident. Repéré sur la description, les
# groupes de ces règles étant trop génériques (« ossec ») pour discriminer.
_RE_STATUT_AGENT = re.compile(
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
SIDS_STATUT_AGENT_GRAINE = {"100803", "100804"}


def _graine_valide(a: dict) -> bool:
    """Une alerte peut-elle OUVRIR un incident (être une graine) ?

    Faux pour le bruit structurel (SCA/CIS, rootcheck, inventaire de vulns,
    login réussi, statut d'agent) : ces alertes ne sont pas des intrusions,
    elles ne doivent pas fonder un case. Elles restent rattachables à un
    incident réel voisin (contexte), mais ne l'amorcent pas.
    """
    if set(a.get("rule_groups") or []) & GROUPES_NON_GRAINE:
        return False
    if (str(a.get("rule_id")) not in SIDS_STATUT_AGENT_GRAINE
            and _RE_STATUT_AGENT.search(a.get("rule_desc") or "")):
        return False
    return True

# Binaires shell omniprésents : les retenir comme « même objet » fusionnerait
# deux intrusions distinctes (ou une intrusion et de l'activité shell normale)
# sur le simple fait qu'elles passent toutes par bash. L'uid et les vrais objets
# (fichiers déposés, IP) restent des liens valides.
ENTITES_GENERIQUES = {
    "/usr/bin/bash", "/bin/bash", "/usr/bin/sh", "/bin/sh",
    "/usr/bin/dash", "/bin/dash",
}

# Exécutables trop communs pour lier deux alertes ou fusionner deux hôtes : un
# rebond d'administration (powershell, cmd, net) ou un shell relierait sinon
# tout le parc. La campagne #4 a fusionné à tort deux hôtes sur
# `...\WindowsPowerShell\v1.0\powershell.exe`. On compare sur le NOM de fichier,
# backslashes doublés de l'eventchannel repliés — un vrai marqueur d'attaquant
# (mimikatz.exe, un compte créé, une IP C2) reste, lui, discriminant.
NOMS_GENERIQUES = {
    "bash", "sh", "dash", "zsh",
    "powershell.exe", "pwsh.exe", "cmd.exe", "conhost.exe", "net.exe",
    "net1.exe", "wsmprovhost.exe", "svchost.exe", "explorer.exe",
    "rundll32.exe", "wmiprvse.exe", "reg.exe", "dllhost.exe",
}


def entite_generique(entity: str | None) -> bool:
    """Vrai si l'entité est trop générique pour lier/fusionner (basename)."""
    if not entity:
        return True
    e = entity.replace("\\\\", "\\").replace("\\", "/").lower().rstrip("/")
    if e in ENTITES_GENERIQUES:
        return True
    return e.rsplit("/", 1)[-1] in NOMS_GENERIQUES


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
            and not entite_generique(a["entity"])):
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
SELECT id, ts, agent_id, agent_name, rule_id, rule_level, rule_desc,
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
SELECT_INCIDENTS_OUVRABLES = """
SELECT id, agent_id, first_seen, last_seen, alert_count, max_level,
       rule_ids, mitre_tactics, entities
  FROM incidents
 WHERE agent_id = ANY(%s) AND last_seen >= %s
 ORDER BY last_seen DESC
"""

SELECT_MEMBRES = """
SELECT id, ts, agent_id, rule_id, rule_level, rule_groups, mitre_tactics,
       srcip, srcuser, entity, audit_uid, incident_id, ueba_signal_id
  FROM alerts WHERE incident_id = ANY(%s) ORDER BY ts
"""

INSERT_INCIDENT = """
INSERT INTO incidents (agent_id, agent_name, first_seen, last_seen,
                       alert_count, max_level, rule_ids, mitre_tactics, entities,
                       ueba, ueba_score, ueba_motifs)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
    # Les agents restent cloisonnés : une alerte sur un endpoint n'a pas à
    # rejoindre un incident d'un autre agent.
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


def _enrichir(incidents: list[list[dict]], candidats: list[dict]) -> int:
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
    ecart_faible = timedelta(minutes=config.CORRELATION_GAP_MINUTES)
    ecart_fort = timedelta(minutes=config.ENTITY_GAP_MINUTES)
    rattaches = 0
    uids_par_inc = [_uids_incident(inc) for inc in incidents]

    for c in candidats:
        meilleur = None
        meilleur_dist = None
        for inc, uids in zip(incidents, uids_par_inc):
            if inc[0]["agent_id"] != c["agent_id"]:
                continue
            debut = min(m["ts"] for m in inc)
            fin = max(m["ts"] for m in inc)
            dans_fenetre = (debut - ecart_faible) <= c["ts"] <= (fin + ecart_faible)

            titre = False
            # Lien par uid : dans la fenêtre et même compte compromis.
            if (dans_fenetre and uids and c.get("audit_uid") is not None
                    and str(c["audit_uid"]) in uids):
                titre = True
            # Lien par IDENTITÉ FORTE seulement (même IP source, ou même objet
            # concret non générique — fichier déposé). On EXCLUT ici les liens
            # faibles (tactique MITRE, groupe de règle) et le compte : ils
            # chaînent l'activité légitime de l'hôte (sessions sudo de l'admin,
            # règles partageant « Privilege Escalation »…) dans l'incident. Le
            # case ne doit contenir que l'intrusion, pas les FP de la machine.
            if not titre and min(abs(c["ts"] - debut),
                                 abs(c["ts"] - fin)) <= ecart_fort:
                for membre in inc:
                    meme_ip = c["srcip"] and c["srcip"] == membre["srcip"]
                    meme_objet = (c["entity"] and c["entity"] == membre["entity"]
                                  and not entite_generique(c["entity"]))
                    if meme_ip or meme_objet:
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


def _rattacher_existants(conn, alertes: list[dict]) -> tuple[list[dict], dict[int, list[dict]]]:
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
    if not alertes:
        return alertes, {}, {}

    ecart_faible = timedelta(minutes=config.CORRELATION_GAP_MINUTES)
    ecart_fort = timedelta(minutes=config.ENTITY_GAP_MINUTES)
    duree_max = timedelta(hours=config.MAX_INCIDENT_HOURS)
    fenetre_max = max(ecart_fort, ecart_faible)

    agents = list({a["agent_id"] for a in alertes})
    ts_min = min(a["ts"] for a in alertes)
    incs = conn.execute(SELECT_INCIDENTS_OUVRABLES,
                        (agents, ts_min - fenetre_max)).fetchall()
    incs_par_id = {i["id"]: i for i in incs}
    if not incs:
        return alertes, {}, incs_par_id

    membres = conn.execute(SELECT_MEMBRES, ([i["id"] for i in incs],)).fetchall()
    par_inc: dict[int, dict] = {i["id"]: {"inc": i, "membres": []} for i in incs}
    for m in membres:
        par_inc[m["incident_id"]]["membres"].append(m)

    restantes: list[dict] = []
    ajouts: dict[int, list[dict]] = {}
    # Ordre chronologique : une alerte rattachée devient membre pour la
    # suivante, ce qui chaîne une salve de proche en proche à travers le lot.
    for a in sorted(alertes, key=lambda x: (x["ts"], x["id"])):
        cible = None
        cible_dist = None
        for iid, e in par_inc.items():
            if e["inc"]["agent_id"] != a["agent_id"] or not e["membres"]:
                continue
            debut = e["membres"][0]["ts"]
            last = e["membres"][-1]["ts"]
            if a["ts"] - debut > duree_max:
                continue
            depuis = abs(a["ts"] - last)
            for m in e["membres"][-20:]:
                lien = point_commun(a, m)
                if lien is None:
                    continue
                _, fort = lien
                if depuis <= (ecart_fort if fort else ecart_faible):
                    if cible_dist is None or depuis < cible_dist:
                        cible, cible_dist = iid, depuis
                    break
        if cible is None:
            restantes.append(a)
        else:
            par_inc[cible]["membres"].append(a)
            ajouts.setdefault(cible, []).append(a)

    return restantes, ajouts, incs_par_id


def _signal_decisif(anciennes_rules: set, nouvelles: list[dict],
                    ancien_max: int) -> bool:
    """Une salve rattachée apporte-t-elle un signal décisif nouveau ?

    Vrai si le niveau max monte, OU si une règle inédite NON structurelle
    apparaît. Faux pour une répétition de bruit (mêmes règles déjà présentes,
    ou alertes structurelles SCA/rootcheck/statut d'agent — cf. _graine_valide) :
    ne re-déclenche alors PAS le triage + le rapport LLM (correctif #2, boucle
    de régénération à l'origine de l'explosion de tokens du 2026-07-30)."""
    if max([ancien_max] + [a["rule_level"] for a in nouvelles]) > ancien_max:
        return True
    return any(a["rule_id"] not in anciennes_rules and _graine_valide(a)
               for a in nouvelles)


def _appliquer_ajouts(conn, incs_par_id: dict[int, dict],
                      ajouts: dict[int, list[dict]]) -> None:
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
    for iid, nouvelles in ajouts.items():
        inc = incs_par_id[iid]
        conn.execute("UPDATE alerts SET incident_id = %s WHERE id = ANY(%s)",
                     (iid, [a["id"] for a in nouvelles]))
        anciennes_rules = set(inc["rule_ids"])
        rules = sorted(anciennes_rules | {a["rule_id"] for a in nouvelles})
        tacs = sorted(set(inc["mitre_tactics"])
                      | {t for a in nouvelles for t in (a["mitre_tactics"] or [])})
        ents = sorted(set(inc["entities"])
                      | {a["entity"] for a in nouvelles if a["entity"]})[:50]
        new_max = max([inc["max_level"]] + [a["rule_level"] for a in nouvelles])
        signal = _signal_decisif(anciennes_rules, nouvelles, inc["max_level"])
        conn.execute(
            "UPDATE incidents SET last_seen = %s, first_seen = %s, "
            "alert_count = alert_count + %s, max_level = %s, rule_ids = %s, "
            "mitre_tactics = %s, entities = %s, "
            "needs_refresh = needs_refresh OR %s WHERE id = %s",
            (max([inc["last_seen"]] + [a["ts"] for a in nouvelles]),
             min([inc["first_seen"]] + [a["ts"] for a in nouvelles]),
             len(nouvelles), new_max,
             rules, tacs, ents, signal, iid))


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

        # 1) Rattrapage : recoller aux incidents déjà en base (anti-doublon de
        # case). Ce qui reste sera groupé en incidents neufs ci-dessous.
        alertes, ajouts, incs_par_id = _rattacher_existants(conn, alertes)
        _appliquer_ajouts(conn, incs_par_id, ajouts)

        # 2) Nouveaux incidents à partir du reste. Le bruit structurel
        # (SCA/rootcheck/statut d'agent/login réussi) ne peut PAS être une
        # graine, même remonté au-dessus du seuil : il n'ouvre pas de case.
        # Deux titres pour être graine : le niveau Wazuh (>= min_level), ou la
        # promotion par le moteur UEBA (`ueba_seed`, posé par ueba.evaluer sur
        # une concentration comportementale anormale). Le filtre structurel
        # `_graine_valide` s'applique aux DEUX : un SCA ou un statut d'agent ne
        # fonde pas un case, même statistiquement rare.
        graines_ids = {a["id"] for a in alertes
                       if (a["rule_level"] >= min_level or a.get("ueba_seed"))
                       and _graine_valide(a)}
        graines = [a for a in alertes if a["id"] in graines_ids]
        candidats = [a for a in alertes if a["id"] not in graines_ids]

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
            ueba_alertes = [a for a in groupe if a.get("ueba_seed")]
            score_ueba, motifs = (0.0, [])
            if ueba_alertes:
                from . import ueba as _ueba
                score_ueba, motifs = _ueba.scorer_groupe(ueba_alertes)

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
                bool(ueba_alertes),
                round(score_ueba, 2) or None,
                json.dumps(motifs, ensure_ascii=False) if motifs else None,
            )).fetchone()["id"]

            conn.execute(
                "UPDATE alerts SET incident_id = %s WHERE id = ANY(%s)",
                (inc_id, [a["id"] for a in groupe]),
            )
        conn.commit()

    rattachees = sum(len(v) for v in ajouts.values())
    correlees = sum(len(g) for g in incidents) + rattachees
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
    if n_alertes and n_inc:
        print(f"{n_alertes} alertes -> {n_inc} incidents neufs "
              f"(facteur {n_alertes / n_inc:.1f}), rattachements aux existants inclus")
    elif n_alertes:
        print(f"{n_alertes} alertes rattachées à des incidents existants, "
              "aucun incident neuf.")
    else:
        print("Aucune alerte à corréler.")


if __name__ == "__main__":
    main()
