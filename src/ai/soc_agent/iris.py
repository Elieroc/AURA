"""Création d'un case DFIR-IRIS par incident trié.

Un case par incident, dès qu'il a un verdict :

- Faux positif → note d'analyse expliquant pourquoi, et l'exception de whitelist
  si le pipeline en a créé une pour cette signature.
- Vrai positif → rapport d'analyse (généré par le LLM : résumé, analyse, angle
  mort de détection éventuel), actions de remédiation proposées, et une piste de
  règle Wazuh si une détection manque.

Écrit en dfir-iris-client direct (déterministe, pas de boucle d'outils LLM). Le
serveur MCP IRIS, lui, sert l'investigation interactive.

    python -m soc_agent.iris                # crée les cases manquants
    python -m soc_agent.iris --incident 12  # un seul
"""

import argparse
import base64
import hashlib
import html
import ipaddress
import json
import logging
import re
from datetime import timedelta, timezone
from pathlib import Path

import psycopg
import urllib3
from psycopg.rows import dict_row

from . import config, correlate
from .anonymize import Anonymiseur, anonymiser, rehydrater, verifier_fuite
from .llm import completion
from .render import rendre
from .triage import charger_map, sauver_map
from .whitelist import _canonique, _signature

log = logging.getLogger("iris")

if not config.IRIS_VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROMPTS = Path(__file__).parent / "prompts"

# Classification IRIS (id) devinée depuis les groupes/tactiques. Best-effort :
# une valeur fausse ne casse rien de vital, elle range juste le case ailleurs.
# ids issus de /manage/case-classifications/list.
CLASSIF_RANSOMWARE = 6      # malicious-code:ransomware
CLASSIF_INTRUSION = 14      # intrusion-attempts:exploit-known-vuln
CLASSIF_BRUTE = 15          # intrusion-attempts:login-attempts
CLASSIF_DEFAUT = CLASSIF_INTRUSION

# --------------------------------------------------------------------------
# Sévérité du case IRIS
# --------------------------------------------------------------------------
#
# Une file de cases où tout est « Low » ne se trie pas. IRIS pose 4 (Low) par
# défaut à la création et son API `add_case` n'expose pas la sévérité : elle se
# règle après coup, par `/manage/cases/update/<id>` (`case_severity_id`).
#
# PIÈGE : les ids de l'échelle IRIS ne suivent PAS l'ordre de gravité —
# 3=Informational, 4=Low, 1=Medium, 5=High, 6=Critical, 2=Unspecified. Toute
# correspondance écrite sur les ids serait fausse (« sévérité 2 » = Unspecified,
# pas Low). On travaille donc sur les NOMS, et on résout l'id à l'exécution
# depuis le serveur : un autre déploiement d'IRIS peut très bien les numéroter
# autrement.
SEV_INFO, SEV_LOW, SEV_MEDIUM = "Informational", "Low", "Medium"
SEV_HIGH, SEV_CRITICAL = "High", "Critical"

# Nom EXACT du champ attendu par `/manage/cases/update/<id>`. `case_severity_id`
# — le nom qu'on devine d'après `case_classification_id` — est accepté, répond
# « updated »… et ne change rien. Vérifié en base : seul `severity_id` écrit
# réellement `cases.severity_id`.
#
# Aucun endpoint de l'API ne RELIT la sévérité (ni `/manage/cases/<id>`, ni
# `/manage/cases/list`, ni `/case/summary`) : un renommage de ce champ dans une
# version future d'IRIS repasserait donc inaperçu côté code. Le seul contrôle
# possible est en base :
#
#   docker exec iris-db psql -U postgres -d iris_db \
#     -c "select case_id, severity_id from cases order by case_id desc limit 5"
CHAMP_SEVERITE = "severity_id"

# Correspondance sévérité effective (échelle Wazuh 1-15, cf. assets.severite)
# -> nom IRIS. Bornes basses inclusives, lues de haut en bas.
#
# On repart de la sévérité EFFECTIVE et non du seul `max_level` : c'est déjà
# « à quel point ça tire » x « sur quoi », et le projet n'a besoin que d'une
# définition de la gravité. L'analyste retrouve donc dans la file IRIS l'ordre
# exact que le pipeline a appliqué, et la valeur affichée dans la description du
# case (« sévérité effective 14/15 ») explique la couleur qu'il voit.
SEUILS_SEVERITE = (
    (15, SEV_CRITICAL),   # attaque avérée sur un asset qui compte
    (12, SEV_HIGH),       # niveau d'ouverture d'incident du pipeline
    (8, SEV_MEDIUM),
    (4, SEV_LOW),
    (0, SEV_INFO),
)


def nom_severite(severite: int, ueba: bool = False, verdict: str = "",
                 actions=()) -> str:
    """Nom de sévérité IRIS pour un incident. Fonction pure.

    Trois règles, dans cet ordre :

    1. le barème `SEUILS_SEVERITE` appliqué à la sévérité effective ;
    2. **plancher UEBA à Medium** : un incident né du moteur comportemental a un
       `max_level` bas PAR CONSTRUCTION (il vient d'alertes 3-11, cf. ueba.py).
       Le barème le classerait « Low » alors qu'il n'existe que parce qu'un
       écart statistique l'a justifié — c'est-à-dire l'inverse de ce que la
       couleur dirait à l'analyste ;
    3. **plafond faux positif à Low** : un case documentant une activité
       légitime ne doit pas trôner en tête de file. SAUF si le garde-fou
       déterministe a refusé la clôture (`escalate_human` dans les actions
       finales) : le verdict du modèle est alors précisément ce qu'on ne croit
       pas, et rétrograder la sévérité reviendrait à appliquer quand même la
       décision qu'on vient de refuser — exactement ce qu'une injection cherche
       à obtenir.
    """
    nom = SEV_INFO
    for plancher, libelle in SEUILS_SEVERITE:
        if severite >= plancher:
            nom = libelle
            break

    ordre = [SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL]
    if ueba and ordre.index(nom) < ordre.index(SEV_MEDIUM):
        nom = SEV_MEDIUM
    if (verdict == "false_positive" and "escalate_human" not in (actions or [])
            and ordre.index(nom) > ordre.index(SEV_LOW)):
        nom = SEV_LOW
    return nom


# Correspondance nom -> id, lue une fois par processus sur le serveur IRIS.
_SEVERITES_ID: dict[str, int] | None = None

# Repli si `/manage/severities/list` est injoignable : les ids observés sur
# IRIS 2.4. Le repli est explicitement DÉCLARÉ faux-possible — mieux vaut une
# sévérité approchée qu'un case sans sévérité, mais on journalise.
_SEVERITES_REPLI = {"informational": 3, "low": 4, "medium": 1, "high": 5,
                    "critical": 6}


def _id_severite(case, nom: str) -> int | None:
    global _SEVERITES_ID
    if _SEVERITES_ID is None:
        try:
            liste = case._s.pi_get("/manage/severities/list").get_data()
            _SEVERITES_ID = {str(s["severity_name"]).lower(): s["severity_id"]
                             for s in liste}
        except Exception as e:  # noqa: BLE001
            log.warning("liste des sévérités IRIS illisible (%s) : repli sur "
                        "les ids par défaut", e)
            _SEVERITES_ID = dict(_SEVERITES_REPLI)
    return _SEVERITES_ID.get(nom.lower())


def _poser_severite(case, case_id: int, incident: dict, triage: dict) -> str | None:
    """Règle la sévérité du case. Best-effort : jamais bloquant.

    `add_case` ne prend pas de sévérité (tous les cases naissent « Low ») et
    `update_case` du client non plus : on passe par l'endpoint brut.
    """
    severite = incident.get("severite") or incident.get("max_level") or 0
    nom = nom_severite(severite, bool(incident.get("ueba")),
                       triage.get("verdict") or "", triage.get("actions") or [])
    sid = _id_severite(case, nom)
    if sid is None:
        log.warning("sévérité « %s » inconnue du serveur IRIS : case #%s laissé "
                    "tel quel", nom, case_id)
        return None
    try:
        r = case._s.pi_post(f"/manage/cases/update/{case_id}",
                            data={CHAMP_SEVERITE: sid})
        if not r.is_success():
            log.warning("sévérité non posée sur le case #%s : %s", case_id,
                        r.get_msg())
            return None
    except Exception as e:  # noqa: BLE001
        log.warning("sévérité non posée sur le case #%s : %s", case_id, e)
        return None
    return nom


def _description(incident: dict, verdict: str, maj: bool = False) -> str:
    """Description du case. UNE seule forme, création comme rafraîchissement.

    Le rafraîchissement réécrivait une description sans la priorité de l'asset :
    un case vieux de dix minutes perdait le contexte qui justifiait sa place
    dans la file.
    """
    desc = (f"Incident #{incident['id']} corrélé par le soc-agent, "
            f"{incident['alert_count']} alertes, niveau max "
            f"{incident['max_level']}/15")
    if incident.get("priorite"):
        role = incident.get("asset_role") or "rôle non déclaré"
        desc += (f", asset P{incident['priorite']} ({role}), sévérité effective "
                 f"{incident.get('severite') or incident['max_level']}/15")
    desc += f". Verdict IA : {verdict}."
    if maj:
        desc += " (mis à jour — nouvelles alertes rattachées)"
    return desc


# Descriptions courtes des actions, pour un rapport lisible par un humain.
LIBELLE_ACTION = {
    "propose_kill_process": "Tuer le process malveillant",
    "propose_isolate_host": "Isoler l'hôte du réseau",
    "propose_disable_user": "Désactiver le compte compromis",
    "propose_block_ip": "Bloquer l'IP source",
    "propose_quarantine_file": "Mettre le fichier en quarantaine",
    "propose_remove_privileged_group": "Retirer du groupe AD privilégié",
    "escalate_human": "Escalade analyste",
    "open_case": "Ouvrir un dossier",
    "close_false_positive": "Clôturer en faux positif",
}


def _client():
    from dfir_iris_client.case import Case
    from dfir_iris_client.session import ClientSession
    session = ClientSession(apikey=config.IRIS_API_KEY, host=config.IRIS_URL,
                            ssl_verify=config.IRIS_VERIFY_TLS)
    return Case(session)


# Répertoire de notes où atterrit l'analyse IA (créé au besoin).
DIR_ANALYSE = "Analyse IA"

# Répertoire de la note d'exposition aux vulnérabilités. SÉPARÉ de « Analyse IA »
# à dessein : son contenu est calculé en Python à partir de l'inventaire Wazuh,
# il n'est ni produit ni relu par le modèle. Les mélanger ferait porter à des
# faits l'avertissement « verdict produit par un LLM » du rapport — et
# inversement donnerait au récit du modèle l'autorité d'une mesure.
DIR_EXPOSITION = "Exposition"
TITRE_EXPOSITION = "Exposition aux vulnérabilités"

# Tag posé sur les évènements de timeline créés par le soc-agent : c'est à ça
# qu'on les reconnaît pour les remplacer au rafraîchissement.
TAG_AUTO = "soc-agent"


def _taguer(case, case_id: int, agent_name: str | None,
            *extras: str | None) -> None:
    """Ajoute le hostname de la machine touchée aux tags du case (union).

    Un analyste retrouve ainsi tous les cases d'une même machine par le tag.
    Union avec l'existant : on n'écrase pas les tags posés à la main. add_case
    n'accepte pas de tags — d'où le update_case juste après la création.

    `extras` : tags supplémentaires (priorité de l'asset, « P1 »…), ignorés
    quand ils sont vides.
    """
    nouveaux = {t for t in (agent_name, *extras) if t}
    if not nouveaux:
        return
    tags: set[str] = set()
    try:
        gc = case.get_case(case_id)
        if gc.is_success():
            brut = gc.get_data().get("case_tags") or ""
            tags = {t.strip() for t in brut.split(",") if t.strip()}
    except Exception as e:  # noqa: BLE001 — le tag ne bloque pas le case
        log.debug("lecture tags case #%s : %s", case_id, e)
    if nouveaux <= tags:
        return
    tags |= nouveaux
    try:
        case.update_case(case_id=case_id, case_tags=sorted(tags))
    except Exception as e:  # noqa: BLE001
        log.debug("tag case #%s : %s", case_id, e)


def _case_existe(case, case_id: int | None) -> bool:
    """Le case est-il encore là ? False s'il a été supprimé dans IRIS.

    Aucune exception ne remonte : ce test sert à DÉCIDER quoi faire ensuite, il
    ne doit pas devenir lui-même une cause de panne.
    """
    if not case_id:
        return False
    try:
        return bool(case.get_case(case_id).is_success())
    except Exception as e:  # noqa: BLE001
        log.debug("existence case #%s indéterminable : %s", case_id, e)
        return False


def _poser_iocs(case, case_id: int, alertes: list[dict]) -> dict[str, int]:
    """Met le case à jour : ajoute les IOC manquants, rafraîchit les descriptions.

    Renvoie la table valeur → ioc_id de TOUS les IOC du case (existants
    compris) : la timeline s'en sert pour rattacher chaque évènement à ses
    indicateurs, ce qui est la condition pour que l'onglet Graph d'IRIS ait
    quelque chose à dessiner (il ne lit que `case_events_ioc`).

    La description est réécrite quand elle a changé. Sans ça, un case ne
    converge jamais vers ce que le code produit : au repliage « un fichier = un
    IOC », les hashs déjà présents ont gardé leur ancienne description et le
    chemin du fichier — désormais porté par cette description — restait
    introuvable dans le case.
    """
    ids: dict[str, int] = {}
    descriptions: dict[str, str] = {}
    try:
        d = case.list_iocs(case_id).get_data() or {}
        for i in d.get("ioc") or []:
            if i.get("ioc_value") and i.get("ioc_id"):
                ids[i["ioc_value"]] = i["ioc_id"]
                descriptions[i["ioc_value"]] = i.get("ioc_description") or ""
    except Exception as e:  # noqa: BLE001
        log.debug("liste IOC case #%s : %s", case_id, e)
    for valeur, type_ioc, description in _iocs(alertes):
        if valeur in ids:
            # Seulement si elle a changé : une écriture inutile par IOC et par
            # rafraîchissement, sur tous les cases, chargerait IRIS pour rien.
            if descriptions.get(valeur) != description:
                try:
                    case.update_ioc(ids[valeur], description=description,
                                    cid=case_id)
                except Exception as e:  # noqa: BLE001
                    log.debug("MAJ description IOC %s : %s", valeur, e)
            continue
        try:
            r = case.add_ioc(value=valeur, ioc_type=type_ioc,
                             description=description, cid=case_id)
            if r.is_success():
                ids[valeur] = (r.get_data() or {}).get("ioc_id")
        except Exception as e:  # noqa: BLE001
            log.debug("IOC ignoré (%s/%s) : %s", type_ioc, valeur, e)
    return {v: i for v, i in ids.items() if i}


def _type_asset(alertes: list[dict]) -> str:
    """Type d'asset IRIS de la machine touchée, déduit des alertes."""
    for a in alertes:
        raw = a["raw"] if isinstance(a["raw"], dict) else json.loads(a["raw"])
        groupes = (raw.get("rule", {}) or {}).get("groups") or []
        if any("windows" in str(g).lower() for g in groupes) or \
                "win" in (raw.get("data", {}) or {}):
            return "Windows - Computer"
    return "Linux - Server"


def _assets_case(case, case_id: int) -> dict[str, int]:
    """Table nom → asset_id des assets du case (dont ceux posés par mitigate)."""
    out: dict[str, int] = {}
    try:
        d = case.list_assets(cid=case_id).get_data() or {}
        items = d.get("assets") if isinstance(d, dict) else d
        for a in items or []:
            if a.get("asset_name") and a.get("asset_id"):
                out[a["asset_name"]] = a["asset_id"]
    except Exception as e:  # noqa: BLE001
        log.debug("liste assets case #%s : %s", case_id, e)
    return out


def _poser_asset_machine(case, case_id: int, incident: dict,
                         alertes: list[dict], compromis: bool) -> list[int]:
    """Crée (ou retrouve) l'asset « machine touchée » du case.

    C'est le nœud pivot du graphe : chaque évènement de timeline lui est
    rattaché, les IOC de l'évènement s'y accrochent en étoile. Sans au moins
    un asset lié à un évènement, l'onglet Graph reste vide même avec des IOC.
    """
    nom = incident.get("agent_name") or str(incident["agent_id"])
    existants = _assets_case(case, case_id)
    if nom in existants:
        return [existants[nom]]

    ip = None
    for a in alertes:
        raw = a["raw"] if isinstance(a["raw"], dict) else json.loads(a["raw"])
        ip = (raw.get("agent", {}) or {}).get("ip")
        if ip:
            break
    try:
        r = case.add_asset(
            name=nom,
            asset_type=_type_asset(alertes),
            analysis_status="Started",
            # 1 = compromised, 0 = to be determined. En dur plutôt qu'en nom :
            # le graphe teste `asset_compromise_status_id == 1` pour choisir
            # l'icône, et on évite un aller-retour de lookup par case.
            compromise_status=1 if compromis else 0,
            description=(f"Endpoint Wazuh {incident['agent_id']} — "
                         f"{incident['alert_count']} alertes corrélées, "
                         f"niveau max {incident['max_level']}/15."),
            ip=ip,
            cid=case_id)
        if r.is_success():
            return [(r.get_data() or {})["asset_id"]]
        log.debug("asset machine non créé (case #%s) : %s", case_id, r.get_msg())
    except Exception as e:  # noqa: BLE001 — l'asset ne bloque pas le case
        log.debug("asset machine case #%s : %s", case_id, e)
    return []


# Marque d'un rapport écrit sans analyse LLM (repli sur la raison du triage).
# Sert aussi de garde : un rapport dégradé n'écrase pas un rapport abouti.
MARQUE_DEGRADE = "⚠️ **Rapport dégradé"


def _note_est_degradee(case, case_id: int, note_id: int) -> bool:
    """Vrai si la note existante est déjà un repli (ou illisible)."""
    try:
        d = case.get_note(note_id, cid=case_id).get_data() or {}
        return MARQUE_DEGRADE in (d.get("note_content") or "")
    except Exception as e:  # noqa: BLE001 — dans le doute, on n'écrase pas
        log.debug("lecture note %s : %s", note_id, e)
        return False


def _poser_note(case, case_id: int, titre: str, contenu: str,
                repertoire: str = DIR_ANALYSE) -> None:
    """Crée ou MET À JOUR une note dans le répertoire demandé.

    Au rafraîchissement d'un case, on remplace le contenu de la note existante
    plutôt que d'en empiler une deuxième : le dossier reste lisible.

    UNE exception : un rapport DÉGRADÉ (analyse LLM en échec, repli sur la
    raison du triage) n'écrase jamais un rapport abouti. Un incident est
    re-trié à chaque nouvelle alerte, donc le rapport est réécrit en boucle ;
    le 2026-08-02, le rapport complet des cases 90 et 91 a été remplacé par le
    repli de deux lignes parce que le dernier appel avait épuisé son budget de
    tokens. Perdre une analyse réussie à cause d'un échec ultérieur est une
    régression pure, jamais un rafraîchissement.
    """
    dir_id = None
    note_id = None
    try:
        for d in case.list_notes_directories(cid=case_id).get_data() or []:
            if d.get("name") == repertoire:
                dir_id = d["id"]
                for n in d.get("notes") or []:
                    if n.get("title") == titre:
                        note_id = n["id"]
                        break
                break
    except Exception as e:  # noqa: BLE001
        log.debug("liste notes case #%s : %s", case_id, e)
    if note_id is not None:
        if (MARQUE_DEGRADE in contenu
                and not _note_est_degradee(case, case_id, note_id)):
            log.warning("case #%s : rapport dégradé NON écrit, la note "
                        "existante est une analyse aboutie", case_id)
            return
        try:
            case.update_note(note_id=note_id, note_content=contenu, cid=case_id)
            return
        except Exception as e:  # noqa: BLE001
            log.debug("maj note %s : %s", note_id, e)
    if dir_id is None:
        rd = case.add_notes_directory(directory_name=repertoire, cid=case_id)
        dir_id = rd.get_data()["id"] if rd.is_success() else None
    case.add_note(note_title=titre, note_content=contenu,
                  directory_id=dir_id, cid=case_id)


def _est_auto_legacy(case, case_id: int, ev: dict) -> bool:
    """Évènement posé par une version antérieure du soc-agent (sans tag).

    Rattrapage : ces évènements-là n'ont que `event_source = "Wazuh"`, absent
    de la liste de timeline — il faut relire l'évènement pour trancher. Un
    appel par évènement non taggé, qui disparaît dès le premier nettoyage.
    """
    try:
        d = case.get_event(ev["event_id"], cid=case_id).get_data() or {}
        return (d.get("event_source") or "") == "Wazuh"
    except Exception as e:  # noqa: BLE001
        log.debug("lecture évènement %s : %s", ev.get("event_id"), e)
        return False


def _reconstruire_timeline(case, case_id: int, alertes: list[dict],
                           agent_id: str, asset_ids: list[int] | None = None,
                           ioc_ids: dict[str, int] | None = None,
                           assets_nom: dict[str, int] | None = None) -> None:
    """Efface les évènements auto (tag `soc-agent`) et les reconstruit.

    Une salve rattachée allonge un groupe de règle ou en crée un ; re-poser
    tout en l'état dupliquerait. On supprime donc les évènements posés par le
    soc-agent, jamais ceux saisis par un analyste, puis on les recrée depuis
    l'état courant.

    Le repère est le **tag** `soc-agent`, pas `event_source` : la liste de
    timeline d'IRIS ne renvoie pas ce champ, donc filtrer dessus ne supprimait
    jamais rien et empilait les doublons à chaque rafraîchissement.
    """
    try:
        tl = case.list_events(cid=case_id).get_data().get("timeline") or []
    except Exception as e:  # noqa: BLE001
        log.debug("liste timeline case #%s : %s", case_id, e)
        tl = []
    for ev in tl:
        tags = {t.strip() for t in (ev.get("event_tags") or "").split(",")}
        if TAG_AUTO not in tags and not _est_auto_legacy(case, case_id, ev):
            continue
        try:
            case.delete_event(ev["event_id"], cid=case_id)
        except Exception as e:  # noqa: BLE001
            log.debug("suppr évènement %s : %s", ev.get("event_id"), e)
    _timeline(case, case_id, alertes, agent_id, asset_ids, ioc_ids, assets_nom)


def _classification(incident: dict, alertes: list[dict]) -> int:
    groups = {g for a in alertes for g in (a.get("rule_groups") or [])}
    tactics = set(incident.get("mitre_tactics") or [])
    if "ransomware" in groups or "Impact" in tactics:
        return CLASSIF_RANSOMWARE
    if {"authentication_failed", "authentication_failures"} & groups:
        return CLASSIF_BRUTE
    return CLASSIF_DEFAUT


# Répertoires où un fichier signale une activité malveillante. Ailleurs
# (/usr, /bin, /etc…), un chemin est un binaire/config légitime que
# l'attaquant a seulement *utilisé* — pas un IOC. /etc/passwd n'est pas un
# indicateur ; /dev/shm/.kworker en est un.
_DIRS_SUSPECTS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/",
                  "/root/.ssh", "/var/www/", "/usr/lib/cgi-bin/")
# Comptes système : leur présence dans un log n'est pas un IOC.
_COMPTES_SYSTEME = {"root", "www-data", "daemon", "nobody", "sync", "sys", "bin"}
# Cible d'un reverse shell dans une redirection /dev/tcp|udp/<ip>/<port>.
_RE_REVSHELL = re.compile(r"/dev/(?:tcp|udp)/(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,5})")
# proctitle auditd : la ligne de commande complète, encodée en hex.
_RE_PROCTITLE = re.compile(r"proctitle=([0-9A-Fa-f]{8,})")
# Création de compte dans une commande (dernier token = nom du compte).
_RE_USERADD = re.compile(r"\b(?:useradd|adduser)\b.*?([A-Za-z_][\w-]*)\s*$")
# Création de compte Windows en ligne de commande : « net user <nom> ... /add »
# (avec ou sans /domain). Capte le backdoor AD quand seul le net.exe est vu.
_RE_NETUSER_ADD = re.compile(r"\bnet\d?\s+user\s+([^\s/]+).*?/add", re.IGNORECASE)
# Préfixe du montage sshfs du scanner YARA : /mnt/yaritrust/<hôte>_<ip>/…
_RE_MONTAGE_SCAN = re.compile(r"^/mnt/yaritrust/[^/]+/")
# Chemin absolu dans une ligne de commande. On s'arrête aux caractères qui
# séparent les tokens d'un shell plutôt qu'à une liste de caractères permis :
# un nom de fichier d'attaquant peut contenir à peu près n'importe quoi.
_RE_CHEMIN_ARGV = re.compile(r"/[^\s'\"><|;,()]+")
# Chemins de /tmp qui appartiennent à la machinerie du système, pas à
# l'attaquant : montages privés des units systemd, sockets X11/ICE.
_RE_ARGV_BRUIT = re.compile(
    r"^/tmp/(?:systemd-private-|\.X11-unix|\.ICE-unix|\.font-unix|\.XIM-unix)")

# Réseaux internes du parc, précompilés une fois.
_NETS_INTERNES = []
for _cidr in config.RESEAUX_INTERNES:
    try:
        _NETS_INTERNES.append(ipaddress.ip_network(_cidr, strict=False))
    except ValueError:
        log.warning("RESEAUX_INTERNES: cidr invalide ignoré: %r", _cidr)


def _ip_ioc_valide(ip: str) -> bool:
    """IP exploitable comme IOC : ni 'none', ni loopback, ni non-spécifiée, ni
    l'infrastructure du SOC.

    Écarte le bruit qui polluait la threat intel (`ip-any = none`, 0.0.0.0,
    127.0.0.1, link-local, multicast).

    Le SOC lui-même (`config.SOC_INFRA_IPS` : manager, indexer, IRIS, Shuffle)
    est exclu ici plutôt qu'à chaque appelant : c'est le seul point de passage
    commun aux IOC et au choix des cibles de blocage de `mitigate`, donc le seul
    endroit où l'exclusion ne peut pas être oubliée par un futur bloc. Le SIEM
    dialogue avec tout le parc ; son IP en `srcip` ou en cible de connexion ne
    dit rien d'une attaque, et la bloquer coupe le SOC de ses agents."""
    try:
        o = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    if str(o) in config.SOC_INFRA_IPS:
        return False
    return not (o.is_loopback or o.is_unspecified or o.is_link_local
                or o.is_multicast)


def _ip_interne(ip: str) -> bool:
    """Vrai si l'IP appartient à un subnet du parc (cf. config.RESEAUX_INTERNES).

    Volontairement PAS `is_private` : un C2 peut être en RFC1918 (VPN, cloud
    privé...) — seule l'appartenance aux subnets déclarés du parc vaut
    « interne »."""
    try:
        o = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return any(o in n for n in _NETS_INTERNES)


# Coquilles d'accent récurrentes du modèle (français écrit sans accents),
# corrigées de façon déterministe sur le récit LLM. Limité aux formes SANS
# collision avec l'anglais/MITRE : « privilege » (Privilege Escalation) et
# « elevation » sont donc EXCLUS. « reseau » n'a pas d'homographe anglais.
_ACCENTS = {
    "acces": "accès", "detecte": "détecté", "detectee": "détectée",
    "detectes": "détectés", "detectees": "détectées", "deja": "déjà",
    "reseau": "réseau", "reseaux": "réseaux",
}
_RE_ACCENTS = re.compile(r"\b(" + "|".join(_ACCENTS) + r")\b", re.IGNORECASE)


def _corriger_accents(txt: str) -> str:
    """Remplace les coquilles d'accent du récit LLM, en préservant la casse."""
    def repl(m):
        mot = m.group(0)
        corr = _ACCENTS[mot.lower()]
        return corr.capitalize() if mot[0].isupper() else corr
    return _RE_ACCENTS.sub(repl, txt or "")


def _decoder_proctitle(full_log: str) -> str:
    """Ligne de commande décodée depuis le proctitle hex d'un log auditd."""
    m = _RE_PROCTITLE.search(full_log or "")
    if not m:
        return ""
    try:
        return bytes.fromhex(m.group(1)).replace(b"\x00", b" ").decode(
            "utf-8", "replace")
    except ValueError:
        return ""


def _ips_revshell(alerte: dict) -> set[str]:
    """IP cibles d'une redirection /dev/tcp|/dev/udp dans la commande de l'alerte.

    Cherche dans le full_log en clair, le proctitle hex décodé et la description.
    Ne filtre PAS interne/externe : l'appelant tranche (IOC de contexte vs cible
    de blocage). C'est la seule source de l'IP du C2 pour un reverse shell
    auditd — l'événement execve ne porte pas de `srcip`, donc sans ça le C2
    détecté (rule 100650) n'était jamais bloqué (régression mesurée)."""
    raw = alerte["raw"] if isinstance(alerte.get("raw"), dict) else json.loads(
        alerte.get("raw") or "{}")
    full_log = raw.get("full_log") or ""
    ips: set[str] = set()
    for texte in (full_log, _decoder_proctitle(full_log),
                  alerte.get("rule_desc") or ""):
        for ip, _port in _RE_REVSHELL.findall(texte):
            if _ip_ioc_valide(ip):
                ips.add(ip)
    return ips


def _chemin_cible(p: str | None) -> str | None:
    """Chemin réel sur la machine scannée, sans le préfixe du montage sshfs.

    Le scanner YARITRUST monte chaque hôte sous /mnt/yaritrust/<hôte>_<ip>/ et
    scanne à travers. `data.file_path` porte déjà le chemin nettoyé, mais les
    alertes antérieures au correctif n'ont que `yara.scan_path`, préfixé. Sans
    ce retrait, le MÊME fichier produit deux IOC distincts dans le case (l'un
    préfixé, l'autre non), et aucun des deux n'est utilisable tel quel sur
    l'hôte concerné.
    """
    if not p:
        return None
    return _RE_MONTAGE_SCAN.sub("/", p, count=1)


def _chemin_suspect(p: str | None) -> bool:
    if not p:
        return False
    if any(p.startswith(d) for d in _DIRS_SUSPECTS):
        return True
    base = p.rsplit("/", 1)[-1]
    # Exécutable planqué (nom en point) hors des emplacements légitimes.
    return base.startswith(".") and not p.startswith(("/etc", "/home", "/root/."))


def _chemins_argv(audit: dict, full_log: str) -> list[str]:
    """Chemins de fichiers suspects cités en ARGUMENT d'une commande auditd.

    `audit.file.name` et `entity` portent le binaire que le NOYAU a chargé, pas
    le fichier sur lequel il agit : pour `python3 /tmp/x.py` c'est
    /usr/bin/python3, pour `insmod /tmp/rk.ko` c'est /usr/bin/kmod (et
    `audit.file.name` peut même désigner un fichier sans rapport, /etc/hosts
    étant lu par le loader). L'artefact déposé par l'attaquant — le seul
    chassable sur le reste du parc — ne vit donc que dans l'argv.

    Deux sources, dans cet ordre : le champ `audit.execve` décodé par Wazuh
    (a0, a1…) et, à défaut, le proctitle hex du full_log. Les chemins de la
    machinerie de session (montages privés systemd, sockets X11) sont écartés :
    ils sont dans /tmp sans rien devoir à l'attaquant.
    """
    morceaux: list[str] = []
    execve = audit.get("execve")
    if isinstance(execve, dict):
        def _rang(cle: str) -> tuple[int, str]:
            suffixe = str(cle).lstrip("a")
            return (int(suffixe), "") if suffixe.isdigit() else (10**6, str(cle))
        morceaux += [str(v) for _, v in sorted(execve.items(),
                                               key=lambda kv: _rang(kv[0]))]
    morceaux.append(_decoder_proctitle(full_log))

    out: list[str] = []
    vus: set[str] = set()
    for texte in morceaux:
        for chemin in _RE_CHEMIN_ARGV.findall(texte or ""):
            chemin = chemin.rstrip(".,;:")
            if chemin in vus or _RE_ARGV_BRUIT.search(chemin):
                continue
            if not _chemin_suspect(chemin):
                continue
            vus.add(chemin)
            out.append(chemin)
    return out


# Ordre de préférence pour REPRÉSENTER un fichier dans la liste d'IOC. Un hash
# identifie le contenu : il survit à un renommage, vaut sur n'importe quelle
# machine, et se partage tel quel avec un tiers ou un moteur de réputation. Un
# chemin ne vaut que sur l'hôte où il a été vu. D'où hash > filename.
_PRIORITE_IOC_FICHIER = ("sha256", "sha1", "md5")


def _ioc_fichier(chemin: str | None, hashes: dict, contexte: str
                 ) -> tuple[str, str, str] | None:
    """UN seul IOC pour un fichier, le reste replié dans la description.

    Un même fichier produisait jusqu'à trois entrées (chemin, sha256, md5). La
    liste d'IOC d'un case en devenait illisible et son compteur trompeur : six
    fichiers détectés y apparaissaient comme dix-huit indicateurs distincts, et
    rien ne disait que ces trois lignes désignaient le même objet.

    Aucune information n'est perdue — les autres hashs et le chemin restent
    écrits dans la description, donc lisibles dans le case et cherchables. Ce
    qui change est le nombre de LIGNES : une par artefact réel.
    """
    principal = next(((t, hashes[t]) for t in _PRIORITE_IOC_FICHIER
                      if hashes.get(t)), None)
    complements = []
    if principal:
        type_ioc, valeur = principal
        if chemin:
            complements.append(f"fichier {chemin}")
    elif chemin:
        type_ioc, valeur = "filename", chemin
    else:
        return None

    # Les hashs non retenus comme valeur principale restent affichés : un
    # analyste qui n'a qu'un MD5 sous la main doit pouvoir faire le lien.
    complements += [f"{t} {hashes[t]}" for t in _PRIORITE_IOC_FICHIER
                    if hashes.get(t) and hashes[t] != valeur]

    description = contexte
    if complements:
        description = f"{contexte} · " + " · ".join(complements)
    return str(valeur), type_ioc, description


# Extensions retenues pour un « exécutable » Windows déposé.
_EXE_WIN = (".exe", ".dll", ".ps1", ".bat", ".scr", ".com", ".vbs", ".js")


def _mitre_observes(alertes: list[dict]) -> set[str]:
    """Identifiants ATT&CK portés par les règles qui ont tiré sur l'incident."""
    out: set[str] = set()
    for a in alertes:
        for t in (a.get("mitre_ids") or []):
            if t:
                out.add(str(t).strip())
    return out - {""}


# Techniques dont la remédiation ne se déduit d'AUCUNE action d'active
# response : elles laissent l'attaquant capable de revenir même une fois l'hôte
# nettoyé. Un exercice purple-team a détecté `kerberos::golden` sans que rien
# nulle part ne dise que le secret krbtgt était à changer — l'incident était
# clos avec un ticket forgé valable dix ans.
_REMEDIATIONS_HORS_PORTEE = {
    "T1558.001": (
        "Golden Ticket — le hash du compte **krbtgt** est compromis",
        "Aucune action automatique ne corrige cela. Tant que le secret n'est "
        "pas renouvelé, l'attaquant peut forger un TGT pour n'importe quel "
        "compte du domaine, y compris après nettoyage complet des hôtes. "
        "**Renouveler le mot de passe de krbtgt DEUX fois**, en laissant "
        "s'écouler au moins la durée de vie maximale d'un ticket (10 h par "
        "défaut) entre les deux : le premier renouvellement seul laisse "
        "l'ancienne clé valide."),
    "T1003.006": (
        "DCSync — la base de comptes du domaine a pu être répliquée",
        "Considérer TOUS les secrets du domaine comme divulgués (comptes de "
        "service, krbtgt, comptes machine). Renouveler krbtgt deux fois et les "
        "mots de passe des comptes à privilèges."),
    "T1003.003": (
        "NTDS.dit — la base Active Directory a pu être copiée",
        "Même portée qu'un DCSync : tous les hashs du domaine sont à "
        "considérer comme connus de l'attaquant."),
    "T1550.002": (
        "Pass-the-Hash — un hash NTLM valide est entre les mains de l'attaquant",
        "Renouveler le mot de passe du compte concerné. Désactiver le compte "
        "ne suffit pas si le hash sert ailleurs dans le domaine."),
}


def _section_remediation_hors_portee(triage: dict,
                                     alertes: list[dict]) -> str:
    """Ce que l'automatisation ne peut PAS réparer, et qu'il faut faire à la main.

    Une remédiation autonome isole, bloque, tue et désactive. Elle ne renouvelle
    pas un secret de domaine. Quand la chaîne d'attaque contient un vol de
    credentials AD, l'incident n'est pas terminé une fois l'hôte nettoyé, et le
    rapport doit le dire en toutes lettres.
    """
    vues = _mitre_observes(alertes) | {(triage.get("mitre") or "").strip()}
    concernees = [(t, _REMEDIATIONS_HORS_PORTEE[t])
                  for t in sorted(_REMEDIATIONS_HORS_PORTEE) if t in vues]
    if not concernees:
        return ""
    lignes = [
        "## À faire à la main — hors de portée de la remédiation automatique",
        "",
        "Les actions automatiques (isolation, blocage, arrêt de process, "
        "désactivation de compte) ne corrigent PAS ce qui suit. Tant que ces "
        "points ne sont pas traités, l'attaquant garde un moyen de revenir.",
        "",
    ]
    for tech, (titre, quoi) in concernees:
        lignes += [f"### {tech} — {titre}", "", quoi, ""]
    return "\n".join(lignes)


def _norm_chemin_win(brut) -> str:
    """Chemin Windows aux backslashes simples.

    Le JSON de l'eventchannel arrive avec les backslashes DOUBLÉS et Wazuh les
    conserve : `C:\\\\Windows\\\\System32\\\\cmd.exe` est stocké avec deux
    caractères entre chaque segment. Tout test de préfixe sur un répertoire
    système échoue silencieusement sans cette normalisation — c'est ce qui a
    envoyé 26 ordres de quarantaine sur des binaires de System32 le
    2026-08-02 (cf. `mitigate._norm_chemin_win`, même correctif).
    """
    p = str(brut or "").strip().strip('"')
    while "\\\\" in p:
        p = p.replace("\\\\", "\\")
    return p


def _exe_windows_suspect(chemin: str) -> bool:
    """Exécutable Windows hors répertoire système : candidat IOC.

    Un binaire signé de System32 lancé par l'attaquant relève de la détection
    comportementale, pas de l'indicateur : le chasser sur le parc ne
    donnerait que du bruit. Ce qui se chasse, c'est ce qu'il a APPORTÉ.
    """
    pl = chemin.lower()
    return bool(chemin and ":\\" in chemin and pl.endswith(_EXE_WIN)
                and not pl.startswith(config.VT_DIRS_SYSTEME)
                and "__psscriptpolicytest_" not in pl)


def _est_cle_registre(chemin: str | None) -> bool:
    """Vrai pour une clé de registre Windows (pas un fichier, donc pas un IOC)."""
    return str(chemin or "").upper().startswith(("HKEY_", "HKLM\\", "HKCU\\",
                                                 "HKLM/", "HKCU/"))


def _vt_malveillant(vt: dict) -> bool:
    """Vrai si VirusTotal a bien rendu un verdict POSITIF.

    L'intégration écrit `found` (VT connaît-il ce hash) et `malicious` (nombre
    de moteurs positifs), tous deux en chaîne. Sans ce test, un hash inconnu de
    VT devenait un indicateur de compromission dans le case.
    """
    def _n(v):
        try:
            return int(str(v).strip() or 0)
        except ValueError:
            return 0
    return _n(vt.get("found")) > 0 and _n(vt.get("malicious")) > 0


def _iocs(alertes: list[dict]) -> list[tuple[str, str, str]]:
    """Vrais indicateurs d'attaque, dédupliqués. Best-effort.

    On ne remonte QUE ce qui caractérise l'attaquant : IP/port du C2, comptes
    créés, fichiers déposés dans des emplacements suspects, hash de malware.
    Les fichiers système simplement lus/modifiés (/etc/passwd, /usr/bin/cat)
    ne sont PAS des IOC et sont écartés.
    """
    vus: set[str] = set()
    fichiers_vus: set[str] = set()
    out: list[tuple[str, str, str]] = []

    def ajouter(valeur, type_ioc, desc):
        if valeur and str(valeur) not in vus:
            vus.add(str(valeur))
            out.append((str(valeur), type_ioc, desc))

    def ajouter_fichier(chemin, hashes, contexte):
        """Un fichier = UN IOC (cf. _ioc_fichier), hash prioritaire sur chemin.

        Dédup supplémentaire sur le CHEMIN : le même fichier vu par deux alertes
        successives (rescan) porte le même hash, donc `ajouter` suffirait ; mais
        un fichier réécrit entre deux scans change de hash tout en restant le
        même artefact, et on ne veut pas deux lignes pour autant.
        """
        ioc = _ioc_fichier(chemin, hashes or {}, contexte)
        if ioc is None:
            return
        if chemin and str(chemin) in fichiers_vus:
            return
        if chemin:
            fichiers_vus.add(str(chemin))
        ajouter(*ioc)

    for a in alertes:
        raw = a["raw"] if isinstance(a["raw"], dict) else json.loads(a["raw"])
        data = raw.get("data", {})
        audit = data.get("audit", {})
        full_log = raw.get("full_log") or ""

        # Cible d'une redirection /dev/tcp|udp, dans le log ou le proctitle.
        # On ne l'étiquette « C2 » que si elle est HORS parc : une cible interne
        # (tout le /24 balayé sur le port 22) est du mouvement latéral / scan,
        # pas un C2 — l'appeler C2 polluait la threat intel et pointait un
        # blocage vers l'infra interne.
        for texte in (full_log, _decoder_proctitle(full_log),
                      a.get("rule_desc") or ""):
            for ip, port in _RE_REVSHELL.findall(texte):
                if not _ip_ioc_valide(ip):
                    continue
                if _ip_interne(ip):
                    ajouter(ip, "ip-any", "Cible interne — connexion /dev/tcp "
                            f"(mouvement latéral / scan, port {port})")
                else:
                    ajouter(ip, "ip-any",
                            f"IP C2 — cible reverse shell (port {port})")

        # IP source d'une attaque réseau (ex. web). Interne = pivot/latéral.
        srcip = a.get("srcip")
        if srcip and _ip_ioc_valide(srcip):
            ajouter(srcip, "ip-any",
                    "IP source interne (pivot / mouvement latéral)"
                    if _ip_interne(srcip) else "IP source externe de l'attaque")

        # Compte créé/manipulé (useradd : dstuser + home/shell).
        dstuser = data.get("dstuser")
        if dstuser and dstuser not in _COMPTES_SYSTEME and (
                data.get("home") or data.get("shell")):
            home = (data.get("home") or "?").rstrip(",")
            shell = (data.get("shell") or "?").rstrip(",")
            ajouter(dstuser, "account",
                    f"Compte créé par l'attaquant (home {home}, shell {shell})")

        # Compte créé vu dans la commande auditd (useradd/adduser) : capte le
        # backdoor account même quand l'alerte syslog 5902 (sans uid ni lien)
        # n'entre pas dans l'incident. Le compte = dernier argument non-option.
        m = _RE_USERADD.search(_decoder_proctitle(full_log))
        if m and m.group(1) not in _COMPTES_SYSTEME:
            ajouter(m.group(1), "account", "Compte créé par l'attaquant (useradd)")

        # Compte Windows créé par l'attaquant : event 4720 (targetUserName) ou une
        # ligne de commande « net user <nom> /add ». Sans ça, la création d'un
        # backdoor AD (net user art-backdoor /add /domain) n'était pas un IOC
        # « account », donc le filet déterministe de mitigate (compte créé ->
        # disable_user) ne se déclenchait pas. Comptes machine ($) écartés.
        wev = (data.get("win") or {}).get("eventdata") or {}
        wsys = (data.get("win") or {}).get("system") or {}
        tuser = wev.get("targetUserName")
        if (str(wsys.get("eventID") or "") == "4720" and tuser
                and not str(tuser).endswith("$")):
            ajouter(tuser, "account", "Compte Windows créé par l'attaquant (4720)")
        mw = _RE_NETUSER_ADD.search(str(wev.get("commandLine") or full_log or ""))
        if mw and not mw.group(1).endswith("$"):
            ajouter(mw.group(1), "account",
                    "Compte créé par l'attaquant (net user /add)")

        # Fichier déposé dans un emplacement suspect (binaire droppé, webshell).
        fichier = (audit.get("file", {}) or {}).get("name") or a.get("entity")
        if _chemin_suspect(fichier):
            ajouter(fichier, "filename", "Fichier déposé (emplacement suspect)")

        # Fichier cité en ARGUMENT de la commande. Les deux champs ci-dessus ne
        # portent que le binaire chargé par le noyau : `insmod /tmp/rootkit.ko`
        # produisait `/usr/bin/kmod`, `python3 /tmp/.implant.py` produisait
        # `/usr/bin/python3`. L'artefact réellement déposé n'apparaissait donc
        # dans AUCUN IOC du case, alors que c'est le premier que l'analyste
        # cherche et le seul qu'il puisse chasser sur les autres hôtes.
        # `ajouter` et non `ajouter_fichier` : sans hash sous la main, réserver
        # le chemin dans `fichiers_vus` empêcherait un bloc suivant (FIM, VT,
        # YARA) de publier le MÊME fichier porté par son hash — la valeur la
        # plus utile des deux.
        for chemin in _chemins_argv(audit, full_log):
            ajouter(chemin, "filename", "Fichier déposé en emplacement suspect "
                    "(cité en argument de commande)")

        # Outil offensif Windows, exécuté ou déposé hors des répertoires
        # système. Sans ce bloc, un exercice purple-team a produit un case avec
        # UN seul IOC (le compte créé) : `mimikatz.exe`, lancé sur le
        # contrôleur de domaine et cité dans une dizaine d'alertes, n'y
        # figurait pas — alors que c'est l'artefact qu'un analyste cherche en
        # premier et le seul qu'il puisse chasser sur le reste du parc. Un
        # autre case du même exercice n'avait, lui, aucun IOC du tout.
        for champ in ("image", "targetFilename", "sourceImage"):
            chemin = _norm_chemin_win(wev.get(champ))
            if _exe_windows_suspect(chemin):
                ajouter_fichier(chemin,
                                {"sha256": wev.get("sha256"),
                                 "sha1": wev.get("sha1"),
                                 "md5": wev.get("md5")},
                                "Exécutable lancé ou déposé hors des "
                                "répertoires système (Windows)")

        # Match YARA (scanner YARITRUST). Cas à part, et c'est voulu : le
        # filtre `_chemin_suspect` ne s'applique PAS ici. Ailleurs, un chemin
        # ne devient un indicateur que par son emplacement, faute de mieux —
        # un scanner de signatures, lui, a DÉJÀ qualifié le contenu. Filtrer
        # sur le répertoire faisait disparaître les vrais IOC : un webshell
        # dans /usr/local/www/ (pfSense) ou /var/www/ hors liste passait à la
        # trappe, alors que c'est précisément le fichier à chercher.
        #
        # `data.file_path` est le chemin RÉEL sur la machine scannée ; le
        # préfixe du montage sshfs (/mnt/yaritrust/<hôte>_<ip>/) est retiré en
        # amont. C'est celui-là qu'il faut mettre dans le case : un analyste
        # doit pouvoir aller voir le fichier sur l'hôte concerné.
        yara = data.get("yara") or {}
        if yara or data.get("event_type") == "file_match":
            hote = yara.get("scanned_host") or data.get("hostname") or "?"
            score = data.get("score")
            suffixe = f" (score {score})" if score else ""
            # Nom de la première règle YARA qui a matché : ce qui dit CE qu'est
            # le fichier, et la seule chose vraiment réutilisable en chasse.
            raisons = data.get("reasons") or []
            regle = (raisons[0].get("message") or "").replace(
                "YARA match with rule ", "") if raisons else ""
            detail = f" — {regle}" if regle else ""
            # Normalisé dans les deux cas : `file_path` lui-même arrive préfixé
            # sur les alertes antérieures au correctif du scanner.
            ajouter_fichier(
                _chemin_cible(data.get("file_path") or yara.get("scan_path")),
                {"sha256": data.get("sha256"), "sha1": data.get("sha1"),
                 "md5": data.get("md5")},
                f"Fichier détecté par YARA sur {hote}{suffixe}{detail}")

        # Fichier jugé malveillant par VirusTotal. Même raison que pour YARA de
        # ne pas filtrer sur le répertoire : la qualification vient du moteur.
        #
        # DEUX conditions, apprises d'un exercice purple-team où deux des
        # trois IOC produits étaient du bruit pur :
        #
        #  1. VirusTotal doit avoir RENDU un verdict de malveillance. Le bloc
        #     ne testait que la présence d'un hash, si bien qu'une réponse
        #     `found=0, malicious=0` — VT ne connaît même pas le fichier —
        #     produisait un IOC intitulé « Fichier signalé par VirusTotal ».
        #     Un hash inconnu de VT n'est pas un indicateur de compromission.
        #  2. La cible doit être un FICHIER. L'intégration VT de Wazuh suit les
        #     événements FIM, registre compris : `source.file` valait ici
        #     `HKEY_LOCAL_MACHINE\System\...\bam\State\...`, une clé de registre.
        #     Une clé n'a pas de contenu à faire analyser, et le hash qui
        #     l'accompagne ne désigne aucun binaire.
        vt_bloc = data.get("virustotal", {}) or {}
        vt = vt_bloc.get("source", {}) or {}
        if _vt_malveillant(vt_bloc) and not _est_cle_registre(vt.get("file")):
            ajouter_fichier(vt.get("file"),
                            {"sha256": vt.get("sha256"), "sha1": vt.get("sha1"),
                             "md5": vt.get("md5")},
                            "Fichier signalé par VirusTotal "
                            f"({vt_bloc.get('malicious')} moteurs positifs)")

        # Fichier suspect modifié (FIM) : ici le répertoire compte, aucun moteur
        # n'a jugé le contenu.
        sc = raw.get("syscheck", {})
        if _chemin_suspect(sc.get("path")):
            ajouter_fichier(sc.get("path"),
                            {"sha256": sc.get("sha256_after"),
                             "sha1": sc.get("sha1_after"),
                             "md5": sc.get("md5_after")},
                            "Fichier modifié dans un emplacement suspect (FIM)")
    return out


def _grouper_regles(alertes: list[dict]) -> list[tuple[str, dict]]:
    """Alertes regroupées par règle, avec fenêtre temporelle, ordre chrono."""
    par: dict[str, dict] = {}
    for a in alertes:
        e = par.get(a["rule_id"])
        if e is None:
            par[a["rule_id"]] = {
                "level": a["rule_level"], "desc": a["rule_desc"] or "",
                "n": 1, "first": a["ts"], "last": a["ts"],
                "users": {a["srcuser"]} if a.get("srcuser") else set(),
                "entities": {a["entity"]} if a.get("entity") else set(),
                # Alertes du groupe : la timeline en réextrait les IOC pour
                # relier chaque évènement à ses indicateurs (onglet Graph).
                "alertes": [a]}
        else:
            e["n"] += 1
            e["alertes"].append(a)
            e["first"] = min(e["first"], a["ts"])
            e["last"] = max(e["last"], a["ts"])
            if a.get("srcuser"):
                e["users"].add(a["srcuser"])
            if a.get("entity"):
                e["entities"].add(a["entity"])
    return sorted(par.items(), key=lambda kv: kv[1]["first"])


def _uids_suspects(alertes: list[dict]) -> set[str]:
    """UID sous lesquels l'activité malveillante a tiré (alertes >= MIN_LEVEL).

    Sert à isoler les commandes de l'attaquant du bruit de fond. Une privesc par
    SUID garde l'uid réel du compte compromis (seul l'euid passe à 0) : filtrer
    sur cet uid capture donc TOUTE la chaîne, y compris les actions root.
    """
    uids: set[str] = set()
    for a in alertes:
        if a["rule_level"] < config.MIN_LEVEL:
            continue
        raw = a["raw"] if isinstance(a["raw"], dict) else json.loads(a["raw"])
        uid = (raw.get("data", {}).get("audit", {}) or {}).get("uid")
        if uid is not None:
            uids.add(str(uid))
    # Si un compte non-root est compromis (cas normal : service web, uid 33),
    # on écarte root : une privesc par SUID garde l'uid réel du compte, donc
    # les actions root de l'attaquant restent taguées à cet uid. Garder « 0 »
    # ne ferait qu'aspirer tous les démons root et la réponse SOC elle-même.
    non_root = uids - {"0"}
    return non_root or uids


# Commandes émises par la machinerie de session/login (systemd --user, gpg-agent,
# dbus), jamais par un shell d'attaquant. Le même uid porte la session légitime
# ET l'attaque : ce filtre écarte le résidu de bruit de login qui tomberait dans
# la fenêtre d'attaque. Best-effort, ancré sur le binaire (pas une simple
# mention) pour ne pas masquer une commande d'attaquant qui les nommerait.
_RE_BRUIT_SESSION = re.compile(
    r"\b(?:gpgconf|gpg-agent|dbus-launch|dbus-update-activation-environment|"
    r"systemd-xdg-autostart-generator)\b"
    r"|/usr/lib/systemd/"
    r"|systemctl\s+--user\s+set-environment"
    r"|enable-ssh-support"       # probe de config gpg-agent (ssh), bruit de login
    r"|^(?:systemd|30-systemd-envi)$",
    re.I)


# Bruit d'exécution Windows : commandes émises par la machinerie de l'endpoint,
# jamais par l'attaquant. Le fils `net1 user …` lancé par l'agent Wazuh (SCA,
# collecte d'inventaire) tirait les mêmes règles 92039 que l'énumération d'un
# attaquant et remplissait la section. Le parent est le discriminant : on ne
# masque une commande que sur ce que son PARENT est, pas sur son texte.
_RE_BRUIT_WIN_PARENT = re.compile(r"ossec-agent|wazuh-agent\.exe", re.I)
# Télémétrie/maintenance Microsoft, elle ancrée sur le binaire appelé.
_RE_BRUIT_WIN = re.compile(
    r"\b(?:CompatTelRunner|MpCmdRun|MpSigStub|TrustedInstaller|"
    r"consent|conhost)\.exe\b", re.I)


def _win_eventdata(raw: dict) -> dict:
    return ((raw.get("data", {}) or {}).get("win", {}) or {}).get("eventdata", {}) or {}


def _deswap_win(txt: str) -> str:
    """Les champs eventdata arrivent doublement échappés (`C:\\\\Windows`, `\\"`)
    du fait du double encodage JSON côté eventchannel, et les redirections sont
    entités-HTML (`&gt;`, `&amp;`). Rendu lisible pour l'analyste, sans toucher
    aux valeurs stockées."""
    return html.unescape(txt.replace("\\\\", "\\").replace('\\"', '"'))


# `powershell -enc <base64>` : la charge utile est en UTF-16LE. Non décodée, la
# ligne ne dit RIEN à l'analyste (et l'attaquant compte là-dessus). Les formes
# abrégées acceptées par PowerShell vont de `-e` à `-encodedcommand`.
_RE_ENCODEDCMD = re.compile(
    r"(-(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|"
    r"encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+)"
    r"([A-Za-z0-9+/=]{40,})", re.I)


def _decoder_encodedcommand(cmd: str) -> str:
    """Remplace la charge base64 d'un `-EncodedCommand` par son texte."""
    def repl(m):
        b64 = m.group(2)
        try:
            txt = base64.b64decode(b64 + "=" * (-len(b64) % 4)).decode("utf-16-le")
        except Exception:  # noqa: BLE001 — un blob non décodable reste tel quel
            return m.group(0)
        return f"{m.group(1)}<décodé> {' '.join(txt.split())}"
    return _RE_ENCODEDCMD.sub(repl, cmd)


def _users_suspects_win(alertes: list[dict]) -> set[str]:
    """Comptes Windows sous lesquels l'activité malveillante a tiré.

    Équivalent de `_uids_suspects` côté eventchannel. Pas d'exclusion analogue à
    celle de root : sous Windows le post-exploit tourne LÉGITIMEMENT en SYSTEM
    (service, tâche planifiée, PsExec), écarter SYSTEM effacerait l'attaque.
    """
    users: set[str] = set()
    for a in alertes:
        if a["rule_level"] < config.MIN_LEVEL:
            continue
        raw = a["raw"] if isinstance(a["raw"], dict) else json.loads(a["raw"])
        ed = _win_eventdata(raw)
        u = ed.get("user") or ed.get("subjectUserName")
        if u:
            users.add(_deswap_win(str(u)))
    return users


def _cmds_windows(alertes: list[dict]) -> tuple[list[tuple], set[str]]:
    """(ts, commande) reconstitués depuis Sysmon EID 1 / Security 4688.

    Pendant Windows de la reconstitution auditd : la section « Commandes
    exécutées » disait « aucune commande » sur TOUS les cases Windows, alors que
    la ligne de commande complète est dans `data.win.eventdata.commandLine`.
    Retourne aussi les comptes retenus, pour la phrase de portée.
    """
    users = _users_suspects_win(alertes)
    occ: list[tuple] = []
    for a in alertes:
        raw = a["raw"] if isinstance(a["raw"], dict) else json.loads(a["raw"])
        ed = _win_eventdata(raw)
        if not ed:
            continue
        u = ed.get("user") or ed.get("subjectUserName")
        if users and (not u or _deswap_win(str(u)) not in users):
            continue
        parent = _deswap_win(str(ed.get("parentCommandLine")
                                 or ed.get("parentImage") or ""))
        if parent and _RE_BRUIT_WIN_PARENT.search(parent):
            continue
        cmd = (ed.get("commandLine") or ed.get("processCommandLine")
               or ed.get("newProcessName") or ed.get("image") or "")
        cmd = _decoder_encodedcommand(_deswap_win(str(cmd)).strip())
        if not cmd or _RE_BRUIT_WIN.search(cmd):
            continue
        occ.append((a["ts"], cmd))
    return occ, users


def _clusters_lies_attaque(occ: list[tuple], anchors: list, gap) -> list[tuple]:
    """Ne garde que les commandes rattachées à l'attaque.

    `occ` : (ts, cmd) triés par ts. On segmente en clusters séparés par un
    silence > `gap`, et on ne conserve que ceux qui touchent (à moins de `gap`)
    une alerte malveillante (`anchors`, timestamps des alertes HIGH). Le bruit
    de session sous le même uid, isolé par un silence plus long, est écarté.
    Sans anchor, on ne filtre pas (on ne sait pas où est l'attaque).
    """
    if not occ or not anchors:
        return occ

    def touche(cluster: list[tuple]) -> bool:
        return any(min(abs(t - a) for a in anchors) <= gap for t, _ in cluster)

    gardees: list[tuple] = []
    cluster = [occ[0]]
    for prec, cur in zip(occ, occ[1:]):
        if cur[0] - prec[0] <= gap:
            cluster.append(cur)
        else:
            if touche(cluster):
                gardees += cluster
            cluster = [cur]
    if touche(cluster):
        gardees += cluster
    return gardees


def _section_commandes(alertes: list[dict]) -> str:
    """Historique des commandes de l'attaquant : auditd (Linux) ET Sysmon EID 1 /
    Security 4688 (Windows), fusionnés dans une seule chronologie — un case de
    campagne couvre les deux OS.

    Le proctitle (règle 80792, niv. 3) porte la ligne de commande complète. En
    descendant ATTACH_MIN_LEVEL à 3, ces alertes entrent dans l'incident : on
    déroule ici l'énumération et l'exploitation (find SUID, cat /etc/shadow,
    useradd, systemctl…) que les seules règles HIGH ne montraient pas.

    Deux filtres pour ne montrer QUE l'attaque, pas la session légitime du même
    compte : (1) rattachement temporel — on ne garde que les commandes formant
    un cluster contigu autour d'une alerte malveillante (`_clusters_lies_attaque`),
    ce qui écarte le burst d'init de login (gpg-agent, générateurs systemd) ;
    (2) filtre catégoriel — les commandes de la machinerie de session résiduelles
    tombées dans la fenêtre (`_RE_BRUIT_SESSION`). L'uid du compte compromis borne
    déjà le périmètre. Déterministe, note locale.
    """
    uids = _uids_suspects(alertes)
    anchors = [a["ts"] for a in alertes if a["rule_level"] >= config.MIN_LEVEL]
    gap = timedelta(seconds=config.COMMAND_CLUSTER_GAP_S)

    occ: list[tuple] = []
    for a in sorted(alertes, key=lambda x: x["ts"]):
        raw = a["raw"] if isinstance(a["raw"], dict) else json.loads(a["raw"])
        audit = raw.get("data", {}).get("audit", {}) or {}
        if uids and str(audit.get("uid")) not in uids:
            continue
        cmd = _decoder_proctitle(raw.get("full_log") or "").strip()
        if not cmd:
            cmd = str(audit.get("command") or "").strip()
        if not cmd or _RE_BRUIT_SESSION.search(cmd):
            continue
        occ.append((a["ts"], cmd))

    occ_win, users_win = _cmds_windows(alertes)
    occ = sorted(occ + occ_win, key=lambda o: o[0])

    # Rattachement à l'attaque, PUIS dédup (une commande vue dans le bruit ET
    # dans l'attaque doit être conservée avec son ts d'attaque).
    occ = _clusters_lies_attaque(occ, anchors, gap)
    vus: set[str] = set()
    cmds: list[tuple] = []
    for ts, cmd in occ:
        if cmd in vus:
            continue
        vus.add(cmd)
        cmds.append((ts, cmd))

    if not cmds:
        return ("## Commandes exécutées\n\nAucune commande "
                "reconstituée (pas d'alerte d'audit de commande dans le "
                "périmètre).")
    comptes = [f"uid {u}" for u in sorted(uids)] + sorted(users_win)
    portee = (f"sous le(s) compte(s) compromis {', '.join(comptes)}" if comptes
              else "tous comptes (compte compromis non identifié)")
    lignes = [
        "## Commandes exécutées",
        "",
        f"{len(cmds)} commandes distinctes reconstituées depuis la télémétrie "
        f"d'exécution ({portee}), rattachées à l'attaque, ordre chronologique :",
        "",
        "```",
    ]
    # Date incluse si les commandes s'étalent sur plusieurs jours UTC, sinon
    # l'heure seule rend l'ordre chronologique ambigu (mêmes HH:MM d'un jour à
    # l'autre).
    jours = {ts.astimezone(timezone.utc).date() for ts, _ in cmds}
    fmt = "%m-%d %H:%M:%S" if len(jours) > 1 else "%H:%M:%S"
    for ts, cmd in cmds[:80]:
        lignes.append(f"{ts.astimezone(timezone.utc):{fmt}}  {cmd[:300]}")
    if len(cmds) > 80:
        lignes.append(f"... (+{len(cmds) - 80} autres)")
    lignes.append("```")
    return "\n".join(lignes)


def _fmt_intervalle(first, last) -> str:
    """Fenêtre lisible. Ajoute la date (mm-jj) dès que l'intervalle franchit un
    jour UTC — sans elle, `%H:%M:%S` seul faisait paraître un span multi-jours à
    l'envers (ex. `15:44 → 13:47`, fin < début, alors que le dernier est le
    lendemain). first ≤ last est garanti par min/max en amont."""
    fu = first.astimezone(timezone.utc)
    lu = last.astimezone(timezone.utc)
    if lu == fu:
        return f"{fu:%H:%M:%S}"
    if fu.date() == lu.date():
        return f"{fu:%H:%M:%S} → {lu:%H:%M:%S}"
    return f"{fu:%m-%d %H:%M:%S} → {lu:%m-%d %H:%M:%S}"


# Au-delà de ce nombre d'occurrences pour une même règle, le compte reflète des
# tirs répétés (ex. une écriture /dev/tcp par cible balayée), pas autant
# d'évènements distincts : on l'annote pour ne pas surestimer l'ampleur.
_SEUIL_RAFALE = 500


def _lien_attaque(tid: str) -> str:
    """URL ATT&CK d'une technique. Une sous-technique T1547.006 vit sous
    `/techniques/T1547/006/`, pas `/techniques/T1547.006/`."""
    base, _, sous = tid.partition(".")
    return (f"https://attack.mitre.org/techniques/{base}/{sous}/" if sous
            else f"https://attack.mitre.org/techniques/{base}/")


def _section_mitre(alertes: list[dict]) -> str:
    """Tableau ATT&CK des techniques du case (déterministe, pas le LLM).

    Ce que les RÈGLES ont mappé, pas la seule technique retenue au triage : le
    triage n'en rend qu'une (celle qui a emporté sa décision), et un case
    d'exercice s'est ainsi résumé à « T1059.001 PowerShell » alors que les
    mêmes alertes portaient dcsync, golden ticket et pass-the-hash.

    Le nom et la tactique sortent de `rule.mitre` du log brut (les colonnes
    n'en gardent que les identifiants et les tactiques) ; ordre = première
    occurrence, le tableau se lit donc comme la progression de l'attaque.
    """
    techs: dict[str, dict] = {}
    for a in alertes:
        raw = a["raw"] if isinstance(a["raw"], dict) else json.loads(a["raw"])
        mitre = (raw.get("rule") or {}).get("mitre") or {}
        ids = list(mitre.get("id") or a.get("mitre_ids") or [])
        noms = list(mitre.get("technique") or [])
        tactiques = list(mitre.get("tactic") or a.get("mitre_tactics") or [])
        for i, tid in enumerate(ids):
            tid = str(tid).strip()
            if not tid:
                continue
            e = techs.setdefault(tid, {"nom": "", "tactiques": set(),
                                       "n": 0, "first": a["ts"]})
            # Les listes id/technique sont parallèles quand la règle mappe
            # plusieurs techniques ; on ne prend le nom que s'il est en face.
            if not e["nom"] and i < len(noms):
                e["nom"] = str(noms[i]).strip()
            e["tactiques"].update(str(t).strip() for t in tactiques if t)
            e["n"] += 1
            e["first"] = min(e["first"], a["ts"])

    if not techs:
        return ("## Techniques MITRE ATT&CK\n\nAucune technique mappée par les "
                "règles déclenchées sur cet incident.")
    lignes = [
        "## Techniques MITRE ATT&CK",
        "",
        f"{len(techs)} technique(s) mappée(s) par les règles Wazuh qui ont "
        "tiré, par ordre d'apparition :",
        "",
        "| Technique | Nom | Tactique(s) | Alertes |",
        "|:---|:---|:---|:---:|",
    ]
    for tid, e in sorted(techs.items(), key=lambda kv: (kv[1]["first"], kv[0])):
        nom = e["nom"] or "—"
        tac = ", ".join(sorted(e["tactiques"])) or "—"
        lignes.append(f"| [{tid}]({_lien_attaque(tid)}) | {nom} | {tac} "
                      f"| {e['n']} |")
    return "\n".join(lignes)


def _section_alertes(alertes: list[dict], agent_id: str) -> str:
    """Tableau des alertes Wazuh du case (déterministe, valeurs réelles).

    Regroupées par règle et ordonnées par première occurrence : le tableau se
    lit comme la chronologie de l'attaque. Colonne « Log » = deep-link Discover
    (référence markdown en bas de section : garde le tableau compact et évite
    les parenthèses de l'URL dans une cellule).
    """
    lignes = [
        "## Alertes Wazuh impliquées",
        "",
        f"{len(alertes)} alertes corrélées, regroupées par règle "
        "(ordre chronologique) :",
        "",
        "| Niveau | Règle | Occ. | Fenêtre UTC | Description | Log |",
        "|:---:|:---:|:---:|:---|:---|:---:|",
    ]
    refs = []
    for rid, e in _grouper_regles(alertes):
        fen = _fmt_intervalle(e["first"], e["last"])
        occ = f"{e['n']} ⚠️rafale" if e["n"] >= _SEUIL_RAFALE else str(e["n"])
        desc = (e["desc"][:78] + "…") if len(e["desc"]) > 78 else e["desc"]
        label = f"w-{rid}"
        lignes.append(f"| {e['level']} | {rid} | {occ} | {fen} | {desc} "
                      f"| [🔎][{label}] |")
        refs.append(f"[{label}]: <{_lien_wazuh(agent_id, rid, e['first'], e['last'])}>")
    lignes.append("")
    lignes.extend(refs)          # définitions de référence des liens Discover
    return "\n".join(lignes)


def _type_ioc_valeur(valeur: str) -> str:
    """Type d'IOC déduit de la seule valeur (pour un IOC déjà sur le case dont on
    n'a pas le type sous la main). Best-effort, aligné sur les types produits par
    `_iocs` : hash, ip, domain, sinon filename."""
    v = valeur.strip()
    if re.fullmatch(r"[0-9a-fA-F]{64}", v):
        return "sha256"
    if re.fullmatch(r"[0-9a-fA-F]{40}", v):
        return "sha1"
    if re.fullmatch(r"[0-9a-fA-F]{32}", v):
        return "md5"
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", v):
        return "ip-src"
    if "\\" not in v and "/" not in v and "." in v and " " not in v:
        return "domain"
    return "filename"


def _iocs_du_case(case, case_id: int, alertes: list[dict]) -> list[tuple[str, str, str]]:
    """IOC AUTORITAIRES du case = ceux réellement posés dans l'onglet IOC.

    Le rapport doit montrer EXACTEMENT la même liste que la section IOC du case,
    y compris les IOC hérités d'une salve précédente (un case de campagne est mis
    à jour plusieurs fois : la timeline/onglet IOC accumule, alors que `_iocs`
    recalculé sur les seules alertes du run courant en montrerait moins). On lit
    donc l'onglet IOC comme source de vérité. Le type/desc de la salve courante
    priment (frais) ; pour un IOC hérité sans type connu, on le déduit de la
    valeur. Ordre : IOC de la salve courante d'abord (ordre de `_iocs`), puis le
    reliquat hérité.

    Repli sur `_iocs(alertes)` si l'onglet est illisible : jamais moins que ce
    que le code sait extraire.
    """
    courant = _iocs(alertes)
    type_par_valeur = {v: t for v, t, _ in courant}
    desc_par_valeur = {v: d for v, _, d in courant}
    try:
        d = case.list_iocs(case_id).get_data() or {}
        tab = [(i.get("ioc_value"), i.get("ioc_description") or "")
               for i in (d.get("ioc") or []) if i.get("ioc_value")]
    except Exception as e:  # noqa: BLE001
        log.debug("lecture onglet IOC case #%s pour le rapport : %s", case_id, e)
        return courant
    if not tab:
        return courant
    ordre = [v for v, _, _ in courant]
    rang = {v: n for n, v in enumerate(ordre)}
    def cle(item):
        return rang.get(item[0], len(ordre))
    out: list[tuple[str, str, str]] = []
    for valeur, desc_tab in sorted(tab, key=cle):
        type_ioc = type_par_valeur.get(valeur) or _type_ioc_valeur(valeur)
        # Desc de la salve courante si dispo (la plus à jour), sinon celle du case.
        desc = desc_par_valeur.get(valeur) or desc_tab
        out.append((valeur, type_ioc, desc))
    return out


def _section_iocs(alertes: list[dict],
                  iocs: list[tuple[str, str, str]] | None = None) -> str:
    """Tableau des IOC extraits (déterministe). Note locale : valeurs réelles.

    `iocs` fourni = liste autoritaire de l'onglet IOC du case (cf. `_iocs_du_case`)
    pour que le rapport montre EXACTEMENT la même chose. Absent = recalcul sur les
    alertes (cas d'un rendu hors case)."""
    if iocs is None:
        iocs = _iocs(alertes)
    if not iocs:
        return "## Indicateurs de compromission (IOC)\n\nAucun IOC extractible " \
               "automatiquement des champs d'alerte."
    lignes = [
        "## Indicateurs de compromission (IOC)",
        "",
        "| Type | Valeur | Contexte |",
        "|:---|:---|:---|",
    ]
    for valeur, type_ioc, desc in iocs:
        v = valeur.replace("|", "\\|")
        lignes.append(f"| {type_ioc} | `{v}` | {desc} |")
    return "\n".join(lignes)


# Rendu lisible du statut d'une remédiation.
#
# Ne JAMAIS afficher « ✅ » sur autre chose qu'un compte rendu de l'agent. Le
# canal d'active response est fire-and-forget : au moment de l'appel, tout ce
# qu'on sait est que l'API a pris la commande. L'ancien libellé « ✅ exécuté »
# était accolé à ce simple accusé de réception, et un rapport d'exercice
# purple-team a affirmé à l'analyste que des dizaines de binaires System32
# d'un contrôleur de domaine avaient été mis en quarantaine — le script les
# avait tous refusés. Un rapport qui ment est pire qu'un rapport incomplet.
_STATUT_REMED = {
    "émis": "📤 commande émise (effet non encore confirmé)",
    "confirmé": "✅ confirmé par l'agent",
    "sans_effet": "⚪ sans effet (rien à faire sur cette cible)",
    "refusé_agent": "🛑 refusé par le garde-fou de l'agent",
    "dry_run": "🟡 simulé (dry-run)",
    "sans_canal": "📄 documenté (manuel)",
    "échec": "❌ échec",
    "annulé": "↩️ annulé (défait)",
}


def _section_remediations(conn, incident_id: int, triage: dict) -> str:
    """Récapitulatif des remédiations RÉELLEMENT exécutées (table mitigations).

    Remplace l'ancienne liste « proposée » : les actions sont désormais lancées
    automatiquement à l'ouverture du case ; on rend compte de ce qui a été fait,
    pas de ce qui pourrait l'être.
    """
    rows = conn.execute(
        "SELECT action, cible, statut FROM mitigations WHERE incident_id = %s "
        "ORDER BY id", (incident_id,)).fetchall()
    lignes = ["## Remédiations"]

    if not rows:
        remed = [a for a in triage.get("actions", [])
                 if a in LIBELLE_ACTION and a.startswith("propose_")]
        lignes.append("")
        if remed:
            lignes.append("Aucune remédiation automatique n'a pu s'appliquer "
                          "(pas de cible exploitable). Actions décidées au "
                          "triage :")
            lignes += [f"- {LIBELLE_ACTION.get(a, a)}" for a in remed]
        else:
            lignes.append("Aucune remédiation à exécuter pour cet incident.")
        return "\n".join(lignes)

    lignes += [
        "",
        "Actions lancées automatiquement par le soc-agent à l'ouverture du "
        "case. Procédures d'annulation détaillées dans le répertoire "
        "« Remédiations ».",
        "",
        "Le statut est celui **rapporté par l'agent**, pas celui de l'appel "
        "d'API : le canal d'active response ne renvoie pas le code de retour du "
        "script, donc une commande partie n'est pas une action faite. Une ligne "
        "« commande émise » qui ne se confirme pas signale un script mort avant "
        "son compte rendu, ou un agent qui ne remonte pas "
        "`active-responses.log`.",
        "",
        "| Action | Cible | Statut |",
        "|:---|:---|:---:|",
    ]
    for r in rows:
        libelle = LIBELLE_ACTION.get(r["action"], r["action"])
        statut = _STATUT_REMED.get(r["statut"], r["statut"])
        lignes.append(f"| {libelle} | `{r['cible']}` | {statut} |")

    refuses = [r for r in rows if r["statut"] == "refusé_agent"]
    if refuses:
        lignes += [
            "",
            f"> **{len(refuses)} action(s) refusée(s) par un garde-fou de "
            "l'agent.** Le garde-fou a fait son travail, mais le soc-agent a "
            "visé une cible qu'il n'aurait pas dû retenir : la résolution de "
            "cibles est à revoir pour ce type d'incident.",
        ]
    return "\n".join(lignes)


def _note_fp(triage: dict, regle: dict | None) -> str:
    """Note d'analyse d'un faux positif, avec l'explication de whitelist.

    Pure : `regle` est la ligne whitelist_rules correspondant à la signature de
    l'incident (ou None), fournie par l'appelant. Testable sans base.
    """
    lignes = [
        "# Analyse — Faux positif",
        "",
        "## Justification",
        triage["reason"],
        "",
        "## Whitelist",
    ]
    if regle:
        etat = "active" if regle["active"] else "inactive"
        lignes += [
            f"Une exception **{etat}** ({regle['source']}) couvre désormais cette "
            "signature — les alertes identiques seront écartées avant analyse :",
            "",
            f"```json\n{json.dumps(regle['match_all'], ensure_ascii=False, indent=2)}\n```",
            "",
            f"Motif : {regle['reason']}",
        ]
    else:
        lignes.append("Pas encore d'exception : ce faux positif n'a pas atteint "
                      "le seuil de récurrence, ou sa signature est trop large "
                      "pour une whitelist automatique sûre.")
    return "\n".join(lignes)


def _regle_whitelist(conn, alertes: list[dict]) -> dict | None:
    """Ligne whitelist_rules correspondant à la signature de l'incident."""
    raws = [a["raw"] if isinstance(a["raw"], dict) else json.loads(a["raw"])
            for a in alertes]
    signature = _signature(raws)
    if not signature:
        return None
    return conn.execute(
        "SELECT match_all, reason, source, active FROM whitelist_rules "
        "WHERE signature = %s", (_canonique(signature),)).fetchone()


# Familles de capteurs, repérées par les groupes de règles qu'elles produisent.
# Sert à dire au modèle — et à l'analyste — ce qui était RÉELLEMENT collecté sur
# l'hôte. Une règle comportementale sans son capteur n'est pas une absence
# d'attaque, c'est un angle mort : mesuré le 2026-07-29, auditd était absent sur
# toute la flotte, les règles 1006xx muettes, et le case ne le disait pas.
# « réseau / IDS (hôte) » : Suricata tourne au périmètre (pfSense), pas sur
# l'hôte — de son point de vue, il n'a aucune visibilité sur son propre trafic.
# « exécution de processus » n'est PAS que auditd : sur Windows la création de
# processus (avec ligne de commande) vient de Sysmon EID1 et du 4688 de
# l'eventchannel, et le contenu des scripts du canal PowerShell. La campagne #4
# a montré le coût de l'omission : sur le DC (Sysmon présent), le rapport se
# croyait aveugle aux lignes de commande et ratait DCSync/Golden/création de
# Domain Admin, MITRE effondré sur T1059.001. Ces groupes rendent la présence
# visible pour que le modèle analyse enfin les cmdlines.
_CAPTEURS = (
    ("exécution de processus (auditd / Sysmon EID1 / 4688)",
     {"audit", "sysmon_event1", "sysmon_eid1_detections",
      "windows_powershell", "powershell"}),
    ("intégrité fichier (FIM)", {"syscheck", "syscheck_file"}),
    ("authentification", {"sshd", "pam", "authentication_success",
                          "authentication_failed", "invalid_login"}),
    ("réseau / IDS (hôte)", {"suricata", "ids"}),
)


def _capteurs_actifs(conn, agent_id: str) -> str:
    """Ligne « télémétrie disponible sur cet hôte », d'après les groupes de
    règles réellement émis par l'agent sur la fenêtre récente. Factuel : ancre
    la section « couverture » du rapport pour qu'elle ne soit pas inventée."""
    rows = conn.execute(
        "SELECT DISTINCT unnest(rule_groups) g FROM alerts "
        "WHERE agent_id = %s AND ts >= now() - interval '7 days'",
        (agent_id,)).fetchall()
    vus = {r["g"] for r in rows}
    etats = [f"{libelle}={'présent' if vus & groupes else 'ABSENT'}"
             for libelle, groupes in _CAPTEURS]
    return "télémétrie disponible sur cet hôte : " + ", ".join(etats)


# Comptes présents sur tout hôte : lier deux incidents dessus n'a aucun sens.
_COMPTES_GENERIQUES = {"root", "admin", "administrator", "www-data", "nobody",
                       "daemon", "sync", "postgres", "mysql", "-", ""}

# La flotte est en conteneurs LXC ; l'auditd tourne sur l'hôte Proxmox (agent
# pve) et voit l'execve de TOUS les conteneurs. L'enrichisseur `soc-audit-enrich`
# tague chaque record du conteneur d'origine (`lxc_ct=<nom>`, cf.
# src/wazuh/agents/pve/). On l'extrait ici pour que le case dise « jellyfin » et pas
# « pve ». Valeurs réelles, note locale — jamais envoyé au LLM (nom d'hôte).
_LXC_CT = re.compile(r"lxc_ct=([A-Za-z0-9_.-]+)")


def _conteneurs(alertes: list[dict]) -> list[str]:
    """Conteneurs LXC d'origine, extraits du full_log enrichi. Ignore host et
    unknown (exec court non résolu). Vide si l'hôte n'est pas l'agent pve."""
    vus: set[str] = set()
    for a in alertes:
        raw = a.get("raw")
        raw = raw if isinstance(raw, dict) else json.loads(raw) if raw else {}
        for ct in _LXC_CT.findall(str(raw.get("full_log", ""))):
            if ct not in ("host", "unknown"):
                vus.add(ct)
    return sorted(vus)


def _incidents_lies(conn, incident: dict) -> list[dict]:
    """Cases IRIS ouverts sur d'AUTRES agents partageant une entité forte (même
    IP, même fichier, même compte) dans une fenêtre ±ENTITY_GAP autour de
    celui-ci.

    La corrélation principale est cloisonnée par agent (correlate.py) — un pivot
    d'un hôte à l'autre est donc invisible par construction. Cette passe le
    rattrape a posteriori SANS fusionner : on signale le lien à l'analyste. Le
    2026-07-29 le pivot bookstack -> jellyfin n'apparaissait dans aucun case.

    Seuls les incidents ayant un case IRIS sont retournés : la section renvoie
    l'analyste vers un dossier ouvrable, pas vers un identifiant interne de la
    base soc-agent qu'il ne peut consulter nulle part. Le case du présent
    incident est exclu — la fusion campagne (`_fondre_campagne`) met plusieurs
    incidents, y compris d'autres hôtes, sur un même case."""
    marge = timedelta(minutes=config.ENTITY_GAP_MINUTES)
    traits = conn.execute(
        "SELECT DISTINCT srcip, entity, srcuser FROM alerts WHERE incident_id=%s",
        (incident["id"],)).fetchall()
    # IP source et fichier sont des liens forts. Le COMPTE, non : `root` (ou
    # www-data, admin…) existe sur chaque hôte — lier dessus rapprocherait tous
    # les incidents entre eux. On écarte donc les comptes génériques, on garde
    # les shells génériques déjà exclus côté corrélation.
    valeurs = {t["srcip"] for t in traits if t["srcip"]}
    valeurs |= {t["entity"] for t in traits
                if t["entity"] and not correlate.entite_generique(t["entity"])}
    valeurs |= {t["srcuser"] for t in traits
                if t["srcuser"] and t["srcuser"].lower() not in _COMPTES_GENERIQUES}
    if not valeurs:
        return []
    liste = list(valeurs)
    rows = conn.execute(
        """SELECT DISTINCT i.id, i.agent_name, i.iris_case_id,
                  a.srcip, a.entity, a.srcuser
             FROM incidents i JOIN alerts a ON a.incident_id = i.id
            WHERE i.id <> %s AND i.agent_id <> %s
              AND i.iris_case_id IS NOT NULL
              AND i.iris_case_id IS DISTINCT FROM %s
              AND i.last_seen >= %s AND i.first_seen <= %s
              AND (a.srcip = ANY(%s) OR a.entity = ANY(%s) OR a.srcuser = ANY(%s))
            ORDER BY i.id""",
        (incident["id"], incident["agent_id"], incident.get("iris_case_id"),
         incident["first_seen"] - marge, incident["last_seen"] + marge,
         liste, liste, liste)).fetchall()
    # Regroupement par CASE : un case de campagne porte plusieurs incidents, il
    # ne doit apparaître qu'une fois — avec tous les hôtes qu'il couvre.
    par_case: dict[int, dict] = {}
    for r in rows:
        partage = next((v for v in (r["srcip"], r["entity"], r["srcuser"])
                        if v and v in valeurs), None)
        if not partage:
            continue
        e = par_case.setdefault(r["iris_case_id"],
                                {"case_id": r["iris_case_id"],
                                 "agents": set(), "entites": set()})
        e["agents"].add(r["agent_name"] or "?")
        e["entites"].add(partage)
    return sorted(par_case.values(), key=lambda e: e["case_id"])


def _lien_case(case_id: int) -> str:
    """URL du case IRIS. Relative à dessein : la note est lue DANS IRIS, et
    `config.IRIS_URL` vaut la loopback du serveur (127.0.0.1:8443) — un lien
    absolu construit dessus serait mort pour l'analyste, qui accède à IRIS par
    l'adresse du parc."""
    return f"/case?cid={case_id}"


def _section_cases_lies(lies: list[dict]) -> str:
    """Note locale (valeurs réelles). Construite en Python, JAMAIS envoyée au
    LLM : les hostnames des autres hôtes ne partent pas vers le cloud."""
    if not lies:
        return ""
    lignes = ["## Cases liés (autres hôtes)", "",
              "Rapprochement par entité partagée, hors du cloisonnement par "
              "agent — possible mouvement latéral ou campagne à investiguer :",
              "",
              "| Case | Hôte(s) | Entité commune |",
              "|:---:|:---|:---|"]
    for l in lies:
        agents = ", ".join(f"**{a}**" for a in sorted(l["agents"]))
        # Une campagne partage souvent une dizaine d'entités : au-delà de 3 la
        # cellule devient illisible et n'ajoute rien — le case lié est ouvrable.
        ents = sorted(l["entites"])
        ent = ", ".join(f"`{e}`" for e in ents[:3])
        if len(ents) > 3:
            ent += f" (+{len(ents) - 3})"
        lignes.append(f"| [#{l['case_id']}]({_lien_case(l['case_id'])}) "
                      f"| {agents} | {ent} |")
    return "\n".join(lignes) + "\n"


# --------------------------------------------------------------------------
# Exposition aux vulnérabilités de la machine touchée
# --------------------------------------------------------------------------
#
# Pourquoi cette section existe : un case dit ce que l'attaquant a FAIT, jamais
# ce qu'il aurait pu faire. Or la même intrusion sur un hôte à jour et sur un
# hôte qui traîne quatorze CVE critiques n'appelle pas la même suite — dans le
# second cas, la remédiation de l'incident ne referme pas la porte. L'analyste
# avait l'information (dashboard VOC) mais devait aller la chercher, sur la
# bonne machine, en croisant lui-même avec la priorité de l'asset.
#
# Trois règles de rédaction, tenues strictement :
#
#  1. Ce qui est CERTAIN et ce qui est PROBABLE ne se mélangent pas. Une CVE
#     citée dans une commande de l'attaquant est un fait ; une CVE critique
#     ouverte sur une machine où l'on voit du T1068 est une piste. Les deux
#     apparaissent, sous des titres différents, avec la nuance écrite.
#  2. « Aucune vulnérabilité connue » et « jamais inventoriée » sont deux
#     affirmations opposées. La seconde est un angle mort et doit être dite —
#     c'est la même leçon que la ligne « télémétrie disponible » des rapports.
#  3. Rien de tout cela ne part au modèle en clair. Seul un résumé chiffré, sans
#     nom d'hôte ni de paquet, lui est fourni comme métadonnée de confiance.

def _lien_cve(cve: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cve}"


def _table_cve(lignes: list[dict], avec_age: bool = True) -> list[str]:
    """Table Markdown de vulnérabilités. Colonnes stables d'un bloc à l'autre
    pour que l'analyste ne relise pas l'en-tête à chaque section."""
    tete = ["| CVE | Sévérité | CVSS | Paquet | Version |"
            + (" Ouverte depuis |" if avec_age else ""),
            "|:---|:---|---:|:---|:---|" + ("---:|" if avec_age else "")]
    for v in lignes:
        age = f" {v['age_jours']:.0f} j |" if avec_age else ""
        tete.append(
            f"| [{v['cve']}]({_lien_cve(v['cve'])}) "
            f"| {(v['severite'] or 'non classée').capitalize()} "
            f"| {v['score_base'] if v['score_base'] is not None else '—'} "
            f"| `{v['paquet']}` | {v['version'] or '—'} |{age}")
    return tete


def _note_exposition(conn, incident: dict, alertes: list[dict]) -> str:
    """Note « Exposition aux vulnérabilités » de la machine du case.

    Construite en Python à partir du journal VOC (`soc_agent.vulns`) : valeurs
    réelles, aucun appel au modèle. Rend toujours une note — y compris quand la
    machine n'a jamais été inventoriée, cas où l'absence de donnée EST
    l'information.
    """
    from . import vulns   # import différé : vulns importe assets, pas iris.

    agent_id = str(incident["agent_id"])
    expo = vulns.exposition(conn, agent_id)
    lien = vulns.lien_incident(conn, agent_id, alertes, expo)

    lignes = [f"# {TITRE_EXPOSITION}", "",
              f"Machine **{incident.get('agent_name') or agent_id}** "
              f"(agent {agent_id}), "
              f"priorité **P{expo['priorite']}** "
              f"({expo['role'] or 'rôle non déclaré'}).", ""]

    if not expo["couverte"]:
        lignes += [
            "> ⚠️ **Cette machine n'a jamais été inventoriée** par le module "
            "Vulnerability Detection de Wazuh. Il n'y a donc aucune donnée de "
            "vulnérabilité à son sujet — ce qui n'est **pas** la même chose que "
            "« aucune vulnérabilité ». Causes usuelles : système d'exploitation "
            "absent du feed CTI (BSD, appliance), ou `syscollector` muet sur "
            "l'agent.",
            "",
            "Vérifier avec `python -m soc_agent.vulns --agent "
            f"{agent_id}` et l'inventaire de paquets côté API Wazuh "
            "(`/syscollector/<agent>/packages`).",
        ]
        return "\n".join(lignes) + "\n"

    # --- Score et répartition ---------------------------------------------
    sev_lisible = {"critical": "Critical", "high": "High", "medium": "Medium",
                   "low": "Low", "": "non classée"}
    repartition = ", ".join(
        f"**{n}** {sev_lisible.get(s, s)}"
        for s, n in sorted(expo["par_severite"].items(),
                           key=lambda kv: -vulns.poids(kv[0])))

    lignes += [
        f"| | |", "|---|---|",
        f"| **Score d'exposition** | **{expo['score']}/100** — "
        f"exposition {expo['niveau']} |",
        f"| **Vulnérabilités ouvertes** | {expo['total']} ({repartition}) |",
        f"| **Hors délai de correction** | {expo['hors_sla_total']} |",
        f"| **Plus ancienne ouverte** | {expo['plus_ancienne_jours']:.0f} jours |",
        (f"| **Corrigées sur 90 jours** | {expo['corrigees_90j']} "
         f"(délai moyen {expo['mttr_jours']} j) |"
         if expo["mttr_jours"] is not None
         else f"| **Corrigées sur 90 jours** | {expo['corrigees_90j']} |"),
        "",
        # Le score est log-compressé et pondéré : sans cette phrase, un lecteur
        # le prendrait pour un pourcentage de machines vulnérables ou pour une
        # note d'audit. Il faut aussi dire qu'il sature, sinon deux machines à
        # 100 passeraient pour équivalentes.
        f"Le score agrège les vulnérabilités ouvertes pondérées par leur "
        f"sévérité (charge {expo['charge']}), multipliées par le facteur de "
        f"priorité de l'asset (×{expo['facteur_priorite']}), sur une échelle "
        f"logarithmique. Il sert à **classer** les machines entre elles, pas à "
        f"mesurer un risque absolu : au-delà du plafond il sature, et ce sont "
        f"alors les compteurs ci-dessus qui départagent.",
        "",
    ]

    # --- Lien avec CE case ------------------------------------------------
    if lien["confirmees"]:
        lignes += [
            "## Vulnérabilités citées dans l'incident",
            "",
            "Ces CVE apparaissent **littéralement** dans les évènements du case "
            "(ligne de commande, nom de fichier, requête) **et** sont ouvertes "
            "sur cette machine. C'est le seul rapprochement certain entre "
            "l'incident et l'exposition : ce que l'attaquant visait était "
            "effectivement présent ici.",
            "",
        ] + _table_cve(lien["confirmees"]) + [
            "",
            "**Conséquence directe** : remédier l'incident ne suffit pas. Tant "
            "que ces paquets ne sont pas corrigés, le même accès reste "
            "reproductible.",
            "",
        ]

    if lien["citees_non_ouvertes"]:
        lignes += [
            "## Vulnérabilités citées mais non ouvertes ici",
            "",
            "CVE mentionnées dans les évènements du case, mais absentes de "
            "l'inventaire de cette machine : tentative contre une version non "
            "vulnérable, reconnaissance à l'aveugle, ou vulnérabilité déjà "
            "corrigée depuis. C'est une information sur la MÉTHODE de "
            "l'attaquant, pas sur l'exposition de l'hôte.",
            "",
            ", ".join(f"[{c}]({_lien_cve(c)})"
                      for c in lien["citees_non_ouvertes"]),
            "",
        ]

    if lien["vecteurs_possibles"]:
        lignes += [
            "## Vecteurs possibles (hypothèse, non démontrée)",
            "",
            f"L'incident porte une ou des techniques d'exploitation "
            f"({', '.join(lien['techniques_exploit'])}) et cette machine a des "
            f"vulnérabilités graves ouvertes. **Aucun élément du case ne relie "
            f"ces CVE à l'attaque** : elles sont listées parce qu'un analyste "
            f"qui cherche par où l'accès a été obtenu doit les avoir sous les "
            f"yeux, pas parce qu'elles ont été exploitées.",
            "",
        ] + _table_cve(lien["vecteurs_possibles"]) + [""]

    # --- Retard de correction ---------------------------------------------
    if expo["hors_sla"]:
        top = expo["hors_sla"][:config.VOC_MAX_CVE_RAPPORT]
        lignes += [
            "## Vulnérabilités hors délai",
            "",
            f"{expo['hors_sla_total']} vulnérabilité(s) ouverte(s) au-delà du "
            f"délai attendu pour leur sévérité sur un asset P{expo['priorite']}"
            + (f" — les {len(top)} plus en retard :" if len(top) < expo['hors_sla_total']
               else " :"),
            "",
            "| CVE | Sévérité | Paquet | Ouverte depuis | Délai | Retard |",
            "|:---|:---|:---|---:|---:|---:|",
        ] + [
            f"| [{v['cve']}]({_lien_cve(v['cve'])}) "
            f"| {(v['severite'] or 'non classée').capitalize()} "
            f"| `{v['paquet']}` | {v['age_jours']:.0f} j "
            f"| {v['sla_jours']} j | **+{v['retard_jours']:.0f} j** |"
            for v in top
        ] + [""]

    # --- Repli : rien de spécifique au case -------------------------------
    if not (lien["confirmees"] or lien["vecteurs_possibles"]
            or expo["hors_sla"]):
        lignes += [
            "## Pires vulnérabilités ouvertes",
            "",
            "Aucune CVE n'est citée dans les évènements de ce case et aucune "
            "vulnérabilité n'est hors délai : **rien ne rattache cet incident à "
            "l'exposition de la machine**. Le contexte reste utile pour évaluer "
            "ce qu'une compromission d'ici permettrait ensuite.",
            "",
        ] + _table_cve(expo["pires"]) + [""]

    lignes += [
        "---",
        "",
        f"Source : module Vulnerability Detection de Wazuh, journalisé par "
        f"`soc_agent.vulns` (index `{config.VOC_INDEX_PREFIX}-*`, dashboard "
        f"VOC). Les délais de correction sont des objectifs de service internes "
        f"définis par sévérité et priorité d'asset, pas une norme externe. Le "
        f"feed indique ce que les distributions publient : il ne dit **rien** "
        f"de l'exploitabilité réelle ni de l'exposition réseau du service "
        f"concerné.",
    ]
    return "\n".join(lignes) + "\n"


def _poser_exposition(case, case_id: int, conn, incident: dict,
                      alertes: list[dict]) -> None:
    """Pose la note d'exposition. Best-effort : le VOC est un enrichissement,
    son indisponibilité ne doit jamais empêcher un case de s'ouvrir."""
    try:
        _poser_note(case, case_id, TITRE_EXPOSITION,
                    _note_exposition(conn, incident, alertes),
                    repertoire=DIR_EXPOSITION)
    except Exception as e:  # noqa: BLE001
        log.warning("note d'exposition case #%s : %s", case_id, e)


def _resume_exposition(conn, agent_id: str, alertes: list[dict]) -> str:
    """Ligne d'exposition destinée au MODÈLE, en métadonnée de confiance.

    Volontairement chiffrée et anonyme : ni nom d'hôte, ni nom de paquet, ni
    version. Les identifiants CVE, eux, passent — ce sont des références
    publiques, et c'est justement l'information qui permet au modèle de relier
    une commande d'exploitation à une vulnérabilité réellement présente. Sans
    cette ligne, le rapport écrivait « aucun élément ne permet de savoir si la
    machine était vulnérable » alors que le SOC le savait.
    """
    try:
        from . import vulns
        expo = vulns.exposition(conn, str(agent_id))
        if not expo["couverte"]:
            return ("exposition aux vulnérabilités : machine JAMAIS "
                    "inventoriée (aucune donnée — ne pas conclure qu'elle est "
                    "à jour)")
        lien = vulns.lien_incident(conn, str(agent_id), alertes, expo)
        bout = (f"exposition aux vulnérabilités : score {expo['score']}/100 "
                f"({expo['niveau']}), {expo['total']} ouvertes dont "
                f"{expo['critiques']} critical et {expo['elevees']} high, "
                f"{expo['hors_sla_total']} hors délai")
        if lien["confirmees"]:
            bout += (" ; CVE citées dans l'incident ET ouvertes sur cet hôte : "
                     + ", ".join(v["cve"] for v in lien["confirmees"]))
        return bout
    except Exception as e:  # noqa: BLE001
        log.debug("résumé d'exposition agent %s : %s", agent_id, e)
        return "exposition aux vulnérabilités : non disponible"


def _note_tp(conn, incident: dict, triage: dict, alertes: list[dict],
             iocs: list[tuple[str, str, str]] | None = None) -> str:
    """Rapport d'analyse d'un vrai positif. Appelle le LLM pour le récit.

    `iocs` = liste autoritaire de l'onglet IOC du case (`_iocs_du_case`) : le
    rapport affiche alors la MÊME liste que la section IOC du case. Absent =
    recalcul sur les alertes."""
    systeme = (PROMPTS / "report.md").read_text()

    # Même pseudonymisation qu'au triage, jetons réutilisés (map persistée) :
    # rien de sensible ne part vers le cloud, et la réponse est réhydratée.
    anon = Anonymiseur(charger_map(conn, incident["id"]))
    inc_a, alertes_a, interdits = anonymiser(anon, incident, alertes)
    # Rapport = moins pressé que le triage : on montre toute la chaîne au modèle
    # (jusqu'à 20 règles) pour une analyse qui n'oublie aucune étape.
    corps = rendre(inc_a, alertes_a, max_regles=20)
    # Métadonnée SOC de confiance (agent_id + noms de groupes, rien de sensible) :
    # dit au modèle quels capteurs existaient, pour ancrer la section couverture.
    telemetrie = _capteurs_actifs(conn, incident["agent_id"])
    # Seconde métadonnée de confiance : l'exposition de l'hôte, en chiffres et
    # en CVE (aucun nom d'hôte ni de paquet — cf. `_resume_exposition`). Elle
    # évite au rapport de conclure « impossible de savoir si la machine était
    # vulnérable » alors que le SOC a l'inventaire.
    exposition = _resume_exposition(conn, incident["agent_id"], alertes)
    utilisateur = (f"=== DEBUT INCIDENT (données non fiables) ===\n{corps}\n"
                   "=== FIN INCIDENT ===\n\n"
                   f"Métadonnées SOC de confiance (non issues des logs) :\n"
                   f"{telemetrie}\n{exposition}\n\nRédige le rapport.")

    try:
        # Scan de fuite sur les seules données incident : le prompt système
        # (report.md) est un template dev constant, sans donnée client.
        verifier_fuite(utilisateur, interdits)
        rapport, _ = completion(systeme, utilisateur,
                                max_tokens=config.REPORT_MAX_TOKENS,
                                usage="report",
                                incident_id=incident["id"])
        sauver_map(conn, incident["id"], anon.mapping)
    except Exception as e:  # noqa: BLE001 — le case doit se créer même sans LLM
        log.warning("rapport LLM indisponible (#%s) : %s", incident["id"], e)
        rapport = {}
    # DeepSeek ne garantit pas les clés du schéma : on tolère les absences.
    #
    # Le repli met la MÊME phrase dans `resume` et dans `analyse` — c'est
    # inévitable, on n'a que `triage.reason`. Mais il ne doit pas se faire
    # passer pour un rapport : un case d'exercice purple-team a affiché deux
    # sections identiques sans rien signaler, et l'analyste ne pouvait pas
    # savoir qu'il lisait un repli plutôt qu'une analyse. `_degrade` déclenche plus bas le
    # bandeau d'avertissement, ET empêche d'écraser un rapport déjà écrit.
    degrade = "analyse" not in rapport
    rapport.setdefault("resume", triage["reason"])
    rapport.setdefault("analyse", triage["reason"])
    # Réhydratation : les jetons redeviennent les vraies valeurs pour l'analyste.
    # Puis correction des coquilles d'accent récurrentes du modèle.
    for cle in ("resume", "analyse"):
        rapport[cle] = _corriger_accents(rehydrater(rapport[cle], anon.mapping))

    cts = _conteneurs(alertes)
    lignes = ["# Rapport d'analyse — Vrai positif", ""]
    # Plus de technique en en-tête : le triage n'en rend QU'UNE, celle qui a
    # emporté sa décision, et elle n'est même pas toujours dans le mapping des
    # règles (case 129 : en-tête T1098, table ATT&CK sans T1098). La couverture
    # ATT&CK est la section « Techniques MITRE ATT&CK », construite sur ce que
    # les règles ont réellement mappé. `triages.mitre` reste tracé en base.
    # Attribution conteneur : l'agent est l'hôte Proxmox (pve) ; le vrai théâtre
    # est le conteneur LXC résolu par l'enrichisseur auditd.
    if cts:
        lignes.append(f"**Conteneur(s) concerné(s)** : {', '.join(cts)} "
                      f"(exécution vue par l'auditd de l'hôte {incident['agent_name']})")
    if degrade:
        lignes += [
            "",
            "> ⚠️ **Rapport dégradé — l'analyse LLM n'a pas abouti.** Les deux "
            "sections ci-dessous reprennent la justification du triage, faute "
            "de mieux. Il n'y a donc PAS eu de reconstitution de la chaîne "
            "d'attaque ici : voir la table des alertes et les IOC plus bas. "
            "Cause la plus fréquente : budget de tokens épuisé par le "
            "raisonnement du modèle (`REPORT_MAX_TOKENS`).",
        ]
    lignes += [
        "",
        "## Résumé",
        rapport["resume"],
        "",
        "## Analyse",
        rapport["analyse"],
        "",
    ]
    lignes += [
        _section_cases_lies(_incidents_lies(conn, incident)),
        _section_commandes(alertes),
        "",
        _section_alertes(alertes, incident["agent_id"]),
        "",
        _section_iocs(alertes, iocs),
        "",
        _section_mitre(alertes),
        "",
        _section_remediations(conn, incident["id"], triage),
        "",
        _section_remediation_hors_portee(triage, alertes),
    ]
    return "\n".join(lignes)


def _alertes(conn, incident_id: int) -> list[dict]:
    return conn.execute(
        "SELECT id, ts, rule_id, rule_level, rule_desc, rule_groups, "
        "mitre_ids, mitre_tactics, srcip, srcuser, entity, raw "
        "FROM alerts WHERE incident_id = %s "
        "ORDER BY ts", (incident_id,)).fetchall()


def _traits(conn, incident_id: int) -> list[dict]:
    """Champs de parenté/identité d'un incident (colonnes, sans parser le raw)."""
    return conn.execute(
        "SELECT srcip, srcuser, entity, mitre_tactics, rule_groups, audit_uid "
        "FROM alerts WHERE incident_id = %s", (incident_id,)).fetchall()


def _identite_forte(traits: list[dict]) -> tuple[set[str], set[str]]:
    """Ce qui NOMME l'intrusion : comptes (uid) et IP compromis. Discriminant.

    Root (uid 0) est écarté : une privesc SUID le fait apparaître partout, il ne
    distingue pas deux intrusions. Deux incidents dont les identités fortes sont
    non vides ET disjointes sont des attaques DIFFÉRENTES — jamais à fondre (deux
    chaînes simultanées, uid 1001 vs uid 33/www-data, doivent rester deux cases).
    """
    uids = {str(t["audit_uid"]) for t in traits if t.get("audit_uid") is not None}
    uids -= {"0"}
    ips = {t["srcip"] for t in traits if t.get("srcip")}
    return uids, ips


def _distincts(a: list[dict], b: list[dict]) -> bool:
    ua, ia = _identite_forte(a)
    ub, ib = _identite_forte(b)
    return bool(ua and ub and not (ua & ub)) or bool(ia and ib and not (ia & ib))


def _apparentes(a: list[dict], b: list[dict]) -> bool:
    """Deux incidents partagent-ils un trait de parenté (lien faible inclus) ?

    Mêmes critères que correlate.point_commun, appliqués incident à incident :
    IP/compte/objet concret, tactique MITRE ou groupe de règle non générique. La
    fenêtre temporelle est déjà bornée en amont (± MAX_INCIDENT_HOURS).
    """
    def feats(al):
        ips = {x["srcip"] for x in al if x.get("srcip")}
        users = {x["srcuser"] for x in al if x.get("srcuser")}
        ents = {x["entity"] for x in al if x.get("entity")
                and not correlate.entite_generique(x["entity"])}
        tacs = {t for x in al for t in (x.get("mitre_tactics") or [])}
        grps = ({g for x in al for g in (x.get("rule_groups") or [])}
                - correlate.GROUPES_GENERIQUES)
        return ips, users, ents, tacs, grps
    return any(x & y for x, y in zip(feats(a), feats(b)))


def _fondre_si_doublon(conn, incident: dict) -> int | None:
    """Dernier garde-fou anti-doublon : idempotence à la création de case.

    _rattacher_existants (corrélation) recolle normalement une salve à son
    incident ; s'il rate la fenêtre à cause du découpage en lots de cycle, deux
    incidents distincts décrivent la MÊME intrusion et chacun ouvrirait un case.
    Ici, à la création, les deux incidents et toutes leurs alertes sont en base :
    si un incident-frère du même agent a DÉJÀ un case, chevauche la fenêtre
    (± MAX_INCIDENT_HOURS), partage un trait de parenté et n'est pas séparé par
    une identité forte contradictoire, on fond cet incident dans le frère et on
    réutilise son case — jamais un doublon. Retourne le case_id adopté, ou None.
    """
    marge = timedelta(hours=config.MAX_INCIDENT_HOURS)
    freres = conn.execute(
        "SELECT id, iris_case_id FROM incidents WHERE agent_id = %s "
        "AND id <> %s AND iris_case_id IS NOT NULL "
        "AND last_seen >= %s AND first_seen <= %s ORDER BY id",
        (incident["agent_id"], incident["id"],
         incident["first_seen"] - marge, incident["last_seen"] + marge)).fetchall()
    if not freres:
        return None

    traits_x = _traits(conn, incident["id"])
    for f in freres:
        traits_f = _traits(conn, f["id"])
        if _distincts(traits_x, traits_f) or not _apparentes(traits_x, traits_f):
            continue
        return _fusionner(conn, incident["id"], f["id"], f["iris_case_id"])
    return None


def _fusionner(conn, src_id: int, dst_id: int, dst_case: int | None) -> int | None:
    """Fond l'incident src dans dst : les alertes de src rejoignent dst, les
    agrégats de dst sont recalculés, dst est marqué à rafraîchir (son case sera
    complété au cycle suivant, remédiation incluse), et src est supprimé (CASCADE
    triages / mitigations / anon_map ; ses alertes ont déjà bougé). Renvoie
    dst_case."""
    conn.execute("UPDATE alerts SET incident_id = %s WHERE incident_id = %s",
                 (dst_id, src_id))
    agg = conn.execute(
        "SELECT count(*) n, min(ts) f, max(ts) l, max(rule_level) lvl, "
        "array_agg(DISTINCT rule_id) r FROM alerts WHERE incident_id = %s",
        (dst_id,)).fetchone()
    conn.execute(
        "UPDATE incidents SET alert_count = %s, first_seen = %s, "
        "last_seen = %s, max_level = %s, rule_ids = %s, needs_refresh = true "
        "WHERE id = %s",
        (agg["n"], agg["f"], agg["l"], agg["lvl"], sorted(agg["r"]), dst_id))
    conn.execute("DELETE FROM incidents WHERE id = %s", (src_id,))
    conn.commit()
    return dst_case


def _signature_campagne(alertes: list[dict]) -> set[str]:
    """Marqueurs APPARTENANT à l'attaquant qui relient les hôtes d'une même
    campagne : comptes créés, IP C2 externes, fichiers/hash malveillants.

    Volontairement PAS les IP internes (un rebond admin relierait tout le
    parc) ni les entités génériques — la sur-fusion se contient en n'admettant
    qu'un marqueur clairement attaquant. Réutilise `_iocs`.

    Cette fonction ne vaut donc que ce que vaut `_iocs`, et c'est ce qui a
    manqué à un exercice purple-team : deux incidents sur deux hôtes Windows
    distincts exécutaient le MÊME `mimikatz.exe`, au même chemin, à la même
    minute, et sont restés deux cases séparés — parce que `_iocs` n'extrayait
    aucun exécutable Windows, l'un n'avait qu'un marqueur (le compte créé) et
    l'autre aucun. Ajouter les binaires déposés hors système aux IOC répare les
    deux d'un coup : la liste d'indicateurs du case ET la fusion de campagne."""
    sig: set[str] = set()
    for valeur, type_ioc, _desc in _iocs(alertes):
        if type_ioc == "ip-any" and _ip_interne(str(valeur)):
            continue                       # IP interne = pas un marqueur de campagne
        sig.add(str(valeur))
    return sig


def _fondre_campagne(conn, incident: dict) -> int | None:
    """Approche A : fond cet incident dans le case d'une campagne DÉJÀ ouverte
    (y compris sur un autre hôte) dès qu'ils partagent un marqueur fort
    appartenant à l'attaquant. Le case devient alors multi-machines ; la
    remédiation les traite ensuite une par une (mitigate._cibles_par_machine),
    et n'agit que là où la preuve est claire.

    Refusé si l'incident n'a aucun marqueur d'attaquant (sans lui, rien ne prouve
    la même campagne) ou si CAMPAGNE_GAP_HOURS = 0. Renvoie le case adopté."""
    if config.CAMPAGNE_GAP_HOURS <= 0:
        return None
    sig = _signature_campagne(_alertes(conn, incident["id"]))
    if not sig:
        return None
    marge = timedelta(hours=config.CAMPAGNE_GAP_HOURS)
    candidats = conn.execute(
        "SELECT id, iris_case_id FROM incidents WHERE id <> %s "
        "AND iris_case_id IS NOT NULL AND last_seen >= %s AND first_seen <= %s "
        "ORDER BY id",
        (incident["id"], incident["first_seen"] - marge,
         incident["last_seen"] + marge)).fetchall()
    for c in candidats:
        commun = _signature_campagne(_alertes(conn, c["id"])) & sig
        if commun:
            log.info("incident #%s fondu dans la campagne du case IRIS #%s "
                     "(marqueur commun : %s)", incident["id"],
                     c["iris_case_id"], ", ".join(sorted(commun))[:100])
            return _fusionner(conn, incident["id"], c["id"], c["iris_case_id"])
    return None


def _lien_wazuh(agent_id: str, rule_id: str, debut, fin) -> str:
    """Deep-link Discover filtré sur (règle, agent) dans la fenêtre de l'évènement.

    On vise la règle + l'agent plutôt qu'un _id d'alerte précis : l'évènement de
    timeline regroupe plusieurs alertes de la même règle, et le lien retombe
    exactement sur ce groupe.

    Structure calquée sur ce que le Discover d'OSD 2.13 (data-explorer) génère
    lui-même — vérifié en direct sur le dashboard prod. Trois pièges qui
    cassaient le lien silencieusement (la page s'ouvrait, mais le filtre ne
    s'appliquait pas) :
      - `_q` DOIT porter `filters:!()` AVANT `query:` : sans ce champ le state de
        recherche est rejeté par data-explorer et la requête est ignorée.
      - `_g` porte `filters:!()` et `refreshInterval:(...)` en plus du `time:`.
      - les guillemets de la KQL sont encodés `%22` (comme les espaces `%20`) :
        c'est la forme qu'OSD sérialise, littéral non garanti côté parseur rison.
    Le reste du fragment #... reste du rison littéral (non décodé par le
    navigateur avant lecture par l'appli).
    """
    requete = f'rule.id:"{rule_id}" and agent.id:"{agent_id}"'
    return _discover_url(requete, debut, fin)


def _lien_wazuh_alerte(alert_id: str, ts) -> str:
    """Deep-link Discover vers UNE alerte précise, par son id Wazuh.

    Utilisé par l'onglet Evidence (une pièce = une alerte brute). L'`id` d'une
    alerte Wazuh (« <epoch>.<offset> », p. ex. 1785949203.70061993) est unique
    et indexé : le lien retombe donc sur exactement cette alerte, pas sur son
    groupe de règle comme `_lien_wazuh`. Fenêtre ±5 min autour de l'horodatage
    pour que le filtre temps de Discover n'exclue pas le document.
    """
    return _discover_url(f'id:"{alert_id}"', ts, ts)


def _discover_url(requete: str, debut, fin) -> str:
    """Construit le deep-link Discover (OSD 2.13 data-explorer) pour une KQL.

    Structure calquée sur ce que le Discover d'OSD 2.13 génère lui-même —
    vérifié en direct sur le dashboard prod. Trois pièges qui cassaient le lien
    silencieusement (la page s'ouvrait, mais le filtre ne s'appliquait pas) :
      - `_q` DOIT porter `filters:!()` AVANT `query:` : sans ce champ le state de
        recherche est rejeté par data-explorer et la requête est ignorée.
      - `_g` porte `filters:!()` et `refreshInterval:(...)` en plus du `time:`.
      - les guillemets de la KQL sont encodés `%22` (comme les espaces `%20`) :
        c'est la forme qu'OSD sérialise, littéral non garanti côté parseur rison.
    Le reste du fragment #... reste du rison littéral.
    """
    marge = timedelta(minutes=5)
    f0 = (debut - marge).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    f1 = (fin + marge).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    patt = config.WAZUH_DASHBOARD_INDEX_PATTERN
    g = (f"(filters:!(),refreshInterval:(pause:!t,value:0),"
         f"time:(from:'{f0}',to:'{f1}'))")
    a = (f"(discover:(columns:!(rule.level,rule.description,agent.name),"
         f"isDirty:!f,sort:!(!('timestamp',desc))),"
         f"metadata:(indexPattern:'{patt}',view:discover))")
    q = f"(filters:!(),query:(language:kuery,query:'{requete}'))"
    base = config.WAZUH_DASHBOARD_URL.rstrip("/") + config.WAZUH_DASHBOARD_DISCOVER_PATH
    return (f"{base}#?_a={a}&_g={g}&_q={q}"
            .replace(" ", "%20").replace('"', "%22"))


def _timeline(case, case_id: int, alertes: list[dict], agent_id: str,
              asset_ids: list[int] | None = None,
              ioc_ids: dict[str, int] | None = None,
              assets_nom: dict[str, int] | None = None) -> int:
    """Remplit la timeline du case : un évènement par règle déclenchée.

    Regroupé par règle plutôt qu'une ligne par alerte : dix détections de
    reverse shell font un évènement « reverse shell (x10) », pas dix lignes
    identiques. L'ordre chronologique reconstitue la kill chain dans IRIS.
    Best-effort : un évènement en échec ne fait pas capoter le case.

    Chaque évènement est lié à la machine touchée (`asset_ids`), aux comptes
    impliqués (`assets_nom`, assets posés par mitigate) et aux IOC qu'il fait
    apparaître (`ioc_ids`) : c'est **uniquement** de ces liens que l'onglet
    Graph tire ses nœuds et ses arêtes (`case_events_assets` /
    `case_events_ioc`, filtrés sur `event_in_graph`). Un case avec des IOC et
    une timeline mais sans ces liens affiche un graphe vide. La machine est
    dans tous les évènements : elle sert de nœud pivot, le reste rayonne.
    """
    asset_ids = asset_ids or []
    ioc_ids = ioc_ids or {}
    assets_nom = assets_nom or {}
    n = 0
    for rid, e in _grouper_regles(alertes):
        titre = (e["desc"][:120] or f"Règle {rid}")
        if e["n"] > 1:
            titre = f"{titre} (x{e['n']})"
        occ = f"{e['n']} occurrence(s)"
        if e["n"] >= _SEUIL_RAFALE:
            occ += " (rafale — tirs répétés, pas autant d'évènements distincts)"
        contenu = [f"Règle Wazuh **{rid}** — niveau {e['level']}/15",
                   f"{occ}, {_fmt_intervalle(e['first'], e['last'])} UTC"]
        if e["users"]:
            contenu.append("Comptes : " + ", ".join(sorted(e["users"])))
        if e["entities"]:
            contenu.append("Objets : " + ", ".join(sorted(e["entities"])[:5]))
        contenu.append("")
        contenu.append("Log Wazuh : "
                       + _lien_wazuh(agent_id, rid, e["first"], e["last"]))
        couleur = ("#dc3545" if e["level"] >= 12 else
                   "#fd7e14" if e["level"] >= 10 else "#ffc107")
        # IOC portés par CE groupe de règle, réextraits de ses seules alertes.
        liens_iocs = [ioc_ids[v] for v, _t, _d in _iocs(e["alertes"])
                      if v in ioc_ids]
        # Comptes cités par le groupe et connus comme assets (cf. mitigate).
        liens_assets = list(asset_ids) + [
            assets_nom[n] for n in (e["users"] | e["entities"])
            if n in assets_nom and assets_nom[n] not in asset_ids]
        try:
            case.add_event(
                title=titre,
                date_time=e["first"],
                content="\n".join(contenu),
                source="Wazuh",
                tags=[TAG_AUTO],
                linked_assets=liens_assets,
                linked_iocs=liens_iocs,
                display_in_graph=True,
                display_in_summary=e["level"] >= 10,
                color=couleur,
                timezone_string="+00:00",
                cid=case_id,
            )
            n += 1
        except Exception as exc:  # noqa: BLE001
            log.debug("évènement timeline ignoré (%s) : %s", rid, exc)
    return n


# Préfixe des noms de pièces Evidence posées par le soc-agent. Sert AUSSI de
# repère d'idempotence : l'id d'alerte Wazuh est le 2e champ du nom.
_EVIDENCE_PREFIXE = "wazuh"


def _evidences(case, case_id: int, alertes: list[dict], agent_id: str) -> int:
    """Une pièce Evidence par alerte Wazuh brute : le log réel conservé.

    Contrairement à la timeline (regroupée par règle) et au lien Discover (qui
    peut pourrir à la rotation des indices), chaque alerte est archivée
    intégralement dans l'onglet Evidence : full_log + JEUX complet de l'alerte
    (JSON), plus un deep-link vers cette alerte précise. Auto-suffisant — la
    preuve survit à la purge de l'indexer.

    Idempotent par **ajout seul** : une alerte n'est jamais mutée, seulement
    rattachée à un incident. On relit donc les pièces déjà posées et on saute
    les id d'alerte déjà présents. Le repère est l'id Wazuh, encodé comme 2e
    champ du nom de fichier (`wazuh <id> ...`), jamais un tag (l'API evidence
    n'en porte pas). Best-effort : une pièce en échec ne fait pas capoter le
    case.
    """
    try:
        existants = case.list_evidences(cid=case_id).get_data() or {}
        existants = existants.get("evidences") or []
    except Exception as e:  # noqa: BLE001
        log.debug("liste evidence case #%s : %s", case_id, e)
        existants = []
    deja = set()
    for ev in existants:
        m = re.match(rf"{_EVIDENCE_PREFIXE} (\S+) ", ev.get("filename") or "")
        if m:
            deja.add(m.group(1))
    n = 0
    for a in alertes:
        aid = str(a.get("id") or "").strip()
        if not aid or aid in deja:
            continue
        deja.add(aid)  # garde-fou anti-doublon si l'alerte apparaît deux fois
        raw = a["raw"] if isinstance(a["raw"], dict) else json.loads(a["raw"])
        brut = json.dumps(raw, ensure_ascii=False, indent=2, sort_keys=True)
        full_log = raw.get("full_log") or ""
        rid, lvl = a["rule_id"], a["rule_level"]
        desc = (a.get("rule_desc") or "").strip()
        ts = a["ts"].astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        corps = [
            f"Règle Wazuh **{rid}** — niveau {lvl}/15",
            desc,
            f"Agent {agent_id} — {ts} UTC",
            f"Alert id Wazuh : `{aid}`",
            "",
            "Log Wazuh (Discover) : " + _lien_wazuh_alerte(aid, a["ts"]),
        ]
        if full_log:
            corps += ["", "**full_log :**", "```", full_log, "```"]
        corps += ["", "**Alerte brute (JSON) :**", "```json", brut, "```"]
        # Nom lisible dans l'onglet, mais 2e champ = id (repère d'idempotence).
        nom = f"{_EVIDENCE_PREFIXE} {aid} r{rid} L{lvl} {desc[:60]}".strip()
        blob = brut.encode("utf-8")
        try:
            case.add_evidence(
                filename=nom[:250] + ".json",
                file_size=len(blob),
                description="\n".join(corps),
                file_hash=hashlib.sha256(blob).hexdigest(),
                cid=case_id,
            )
            n += 1
        except Exception as exc:  # noqa: BLE001
            log.debug("evidence ignorée (alerte %s) : %s", aid, exc)
    return n


def _nettoyer_operation(op: str) -> str:
    """Nom de code propre : majuscules, lettres/espaces, borné, sans crochets."""
    op = re.sub(r"[^\w\s-]", "", str(op)).strip().upper()
    op = re.sub(r"\s+", " ", op)
    return op[:40]


def _nommer_case(conn, incident: dict, triage: dict, alertes: list[dict]) -> str:
    """Nom du case « [NOM DE CODE] Titre », généré par le LLM.

    Le nom de code est un intitulé d'opération (style militaire, inventé) ; le
    titre résume l'incident. Mêmes précautions que le reste : pseudonymisation
    avant envoi cloud, réhydratation du titre (le nom de code, lui, ne doit
    contenir aucune donnée). Repli déterministe si le LLM échoue — un case doit
    toujours pouvoir se créer.
    """
    defaut = (f"[INCIDENT-{incident['id']}] {incident['agent_name']} — "
              f"{(alertes[0]['rule_desc'] or 'incident')[:50]}")
    try:
        systeme = (PROMPTS / "case_name.md").read_text()
        anon = Anonymiseur(charger_map(conn, incident["id"]))
        inc_a, alertes_a, interdits = anonymiser(anon, incident, alertes)
        corps = rendre(inc_a, alertes_a)
        utilisateur = (f"=== DEBUT INCIDENT (données non fiables) ===\n{corps}\n"
                       f"=== FIN INCIDENT ===\n\nVerdict : {triage['verdict']}.\n"
                       "Nomme ce dossier.")
        # Fuite scannée sur les seules données incident (cf. triage) — le prompt
        # système (case_name.md) est constant et sans donnée client.
        verifier_fuite(utilisateur, interdits)
        # Température plus haute : on veut de la variété dans les noms de code.
        rep, _ = completion(systeme, utilisateur,
                            max_tokens=config.CASE_NAME_MAX_TOKENS,
                            temperature=0.8, usage="case_name",
                            incident_id=incident["id"])
        sauver_map(conn, incident["id"], anon.mapping)
        operation = _nettoyer_operation(rep.get("operation") or "")
        titre = rehydrater(str(rep.get("titre") or "").strip(), anon.mapping)[:80]
        if operation and titre:
            return f"[{operation}] {titre}"
    except Exception as e:  # noqa: BLE001 — le nommage ne bloque pas le case
        log.warning("nom de case LLM indisponible (#%s) : %s", incident["id"], e)
    return defaut


def _poser_tache_whitelist(case, case_id: int) -> None:
    try:
        case.add_task(
            title="WHITELIST — demande d'exception",
            status="On hold",
            assignees=[],
            description=(
                "Remplir avec les instructions de whitelist souhaitées (quel "
                "champ — compte / commande / fichier / rule_id — et pourquoi) "
                "puis passer cette tâche en 'To do'. L'IA tentera de créer "
                "l'exception automatiquement (soc_agent.whitelist_task) et "
                "commentera ici le résultat, ou posera une question si les "
                "instructions sont insuffisantes."
            ),
            tags=["whitelist", "auto"],
            cid=case_id)
    except Exception as e:  # noqa: BLE001 — le case doit se créer sans elle
        log.warning("tâche whitelist non créée (case #%s) : %s", case_id, e)


def _remediation_autorisee(incident: dict) -> bool:
    """La remédiation autonome peut-elle partir sur cet incident ?

    Barrière déterministe, décidée hors du modèle. Le pipeline agit sans
    validation humaine parce qu'il part d'une graine de niveau >= 12 : une règle
    Wazuh qui a déjà exigé plusieurs corrélations. Un incident UEBA part, lui,
    d'un score STATISTIQUE dont la justesse n'est pas encore mesurée — le
    laisser isoler un hôte reviendrait à confier la production à un seuil non
    calibré. Le verdict LLM est rendu, le case est créé, les actions proposées
    sont écrites dans le rapport ; rien n'est exécuté tant que UEBA_MITIGATE
    est à false.

    Ce n'est PAS un gate humain déguisé : c'est le même raisonnement que
    `evaluate.py` (« on n'agit pas sur ce qu'on n'a pas mesuré »), appliqué à un
    moteur neuf. Le drapeau se lève quand les verdicts UEBA auront été labellisés.
    """
    if incident.get("ueba") and not config.UEBA_MITIGATE:
        log.info("#%s : remédiation autonome NON exécutée — incident d'origine "
                 "UEBA (score %s) et UEBA_MITIGATE=false. Le case porte les "
                 "actions proposées, l'analyste tranche.",
                 incident.get("id"), incident.get("ueba_score"))
        return False
    return True


def creer_case(conn, incident: dict, triage: dict) -> int:
    # Garde-fou d'idempotence : si cet incident double un frère déjà versé dans
    # IRIS (raté de _rattacher_existants), on réutilise son case au lieu d'en
    # ouvrir un second. L'incident doublon est fondu dans le frère.
    adopte = _fondre_si_doublon(conn, incident)
    if adopte is None:
        # Approche A : à défaut d'un doublon du même hôte, rattachement à une
        # campagne déjà ouverte (autre hôte inclus) sur marqueur d'attaquant.
        adopte = _fondre_campagne(conn, incident)
    if adopte is not None:
        log.info("incident #%s → fondu dans le case IRIS #%s "
                 "(pas de nouveau case)", incident["id"], adopte)
        return adopte

    alertes = _alertes(conn, incident["id"])
    verdict = triage["verdict"]
    fp = verdict == "false_positive"

    log.debug("incident #%s : création case IRIS (verdict=%s, alerts=%d)",
              incident["id"], verdict, incident["alert_count"])
    try:
        case = _client()
        log.debug("  client IRIS obtenu (url=%s)", config.IRIS_URL)
    except Exception as e:
        log.error("  client IRIS échoué : %s", e)
        raise RuntimeError(f"client IRIS échoué : {e}") from e

    nom = _nommer_case(conn, incident, triage, alertes)
    # Priorité de l'asset dans la DESCRIPTION et dans un TAG (filtrable côté
    # IRIS). La SÉVÉRITÉ du case, elle, se pose après création : `add_case` ne
    # la prend pas et tous les cases naissent « Low ».
    priorite = incident.get("priorite")
    desc = _description(incident, verdict)

    log.debug("  appel add_case (nom=%s, cust=%s)", nom[:50], config.IRIS_CUSTOMER)
    r = case.add_case(
        case_name=nom,
        case_description=desc,
        case_customer=config.IRIS_CUSTOMER,
        case_classification=_classification(incident, alertes),
        soc_id=f"Aura-SOC-{incident['id']}",
    )
    log.debug("  réponse add_case: success=%s", r.is_success())
    if not r.is_success():
        log.error("  msg erreur IRIS: %s", r.get_msg())
        raise RuntimeError(f"création case échouée : {r.get_msg()}")
    case_id = r.get_data()["case_id"]

    # Rattachement du case AVANT la remédiation : mitigate.executer ouvre sa
    # propre connexion et lit iris_case_id pour y déposer ses notes. Commit
    # immédiat pour qu'il le voie. needs_refresh remis à false : le case reflète
    # l'incident dans son état courant.
    conn.execute(
        "UPDATE incidents SET iris_case_id = %s, status = %s, "
        "needs_refresh = false WHERE id = %s",
        (case_id, "fp_classe" if fp else "case_ouvert", incident["id"]))
    conn.commit()

    # Tags = hostname de la machine touchée + priorité de l'asset (add_case ne
    # prend pas de tags, d'où l'update juste après la création).
    _taguer(case, case_id, incident.get("agent_name"),
            f"P{priorite}" if priorite else None)
    sev = _poser_severite(case, case_id, incident, triage)
    if sev:
        log.info("case #%s : sévérité IRIS %s (effective %s/15, asset P%s)",
                 case_id, sev, incident.get("severite"), priorite)

    # IOC (best-effort : un type inconnu ne doit pas faire échouer le case) et
    # asset « machine touchée ». Les ids récupérés servent à lier la timeline :
    # sans ces liens, l'onglet Graph d'IRIS reste vide.
    ioc_ids = _poser_iocs(case, case_id, alertes)
    asset_ids = _poser_asset_machine(case, case_id, incident, alertes,
                                     compromis=not fp)

    # Tâche WHITELIST « On hold » : l'analyste la remplit et la passe en
    # 'To do' quand il veut une exception ; soc_agent.whitelist_task la
    # traite alors de façon cyclique. Best-effort : un échec ne bloque pas
    # la création du case.
    _poser_tache_whitelist(case, case_id)

    # Remédiation AUTOMATIQUE, avant le rapport : les actions décidées au triage
    # sont exécutées maintenant (isolation, blocage, désactivation de compte),
    # tracées en table `mitigations` + notes IRIS dédiées. Le rapport en fait
    # ensuite le récapitulatif. Barrières conservées dans mitigate.executer
    # (dry-run si MITIGATE_EXECUTE=false, suspension si motifs d'injection).
    # Import différé : mitigate importe iris, on casse le cycle à l'appel.
    if not fp and _remediation_autorisee(incident):
        try:
            from . import mitigate
            mitigate.executer(incident["id"])
        except Exception as e:  # noqa: BLE001 — une remédiation KO ne bloque
            # pas la création du case ; elle est tracée en 'échec'.
            log.warning("remédiation auto #%s : %s", incident["id"], e)

    # Vrai positif : les traits UEBA impliqués ne doivent plus jamais devenir
    # une habitude. Sans ça, un attaquant patient normalise son propre outillage
    # en le lançant tous les jours jusqu'à ce qu'il cesse d'être scoré.
    #
    # JAMAIS sur un incident d'origine UEBA, en revanche : le gel serait
    # circulaire. Le score comportemental désigne l'incident, le LLM le déclare
    # vrai positif, et le gel réinjecte les traits qui ont produit le score en
    # les portant au plafond — définitivement, `purger()` préservant
    # explicitement `seen_in_tp`. Même raisonnement que `UEBA_MITIGATE` : un
    # verdict rendu sur un score non calibré ne réécrit pas la baseline qui l'a
    # produit.
    #
    # Constaté en production le 2026-08-08 : l'incident #2550 (case #193) a figé
    # 24 traits, dont `compte=WIN-DC$` (38 650 observations), `heure=hors_ouvre`
    # (27 954) et `rule_id=60137` (19 471) — les traits les plus banals du parc,
    # bloqués à 12 bits. Les signaux suivants montaient à 238 sans qu'il se
    # passe quoi que ce soit, et le budget quotidien partait dans ce bruit.
    if not fp and not incident.get("ueba"):
        try:
            from . import ueba
            n = ueba.marquer_tp(incident["id"])
            if n:
                log.info("#%s : %d trait(s) UEBA figés (vus en vrai positif)",
                         incident["id"], n)
        except Exception as e:  # noqa: BLE001
            log.warning("marquage UEBA TP #%s : %s", incident["id"], e)

    # Note d'analyse, dans un répertoire dédié. Après la remédiation : le récap
    # des actions exécutées en dépend.
    contenu = (_note_fp(triage, _regle_whitelist(conn, alertes)) if fp
               else _note_tp(conn, incident, triage, alertes,
                             _iocs_du_case(case, case_id, alertes)))
    titre = "Analyse — Faux positif" if fp else "Rapport d'analyse"
    _poser_note(case, case_id, titre, contenu)

    # Exposition aux vulnérabilités de la machine touchée. Posée aussi sur les
    # FAUX POSITIFS : le verdict porte sur l'évènement, pas sur l'état de
    # l'hôte, et une machine hors délai de correction le reste que l'alerte du
    # jour ait été fondée ou non.
    _poser_exposition(case, case_id, conn, incident, alertes)

    # Timeline : la kill chain, évènement par règle (TP seulement — un FP n'a
    # pas de chronologie d'attaque à reconstituer).
    # Relu APRÈS la remédiation : mitigate y a posé les comptes visés comme
    # assets, qu'on veut voir apparaître dans le graphe.
    if not fp:
        _timeline(case, case_id, alertes, incident["agent_id"],
                  asset_ids, ioc_ids, _assets_case(case, case_id))
        # Onglet Evidence : chaque alerte brute archivée (log réel + deep-link).
        _evidences(case, case_id, alertes, incident["agent_id"])

    conn.commit()
    return case_id


def _verdict_a_change(conn, incident_id: int) -> bool:
    """Le verdict ou les actions ont-ils changé au dernier triage ?

    Correctif #1 (explosion tokens du 2026-07-30) : sur un refresh où le triage
    rejoué rend le MÊME verdict et les MÊMES actions que le précédent, le
    rapport LLM ressortirait mot pour mot (verdict reproductible, temp 0.2 +
    seed). On évite alors de régénérer l'appel `report` — le plus coûteux du
    pipeline (~2000 tokens de complétion). Renvoie True (donc « régénérer »)
    s'il n'existe qu'un seul triage : c'est la première analyse."""
    rows = conn.execute(
        "SELECT verdict, actions FROM triages WHERE incident_id = %s "
        "ORDER BY created_at DESC LIMIT 2", (incident_id,)).fetchall()
    if len(rows) < 2:
        return True
    return (rows[0]["verdict"] != rows[1]["verdict"]
            or list(rows[0]["actions"]) != list(rows[1]["actions"]))


def rafraichir_case(conn, incident: dict, triage: dict) -> int:
    """Met à jour le case existant d'un incident enrichi de nouvelles alertes.

    C'est l'autre moitié du correctif anti-doublon : quand une salve d'une
    intrusion en cours est rattachée à un incident qui a DÉJÀ un case (cf.
    correlate._rattacher_existants + needs_refresh), on complète ce case au
    lieu d'en ouvrir un second. IOC manquants ajoutés, timeline reconstruite,
    note d'analyse et description remises à jour, tag hostname réaffirmé.
    """
    case_id = incident["iris_case_id"]
    case = _client()

    # Case supprimé côté IRIS : le lien en base pend dans le vide. On le remet
    # à NULL et on recrée, plutôt que d'écrire indéfiniment dans un case_id qui
    # n'existe plus.
    #
    # Le symptôme est trompeur : IRIS ne répond pas 404 mais **500**. Son
    # contrôle d'accès, ne trouvant pas le case dans ceux de l'utilisateur,
    # retombe sur « suis-je administrateur serveur ? », qui lit
    # `session['permissions']` — absent en authentification par clé d'API
    # (KeyError, cf. iris_engine/access_control/utils.py). Un case supprimé et
    # un vrai défaut de droits produisent donc la même erreur illisible.
    if not _case_existe(case, case_id):
        log.warning("case IRIS #%s introuvable (supprimé ?) — incident #%s "
                    "recréé", case_id, incident["id"])
        conn.execute("UPDATE incidents SET iris_case_id = NULL WHERE id = %s",
                     (incident["id"],))
        conn.commit()
        return creer_case(conn, dict(incident, iris_case_id=None), triage)

    alertes = _alertes(conn, incident["id"])
    fp = triage["verdict"] == "false_positive"
    desc = _description(incident, triage["verdict"], maj=True)
    try:
        case.update_case(case_id=case_id, case_description=desc)
    except Exception as e:  # noqa: BLE001
        log.debug("maj description case #%s : %s", case_id, e)

    _taguer(case, case_id, incident.get("agent_name"),
            f"P{incident['priorite']}" if incident.get("priorite") else None)
    # La sévérité est REJOUÉE : une salve peut avoir fait monter le niveau max,
    # donc la sévérité effective. Un case ouvert « High » qui devient une
    # attaque avérée doit changer de couleur dans la file, sans quoi l'analyste
    # trie sur une information périmée.
    _poser_severite(case, case_id, incident, triage)
    ioc_ids = _poser_iocs(case, case_id, alertes)
    asset_ids = _poser_asset_machine(case, case_id, incident, alertes,
                                     compromis=not fp)

    # Remédiation rejouée : idempotente (clé unique incident/action/cible), elle
    # ne couvre que d'éventuelles nouvelles cibles apparues avec la salve.
    if not fp and _remediation_autorisee(incident):
        try:
            from . import mitigate
            mitigate.executer(incident["id"])
        except Exception as e:  # noqa: BLE001
            log.warning("remédiation refresh #%s : %s", incident["id"], e)

    # Note d'analyse. Le FP est cheap (pas d'appel LLM) -> toujours régénéré.
    # Le rapport TP appelle le LLM : correctif #1, on ne le régénère que si le
    # verdict/les actions ont changé depuis la note en place (sinon identique).
    if fp:
        _poser_note(case, case_id, "Analyse — Faux positif",
                    _note_fp(triage, _regle_whitelist(conn, alertes)))
    elif _verdict_a_change(conn, incident["id"]):
        _poser_note(case, case_id, "Rapport d'analyse",
                    _note_tp(conn, incident, triage, alertes,
                             _iocs_du_case(case, case_id, alertes)))
    else:
        log.info("#%s rapport non régénéré : verdict inchangé depuis la note "
                 "en place (économie de l'appel LLM report)", incident["id"])

    # Toujours régénérée, elle : elle ne coûte aucun appel au modèle, et
    # l'exposition de la machine bouge indépendamment du verdict (un patch
    # appliqué entre deux salves doit se voir dans le case).
    _poser_exposition(case, case_id, conn, incident, alertes)

    if not fp:
        _reconstruire_timeline(case, case_id, alertes, incident["agent_id"],
                               asset_ids, ioc_ids, _assets_case(case, case_id))
        # Evidence : ajout seul des alertes nouvellement rattachées (idempotent).
        _evidences(case, case_id, alertes, incident["agent_id"])

    conn.execute(
        "UPDATE incidents SET needs_refresh = false, status = %s WHERE id = %s",
        ("fp_classe" if fp else "case_ouvert", incident["id"]))
    conn.commit()
    return case_id


# Deux populations : les incidents SANS case (à créer) et ceux qui ont un case
# mais ont gagné des alertes depuis (needs_refresh → à mettre à jour, pas à
# dupliquer). Même forme de ligne pour les deux, on ajoute iris_case_id.
_SELECT_BASE = """
SELECT DISTINCT ON (i.id)
       i.id, i.agent_id, i.agent_name, i.first_seen, i.last_seen,
       i.alert_count, i.max_level, i.mitre_tactics, i.entities, i.iris_case_id,
       i.ueba, i.ueba_score, i.ueba_motifs, i.priorite, i.severite,
       i.asset_role,
       t.verdict, t.confidence, t.mitre, t.actions, t.reason
  FROM incidents i
  JOIN triages t ON t.incident_id = i.id
 WHERE {filtre}
   AND (%(un_seul)s::bigint IS NULL OR i.id = %(un_seul)s)
 ORDER BY i.id, t.created_at DESC
"""
SELECT_A_TRAITER = _SELECT_BASE.format(
    filtre="i.iris_case_id IS NULL AND i.status <> 'fp_ueba'")
SELECT_A_RAFRAICHIR = _SELECT_BASE.format(
    filtre="i.iris_case_id IS NOT NULL AND i.needs_refresh")


def creer_cases(un_seul: int | None = None) -> list[tuple[int, int, str]]:
    """Crée les cases manquants ET met à jour ceux des incidents enrichis.

    Retourne (incident_id, case_id, verdict). Un incident déjà versé dans IRIS
    qui a gagné des alertes (needs_refresh) voit son case COMPLÉTÉ, jamais
    dupliqué.
    """
    faits: list[tuple[int, int, str]] = []
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        a_creer = conn.execute(SELECT_A_TRAITER, {"un_seul": un_seul}).fetchall()
        for inc in a_creer:
            # Incident d'origine UEBA jugé faux positif : PAS de case.
            #
            # Un case FP a du sens pour un incident de niveau >= 12 : une règle
            # a tiré fort, l'analyste veut voir pourquoi ça n'était rien. Un
            # incident UEBA, lui, ne repose que sur un score comportemental non
            # calibré (c'est aussi pourquoi UEBA_MITIGATE est à false) : quand
            # le LLM dit « faux positif », il n'y a rien à documenter, et le
            # case est du bruit pur dans la file de l'analyste. Le verdict reste
            # en base (table `triages`) pour la whitelist et les métriques.
            #
            # Origine : case IRIS #192, ouvert sur 2 alertes de niveau 3
            # (planification du service Software Protection de Windows).
            if inc["ueba"] and inc["verdict"] == "false_positive":
                conn.execute(
                    "UPDATE incidents SET status = %s, needs_refresh = false "
                    "WHERE id = %s", ("fp_ueba", inc["id"]))
                conn.commit()
                log.info("incident #%s (UEBA, score %s) jugé faux positif : "
                         "aucun case IRIS ouvert", inc["id"], inc["ueba_score"])
                continue
            triage = {k: inc[k] for k in
                      ("verdict", "confidence", "mitre", "actions", "reason")}
            try:
                case_id = creer_case(conn, inc, triage)
                faits.append((inc["id"], case_id, inc["verdict"]))
                print(f"  incident #{inc['id']} -> case IRIS #{case_id} "
                      f"({inc['verdict']})")
            except Exception as e:  # noqa: BLE001
                log.error("création case incident #%s échouée : %s", inc["id"], e)
                # mark incident so we retry next cycle
                conn.execute("UPDATE incidents SET status = %s WHERE id = %s",
                           ("case_creation_failed", inc["id"]))
                conn.commit()

        a_rafraichir = conn.execute(
            SELECT_A_RAFRAICHIR, {"un_seul": un_seul}).fetchall()
        for inc in a_rafraichir:
            triage = {k: inc[k] for k in
                      ("verdict", "confidence", "mitre", "actions", "reason")}
            try:
                case_id = rafraichir_case(conn, inc, triage)
                faits.append((inc["id"], case_id, inc["verdict"]))
                print(f"  incident #{inc['id']} -> case IRIS #{case_id} MAJ "
                      f"({inc['verdict']}, {inc['alert_count']} alertes)")
            except Exception as e:  # noqa: BLE001
                log.error("rafraîchissement case incident #%s échoué : %s", inc["id"], e)
    return faits


def nettoyer_iocs(simulation: bool = True) -> list[tuple[int, str, str]]:
    """Retire des cases existants les IOC devenus redondants.

    `_poser_iocs` n'AJOUTE que le manquant, il ne retire jamais : les cases
    créés avant le repliage « un fichier = un IOC » gardent leurs trois lignes
    par fichier (chemin, sha256, md5). Ce nettoyage les ramène à une.

    Prudence : on ne supprime QUE des valeurs que ce code a lui-même produites
    auparavant pour un fichier désormais représenté par son hash — jamais un IOC
    ajouté à la main par un analyste, qui ne peut pas figurer dans cette liste.
    """
    a_faire: list[tuple[int, str, str]] = []
    case = _client()
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        incidents = conn.execute(
            "SELECT id, iris_case_id FROM incidents "
            "WHERE iris_case_id IS NOT NULL ORDER BY id").fetchall()
        for inc in incidents:
            alertes = conn.execute(
                "SELECT * FROM alerts WHERE incident_id = %s ORDER BY ts",
                (inc["id"],)).fetchall()
            if not alertes:
                continue
            # Ce que le code produit AUJOURD'HUI : la liste de référence.
            gardes = {v for v, _t, _d in _iocs(alertes)}
            # Les valeurs de fichier connues de ces alertes : chemins et hashs.
            # Tout ce qui est là-dedans mais plus dans `gardes` est un reliquat
            # de l'ancienne forme, replié depuis dans une description.
            connues = _valeurs_fichier(alertes)
            if not _case_existe(case, inc["iris_case_id"]):
                print(f"  case #{inc['iris_case_id']} : introuvable dans IRIS "
                      f"(supprimé) — incident #{inc['id']} ignoré, il sera "
                      "recréé au prochain rafraîchissement")
                continue
            try:
                presents = (case.list_iocs(inc["iris_case_id"]).get_data()
                            or {}).get("ioc") or []
            except Exception as e:                            # noqa: BLE001
                log.warning("case #%s : IOC illisibles (%s)",
                            inc["iris_case_id"], e)
                continue
            for i in presents:
                valeur = i.get("ioc_value")
                if not valeur or valeur in gardes or valeur not in connues:
                    continue
                a_faire.append((inc["iris_case_id"], valeur, i.get("ioc_id")))
                if not simulation:
                    try:
                        case.delete_ioc(i["ioc_id"], cid=inc["iris_case_id"])
                    except Exception as e:                    # noqa: BLE001
                        log.warning("suppression IOC %s : %s", valeur, e)
    return a_faire


def _valeurs_fichier(alertes: list[dict]) -> set[str]:
    """Chemins et hashs de fichier présents dans ces alertes.

    Périmètre du nettoyage : on ne supprime rien qui ne vienne pas de là.
    """
    valeurs: set[str] = set()
    for a in alertes:
        raw = a["raw"] if isinstance(a["raw"], dict) else json.loads(a["raw"])
        data = raw.get("data", {}) or {}
        yara = data.get("yara") or {}
        vt = (data.get("virustotal", {}) or {}).get("source", {}) or {}
        sc = raw.get("syscheck", {}) or {}
        for v in (data.get("file_path"), yara.get("scan_path"),
                  _chemin_cible(data.get("file_path") or yara.get("scan_path")),
                  data.get("sha256"), data.get("sha1"), data.get("md5"),
                  vt.get("file"), vt.get("sha256"), vt.get("sha1"), vt.get("md5"),
                  sc.get("path"), sc.get("sha256_after"), sc.get("sha1_after"),
                  sc.get("md5_after")):
            if v:
                valeurs.add(str(v))
    return valeurs


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--incident", type=int, default=None)
    ap.add_argument("--nettoyer-iocs", action="store_true",
                    help="retire des cases existants les IOC redondants "
                         "(un fichier = un IOC, hash prioritaire sur chemin)")
    ap.add_argument("--appliquer", action="store_true",
                    help="avec --nettoyer-iocs : supprime réellement "
                         "(sans ce drapeau, simulation)")
    args = ap.parse_args()

    if args.nettoyer_iocs:
        faits = nettoyer_iocs(simulation=not args.appliquer)
        verbe = "supprimé" if args.appliquer else "à supprimer"
        for case_id, valeur, _ in faits:
            print(f"  case #{case_id} : {verbe} {valeur}")
        print(f"  {len(faits)} IOC redondant(s) {verbe}.")
        if faits and not args.appliquer:
            print("  Relancer avec --appliquer pour supprimer.")
        return

    crees = creer_cases(args.incident)
    if not crees:
        print("Aucun incident à verser dans IRIS.")


if __name__ == "__main__":
    main()
