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

# Descriptions courtes des actions, pour un rapport lisible par un humain.
LIBELLE_ACTION = {
    "propose_kill_process": "Tuer le process malveillant",
    "propose_isolate_host": "Isoler l'hôte du réseau",
    "propose_disable_user": "Désactiver le compte compromis",
    "propose_block_ip": "Bloquer l'IP source",
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

# Tag posé sur les évènements de timeline créés par le soc-agent : c'est à ça
# qu'on les reconnaît pour les remplacer au rafraîchissement.
TAG_AUTO = "soc-agent"


def _taguer(case, case_id: int, agent_name: str | None) -> None:
    """Ajoute le hostname de la machine touchée aux tags du case (union).

    Un analyste retrouve ainsi tous les cases d'une même machine par le tag.
    Union avec l'existant : on n'écrase pas les tags posés à la main. add_case
    n'accepte pas de tags — d'où le update_case juste après la création.
    """
    if not agent_name:
        return
    tags: set[str] = set()
    try:
        gc = case.get_case(case_id)
        if gc.is_success():
            brut = gc.get_data().get("case_tags") or ""
            tags = {t.strip() for t in brut.split(",") if t.strip()}
    except Exception as e:  # noqa: BLE001 — le tag ne bloque pas le case
        log.debug("lecture tags case #%s : %s", case_id, e)
    if agent_name in tags:
        return
    tags.add(agent_name)
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


def _poser_note(case, case_id: int, titre: str, contenu: str) -> None:
    """Crée ou MET À JOUR la note d'analyse dans le répertoire « Analyse IA ».

    Au rafraîchissement d'un case, on remplace le contenu de la note existante
    plutôt que d'en empiler une deuxième : le dossier reste lisible.
    """
    dir_id = None
    note_id = None
    try:
        for d in case.list_notes_directories(cid=case_id).get_data() or []:
            if d.get("name") == DIR_ANALYSE:
                dir_id = d["id"]
                for n in d.get("notes") or []:
                    if n.get("title") == titre:
                        note_id = n["id"]
                        break
                break
    except Exception as e:  # noqa: BLE001
        log.debug("liste notes case #%s : %s", case_id, e)
    if note_id is not None:
        try:
            case.update_note(note_id=note_id, note_content=contenu, cid=case_id)
            return
        except Exception as e:  # noqa: BLE001
            log.debug("maj note %s : %s", note_id, e)
    if dir_id is None:
        rd = case.add_notes_directory(directory_name=DIR_ANALYSE, cid=case_id)
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
# Préfixe du montage sshfs du scanner YARA : /mnt/yaritrust/<hôte>_<ip>/…
_RE_MONTAGE_SCAN = re.compile(r"^/mnt/yaritrust/[^/]+/")

# Réseaux internes du parc, précompilés une fois.
_NETS_INTERNES = []
for _cidr in config.RESEAUX_INTERNES:
    try:
        _NETS_INTERNES.append(ipaddress.ip_network(_cidr, strict=False))
    except ValueError:
        log.warning("RESEAUX_INTERNES: cidr invalide ignoré: %r", _cidr)


def _ip_ioc_valide(ip: str) -> bool:
    """IP exploitable comme IOC : ni 'none', ni loopback, ni non-spécifiée.

    Écarte le bruit qui polluait la threat intel (`ip-any = none`, 0.0.0.0,
    127.0.0.1, link-local, multicast)."""
    try:
        o = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return not (o.is_loopback or o.is_unspecified or o.is_link_local
                or o.is_multicast)


def _ip_interne(ip: str) -> bool:
    """Vrai si l'IP appartient à un subnet du parc (cf. config.RESEAUX_INTERNES).

    Volontairement PAS `is_private` : le C2 du lab est en RFC1918 — seule
    l'appartenance aux subnets déclarés du parc vaut « interne »."""
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

        # Fichier déposé dans un emplacement suspect (binaire droppé, webshell).
        fichier = (audit.get("file", {}) or {}).get("name") or a.get("entity")
        if _chemin_suspect(fichier):
            ajouter(fichier, "filename", "Fichier déposé (emplacement suspect)")

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
        vt = data.get("virustotal", {}).get("source", {})
        if vt.get("sha256") or vt.get("file"):
            ajouter_fichier(vt.get("file"),
                            {"sha256": vt.get("sha256"), "sha1": vt.get("sha1"),
                             "md5": vt.get("md5")},
                            "Fichier signalé par VirusTotal")

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
    """Historique des commandes de l'attaquant, reconstitué depuis auditd.

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
        return ("## Commandes exécutées (auditd)\n\nAucune commande "
                "reconstituée (pas d'alerte d'audit de commande dans le "
                "périmètre).")
    portee = (f"sous l'uid compromis {', '.join(sorted(uids))}" if uids
              else "tous uids (compte compromis non identifié)")
    lignes = [
        "## Commandes exécutées (auditd)",
        "",
        f"{len(cmds)} commandes distinctes reconstituées depuis le proctitle "
        f"auditd ({portee}), rattachées à l'attaque, ordre chronologique :",
        "",
        "```",
    ]
    # Date incluse si les commandes s'étalent sur plusieurs jours UTC, sinon
    # l'heure seule rend l'ordre chronologique ambigu (mêmes HH:MM d'un jour à
    # l'autre).
    jours = {ts.astimezone(timezone.utc).date() for ts, _ in cmds}
    fmt = "%m-%d %H:%M:%S" if len(jours) > 1 else "%H:%M:%S"
    for ts, cmd in cmds[:80]:
        lignes.append(f"{ts.astimezone(timezone.utc):{fmt}}  {cmd[:200]}")
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


def _section_iocs(alertes: list[dict]) -> str:
    """Tableau des IOC extraits (déterministe). Note locale : valeurs réelles."""
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


# Rendu lisible du statut d'une remédiation exécutée.
_STATUT_REMED = {
    "exécuté": "✅ exécuté",
    "dry_run": "🟡 simulé (dry-run)",
    "sans_canal": "📄 documenté (manuel)",
    "échec": "❌ échec",
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
    lignes = ["## Remédiations exécutées"]

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
        "| Action | Cible | Statut |",
        "|:---|:---|:---:|",
    ]
    for r in rows:
        libelle = LIBELLE_ACTION.get(r["action"], r["action"])
        statut = _STATUT_REMED.get(r["statut"], r["statut"])
        lignes.append(f"| {libelle} | `{r['cible']}` | {statut} |")
    return "\n".join(lignes)


def _note_fp(triage: dict, regle: dict | None) -> str:
    """Note d'analyse d'un faux positif, avec l'explication de whitelist.

    Pure : `regle` est la ligne whitelist_rules correspondant à la signature de
    l'incident (ou None), fournie par l'appelant. Testable sans base.
    """
    lignes = [
        "# Analyse — Faux positif",
        "",
        f"**Verdict IA** : faux positif (confiance {triage['confidence']})",
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
_CAPTEURS = (
    ("exécution de processus (auditd)", {"audit"}),
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
# wazuh/agents/pve/). On l'extrait ici pour que le case dise « jellyfin » et pas
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
    """Incidents sur d'AUTRES agents partageant une entité forte (même IP, même
    fichier, même compte) dans une fenêtre ±ENTITY_GAP autour de celui-ci.

    La corrélation principale est cloisonnée par agent (correlate.py) — un pivot
    d'un hôte à l'autre est donc invisible par construction. Cette passe le
    rattrape a posteriori SANS fusionner : on signale le lien à l'analyste. Le
    2026-07-29 le pivot bookstack -> jellyfin n'apparaissait dans aucun case."""
    marge = timedelta(minutes=config.ENTITY_GAP_MINUTES)
    traits = conn.execute(
        "SELECT DISTINCT srcip, entity, srcuser FROM alerts WHERE incident_id=%s",
        (incident["id"],)).fetchall()
    # IP source et fichier sont des liens forts. Le COMPTE, non : `root` (ou
    # www-data, admin…) existe sur chaque hôte — lier dessus rapprocherait tous
    # les incidents entre eux. On écarte donc les comptes génériques, on garde
    # les shells génériques déjà exclus côté corrélation.
    valeurs = {v for t in traits for v in (t["srcip"], t["entity"])
               if v and v not in correlate.ENTITES_GENERIQUES}
    valeurs |= {t["srcuser"] for t in traits
                if t["srcuser"] and t["srcuser"].lower() not in _COMPTES_GENERIQUES}
    if not valeurs:
        return []
    liste = list(valeurs)
    rows = conn.execute(
        """SELECT DISTINCT i.id, i.agent_name, a.srcip, a.entity, a.srcuser
             FROM incidents i JOIN alerts a ON a.incident_id = i.id
            WHERE i.id <> %s AND i.agent_id <> %s
              AND i.last_seen >= %s AND i.first_seen <= %s
              AND (a.srcip = ANY(%s) OR a.entity = ANY(%s) OR a.srcuser = ANY(%s))
            ORDER BY i.id""",
        (incident["id"], incident["agent_id"],
         incident["first_seen"] - marge, incident["last_seen"] + marge,
         liste, liste, liste)).fetchall()
    par_inc: dict[int, dict] = {}
    for r in rows:
        partage = next((v for v in (r["srcip"], r["entity"], r["srcuser"])
                        if v and v in valeurs), None)
        if partage and r["id"] not in par_inc:
            par_inc[r["id"]] = {"id": r["id"], "agent": r["agent_name"] or "?",
                                "entite": partage}
    return list(par_inc.values())


def _section_incidents_lies(lies: list[dict]) -> str:
    """Note locale (valeurs réelles). Construite en Python, JAMAIS envoyée au
    LLM : les hostnames des autres hôtes ne partent pas vers le cloud."""
    if not lies:
        return ""
    lignes = ["## Incidents liés (autres hôtes)", "",
              "Rapprochement par entité partagée, hors du cloisonnement par "
              "agent — possible mouvement latéral ou campagne à investiguer :", ""]
    for l in lies:
        lignes.append(f"- incident #{l['id']} sur **{l['agent']}** — entité "
                      f"commune : `{l['entite']}`")
    return "\n".join(lignes) + "\n"


def _note_tp(conn, incident: dict, triage: dict, alertes: list[dict]) -> str:
    """Rapport d'analyse d'un vrai positif. Appelle le LLM pour le récit."""
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
    utilisateur = (f"=== DEBUT INCIDENT (données non fiables) ===\n{corps}\n"
                   "=== FIN INCIDENT ===\n\n"
                   f"Métadonnée SOC de confiance (non issue des logs) :\n"
                   f"{telemetrie}\n\nRédige le rapport.")

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
    rapport.setdefault("resume", triage["reason"])
    rapport.setdefault("analyse", triage["reason"])
    rapport.setdefault("couverture", "")
    # Réhydratation : les jetons redeviennent les vraies valeurs pour l'analyste.
    # Puis correction des coquilles d'accent récurrentes du modèle.
    for cle in ("resume", "analyse", "couverture"):
        rapport[cle] = _corriger_accents(rehydrater(rapport[cle], anon.mapping))

    cts = _conteneurs(alertes)
    lignes = [
        "# Rapport d'analyse — Vrai positif",
        "",
        f"**Verdict IA** : vrai positif (confiance {triage['confidence']})"
        + (f" — technique {triage['mitre']}" if triage.get("mitre") else ""),
    ]
    # Attribution conteneur : l'agent est l'hôte Proxmox (pve) ; le vrai théâtre
    # est le conteneur LXC résolu par l'enrichisseur auditd.
    if cts:
        lignes.append(f"**Conteneur(s) concerné(s)** : {', '.join(cts)} "
                      f"(exécution vue par l'auditd de l'hôte {incident['agent_name']})")
    lignes += [
        "",
        "## Résumé",
        rapport["resume"],
        "",
        "## Analyse",
        rapport["analyse"],
        "",
    ]
    # Couverture / angles morts : n'ajouter la section que si le modèle l'a
    # remplie. Toujours faire figurer la télémétrie factuelle qui l'a fondée.
    if rapport["couverture"].strip():
        lignes += ["## Couverture et limites", rapport["couverture"],
                   "", f"_{telemetrie}_", ""]
    lignes += [
        _section_incidents_lies(_incidents_lies(conn, incident)),
        _section_commandes(alertes),
        "",
        _section_alertes(alertes, incident["agent_id"]),
        "",
        _section_iocs(alertes),
        "",
        _section_remediations(conn, incident["id"], triage),
    ]
    return "\n".join(lignes)


def _alertes(conn, incident_id: int) -> list[dict]:
    return conn.execute(
        "SELECT id, ts, rule_id, rule_level, rule_desc, rule_groups, "
        "srcip, srcuser, entity, raw FROM alerts WHERE incident_id = %s "
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
                and x["entity"] not in correlate.ENTITES_GENERIQUES}
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
        # Fusion : les alertes rejoignent le frère, agrégats recalculés, case du
        # frère marqué à rafraîchir, incident doublon supprimé (CASCADE triages/
        # mitigations/anon_map ; alertes déjà déplacées).
        conn.execute("UPDATE alerts SET incident_id = %s WHERE incident_id = %s",
                     (f["id"], incident["id"]))
        agg = conn.execute(
            "SELECT count(*) n, min(ts) f, max(ts) l, max(rule_level) lvl, "
            "array_agg(DISTINCT rule_id) r FROM alerts WHERE incident_id = %s",
            (f["id"],)).fetchone()
        conn.execute(
            "UPDATE incidents SET alert_count = %s, first_seen = %s, "
            "last_seen = %s, max_level = %s, rule_ids = %s, needs_refresh = true "
            "WHERE id = %s",
            (agg["n"], agg["f"], agg["l"], agg["lvl"], sorted(agg["r"]), f["id"]))
        conn.execute("DELETE FROM incidents WHERE id = %s", (incident["id"],))
        conn.commit()
        return f["iris_case_id"]
    return None


def _lien_wazuh(agent_id: str, rule_id: str, debut, fin) -> str:
    """Deep-link Discover filtré sur (règle, agent) dans la fenêtre de l'évènement.

    On vise la règle + l'agent plutôt qu'un _id d'alerte précis : l'évènement de
    timeline regroupe plusieurs alertes de la même règle, et le lien retombe
    exactement sur ce groupe. Rison laissé littéral (le fragment #... n'est pas
    décodé par le navigateur avant lecture par l'appli) ; seuls les espaces sont
    encodés, ce que OpenSearch Dashboards tolère.
    """
    marge = timedelta(minutes=5)
    f0 = (debut - marge).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    f1 = (fin + marge).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    patt = config.WAZUH_DASHBOARD_INDEX_PATTERN
    requete = f'rule.id:"{rule_id}" and agent.id:"{agent_id}"'
    g = f"(time:(from:'{f0}',to:'{f1}'))"
    a = (f"(discover:(columns:!(rule.level,rule.description,agent.name),"
         f"sort:!(!('timestamp',desc))),"
         f"metadata:(indexPattern:'{patt}',view:discover))")
    q = f"(query:(language:kuery,query:'{requete}'))"
    base = config.WAZUH_DASHBOARD_URL.rstrip("/") + config.WAZUH_DASHBOARD_DISCOVER_PATH
    return f"{base}#?_g={g}&_a={a}&_q={q}".replace(" ", "%20")


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


def creer_case(conn, incident: dict, triage: dict) -> int:
    # Garde-fou d'idempotence : si cet incident double un frère déjà versé dans
    # IRIS (raté de _rattacher_existants), on réutilise son case au lieu d'en
    # ouvrir un second. L'incident doublon est fondu dans le frère.
    adopte = _fondre_si_doublon(conn, incident)
    if adopte is not None:
        log.info("incident #%s doublon → fondu dans le case IRIS #%s "
                 "(pas de nouveau case)", incident["id"], adopte)
        return adopte

    alertes = _alertes(conn, incident["id"])
    verdict = triage["verdict"]
    fp = verdict == "false_positive"

    case = _client()
    nom = _nommer_case(conn, incident, triage, alertes)
    desc = (f"Incident #{incident['id']} corrélé par le soc-agent, "
            f"{incident['alert_count']} alertes, niveau max "
            f"{incident['max_level']}/15. Verdict IA : {verdict}.")

    r = case.add_case(
        case_name=nom,
        case_description=desc,
        case_customer=config.IRIS_CUSTOMER,
        case_classification=_classification(incident, alertes),
        soc_id=f"SOC-AI-{incident['id']}",
    )
    if not r.is_success():
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

    # Tag = hostname de la machine touchée (add_case ne prend pas de tags).
    _taguer(case, case_id, incident.get("agent_name"))

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
    if not fp:
        try:
            from . import mitigate
            mitigate.executer(incident["id"])
        except Exception as e:  # noqa: BLE001 — une remédiation KO ne bloque
            # pas la création du case ; elle est tracée en 'échec'.
            log.warning("remédiation auto #%s : %s", incident["id"], e)

    # Note d'analyse, dans un répertoire dédié. Après la remédiation : le récap
    # des actions exécutées en dépend.
    contenu = (_note_fp(triage, _regle_whitelist(conn, alertes)) if fp
               else _note_tp(conn, incident, triage, alertes))
    titre = "Analyse — Faux positif" if fp else "Rapport d'analyse"
    _poser_note(case, case_id, titre, contenu)

    # Timeline : la kill chain, évènement par règle (TP seulement — un FP n'a
    # pas de chronologie d'attaque à reconstituer).
    # Relu APRÈS la remédiation : mitigate y a posé les comptes visés comme
    # assets, qu'on veut voir apparaître dans le graphe.
    if not fp:
        _timeline(case, case_id, alertes, incident["agent_id"],
                  asset_ids, ioc_ids, _assets_case(case, case_id))

    conn.commit()
    return case_id


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
    desc = (f"Incident #{incident['id']} corrélé par le soc-agent, "
            f"{incident['alert_count']} alertes, niveau max "
            f"{incident['max_level']}/15. Verdict IA : {triage['verdict']}. "
            "(mis à jour — nouvelles alertes rattachées)")
    try:
        case.update_case(case_id=case_id, case_description=desc)
    except Exception as e:  # noqa: BLE001
        log.debug("maj description case #%s : %s", case_id, e)

    _taguer(case, case_id, incident.get("agent_name"))
    ioc_ids = _poser_iocs(case, case_id, alertes)
    asset_ids = _poser_asset_machine(case, case_id, incident, alertes,
                                     compromis=not fp)

    # Remédiation rejouée : idempotente (clé unique incident/action/cible), elle
    # ne couvre que d'éventuelles nouvelles cibles apparues avec la salve.
    if not fp:
        try:
            from . import mitigate
            mitigate.executer(incident["id"])
        except Exception as e:  # noqa: BLE001
            log.warning("remédiation refresh #%s : %s", incident["id"], e)

    contenu = (_note_fp(triage, _regle_whitelist(conn, alertes)) if fp
               else _note_tp(conn, incident, triage, alertes))
    titre = "Analyse — Faux positif" if fp else "Rapport d'analyse"
    _poser_note(case, case_id, titre, contenu)

    if not fp:
        _reconstruire_timeline(case, case_id, alertes, incident["agent_id"],
                               asset_ids, ioc_ids, _assets_case(case, case_id))

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
       t.verdict, t.confidence, t.mitre, t.actions, t.reason
  FROM incidents i
  JOIN triages t ON t.incident_id = i.id
 WHERE {filtre}
   AND (%(un_seul)s::bigint IS NULL OR i.id = %(un_seul)s)
 ORDER BY i.id, t.created_at DESC
"""
SELECT_A_TRAITER = _SELECT_BASE.format(filtre="i.iris_case_id IS NULL")
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
            triage = {k: inc[k] for k in
                      ("verdict", "confidence", "mitre", "actions", "reason")}
            case_id = creer_case(conn, inc, triage)
            faits.append((inc["id"], case_id, inc["verdict"]))
            print(f"  incident #{inc['id']} -> case IRIS #{case_id} "
                  f"({inc['verdict']})")

        a_rafraichir = conn.execute(
            SELECT_A_RAFRAICHIR, {"un_seul": un_seul}).fetchall()
        for inc in a_rafraichir:
            triage = {k: inc[k] for k in
                      ("verdict", "confidence", "mitre", "actions", "reason")}
            case_id = rafraichir_case(conn, inc, triage)
            faits.append((inc["id"], case_id, inc["verdict"]))
            print(f"  incident #{inc['id']} -> case IRIS #{case_id} MAJ "
                  f"({inc['verdict']}, {inc['alert_count']} alertes)")
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
