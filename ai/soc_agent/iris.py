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
import json
import logging
import re
from datetime import timedelta, timezone

import psycopg
import urllib3
from psycopg.rows import dict_row

from . import config
from .anonymize import Anonymiseur, anonymiser, rehydrater, verifier_fuite
from .llm import completion
from .render import rendre
from .triage import charger_map, sauver_map
from .whitelist import _canonique, _signature

log = logging.getLogger("iris")

if not config.IRIS_VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from pathlib import Path  # noqa: E402

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
    "propose_isolate_host": "Isoler l'hôte du réseau",
    "propose_disable_user": "Désactiver le compte compromis",
    "propose_block_ip": "Bloquer l'IP source",
    "collect_endpoint_evidence": "Collecter des preuves sur l'endpoint",
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


def _poser_iocs(case, case_id: int, alertes: list[dict]) -> None:
    """Ajoute les IOC manquants du case (dédup sur la valeur déjà présente)."""
    existants: set[str] = set()
    try:
        d = case.list_iocs(case_id).get_data() or {}
        existants = {i.get("ioc_value") for i in (d.get("ioc") or [])}
    except Exception as e:  # noqa: BLE001
        log.debug("liste IOC case #%s : %s", case_id, e)
    for valeur, type_ioc, description in _iocs(alertes):
        if valeur in existants:
            continue
        try:
            case.add_ioc(value=valeur, ioc_type=type_ioc,
                         description=description, cid=case_id)
        except Exception as e:  # noqa: BLE001
            log.debug("IOC ignoré (%s/%s) : %s", type_ioc, valeur, e)


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


def _reconstruire_timeline(case, case_id: int, alertes: list[dict],
                           agent_id: str) -> None:
    """Efface les évènements auto (source Wazuh) et les reconstruit.

    Une salve rattachée allonge un groupe de règle ou en crée un ; re-poser
    tout en l'état dupliquerait. On supprime donc les évènements posés par le
    soc-agent (source « Wazuh »), jamais ceux saisis par un analyste, puis on
    les recrée depuis l'état courant.
    """
    try:
        tl = case.list_events(cid=case_id).get_data().get("timeline") or []
    except Exception as e:  # noqa: BLE001
        log.debug("liste timeline case #%s : %s", case_id, e)
        tl = []
    for ev in tl:
        if (ev.get("event_source") or "") == "Wazuh":
            try:
                case.delete_event(ev["event_id"], cid=case_id)
            except Exception as e:  # noqa: BLE001
                log.debug("suppr évènement %s : %s", ev.get("event_id"), e)
    _timeline(case, case_id, alertes, agent_id)


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


def _chemin_suspect(p: str | None) -> bool:
    if not p:
        return False
    if any(p.startswith(d) for d in _DIRS_SUSPECTS):
        return True
    base = p.rsplit("/", 1)[-1]
    # Exécutable planqué (nom en point) hors des emplacements légitimes.
    return base.startswith(".") and not p.startswith(("/etc", "/home", "/root/."))


def _iocs(alertes: list[dict]) -> list[tuple[str, str, str]]:
    """Vrais indicateurs d'attaque, dédupliqués. Best-effort.

    On ne remonte QUE ce qui caractérise l'attaquant : IP/port du C2, comptes
    créés, fichiers déposés dans des emplacements suspects, hash de malware.
    Les fichiers système simplement lus/modifiés (/etc/passwd, /usr/bin/cat)
    ne sont PAS des IOC et sont écartés.
    """
    vus: set[str] = set()
    out: list[tuple[str, str, str]] = []

    def ajouter(valeur, type_ioc, desc):
        if valeur and str(valeur) not in vus:
            vus.add(str(valeur))
            out.append((str(valeur), type_ioc, desc))

    for a in alertes:
        raw = a["raw"] if isinstance(a["raw"], dict) else json.loads(a["raw"])
        data = raw.get("data", {})
        audit = data.get("audit", {})
        full_log = raw.get("full_log") or ""

        # C2 : cible d'un reverse shell, dans le log ou le proctitle décodé.
        for texte in (full_log, _decoder_proctitle(full_log),
                      a.get("rule_desc") or ""):
            for ip, port in _RE_REVSHELL.findall(texte):
                ajouter(ip, "ip-any", f"IP C2 — cible reverse shell (port {port})")

        # IP source d'une attaque réseau (ex. web).
        if a.get("srcip"):
            ajouter(a["srcip"], "ip-any", "IP source de l'attaque")

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

        # Hash de malware (VT) ou de fichier suspect modifié (FIM).
        vt = data.get("virustotal", {}).get("source", {})
        ajouter(vt.get("sha256"), "sha256", "Hash VirusTotal (malveillant)")
        sc = raw.get("syscheck", {})
        if _chemin_suspect(sc.get("path")):
            ajouter(sc.get("sha256_after"), "sha256",
                    f"Hash FIM — {sc.get('path')}")
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
                "entities": {a["entity"]} if a.get("entity") else set()}
        else:
            e["n"] += 1
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


def _section_commandes(alertes: list[dict]) -> str:
    """Historique des commandes de l'attaquant, reconstitué depuis auditd.

    Le proctitle (règle 80792, niv. 3) porte la ligne de commande complète. En
    descendant ATTACH_MIN_LEVEL à 3, ces alertes entrent dans l'incident : on
    déroule ici l'énumération et l'exploitation (find SUID, cat /etc/shadow,
    useradd, systemctl…) que les seules règles HIGH ne montraient pas.

    Filtré sur l'uid du compte compromis (déduit des alertes HIGH) pour écarter
    le bruit de fond — sessions de login, démons, générateurs systemd. À défaut
    d'uid identifié, on retombe sur le flux complet. Déterministe, note locale.
    """
    uids = _uids_suspects(alertes)
    vus: set[str] = set()
    cmds: list[tuple] = []
    for a in sorted(alertes, key=lambda x: x["ts"]):
        raw = a["raw"] if isinstance(a["raw"], dict) else json.loads(a["raw"])
        audit = raw.get("data", {}).get("audit", {}) or {}
        if uids and str(audit.get("uid")) not in uids:
            continue
        cmd = _decoder_proctitle(raw.get("full_log") or "").strip()
        if not cmd:
            cmd = str(audit.get("command") or "").strip()
        if not cmd or cmd in vus:
            continue
        vus.add(cmd)
        cmds.append((a["ts"], cmd))

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
        f"auditd ({portee}), ordre chronologique :",
        "",
        "```",
    ]
    for ts, cmd in cmds[:80]:
        lignes.append(f"{ts:%H:%M:%S}  {cmd[:200]}")
    if len(cmds) > 80:
        lignes.append(f"... (+{len(cmds) - 80} autres)")
    lignes.append("```")
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
        fen = f"{e['first']:%H:%M:%S}"
        if e["last"] != e["first"]:
            fen += f" → {e['last']:%H:%M:%S}"
        desc = (e["desc"][:78] + "…") if len(e["desc"]) > 78 else e["desc"]
        label = f"w-{rid}"
        lignes.append(f"| {e['level']} | {rid} | {e['n']} | {fen} | {desc} "
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
                 if a in LIBELLE_ACTION and a.startswith(("propose_", "collect_"))]
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
    utilisateur = (f"=== DEBUT INCIDENT (données non fiables) ===\n{corps}\n"
                   "=== FIN INCIDENT ===\n\nRédige le rapport.")

    try:
        verifier_fuite(systeme + utilisateur, interdits)
        rapport, _ = completion(systeme, utilisateur,
                                max_tokens=config.REPORT_MAX_TOKENS)
        sauver_map(conn, incident["id"], anon.mapping)
    except Exception as e:  # noqa: BLE001 — le case doit se créer même sans LLM
        log.warning("rapport LLM indisponible (#%s) : %s", incident["id"], e)
        rapport = {}
    # DeepSeek ne garantit pas les clés (plus de GBNF) : on tolère les absences.
    rapport.setdefault("resume", triage["reason"])
    rapport.setdefault("analyse", triage["reason"])
    # Réhydratation : les jetons redeviennent les vraies valeurs pour l'analyste.
    for cle in ("resume", "analyse"):
        rapport[cle] = rehydrater(rapport[cle], anon.mapping)

    lignes = [
        "# Rapport d'analyse — Vrai positif",
        "",
        f"**Verdict IA** : vrai positif (confiance {triage['confidence']})"
        + (f" — technique {triage['mitre']}" if triage.get("mitre") else ""),
        "",
        "## Résumé",
        rapport["resume"],
        "",
        "## Analyse",
        rapport["analyse"],
        "",
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


def _timeline(case, case_id: int, alertes: list[dict], agent_id: str) -> int:
    """Remplit la timeline du case : un évènement par règle déclenchée.

    Regroupé par règle plutôt qu'une ligne par alerte : dix détections de
    reverse shell font un évènement « reverse shell (x10) », pas dix lignes
    identiques. L'ordre chronologique reconstitue la kill chain dans IRIS.
    Best-effort : un évènement en échec ne fait pas capoter le case.
    """
    n = 0
    for rid, e in _grouper_regles(alertes):
        titre = (e["desc"][:120] or f"Règle {rid}")
        if e["n"] > 1:
            titre = f"{titre} (x{e['n']})"
        contenu = [f"Règle Wazuh **{rid}** — niveau {e['level']}/15",
                   f"{e['n']} occurrence(s), de {e['first']:%H:%M:%S} à "
                   f"{e['last']:%H:%M:%S} UTC"]
        if e["users"]:
            contenu.append("Comptes : " + ", ".join(sorted(e["users"])))
        if e["entities"]:
            contenu.append("Objets : " + ", ".join(sorted(e["entities"])[:5]))
        contenu.append("")
        contenu.append("Log Wazuh : "
                       + _lien_wazuh(agent_id, rid, e["first"], e["last"]))
        couleur = ("#dc3545" if e["level"] >= 12 else
                   "#fd7e14" if e["level"] >= 10 else "#ffc107")
        try:
            case.add_event(
                title=titre,
                date_time=e["first"],
                content="\n".join(contenu),
                source="Wazuh",
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
        verifier_fuite(systeme + utilisateur, interdits)
        # Température plus haute : on veut de la variété dans les noms de code.
        rep, _ = completion(systeme, utilisateur,
                            max_tokens=config.CASE_NAME_MAX_TOKENS,
                            temperature=0.8)
        sauver_map(conn, incident["id"], anon.mapping)
        operation = _nettoyer_operation(rep.get("operation") or "")
        titre = rehydrater(str(rep.get("titre") or "").strip(), anon.mapping)[:80]
        if operation and titre:
            return f"[{operation}] {titre}"
    except Exception as e:  # noqa: BLE001 — le nommage ne bloque pas le case
        log.warning("nom de case LLM indisponible (#%s) : %s", incident["id"], e)
    return defaut


def creer_case(conn, incident: dict, triage: dict) -> int:
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

    # IOC (best-effort : un type inconnu ne doit pas faire échouer le case).
    _poser_iocs(case, case_id, alertes)

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
    if not fp:
        _timeline(case, case_id, alertes, incident["agent_id"])

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
    alertes = _alertes(conn, incident["id"])
    fp = triage["verdict"] == "false_positive"

    case = _client()
    desc = (f"Incident #{incident['id']} corrélé par le soc-agent, "
            f"{incident['alert_count']} alertes, niveau max "
            f"{incident['max_level']}/15. Verdict IA : {triage['verdict']}. "
            "(mis à jour — nouvelles alertes rattachées)")
    try:
        case.update_case(case_id=case_id, case_description=desc)
    except Exception as e:  # noqa: BLE001
        log.debug("maj description case #%s : %s", case_id, e)

    _taguer(case, case_id, incident.get("agent_name"))
    _poser_iocs(case, case_id, alertes)

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
        _reconstruire_timeline(case, case_id, alertes, incident["agent_id"])

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


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--incident", type=int, default=None)
    args = ap.parse_args()
    crees = creer_cases(args.incident)
    if not crees:
        print("Aucun incident à verser dans IRIS.")


if __name__ == "__main__":
    main()
