"""Exécution des remédiations décidées au triage, avec trace IRIS par action.

Passage de « proposer » à « exécuter ». Pour chaque action de remédiation d'un
incident vrai positif, on :

1. l'exécute par son canal (Shuffle SOAR pour l'isolation ; API Wazuh pour le
   blocage d'IP et la désactivation de compte) ;
2. écrit une note dans le case IRIS : ce qui a été fait, pourquoi, et COMMENT
   l'annuler — toute mitigation doit être défaisable ;
3. la trace en base (`mitigations`) : audit + idempotence.

Sécurité — ceci exécute des actions à fort impact sur la prod à partir d'un
verdict de modèle, DE FAÇON AUTONOME (but du projet : XDR autonome). Les
barrières ne sont pas un accord humain a priori, mais des garde-fous
déterministes :

- `MITIGATE_EXECUTE=true` : les remédiations sont réellement déclenchées, y
  compris les actions à fort impact (isolation, blocage, désactivation). Mettre
  à `false` pour un dry-run global (bac à sable), pas pour exiger un humain.
- Un incident dont le triage a relevé des motifs d'injection est SUSPENDU :
  un verdict rendu sur un contexte manipulé ne commande pas d'action réelle.
- Comptes protégés (`_compte_protege`) jamais désactivés, niveau de clôture
  plafonné, cibles internes exclues du blocage : la sûreté tient à des règles
  vérifiables dans le code, pas à une revue humaine.
- Seules les actions de l'énumération fermée sont exécutables ; open_case /
  close / escalate ne passent pas par ici.

    python -m soc_agent.mitigate --incident 15
    MITIGATE_EXECUTE=true python -m soc_agent.mitigate --incident 15
"""

import argparse
import json
import logging
import re
import subprocess
import time

import psycopg
import requests
import urllib3
from psycopg.rows import dict_row

from . import config
from .anonymize import _est_interne
from .anonymize import COMPTES_GENERIQUES
from .iris import LIBELLE_ACTION, _client

log = logging.getLogger("mitigate")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Actions réellement exécutables (remédiations). Le reste (open_case,
# close_false_positive, escalate_human) n'est pas une action machine. La
# collecte forensique n'en fait PAS partie : elle n'est pas pilotée par l'IA.
REMEDIATIONS = {"propose_isolate_host", "propose_block_ip",
                "propose_disable_user", "propose_kill_process"}

# Ordre d'exécution : tuer le process malveillant et couper les flux/comptes
# AVANT d'isoler ; isoler EN DERNIER (l'isolation coupe les canaux — API Wazuh,
# Shuffle — dont dépendent les autres remédiations).
ORDRE_EXEC = ["propose_kill_process", "propose_block_ip",
              "propose_disable_user", "propose_isolate_host"]

# Répertoires d'où un exécutable est un implant à tuer (jamais un binaire
# système légitime). Sert à cibler le process malveillant, pas un shell normal.
_DIRS_SUSPECTS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/")


# --- canaux d'exécution -----------------------------------------------------

def _shuffle(webhook: str, payload: dict) -> str:
    r = requests.post(f"{config.SHUFFLE_URL}/api/v1/hooks/{webhook}",
                      json=payload, timeout=15)
    r.raise_for_status()
    return r.text


def fire_isolation(agent_id: str, isoler: bool, reason: str) -> str:
    """Isole (ou désisole) un agent via le webhook Shuffle. Retourne la réponse.

    Même workflow dans les deux sens, seule l'active-response change :
    host-isolate.sh pose les règles nftables, host-unisolate.sh les retire.
    """
    cmd = "!host-isolate.sh" if isoler else "!host-unisolate.sh"
    return _shuffle(config.SHUFFLE_WEBHOOK_ISOLATE,
                    {"agent_id": agent_id, "ar_command": cmd, "reason": reason})


def fire_kill(agent_id: str, process: str, reason: str) -> str:
    """Tue un process par nom exact (comm) sur l'agent, via le webhook Shuffle.

    `extra_args` = le nom EXACT du process (pkill -x côté AR) ; la safelist de
    `kill-process.sh` refuse déjà les process critiques (sshd, agent Wazuh,
    systemd). Chaîne simple : le body Shuffle l'encapsule dans le tableau
    attendu par l'API Wazuh.
    """
    return _shuffle(config.SHUFFLE_WEBHOOK_KILL,
                    {"agent_id": agent_id, "ar_command": "!kill-process.sh",
                     "extra_args": process, "reason": reason})


def _tracer_isolation(agent_id: str, isoler: bool, reason: str) -> None:
    """Trace une (dé)isolation manuelle sur les incidents ouverts de l'agent.

    Pas d'incident rattaché -> pas de trace en base (la table `mitigations` est
    indexée par incident) ; Shuffle et Wazuh gardent de toute façon le journal.
    """
    statut = "exécuté" if isoler else "annulé"
    action, cible = "propose_isolate_host", agent_id
    details = (f"Isolation réseau manuelle de l'agent {agent_id}." if isoler
               else f"Levée manuelle de l'isolation de l'agent {agent_id}.")
    undo = (f"Désisoler : python -m soc_agent.mitigate --desisoler {agent_id}"
            if isoler else "—")
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        incs = conn.execute(
            "SELECT id FROM incidents WHERE agent_id = %s AND iris_case_id IS NOT NULL "
            "ORDER BY id DESC LIMIT 1", (agent_id,)).fetchall()
        for r in incs:
            conn.execute(INSERT_MITIG, {
                "incident_id": r["id"], "action": action, "cible": cible,
                "statut": statut, "details": f"{details} Motif : {reason}",
                "undo": undo, "iris_task_id": None})
        conn.commit()


def _afficher_etat(etat: dict) -> None:
    a = etat["agent_id"]
    if not etat["reachable"]:
        print(f"  agent {a} : état INCONNU (injoignable via SSH depuis le manager)")
    elif etat["isolated"]:
        depuis = (etat.get("marker") or {}).get("since", "?")
        print(f"  agent {a} : ISOLÉ (marqueur présent, depuis {depuis})")
    else:
        print(f"  agent {a} : non isolé (pas de marqueur)")


def isoler(agent_id: str, reason: str = "isolation manuelle") -> None:
    fire_isolation(agent_id, True, reason)
    _tracer_isolation(agent_id, True, reason)
    print(f"  agent {agent_id} : isolation demandée ({reason})")
    _afficher_etat(_confirmer(agent_id, True))


def desisoler(agent_id: str, reason: str = "désisolation manuelle") -> None:
    fire_isolation(agent_id, False, reason)
    _tracer_isolation(agent_id, False, reason)
    print(f"  agent {agent_id} : levée d'isolation demandée ({reason})")
    _afficher_etat(_confirmer(agent_id, False))


def _wazuh_token() -> str:
    r = requests.post(
        f"{config.WAZUH_API_URL}/security/user/authenticate?raw=true",
        auth=(config.WAZUH_API_USER, config.WAZUH_API_PASSWORD),
        verify=False, timeout=15)
    r.raise_for_status()
    return r.text.strip()


def _wazuh_ar(agent_id: str, command: str, arguments: list[str]) -> dict:
    """Déclenche une active-response Wazuh sur un agent (API directe)."""
    tok = _wazuh_token()
    r = requests.put(
        f"{config.WAZUH_API_URL}/active-response",
        params={"agents_list": agent_id},
        headers={"Authorization": f"Bearer {tok}"},
        json={"command": command, "arguments": arguments},
        verify=False, timeout=20)
    r.raise_for_status()
    return r.json()


# --- lecture de l'état d'isolation (marqueur, via SSH) ----------------------

def _agent_ip(agent_id: str) -> str | None:
    tok = _wazuh_token()
    r = requests.get(f"{config.WAZUH_API_URL}/agents",
                     params={"agents_list": agent_id, "select": "ip"},
                     headers={"Authorization": f"Bearer {tok}"},
                     verify=False, timeout=15)
    r.raise_for_status()
    items = r.json().get("data", {}).get("affected_items", [])
    return items[0].get("ip") if items else None


def _interpreter(stdout: str, returncode: int) -> dict:
    """Traduit la sortie de `cat marqueur` en état d'isolation. Fonction pure.

    - rc 255  : échec SSH (agent injoignable) -> état inconnu.
    - stdout non vide : marqueur présent -> isolé (on parse le JSON si possible).
    - stdout vide (fichier absent) : non isolé.
    """
    if returncode == 255:
        return {"isolated": None, "reachable": False, "marker": None}
    texte = stdout.strip()
    if not texte:
        return {"isolated": False, "reachable": True, "marker": None}
    try:
        marker = json.loads(texte)
        isolated = bool(marker.get("isolated"))
    except (json.JSONDecodeError, AttributeError):
        marker, isolated = None, True  # marqueur présent mais illisible = isolé
    return {"isolated": isolated, "reachable": True, "marker": marker}


def etat_isolation(agent_id: str) -> dict:
    """État d'isolation d'un agent, lu depuis le marqueur /var/ossec/isolated.

    Vérité terrain (fichier posé par host-isolate.sh), fiable même agent isolé
    tant que ce lecteur tourne sur l'hôte du manager (SSH autorisé de là).
    Lecture seule, commande figée — pas de shell piloté.
    """
    ip = _agent_ip(agent_id)
    if not ip:
        return {"agent_id": agent_id, "ip": None, "isolated": None,
                "reachable": False, "marker": None}
    cmd = ["ssh", "-i", config.SSH_KEY,
           "-o", "StrictHostKeyChecking=accept-new",
           "-o", "ConnectTimeout=8", "-o", "BatchMode=yes",
           f"{config.SSH_USER}@{ip}",
           f"sudo -n cat {config.ISOLATION_MARKER} 2>/dev/null"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        etat = _interpreter(p.stdout, p.returncode)
    except subprocess.TimeoutExpired:
        etat = {"isolated": None, "reachable": False, "marker": None}
    etat.update({"agent_id": agent_id, "ip": ip})
    return etat


def _confirmer(agent_id: str, attendu: bool, essais: int = 6) -> dict:
    """Attend que le marqueur reflète l'état attendu (l'AR met qq s à se poser)."""
    etat = {}
    for _ in range(essais):
        etat = etat_isolation(agent_id)
        if etat["isolated"] == attendu:
            return etat
        time.sleep(3)
    return etat


# --- exécuteurs par action --------------------------------------------------
#
# Chacun retourne (statut, canal, details, undo). En dry-run, il DÉCRIT l'action
# sans la déclencher (statut 'dry_run'). Toute exception -> statut 'échec'.

def _isolate(cible: str, ctx: dict):
    canal = "Shuffle → active-response host-isolate.sh (nftables)"
    details = ("Isolation réseau de l'hôte : nftables ne laisse joignable que le "
               "manager Wazuh (canal 1514). SSH et tout autre flux sont coupés, "
               "arrêtant une attaque en cours sur la machine.")
    undo = (f"curl -X POST {config.SHUFFLE_URL}/api/v1/hooks/"
            f"{config.SHUFFLE_WEBHOOK_ISOLATE} -H 'Content-Type: application/json' "
            f"-d '{{\"agent_id\": \"{cible}\", \"ar_command\": "
            f"\"!host-unisolate.sh\", \"reason\": \"incident clos\"}}'")
    if config.MITIGATE_EXECUTE:
        fire_isolation(cible, True, ctx["reason_court"])
        return "exécuté", canal, details, undo
    return "dry_run", canal, details, undo


def _block_ip(cible: str, ctx: dict):
    canal = "API Wazuh → active-response firewall-drop"
    details = (f"Blocage du flux réseau de l'IP {cible} sur l'agent "
               f"{ctx['agent_id']} (firewall-drop). Requiert l'AR firewall-drop "
               "configurée sur l'agent ; sinon l'API renvoie une erreur.")
    undo = (f"L'entrée firewall-drop expire au bout du timeout de l'AR. Pour un "
            f"retrait immédiat : supprimer la règle visant {cible} dans le "
            f"pare-feu de l'agent {ctx['agent_id']}.")
    if config.MITIGATE_EXECUTE:
        _wazuh_ar(ctx["agent_id"], "!firewall-drop0", [cible])
        return "exécuté", canal, details, undo
    return "dry_run", canal, details, undo


def _disable_user(cible: str, ctx: dict):
    canal = "API Wazuh → active-response disable-account"
    details = (f"Désactivation du compte {cible} sur l'agent {ctx['agent_id']} "
               "(disable-account). Requiert l'AR disable-account configurée.")
    undo = (f"Réactiver le compte {cible} sur l'agent {ctx['agent_id']} "
            f"(passwd -u {cible} sous Linux, ou enable-account).")
    if config.MITIGATE_EXECUTE:
        _wazuh_ar(ctx["agent_id"], "!disable-account", [cible])
        return "exécuté", canal, details, undo
    return "dry_run", canal, details, undo


def _kill_process(cible: str, ctx: dict):
    canal = "Shuffle → active-response kill-process.sh (pkill -x)"
    details = (f"Arrêt du process malveillant « {cible} » sur l'agent "
               f"{ctx['agent_id']} (pkill -x, nom exact). La safelist de l'AR "
               "protège les process critiques (sshd, agent Wazuh, systemd).")
    undo = ("Action irréversible (pas d'« unkill »). Si le process était "
            "légitime, le relancer manuellement sur l'hôte.")
    if config.MITIGATE_EXECUTE:
        fire_kill(ctx["agent_id"], cible, ctx["reason_court"])
        return "exécuté", canal, details, undo
    return "dry_run", canal, details, undo


EXECUTEURS = {
    "propose_kill_process": _kill_process,
    "propose_isolate_host": _isolate,
    "propose_block_ip": _block_ip,
    "propose_disable_user": _disable_user,
}


# Regex du suffixe "(uid=NNNN)" que certains décodeurs collent au nom de compte.
_RE_UID_SUFFIXE = re.compile(r"\(uid=(\d+)\)")


def _nom_compte(brut: str) -> str:
    """Nom de compte nu, sans le suffixe (uid=NNNN) ni les espaces."""
    return _RE_UID_SUFFIXE.sub("", str(brut)).strip()


def _compte_protege(brut: str) -> bool:
    """Un compte à ne JAMAIS désactiver automatiquement.

    Garde-fou critique : en descendant les seuils, l'activité de comptes
    légitimes (root, l'admin SOC, les sessions de login) entre dans l'incident
    et se retrouvait ciblée par la désactivation — l'IA a réellement verrouillé
    `wazuh-admin`. On protège :
      - les comptes génériques/système (root, admin, system…) ;
      - les comptes d'exploitation du SOC (SSH_USER, WAZUH_API_USER) ;
      - tout compte dont l'uid embarqué est < 1000 (comptes système Linux).
    Le suffixe (uid=NNNN) qui faisait passer `root(uid=0)` à travers le filtre
    exact est désormais normalisé.
    """
    nom = _nom_compte(brut).lower()
    if not nom or nom in COMPTES_GENERIQUES:
        return True
    if nom in {str(config.SSH_USER).lower(), str(config.WAZUH_API_USER).lower()}:
        return True
    m = _RE_UID_SUFFIXE.search(str(brut))
    return bool(m and int(m.group(1)) < 1000)


def _cibles(action: str, incident: dict, alertes: list[dict]) -> list[str]:
    """Cibles d'une action : agent pour l'isolation, IP externes pour le
    blocage, comptes nommés pour la désactivation, process malveillants
    (basename) pour le kill."""
    if action == "propose_isolate_host":
        return [str(incident["agent_id"])]
    if action == "propose_kill_process":
        # Nom exact (comm) des exécutables lancés depuis un répertoire suspect :
        # l'implant, jamais un shell système. pkill -x matchera ce nom.
        noms: set[str] = set()
        for a in alertes:
            raw = a.get("raw")
            if not raw:
                continue
            data = (raw if isinstance(raw, dict) else json.loads(raw)).get("data", {})
            audit = data.get("audit", {}) or {}
            for chemin in (audit.get("exe"), a.get("entity")):
                p = str(chemin or "")
                if p.startswith(_DIRS_SUSPECTS):
                    base = p.rsplit("/", 1)[-1]
                    if base:
                        noms.add(base[:15])   # comm est plafonné à 15 caractères
        return sorted(noms)
    if action == "propose_block_ip":
        return sorted({a["srcip"] for a in alertes
                       if a["srcip"] and not _est_interne(str(a["srcip"]))})
    if action == "propose_disable_user":
        # srcuser d'une activité malveillante, MOINS les comptes protégés.
        comptes = {_nom_compte(a["srcuser"]) for a in alertes if a["srcuser"]
                   and not _compte_protege(a["srcuser"])}
        # Comptes CRÉÉS par l'attaquant (useradd : dstuser + home/shell). Ce
        # sont les cibles les plus pertinentes d'une désactivation, et ils
        # n'apparaissent jamais en srcuser.
        for a in alertes:
            raw = a.get("raw")
            if not raw:
                continue
            data = (raw if isinstance(raw, dict) else json.loads(raw)).get("data", {})
            du = data.get("dstuser")
            if du and not _compte_protege(du) and (data.get("home")
                                                   or data.get("shell")):
                comptes.add(_nom_compte(du))
        return sorted(comptes)
    return []


# --- assets / tasks IRIS + persistance --------------------------------------
#
# Les remédiations ne vont PLUS dans l'onglet Notes : chaque action devient une
# TASK (onglet Tasks) et les cibles concrètes (hôte, comptes) des ASSETS
# (onglet Assets). L'onglet Notes reste réservé à l'analyse (rapport LLM).

# Statut de remédiation -> statut de tâche IRIS.
_STATUT_TASK = {
    "exécuté": "Done",
    "dry_run": "To do",        # simulé : l'action réelle reste à faire
    "échec": "Canceled",
    "annulé": "Canceled",
}


def _desc_tache(triage: dict, cible: str, statut: str, canal: str,
                details: str, undo: str) -> str:
    """Corps (markdown) de la tâche de remédiation."""
    return "\n".join([
        f"**Cible** : {cible}",
        f"**Statut** : {statut}",
        f"**Canal** : {canal}",
        "",
        "## Ce qui a été fait",
        details,
        "",
        "## Pourquoi",
        f"Verdict IA : {triage['verdict']} (confiance {triage['confidence']}). "
        + triage["reason"],
        "",
        "## Comment annuler",
        undo,
    ])


def _assets_existants(case, case_id: int) -> set[str]:
    try:
        d = case.list_assets(case_id).get_data() or {}
        items = d.get("assets") if isinstance(d, dict) else d
        return {a.get("asset_name") for a in (items or [])}
    except Exception as e:  # noqa: BLE001
        log.debug("liste assets case #%s : %s", case_id, e)
        return set()


def _poser_assets(case, case_id: int, inc: dict, alertes: list[dict]) -> None:
    """Renseigne l'onglet Assets : l'hôte touché et les comptes compromis.

    Best-effort et idempotent (dédup sur le nom déjà présent). Les IP/hash/
    fichiers restent des IOC (onglet IOC, posé par iris.py) ; ici on ne met que
    les entités sur lesquelles on AGIT et qui ont un type d'asset propre.
    """
    existants = _assets_existants(case, case_id)

    def ajouter(name: str, atype: str, desc: str) -> None:
        if not name or name in existants:
            return
        try:
            case.add_asset(name=name, asset_type=atype,
                           analysis_status="Started",
                           compromise_status="Compromised",
                           description=desc, cid=case_id)
            existants.add(name)
        except Exception as e:  # noqa: BLE001
            log.debug("asset ignoré (%s) : %s", name, e)

    ajouter(inc.get("agent_name") or str(inc["agent_id"]), "Linux - Server",
            "Hôte touché par l'incident (cible d'isolation / kill de process).")
    for compte in _cibles("propose_disable_user", inc, alertes):
        ajouter(compte, "Linux Account",
                "Compte compromis ou créé par l'attaquant (cible de désactivation).")


INSERT_MITIG = """
INSERT INTO mitigations (incident_id, action, cible, statut, details, undo,
                         iris_task_id)
VALUES (%(incident_id)s, %(action)s, %(cible)s, %(statut)s, %(details)s,
        %(undo)s, %(iris_task_id)s)
ON CONFLICT (incident_id, action, cible) DO UPDATE
SET statut = EXCLUDED.statut, details = EXCLUDED.details, undo = EXCLUDED.undo,
    iris_task_id = EXCLUDED.iris_task_id, executed_at = now()
RETURNING id
"""


def _deja_exec(conn, incident_id: int, action: str, cible: str) -> bool:
    r = conn.execute(
        "SELECT statut FROM mitigations WHERE incident_id=%s AND action=%s "
        "AND cible=%s", (incident_id, action, cible)).fetchone()
    return bool(r and r["statut"] == "exécuté")


SELECT_TRIAGE = """
SELECT verdict, confidence, reason, actions, injection_motifs, garde_fous
  FROM triages WHERE incident_id = %s ORDER BY created_at DESC LIMIT 1
"""


def executer(incident_id: int) -> list[dict]:
    resultats: list[dict] = []
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        inc = conn.execute(
            "SELECT id, agent_id, agent_name, max_level, iris_case_id "
            "FROM incidents WHERE id = %s", (incident_id,)).fetchone()
        if not inc:
            print(f"Incident #{incident_id} introuvable.")
            return []
        triage = conn.execute(SELECT_TRIAGE, (incident_id,)).fetchone()
        if not triage:
            print(f"Incident #{incident_id} pas encore trié.")
            return []

        # Barrière : un verdict rendu sur un contexte manipulé ne commande rien.
        if triage["injection_motifs"]:
            print(f"  #{incident_id} SUSPENDU — motifs d'injection au triage : "
                  f"{', '.join(triage['injection_motifs'])}. Aucune exécution.")
            return []

        remed = [a for a in triage["actions"] if a in REMEDIATIONS]
        if not remed:
            print(f"  #{incident_id} aucune remédiation à exécuter "
                  f"(verdict {triage['verdict']}).")
            return []

        alertes = conn.execute(
            "SELECT srcip, srcuser, entity, raw FROM alerts WHERE incident_id = %s",
            (incident_id,)).fetchall()

        case = _client() if inc["iris_case_id"] else None
        # Assets (onglet Assets) : hôte + comptes, une fois, avant les actions.
        if case:
            _poser_assets(case, inc["iris_case_id"], inc, alertes)

        mode = "EXÉCUTION" if config.MITIGATE_EXECUTE else "DRY-RUN"
        print(f"  #{incident_id} {inc['agent_name']} — {mode} — "
              f"{len(remed)} action(s)")

        ctx = {"agent_id": str(inc["agent_id"]),
               "reason_court": (triage["reason"] or "")[:120]}

        for action in sorted(remed, key=lambda a: ORDRE_EXEC.index(a)
                             if a in ORDRE_EXEC else 99):
            for cible in _cibles(action, inc, alertes):
                if config.MITIGATE_EXECUTE and _deja_exec(
                        conn, incident_id, action, cible):
                    print(f"      {action} [{cible}] déjà exécuté, ignoré.")
                    continue
                try:
                    statut, canal, details, undo = EXECUTEURS[action](cible, ctx)
                except Exception as e:  # noqa: BLE001 — un échec de canal ne doit
                    # pas arrêter les autres remédiations ; on le trace.
                    statut, canal = "échec", "—"
                    details, undo = f"Échec du canal : {e}", "—"
                    log.warning("échec %s [%s] : %s", action, cible, e)

                # Chaque remédiation = une TASK (onglet Tasks), pas une note.
                task_id = None
                if case:
                    titre = ("[SIMULATION] " if statut == "dry_run" else "") + \
                        f"Remédiation — {LIBELLE_ACTION.get(action, action)} ({cible})"
                    rt = case.add_task(
                        title=titre,
                        status=_STATUT_TASK.get(statut, "To do"),
                        assignees=[],
                        description=_desc_tache(triage, cible, statut, canal,
                                                details, undo),
                        tags=["remediation", "auto"],
                        cid=inc["iris_case_id"])
                    if rt.is_success():
                        task_id = rt.get_data().get("id")

                conn.execute(INSERT_MITIG, {
                    "incident_id": incident_id, "action": action, "cible": cible,
                    "statut": statut, "details": details, "undo": undo,
                    "iris_task_id": task_id})
                conn.commit()

                resultats.append({"action": action, "cible": cible,
                                  "statut": statut})
                print(f"      {action} [{cible}] -> {statut}  ({canal})")
    return resultats


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    ap = argparse.ArgumentParser(description=__doc__)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--incident", type=int,
                   help="exécute les remédiations décidées au triage de cet incident")
    g.add_argument("--isoler", metavar="AGENT_ID",
                   help="isole un agent du réseau (action opérateur, exécutée)")
    g.add_argument("--desisoler", metavar="AGENT_ID",
                   help="lève l'isolation d'un agent (action opérateur, exécutée)")
    g.add_argument("--etat", metavar="AGENT_ID",
                   help="lit l'état d'isolation d'un agent (marqueur, SSH)")
    ap.add_argument("--motif", default="action opérateur",
                    help="motif consigné avec l'(dé)isolation manuelle")
    args = ap.parse_args()

    # --isoler / --desisoler sont des commandes opérateur explicites : elles
    # s'exécutent réellement, indépendamment de MITIGATE_EXECUTE (qui ne borne
    # que l'exécution AUTOMATIQUE depuis un verdict).
    if args.isoler:
        isoler(args.isoler, args.motif)
    elif args.desisoler:
        desisoler(args.desisoler, args.motif)
    elif args.etat:
        _afficher_etat(etat_isolation(args.etat))
    else:
        executer(args.incident)


if __name__ == "__main__":
    main()
