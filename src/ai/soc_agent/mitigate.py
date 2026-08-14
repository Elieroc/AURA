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
import ipaddress
import json
import logging
import ntpath
import re
import subprocess
import time

import psycopg
import requests
import urllib3
from psycopg.rows import dict_row

from . import alerts as alerts_mod
from . import config
from .anonymize import GENERIC_ACCOUNTS
from .iris import (LABEL_ACTION, _client, _iocs, _ip_internal,
                   _ip_ioc_valid, _ips_revshell)

log = logging.getLogger("mitigate")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Actions réellement exécutables (remédiations). Le reste (open_case,
# close_false_positive, escalate_human) n'est pas une action machine. La
# collecte forensique n'en fait PAS partie : elle n'est pas pilotée par l'IA.
REMEDIATIONS = {"propose_isolate_host", "propose_block_ip",
                "propose_disable_user", "propose_kill_process",
                "propose_quarantine_file", "propose_remove_privileged_group"}

# Ordre d'exécution : tuer le process malveillant, mettre le fichier en
# quarantaine et couper les flux/comptes AVANT d'isoler ; isoler EN DERNIER
# (l'isolation coupe les canaux — API Wazuh, Shuffle — dont dépendent les autres
# remédiations).
ORDER_EXEC = ["propose_kill_process", "propose_quarantine_file",
              "propose_block_ip", "propose_disable_user",
              "propose_remove_privileged_group", "propose_isolate_host"]

# Actions PROPOSÉES seulement (jamais exécutées automatiquement, même en
# MITIGATE_EXECUTE) : trop fort impact pour l'autonomie actuelle (retrait d'un
# groupe privilégié AD). L'exécuteur rend 'dry_run' et l'analyste tranche via la
# tâche IRIS. Cf. le palier d'autonomie « local + disable AD account auto ».
MANUAL_ACTIONS = {"propose_remove_privileged_group"}

# Répertoires d'où un exécutable est un implant à tuer (jamais un binaire
# système légitime). Sert à cibler le process malveillant, pas un shell normal.
_DIRS_SUSPICIOUS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/")


# --- canaux d'exécution -----------------------------------------------------

def _shuffle(webhook: str, payload: dict) -> str:
    r = requests.post(f"{config.SHUFFLE_URL}/api/v1/hooks/{webhook}",
                      json=payload, timeout=15)
    r.raise_for_status()
    return r.text


def fire_isolation(agent_id: str, isolate: bool, reason: str) -> str:
    """Isole (ou désisole) un agent via le webhook Shuffle. Retourne la réponse.

    Même workflow dans les deux sens, seule l'active-response change :
    host-isolate.sh pose les règles nftables, host-unisolate.sh les retire.
    """
    cmd = "!host-isolate.sh" if isolate else "!host-unisolate.sh"
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


def _trace_isolation(agent_id: str, isolate: bool, reason: str) -> None:
    """Trace une (dé)isolation manuelle sur les incidents ouverts de l'agent.

    Pas d'incident rattaché -> pas de trace en base (la table `mitigations` est
    indexée par incident) ; Shuffle et Wazuh gardent de toute façon le journal.
    """
    status = "exécuté" if isolate else "annulé"
    action, target = "propose_isolate_host", agent_id
    details = (f"Isolation réseau manuelle de l'agent {agent_id}." if isolate
               else f"Levée manuelle de l'isolation de l'agent {agent_id}.")
    undo = (f"Désisoler : python -m soc_agent.mitigate --desisoler {agent_id}"
            if isolate else "—")
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        incs = conn.execute(
            "SELECT id FROM incidents WHERE agent_id = %s AND iris_case_id IS NOT NULL "
            "ORDER BY id DESC LIMIT 1", (agent_id,)).fetchall()
        for r in incs:
            conn.execute(INSERT_MITIG, {
                "incident_id": r["id"], "action": action, "target": target,
                "agent_id": agent_id, "status": status,
                "details": f"{details} Motif : {reason}",
                "undo": undo, "iris_task_id": None})
        conn.commit()


def _show_state(state: dict) -> None:
    a = state["agent_id"]
    if not state["reachable"]:
        print(f"  agent {a} : état INCONNU (injoignable via SSH depuis le manager)")
    elif state["isolated"]:
        since = (state.get("marker") or {}).get("since", "?")
        print(f"  agent {a} : ISOLÉ (marqueur présent, depuis {since})")
    else:
        print(f"  agent {a} : non isolé (pas de marqueur)")


def isolate(agent_id: str, reason: str = "isolation manuelle",
           forcer: bool = False) -> None:
    """Isolation demandée par un opérateur.

    Le garde-fou « endpoints seulement » s'applique AUSSI ici : un opérateur qui
    tape la commande sur un pare-feu ne veut presque jamais couper le site, il
    s'est trompé d'agent. Mais il reste le décideur — `--forcer` lève le refus.
    C'est la différence entre une barrière (l'automatisme, jamais franchissable)
    et un filet (l'humain, qui doit dire explicitement qu'il sait).
    """
    refusal = not_isolatable_reason(agent_id)
    if refusal and not forcer:
        print(f"  REFUS : {refusal}")
        print("  Relancer avec --forcer si l'isolation est bien voulue.")
        return
    if refusal:
        print(f"  /!\\ garde-fou outrepassé (--forcer) : {refusal}")
    fire_isolation(agent_id, True, reason)
    _trace_isolation(agent_id, True, reason)
    print(f"  agent {agent_id} : isolation demandée ({reason})")
    _show_state(_confirm(agent_id, True))


def unisolate(agent_id: str, reason: str = "désisolation manuelle") -> None:
    fire_isolation(agent_id, False, reason)
    _trace_isolation(agent_id, False, reason)
    print(f"  agent {agent_id} : levée d'isolation demandée ({reason})")
    _show_state(_confirm(agent_id, False))


def _wazuh_token() -> str:
    r = requests.post(
        f"{config.WAZUH_API_URL}/security/user/authenticate?raw=true",
        auth=(config.WAZUH_API_USER, config.WAZUH_API_PASSWORD),
        verify=False, timeout=15)
    r.raise_for_status()
    return r.text.strip()


# Horodatage (monotone) de la dernière AR émise, pour sérialiser les rafales.
_last_ar_ts: float = 0.0


def _throttle_ar() -> None:
    """Espace les émissions d'AR d'au moins MITIGATE_AR_GAP_SECONDS.

    `wazuh-execd` traite les active-responses en file ; une rafale de commandes
    rapprochées vers le même agent en fait droper une partie avant même le
    script (mesuré à l'exercice). On tient un intervalle minimal entre deux envois.
    """
    global _last_ar_ts
    gap = config.MITIGATE_AR_GAP_SECONDS
    if gap > 0:
        remains = gap - (time.monotonic() - _last_ar_ts)
        if remains > 0:
            time.sleep(remains)
    _last_ar_ts = time.monotonic()


def _wazuh_ar(agent_id: str, command: str, arguments: list[str]) -> dict:
    """Déclenche une active-response Wazuh sur un agent (API directe).

    Lève si l'API n'a pas retenu l'agent. Un 200 ne suffit pas : l'API répond
    200 avec l'agent dans `failed_items` quand il est déconnecté ou inconnu, et
    l'appelant marquait alors la remédiation 'executed' alors que rien n'était
    parti.

    Reste hors de portée : le RÉSULTAT du script côté agent. L'API est
    fire-and-forget, l'AR ne renvoie rien — un script qui refuse la cible ne
    remonte que dans `active-responses.log` de l'agent. D'où l'importance que le
    script lui-même soit correct (cf. wazuh/active-response/), la vérification
    de bout en bout ne pouvant se faire qu'en lisant l'état réel de l'hôte.
    """
    _throttle_ar()
    tok = _wazuh_token()
    r = requests.put(
        f"{config.WAZUH_API_URL}/active-response",
        params={"agents_list": agent_id},
        headers={"Authorization": f"Bearer {tok}"},
        json={"command": command, "arguments": arguments},
        verify=False, timeout=20)
    r.raise_for_status()
    rep = r.json()
    data = rep.get("data", {}) or {}
    failures = data.get("failed_items") or []
    if failures or not (data.get("affected_items") or []):
        raise RuntimeError(
            f"l'API Wazuh n'a pas transmis {command} à l'agent {agent_id} : "
            f"{rep.get('message') or ''} {failures}".strip())
    return rep


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


# IP de tous les agents du parc, mémoïsées le temps du process. L'inventaire ne
# bouge pas à l'échelle d'un cycle de remédiation ; un appel API suffit.
_IPS_AGENTS_CACHE: set[str] | None = None


def _agent_ips() -> set[str]:
    """IP de tous les agents Wazuh — nos propres assets surveillés.

    Garde-fou de blocage : une IP d'agent n'est JAMAIS une cible de block_ip.
    Un hôte du parc qui apparaît en srcip est une victime ou un pivot (l'attaque
    a rebondi PAR lui), pas l'attaquant — on le contient sur SA machine
    (isolation, désactivation de compte), on ne blackhole pas son IP chez un
    voisin. Mesuré à un exercice purple-team : block_ip a visé l'IP d'un hôte pivot
    (une victime, pas l'attaquant), parce que son subnet n'était pas
    dans NETWORKS_INTERNAL — l'exclusion par appartenance au parc est robuste
    quel que soit le plan d'adressage, et laisse bloquable un attaquant qui
    partagerait le même subnet sans être un agent.

    En cas d'API injoignable : ensemble vide (on ne bloque pas la remédiation,
    mais on trace — le repli est « bloquer sans exclusion d'asset », pas « ne
    rien bloquer »)."""
    global _IPS_AGENTS_CACHE
    if _IPS_AGENTS_CACHE is not None:
        return _IPS_AGENTS_CACHE
    ips: set[str] = set()
    try:
        tok = _wazuh_token()
        r = requests.get(f"{config.WAZUH_API_URL}/agents",
                         params={"select": "ip", "limit": 1000},
                         headers={"Authorization": f"Bearer {tok}"},
                         verify=False, timeout=15)
        r.raise_for_status()
        for it in r.json().get("data", {}).get("affected_items", []):
            ip = it.get("ip")
            if ip:
                ips.add(str(ip))
    except (requests.RequestException, ValueError, KeyError) as e:
        log.warning("inventaire IP des agents illisible (%s) : blocage sans "
                    "exclusion d'asset ce tour-ci", e)
    _IPS_AGENTS_CACHE = ips
    return ips


def _is_private_ip(ip: str) -> bool:
    """IP en plage privée RFC1918/loopback/link-local (pour l'ORDRE de blocage).

    Sert uniquement à trier : les IP publiques d'abord. Ce n'est PAS un critère
    d'exclusion — un C2 peut être en RFC1918 (VPN, cloud privé...) et doit
    rester bloquable — juste une priorité : un attaquant réel est le plus
    souvent hors RFC1918, une IP privée résiduelle est plus probablement un
    rebond interne mal classé."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _agent_groups(agent_id: str) -> set[str] | None:
    """Groupes Wazuh de l'agent, ou None si on n'a pas pu les lire.

    None et set() ne veulent PAS dire la même chose : None = « je ne sais pas »
    (API injoignable, agent inconnu), set() = « aucun groupe », qui est un fait.
    L'appelant traite les deux différemment.
    """
    try:
        tok = _wazuh_token()
        r = requests.get(f"{config.WAZUH_API_URL}/agents",
                         params={"agents_list": agent_id, "select": "group"},
                         headers={"Authorization": f"Bearer {tok}"},
                         verify=False, timeout=15)
        r.raise_for_status()
        items = r.json().get("data", {}).get("affected_items", [])
        if not items:
            return None
        return {str(g).lower() for g in (items[0].get("group") or [])}
    except (requests.RequestException, ValueError, KeyError) as e:
        log.warning("groupes de l'agent %s illisibles : %s", agent_id, e)
        return None


def not_isolatable_reason(agent_id: str) -> str | None:
    """Motif de refus d'isolation pour cet agent, ou None s'il est isolable.

    L'isolation ne vise que les ENDPOINTS. Trois barrières, dans l'ordre :

    1. agent explicitement protégé (`AGENTS_PROTECTED`, dont 000 le manager, qui
       n'a d'ailleurs aucun groupe — le mécanisme de groupes ne le couvrirait
       pas) ;
    2. agent appartenant à un groupe d'infrastructure : pare-feu, proxy, DNS,
       VPN. Ces machines acheminent le trafic d'autrui, les couper provoque une
       panne générale au lieu de contenir un incident ;
    3. rôle indéterminable — refus par défaut (cf.
       ISOLATION_REFUSE_IF_ROLE_UNKNOWN).
    """
    if str(agent_id) in config.AGENTS_PROTECTED:
        return f"agent {agent_id} protégé (AGENTS_PROTECTED)"

    groups = _agent_groups(str(agent_id))
    if groups is None:
        if config.ISOLATION_REFUSE_IF_ROLE_UNKNOWN:
            return (f"rôle de l'agent {agent_id} indéterminable (groupes "
                    "illisibles) — isolation refusée par prudence")
        return None

    forbidden = groups & config.ISOLATION_FORBIDDEN_GROUPS
    if forbidden:
        return (f"agent {agent_id} dans le groupe {', '.join(sorted(forbidden))} "
                "— infrastructure réseau, jamais isolée")
    return None


def _interpret(stdout: str, returncode: int) -> dict:
    """Traduit la sortie de `cat marqueur` en état d'isolation. Fonction pure.

    - rc 255  : échec SSH (agent injoignable) -> état inconnu.
    - stdout non vide : marqueur présent -> isolé (on parse le JSON si possible).
    - stdout vide (fichier absent) : non isolé.
    """
    if returncode == 255:
        return {"isolated": None, "reachable": False, "marker": None}
    text = stdout.strip()
    if not text:
        return {"isolated": False, "reachable": True, "marker": None}
    try:
        marker = json.loads(text)
        isolated = bool(marker.get("isolated"))
    except (json.JSONDecodeError, AttributeError):
        marker, isolated = None, True  # marqueur présent mais illisible = isolé
    return {"isolated": isolated, "reachable": True, "marker": marker}


def isolation_state(agent_id: str) -> dict:
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
        state = _interpret(p.stdout, p.returncode)
    except subprocess.TimeoutExpired:
        state = {"isolated": None, "reachable": False, "marker": None}
    state.update({"agent_id": agent_id, "ip": ip})
    return state


def _confirm(agent_id: str, expected: bool, attempts: int = 6) -> dict:
    """Attend que le marqueur reflète l'état attendu (l'AR met qq s à se poser)."""
    state = {}
    for _ in range(attempts):
        state = isolation_state(agent_id)
        if state["isolated"] == expected:
            return state
        time.sleep(3)
    return state


# --- exécuteurs par action --------------------------------------------------
#
# Chacun retourne (statut, canal, details, undo). En dry-run, il DÉCRIT l'action
# sans la déclencher (statut 'dry_run'). Toute exception -> statut 'failed'.

def _agent_windows(agent_id: str) -> bool:
    """Vrai si l'agent tourne sous Windows (route vers les AR Windows/AD)."""
    return str(agent_id) in config.AGENTS_WINDOWS


def _un_dc() -> str | None:
    """Un agent contrôleur de domaine (exécuteur des actions de domaine)."""
    return sorted(config.AGENTS_DC)[0] if config.AGENTS_DC else None


def _isolate(target: str, ctx: dict):
    if _agent_windows(ctx["agent_id"]):
        channel = "API Wazuh → win-host-isolate.exe (Windows Firewall)"
        details = (f"Isolation réseau de l'hôte Windows {ctx['agent_id']} : le "
                   "pare-feu ne laisse joignable que le manager Wazuh "
                   f"({', '.join(config.MITIGATE_ISOLATE_ALLOW)}). Un DC n'est "
                   "jamais isolé (refus dans le script).")
        undo = (f"Lever l'isolation : active-response win-host-unisolate.exe sur "
                f"l'agent {ctx['agent_id']}.")
        if config.MITIGATE_EXECUTE:
            _wazuh_ar(ctx["agent_id"], "!win-host-isolate.exe",
                      list(config.MITIGATE_ISOLATE_ALLOW))
            return "émis", channel, details, undo
        return "dry_run", channel, details, undo

    channel = "Shuffle → active-response host-isolate.sh (nftables)"
    details = ("Isolation réseau de l'hôte : nftables ne laisse joignable que le "
               "manager Wazuh (canal 1514). SSH et tout autre flux sont coupés, "
               "arrêtant une attaque en cours sur la machine.")
    undo = (f"curl -X POST {config.SHUFFLE_URL}/api/v1/hooks/"
            f"{config.SHUFFLE_WEBHOOK_ISOLATE} -H 'Content-Type: application/json' "
            f"-d '{{\"agent_id\": \"{target}\", \"ar_command\": "
            f"\"!host-unisolate.sh\", \"reason\": \"incident clos\"}}'")
    if config.MITIGATE_EXECUTE:
        fire_isolation(target, True, ctx["reason_court"])
        return "émis", channel, details, undo
    return "dry_run", channel, details, undo


def _block_ip(target: str, ctx: dict):
    win = _agent_windows(ctx["agent_id"])
    ar = "!win-block-ip.exe" if win else "!firewall-drop.sh"
    channel = ("API Wazuh → win-block-ip.exe (Windows Firewall)" if win
             else "API Wazuh → active-response firewall-drop")
    details = (f"Blocage du flux réseau de l'IP {target} sur l'agent "
               f"{ctx['agent_id']} ({ar}). Requiert l'AR configurée sur l'agent.")
    undo = (f"Retrait : active-response "
            f"{'win-allow-ip.exe' if win else 'firewall-allow'} visant {target} "
            f"sur l'agent {ctx['agent_id']}.")
    if config.MITIGATE_EXECUTE:
        _wazuh_ar(ctx["agent_id"], ar, [target])
        return "émis", channel, details, undo
    return "dry_run", channel, details, undo


def _disable_user(target: str, ctx: dict):
    # Sur une cible Windows, _cibles_par_machine a déjà routé ctx['agent_id']
    # vers un DC : on désactive le compte DANS l'annuaire (ad-disable-account),
    # pas localement sur l'hôte membre où le compte n'existe pas.
    win = _agent_windows(ctx["agent_id"])
    ar = "!ad-disable-account.exe" if win else "!disable-account.sh"
    channel = ("API Wazuh → ad-disable-account.exe (Active Directory, sur DC)" if win
             else "API Wazuh → active-response disable-account")
    details = (f"Désactivation du compte {target} "
               f"{'dans AD (sur le DC ' + ctx['agent_id'] + ')' if win else 'sur agent ' + ctx['agent_id']} "
               f"({ar}). Comptes protégés refusés par le script.")
    undo = (f"Réactiver le compte {target} : active-response "
            f"{'ad-enable-account.exe' if win else 'enable-account'} sur l'agent "
            f"{ctx['agent_id']}.")
    if config.MITIGATE_EXECUTE:
        _wazuh_ar(ctx["agent_id"], ar, [target])
        return "émis", channel, details, undo
    return "dry_run", channel, details, undo


def _kill_process(target: str, ctx: dict):
    if _agent_windows(ctx["agent_id"]):
        # Cible « image.exe#pid » (cf. _win_process_suspects) : on envoie le PID
        # en premier argument et l'image attendue en second. Le script tue le
        # PID SEULEMENT s'il porte encore cette image — un PID est réutilisé, et
        # il s'écoule jusqu'à 5 min entre l'alerte et la remédiation.
        image, _, pid = target.partition("#")
        args = [pid, image] if pid else [image]
        precision = (f"PID {pid} (image attendue « {image} », vérifiée par le "
                     "script avant l'arrêt)" if pid
                     else f"toutes les instances de « {image} »")
        channel = "API Wazuh → win-kill-process.exe (Stop-Process)"
        details = (f"Arrêt du process sur l'hôte Windows {ctx['agent_id']} : "
                   f"{precision}. La safelist du script protège les process "
                   "critiques (lsass, services, agent Wazuh, Sysmon) et les "
                   "images génériques (powershell, cmd, net, wsmprovhost), qui "
                   "ne sont tuables que par PID.")
        undo = ("Action irréversible (pas d'« unkill »).")
        if config.MITIGATE_EXECUTE:
            _wazuh_ar(ctx["agent_id"], "!win-kill-process.exe", args)
            return "émis", channel, details, undo
        return "dry_run", channel, details, undo

    channel = "Shuffle → active-response kill-process.sh (pkill -x)"
    details = (f"Arrêt du process malveillant « {target} » sur l'agent "
               f"{ctx['agent_id']} (pkill -x, nom exact). La safelist de l'AR "
               "protège les process critiques (sshd, agent Wazuh, systemd).")
    undo = ("Action irréversible (pas d'« unkill »). Si le process était "
            "légitime, le relancer manuellement sur l'hôte.")
    if config.MITIGATE_EXECUTE:
        fire_kill(ctx["agent_id"], target, ctx["reason_court"])
        return "émis", channel, details, undo
    return "dry_run", channel, details, undo


def _quarantine_file(target: str, ctx: dict):
    # Windows uniquement (analogue quarantine.sh côté Linux non exposé à l'IA).
    channel = "API Wazuh → win-quarantine-file.exe (déplacement + deny ACL)"
    details = (f"Mise en quarantaine du fichier {target} sur l'hôte Windows "
               f"{ctx['agent_id']} : hash SHA256, déplacement vers le dossier de "
               "quarantaine, accès refusé. Les chemins système sont exclus.")
    undo = (f"Restaurer : active-response win-restore-file.exe pour {target} sur "
            f"l'agent {ctx['agent_id']}.")
    if config.MITIGATE_EXECUTE:
        _wazuh_ar(ctx["agent_id"], "!win-quarantine-file.exe", [target])
        return "émis", channel, details, undo
    return "dry_run", channel, details, undo


def _remove_group_member(target: str, ctx: dict):
    # PROPOSE-ONLY (ACTIONS_MANUELLES) : jamais exécuté automatiquement, même en
    # MITIGATE_EXECUTE. cible = "groupe|membre".
    group, _, member = target.partition("|")
    channel = "API Wazuh → ad-remove-group-member.exe (Active Directory, sur DC)"
    details = (f"Retrait de « {member} » du groupe privilégié « {group} » dans "
               f"AD (sur le DC {ctx['agent_id']}). Action à FORT IMPACT — proposée "
               "à l'analyste, exécution manuelle (palier d'autonomie actuel).")
    undo = (f"Réintégrer : active-response ad-add-group-member.exe {group} "
            f"{member} sur l'agent {ctx['agent_id']}.")
    # Toujours 'dry_run' : c'est une proposition, l'analyste exécute la tâche IRIS.
    return "dry_run", channel, details, undo


EXECUTEURS = {
    "propose_kill_process": _kill_process,
    "propose_quarantine_file": _quarantine_file,
    "propose_isolate_host": _isolate,
    "propose_block_ip": _block_ip,
    "propose_disable_user": _disable_user,
    "propose_remove_privileged_group": _remove_group_member,
}


# --- reverse par action (annulation d'une remédiation) ----------------------
#
# Toute remédiation doit être défaisable : quand l'analyste passe la tâche IRIS
# d'une action en 'Canceled', `reconcilier` rejoue le reverse correspondant.
# Chacun défait l'action par le MÊME canal que l'aller (Shuffle pour l'hôte, API
# Wazuh pour l'IP/compte), via l'active-response inverse. Retourne le libellé du
# canal utilisé, et LÈVE si le canal échoue (l'appelant garde alors le statut
# 'executed' et retentera).
#
# Un reverse s'exécute TOUJOURS, indépendamment de MITIGATE_EXECUTE — même
# logique que --isoler/--desisoler : ce drapeau ne borne que l'exécution
# AUTOMATIQUE depuis un verdict, jamais la restauration. Le gater était un piège
# de sûreté : `reconcilier` marque 'canceled' dès que le reverse rend la main, donc
# couper l'exécution puis annuler ne défaisait RIEN tout en sortant la ligne de
# la sélection `statut='executed'` — l'annulation était perdue en silence, sans
# nouvelle tentative possible. Et il n'y a rien à protéger : seules les actions
# réellement parties portent le statut 'executed' (une action en dry-run reste en
# 'dry_run'), donc un reverse ne touche que ce qui a vraiment été appliqué.

def _revert_isolate(target: str, ctx: dict) -> str:
    if _agent_windows(ctx["agent_id"]):
        _wazuh_ar(ctx["agent_id"], "!win-host-unisolate.exe", [])
        return "API Wazuh → win-host-unisolate.exe (Windows Firewall)"
    fire_isolation(target, False, ctx["reason_court"])
    return "Shuffle → active-response host-unisolate.sh (nftables)"


def _revert_block_ip(target: str, ctx: dict) -> str:
    if _agent_windows(ctx["agent_id"]):
        _wazuh_ar(ctx["agent_id"], "!win-allow-ip.exe", [target])
        return "API Wazuh → win-allow-ip.exe (Windows Firewall)"
    _wazuh_ar(ctx["agent_id"], "!firewall-allow.sh", [target])
    return "API Wazuh → active-response firewall-allow"


def _revert_disable_user(target: str, ctx: dict) -> str:
    if _agent_windows(ctx["agent_id"]):
        _wazuh_ar(ctx["agent_id"], "!ad-enable-account.exe", [target])
        return "API Wazuh → ad-enable-account.exe (Active Directory, sur DC)"
    _wazuh_ar(ctx["agent_id"], "!enable-account.sh", [target])
    return "API Wazuh → active-response enable-account"


def _revert_quarantine_file(target: str, ctx: dict) -> str:
    _wazuh_ar(ctx["agent_id"], "!win-restore-file.exe", [target])
    return "API Wazuh → win-restore-file.exe"


# Pas de propose_kill_process : un process tué n'a pas de reverse (« unkill »).
# Pas de propose_remove_privileged_group : proposé seulement, jamais exécuté auto
# (donc jamais 'executed' à défaire) ; ad-add-group-member reste dispo à la main.
REVERTERS = {
    "propose_isolate_host": _revert_isolate,
    "propose_block_ip": _revert_block_ip,
    "propose_disable_user": _revert_disable_user,
    "propose_quarantine_file": _revert_quarantine_file,
}


# Regex du suffixe "(uid=NNNN)" que certains décodeurs collent au nom de compte.
_RE_UID_SUFFIX = re.compile(r"\(uid=(\d+)\)")


def _account_name(raw: str) -> str:
    """Nom de compte nu : sans (uid=NNNN), sans préfixe DOMAINE\\ ni @domaine.

    Le préfixe de domaine Windows (`LAB\\Administrateur`, `Administrateur@lab`)
    faisait échouer le filtre des comptes protégés (comparé à la forme nue) et
    devenait une mauvaise cible d'action — ad-disable-account veut le SAM nu.
    """
    name = _RE_UID_SUFFIX.sub("", str(raw))
    name = re.split(r"[\\/]", name)[-1]      # DOMAINE\user -> user
    name = name.split("@", 1)[0]             # user@domaine -> user
    return name.strip()


# Comptes Windows/AD intégrés à ne JAMAIS désactiver (COMPTES_GENERIQUES ne porte
# que la forme anglaise « administrator »). Miroir du garde-fou de l'AR
# (_ar-common.ps1 Test-ProtectedAccount) côté sélection de cible Python : sans
# ça, l'IA tirait sur « Administrateur » et le compte machine « WIN-DC$ » (vus
# comme srcuser dans les logons), rattrapés seulement par le script AR.
#
# Les libellés de « compte » qui apparaissent dans les events de logon Windows
# ne sont pas tous des comptes : `Système`, `ANONYMOUS LOGON`, `SERVICE LOCAL`,
# `UMFD-0` sont des identités bien connues (well-known SID) ou des sessions de
# service. Un exercice purple-team a envoyé `ad-disable-account` sur trois
# d'entre elles (seul le script AR a refusé). Les deux graphies sont listées :
# un DC en français renvoie l'une, un DC anglais renvoie l'autre.
_ACCOUNTS_WINDOWS_PROTECTED = {
    "administrateur", "krbtgt", "defaultaccount", "wdagutilityaccount",
    "localservice",
    # identités système, graphie EN puis FR
    "system", "système", "local service", "service local",
    "network service", "service réseau", "anonymous logon",
    "connexion anonyme", "iusr", "invité", "guest",
    "openssh_users", "tout le monde", "everyone",
}

# Comptes techniques de session dont le nom est indexé (UMFD-0, DWM-1, DWM-2…).
_RE_ACCOUNT_SESSION = re.compile(r"^(umfd|dwm)-\d+$", re.IGNORECASE)


def _created_accounts(alerts: list[dict]) -> list[str]:
    """Comptes CRÉÉS par l'attaquant (useradd/adduser), non protégés.

    Réutilise l'extraction d'IOC d'iris (`_iocs`, type « account ») : elle
    décode la ligne de commande depuis le proctitle auditd (règle 80792, niv. 3)
    et capte le backdoor account MÊME quand l'alerte syslog 5902 « new user »
    (qui porte dstuser/home/shell) n'est pas ingérée. C'est le point de vérité
    unique pour « quel compte l'attaquant a-t-il créé ». Comptes protégés exclus.
    """
    return sorted({v for v, t, _ in _iocs(alerts)
                   if t == "account" and not _is_protected_account(v)})


def _is_protected_account(raw: str) -> bool:
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
    name = _account_name(raw).lower()
    if not name or name in GENERIC_ACCOUNTS or name in _ACCOUNTS_WINDOWS_PROTECTED:
        return True
    if name.endswith("$"):        # compte machine / trust AD (ex. WIN-DC$)
        return True
    if _RE_ACCOUNT_SESSION.match(name):   # UMFD-0, DWM-1 : sessions, pas des comptes
        return True
    if name in {str(config.SSH_USER).lower(), str(config.WAZUH_API_USER).lower()}:
        return True
    m = _RE_UID_SUFFIX.search(str(raw))
    return bool(m and int(m.group(1)) < 1000)


_WIN_EXE_EXT = (".exe", ".dll", ".ps1", ".bat", ".scr", ".com", ".vbs")

# Sondes AppLocker créées par PowerShell lui-même à chaque lancement dans
# %TEMP% : ce ne sont ni un implant, ni un process de l'attaquant. Le
# exercice purple-team en a tué et mis en quarantaine dix.
_RE_PROBE_PS = re.compile(r"__PSScriptPolicyTest_", re.IGNORECASE)

# Préfixes de chemin long Windows : `\\?\`, `\??\` (forme objet NT) et leurs
# variantes UNC. Ils désignent exactement le même fichier que le chemin nu mais
# ne commencent pas par `c:\windows` — ce qui suffisait à faire passer un
# binaire de System32 pour un implant déposé (cf. _norm_chemin_win).
_RE_PREFIX_LONG = re.compile(r"^\\{1,2}\?{1,2}\\(?P<unc>UNC\\)?", re.IGNORECASE)

# Noms de process trop génériques pour être tués « par nom » : Stop-Process
# -Name tue TOUTES les instances de la machine. Sur le DC d'un exercice purple-team, le
# kill de `powershell` et `wsmprovhost` a coupé les sessions d'administration
# et toutes les sessions WinRM légitimes. Ces process ne sont tuables que par
# PID, avec vérification de l'image côté script AR.
_NAMES_PROCESS_GENERIC = {
    "powershell.exe", "powershell_ise.exe", "pwsh.exe", "cmd.exe", "net.exe",
    "net1.exe", "wsmprovhost.exe", "conhost.exe", "explorer.exe", "runas.exe",
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "wmic.exe", "cscript.exe",
    "wscript.exe", "svchost.exe", "dllhost.exe", "taskhostw.exe",
    "werfault.exe", "msiexec.exe", "schtasks.exe", "reg.exe", "sc.exe",
}


def _norm_win_path(raw: str) -> str:
    """Chemin Windows normalisé : séparateurs simples, sans guillemets.

    Le JSON de l'eventchannel Windows arrive avec les backslashes DOUBLÉS et
    Wazuh les conserve tels quels — `C:\\\\Windows\\\\System32\\\\cmd.exe` est
    stocké avec deux caractères backslash entre chaque segment. Le test
    d'exclusion des répertoires système comparait donc `c:\\\\windows...` à
    `c:\\windows` : jamais vrai. Résultat mesuré à un exercice purple-team :
    26 ordres de quarantaine sur des binaires signés de System32 d'un
    contrôleur de domaine (cmd.exe, net.exe, powershell.exe, dsquery.exe…),
    rattrapés uniquement par la safelist du script AR. Normaliser ici est la
    PREMIÈRE barrière ; celle du script reste la dernière.

    La normalisation va plus loin que le dédoublement des antislashes, parce que
    l'exclusion des répertoires système est une comparaison de PRÉFIXE : toute
    écriture non canonique du même chemin la contourne. Deux formes, toutes deux
    acceptées telles quelles par l'API Windows en bout de chaîne :

    - le préfixe de chemin long `\\\\?\\` — `\\\\?\\C:\\Windows\\System32\\lsass.exe`
      ne commence pas par `c:\\windows` ;
    - les segments `..` — `C:\\Users\\Public\\..\\..\\Windows\\System32\\lsass.exe`
      non plus.

    On retire donc le préfixe long et on résout la remontée de répertoires
    (`ntpath.normpath`, qui raisonne en syntaxe Windows quel que soit l'OS qui
    exécute ce code — le soc-agent tourne sous Linux).
    """
    p = str(raw or "").strip().strip('"')
    while "\\\\" in p:
        p = p.replace("\\\\", "\\")
    # Le repli ci-dessus ramène `\\?\` à `\?\` : le préfixe est donc reconnu
    # sous ses deux formes, avant et après dédoublement. La variante UNC
    # (`\\?\UNC\serveur\partage`) redevient un chemin UNC ordinaire.
    m = _RE_PREFIX_LONG.match(p)
    if m:
        p = ("\\\\" if m.group("unc") else "") + p[m.end():]
    return ntpath.normpath(p) if p else p


def _win_path_outside_system(p: str) -> bool:
    """Vrai si `p` est un chemin Windows plausible, hors répertoire système et
    hors sonde AppLocker. Ne présume rien de l'extension : un webshell ou un
    payload sans extension exécutable reste quarantainable.

    `p` DOIT venir de `_norm_chemin_win` : la comparaison est un test de
    préfixe, elle ne vaut que sur un chemin canonique. Un `..` résiduel suffit
    à faire passer un binaire de System32 pour un implant déposé.
    """
    p = _norm_win_path(p)
    pl = p.lower()
    if ".." in pl.split("\\"):
        # normpath n'a pas pu résoudre (chemin relatif, remontée au-delà de la
        # racine) : on ne sait pas ce que ce chemin désigne, donc on n'agit pas.
        return False
    return bool((":\\" in p or p.startswith("\\"))
                and not pl.startswith(config.VT_DIRS_SYSTEM)
                and not _RE_PROBE_PS.search(p))


def _win_path_suspicious(p: str) -> bool:
    """Vrai si `p` est un EXÉCUTABLE Windows hors répertoire système."""
    return bool(_win_path_outside_system(p) and p.lower().endswith(_WIN_EXE_EXT))


def _win_suspicious_files(alerts: list[dict]) -> set[str]:
    """Chemins d'exécutables Windows vus dans des emplacements NON système
    (déposés ou lancés par l'attaquant). Cible de kill_process (nom) et de
    quarantine (chemin plein). Les répertoires système sont exclus : un binaire
    signé de System32 relève d'une détection comportementale, pas d'un implant à
    tuer/quarantiner. Sources : Sysmon (image / targetFilename / *Image) + entity."""
    out: set[str] = set()
    for a in alerts:
        for c in _win_path_fields(a):
            p = _norm_win_path(c)
            if _win_path_suspicious(p):
                out.add(p)
    return out


def _eventdata(alert: dict) -> dict:
    """Bloc `data.win.eventdata` d'une alerte Windows (vide si absent)."""
    raw = alert.get("raw")
    if not raw:
        return {}
    data = ((raw if isinstance(raw, dict) else json.loads(raw)) or {}).get("data", {})
    return (data.get("win") or {}).get("eventdata") or {}


def _win_path_fields(alert: dict) -> tuple:
    ev = _eventdata(alert)
    return (ev.get("image"), ev.get("targetFilename"), ev.get("sourceImage"),
            ev.get("targetImage"), alert.get("entity"))


def _win_suspicious_processes(alerts: list[dict]) -> set[tuple[str, str]]:
    """Process Windows à tuer, sous la forme (nom d'image, pid).

    Le PID vient de Sysmon EID 1 (`processId`, décimal) ou de l'event 4688
    (`newProcessId`, hexadécimal). Il est indispensable pour les images
    génériques : `Stop-Process -Name powershell` tue toutes les sessions de la
    machine, y compris celles de l'administrateur et de WinRM. Un process dont
    l'image est générique ET dont on n'a pas le PID n'est PAS une cible : dans
    le doute, on n'agit pas.

    Le pid est retourné à côté du nom pour que le script AR puisse vérifier que
    le PID porte bien cette image avant de tuer (un PID est réutilisable, et il
    peut s'écouler plusieurs minutes entre l'alerte et la remédiation).
    """
    out: set[tuple[str, str]] = set()
    for a in alerts:
        ev = _eventdata(a)
        image = _norm_win_path(ev.get("image") or "")
        if not image or not _win_path_suspicious(image):
            # Image système/inconnue : on retombe sur les chemins suspects vus
            # ailleurs dans l'alerte (dépôt de fichier, targetFilename…).
            continue
        base = image.rsplit("\\", 1)[-1]
        pid = _alert_pid(ev)
        if not pid and base.lower() in _NAMES_PROCESS_GENERIC:
            log.info("kill_process : '%s' sans PID exploitable et nom générique "
                     "— non ciblé (tuer par nom couperait les sessions "
                     "légitimes)", base)
            continue
        out.add((base, pid))
    # Implants déposés hors système et vus sans event de création de process :
    # tuables par nom, le nom n'étant pas générique.
    for p in _win_suspicious_files(alerts):
        base = p.rsplit("\\", 1)[-1]
        if base.lower() in _NAMES_PROCESS_GENERIC:
            continue
        if not any(n == base for n, _ in out):
            out.add((base, ""))
    return out


def _alert_pid(ev: dict) -> str:
    """PID décimal du process créé, depuis Sysmon EID 1 ou l'event 4688."""
    pid = str(ev.get("processId") or "").strip()
    if pid.isdigit():
        return pid
    raw = str(ev.get("newProcessId") or "").strip()   # 4688 : "0x1a4c"
    try:
        return str(int(raw, 16)) if raw.lower().startswith("0x") else ""
    except ValueError:
        return ""


def _alerts_by_agent(alerts: list[dict]) -> dict[str, list[dict]]:
    """Alertes regroupées par agent. Un incident peut couvrir plusieurs machines
    (fusion campagne) : chaque preuve reste attachée à SA machine (agent de
    l'alerte), qui est la seule où l'action correspondante a un sens."""
    by: dict[str, list[dict]] = {}
    for a in alerts:
        ag = str(a.get("agent_id") or "")
        if ag:
            by.setdefault(ag, []).append(a)
    return by


def _targets_by_machine(action: str, incident: dict,
                        alerts: list[dict]) -> list[tuple[str, str]]:
    """Cibles (agent_id, valeur) d'une action, résolues MACHINE PAR MACHINE à
    partir de l'agent de l'alerte qui porte la preuve.

    Garde-fous « dans le doute, on n'agit pas » :
      - jamais un agent CAPTEUR d'hôte (config.AGENTS_SENSORS) : sa télémétrie
        décrit l'activité d'autres machines (conteneurs), donc on ne sait pas sur
        quelle machine agir — on s'abstient plutôt que de viser le mauvais hôte ;
      - une preuve sans agent exploitable est écartée.
    Chaque (machine, valeur) est explicite : pas d'ambiguïté sur « où » — l'action
    part sur la machine où la preuve a été observée, et nulle part ailleurs."""
    by_agent = _alerts_by_agent(alerts)
    agents = [ag for ag in by_agent if ag not in config.AGENTS_SENSORS]
    # Trace des capteurs écartés, pour l'analyste (garde-fou visible).
    for ag in by_agent:
        if ag in config.AGENTS_SENSORS:
            log.info("#%s %s : agent capteur d'hôte %s écarté des cibles "
                     "(théâtre réel = machine surveillée, remédiation non "
                     "appliquée par sûreté)", incident.get("id"), action, ag)

    if action == "propose_isolate_host":
        out = []
        for ag in sorted(agents):
            refusal = not_isolatable_reason(ag)
            if refusal:
                log.warning("isolation refusée : %s", refusal)
                continue
            out.append((ag, ag))
        return out

    if action == "propose_kill_process":
        # Nom exact (comm) des exécutables lancés depuis un répertoire suspect,
        # sur la machine qui l'a exécuté. pkill -x (Linux) / Stop-Process (Windows).
        out: set[tuple[str, str]] = set()
        for ag in agents:
            if _agent_windows(ag):
                # Windows : « image#pid » (le pid peut être vide). Le script AR
                # tue le PID après avoir vérifié qu'il porte bien cette image ;
                # sans pid il retombe sur le nom, ce que _win_process_suspects
                # n'autorise que pour un nom non générique.
                for base, pid in _win_suspicious_processes(by_agent[ag]):
                    if base:
                        out.add((ag, f"{base}#{pid}" if pid else base))
                continue
            for a in by_agent[ag]:
                raw = a.get("raw")
                if not raw:
                    continue
                data = (raw if isinstance(raw, dict)
                        else json.loads(raw)).get("data", {})
                audit = data.get("audit", {}) or {}
                for path in (audit.get("exe"), a.get("entity")):
                    p = str(path or "")
                    if p.startswith(_DIRS_SUSPICIOUS):
                        base = p.rsplit("/", 1)[-1]
                        if base:
                            out.add((ag, base[:15]))  # comm plafonné à 15 car.
        return sorted(out)

    if action == "propose_block_ip":
        # IP de l'ATTAQUANT, bloquée sur chaque endpoint qui l'a contactée.
        # Trois filtres, du plus sûr au plus fin :
        #  1. IP invalide (none, loopback, broadcast) écartée ;
        #  2. IP d'un subnet du parc (_ip_interne) écartée — mouvement latéral
        #     interne, pas un C2. « Interne » = subnets listés, PAS tout RFC1918
        #     (un C2 peut être privé et doit rester bloquable) ;
        #  3. IP d'un AGENT surveillé écartée — une victime/un pivot n'est pas
        #     l'attaquant (garde-fou ajouté après un exercice purple-team, où
        #     l'hôte pivot d'une attaque a été bloqué à tort).
        # Puis on ORDONNE (IP publiques d'abord) sans réduire : un bruteforce
        # vient de N IP, toutes à bloquer.
        assets = _agent_ips()

        def _blockable(ip: str) -> bool:
            ip = str(ip)
            if not _ip_ioc_valid(ip) or _ip_internal(ip):
                return False        # invalide, ou subnet du parc (victime/pivot)
            if ip in assets:
                log.info("#%s block_ip : %s écartée (IP d'un agent surveillé "
                         "— victime/pivot, pas l'attaquant)",
                         incident.get("id"), ip)
                return False
            return True

        out = set()
        for ag in agents:
            for a in by_agent[ag]:
                # 1) IP source d'une attaque réseau (web, bruteforce…).
                ip = a.get("srcip")
                if ip and _blockable(str(ip)):
                    out.add((ag, str(ip)))
                # 2) IP C2 cible d'un reverse shell /dev/tcp|/dev/udp, extraite
                #    de la commande : l'execve auditd n'a pas de srcip, donc sans
                #    ça un reverse shell détecté (100650) restait détecté mais
                #    jamais bloqué (régression mesurée : des milliers de hits, 0 blocage).
                for c2 in _ips_revshell(a):
                    if _blockable(c2):
                        out.add((ag, c2))
        return sorted(out, key=lambda t: (_is_private_ip(t[1]), t[0], t[1]))

    if action == "propose_disable_user":
        # Compte compromis/créé, désactivé SUR la machine où il apparaît. Comptes
        # protégés exclus. Un backdoor vu seulement par un capteur d'hôte (pas
        # d'auditd dans le conteneur) n'a pas de machine exploitable ici → non
        # désactivé automatiquement (garde-fou), à traiter par l'analyste.
        # Sur un hôte Windows, le compte est un compte de DOMAINE : la cible
        # d'exécution devient un DC (ad-disable-account), pas l'hôte membre.
        out = set()
        for ag in agents:
            al = by_agent[ag]
            machine = ag
            if _agent_windows(ag):
                # Windows : SEULS les comptes CRÉÉS par l'attaquant sont des
                # cibles. Le `srcuser` d'un 4624/4634 est l'identité qui s'est
                # connectée — donc la victime, ou une identité système. Le
                # un exercice purple-team en a tiré `Système`, `SERVICE LOCAL`
                # et `ANONYMOUS LOGON` : trois ordres de désactivation dans AD,
                # refusés seulement par le script. Sur Linux, le srcuser reste
                # exploitable (il provient de l'audit de commande, pas d'un
                # logon), on le garde.
                accounts = set(_created_accounts(al))
                machine = _un_dc()
                if not machine:      # pas de DC configuré : on ne sait pas où agir
                    log.warning("#%s disable_user : hôte Windows %s mais aucun "
                                "AGENTS_DC — compte non désactivé (garde-fou)",
                                incident.get("id"), ag)
                    continue
            else:
                accounts = {_account_name(a["srcuser"]) for a in al
                           if a.get("srcuser") and not _is_protected_account(a["srcuser"])}
                accounts |= set(_created_accounts(al))
            for c in accounts:
                if c:
                    out.add((machine, c))
        return sorted(out)

    if action == "propose_quarantine_file":
        # Fichier malveillant déposé, mis en quarantaine SUR l'hôte Windows qui
        # le porte. Chemins système exclus (le script refuse aussi de son côté).
        out = set()
        for ag in agents:
            if not _agent_windows(ag):
                continue
            # Chemins pleins des exécutables déposés hors système (Sysmon), plus
            # les fichiers signalés comme IOC. win-quarantine-file prend le chemin.
            for p in _win_suspicious_files(by_agent[ag]):
                out.add((ag, p))
            for v, t, _ in _iocs(by_agent[ag]):
                p = _norm_win_path(v)
                if t in ("file", "filename") and ("\\" in p or "/" in p) \
                        and _win_path_outside_system(p):
                    out.add((ag, p))
        return sorted(out)

    if action == "propose_remove_privileged_group":
        # Retrait d'un compte attaquant d'un groupe privilégié, exécuté sur un DC.
        # PROPOSE-ONLY : heuristique volontairement large (l'analyste tranche) —
        # les comptes créés par l'attaquant, retirés de « Domain Admins ».
        dc = _un_dc()
        if not dc:
            return []
        out = set()
        for ag in agents:
            if not _agent_windows(ag):
                continue
            for member in _created_accounts(by_agent[ag]):
                if member:
                    out.add((dc, f"Domain Admins|{member}"))
        return sorted(out)
    return []


# --- assets / tasks IRIS + persistance --------------------------------------
#
# Les remédiations ne vont PLUS dans l'onglet Notes : chaque action devient une
# TASK (onglet Tasks) et les cibles concrètes (hôte, comptes) des ASSETS
# (onglet Assets). L'onglet Notes reste réservé à l'analyse (rapport LLM).

# Cycle de vie d'une remédiation.
#
# Le canal d'active response de Wazuh est fire-and-forget : l'API rend la main
# dès que la commande est mise en file, et le code de retour du script ne
# revient jamais. Il n'y a donc PAS un statut « exécuté » mais deux moments
# distincts, et les confondre est ce qui a produit le pire défaut du
# exercice purple-team — un rapport IRIS annonçant des dizaines de quarantaines
# réussies de binaires System32 sur un contrôleur de domaine, quand le script
# les avait toutes refusées :
#
#   émis         l'API Wazuh a pris la commande. C'est TOUT ce qu'on sait à
#                l'instant de l'appel. Ce n'est pas un succès.
#   confirmé     l'agent a renvoyé `ar-result status=applied` : le changement
#                a réellement eu lieu sur l'hôte.
#   sans_effet   `status=noop` : il n'y avait rien à faire (cible absente,
#                déjà dans cet état). Ni succès ni échec — souvent le signe
#                d'une cible mal résolue, donc surtout pas « Done ».
#   refusé_agent `status=refused` : un garde-fou du script a décliné. La
#                dernière ligne de défense a tenu, et le soc-agent a visé ce
#                qu'il n'aurait pas dû : à voir par l'analyste.
#   échec        le canal lui-même a échoué, ou `status=error`.
#
# Le passage de « émis » à l'un des trois états réels est fait par
# `reconcilier_resultats_ar()`, alimenté par les règles 100930-100935.
STATUSES_GONE = ("émis", "confirmé", "sans_effet", "refusé_agent")

# Statut de remédiation -> statut de tâche IRIS.
_STATUS_TASK = {
    "émis": "In progress",     # commande partie, effet pas encore confirmé
    "confirmé": "Done",
    "sans_effet": "On hold",   # rien à faire sur cette cible : à regarder
    "refusé_agent": "Canceled",
    "dry_run": "To do",        # simulé : l'action réelle reste à faire
    "échec": "Canceled",
    "annulé": "Canceled",
}

# Statut d'AR renvoyé par l'agent -> statut de remédiation.
_STATUS_AR = {
    "applied": "confirmé",
    "noop": "sans_effet",
    "refused": "refusé_agent",
    "error": "échec",
}


def _task_desc(triage: dict, target: str, status: str, channel: str,
                details: str, undo: str) -> str:
    """Corps (markdown) de la tâche de remédiation."""
    return "\n".join([
        f"**Cible** : {target}",
        f"**Statut** : {status}",
        f"**Canal** : {channel}",
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


def _existing_assets(case, case_id: int) -> set[str]:
    try:
        d = case.list_assets(case_id).get_data() or {}
        items = d.get("assets") if isinstance(d, dict) else d
        return {a.get("asset_name") for a in (items or [])}
    except Exception as e:  # noqa: BLE001
        log.debug("liste assets case #%s : %s", case_id, e)
        return set()


def _set_assets(case, case_id: int, inc: dict, alerts: list[dict]) -> None:
    """Renseigne l'onglet Assets : l'hôte touché et les comptes compromis.

    Best-effort et idempotent (dédup sur le nom déjà présent). Les IP/hash/
    fichiers restent des IOC (onglet IOC, posé par iris.py) ; ici on ne met que
    les entités sur lesquelles on AGIT et qui ont un type d'asset propre.
    """
    existing = _existing_assets(case, case_id)

    def add(name: str, atype: str, desc: str) -> None:
        if not name or name in existing:
            return
        try:
            case.add_asset(name=name, asset_type=atype,
                           analysis_status="Started",
                           compromise_status="Compromised",
                           description=desc, cid=case_id)
            existing.add(name)
        except Exception as e:  # noqa: BLE001
            log.debug("asset ignoré (%s) : %s", name, e)

    # Une machine par agent réellement touché (hors capteurs d'hôte) : un
    # incident de campagne en couvre plusieurs. Nom via l'alerte, à défaut l'id.
    names = {str(a["agent_id"]): (a.get("agent_name") or str(a["agent_id"]))
            for a in alerts if a.get("agent_id")
            and str(a["agent_id"]) not in config.AGENTS_SENSORS}
    if not names:  # aucun endpoint exploitable : au moins l'agent de l'incident.
        names = {str(inc["agent_id"]): inc.get("agent_name") or str(inc["agent_id"])}
    for name in sorted(set(names.values())):
        add(name, "Linux - Server",
                "Hôte touché par l'incident (cible d'isolation / kill de process).")
    for _ag, account in _targets_by_machine("propose_disable_user", inc, alerts):
        add(account, "Linux Account",
                "Compte compromis ou créé par l'attaquant (cible de désactivation).")


INSERT_MITIG = """
INSERT INTO mitigations (incident_id, action, target, agent_id, status, details,
                         undo, iris_task_id)
VALUES (%(incident_id)s, %(action)s, %(target)s, %(agent_id)s, %(status)s,
        %(details)s, %(undo)s, %(iris_task_id)s)
ON CONFLICT (incident_id, action, target, agent_id) DO UPDATE
SET status = EXCLUDED.status, details = EXCLUDED.details, undo = EXCLUDED.undo,
    iris_task_id = EXCLUDED.iris_task_id, executed_at = now(),
    attempts = mitigations.attempts + 1
RETURNING id
"""


# Statuts qui interdisent de rejouer une action sur le même couple
# (incident, cible). Les quatre statuts « la commande est partie » pour
# l'idempotence évidente — y compris 'agent_refused' : une action que le script
# a déclinée par garde-fou serait redemandée à chaque cycle, et redéclinée,
# indéfiniment. Un refus est une réponse, pas une erreur transitoire.
# 'failed' n'y est PAS : un canal qui tombe mérite un nouvel essai.
# 'canceled' et
# 'annulation_impossible' parce qu'une action ANNULÉE ne doit pas revenir : un
# incident gagne de nouvelles alertes en continu (needs_refresh), donc le triage
# est rejoué, donc la remédiation aussi — l'analyste qui passe la tâche IRIS en
# 'Canceled' verrait l'hôte se réisoler au cycle suivant, en boucle contre sa
# décision. Une annulation est un ordre, pas une suggestion.
#
# Contrepartie assumée : si l'incident s'aggrave vraiment après une annulation,
# rien ne repart tout seul. C'est le bon défaut (l'analyste a tranché en
# connaissance de cause) et il reste rattrapable à la main :
# `mitigate --isoler <agent>`, ou suppression de la ligne pour rouvrir le droit.
# Statuts TERMINAUX : on connaît l'issue, on ne rejoue jamais. 'sent' n'en fait
# PAS partie — c'est « la commande est partie », pas « elle a eu l'effet voulu ».
# Une action restée 'sent' (aucun `ar-result` de confirmation) est retentée
# jusqu'à MITIGATE_MAX_ATTEMPTS : sans quoi un compte attaquant recréé sous un
# incident déjà ouvert n'est jamais désactivé (mesuré à l'exercice : `art-backdoor`
# figé sur un 'sent' hérité, disable_user jamais rejoué). 'confirmed'/'no_effect'
# sont, eux, des réponses de l'agent : terminaux.
_STATUSES_FROZEN = ("confirmé", "sans_effet", "refusé_agent",
                  "annulé", "annulation_impossible")


def _already_executed(conn, incident_id: int, action: str, target: str,
               agent_id: str) -> bool:
    r = conn.execute(
        "SELECT status, attempts FROM mitigations WHERE incident_id=%s "
        "AND action=%s AND target=%s AND agent_id=%s",
        (incident_id, action, target, agent_id)).fetchone()
    if not r:
        return False
    if r["status"] in _STATUSES_FROZEN:
        return True
    # 'sent' non confirmé : rejouable tant que le plafond n'est pas atteint.
    if r["status"] == "émis":
        return r["attempts"] >= config.MITIGATE_MAX_ATTEMPTS
    return False


SELECT_TRIAGE = """
SELECT verdict, confidence, reason, actions, injection_patterns, guardrails
  FROM triages WHERE incident_id = %s ORDER BY created_at DESC LIMIT 1
"""


def run(incident_id: int) -> list[dict]:
    results: list[dict] = []
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
        if triage["injection_patterns"]:
            print(f"  #{incident_id} SUSPENDU — motifs d'injection au triage : "
                  f"{', '.join(triage['injection_patterns'])}. Aucune exécution.")
            return []

        # Borné : cette requête ramenait les 102 869 alertes de l'incident
        # #2555 avec leur `raw` et faisait OOM-killer le cycle à chaque
        # passe (cf. alertes.py).
        alerts = alerts_mod.load_bounded(
            conn, incident_id, alerts_mod.COLUMNS_TARGETING, "remédiation")

        remed = [a for a in triage["actions"] if a in REMEDIATIONS]

        # Garde-fou déterministe : un compte CRÉÉ par l'attaquant sur un vrai
        # positif doit être désactivé même si le LLM n'a pas proposé l'action.
        # Le triage ne voit que les alertes HIGH ; la création de compte remonte
        # d'une alerte auditd bas niveau (proctitle, niv. 3) rattachée à
        # l'incident — visible dans le case, mais absente du prompt de décision.
        # On complète l'action ici, sans jamais toucher au niveau de l'alerte.
        if (triage["verdict"] == "true_positive"
                and "propose_disable_user" not in remed
                and _created_accounts(alerts)):
            remed.append("propose_disable_user")
            print(f"  #{incident_id} + propose_disable_user (déterministe : "
                  f"compte créé par l'attaquant — {', '.join(_created_accounts(alerts))})")

        if not remed:
            print(f"  #{incident_id} aucune remédiation à exécuter "
                  f"(verdict {triage['verdict']}).")
            return []

        case = _client() if inc["iris_case_id"] else None
        # Assets (onglet Assets) : hôte + comptes, une fois, avant les actions.
        if case:
            _set_assets(case, inc["iris_case_id"], inc, alerts)

        mode = "EXÉCUTION" if config.MITIGATE_EXECUTE else "DRY-RUN"
        print(f"  #{incident_id} {inc['agent_name']} — {mode} — "
              f"{len(remed)} action(s)")

        reason_short = (triage["reason"] or "")[:120]

        for action in sorted(remed, key=lambda a: ORDER_EXEC.index(a)
                             if a in ORDER_EXEC else 99):
            for machine, target in _targets_by_machine(action, inc, alerts):
                # Contexte reconstruit PAR CIBLE : chaque remédiation part sur la
                # machine où sa preuve a été observée, jamais sur un agent global.
                ctx = {"agent_id": machine, "reason_court": reason_short}
                if config.MITIGATE_EXECUTE and _already_executed(
                        conn, incident_id, action, target, machine):
                    print(f"      {action} [{target}@{machine}] déjà exécuté, "
                          "ignoré.")
                    continue
                try:
                    status, channel, details, undo = EXECUTEURS[action](target, ctx)
                except Exception as e:  # noqa: BLE001 — un échec de canal ne doit
                    # pas arrêter les autres remédiations ; on le trace.
                    status, channel = "échec", "—"
                    details, undo = f"Échec du canal : {e}", "—"
                    log.warning("échec %s [%s] : %s", action, target, e)

                # Chaque remédiation = une TASK (onglet Tasks), pas une note.
                # La machine visée est dans le titre : un incident de campagne
                # porte la même action sur plusieurs hôtes.
                task_id = None
                if case:
                    title = ("[SIMULATION] " if status == "dry_run" else "") + \
                        f"Remédiation — {LABEL_ACTION.get(action, action)} " \
                        f"({target} @ {machine})"
                    rt = case.add_task(
                        title=title,
                        status=_STATUS_TASK.get(status, "To do"),
                        assignees=[],
                        description=_task_desc(triage, target, status, channel,
                                                details, undo),
                        tags=["remediation", "auto"],
                        cid=inc["iris_case_id"])
                    if rt.is_success():
                        task_id = rt.get_data().get("id")

                conn.execute(INSERT_MITIG, {
                    "incident_id": incident_id, "action": action, "target": target,
                    "agent_id": machine, "status": status, "details": details,
                    "undo": undo, "iris_task_id": task_id})
                conn.commit()

                results.append({"action": action, "target": target,
                                  "agent_id": machine, "status": status})
                print(f"      {action} [{target}@{machine}] -> {status}  ({channel})")
    return results


# --- réconciliation : annuler ce que l'analyste a passé en 'Canceled' -------

# Statut de tâche IRIS qui déclenche l'annulation de la remédiation.
_TASK_CANCELED = "Canceled"


def _canceled_tasks(tasks: list[dict]) -> set[int]:
    """IDs des tâches en statut 'Canceled' (lecture pure d'un list_tasks IRIS)."""
    return {t["task_id"] for t in (tasks or [])
            if (t.get("status_name") or "") == _TASK_CANCELED}


def _comment_task(case, case_id: int, task_id: int, text: str) -> None:
    """Ajoute un commentaire à la tâche (best-effort : ne bloque pas le reste)."""
    try:
        case.add_task_comment(task_id=task_id, comment=text, cid=case_id)
    except Exception as e:  # noqa: BLE001
        log.debug("commentaire tâche %s : %s", task_id, e)


def _update_task_status(case, case_id: int, task_id: int, status: str) -> bool:
    """Change le statut d'une tâche IRIS. Retourne True si c'est passé.

    `Case.update_task()` relit la tâche avant de la réécrire, et cette relecture
    utilise le cid de l'INSTANCE, pas le `cid=` de l'appel : passer seulement
    `cid=` lève « No case ID provided ». Le symptôme était muet — les deux
    appelants enveloppaient l'échec dans un try/except best-effort, donc aucune
    tâche de remédiation ni de whitelist n'a jamais changé de statut : elles
    restaient en 'To do' quel que soit le sort réel de l'action.

    `set_cid` mute l'instance ; on la repositionne donc à chaque appel plutôt que
    de supposer un cid courant, les appelants bouclant sur plusieurs cases.
    """
    try:
        case.set_cid(case_id)
        r = case.update_task(task_id, status=status, cid=case_id)
        if r.is_success():
            return True
        log.warning("maj tâche %s (case %s) refusée : %s",
                    task_id, case_id, r.get_msg())
    except Exception as e:  # noqa: BLE001 — best-effort, jamais bloquant
        log.warning("maj tâche %s (case %s) : %s", task_id, case_id, e)
    return False


# --- réconciliation : ce que l'agent a VRAIMENT fait ------------------------
#
# Script d'active response par action, Windows puis Linux. C'est la clé de
# rapprochement entre une ligne de `mitigations` et l'alerte `ar-result`
# renvoyée par l'agent (règles 100931-100934).
_SCRIPTS_AR = {
    "propose_isolate_host":    ("win-host-isolate", "host-isolate"),
    "propose_block_ip":        ("win-block-ip", "firewall-drop"),
    "propose_disable_user":    ("ad-disable-account", "disable-account"),
    "propose_kill_process":    ("win-kill-process", "kill-process"),
    "propose_quarantine_file": ("win-quarantine-file", "quarantine"),
}

# Règles qui portent un compte rendu d'AR exploitable. 100935 (expiration du
# timeout execd) est en niveau 0 : elle ne produit pas d'alerte, donc n'arrive
# jamais ici — c'est voulu, un `delete` no-op ne dit rien de l'action initiale.
_RULES_AR = ("100931", "100932", "100933", "100934")

SELECT_AR_RESULTS = """
SELECT a.ts,
       a.agent_id,
       a.raw#>>'{data,ar_script}' AS ar_script,
       a.raw#>>'{data,ar_status}' AS ar_status,
       a.raw#>>'{data,ar_target}' AS ar_target,
       a.raw#>>'{data,ar_reason}' AS ar_reason
  FROM alerts a
 WHERE a.rule_id = ANY(%(regles)s)
   AND a.ts > now() - interval '24 hours'
 ORDER BY a.ts
"""


def reconcile_ar_results() -> list[dict]:
    """Remplace le statut « émis » par ce que l'agent a réellement fait.

    L'API Wazuh est fire-and-forget : au moment de l'appel, tout ce qu'on sait
    est que la commande est partie. Les scripts d'AR écrivent maintenant une
    ligne `ar-result` à chaque sortie, l'agent la remonte, les règles
    100931-100934 en font des alertes ; ici on les rapproche de la table
    `mitigations` sur (agent, script, cible) et on fige le vrai statut.

    Sans cette boucle, un refus du script était invisible : un rapport IRIS
    d'exercice a annoncé des dizaines de quarantaines réussies de binaires
    System32 sur un contrôleur de domaine, quand le script les avait toutes
    déclinées.

    Une remédiation qui ne reçoit AUCUN compte rendu reste 'sent' — jamais
    promue en succès. C'est le bon défaut : un script qui meurt avant d'écrire
    sa ligne (exception PowerShell) ne doit pas être lu comme un succès.
    """
    results: list[dict] = []
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        lines = conn.execute(SELECT_AR_RESULTS,
                              {"regles": list(_RULES_AR)}).fetchall()
        if not lines:
            return []

        case = None
        for r in lines:
            status = _STATUS_AR.get(r["ar_status"] or "")
            if not status or not r["ar_script"] or r["ar_target"] is None:
                continue
            # Actions candidates : celles dont l'un des deux scripts (Windows ou
            # Linux) porte ce nom. `host-isolation.sh` n'est qu'un aiguilleur,
            # c'est le script délégué qui signe le compte rendu.
            actions = [a for a, scripts in _SCRIPTS_AR.items()
                       if r["ar_script"] in scripts]
            if not actions:
                continue
            timestamp = r["ts"].strftime("%Y-%m-%d %H:%M:%S")
            update = conn.execute("""
                UPDATE mitigations m
                   SET status = %(status)s,
                       details = m.details || %(suffixe)s
                 WHERE m.status = 'sent'
                   AND m.agent_id = %(agent)s
                   AND m.action = ANY(%(actions)s)
                   AND m.target = %(target)s
                   AND m.executed_at <= %(ts)s + interval '5 minutes'
             RETURNING m.id, m.incident_id, m.action, m.iris_task_id
            """, {
                "status": status,
                "suffixe": (f"\n\nCompte rendu de l'agent ({timestamp} UTC) : "
                            f"{r['ar_status']}"
                            + (f" — {r['ar_reason']}" if r["ar_reason"] else "")),
                "agent": r["agent_id"],
                "actions": actions,
                "target": r["ar_target"],
                "ts": r["ts"],
            }).fetchall()
            if not update:
                continue
            conn.commit()

            for m in update:
                results.append({"id": m["id"], "action": m["action"],
                                  "target": r["ar_target"], "status": status})
                log.info("#%s %s [%s@%s] : émis -> %s (%s)", m["incident_id"],
                         m["action"], r["ar_target"], r["agent_id"], status,
                         r["ar_reason"] or "-")
                if not m["iris_task_id"]:
                    continue
                case = case or _client()
                cid = conn.execute(
                    "SELECT iris_case_id FROM incidents WHERE id = %s",
                    (m["incident_id"],)).fetchone()["iris_case_id"]
                if not cid:
                    continue
                _update_task_status(case, cid, m["iris_task_id"],
                                  _STATUS_TASK.get(status, "To do"))
                _comment_task(
                    case, cid, m["iris_task_id"],
                    f"Compte rendu de l'agent : **{r['ar_status']}**"
                    + (f" — {r['ar_reason']}" if r["ar_reason"] else "")
                    + f"\n\nStatut de la remédiation : `émis` → `{status}`.")
    return results


SELECT_REVERSIBLES = """
SELECT m.id, m.incident_id, m.action, m.target, m.details, m.iris_task_id,
       COALESCE(NULLIF(m.agent_id, ''), i.agent_id) AS agent_id, i.iris_case_id
  FROM mitigations m
  JOIN incidents i ON i.id = m.incident_id
 WHERE m.status IN ('sent', 'confirmed', 'no_effect')
   AND m.iris_task_id IS NOT NULL
   AND i.iris_case_id IS NOT NULL
   AND (%(inc)s::bigint IS NULL OR m.incident_id = %(inc)s)
 ORDER BY i.iris_case_id, m.id
"""

# Marque terminale d'une action tuée qu'on ne peut pas défaire : évite de
# re-commenter la tâche à chaque cycle (elle n'est plus sélectionnée).
_STATUS_IRREVERSIBLE = "annulation_impossible"

# Verrou consultatif dédié à la réconciliation. Son timer (1 min) est plus court
# que celui du cycle : deux passages ne doivent pas se superposer et double-tirer
# un reverse (fenêtre entre le SELECT et le commit du statut 'canceled').
_LOCK_RECONCILE = 0x50CA2


def reconcile(incident_id: int | None = None) -> list[dict]:
    """Défait les remédiations dont la tâche IRIS est passée en 'Canceled'.

    L'analyste garde la main a posteriori : mettre une tâche de remédiation en
    'Canceled' dans IRIS demande au soc-agent de DÉFAIRE l'action — désisoler
    l'hôte, débloquer l'IP, réactiver le compte. Boucle fermée : la tâche IRIS
    est le signal, la table `mitigations` la mémoire (une action partie — 'sent',
    'confirmed' ou 'no_effect' — est à surveiller ; 'canceled' = déjà défait, plus
    repris). Le kill de process n'a pas de reverse : on le documente une fois et
    on le marque terminal. Une action 'agent_refused' n'est pas défaisable : le
    script l'a déclinée, il n'y a rien à remettre en état.

    Idempotent : une remédiation déjà annulée n'est plus sélectionnée ; un
    reverse en échec garde son statut et sera retenté au cycle suivant.
    """
    results: list[dict] = []
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        # Un seul reconcile à la fois (son timer est court) : sinon deux passages
        # pourraient sélectionner puis double-défaire la même remédiation.
        if not conn.execute("SELECT pg_try_advisory_lock(%s)",
                            (_LOCK_RECONCILE,)).fetchone()["pg_try_advisory_lock"]:
            log.info("réconciliation déjà en cours, on passe ce tour")
            return []
        try:
            # D'abord, ce que les agents ont réellement fait : sans ça, une
            # remédiation refusée par le script resterait 'sent' et le rapport
            # IRIS continuerait d'annoncer une action qui n'a pas eu lieu.
            # Même verrou : les deux passes écrivent dans `mitigations`.
            try:
                reconcile_ar_results()
            except Exception as e:  # noqa: BLE001 — ne doit pas empêcher les
                # annulations demandées par l'analyste, qui sont prioritaires.
                log.warning("réconciliation des comptes rendus d'AR : %s", e)

            rows = conn.execute(SELECT_REVERSIBLES,
                                {"inc": incident_id}).fetchall()
            if not rows:
                return []
            results = _reconcile_rows(conn, rows)
        finally:
            conn.execute("SELECT pg_advisory_unlock(%s)", (_LOCK_RECONCILE,))
    return results


def _case_deleted(conn, case, case_id: int) -> bool:
    """Le case IRIS a-t-il disparu ? Si oui, on coupe la référence morte.

    Un case supprimé à la main dans IRIS laisse `incidents.iris_case_id` qui
    pointe dans le vide. Et IRIS ne répond pas proprement 404 sur un case
    inexistant : son contrôle d'accès plante en `KeyError: 'permissions'`
    (session Flask absente sur un appel par jeton d'API) et rend un 500. Le
    reconcile retentait donc à chaque minute, indéfiniment — 28 343 traces
    d'erreur en six jours dans les journaux d'IRIS, qui noyaient tout le reste.

    On ne coupe la référence QUE si `get_case` échoue lui aussi : une panne
    passagère d'IRIS ne doit pas faire perdre le lien vers un case vivant.
    """
    try:
        if case.get_case(case_id).is_success():
            return False
    except Exception:  # noqa: BLE001 — pas de case lisible : voir ci-dessous
        pass
    conn.execute("UPDATE incidents SET iris_case_id = NULL "
                 "WHERE iris_case_id = %s", (case_id,))
    conn.commit()
    log.warning("case IRIS #%s introuvable (supprimé ?) — référence coupée sur "
                "les incidents concernés, plus de réconciliation dessus",
                case_id)
    return True


def _reconcile_rows(conn, rows: list[dict]) -> list[dict]:
    """Cœur de la réconciliation, verrou déjà pris par l'appelant."""
    results: list[dict] = []
    case = _client()
    canceled: dict[int, set[int]] = {}   # case_id -> {task_id Canceled}
    for r in rows:
        cid = r["iris_case_id"]
        if cid not in canceled:
            try:
                d = case.list_tasks(cid).get_data() or {}
                canceled[cid] = _canceled_tasks(d.get("tasks"))
            except Exception as e:  # noqa: BLE001 — IRIS KO ne casse rien
                canceled[cid] = set()
                if _case_deleted(conn, case, cid):
                    continue
                log.warning("list_tasks case #%s : %s", cid, e)
        if r["iris_task_id"] not in canceled[cid]:
            continue   # tâche pas (encore) annulée par l'analyste

        action, target, task_id = r["action"], r["target"], r["iris_task_id"]
        reverter = REVERTERS.get(action)

        # Action irréversible (kill) : documenter, marquer terminal, passer.
        if reverter is None:
            _comment_task(case, cid, task_id,
                f"⚠️ Annulation demandée (tâche passée en {_TASK_CANCELED}) "
                f"mais l'action « {LABEL_ACTION.get(action, action)} » est "
                "irréversible (pas de reverse). Rien n'a été défait "
                "automatiquement.")
            conn.execute("UPDATE mitigations SET status = %s WHERE id = %s",
                         (_STATUS_IRREVERSIBLE, r["id"]))
            conn.commit()
            results.append({"action": action, "target": target,
                              "status": _STATUS_IRREVERSIBLE})
            print(f"      {action} [{target}] annulation impossible (kill)")
            continue

        ctx = {"agent_id": str(r["agent_id"]),
               "reason_court": f"tâche IRIS #{task_id} passée en {_TASK_CANCELED}"}
        try:
            channel = reverter(target, ctx)
        except Exception as e:  # noqa: BLE001 — reverse en échec : on garde le
            # statut 'executed' pour retenter au prochain passage, on trace.
            log.warning("reverse %s [%s] échoué : %s", action, target, e)
            _comment_task(case, cid, task_id,
                f"❌ Tentative d'annulation automatique de « "
                f"{LABEL_ACTION.get(action, action)} » ({target}) en échec : "
                f"{e}. Nouvelle tentative au prochain passage.")
            continue

        conn.execute(
            "UPDATE mitigations SET status = 'canceled', "
            "details = %s, executed_at = now() WHERE id = %s",
            (f"{r['details'] or ''} — Annulé : tâche IRIS passée en "
             f"{_TASK_CANCELED}, action défaite via {channel}.", r["id"]))
        conn.commit()
        _comment_task(case, cid, task_id,
            f"↩️ Remédiation défaite automatiquement suite au passage "
            f"de la tâche en {_TASK_CANCELED} : « "
            f"{LABEL_ACTION.get(action, action)} » ({target}) annulée via "
            f"{channel}.")
        results.append({"action": action, "target": target, "status": "annulé"})
        print(f"      {action} [{target}] -> annulé  ({channel})")
    return results


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
    g.add_argument("--reconcilier", action="store_true",
                   help="défait les remédiations dont la tâche IRIS est passée "
                        "en 'Canceled' (desisolation, deblocage, reactivation)")
    ap.add_argument("--motif", default="action opérateur",
                    help="motif consigné avec l'(dé)isolation manuelle")
    ap.add_argument("--forcer", action="store_true",
                    help="isole malgré le garde-fou « endpoints seulement » "
                         "(pare-feu, proxy, DNS, VPN, manager). À n'utiliser "
                         "qu'en sachant que le trafic d'autres machines tombe.")
    args = ap.parse_args()

    # --isoler / --desisoler sont des commandes opérateur explicites : elles
    # s'exécutent réellement, indépendamment de MITIGATE_EXECUTE (qui ne borne
    # que l'exécution AUTOMATIQUE depuis un verdict).
    if args.isolate:
        isolate(args.isolate, args.pattern, args.forcer)
    elif args.unisolate:
        unisolate(args.unisolate, args.pattern)
    elif args.state:
        _show_state(isolation_state(args.state))
    elif args.reconcile:
        reconcile()
    else:
        run(args.incident)


if __name__ == "__main__":
    main()
