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
from .anonymize import COMPTES_GENERIQUES
from .iris import LIBELLE_ACTION, _client, _iocs, _ip_interne, _ip_ioc_valide

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
                "agent_id": agent_id, "statut": statut,
                "details": f"{details} Motif : {reason}",
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


def isoler(agent_id: str, reason: str = "isolation manuelle",
           forcer: bool = False) -> None:
    """Isolation demandée par un opérateur.

    Le garde-fou « endpoints seulement » s'applique AUSSI ici : un opérateur qui
    tape la commande sur un pare-feu ne veut presque jamais couper le site, il
    s'est trompé d'agent. Mais il reste le décideur — `--forcer` lève le refus.
    C'est la différence entre une barrière (l'automatisme, jamais franchissable)
    et un filet (l'humain, qui doit dire explicitement qu'il sait).
    """
    refus = raison_non_isolable(agent_id)
    if refus and not forcer:
        print(f"  REFUS : {refus}")
        print("  Relancer avec --forcer si l'isolation est bien voulue.")
        return
    if refus:
        print(f"  /!\\ garde-fou outrepassé (--forcer) : {refus}")
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
    """Déclenche une active-response Wazuh sur un agent (API directe).

    Lève si l'API n'a pas retenu l'agent. Un 200 ne suffit pas : l'API répond
    200 avec l'agent dans `failed_items` quand il est déconnecté ou inconnu, et
    l'appelant marquait alors la remédiation 'exécuté' alors que rien n'était
    parti.

    Reste hors de portée : le RÉSULTAT du script côté agent. L'API est
    fire-and-forget, l'AR ne renvoie rien — un script qui refuse la cible ne
    remonte que dans `active-responses.log` de l'agent. D'où l'importance que le
    script lui-même soit correct (cf. wazuh/active-response/), la vérification
    de bout en bout ne pouvant se faire qu'en lisant l'état réel de l'hôte.
    """
    tok = _wazuh_token()
    r = requests.put(
        f"{config.WAZUH_API_URL}/active-response",
        params={"agents_list": agent_id},
        headers={"Authorization": f"Bearer {tok}"},
        json={"command": command, "arguments": arguments},
        verify=False, timeout=20)
    r.raise_for_status()
    rep = r.json()
    donnees = rep.get("data", {}) or {}
    echecs = donnees.get("failed_items") or []
    if echecs or not (donnees.get("affected_items") or []):
        raise RuntimeError(
            f"l'API Wazuh n'a pas transmis {command} à l'agent {agent_id} : "
            f"{rep.get('message') or ''} {echecs}".strip())
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


def _groupes_agent(agent_id: str) -> set[str] | None:
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


def raison_non_isolable(agent_id: str) -> str | None:
    """Motif de refus d'isolation pour cet agent, ou None s'il est isolable.

    L'isolation ne vise que les ENDPOINTS. Trois barrières, dans l'ordre :

    1. agent explicitement protégé (`AGENTS_PROTEGES`, dont 000 le manager, qui
       n'a d'ailleurs aucun groupe — le mécanisme de groupes ne le couvrirait
       pas) ;
    2. agent appartenant à un groupe d'infrastructure : pare-feu, proxy, DNS,
       VPN. Ces machines acheminent le trafic d'autrui, les couper provoque une
       panne générale au lieu de contenir un incident ;
    3. rôle indéterminable — refus par défaut (cf.
       ISOLATION_REFUS_SI_ROLE_INCONNU).
    """
    if str(agent_id) in config.AGENTS_PROTEGES:
        return f"agent {agent_id} protégé (AGENTS_PROTEGES)"

    groupes = _groupes_agent(str(agent_id))
    if groupes is None:
        if config.ISOLATION_REFUS_SI_ROLE_INCONNU:
            return (f"rôle de l'agent {agent_id} indéterminable (groupes "
                    "illisibles) — isolation refusée par prudence")
        return None

    interdits = groupes & config.ISOLATION_GROUPES_INTERDITS
    if interdits:
        return (f"agent {agent_id} dans le groupe {', '.join(sorted(interdits))} "
                "— infrastructure réseau, jamais isolée")
    return None


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
        _wazuh_ar(ctx["agent_id"], "!firewall-drop.sh", [cible])
        return "exécuté", canal, details, undo
    return "dry_run", canal, details, undo


def _disable_user(cible: str, ctx: dict):
    canal = "API Wazuh → active-response disable-account"
    details = (f"Désactivation du compte {cible} sur l'agent {ctx['agent_id']} "
               "(disable-account). Requiert l'AR disable-account configurée.")
    undo = (f"Réactiver le compte {cible} sur l'agent {ctx['agent_id']} "
            f"(passwd -u {cible} sous Linux, ou enable-account).")
    if config.MITIGATE_EXECUTE:
        _wazuh_ar(ctx["agent_id"], "!disable-account.sh", [cible])
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


# --- reverse par action (annulation d'une remédiation) ----------------------
#
# Toute remédiation doit être défaisable : quand l'analyste passe la tâche IRIS
# d'une action en 'Canceled', `reconcilier` rejoue le reverse correspondant.
# Chacun défait l'action par le MÊME canal que l'aller (Shuffle pour l'hôte, API
# Wazuh pour l'IP/compte), via l'active-response inverse. Retourne le libellé du
# canal utilisé, et LÈVE si le canal échoue (l'appelant garde alors le statut
# 'exécuté' et retentera).
#
# Un reverse s'exécute TOUJOURS, indépendamment de MITIGATE_EXECUTE — même
# logique que --isoler/--desisoler : ce drapeau ne borne que l'exécution
# AUTOMATIQUE depuis un verdict, jamais la restauration. Le gater était un piège
# de sûreté : `reconcilier` marque 'annulé' dès que le reverse rend la main, donc
# couper l'exécution puis annuler ne défaisait RIEN tout en sortant la ligne de
# la sélection `statut='exécuté'` — l'annulation était perdue en silence, sans
# nouvelle tentative possible. Et il n'y a rien à protéger : seules les actions
# réellement parties portent le statut 'exécuté' (une action en dry-run reste en
# 'dry_run'), donc un reverse ne touche que ce qui a vraiment été appliqué.

def _revert_isolate(cible: str, ctx: dict) -> str:
    fire_isolation(cible, False, ctx["reason_court"])
    return "Shuffle → active-response host-unisolate.sh (nftables)"


def _revert_block_ip(cible: str, ctx: dict) -> str:
    _wazuh_ar(ctx["agent_id"], "!firewall-allow.sh", [cible])
    return "API Wazuh → active-response firewall-allow"


def _revert_disable_user(cible: str, ctx: dict) -> str:
    _wazuh_ar(ctx["agent_id"], "!enable-account.sh", [cible])
    return "API Wazuh → active-response enable-account"


# Pas de propose_kill_process : un process tué n'a pas de reverse (« unkill »).
REVERSEURS = {
    "propose_isolate_host": _revert_isolate,
    "propose_block_ip": _revert_block_ip,
    "propose_disable_user": _revert_disable_user,
}


# Regex du suffixe "(uid=NNNN)" que certains décodeurs collent au nom de compte.
_RE_UID_SUFFIXE = re.compile(r"\(uid=(\d+)\)")


def _nom_compte(brut: str) -> str:
    """Nom de compte nu, sans le suffixe (uid=NNNN) ni les espaces."""
    return _RE_UID_SUFFIXE.sub("", str(brut)).strip()


def _comptes_crees(alertes: list[dict]) -> list[str]:
    """Comptes CRÉÉS par l'attaquant (useradd/adduser), non protégés.

    Réutilise l'extraction d'IOC d'iris (`_iocs`, type « account ») : elle
    décode la ligne de commande depuis le proctitle auditd (règle 80792, niv. 3)
    et capte le backdoor account MÊME quand l'alerte syslog 5902 « new user »
    (qui porte dstuser/home/shell) n'est pas ingérée. C'est le point de vérité
    unique pour « quel compte l'attaquant a-t-il créé ». Comptes protégés exclus.
    """
    return sorted({v for v, t, _ in _iocs(alertes)
                   if t == "account" and not _compte_protege(v)})


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


def _alertes_par_agent(alertes: list[dict]) -> dict[str, list[dict]]:
    """Alertes regroupées par agent. Un incident peut couvrir plusieurs machines
    (fusion campagne) : chaque preuve reste attachée à SA machine (agent de
    l'alerte), qui est la seule où l'action correspondante a un sens."""
    par: dict[str, list[dict]] = {}
    for a in alertes:
        ag = str(a.get("agent_id") or "")
        if ag:
            par.setdefault(ag, []).append(a)
    return par


def _cibles_par_machine(action: str, incident: dict,
                        alertes: list[dict]) -> list[tuple[str, str]]:
    """Cibles (agent_id, valeur) d'une action, résolues MACHINE PAR MACHINE à
    partir de l'agent de l'alerte qui porte la preuve.

    Garde-fous « dans le doute, on n'agit pas » :
      - jamais un agent CAPTEUR d'hôte (config.AGENTS_CAPTEURS) : sa télémétrie
        décrit l'activité d'autres machines (conteneurs), donc on ne sait pas sur
        quelle machine agir — on s'abstient plutôt que de viser le mauvais hôte ;
      - une preuve sans agent exploitable est écartée.
    Chaque (machine, valeur) est explicite : pas d'ambiguïté sur « où » — l'action
    part sur la machine où la preuve a été observée, et nulle part ailleurs."""
    par_agent = _alertes_par_agent(alertes)
    agents = [ag for ag in par_agent if ag not in config.AGENTS_CAPTEURS]
    # Trace des capteurs écartés, pour l'analyste (garde-fou visible).
    for ag in par_agent:
        if ag in config.AGENTS_CAPTEURS:
            log.info("#%s %s : agent capteur d'hôte %s écarté des cibles "
                     "(théâtre réel = machine surveillée, remédiation non "
                     "appliquée par sûreté)", incident.get("id"), action, ag)

    if action == "propose_isolate_host":
        out = []
        for ag in sorted(agents):
            refus = raison_non_isolable(ag)
            if refus:
                log.warning("isolation refusée : %s", refus)
                continue
            out.append((ag, ag))
        return out

    if action == "propose_kill_process":
        # Nom exact (comm) des exécutables lancés depuis un répertoire suspect,
        # sur la machine qui l'a exécuté. pkill -x matchera ce nom.
        out: set[tuple[str, str]] = set()
        for ag in agents:
            for a in par_agent[ag]:
                raw = a.get("raw")
                if not raw:
                    continue
                data = (raw if isinstance(raw, dict)
                        else json.loads(raw)).get("data", {})
                audit = data.get("audit", {}) or {}
                for chemin in (audit.get("exe"), a.get("entity")):
                    p = str(chemin or "")
                    if p.startswith(_DIRS_SUSPECTS):
                        base = p.rsplit("/", 1)[-1]
                        if base:
                            out.add((ag, base[:15]))  # comm plafonné à 15 car.
        return sorted(out)

    if action == "propose_block_ip":
        # IP C2 EXTERNE au parc, bloquée sur chaque endpoint qui l'a contactée.
        # « Interne » = subnets du parc (cf. _ip_interne) et non RFC1918 : le C2
        # du lab est lui-même privé et doit rester bloquable ; les IP invalides
        # (none, loopback) sont écartées.
        out = set()
        for ag in agents:
            for a in par_agent[ag]:
                ip = a.get("srcip")
                if ip and _ip_ioc_valide(str(ip)) and not _ip_interne(str(ip)):
                    out.add((ag, str(ip)))
        return sorted(out)

    if action == "propose_disable_user":
        # Compte compromis/créé, désactivé SUR la machine où il apparaît. Comptes
        # protégés exclus. Un backdoor vu seulement par un capteur d'hôte (pas
        # d'auditd dans le conteneur) n'a pas de machine exploitable ici → non
        # désactivé automatiquement (garde-fou), à traiter par l'analyste.
        out = set()
        for ag in agents:
            al = par_agent[ag]
            comptes = {_nom_compte(a["srcuser"]) for a in al
                       if a.get("srcuser") and not _compte_protege(a["srcuser"])}
            comptes |= set(_comptes_crees(al))
            for c in comptes:
                if c:
                    out.add((ag, c))
        return sorted(out)
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

    # Une machine par agent réellement touché (hors capteurs d'hôte) : un
    # incident de campagne en couvre plusieurs. Nom via l'alerte, à défaut l'id.
    noms = {str(a["agent_id"]): (a.get("agent_name") or str(a["agent_id"]))
            for a in alertes if a.get("agent_id")
            and str(a["agent_id"]) not in config.AGENTS_CAPTEURS}
    if not noms:  # aucun endpoint exploitable : au moins l'agent de l'incident.
        noms = {str(inc["agent_id"]): inc.get("agent_name") or str(inc["agent_id"])}
    for nom in sorted(set(noms.values())):
        ajouter(nom, "Linux - Server",
                "Hôte touché par l'incident (cible d'isolation / kill de process).")
    for _ag, compte in _cibles_par_machine("propose_disable_user", inc, alertes):
        ajouter(compte, "Linux Account",
                "Compte compromis ou créé par l'attaquant (cible de désactivation).")


INSERT_MITIG = """
INSERT INTO mitigations (incident_id, action, cible, agent_id, statut, details,
                         undo, iris_task_id)
VALUES (%(incident_id)s, %(action)s, %(cible)s, %(agent_id)s, %(statut)s,
        %(details)s, %(undo)s, %(iris_task_id)s)
ON CONFLICT (incident_id, action, cible, agent_id) DO UPDATE
SET statut = EXCLUDED.statut, details = EXCLUDED.details, undo = EXCLUDED.undo,
    iris_task_id = EXCLUDED.iris_task_id, executed_at = now()
RETURNING id
"""


# Statuts qui interdisent de rejouer une action sur le même couple
# (incident, cible). 'exécuté' pour l'idempotence évidente ; 'annulé' et
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
_STATUTS_FIGES = ("exécuté", "annulé", "annulation_impossible")


def _deja_exec(conn, incident_id: int, action: str, cible: str,
               agent_id: str) -> bool:
    r = conn.execute(
        "SELECT statut FROM mitigations WHERE incident_id=%s AND action=%s "
        "AND cible=%s AND agent_id=%s",
        (incident_id, action, cible, agent_id)).fetchone()
    return bool(r and r["statut"] in _STATUTS_FIGES)


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

        alertes = conn.execute(
            "SELECT agent_id, agent_name, srcip, srcuser, entity, raw "
            "FROM alerts WHERE incident_id = %s", (incident_id,)).fetchall()

        remed = [a for a in triage["actions"] if a in REMEDIATIONS]

        # Garde-fou déterministe : un compte CRÉÉ par l'attaquant sur un vrai
        # positif doit être désactivé même si le LLM n'a pas proposé l'action.
        # Le triage ne voit que les alertes HIGH ; la création de compte remonte
        # d'une alerte auditd bas niveau (proctitle, niv. 3) rattachée à
        # l'incident — visible dans le case, mais absente du prompt de décision.
        # On complète l'action ici, sans jamais toucher au niveau de l'alerte.
        if (triage["verdict"] == "true_positive"
                and "propose_disable_user" not in remed
                and _comptes_crees(alertes)):
            remed.append("propose_disable_user")
            print(f"  #{incident_id} + propose_disable_user (déterministe : "
                  f"compte créé par l'attaquant — {', '.join(_comptes_crees(alertes))})")

        if not remed:
            print(f"  #{incident_id} aucune remédiation à exécuter "
                  f"(verdict {triage['verdict']}).")
            return []

        case = _client() if inc["iris_case_id"] else None
        # Assets (onglet Assets) : hôte + comptes, une fois, avant les actions.
        if case:
            _poser_assets(case, inc["iris_case_id"], inc, alertes)

        mode = "EXÉCUTION" if config.MITIGATE_EXECUTE else "DRY-RUN"
        print(f"  #{incident_id} {inc['agent_name']} — {mode} — "
              f"{len(remed)} action(s)")

        reason_court = (triage["reason"] or "")[:120]

        for action in sorted(remed, key=lambda a: ORDRE_EXEC.index(a)
                             if a in ORDRE_EXEC else 99):
            for machine, cible in _cibles_par_machine(action, inc, alertes):
                # Contexte reconstruit PAR CIBLE : chaque remédiation part sur la
                # machine où sa preuve a été observée, jamais sur un agent global.
                ctx = {"agent_id": machine, "reason_court": reason_court}
                if config.MITIGATE_EXECUTE and _deja_exec(
                        conn, incident_id, action, cible, machine):
                    print(f"      {action} [{cible}@{machine}] déjà exécuté, "
                          "ignoré.")
                    continue
                try:
                    statut, canal, details, undo = EXECUTEURS[action](cible, ctx)
                except Exception as e:  # noqa: BLE001 — un échec de canal ne doit
                    # pas arrêter les autres remédiations ; on le trace.
                    statut, canal = "échec", "—"
                    details, undo = f"Échec du canal : {e}", "—"
                    log.warning("échec %s [%s] : %s", action, cible, e)

                # Chaque remédiation = une TASK (onglet Tasks), pas une note.
                # La machine visée est dans le titre : un incident de campagne
                # porte la même action sur plusieurs hôtes.
                task_id = None
                if case:
                    titre = ("[SIMULATION] " if statut == "dry_run" else "") + \
                        f"Remédiation — {LIBELLE_ACTION.get(action, action)} " \
                        f"({cible} @ {machine})"
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
                    "agent_id": machine, "statut": statut, "details": details,
                    "undo": undo, "iris_task_id": task_id})
                conn.commit()

                resultats.append({"action": action, "cible": cible,
                                  "agent_id": machine, "statut": statut})
                print(f"      {action} [{cible}@{machine}] -> {statut}  ({canal})")
    return resultats


# --- réconciliation : annuler ce que l'analyste a passé en 'Canceled' -------

# Statut de tâche IRIS qui déclenche l'annulation de la remédiation.
_TASK_CANCELED = "Canceled"


def _taches_annulees(tasks: list[dict]) -> set[int]:
    """IDs des tâches en statut 'Canceled' (lecture pure d'un list_tasks IRIS)."""
    return {t["task_id"] for t in (tasks or [])
            if (t.get("status_name") or "") == _TASK_CANCELED}


def _commenter_tache(case, case_id: int, task_id: int, texte: str) -> None:
    """Ajoute un commentaire à la tâche (best-effort : ne bloque pas le reste)."""
    try:
        case.add_task_comment(task_id=task_id, comment=texte, cid=case_id)
    except Exception as e:  # noqa: BLE001
        log.debug("commentaire tâche %s : %s", task_id, e)


SELECT_REVERSIBLES = """
SELECT m.id, m.incident_id, m.action, m.cible, m.details, m.iris_task_id,
       COALESCE(NULLIF(m.agent_id, ''), i.agent_id) AS agent_id, i.iris_case_id
  FROM mitigations m
  JOIN incidents i ON i.id = m.incident_id
 WHERE m.statut = 'exécuté'
   AND m.iris_task_id IS NOT NULL
   AND i.iris_case_id IS NOT NULL
   AND (%(inc)s::bigint IS NULL OR m.incident_id = %(inc)s)
 ORDER BY i.iris_case_id, m.id
"""

# Marque terminale d'une action tuée qu'on ne peut pas défaire : évite de
# re-commenter la tâche à chaque cycle (elle n'est plus sélectionnée).
_STATUT_IRREVERSIBLE = "annulation_impossible"

# Verrou consultatif dédié à la réconciliation. Son timer (1 min) est plus court
# que celui du cycle : deux passages ne doivent pas se superposer et double-tirer
# un reverse (fenêtre entre le SELECT et le commit du statut 'annulé').
_VERROU_RECONCILE = 0x50CA2


def reconcilier(incident_id: int | None = None) -> list[dict]:
    """Défait les remédiations dont la tâche IRIS est passée en 'Canceled'.

    L'analyste garde la main a posteriori : mettre une tâche de remédiation en
    'Canceled' dans IRIS demande au soc-agent de DÉFAIRE l'action — désisoler
    l'hôte, débloquer l'IP, réactiver le compte. Boucle fermée : la tâche IRIS
    est le signal, la table `mitigations` la mémoire (statut 'exécuté' = à
    surveiller ; 'annulé' = déjà défait, plus repris). Le kill de process n'a
    pas de reverse : on le documente une fois et on le marque terminal.

    Idempotent : une remédiation déjà annulée n'est plus sélectionnée ; un
    reverse en échec reste 'exécuté' et sera retenté au cycle suivant.
    """
    resultats: list[dict] = []
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        # Un seul reconcile à la fois (son timer est court) : sinon deux passages
        # pourraient sélectionner puis double-défaire la même remédiation.
        if not conn.execute("SELECT pg_try_advisory_lock(%s)",
                            (_VERROU_RECONCILE,)).fetchone()["pg_try_advisory_lock"]:
            log.info("réconciliation déjà en cours, on passe ce tour")
            return []
        try:
            rows = conn.execute(SELECT_REVERSIBLES,
                                {"inc": incident_id}).fetchall()
            if not rows:
                return []
            resultats = _reconcilier_rows(conn, rows)
        finally:
            conn.execute("SELECT pg_advisory_unlock(%s)", (_VERROU_RECONCILE,))
    return resultats


def _reconcilier_rows(conn, rows: list[dict]) -> list[dict]:
    """Cœur de la réconciliation, verrou déjà pris par l'appelant."""
    resultats: list[dict] = []
    case = _client()
    annulees: dict[int, set[int]] = {}   # case_id -> {task_id Canceled}
    for r in rows:
        cid = r["iris_case_id"]
        if cid not in annulees:
            try:
                d = case.list_tasks(cid).get_data() or {}
                annulees[cid] = _taches_annulees(d.get("tasks"))
            except Exception as e:  # noqa: BLE001 — IRIS KO ne casse rien
                log.warning("list_tasks case #%s : %s", cid, e)
                annulees[cid] = set()
        if r["iris_task_id"] not in annulees[cid]:
            continue   # tâche pas (encore) annulée par l'analyste

        action, cible, task_id = r["action"], r["cible"], r["iris_task_id"]
        reverseur = REVERSEURS.get(action)

        # Action irréversible (kill) : documenter, marquer terminal, passer.
        if reverseur is None:
            _commenter_tache(case, cid, task_id,
                f"⚠️ Annulation demandée (tâche passée en {_TASK_CANCELED}) "
                f"mais l'action « {LIBELLE_ACTION.get(action, action)} » est "
                "irréversible (pas de reverse). Rien n'a été défait "
                "automatiquement.")
            conn.execute("UPDATE mitigations SET statut = %s WHERE id = %s",
                         (_STATUT_IRREVERSIBLE, r["id"]))
            conn.commit()
            resultats.append({"action": action, "cible": cible,
                              "statut": _STATUT_IRREVERSIBLE})
            print(f"      {action} [{cible}] annulation impossible (kill)")
            continue

        ctx = {"agent_id": str(r["agent_id"]),
               "reason_court": f"tâche IRIS #{task_id} passée en {_TASK_CANCELED}"}
        try:
            canal = reverseur(cible, ctx)
        except Exception as e:  # noqa: BLE001 — reverse en échec : on garde le
            # statut 'exécuté' pour retenter au prochain passage, on trace.
            log.warning("reverse %s [%s] échoué : %s", action, cible, e)
            _commenter_tache(case, cid, task_id,
                f"❌ Tentative d'annulation automatique de « "
                f"{LIBELLE_ACTION.get(action, action)} » ({cible}) en échec : "
                f"{e}. Nouvelle tentative au prochain passage.")
            continue

        conn.execute(
            "UPDATE mitigations SET statut = 'annulé', "
            "details = %s, executed_at = now() WHERE id = %s",
            (f"{r['details'] or ''} — Annulé : tâche IRIS passée en "
             f"{_TASK_CANCELED}, action défaite via {canal}.", r["id"]))
        conn.commit()
        _commenter_tache(case, cid, task_id,
            f"↩️ Remédiation défaite automatiquement suite au passage "
            f"de la tâche en {_TASK_CANCELED} : « "
            f"{LIBELLE_ACTION.get(action, action)} » ({cible}) annulée via "
            f"{canal}.")
        resultats.append({"action": action, "cible": cible, "statut": "annulé"})
        print(f"      {action} [{cible}] -> annulé  ({canal})")
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
    if args.isoler:
        isoler(args.isoler, args.motif, args.forcer)
    elif args.desisoler:
        desisoler(args.desisoler, args.motif)
    elif args.etat:
        _afficher_etat(etat_isolation(args.etat))
    elif args.reconcilier:
        reconcilier()
    else:
        executer(args.incident)


if __name__ == "__main__":
    main()
