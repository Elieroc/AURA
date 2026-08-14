"""Executing the remediations decided at triage, with an IRIS record per action.

The move from "propose" to "execute". For every remediation action of a true
positive incident, we:

1. execute it through its channel (Shuffle SOAR for isolation; the Wazuh API for
   IP blocking and account disabling);
2. write a note in the IRIS case: what was done, why, and HOW to undo it — every
   mitigation must be reversible;
3. record it in database (`mitigations`): audit plus idempotence.

Security — this executes high-impact actions on production from a model verdict,
AUTONOMOUSLY (the project goal: an autonomous XDR). The barriers are not a human
sign-off up front, but deterministic guardrails:

- `MITIGATE_EXECUTE=true`: remediations really fire, including the high-impact
  ones (isolation, blocking, disabling). Set it to `false` for a global dry-run
  (sandbox), not to require a human.
- An incident whose triage spotted injection patterns is SUSPENDED: a verdict
  rendered on a manipulated context does not command a real action.
- Protected accounts (`_is_protected_account`) are never disabled, the closure
  level is capped, internal targets are excluded from blocking: safety rests on
  rules verifiable in the code, not on a human review.
- Only the actions of the closed enumeration are executable; open_case / close /
  escalate do not go through here.

The IRIS notes and tasks written here stay in French: analysts read them.

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

# Actions actually executable (remediations). The rest (open_case,
# close_false_positive, escalate_human) is not a machine action. Forensic
# collection is NOT part of it: it is not driven by the AI.
REMEDIATIONS = {"propose_isolate_host", "propose_block_ip",
                "propose_disable_user", "propose_kill_process",
                "propose_quarantine_file", "propose_remove_privileged_group"}

# Execution order: kill the malicious process, quarantine the file and cut the
# flows/accounts BEFORE isolating; isolate LAST (isolation cuts the channels —
# Wazuh API, Shuffle — the other remediations depend on).
ORDER_EXEC = ["propose_kill_process", "propose_quarantine_file",
              "propose_block_ip", "propose_disable_user",
              "propose_remove_privileged_group", "propose_isolate_host"]

# Actions only PROPOSED (never executed automatically, even with
# MITIGATE_EXECUTE): too high-impact for the current autonomy (removal from a
# privileged AD group). The executor returns 'dry_run' and the analyst decides
# through the IRIS task. See the autonomy tier "local + disable AD account
# auto".
MANUAL_ACTIONS = {"propose_remove_privileged_group"}

# Directories from which an executable is an implant to kill (never a legitimate
# system binary). Used to target the malicious process, not a normal shell.
_DIRS_SUSPICIOUS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/")


# --- execution channels -----------------------------------------------------

def _shuffle(webhook: str, payload: dict) -> str:
    r = requests.post(f"{config.SHUFFLE_URL}/api/v1/hooks/{webhook}",
                      json=payload, timeout=15)
    r.raise_for_status()
    return r.text


def fire_isolation(agent_id: str, isolate: bool, reason: str) -> str:
    """Isolates (or un-isolates) an agent through the Shuffle webhook.

    The same workflow both ways, only the active response changes:
    host-isolate.sh sets the nftables rules, host-unisolate.sh removes them.
    """
    cmd = "!host-isolate.sh" if isolate else "!host-unisolate.sh"
    return _shuffle(config.SHUFFLE_WEBHOOK_ISOLATE,
                    {"agent_id": agent_id, "ar_command": cmd, "reason": reason})


def fire_kill(agent_id: str, process: str, reason: str) -> str:
    """Kills a process by exact name (comm) on the agent, through the Shuffle
    webhook.

    `extra_args` = the EXACT process name (pkill -x on the AR side); the safelist
    of `kill-process.sh` already refuses the critical processes (sshd, Wazuh
    agent, systemd). A plain string: the Shuffle body wraps it into the array the
    Wazuh API expects.
    """
    return _shuffle(config.SHUFFLE_WEBHOOK_KILL,
                    {"agent_id": agent_id, "ar_command": "!kill-process.sh",
                     "extra_args": process, "reason": reason})


def _trace_isolation(agent_id: str, isolate: bool, reason: str) -> None:
    """Records a manual (un)isolation on the agent's open incidents.

    No incident attached -> no record in database (the `mitigations` table is
    indexed by incident); Shuffle and Wazuh keep the log anyway.
    """
    status = "executed" if isolate else "canceled"
    action, target = "propose_isolate_host", agent_id
    details = (f"Isolation réseau manuelle de l'agent {agent_id}." if isolate
               else f"Levée manuelle de l'isolation de l'agent {agent_id}.")
    undo = (f"Désisoler : python -m soc_agent.mitigate --unisolate {agent_id}"
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
        print(f"  agent {a}: UNKNOWN state (unreachable over SSH from the manager)")
    elif state["isolated"]:
        since = (state.get("marker") or {}).get("since", "?")
        print(f"  agent {a}: ISOLATED (marker present, since {since})")
    else:
        print(f"  agent {a}: not isolated (no marker)")


def isolate(agent_id: str, reason: str = "manual isolation",
           force: bool = False) -> None:
    """Isolation requested by an operator.

    The "endpoints only" guardrail applies HERE too: an operator typing the
    command on a firewall almost never wants to cut the site off, they picked the
    wrong agent. But they remain the decision-maker — `--force` lifts the
    refusal. That is the difference between a barrier (the automation, never
    crossable) and a net (the human, who must explicitly say they know).
    """
    refusal = not_isolatable_reason(agent_id)
    if refusal and not force:
        print(f"  REFUSED: {refusal}")
        print("  Run again with --force if the isolation is really wanted.")
        return
    if refusal:
        print(f"  /!\\ guardrail overridden (--force): {refusal}")
    fire_isolation(agent_id, True, reason)
    _trace_isolation(agent_id, True, reason)
    print(f"  agent {agent_id}: isolation requested ({reason})")
    _show_state(_confirm(agent_id, True))


def unisolate(agent_id: str, reason: str = "manual unisolation") -> None:
    fire_isolation(agent_id, False, reason)
    _trace_isolation(agent_id, False, reason)
    print(f"  agent {agent_id}: isolation lift requested ({reason})")
    _show_state(_confirm(agent_id, False))


def _wazuh_token() -> str:
    r = requests.post(
        f"{config.WAZUH_API_URL}/security/user/authenticate?raw=true",
        auth=(config.WAZUH_API_USER, config.WAZUH_API_PASSWORD),
        verify=False, timeout=15)
    r.raise_for_status()
    return r.text.strip()


# Monotonic timestamp of the last AR sent, to serialise bursts.
_last_ar_ts: float = 0.0


def _throttle_ar() -> None:
    """Space the AR emissions by at least MITIGATE_AR_GAP_SECONDS.

    `wazuh-execd` processes active responses in a queue; a burst of closely
    spaced commands towards the same agent makes it drop some of them before the
    script even runs (measured at the exercise). We hold a minimum interval
    between two sends.
    """
    global _last_ar_ts
    gap = config.MITIGATE_AR_GAP_SECONDS
    if gap > 0:
        remains = gap - (time.monotonic() - _last_ar_ts)
        if remains > 0:
            time.sleep(remains)
    _last_ar_ts = time.monotonic()


def _wazuh_ar(agent_id: str, command: str, arguments: list[str]) -> dict:
    """Fires a Wazuh active response on an agent (direct API).

    Raises if the API did not accept the agent. A 200 is not enough: the API
    answers 200 with the agent in `failed_items` when it is disconnected or
    unknown, and the caller then marked the remediation 'executed' while nothing
    had gone out.

    Out of reach: the RESULT of the script on the agent side. The API is
    fire-and-forget, the AR returns nothing — a script refusing the target only
    surfaces in the agent's `active-responses.log`. Hence the importance of the
    script itself being correct (see wazuh/active-response/), end-to-end
    verification only being possible by reading the host's real state.
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
            f"the Wazuh API did not pass {command} to agent {agent_id}: "
            f"{rep.get('message') or ''} {failures}".strip())
    return rep


# --- reading the isolation state (marker, over SSH) -------------------------

def _agent_ip(agent_id: str) -> str | None:
    tok = _wazuh_token()
    r = requests.get(f"{config.WAZUH_API_URL}/agents",
                     params={"agents_list": agent_id, "select": "ip"},
                     headers={"Authorization": f"Bearer {tok}"},
                     verify=False, timeout=15)
    r.raise_for_status()
    items = r.json().get("data", {}).get("affected_items", [])
    return items[0].get("ip") if items else None


# IPs of every agent of the estate, memoised for the lifetime of the process.
# The inventory does not move at the scale of a remediation cycle; one API call
# is enough.
_IPS_AGENTS_CACHE: set[str] | None = None


def _agent_ips() -> set[str]:
    """IPs of every Wazuh agent — our own monitored assets.

    Blocking guardrail: an agent IP is NEVER a block_ip target. A host of the
    estate appearing as srcip is a victim or a pivot (the attack bounced THROUGH
    it), not the attacker — we contain it on ITS machine (isolation, account
    disabling), we do not blackhole its IP at a neighbour's. Measured at a
    purple-team exercise: block_ip targeted the IP of a pivot host (a victim, not
    the attacker), because its subnet was not in NETWORKS_INTERNAL — exclusion by
    membership of the estate is robust whatever the addressing plan, and still
    leaves blockable an attacker sharing the same subnet without being an agent.

    If the API is unreachable: an empty set (we do not block the remediation, but
    we log it — the fallback is "block without asset exclusion", not "block
    nothing")."""
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
        log.warning("agent IP inventory unreadable (%s): blocking without asset "
                    "exclusion this round", e)
    _IPS_AGENTS_CACHE = ips
    return ips


def _is_private_ip(ip: str) -> bool:
    """IP in a private RFC1918/loopback/link-local range (for the blocking ORDER).

    Only used for sorting: public IPs first. This is NOT an exclusion criterion —
    a C2 can be in RFC1918 (VPN, private cloud...) and must stay blockable — just
    a priority: a real attacker is most often outside RFC1918, and a residual
    private IP is more probably a misclassified internal bounce."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _agent_groups(agent_id: str) -> set[str] | None:
    """Wazuh groups of the agent, or None when they could not be read.

    None and set() do NOT mean the same thing: None = "I do not know" (API
    unreachable, unknown agent), set() = "no group", which is a fact. The caller
    treats the two differently.
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
        log.warning("groups of agent %s unreadable: %s", agent_id, e)
        return None


def not_isolatable_reason(agent_id: str) -> str | None:
    """Reason to refuse isolating this agent, or None when it is isolatable.

    Isolation only targets ENDPOINTS. Three barriers, in order:

    1. agent explicitly protected (`AGENTS_PROTECTED`, including 000 the manager,
       which has no group at all — the group mechanism would not cover it);
    2. agent belonging to an infrastructure group: firewall, proxy, DNS, VPN.
       Those machines route other people's traffic, cutting them causes a general
       outage instead of containing an incident;
    3. role undeterminable — refused by default (see
       ISOLATION_REFUSE_IF_ROLE_UNKNOWN).
    """
    if str(agent_id) in config.AGENTS_PROTECTED:
        return f"agent {agent_id} protected (AGENTS_PROTECTED)"

    groups = _agent_groups(str(agent_id))
    if groups is None:
        if config.ISOLATION_REFUSE_IF_ROLE_UNKNOWN:
            return (f"role of agent {agent_id} undeterminable (unreadable "
                    "groups) — isolation refused out of caution")
        return None

    forbidden = groups & config.ISOLATION_FORBIDDEN_GROUPS
    if forbidden:
        return (f"agent {agent_id} in group {', '.join(sorted(forbidden))} "
                "— network infrastructure, never isolated")
    return None


def _interpret(stdout: str, returncode: int) -> dict:
    """Translates the output of `cat marker` into an isolation state. Pure.

    - rc 255: SSH failure (agent unreachable) -> unknown state.
    - non-empty stdout: marker present -> isolated (we parse the JSON if we can).
    - empty stdout (file absent): not isolated.
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
        marker, isolated = None, True  # marker present but unreadable = isolated
    return {"isolated": isolated, "reachable": True, "marker": marker}


def isolation_state(agent_id: str) -> dict:
    """Isolation state of an agent, read from the /var/ossec/isolated marker.

    Ground truth (a file set by host-isolate.sh), reliable even on an isolated
    agent as long as this reader runs on the manager host (SSH allowed from
    there). Read-only, a frozen command — no driven shell.
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
    """Waits for the marker to reflect the expected state (the AR takes a few
    seconds to land)."""
    state = {}
    for _ in range(attempts):
        state = isolation_state(agent_id)
        if state["isolated"] == expected:
            return state
        time.sleep(3)
    return state


# --- executors per action ---------------------------------------------------
#
# Each returns (status, channel, details, undo). In dry-run it DESCRIBES the
# action without firing it (status 'dry_run'). Any exception -> status
# 'failed'.

def _agent_windows(agent_id: str) -> bool:
    """True if the agent runs Windows (routes to the Windows/AD ARs)."""
    return str(agent_id) in config.AGENTS_WINDOWS


def _un_dc() -> str | None:
    """A domain controller agent (executor of the domain actions)."""
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
            return "sent", channel, details, undo
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
        fire_isolation(target, True, ctx["reason_short"])
        return "sent", channel, details, undo
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
        return "sent", channel, details, undo
    return "dry_run", channel, details, undo


def _disable_user(target: str, ctx: dict):
    # On a Windows target, _targets_by_machine has already routed
    # ctx['agent_id'] to a DC: we disable the account IN the directory
    # (ad-disable-account), not locally on the member host where it does not
    # exist.
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
        return "sent", channel, details, undo
    return "dry_run", channel, details, undo


def _kill_process(target: str, ctx: dict):
    if _agent_windows(ctx["agent_id"]):
        # Target "image.exe#pid" (see _win_suspicious_processes): we send the
        # PID as the first argument and the expected image as the second. The
        # script kills the PID ONLY if it still carries that image — a PID gets
        # reused, and up to 5 min elapse between the alert and the remediation.
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
            return "sent", channel, details, undo
        return "dry_run", channel, details, undo

    channel = "Shuffle → active-response kill-process.sh (pkill -x)"
    details = (f"Arrêt du process malveillant « {target} » sur l'agent "
               f"{ctx['agent_id']} (pkill -x, nom exact). La safelist de l'AR "
               "protège les process critiques (sshd, agent Wazuh, systemd).")
    undo = ("Action irréversible (pas d'« unkill »). Si le process était "
            "légitime, le relancer manuellement sur l'hôte.")
    if config.MITIGATE_EXECUTE:
        fire_kill(ctx["agent_id"], target, ctx["reason_short"])
        return "sent", channel, details, undo
    return "dry_run", channel, details, undo


def _quarantine_file(target: str, ctx: dict):
    # Windows only (the Linux quarantine.sh analogue is not exposed to the AI).
    channel = "API Wazuh → win-quarantine-file.exe (déplacement + deny ACL)"
    details = (f"Mise en quarantaine du fichier {target} sur l'hôte Windows "
               f"{ctx['agent_id']} : hash SHA256, déplacement vers le dossier de "
               "quarantaine, accès refusé. Les chemins système sont exclus.")
    undo = (f"Restaurer : active-response win-restore-file.exe pour {target} sur "
            f"l'agent {ctx['agent_id']}.")
    if config.MITIGATE_EXECUTE:
        _wazuh_ar(ctx["agent_id"], "!win-quarantine-file.exe", [target])
        return "sent", channel, details, undo
    return "dry_run", channel, details, undo


def _remove_group_member(target: str, ctx: dict):
    # PROPOSE-ONLY (MANUAL_ACTIONS): never executed automatically, even with
    # MITIGATE_EXECUTE. target = "group|member".
    group, _, member = target.partition("|")
    channel = "API Wazuh → ad-remove-group-member.exe (Active Directory, sur DC)"
    details = (f"Retrait de « {member} » du groupe privilégié « {group} » dans "
               f"AD (sur le DC {ctx['agent_id']}). Action à FORT IMPACT — proposée "
               "à l'analyste, exécution manuelle (palier d'autonomie actuel).")
    undo = (f"Réintégrer : active-response ad-add-group-member.exe {group} "
            f"{member} sur l'agent {ctx['agent_id']}.")
    # Always 'dry_run': it is a proposal, the analyst runs the IRIS task.
    return "dry_run", channel, details, undo


EXECUTORS = {
    "propose_kill_process": _kill_process,
    "propose_quarantine_file": _quarantine_file,
    "propose_isolate_host": _isolate,
    "propose_block_ip": _block_ip,
    "propose_disable_user": _disable_user,
    "propose_remove_privileged_group": _remove_group_member,
}


# --- reverse per action (undoing a remediation) -----------------------------
#
# Every remediation must be reversible: when the analyst moves an action's IRIS
# task to 'Canceled', `reconcile` replays the matching reverse. Each undoes the
# action through the SAME channel as the outbound one (Shuffle for the host, the
# Wazuh API for the IP/account), through the inverse active response. Returns the
# label of the channel used, and RAISES if the channel fails (the caller then
# keeps the 'executed' status and will retry).
#
# A reverse ALWAYS runs, independently of MITIGATE_EXECUTE — same logic as
# --isolate/--unisolate: that flag only bounds AUTOMATIC execution from a
# verdict, never the restoration. Gating it was a safety trap: `reconcile` marks
# 'canceled' as soon as the reverse returns, so turning execution off then
# cancelling undid NOTHING while removing the row from the `status='executed'`
# selection — the cancellation was lost silently, with no possible retry. And
# there is nothing to protect: only actions that really went out carry the
# 'executed' status (a dry-run action stays at 'dry_run'), so a reverse only
# touches what was actually applied.

def _revert_isolate(target: str, ctx: dict) -> str:
    if _agent_windows(ctx["agent_id"]):
        _wazuh_ar(ctx["agent_id"], "!win-host-unisolate.exe", [])
        return "API Wazuh → win-host-unisolate.exe (Windows Firewall)"
    fire_isolation(target, False, ctx["reason_short"])
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


# No propose_kill_process: a killed process has no reverse ("unkill"). No
# propose_remove_privileged_group: proposed only, never executed automatically
# (hence never 'executed' to undo); ad-add-group-member stays available by
# hand.
REVERTERS = {
    "propose_isolate_host": _revert_isolate,
    "propose_block_ip": _revert_block_ip,
    "propose_disable_user": _revert_disable_user,
    "propose_quarantine_file": _revert_quarantine_file,
}


# Regex of the "(uid=NNNN)" suffix some decoders glue to the account name.
_RE_UID_SUFFIX = re.compile(r"\(uid=(\d+)\)")


def _account_name(raw: str) -> str:
    """Bare account name: without (uid=NNNN), without a DOMAIN\\ prefix nor
    @domain.

    The Windows domain prefix (`LAB\\Administrateur`, `Administrateur@lab`) made
    the protected-account filter fail (compared against the bare form) and became
    a bad action target — ad-disable-account wants the bare SAM.
    """
    name = _RE_UID_SUFFIX.sub("", str(raw))
    name = re.split(r"[\\/]", name)[-1]      # DOMAINE\user -> user
    name = name.split("@", 1)[0]             # user@domaine -> user
    return name.strip()


# Built-in Windows/AD accounts NEVER to disable (GENERIC_ACCOUNTS only carries
# the English form "administrator"). A mirror of the AR guardrail
# (_ar-common.ps1 Test-ProtectedAccount) on the Python target-selection side:
# without it, the AI fired at "Administrateur" and at the machine account
# "WIN-DC$" (seen as srcuser in the logons), caught only by the AR script.
#
# The "account" labels appearing in Windows logon events are not all accounts:
# `Système`, `ANONYMOUS LOGON`, `SERVICE LOCAL`, `UMFD-0` are well-known
# identities (well-known SIDs) or service sessions. A purple-team exercise sent
# `ad-disable-account` at three of them (only the AR script refused). Both
# spellings are listed: a French DC returns one, an English DC the other.
_ACCOUNTS_WINDOWS_PROTECTED = {
    "administrateur", "krbtgt", "defaultaccount", "wdagutilityaccount",
    "localservice",
    # system identities, EN then FR spelling
    "system", "système", "local service", "service local",
    "network service", "service réseau", "anonymous logon",
    "connexion anonyme", "iusr", "invité", "guest",
    "openssh_users", "tout le monde", "everyone",
}

# Technical session accounts whose name is indexed (UMFD-0, DWM-1, DWM-2...).
_RE_ACCOUNT_SESSION = re.compile(r"^(umfd|dwm)-\d+$", re.IGNORECASE)


def _created_accounts(alerts: list[dict]) -> list[str]:
    """Accounts CREATED by the attacker (useradd/adduser), not protected.

    Reuses the IOC extraction of iris (`_iocs`, type "account"): it decodes the
    command line from the auditd proctitle (rule 80792, level 3) and catches the
    backdoor account EVEN when the syslog 5902 "new user" alert (which carries
    dstuser/home/shell) is not ingested. It is the single point of truth for
    "which account did the attacker create". Protected accounts excluded.
    """
    return sorted({v for v, t, _ in _iocs(alerts)
                   if t == "account" and not _is_protected_account(v)})


def _is_protected_account(raw: str) -> bool:
    """An account NEVER to disable automatically.

    A critical guardrail: as the thresholds came down, the activity of legitimate
    accounts (root, the SOC admin, the login sessions) entered the incident and
    ended up targeted by the disabling — the AI really did lock `wazuh-admin`. We
    protect:
      - the generic/system accounts (root, admin, system...);
      - the SOC operations accounts (SSH_USER, WAZUH_API_USER);
      - any account whose embedded uid is < 1000 (Linux system accounts).
    The (uid=NNNN) suffix that let `root(uid=0)` through the exact filter is now
    normalised away.
    """
    name = _account_name(raw).lower()
    if not name or name in GENERIC_ACCOUNTS or name in _ACCOUNTS_WINDOWS_PROTECTED:
        return True
    if name.endswith("$"):        # machine / AD trust account (e.g. WIN-DC$)
        return True
    if _RE_ACCOUNT_SESSION.match(name):   # UMFD-0, DWM-1: sessions, not accounts
        return True
    if name in {str(config.SSH_USER).lower(), str(config.WAZUH_API_USER).lower()}:
        return True
    m = _RE_UID_SUFFIX.search(str(raw))
    return bool(m and int(m.group(1)) < 1000)


_WIN_EXE_EXT = (".exe", ".dll", ".ps1", ".bat", ".scr", ".com", ".vbs")

# AppLocker probes created by PowerShell itself on every launch in %TEMP%: they
# are neither an implant nor an attacker process. The purple-team exercise killed
# and quarantined ten of them.
_RE_PROBE_PS = re.compile(r"__PSScriptPolicyTest_", re.IGNORECASE)

# Windows long-path prefixes: `\\?\`, `\??\` (the NT object form) and their UNC
# variants. They designate exactly the same file as the bare path but do not
# start with `c:\windows` — which was enough to make a System32 binary pass for a
# dropped implant (see _norm_win_path).
_RE_PREFIX_LONG = re.compile(r"^\\{1,2}\?{1,2}\\(?P<unc>UNC\\)?", re.IGNORECASE)

# Process names too generic to be killed "by name": Stop-Process -Name kills
# EVERY instance on the machine. On the DC of a purple-team exercise, killing
# `powershell` and `wsmprovhost` cut the administration sessions and every
# legitimate WinRM session. Those processes are only killable by PID, with the
# image checked on the AR script side.
_NAMES_PROCESS_GENERIC = {
    "powershell.exe", "powershell_ise.exe", "pwsh.exe", "cmd.exe", "net.exe",
    "net1.exe", "wsmprovhost.exe", "conhost.exe", "explorer.exe", "runas.exe",
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "wmic.exe", "cscript.exe",
    "wscript.exe", "svchost.exe", "dllhost.exe", "taskhostw.exe",
    "werfault.exe", "msiexec.exe", "schtasks.exe", "reg.exe", "sc.exe",
}


def _norm_win_path(raw: str) -> str:
    r"""Normalised Windows path: single separators, no quotes.

    The JSON of the Windows eventchannel arrives with DOUBLED backslashes and
    Wazuh keeps them as is: `C:\\Windows\\System32\\cmd.exe` is stored with two
    backslash characters between each segment. The system-directory exclusion
    test therefore compared `c:\\windows...` with `c:\windows`: never true.
    Result measured at a purple-team exercise: 26 quarantine orders on signed
    System32 binaries of a domain controller (cmd.exe, net.exe, powershell.exe,
    dsquery.exe...), caught only by the AR script safelist. Normalising here is
    the FIRST barrier; the script's remains the last.

    The normalisation goes further than un-doubling the backslashes, because the
    system-directory exclusion is a PREFIX comparison: any non-canonical writing
    of the same path bypasses it. Two forms, both accepted as is by the Windows
    API at the end of the chain:

    - the long-path prefix, which makes a System32 path stop starting with
      `c:\windows`;
    - the `..` segments, which do the same through traversal.

    So we strip the long prefix and resolve the directory traversal
    (`ntpath.normpath`, which reasons in Windows syntax whatever OS runs this
    code: the soc-agent runs on Linux).
    """
    p = str(raw or "").strip().strip('"')
    while "\\\\" in p:
        p = p.replace("\\\\", "\\")
    # The folding above turns `\\?\` into `\?\`: the prefix is therefore
    # recognised in both forms, before and after un-doubling. The UNC variant
    # (`\\?\UNC\server\share`) becomes an ordinary UNC path again.
    m = _RE_PREFIX_LONG.match(p)
    if m:
        p = ("\\\\" if m.group("unc") else "") + p[m.end():]
    return ntpath.normpath(p) if p else p


def _win_path_outside_system(p: str) -> bool:
    """True if `p` is a plausible Windows path, outside a system directory and
    outside an AppLocker probe. Assumes nothing about the extension: a webshell or
    a payload with no executable extension stays quarantinable.

    `p` MUST come from `_norm_win_path`: the comparison is a prefix test, it only
    holds on a canonical path. A residual `..` is enough to make a System32
    binary pass for a dropped implant.
    """
    p = _norm_win_path(p)
    pl = p.lower()
    if ".." in pl.split("\\"):
        # normpath could not resolve (relative path, traversal beyond the
        # root): we do not know what this path designates, so we do not act.
        return False
    return bool((":\\" in p or p.startswith("\\"))
                and not pl.startswith(config.VT_DIRS_SYSTEM)
                and not _RE_PROBE_PS.search(p))


def _win_path_suspicious(p: str) -> bool:
    """True if `p` is a Windows EXECUTABLE outside a system directory."""
    return bool(_win_path_outside_system(p) and p.lower().endswith(_WIN_EXE_EXT))


def _win_suspicious_files(alerts: list[dict]) -> set[str]:
    """Paths of Windows executables seen in NON-system locations (dropped or
    launched by the attacker). Target of kill_process (name) and of quarantine
    (full path). System directories are excluded: a signed System32 binary is a
    matter of behavioural detection, not of an implant to kill/quarantine.
    Sources: Sysmon (image / targetFilename / *Image) plus entity."""
    out: set[str] = set()
    for a in alerts:
        for c in _win_path_fields(a):
            p = _norm_win_path(c)
            if _win_path_suspicious(p):
                out.add(p)
    return out


def _eventdata(alert: dict) -> dict:
    """The `data.win.eventdata` block of a Windows alert (empty if absent)."""
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
    """Windows processes to kill, as (image name, pid).

    The PID comes from Sysmon EID 1 (`processId`, decimal) or from event 4688
    (`newProcessId`, hexadecimal). It is indispensable for generic images:
    `Stop-Process -Name powershell` kills every session on the machine,
    including the administrator's and WinRM's. A process whose image is generic
    AND whose PID we do not have is NOT a target: when in doubt, do not act.

    The pid is returned next to the name so the AR script can check that the PID
    really carries that image before killing (a PID is reusable, and several
    minutes can pass between the alert and the remediation).
    """
    out: set[tuple[str, str]] = set()
    for a in alerts:
        ev = _eventdata(a)
        image = _norm_win_path(ev.get("image") or "")
        if not image or not _win_path_suspicious(image):
            # System/unknown image: fall back on the suspicious paths seen
            # elsewhere in the alert (file drop, targetFilename...).
            continue
        base = image.rsplit("\\", 1)[-1]
        pid = _alert_pid(ev)
        if not pid and base.lower() in _NAMES_PROCESS_GENERIC:
            log.info("kill_process: '%s' with no usable PID and a generic name "
                     "— not targeted (killing by name would cut legitimate "
                     "sessions)", base)
            continue
        out.add((base, pid))
    # Implants dropped outside the system directories and seen without a
    # process-creation event: killable by name, the name not being generic.
    for p in _win_suspicious_files(alerts):
        base = p.rsplit("\\", 1)[-1]
        if base.lower() in _NAMES_PROCESS_GENERIC:
            continue
        if not any(n == base for n, _ in out):
            out.add((base, ""))
    return out


def _alert_pid(ev: dict) -> str:
    """Decimal PID of the created process, from Sysmon EID 1 or event 4688."""
    pid = str(ev.get("processId") or "").strip()
    if pid.isdigit():
        return pid
    raw = str(ev.get("newProcessId") or "").strip()   # 4688: "0x1a4c"
    try:
        return str(int(raw, 16)) if raw.lower().startswith("0x") else ""
    except ValueError:
        return ""


def _alerts_by_agent(alerts: list[dict]) -> dict[str, list[dict]]:
    """Alerts grouped by agent. An incident can span several machines (campaign
    merge): every piece of evidence stays attached to ITS machine (the alert's
    agent), the only one where the matching action makes sense."""
    by: dict[str, list[dict]] = {}
    for a in alerts:
        ag = str(a.get("agent_id") or "")
        if ag:
            by.setdefault(ag, []).append(a)
    return by


def _targets_by_machine(action: str, incident: dict,
                        alerts: list[dict]) -> list[tuple[str, str]]:
    """Targets (agent_id, value) of an action, resolved MACHINE BY MACHINE from
    the agent of the alert that carries the evidence.

    "When in doubt, do not act" guardrails:
      - never a host SENSOR agent (config.AGENTS_SENSORS): its telemetry
        describes the activity of other machines (containers), so we do not know
        which machine to act on — better to abstain than to hit the wrong host;
      - evidence without a usable agent is discarded.
    Every (machine, value) is explicit: no ambiguity about "where" — the action
    goes to the machine where the evidence was observed, and nowhere else."""
    by_agent = _alerts_by_agent(alerts)
    agents = [ag for ag in by_agent if ag not in config.AGENTS_SENSORS]
    # Trace of the discarded sensors, for the analyst (visible guardrail).
    for ag in by_agent:
        if ag in config.AGENTS_SENSORS:
            log.info("#%s %s: host sensor agent %s dropped from the targets "
                     "(the real theatre is the monitored machine, remediation "
                     "not applied for safety)", incident.get("id"), action, ag)

    if action == "propose_isolate_host":
        out = []
        for ag in sorted(agents):
            refusal = not_isolatable_reason(ag)
            if refusal:
                log.warning("isolation refused: %s", refusal)
                continue
            out.append((ag, ag))
        return out

    if action == "propose_kill_process":
        # Exact name (comm) of the executables launched from a suspicious
        # directory, on the machine that ran them. pkill -x (Linux) /
        # Stop-Process (Windows).
        out: set[tuple[str, str]] = set()
        for ag in agents:
            if _agent_windows(ag):
                # Windows: "image#pid" (the pid may be empty). The AR script
                # kills the PID after checking it really carries that image;
                # without a pid it falls back on the name, which
                # _win_suspicious_processes only allows for a non-generic name.
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
                            out.add((ag, base[:15]))  # comm capped at 15 chars
        return sorted(out)

    if action == "propose_block_ip":
        # IP of the ATTACKER, blocked on every endpoint that contacted it.
        # Three filters, from the safest to the finest:
        #  1. invalid IP (none, loopback, broadcast) discarded;
        #  2. IP in a subnet of the estate (_ip_internal) discarded — internal
        #     lateral movement, not a C2. "Internal" = the listed subnets, NOT
        #     all of RFC1918 (a C2 can be private and must stay blockable);
        #  3. IP of a MONITORED AGENT discarded — a victim or a pivot is not the
        #     attacker (guardrail added after a purple-team exercise where the
        #     pivot host of an attack was wrongly blocked).
        # Then we ORDER them (public IPs first) without reducing: a bruteforce
        # comes from N IPs, all of them to block.
        assets = _agent_ips()

        def _blockable(ip: str) -> bool:
            ip = str(ip)
            if not _ip_ioc_valid(ip) or _ip_internal(ip):
                return False        # invalid, or estate subnet (victim/pivot)
            if ip in assets:
                log.info("#%s block_ip: %s discarded (IP of a monitored agent "
                         "— victim/pivot, not the attacker)",
                         incident.get("id"), ip)
                return False
            return True

        out = set()
        for ag in agents:
            for a in by_agent[ag]:
                # 1) Source IP of a network attack (web, bruteforce...).
                ip = a.get("srcip")
                if ip and _blockable(str(ip)):
                    out.add((ag, str(ip)))
                # 2) C2 IP targeted by a /dev/tcp|/dev/udp reverse shell,
                #    extracted from the command: the auditd execve has no srcip,
                #    so without this a detected reverse shell (100650) stayed
                #    detected but never blocked (measured regression: thousands
                #    of hits, 0 blocks).
                for c2 in _ips_revshell(a):
                    if _blockable(c2):
                        out.add((ag, c2))
        return sorted(out, key=lambda t: (_is_private_ip(t[1]), t[0], t[1]))

    if action == "propose_disable_user":
        # Compromised/created account, disabled ON the machine where it shows
        # up. Protected accounts excluded. A backdoor seen only by a host sensor
        # (no auditd inside the container) has no usable machine here → not
        # disabled automatically (guardrail), left to the analyst.
        # On a Windows host the account is a DOMAIN account: the execution
        # target becomes a DC (ad-disable-account), not the member host.
        out = set()
        for ag in agents:
            al = by_agent[ag]
            machine = ag
            if _agent_windows(ag):
                # Windows: ONLY the accounts CREATED by the attacker are
                # targets. The `srcuser` of a 4624/4634 is the identity that
                # logged in — so the victim, or a system identity. A purple-team
                # exercise pulled `Système`, `SERVICE LOCAL` and
                # `ANONYMOUS LOGON` out of it: three disable orders in AD,
                # refused only by the script. On Linux the srcuser stays usable
                # (it comes from command auditing, not from a logon), so we keep
                # it.
                accounts = set(_created_accounts(al))
                machine = _un_dc()
                if not machine:      # no DC configured: we do not know where to act
                    log.warning("#%s disable_user: Windows host %s but no "
                                "AGENTS_DC — account not disabled (guardrail)",
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
        # Malicious dropped file, quarantined ON the Windows host that carries
        # it. System paths excluded (the script refuses them on its side too).
        out = set()
        for ag in agents:
            if not _agent_windows(ag):
                continue
            # Full paths of the executables dropped outside the system
            # directories (Sysmon), plus the files flagged as IOCs.
            # win-quarantine-file takes the path.
            for p in _win_suspicious_files(by_agent[ag]):
                out.add((ag, p))
            for v, t, _ in _iocs(by_agent[ag]):
                p = _norm_win_path(v)
                if t in ("file", "filename") and ("\\" in p or "/" in p) \
                        and _win_path_outside_system(p):
                    out.add((ag, p))
        return sorted(out)

    if action == "propose_remove_privileged_group":
        # Removal of an attacker account from a privileged group, run on a DC.
        # PROPOSE-ONLY: deliberately broad heuristic (the analyst decides) —
        # the accounts created by the attacker, removed from "Domain Admins".
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


# --- IRIS assets / tasks + persistence --------------------------------------
#
# Remediations do NOT go into the Notes tab any more: every action becomes a
# TASK (Tasks tab) and the concrete targets (host, accounts) become ASSETS
# (Assets tab). The Notes tab stays reserved for the analysis (LLM report).

# Life cycle of a remediation.
#
# Wazuh's active-response channel is fire-and-forget: the API returns as soon as
# the command is queued, and the script's return code never comes back. So there
# is NOT one "executed" status but two distinct moments, and conflating them is
# what produced the worst defect of the purple-team exercise — an IRIS report
# announcing dozens of successful quarantines of System32 binaries on a domain
# controller, when the script had refused every one of them:
#
#   sent           the Wazuh API took the command. That is ALL we know at the
#                  moment of the call. It is not a success.
#   confirmed      the agent returned `ar-result status=applied`: the change
#                  really happened on the host.
#   no_effect      `status=noop`: there was nothing to do (target absent, already
#                  in that state). Neither success nor failure — often the sign
#                  of a badly resolved target, so definitely not "Done".
#   agent_refused  `status=refused`: a guardrail of the script declined. The last
#                  line of defence held, and the soc-agent aimed at something it
#                  should not have: for the analyst to look at.
#   failed         the channel itself failed, or `status=error`.
#
# The move from "sent" to one of the three real states is done by
# `reconcile_ar_results()`, fed by rules 100930-100935.
STATUSES_GONE = ("sent", "confirmed", "no_effect", "agent_refused")

# Remediation status -> IRIS task status.
_STATUS_TASK = {
    "sent": "In progress",     # command sent, effect not confirmed yet
    "confirmed": "Done",
    "no_effect": "On hold",   # nothing to do on this target: worth a look
    "agent_refused": "Canceled",
    "dry_run": "To do",        # simulated: the real action is still to do
    "failed": "Canceled",
    "canceled": "Canceled",
}

# AR status returned by the agent -> remediation status.
_STATUS_AR = {
    "applied": "confirmed",
    "noop": "no_effect",
    "refused": "agent_refused",
    "error": "failed",
}


def _task_desc(triage: dict, target: str, status: str, channel: str,
                details: str, undo: str) -> str:
    """Body (markdown) of the remediation task."""
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
        log.debug("asset list of case #%s: %s", case_id, e)
        return set()


def _set_assets(case, case_id: int, inc: dict, alerts: list[dict]) -> None:
    """Fill in the Assets tab: the affected host and the compromised accounts.

    Best-effort and idempotent (dedup on the name already present). IPs, hashes
    and files stay IOCs (IOC tab, filled by iris.py); here we only put the
    entities we ACT on and that have a proper asset type.
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
            log.debug("asset skipped (%s): %s", name, e)

    # One machine per agent actually affected (host sensors excluded): a
    # campaign incident covers several. Name from the alert, else the id.
    names = {str(a["agent_id"]): (a.get("agent_name") or str(a["agent_id"]))
            for a in alerts if a.get("agent_id")
            and str(a["agent_id"]) not in config.AGENTS_SENSORS}
    if not names:  # no usable endpoint: at least the incident's agent.
        names = {str(inc["agent_id"]): inc.get("agent_name") or str(inc["agent_id"])}
    for name in sorted(set(names.values())):
        add(name, "Linux - Server",
                "Host hit by the incident (isolation / process-kill target).")
    for _ag, account in _targets_by_machine("propose_disable_user", inc, alerts):
        add(account, "Linux Account",
                "Account compromised or created by the attacker (disable target).")


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


# TERMINAL statuses: we know the outcome, so we never replay the action on the
# same (incident, target) pair.
#
# 'agent_refused' is in there: an action the script declined by guardrail would
# be requested again every cycle, and declined again, forever. A refusal is an
# answer, not a transient error. 'canceled' and 'undo_failed' too, because an
# UNDONE action must not come back: an incident keeps gaining alerts
# (needs_refresh), so triage is replayed, so is remediation — the analyst who
# moves the IRIS task to 'Canceled' would see the host re-isolate on the next
# cycle, looping against their decision. A cancellation is an order, not a
# suggestion. Accepted trade-off: if the incident really gets worse after a
# cancellation, nothing restarts by itself. That is the right default (the
# analyst decided knowingly) and it stays fixable by hand: `mitigate --isolate
# <agent>`, or delete the row to reopen the right.
#
# 'failed' is NOT in there: a channel that goes down deserves another try. Nor
# is 'sent' — that means "the command left", not "it had the intended effect".
# An action stuck on 'sent' (no confirming `ar-result`) is retried up to
# MITIGATE_MAX_ATTEMPTS: without that, an attacker account recreated under an
# already-open incident is never disabled (measured at the exercise:
# `art-backdoor` frozen on an inherited 'sent', disable_user never replayed).
# 'confirmed' and 'no_effect', on the other hand, are answers from the agent:
# terminal.
_STATUSES_FROZEN = ("confirmed", "no_effect", "agent_refused",
                  "canceled", "undo_failed")


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
    # unconfirmed 'sent': replayable as long as the cap is not reached.
    if r["status"] == "sent":
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
            print(f"Incident #{incident_id} not found.")
            return []
        triage = conn.execute(SELECT_TRIAGE, (incident_id,)).fetchone()
        if not triage:
            print(f"Incident #{incident_id} not triaged yet.")
            return []

        # Barrier: a verdict rendered on a manipulated context commands nothing.
        if triage["injection_patterns"]:
            print(f"  #{incident_id} SUSPENDED — injection patterns at triage: "
                  f"{', '.join(triage['injection_patterns'])}. No execution.")
            return []

        # Bounded: this query used to pull the 102,869 alerts of incident #2555
        # with their `raw` and got the cycle OOM-killed on every pass
        # (cf. alerts.py).
        alerts = alerts_mod.load_bounded(
            conn, incident_id, alerts_mod.COLUMNS_TARGETING, "remediation")

        remed = [a for a in triage["actions"] if a in REMEDIATIONS]

        # Deterministic guardrail: an account CREATED by the attacker on a true
        # positive must be disabled even if the LLM did not propose the action.
        # Triage only sees HIGH alerts; the account creation comes up from a
        # low-level auditd alert (proctitle, level 3) attached to the incident —
        # visible in the case, but absent from the decision prompt. We add the
        # action here, without ever touching the alert level.
        if (triage["verdict"] == "true_positive"
                and "propose_disable_user" not in remed
                and _created_accounts(alerts)):
            remed.append("propose_disable_user")
            print(f"  #{incident_id} + propose_disable_user (deterministic: "
                  f"account created by the attacker — {', '.join(_created_accounts(alerts))})")

        if not remed:
            print(f"  #{incident_id} no remediation to execute "
                  f"(verdict {triage['verdict']}).")
            return []

        case = _client() if inc["iris_case_id"] else None
        # Assets (Assets tab): host + accounts, once, before the actions.
        if case:
            _set_assets(case, inc["iris_case_id"], inc, alerts)

        mode = "EXECUTION" if config.MITIGATE_EXECUTE else "DRY-RUN"
        print(f"  #{incident_id} {inc['agent_name']} — {mode} — "
              f"{len(remed)} action(s)")

        reason_short = (triage["reason"] or "")[:120]

        for action in sorted(remed, key=lambda a: ORDER_EXEC.index(a)
                             if a in ORDER_EXEC else 99):
            for machine, target in _targets_by_machine(action, inc, alerts):
                # Context rebuilt PER TARGET: every remediation goes to the
                # machine where its evidence was observed, never to a global
                # agent.
                ctx = {"agent_id": machine, "reason_short": reason_short}
                if config.MITIGATE_EXECUTE and _already_executed(
                        conn, incident_id, action, target, machine):
                    print(f"      {action} [{target}@{machine}] already "
                          "executed, skipped.")
                    continue
                try:
                    status, channel, details, undo = EXECUTORS[action](target, ctx)
                except Exception as e:  # noqa: BLE001 — a channel failure must
                    # not stop the other remediations; we trace it.
                    status, channel = "failed", "—"
                    details, undo = f"Échec du canal : {e}", "—"
                    log.warning("failure %s [%s]: %s", action, target, e)

                # Every remediation = one TASK (Tasks tab), not a note. The
                # targeted machine is in the title: a campaign incident carries
                # the same action on several hosts.
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


# --- reconciliation: undo what the analyst moved to 'Canceled' -------------

# IRIS task status that triggers the undo of the remediation.
_TASK_CANCELED = "Canceled"


def _canceled_tasks(tasks: list[dict]) -> set[int]:
    """IDs of the tasks in 'Canceled' status (pure read of an IRIS list_tasks)."""
    return {t["task_id"] for t in (tasks or [])
            if (t.get("status_name") or "") == _TASK_CANCELED}


def _comment_task(case, case_id: int, task_id: int, text: str) -> None:
    """Add a comment to the task (best-effort: never blocks the rest)."""
    try:
        case.add_task_comment(task_id=task_id, comment=text, cid=case_id)
    except Exception as e:  # noqa: BLE001
        log.debug("comment on task %s: %s", task_id, e)


def _update_task_status(case, case_id: int, task_id: int, status: str) -> bool:
    """Change the status of an IRIS task. Returns True if it went through.

    `Case.update_task()` re-reads the task before rewriting it, and that re-read
    uses the cid of the INSTANCE, not the `cid=` of the call: passing only `cid=`
    raises "No case ID provided". The symptom was silent — both callers wrapped
    the failure in a best-effort try/except, so no remediation or whitelist task
    ever changed status: they stayed on 'To do' whatever the real fate of the
    action.

    `set_cid` mutates the instance, so we reposition it on every call rather than
    assume a current cid, the callers looping over several cases.
    """
    try:
        case.set_cid(case_id)
        r = case.update_task(task_id, status=status, cid=case_id)
        if r.is_success():
            return True
        log.warning("task %s update (case %s) refused: %s",
                    task_id, case_id, r.get_msg())
    except Exception as e:  # noqa: BLE001 — best-effort, never blocking
        log.warning("task %s update (case %s): %s", task_id, case_id, e)
    return False


# --- reconciliation: what the agent REALLY did ------------------------------
#
# Active-response script per action, Windows then Linux. This is the join key
# between a `mitigations` row and the `ar-result` alert returned by the agent
# (rules 100931-100934).
_SCRIPTS_AR = {
    "propose_isolate_host":    ("win-host-isolate", "host-isolate"),
    "propose_block_ip":        ("win-block-ip", "firewall-drop"),
    "propose_disable_user":    ("ad-disable-account", "disable-account"),
    "propose_kill_process":    ("win-kill-process", "kill-process"),
    "propose_quarantine_file": ("win-quarantine-file", "quarantine"),
}

# Rules that carry a usable AR report. 100935 (expiry of the execd timeout) is
# at level 0: it produces no alert, so it never gets here — that is intended, a
# no-op `delete` says nothing about the initial action.
_RULES_AR = ("100931", "100932", "100933", "100934")

SELECT_AR_RESULTS = """
SELECT a.ts,
       a.agent_id,
       a.raw#>>'{data,ar_script}' AS ar_script,
       a.raw#>>'{data,ar_status}' AS ar_status,
       a.raw#>>'{data,ar_target}' AS ar_target,
       a.raw#>>'{data,ar_reason}' AS ar_reason
  FROM alerts a
 WHERE a.rule_id = ANY(%(rules)s)
   AND a.ts > now() - interval '24 hours'
 ORDER BY a.ts
"""


def reconcile_ar_results() -> list[dict]:
    """Replace the "sent" status by what the agent really did.

    The Wazuh API is fire-and-forget: at the moment of the call, all we know is
    that the command left. The AR scripts now write an `ar-result` line on every
    exit, the agent ships it up, rules 100931-100934 turn it into alerts; here we
    join them with the `mitigations` table on (agent, script, target) and freeze
    the real status.

    Without this loop, a refusal from the script was invisible: an exercise IRIS
    report announced dozens of successful quarantines of System32 binaries on a
    domain controller, when the script had declined every one of them.

    A remediation that receives NO report at all stays 'sent' — never promoted to
    a success. That is the right default: a script that dies before writing its
    line (PowerShell exception) must not be read as a success.
    """
    results: list[dict] = []
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        lines = conn.execute(SELECT_AR_RESULTS,
                              {"rules": list(_RULES_AR)}).fetchall()
        if not lines:
            return []

        case = None
        for r in lines:
            status = _STATUS_AR.get(r["ar_status"] or "")
            if not status or not r["ar_script"] or r["ar_target"] is None:
                continue
            # Candidate actions: those whose Windows or Linux script carries
            # that name. `host-isolation.sh` is only a dispatcher, the delegated
            # script is the one that signs the report.
            actions = [a for a, scripts in _SCRIPTS_AR.items()
                       if r["ar_script"] in scripts]
            if not actions:
                continue
            timestamp = r["ts"].strftime("%Y-%m-%d %H:%M:%S")
            update = conn.execute("""
                UPDATE mitigations m
                   SET status = %(status)s,
                       details = m.details || %(suffix)s
                 WHERE m.status = 'sent'
                   AND m.agent_id = %(agent)s
                   AND m.action = ANY(%(actions)s)
                   AND m.target = %(target)s
                   AND m.executed_at <= %(ts)s + interval '5 minutes'
             RETURNING m.id, m.incident_id, m.action, m.iris_task_id
            """, {
                "status": status,
                "suffix": (f"\n\nCompte rendu de l'agent ({timestamp} UTC) : "
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
                log.info("#%s %s [%s@%s]: sent -> %s (%s)", m["incident_id"],
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

# Terminal mark of a killed action we cannot undo: avoids re-commenting the
# task on every cycle (it is no longer selected).
_STATUS_IRREVERSIBLE = "undo_failed"

# Advisory lock dedicated to reconciliation. Its timer (1 min) is shorter than
# the cycle's: two passes must not overlap and double-fire a reverse (window
# between the SELECT and the commit of the 'canceled' status).
_LOCK_RECONCILE = 0x50CA2


def reconcile(incident_id: int | None = None) -> list[dict]:
    """Undo the remediations whose IRIS task moved to 'Canceled'.

    The analyst keeps control after the fact: moving a remediation task to
    'Canceled' in IRIS asks the soc-agent to UNDO the action — unisolate the
    host, unblock the IP, re-enable the account. Closed loop: the IRIS task is
    the signal, the `mitigations` table the memory (an action that left — 'sent',
    'confirmed' or 'no_effect' — is to watch; 'canceled' = already undone, not
    picked up again). Killing a process has no reverse: we document it once and
    mark it terminal. An 'agent_refused' action cannot be undone: the script
    declined it, there is nothing to restore.

    Idempotent: an already-cancelled remediation is no longer selected; a failed
    reverse keeps its status and will be retried on the next cycle.
    """
    results: list[dict] = []
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        # One reconcile at a time (its timer is short): otherwise two passes
        # could select and then double-undo the same remediation.
        if not conn.execute("SELECT pg_try_advisory_lock(%s)",
                            (_LOCK_RECONCILE,)).fetchone()["pg_try_advisory_lock"]:
            log.info("reconciliation already running, skipping this round")
            return []
        try:
            # First, what the agents really did: without this, a remediation
            # refused by the script would stay 'sent' and the IRIS report would
            # keep announcing an action that never happened. Same lock: both
            # passes write to `mitigations`.
            try:
                reconcile_ar_results()
            except Exception as e:  # noqa: BLE001 — must not prevent the
                # cancellations asked by the analyst, which take priority.
                log.warning("reconciliation of the AR reports: %s", e)

            rows = conn.execute(SELECT_REVERSIBLES,
                                {"inc": incident_id}).fetchall()
            if not rows:
                return []
            results = _reconcile_rows(conn, rows)
        finally:
            conn.execute("SELECT pg_advisory_unlock(%s)", (_LOCK_RECONCILE,))
    return results


def _case_deleted(conn, case, case_id: int) -> bool:
    """Has the IRIS case disappeared? If so, cut the dead reference.

    A case deleted by hand in IRIS leaves `incidents.iris_case_id` pointing at
    nothing. And IRIS does not answer a clean 404 on a non-existent case: its
    access control crashes with `KeyError: 'permissions'` (no Flask session on an
    API-token call) and returns a 500. So reconcile kept retrying every minute,
    forever — 28,343 error traces in six days in the IRIS logs, drowning
    everything else.

    We cut the reference ONLY if `get_case` fails too: a transient IRIS outage
    must not lose the link to a live case.
    """
    try:
        if case.get_case(case_id).is_success():
            return False
    except Exception:  # noqa: BLE001 — no readable case: see below
        pass
    conn.execute("UPDATE incidents SET iris_case_id = NULL "
                 "WHERE iris_case_id = %s", (case_id,))
    conn.commit()
    log.warning("IRIS case #%s not found (deleted?) — reference cut on the "
                "affected incidents, no more reconciliation on them", case_id)
    return True


def _reconcile_rows(conn, rows: list[dict]) -> list[dict]:
    """Core of the reconciliation, lock already held by the caller."""
    results: list[dict] = []
    case = _client()
    canceled: dict[int, set[int]] = {}   # case_id -> {Canceled task_id}
    for r in rows:
        cid = r["iris_case_id"]
        if cid not in canceled:
            try:
                d = case.list_tasks(cid).get_data() or {}
                canceled[cid] = _canceled_tasks(d.get("tasks"))
            except Exception as e:  # noqa: BLE001 — IRIS down breaks nothing
                canceled[cid] = set()
                if _case_deleted(conn, case, cid):
                    continue
                log.warning("list_tasks case #%s: %s", cid, e)
        if r["iris_task_id"] not in canceled[cid]:
            continue   # task not (yet) cancelled by the analyst

        action, target, task_id = r["action"], r["target"], r["iris_task_id"]
        reverter = REVERTERS.get(action)

        # Irreversible action (kill): document it, mark it terminal, move on.
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
            print(f"      {action} [{target}] cannot be undone (kill)")
            continue

        ctx = {"agent_id": str(r["agent_id"]),
               "reason_short": f"tâche IRIS #{task_id} passée en {_TASK_CANCELED}"}
        try:
            channel = reverter(target, ctx)
        except Exception as e:  # noqa: BLE001 — failed reverse: we keep the
            # current status to retry on the next pass, and trace it.
            log.warning("reverse %s [%s] failed: %s", action, target, e)
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
        results.append({"action": action, "target": target, "status": "canceled"})
        print(f"      {action} [{target}] -> canceled  ({channel})")
    return results


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    ap = argparse.ArgumentParser(description=__doc__)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--incident", type=int,
                   help="run the remediations decided at the triage of this "
                        "incident")
    g.add_argument("--isolate", metavar="AGENT_ID",
                   help="isolate an agent from the network (operator action, "
                        "really executed)")
    g.add_argument("--unisolate", metavar="AGENT_ID",
                   help="lift the isolation of an agent (operator action, "
                        "really executed)")
    g.add_argument("--state", metavar="AGENT_ID",
                   help="read the isolation state of an agent (marker, SSH)")
    g.add_argument("--reconcile", action="store_true",
                   help="undo the remediations whose IRIS task moved to "
                        "'Canceled' (unisolate, unblock, re-enable)")
    ap.add_argument("--reason", default="operator action",
                    help="reason recorded with the manual (un)isolation")
    ap.add_argument("--force", action="store_true",
                    help="isolate despite the \"endpoints only\" guardrail "
                         "(firewall, proxy, DNS, VPN, manager). Only use it "
                         "knowing that the traffic of other machines drops.")
    args = ap.parse_args()

    # --isolate / --unisolate are explicit operator commands: they really run,
    # independently of MITIGATE_EXECUTE (which only bounds the AUTOMATIC
    # execution from a verdict).
    if args.isolate:
        isolate(args.isolate, args.reason, args.force)
    elif args.unisolate:
        unisolate(args.unisolate, args.reason)
    elif args.state:
        _show_state(isolation_state(args.state))
    elif args.reconcile:
        reconcile()
    else:
        run(args.incident)


if __name__ == "__main__":
    main()
