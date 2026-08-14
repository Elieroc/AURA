"""Enrollment tools: putting a machine under AURA surveillance.

`aura:admin`: installing an agent durably modifies the target machine
(packages, audit policy, admin account, root execution delegated to the
manager via the active response channel).

The point that matters more than the installation itself: **verification**.
An "installed" agent that emits no `execve`, or whose active response
scripts are missing, produces exactly the same thing as a healthy machine —
nothing. That's why every enrollment ends with a check read from the
machine, and the tool states plainly what isn't good yet.
"""

from soc_agent import config as soc_config

from .. import auth, enrollment, output
from ..server import register


@auth.require("aura:admin")
def aura_enroll_agent(
    host: str,
    system: str,
    agent_name: str | None = None,
    manager: str | None = None,
    ssh_user: str = "root",
    winrm_user: str | None = None,
    winrm_password: str | None = None,
    skip_sysmon: bool = False,
    role: str | None = None,
    confirm: bool = False,
) -> dict:
    """Installs a full Wazuh agent on a machine. MODIFIES THE MACHINE.

    Lays down the four layers without which coverage is illusory: the
    agent, the telemetry the rules expect, the active response scripts, and
    the SOC's administration access.

    **Linux** (Debian/Ubuntu, SSH key access): pinned Wazuh agent, auditd
    with AURA's `execve` rule set, `/etc/ld.so.preload` created to make it
    monitorable, active response scripts, `wazuh-admin` account with
    passwordless sudo reachable via the SOC's key.

    **Windows** (WinRM): agent, process-creation auditing WITH command
    line, AD audit subcategories, PowerShell ScriptBlock logging, Sysmon,
    agent subscription to the channels — then the Windows/AD active
    response scripts and their compiled `.exe` launchers.

    After a Linux enrollment, a REBOOT is almost always required: as long as
    journald holds the netlink socket, auditd emits nothing and the machine
    looks quiet while it's actually mute. The verification flags it.

    On the Windows side, one step remains on the MANAGER: declaring the
    `<command>`/`<active-response>` blocks (`aura_manager_ar_status` checks
    it). Without them, `execd` refuses every action silently, the API
    replying 200.

    Args:
        host: IP address or name of the machine to enroll.
        system: `linux` or `windows`.
        agent_name: name registered on the manager (default: the host).
        manager: Wazuh manager address (default: `WAZUH_MANAGER_IP`).
        ssh_user: SSH account for a Linux enrollment — must be root or able
            to become root.
        winrm_user: Windows administrator account.
        winrm_password: associated password.
        skip_sysmon: Windows only — skip the Sysmon install (host without
            internet access).
        role: the machine's role, which sets its PRIORITY (P1-P4) in the
            SOC: `dc`, `firewall`, `soc`, `hypervisor`, `pki`, `backup`
            (P1); `web`, `db`, `mail`, `proxy`, `dns`, `vpn`, `fileserver`
            (P2); `server`, `admin` (P3); `endpoint`, `lab` (P4). The agent
            is placed in the Wazuh group `role-<role>`, which is the source
            of truth. **Without a role, the machine is treated as P4** — its
            incidents go to the back of the queue and its severity is
            lowered by one level. Declare it even approximately: a debatable
            role beats an invisible critical asset.
        confirm: must be `true` to act. At `false` (default), the tool
            returns the plan without touching anything.
    """
    system = system.lower().strip()
    if system not in ("linux", "windows"):
        return {"error": "system must be 'linux' or 'windows'."}

    manager = manager or enrollment.MANAGER
    if not manager:
        return {"error": "Unknown manager address: pass `manager` or set "
                          "WAZUH_MANAGER_IP in the .env."}
    if system == "windows" and not (winrm_user and winrm_password):
        return {"error": "winrm_user and winrm_password are required for "
                          "Windows."}

    plan = _plan(system, host, agent_name or host, manager, skip_sysmon, role)
    if not confirm:
        return {"execute": False, "plan": plan,
                "reason": "confirm=false — the machine was not touched."}

    try:
        if system == "linux":
            result = enrollment.enroll_linux(host, agent_name, ssh_user,
                                                manager, role)
        else:
            result = enrollment.enroll_windows(
                host, agent_name, winrm_user, winrm_password, manager,
                skip_sysmon, role)
    except enrollment.EnrollmentError as e:
        # An enrollment can fail halfway through. Saying so with the
        # offending step is better than a stack trace: the machine may be
        # half-configured, and that's operational information.
        return {"execute": True, "success": False, "error": str(e),
                "warning": "The machine may be partially configured. "
                                 "Re-running the tool is safe: the recipes "
                                 "are idempotent."}

    return {"execute": True, "success": True, "system": system,
            "host": host, "manager": manager,
            **output.jsonifiable(result),
            "next_steps": _next_steps(system)}


def _plan(system: str, host: str, name: str, manager: str,
          skip_sysmon: bool, role: str | None = None) -> list[str]:
    ranking = (
        f"Place the agent in the role-{role} group and register it in the CMDB."
        if role else
        f"NO role declared: the machine will be treated as "
        f"P{soc_config.DEFAULT_PRIORITY} (back of the analysis queue, "
        f"lowered severity). Pass `role` to classify it.")
    if system == "linux":
        return [
            f"Copy AURA's recipes to {host} (SSH key).",
            f"Install the Wazuh agent, enrolled on {manager} under the name {name}.",
            "Install auditd and AURA's execve rule set "
            "(zz- prefix mandatory, otherwise Debian's -D clears them).",
            "Create /etc/ld.so.preload if missing, to make it monitorable.",
            "Deploy the active response scripts.",
            "Create the wazuh-admin account (passwordless sudo, SSH key).",
            ranking,
            "Verify on the machine, and flag whether a reboot is required.",
        ]
    return [
        f"Push the installation recipe to {host} (WinRM).",
        f"Install the Wazuh agent, enrolled on {manager} under the name {name}.",
        "Enable process-creation auditing WITH command line, the AD "
        "subcategories, and ScriptBlock logging.",
        "Install Sysmon." if not skip_sysmon else "Skip Sysmon (requested).",
        "Subscribe the agent to the Sysmon and PowerShell Operational channels.",
        "Push the Windows/AD active response scripts, compile the "
        "wrapper, and copy it under each action's name.",
        ranking,
        "Verify on the machine.",
    ]


def _next_steps(system: str) -> list[str]:
    common = [
        "Check that the agent reports in: aura_alerts_search on its name.",
        "Trigger a harmless action and check the outcome "
        "(aura_ar_reconcile) — never trust the API's 200.",
    ]
    if system == "linux":
        return ["REBOOT the machine if the verification asks for it: "
                "otherwise auditd emits nothing and the machine will look "
                "quiet.",
                *common]
    return ["Declare the Windows <command>/<active-response> blocks on the "
            "manager (aura_manager_ar_status checks it): without them execd "
            "silently refuses every action.",
            *common]


@auth.require("aura:read")
def aura_agent_health(host: str, system: str, agent_name: str | None = None,
                      ssh_user: str = "root",
                      winrm_user: str | None = None,
                      winrm_password: str | None = None) -> dict:
    """Is this machine actually covered? Check the evidence.

    Changes nothing. Answers the question a dashboard can't ask: the agent
    is green, but **is it emitting**? An agent that's connected but whose
    kernel audit is cut off, or whose active response scripts are missing,
    is indistinguishable from a healthy machine — until the day it's asked
    to do something.

    Two points decide, and neither can be read off a dashboard:

    - `monitored`: does the manager see this agent as `active` AND does the
      machine carry ITS OWN identity? A cloned machine inherits its
      template's `client.keys`, presents an already-taken identity, and
      loops connecting/disconnecting — all while looking perfectly
      installed.
    - `reboot_required`: as long as journald holds the netlink socket,
      auditd emits nothing.

    Args:
        host: machine address.
        system: `linux` or `windows`.
        agent_name: name expected on the manager side. Without it, the
            check stays local and can't say whether the machine is actually
            monitored.
        ssh_user: SSH account (Linux).
        winrm_user: administrator account (Windows).
        winrm_password: associated password (Windows).
    """
    system = system.lower().strip()
    try:
        if system == "linux":
            state = enrollment.check_linux(host, ssh_user, agent_name)
        elif system == "windows":
            if not (winrm_user and winrm_password):
                return {"error": "winrm_user and winrm_password required."}
            state = enrollment.check_windows(host, winrm_user,
                                               winrm_password)
        else:
            return {"error": "system must be 'linux' or 'windows'."}
    except enrollment.EnrollmentError as e:
        return {"host": host, "reachable": False, "error": str(e)}
    # `reachable` comes from the check itself: on the Linux side, each check
    # is a separate remote command that can fail on its own.
    return {"host": host, "system": system, "reachable": True, **state}


@auth.require("aura:read")
def aura_manager_ar_status() -> dict:
    """Are the remediation actions declared manager-side complete?

    `execd` validates every requested action against the `ar.conf` the
    manager generates from its `<command>` blocks. A missing action is
    refused **without a message**: the API replies 200 and nothing happens
    on the machine. This is AURA's costliest failure mode, because it looks
    like a success.

    This tool compares the actions expected by the pipeline against what the
    manager actually declares.
    """
    import re

    conf = enrollment.REPO / "src/wazuh/config/wazuh_cluster/wazuh_manager.conf"
    if not conf.is_file():
        return {"error": f"{conf} unreadable from the container — the repo "
                          f"root must be mounted at {enrollment.REPO}."}
    text = conf.read_text(encoding="utf-8", errors="replace")
    declared = set(re.findall(r"<command>\s*<name>([^<]+)</name>", text))
    declared |= set(re.findall(r"<name>([^<]+)</name>\s*<executable>", text))
    referenced = set(re.findall(
        r"<active-response>.*?<command>([^<]+)</command>", text, re.S))

    expected = set(soc_config.__dict__.get("AR_EXPECTED", ())) or {
        "firewall-drop", "firewall-allow", "host-deny", "host-allow",
        "disable-account", "enable-account", "host-isolate", "host-unisolate",
        "kill-process", "quarantine", "win-host-isolate", "win-host-unisolate",
        "win-kill-process", "win-quarantine-file", "win-restore-file",
        "win-block-ip", "win-allow-ip", "ad-disable-account",
        "ad-enable-account", "ad-remove-group-member", "ad-add-group-member",
    }

    return {
        "declared": sorted(declared),
        "referenced_by_an_active_response": sorted(referenced),
        "missing": sorted(expected - declared),
        "declared_but_not_referenced": sorted(declared - referenced),
        "reminder": "An action that is declared but never referenced by an "
                  "<active-response> block is refused by execd, even when "
                  "called via the API. The rules_id 999999 trick (a "
                  "nonexistent rule) exists exactly for this: reference "
                  "without ever triggering.",
    }


register(aura_enroll_agent)
register(aura_agent_health)
register(aura_manager_ar_status)
