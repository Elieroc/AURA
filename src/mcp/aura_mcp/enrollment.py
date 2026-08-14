"""Enrolling a machine into AURA: agent, telemetry, remediation.

Deploying a Wazuh agent isn't enough — that's the mistake that left the
fleet half-blind for weeks. A machine is only truly covered if all four
layers are in place:

1. **the agent**, enrolled and connected to the manager;
2. **the telemetry** the rules expect: auditd `execve` on the Linux side,
   process-creation auditing with command line + ScriptBlock + Sysmon on
   the Windows side. Without it, rules 1006xx/1007xx never fire and the SOC
   believes the machine is quiet;
3. **the active response scripts**, without which every remediation fails
   **silently**: the manager forwards it, the API replies 200, and nothing
   happens;
4. **the manager-side declaration** (`ar.conf` generated from the
   `<command>` blocks), without which `execd` refuses the command without
   saying so.

This module invents nothing: it runs the repo's already-proven recipes
(`scripts/install-agent.sh`, `src/wazuh/config/agent/Install-WazuhAgent-Windows.ps1`,
`src/wazuh/active-response/`). The Windows path replays step by step what
`src/wazuh/active-response/windows/deploy-windows-ar.sh` does — whose
tooling (NetExec) can't be installed in this image — going through WinRM
instead.
"""

import base64
import os
import pathlib
import re
import subprocess

# Repo root mounted read-only in the container (see the aura-mcp compose
# service). Enrollment recipes are files from the repo, not strings copied
# here: a divergence between the two would stay invisible until the day a
# remediation silently fails on a machine.
REPO = pathlib.Path(os.environ.get("AURA_DEPOT", "/aura"))
SSH_KEY = os.environ.get("SSH_KEY", "/root/.ssh/wazuh_ops_ed25519")
MANAGER = os.environ.get("WAZUH_MANAGER_IP", "")

AR_WINDOWS = REPO / "src/wazuh/active-response/windows"
AR_LINUX = REPO / "src/wazuh/active-response"
INSTALL_LINUX = REPO / "scripts/install-agent.sh"
INSTALL_WINDOWS = REPO / "src/wazuh/config/agent/Install-WazuhAgent-Windows.ps1"
AUDIT_RULES = REPO / "src/wazuh/config/agent/zz-audit-wazuh.rules"

BIN_AR_WINDOWS = r"C:\Program Files (x86)\ossec-agent\active-response\bin"
CSC = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"

# Generous timeout: installation downloads an MSI or apt packages, and
# Sysmon takes its time. A short timeout would fail an enrollment that would
# otherwise have succeeded, leaving the machine half-configured.
TIMEOUT = int(os.environ.get("AURA_ENROLL_TIMEOUT", "900"))


class EnrollmentError(Exception):
    """Explicit failure, with the output of the offending command."""


# --------------------------------------------------------------------------
# Parameter validation
# --------------------------------------------------------------------------
#
# `_ssh` passes its command as a single argument: it's the REMOTE shell that
# splits it. Everything interpolated into that string — agent name, manager
# address — is therefore code, not data. Same on the Windows side, where the
# same values go into a `run_ps`.
#
# This MCP server's client is an AI agent that reads alerts written by the
# monitored machines, so possibly by an attacker (see the server's
# INSTRUCTIONS, and the safeguards in sanitize.py: three injection payloads
# out of four turn the model's verdict around). A value suggested by alert
# content must not be able to become a command. Everywhere else in AURA,
# action targets are derived by code and never freely chosen; these three
# fields were the exception.
#
# Allowlist, not escaping: we know exactly what a Wazuh agent name, a
# hostname, and a Unix account look like, and everything else is refused.

_RE_AGENT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_RE_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,253}$")
_RE_USER = re.compile(r"^[A-Za-z_][A-Za-z0-9._-]{0,31}$")


def _validate(value: str, pattern: re.Pattern, field: str, example: str) -> str:
    value = str(value or "").strip()
    if not pattern.match(value):
        raise EnrollmentError(
            f"{field} refused: \u00ab {value[:80]} \u00bb. This value is interpolated "
            f"into a command executed as root on the target machine, so it "
            f"is restricted to the strict necessary (example: {example}).")
    return value


# --------------------------------------------------------------------------
# Linux
# --------------------------------------------------------------------------

SSH_OPTIONS = [
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=15",
    # The host isn't known yet on first enrollment. We accept its key on
    # first encounter and pin it afterwards: refusing would block every
    # first deployment, ignoring verification forever would be worse.
    "-o", "StrictHostKeyChecking=accept-new",
]


def _ssh(host: str, user: str, command: str) -> str:
    r = subprocess.run(
        ["ssh", *SSH_OPTIONS, "-i", SSH_KEY, f"{user}@{host}", command],
        capture_output=True, text=True, timeout=TIMEOUT)
    if r.returncode != 0:
        raise EnrollmentError(
            f"ssh {user}@{host}: code {r.returncode}\n"
            f"{r.stderr.strip() or r.stdout.strip()}")
    return r.stdout


def _scp(host: str, user: str, sources: list[pathlib.Path],
         destination: str) -> None:
    r = subprocess.run(
        ["scp", *SSH_OPTIONS, "-i", SSH_KEY, "-r",
         *[str(s) for s in sources], f"{user}@{host}:{destination}"],
        capture_output=True, text=True, timeout=TIMEOUT)
    if r.returncode != 0:
        raise EnrollmentError(f"scp to {host}: {r.stderr.strip()}")


def public_key() -> str:
    """Operations public key, deposited in the agent's `authorized_keys`.

    This is what will give the SOC `wazuh-admin` access on the machine, for
    investigation and forensic collection.
    """
    pub = pathlib.Path(f"{SSH_KEY}.pub")
    if pub.is_file():
        return pub.read_text().strip()
    r = subprocess.run(["ssh-keygen", "-y", "-f", SSH_KEY],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise EnrollmentError(
            f"Unable to derive the public key from {SSH_KEY}: "
            f"{r.stderr.strip()}")
    return r.stdout.strip()


# --------------------------------------------------------------------------
# Asset role and priority (CMDB)
# --------------------------------------------------------------------------

# A Wazuh group name, and an API URL segment: strict allowlist, as
# everywhere else in this module.
_RE_ROLE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")


def _default_priority() -> int:
    from soc_agent import config as soc_config  # noqa: PLC0415
    return soc_config.DEFAULT_PRIORITY


def _group_of_role(role: str) -> str:
    from soc_agent import config as soc_config  # noqa: PLC0415
    return f"{soc_config.CMDB_GROUP_PREFIX}{role}"


def _api(path: str, method: str = "GET", body: dict | None = None) -> dict:
    """Authenticated call to the Wazuh API. Raises on failure, except explicit 4xx."""
    import json  # noqa: PLC0415
    import ssl  # noqa: PLC0415
    import urllib.request  # noqa: PLC0415

    from soc_agent import config as soc_config  # noqa: PLC0415

    ctx = ssl._create_unverified_context()
    base = soc_config.WAZUH_API_URL.rstrip("/")
    creds = base64.b64encode(
        f"{soc_config.WAZUH_API_USER}:"
        f"{soc_config.WAZUH_API_PASSWORD}".encode()).decode()
    auth = urllib.request.Request(
        f"{base}/security/user/authenticate",
        headers={"Authorization": f"Basic {creds}"})
    with urllib.request.urlopen(auth, context=ctx, timeout=20) as r:
        token = json.loads(r.read())["data"]["token"]

    query = urllib.request.Request(
        f"{base}{path}", method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(query, context=ctx, timeout=30) as r:
        return json.loads(r.read() or b"{}")


def _create_group(group: str) -> None:
    """Creates the group if it doesn't exist. An existing group isn't an error."""
    import urllib.error  # noqa: PLC0415
    try:
        _api("/groups", "POST", {"group_id": group})
    except urllib.error.HTTPError as e:
        # 400 "group already exists": the nominal case on a second
        # enrollment of the same role. Any other error propagates.
        if e.code != 400:
            raise EnrollmentError(
                f"creation of group {group} refused by the Wazuh API "
                f"({e.code}): {e.read()[:300]!r}") from e


def _assign_group(agent_id: str, group: str) -> None:
    import urllib.error  # noqa: PLC0415
    try:
        _api(f"/agents/{agent_id}/group/{group}", "PUT")
    except urllib.error.HTTPError as e:
        raise EnrollmentError(
            f"assignment of agent {agent_id} to group {group} refused "
            f"({e.code}): {e.read()[:300]!r}") from e


def declare_role(agent_name: str, role: str | None) -> dict:
    """Places the agent in its `role-…` group and registers it in the CMDB.

    This is where the machine's PRIORITY (P1-P4) gets decided, and therefore
    the order in which its incidents will be analyzed and the severity they
    will carry. The Wazuh group is the source of truth (native inventory,
    survives stack redeployment); the `assets` table is only a queryable
    mirror of it, rebuilt by `soc_agent.assets --sync`.

    Without a declared role, the machine falls back to `DEFAULT_PRIORITY`
    (P4): its incidents come after those of declared assets. This is a
    deliberate choice — what isn't declared doesn't take the place of what
    is — whose downside is real: an important machine never declared is
    treated as a disposable endpoint. Hence the `priority_source = 'default'`
    trace and the `soc_agent.assets --coverage` report, which surfaces that
    debt.
    """
    from soc_agent import assets as soc_assets  # noqa: PLC0415

    state = state_on_manager(agent_name)
    if not state.get("known"):
        return {"step": "role", "ok": False, "role": role,
                "detail": "agent unknown to the manager: role not "
                         "declarable (enrollment did not succeed)"}
    agent_id = state["agent_id"]

    if not role:
        # Register anyway: a known asset without a role is a VISIBLE
        # inventory debt, whereas an asset absent from the table is a blind
        # spot. It will be reviewed at the next --sync regardless.
        soc_assets.set_asset(agent_id, priority=_default_priority(),
                           source="default",
                           notes="enrolled without a declared role")
        return {"step": "role", "ok": True, "role": None,
                "agent_id": agent_id, "priority": _default_priority(),
                "warning":
                    f"no role declared: the machine is treated as "
                    f"P{_default_priority()} (back of the queue). Declare "
                    f"it with aura_asset_set as soon as its purpose is "
                    f"known."}

    from soc_agent import config as soc_config  # noqa: PLC0415
    role = _validate(role.lower(), _RE_ROLE, "role", "dc, web, firewall")
    if role not in soc_config.PRIORITY_ROLES:
        # Checked BEFORE touching the manager: an unknown role has no
        # priority, so creating its group would only give the illusion of a
        # declaration while the machine would stay at P4.
        raise EnrollmentError(
            f"unknown role: \u00ab {role} \u00bb. Known roles: "
            f"{', '.join(sorted(soc_config.PRIORITY_ROLES))}. Add one via "
            f"PRIORITY_ROLES (e.g. PRIORITY_ROLES=\"nas=1\").")
    group = _group_of_role(role)
    _create_group(group)
    _assign_group(agent_id, group)

    # Did the group ACTUALLY take? The API accepts the assignment without
    # complaint for agents that can't belong to a group — the manager itself
    # (000) is one. Without this check, the declaration looked successful
    # and the next resync would silently reset the machine to P4: observed
    # on `wazuh.manager`, classified soc then demoted back at the first
    # `assets --sync`.
    #
    # In that case we fall back to the `operator` source, the only one the
    # sync never overwrites.
    groups = {str(g).lower()
               for g in (state_on_manager(agent_name).get("groups") or [])}
    held = group.lower() in groups
    line = soc_assets.set_asset(agent_id, role=role,
                               source="group" if held else "operator",
                               notes=None if held else
                               f"agent {agent_id}: the manager doesn't "
                               f"accept the group {group}, priority hardcoded")
    return {"step": "role", "ok": True, "role": role, "group": group,
            "agent_id": agent_id, "priority": line["priority"],
            "source": line["priority_source"],
            **({} if held else {
                "warning":
                    f"the manager did not keep the group {group} for "
                    f"agent {agent_id} (the manager's own case): the "
                    f"priority is recorded with source \u00ab operator \u00bb, "
                    f"which the sync doesn't overwrite."}),
            }


def enroll_linux(host: str, agent_name: str | None, user: str,
                  manager: str, role: str | None = None) -> dict:
    """Deploys the agent, auditd, and the active response scripts on a Linux host."""
    host = _validate(host, _RE_HOST, "host", "192.168.10.12 or srv-web.lab")
    user = _validate(user, _RE_USER, "ssh_user", "root")
    manager = _validate(manager, _RE_HOST, "manager", "192.168.10.5")
    agent_name = _validate(agent_name or host, _RE_AGENT_NAME, "agent_name",
                         "srv-web-01")

    for path in (INSTALL_LINUX, AUDIT_RULES, AR_LINUX):
        if not path.exists():
            raise EnrollmentError(
                f"{path} missing from the container — the repo root must "
                f"be mounted at {REPO} (aura-mcp compose service).")

    steps = []
    # We replay the directory tree `install-agent.sh` expects (it resolves
    # its dependencies relative to its own location), rather than patching
    # the script: it stays usable by hand, unchanged.
    _ssh(host, user,
         "rm -rf /tmp/aura-enroll && "
         "mkdir -p /tmp/aura-enroll/scripts "
         "/tmp/aura-enroll/src/wazuh/config/agent "
         "/tmp/aura-enroll/src/wazuh/active-response")
    _scp(host, user, [INSTALL_LINUX], "/tmp/aura-enroll/scripts/")
    _scp(host, user, [AUDIT_RULES],
         "/tmp/aura-enroll/src/wazuh/config/agent/")
    _scp(host, user, sorted(AR_LINUX.glob("*.sh")),
         "/tmp/aura-enroll/src/wazuh/active-response/")
    steps.append({"step": "copy", "ok": True})

    pubkey = public_key()
    name = agent_name or host
    output = _ssh(
        host, user,
        f"chmod +x /tmp/aura-enroll/scripts/install-agent.sh && "
        f"/tmp/aura-enroll/scripts/install-agent.sh "
        f"-m {manager} -n {name} -k '{pubkey}'")
    steps.append({"step": "install-agent.sh", "ok": True, "output": output})

    steps.append(ensure_identity(host, user, name, manager))
    steps.append(declare_role(name, role))
    return {"steps": steps,
            "verification": check_linux(host, user, name)}


def agent_identity(host: str, user: str) -> tuple[str | None, str | None]:
    """(id, name) declared in the machine's `client.keys`, or (None, None)."""
    raw = _ssh(host, user,
                "cat /var/ossec/etc/client.keys 2>/dev/null | head -1").strip()
    if not raw:
        return None, None
    chunks = raw.split()
    return (chunks[0], chunks[1]) if len(chunks) >= 2 else (None, None)


def ensure_identity(host: str, user: str, name: str,
                     manager: str) -> dict:
    """Forces the agent to carry ITS OWN identity on the manager.

    `install-agent.sh` only enrolls at package installation: on a machine
    where the agent is already present, it skips past it. But that's
    exactly where the worst case hides — a **cloned** machine, which
    inherited its template's `client.keys`. Two agents then present the
    same identity: the manager accepts only one, the other loops
    connecting/disconnecting, and everything it observes is lost. Yet from
    the inventory's point of view, it "exists".

    So we compare the locally declared name to the desired name, and
    re-enroll (`agent-auth` against the manager's authd, port 1515) if they
    diverge or if no key is present.
    """
    # Revalidated here and not only by the caller: this function also
    # builds a remote command, and it is callable directly.
    name = _validate(name, _RE_AGENT_NAME, "agent_name", "srv-web-01")
    manager = _validate(manager, _RE_HOST, "manager", "192.168.10.5")

    ident, local_name = agent_identity(host, user)
    if local_name == name:
        return {"step": "identity", "ok": True, "re_enrolled": False,
                "agent_id": ident, "name": local_name}

    detail = ("no enrollment key" if not local_name
              else f"the machine carries the identity \u00ab {local_name} \u00bb "
                   f"(agent {ident}), not \u00ab {name} \u00bb")
    _ssh(host, user,
         f"systemctl stop wazuh-agent; "
         f"/var/ossec/bin/agent-auth -m {manager} -A {name} 2>&1 | tail -3; "
         f"systemctl start wazuh-agent")
    ident, local_name = agent_identity(host, user)
    return {"step": "identity", "ok": local_name == name, "re_enrolled": True,
            "detail": detail, "agent_id": ident, "name": local_name}


def state_on_manager(name: str) -> dict:
    """What the MANAGER says about this agent — the only truth that matters.

    A machine can have an active agent, loaded auditd, and the scripts in
    place while being known to no one: duplicate identity, firewall on
    1514, an enrollment that never succeeded. As long as the manager
    doesn't see it as `active`, it isn't monitored, whatever the machine
    itself says.
    """
    import json
    import urllib.error
    import urllib.parse
    import urllib.request

    from soc_agent import config as soc_config

    ssl_ctx = __import__("ssl")._create_unverified_context()
    base = soc_config.WAZUH_API_URL.rstrip("/")

    def _call(path: str, headers: dict) -> dict:
        query = urllib.request.Request(f"{base}{path}", headers=headers)
        with urllib.request.urlopen(query, context=ssl_ctx,
                                    timeout=20) as response:
            return json.loads(response.read())

    try:
        import base64
        creds = base64.b64encode(
            f"{soc_config.WAZUH_API_USER}:"
            f"{soc_config.WAZUH_API_PASSWORD}".encode()).decode()
        token = _call("/security/user/authenticate",
                       {"Authorization": f"Basic {creds}"})["data"]["token"]
        agents = _call(
            "/agents?name=" + urllib.parse.quote(name),
            {"Authorization": f"Bearer {token}"})["data"]["affected_items"]
    except (urllib.error.URLError, KeyError, ValueError) as e:
        return {"known": None, "error": f"Wazuh API unreachable: {e}"}

    if not agents:
        return {"known": False,
                "consequence": f"The manager knows no agent named \u00ab {name} \u00bb: "
                               f"this machine is not monitored, whatever "
                               f"its local state."}
    a = agents[0]
    return {"known": True, "agent_id": a["id"], "status": a.get("status"),
            "ip": a.get("ip"), "version": a.get("version"),
            "last_contact": a.get("lastKeepAlive"),
            "groups": a.get("group", [])}


def check_linux(host: str, user: str,
                   agent_name: str | None = None) -> dict:
    """Checks against the machine itself, not against the return code.

    `audit_active` is the point that decides everything: as long as
    `auditd` doesn't hold the netlink socket (journald takes it away), no
    execution rule fires — and a REBOOT is required to fix it.
    """
    # Reachable at `aura:read` (aura_agent_health). The commands below are
    # fixed, but the host and account go into an SSH target: they're
    # bounded to what they're supposed to be rather than relying on
    # subprocess not opening a shell.
    host = _validate(host, _RE_HOST, "host", "192.168.10.12 or srv-web.lab")
    user = _validate(user, _RE_USER, "ssh_user", "root")

    commands = {
        "agent_active": "systemctl is-active wazuh-agent",
        "auditd_active": "systemctl is-active auditd",
        "audit_rules": "auditctl -l 2>/dev/null | grep -c execveat || true",
        "audit_active": "auditctl -s 2>/dev/null | awk '/^enabled/{print $2}'",
        "ar_scripts": "ls -1 /var/ossec/active-response/bin/*.sh 2>/dev/null "
                      "| wc -l",
    }
    result: dict = {}
    failures = 0
    for key, command in commands.items():
        try:
            result[key] = _ssh(host, user,
                                 f"{command} 2>/dev/null || true").strip()
        except EnrollmentError as e:
            result[key] = None
            result.setdefault("ssh_error", str(e))
            failures += 1

    # An unreachable host isn't "doing" anything: it isn't measured.
    # Answering that everything is unavailable AND that a reboot is needed
    # would be wrong twice over — the second point would reboot a machine
    # for no reason.
    result["reachable"] = failures < len(commands)
    if not result["reachable"]:
        result["reboot_required"] = None
        result["advice"] = (
            f"No command could be run on {host}. Check that key "
            f"{SSH_KEY} is authorized for user "
            f"\u00ab {user} \u00bb on this host: the MCP container reaches "
            f"machines DIRECTLY, it doesn't go through any jump host.")
        return result

    # `enabled 2` = audit active AND configuration locked: that's the
    # targeted state, not an anomaly (install-agent.sh, for its part, only
    # tests for `= 1` and cries wolf on a perfectly instrumented machine).
    known = result.get("audit_active") in ("0", "1", "2")
    result["reboot_required"] = (
        result.get("audit_active") not in ("1", "2") if known else None)

    # Local identity versus what the manager knows. Without this check, a
    # cloned machine passes for enrolled: agent active, auditd loaded,
    # scripts in place… and not a single alert, because it speaks under
    # another machine's identity.
    ident, local_name = agent_identity(host, user)
    result["local_identity"] = {"agent_id": ident, "name": local_name}
    if agent_name:
        result["manager"] = state_on_manager(agent_name)
        result["monitored"] = bool(
            result["manager"].get("known")
            and result["manager"].get("status") == "active"
            and local_name == agent_name)
    if result["reboot_required"]:
        result["why_reboot"] = (
            "Kernel audit is not active: journald holds the netlink "
            "socket. Until the machine reboots, no execution rule "
            "(1006xx/1007xx) can fire — the machine will look quiet "
            "because it is mute.")
    return result


# --------------------------------------------------------------------------
# Windows
# --------------------------------------------------------------------------

def _winrm(host: str, user: str, password: str, script: str) -> str:
    """Runs PowerShell on the host. Lazy import: WinRM is optional."""
    try:
        import winrm  # noqa: PLC0415
    except ImportError as e:  # pragma: no cover
        raise EnrollmentError(
            "The pywinrm module is missing from the image — Windows "
            "enrollment cannot work.") from e

    session = winrm.Session(f"http://{host}:5985/wsman",
                            auth=(user, password), transport="ntlm")
    r = session.run_ps(script)
    if r.status_code != 0:
        raise EnrollmentError(
            f"WinRM {host}: code {r.status_code}\n"
            f"{r.std_err.decode('utf-8', 'replace')[:2000]}")
    return r.std_out.decode("utf-8", "replace")


def _push_file(host: str, u: str, p: str, source: pathlib.Path,
                     name: str) -> None:
    """Writes a file to the host via WinRM, in base64.

    Same channel as `deploy-windows-ar.sh`: everything goes through WinRM,
    which works even when SMB/445 is filtered. The write is binary — a
    `Set-Content` would re-encode and break the scripts.
    """
    b64 = base64.b64encode(source.read_bytes()).decode()
    _winrm(host, u, p,
           f"[IO.File]::WriteAllBytes('{BIN_AR_WINDOWS}\\{name}', "
           f"[Convert]::FromBase64String('{b64}'))")


def deploy_ar_windows(host: str, user: str, password: str) -> dict:
    """Deploys the Windows/AD active response scripts and their .exe launchers.

    Replays `deploy-windows-ar.sh`. Two pitfalls are handled there and must
    stay handled:

    - `wazuh-execd` launches the executable registered via a raw
      `CreateProcess`, which only starts a real `.exe`: a `.ps1` fails with
      "(1317): Could not launch command". Hence the compiled wrapper,
      copied under each action's name.
    - a stuck wrapper keeps its own `.exe` open: the copy would fail with
      "file in use". So running wrappers are killed first.
    """
    if not AR_WINDOWS.is_dir():
        raise EnrollmentError(f"{AR_WINDOWS} missing from the container.")

    _winrm(host, user, password,
           f"New-Item -ItemType Directory -Force -Path '{BIN_AR_WINDOWS}' "
           f"| Out-Null")

    scripts = [p for p in sorted(AR_WINDOWS.glob("*.ps1"))]
    for ps1 in scripts:
        _push_file(host, user, password, ps1, ps1.name)

    _winrm(host, user, password,
           "Get-CimInstance Win32_Process | Where-Object { "
           "$_.Name -match '^(win-|ad-|ar-wrapper)' } | ForEach-Object { "
           "Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }")

    wrapper = AR_WINDOWS / "ar-wrapper.cs"
    _push_file(host, user, password, wrapper, "ar-wrapper.cs")
    _winrm(host, user, password,
           f"& '{CSC}' /nologo /target:exe "
           f"/out:'{BIN_AR_WINDOWS}\\ar-wrapper.exe' "
           f"'{BIN_AR_WINDOWS}\\ar-wrapper.cs' 2>&1 | Out-Null")

    placed = []
    for ps1 in scripts:
        if ps1.name == "_ar-common.ps1":
            continue
        exe = f"{ps1.stem}.exe"
        _winrm(host, user, password,
               f"Copy-Item '{BIN_AR_WINDOWS}\\ar-wrapper.exe' "
               f"'{BIN_AR_WINDOWS}\\{exe}' -Force")
        placed.append(exe)
    return {"scripts": [p.name for p in scripts], "executables": placed}


def enroll_windows(host: str, agent_name: str | None, user: str,
                    password: str, manager: str,
                    skip_sysmon: bool = False, role: str | None = None) -> dict:
    """Deploys the Windows agent, its full telemetry, then active response."""
    # `options` is concatenated into a PowerShell script executed on the
    # target: same requirement as on the Linux side.
    host = _validate(host, _RE_HOST, "host", "192.168.10.20 or win-dc.lab")
    manager = _validate(manager, _RE_HOST, "manager", "192.168.10.5")
    agent_name = _validate(agent_name or host, _RE_AGENT_NAME, "agent_name",
                         "WIN-DC")

    if not INSTALL_WINDOWS.is_file():
        raise EnrollmentError(f"{INSTALL_WINDOWS} missing from the container.")

    remote = r"C:\Windows\Temp\Install-WazuhAgent-Windows.ps1"
    b64 = base64.b64encode(INSTALL_WINDOWS.read_bytes()).decode()
    _winrm(host, user, password,
           f"[IO.File]::WriteAllBytes('{remote}', "
           f"[Convert]::FromBase64String('{b64}'))")

    name = agent_name or host
    options = f"-Manager {manager} -AgentName {name}"
    if skip_sysmon:
        options += " -SkipSysmon"
    output = _winrm(host, user, password,
                    f"& '{remote}' {options}")

    ar = deploy_ar_windows(host, user, password)
    return {
        "installation": output[-4000:],
        "active_response": ar,
        "role": declare_role(name, role),
        "verification": check_windows(host, user, password),
    }


def check_windows(host: str, user: str, password: str) -> dict:
    """Machine-side check: service, event channels, AR binaries."""
    script = f"""
$svc = (Get-Service WazuhSvc -EA SilentlyContinue).Status
$exe = (Get-ChildItem '{BIN_AR_WINDOWS}\\*.exe' -EA SilentlyContinue).Count
$sys = (Get-Service Sysmon64,Sysmon -EA SilentlyContinue | Select -First 1).Status
$cmd = (auditpol /get /subcategory:"{{0CCE922B-69AE-11D9-BED3-505054503030}}" 2>$null | Out-String)
"agent=$svc;ar_exe=$exe;sysmon=$sys;audit_process=$($cmd -match 'Succ')"
"""
    raw = _winrm(host, user, password, script).strip()
    result = {}
    for chunk in raw.split(";"):
        if "=" in chunk:
            key, value = chunk.split("=", 1)
            result[key] = value
    result["raw"] = raw
    return result
