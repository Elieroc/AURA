# Windows / AD active-response scripts

Windows counterparts of the Linux active-response scripts in `../`. Same contract,
same guardrail philosophy (deterministic refusals in the script itself, because the
AR is reachable via the Wazuh API and the MCP server, not only via the soc-agent
Python code).

## Execution model

`wazuh-execd` on Windows launches the `<executable>` from a manager `<command>` block
with a **raw `CreateProcess`**, which only starts a genuine `.exe` — a `.ps1` or `.cmd`
fails with `(1317): Could not launch command`. So each action ships as:

| file | role |
|------|------|
| `<action>.exe` | a copy of the compiled wrapper (`ar-wrapper.cs`) — the registered executable |
| `<action>.ps1` | the actual logic |
| `ar-wrapper.cs` | wrapper source, compiled on the host with `csc.exe` (.NET Framework, always present) |
| `_ar-common.ps1` | shared helpers (stdin parse, logging, protected-account guardrail) |

The `.exe` reads its own name, forwards its stdin to
`powershell -File <action>.ps1`, and returns that script's exit code — so one binary
serves every action and the PowerShell keeps the exact stdin contract.

> **ASCII only.** PowerShell 5.1 reads a BOM-less `.ps1` as the system ANSI codepage;
> a stray em-dash or arrow breaks string parsing and the whole dot-sourced
> `_ar-common.ps1` fails to load (the scripts then silently do nothing). Keep every
> `.ps1` ASCII.

**Contract** (identical to the Linux AR): stdin JSON
`{"command":"add|delete","parameters":{"extra_args":[...]}}`. `add` applies; `delete`
(emitted by execd at timeout) is a no-op for high-impact actions — only the symmetric
reverse script undoes them. Logs go to `active-response\active-responses.log`.

**Registration is required** (not optional): execd only runs a command that is present
in `shared\ar.conf`, which the manager builds from the `<command>` blocks **referenced
by an `<active-response>`**. See `register-commands.xml` — both the `<command>` and the
`<active-response rules_id=999999>` (never auto-fires) blocks are needed, then restart
the manager. Without them the API call is accepted but the script never runs.

## Catalogue

### Group A — local host (runs on the compromised Windows agent)

| action / reverse | technique | notes |
|------------------|-----------|-------|
| `win-host-isolate` / `win-host-unisolate` | C2, ransomware | Windows Firewall block-all except manager+allowlist. **Refuses to isolate a DC.** |
| `win-kill-process` | T1003.001, malware exec | by name or PID; safelist protects lsass/services/wazuh/sysmon. No reverse. |
| `win-quarantine-file` / `win-restore-file` | T1105 | hash + move + deny ACL; refuses system dirs. |
| `win-block-ip` / `win-allow-ip` | T1071/T1041 | firewall block in+out; refuses loopback/gateway. |

### Group B — domain (routed to a DC agent)

| action / reverse | technique | notes |
|------------------|-----------|-------|
| `ad-disable-account` / `ad-enable-account` | T1136.002 | `Disable-ADAccount` + expire. Protected accounts refused. **Auto-eligible.** |
| `ad-remove-group-member` / `ad-add-group-member` | T1098.007 | never empties a group; won't remove Administrator/machine accounts. **Propose-only (manual).** |

## Guardrails (in `_ar-common.ps1`)

- **Protected accounts** never disabled: builtin Administrator/Administrateur, krbtgt,
  Guest, machine accounts (`*$`), SOC service accounts, and any member of Domain /
  Enterprise / Schema Admins or Administrators.
- **Domain actions require a DC** (`Confirm-DomainController`) — a domain object action
  mis-routed to a member host is refused, not applied to a non-existent local account.

## Deployment

`deploy-windows-ar.sh` pushes every file to each agent's
`active-response\bin\` over WinRM and registers the `<command>` blocks on the manager.

```sh
export WINRM_USER='Administrateur' WINRM_PASS='...'      # domain admin
AGENTS='10.0.1.100 10.0.1.49' MANAGER=10.0.1.5 \
    ./deploy-windows-ar.sh
```

Requires `nxc` (NetExec) in PATH. Idempotent: re-running overwrites the scripts and
skips `<command>` blocks already present.
