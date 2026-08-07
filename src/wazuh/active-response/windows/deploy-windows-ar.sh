#!/usr/bin/env bash
# Deploy the Aura-SOC Windows/AD active-response scripts to Wazuh agents over WinRM.
#
#   export WINRM_USER='Administrateur' WINRM_PASS='...'
#   AGENTS='10.0.1.100 10.0.1.49' MANAGER=10.0.1.5 ./deploy-windows-ar.sh
#
# For each action it pushes <action>.ps1 (the logic) plus <action>.exe — a copy of
# a tiny compiled wrapper (ar-wrapper.cs). wazuh-execd on Windows launches the
# registered executable with a raw CreateProcess, which only starts a real .exe
# (a .ps1 fails with "(1317): Could not launch command"). The .exe forwards its
# stdin to `powershell -File <action>.ps1`, preserving the AR stdin contract.
#
# Scripts MUST stay ASCII-only: PowerShell 5.1 reads a BOM-less .ps1 as the system
# ANSI codepage, and a stray em-dash/arrow breaks string parsing so the whole
# dot-sourced _ar-common.ps1 fails to load.
#
# Requires nxc (NetExec) in PATH. Works even when SMB/445 is filtered (everything
# is streamed as base64 through WinRM).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
AGENTS="${AGENTS:?set AGENTS='ip1 ip2'}"
WINRM_USER="${WINRM_USER:?set WINRM_USER}"
WINRM_PASS="${WINRM_PASS:?set WINRM_PASS}"
BIN='C:\Program Files (x86)\ossec-agent\active-response\bin'
CSC='C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'

winrm() { nxc winrm "$1" -u "$WINRM_USER" -p "$WINRM_PASS" "${@:2}"; }

push_file() {   # ip localfile remotename
    local ip="$1" f="$2" name="$3"
    local b64; b64="$(base64 -w0 "$f")"
    winrm "$ip" -X "[IO.File]::WriteAllBytes(\"$BIN\\$name\",[Convert]::FromBase64String('$b64'))" >/dev/null
}

for ip in $AGENTS; do
    echo "== $ip =="
    winrm "$ip" -X "New-Item -ItemType Directory -Force -Path \"$BIN\" | Out-Null" >/dev/null

    # 1. logic scripts (ASCII-only) + shared lib
    push_file "$ip" "$HERE/_ar-common.ps1" "_ar-common.ps1"
    for ps1 in "$HERE"/*.ps1; do
        base="$(basename "$ps1")"; [ "$base" = "_ar-common.ps1" ] && continue
        push_file "$ip" "$ps1" "$base"
    done

    # 2. compile the wrapper once, copy to <action>.exe for every logic script
    #
    # Kill any wrapper still running first. A wrapper that is stuck holds its
    # own .exe open, so the copy below fails with "file in use" — and a stuck
    # wrapper is exactly what an out-of-date binary produces (see the stdin
    # contract in ar-wrapper.cs: reading to EOF deadlocks against execd and
    # freezes the agent's whole active-response thread).
    winrm "$ip" -X "Get-CimInstance Win32_Process | Where-Object { \$_.Name -match '^(win-|ad-|ar-wrapper)' } | ForEach-Object { Stop-Process -Id \$_.ProcessId -Force -EA SilentlyContinue }" >/dev/null
    push_file "$ip" "$HERE/ar-wrapper.cs" "ar-wrapper.cs"
    winrm "$ip" -X "& '$CSC' /nologo /target:exe /out:\"$BIN\\ar-wrapper.exe\" \"$BIN\\ar-wrapper.cs\" 2>&1 | Out-Null" >/dev/null
    for ps1 in "$HERE"/*.ps1; do
        base="$(basename "$ps1")"; [ "$base" = "_ar-common.ps1" ] && continue
        exe="${base%.ps1}.exe"
        winrm "$ip" -X "Copy-Item \"$BIN\\ar-wrapper.exe\" \"$BIN\\$exe\" -Force" >/dev/null
        echo "  $exe + $base"
    done
done

echo
echo "Now declare the <command>/<active-response> blocks on the manager ($MANAGER):"
echo "  ssh root@$MANAGER 'cd /opt/AURA && python3 scripts/patch-manager-ar-windows.py'"
echo "then copy the config into the container and restart it. Without those"
echo "blocks the agent's execd silently ignores every Windows AR: the API still"
echo "answers 200, and nothing whatsoever runs on the host."
echo
echo "Verify end to end — never trust the API's 200 nor the mitigations table:"
echo "  1. fire a harmless AR   (!win-kill-process.exe on a name that is not running)"
echo "  2. the agent's active-response\\active-responses.log must gain an"
echo "     'ar-result: ... status=noop' line WITHIN SECONDS, with no service restart"
echo "  3. the manager must raise rule 100934 carrying ar_script/ar_status/ar_target"
echo "A line that only appears after a 'Restart-Service WazuhSvc' means the"
echo "wrapper is deadlocked on stdin — an out-of-date ar-wrapper.exe."
