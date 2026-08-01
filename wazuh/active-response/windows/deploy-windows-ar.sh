#!/usr/bin/env bash
# Deploy the SOC-AI Windows/AD active-response scripts to Wazuh agents over WinRM.
#
#   export WINRM_USER='Administrateur' WINRM_PASS='...'
#   AGENTS='192.168.30.100 192.168.30.49' MANAGER=192.168.10.5 ./deploy-windows-ar.sh
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
    push_file "$ip" "$HERE/ar-wrapper.cs" "ar-wrapper.cs"
    winrm "$ip" -X "& '$CSC' /nologo /target:exe /out:\"$BIN\\ar-wrapper.exe\" \"$BIN\\ar-wrapper.cs\" 2>&1 | Out-Null" >/dev/null
    for ps1 in "$HERE"/*.ps1; do
        base="$(basename "$ps1")"; [ "$base" = "_ar-common.ps1" ] && continue
        exe="${base%.ps1}.exe"
        winrm "$ip" -X "Copy-Item \"$BIN\\ar-wrapper.exe\" \"$BIN\\$exe\" -Force" >/dev/null
        echo "  $exe + $base"
    done
done

echo "Now register the <command>/<active-response> blocks on the manager ($MANAGER)"
echo "from register-commands.xml (executables are the .exe), then restart the manager."
