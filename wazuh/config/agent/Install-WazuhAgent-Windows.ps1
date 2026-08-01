#Requires -Version 5.1
<#
.SYNOPSIS
    Deploys a Wazuh agent on a Windows host (DC or member) with the full SOC-AI
    telemetry stack: process-creation auditing with command line, AD-relevant audit
    subcategories, PowerShell ScriptBlock logging, and Sysmon — all shipped to the
    Wazuh manager. Run once on any new host and it emits every event the detection
    rules expect.

.DESCRIPTION
    Idempotent. Safe to re-run: existing pieces are detected and skipped or updated
    (Sysmon config is refreshed with -c, ossec.conf channels are inserted only once).

    Steps:
      1. Install the Wazuh agent MSI (auto-enroll via authd) if not present.
      2. Enable audit policy (locale-independent, by subcategory GUID):
         Process Creation, Logon, Account/Group/Computer Management, Credential
         Validation, and — on a DC — Directory Service Access/Changes + Kerberos.
      3. Enable command line in 4688 events.
      4. Enable PowerShell ScriptBlock logging (4104).
      5. Install Sysmon with the SwiftOnSecurity config.
      6. Subscribe the Wazuh agent to the Sysmon and PowerShell Operational channels.
      7. Restart the agent and print a verification summary.

    NO active-response / remediation scripts are deployed — telemetry only.

.PARAMETER Manager
    Wazuh manager IP/host (registration + reporting). Default 192.168.10.5.

.PARAMETER AgentName
    Name registered on the manager. Default = computer name.

.PARAMETER WazuhVersion
    Agent MSI version to install. Default 4.9.2 (match the manager).

.PARAMETER SysmonConfigPath
    Local path to a Sysmon config XML. If omitted, the SwiftOnSecurity config is
    downloaded from GitHub (host needs internet). Use this for offline/air-gapped DCs.

.PARAMETER SkipSysmon
    Skip the Sysmon install (audit + 4104 + agent only).

.EXAMPLE
    # On the new host, elevated PowerShell:
    .\Install-WazuhAgent-Windows.ps1 -Manager 192.168.10.5 -AgentName newdc

.EXAMPLE
    # Offline DC with a vendored config:
    .\Install-WazuhAgent-Windows.ps1 -SysmonConfigPath C:\temp\sysmonconfig.xml

.NOTES
    Remote push (no console) via NetExec/WinRM from the SOC box, e.g.:
      nxc winrm <ip> -u <admin> -p <pw> --put-file Install-WazuhAgent-Windows.ps1 \
          'C:\Windows\Temp\inst.ps1'
      nxc winrm <ip> -u <admin> -p <pw> -X 'powershell -ep bypass -f C:\Windows\Temp\inst.ps1 -AgentName newdc'
#>
[CmdletBinding()]
param(
    [string]$Manager          = '192.168.10.5',
    [string]$AgentName        = $env:COMPUTERNAME,
    [string]$WazuhVersion     = '4.9.2',
    [string]$SysmonConfigUrl  = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml',
    [string]$SysmonConfigPath,
    [switch]$SkipSysmon
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
$tmp      = $env:TEMP
$ossecDir = "${env:ProgramFiles(x86)}\ossec-agent"
$ossecCfg = Join-Path $ossecDir 'ossec.conf'
$report   = [ordered]@{}

function Write-Step($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green }
function Write-Warn2($m){ Write-Host "[!] $m" -ForegroundColor Yellow }

# Elevation check
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
          ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) { throw 'Must run elevated (Administrator).' }

# Is this a domain controller? (drives whether DS/Kerberos auditing is relevant)
$isDC = $false
try {
    $isDC = ((Get-CimInstance Win32_OperatingSystem).ProductType -eq 2)  # 2 = domain controller
} catch { }

# ---------------------------------------------------------------------------
# 1. Wazuh agent
# ---------------------------------------------------------------------------
Write-Step "Wazuh agent (target manager $Manager, name $AgentName)"
if (Get-Service WazuhSvc -ErrorAction SilentlyContinue) {
    Write-Ok 'Agent already installed — skipping MSI.'
    $report['agent'] = 'already installed'
} else {
    $msi = Join-Path $tmp "wazuh-agent-$WazuhVersion.msi"
    $url = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WazuhVersion-1.msi"
    Write-Step "Downloading $url"
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $msi
    Write-Step 'Installing MSI (silent, auto-enroll)'
    $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @(
        '/i', $msi, '/qn', '/norestart',
        "WAZUH_MANAGER=$Manager",
        "WAZUH_REGISTRATION_SERVER=$Manager",
        "WAZUH_AGENT_NAME=$AgentName"
    )
    if ($p.ExitCode -ne 0) { throw "msiexec failed with exit code $($p.ExitCode)" }
    Start-Sleep 3
    Start-Service WazuhSvc -ErrorAction SilentlyContinue
    Write-Ok 'Agent installed.'
    $report['agent'] = 'installed'
}

# ---------------------------------------------------------------------------
# 2. Audit policy (by subcategory GUID = locale independent)
# ---------------------------------------------------------------------------
Write-Step 'Audit policy'
# guid => success/failure flags
$audit = [ordered]@{
    '{0CCE922B-69AE-11D9-BED3-505054503030}' = 'success'         # Process Creation (4688)
    '{0CCE9215-69AE-11D9-BED3-505054503030}' = 'success,failure' # Logon (4624/4625)
    '{0CCE9235-69AE-11D9-BED3-505054503030}' = 'success,failure' # User Account Mgmt (4720..)
    '{0CCE9236-69AE-11D9-BED3-505054503030}' = 'success'         # Computer Account Mgmt (4741)
    '{0CCE9237-69AE-11D9-BED3-505054503030}' = 'success'         # Security Group Mgmt (4728/4732)
    '{0CCE923F-69AE-11D9-BED3-505054503030}' = 'success,failure' # Credential Validation (4776)
}
if ($isDC) {
    $audit['{0CCE923B-69AE-11D9-BED3-505054503030}'] = 'success'         # DS Access (4662 - DCSync)
    $audit['{0CCE923C-69AE-11D9-BED3-505054503030}'] = 'success'         # DS Changes
    $audit['{0CCE9240-69AE-11D9-BED3-505054503030}'] = 'success,failure' # Kerberos Service Ticket (4769)
    $audit['{0CCE9242-69AE-11D9-BED3-505054503030}'] = 'success,failure' # Kerberos Auth (4768)
}
foreach ($guid in $audit.Keys) {
    $flags = $audit[$guid]
    $s = if ($flags -match 'success') { 'enable' } else { 'disable' }
    $f = if ($flags -match 'failure') { 'enable' } else { 'disable' }
    & auditpol.exe /set /subcategory:"$guid" /success:$s /failure:$f | Out-Null
}
Write-Ok ("Audit policy set ({0} subcategories, DC={1})." -f $audit.Count, $isDC)
$report['audit'] = "$($audit.Count) subcategories (DC=$isDC)"

# 3. Command line in 4688
$auditKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
New-Item -Path $auditKey -Force | Out-Null
Set-ItemProperty -Path $auditKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord
Write-Ok 'Command line included in 4688.'
$report['cmdline_4688'] = 'enabled'

# 4. PowerShell ScriptBlock logging (4104)
$psKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $psKey -Force | Out-Null
Set-ItemProperty -Path $psKey -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord
Write-Ok 'PowerShell ScriptBlock logging (4104) enabled.'
$report['scriptblock_4104'] = 'enabled'

# ---------------------------------------------------------------------------
# 5. Sysmon
# ---------------------------------------------------------------------------
if ($SkipSysmon) {
    Write-Warn2 'Sysmon skipped (-SkipSysmon).'
    $report['sysmon'] = 'skipped'
} else {
    Write-Step 'Sysmon'
    $smDir = Join-Path $tmp 'Sysmon'
    $smExe = Join-Path $smDir 'Sysmon64.exe'
    $smCfg = Join-Path $smDir 'sysmonconfig.xml'
    if (-not (Test-Path $smExe)) {
        $zip = Join-Path $tmp 'Sysmon.zip'
        Invoke-WebRequest -UseBasicParsing -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $zip
        if (Test-Path $smDir) { Remove-Item $smDir -Recurse -Force }
        Add-Type -AssemblyName System.IO.Compression.FileSystem  # Expand-Archive is unreliable over WinRM
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $smDir)
    }
    if ($SysmonConfigPath) {
        Copy-Item $SysmonConfigPath $smCfg -Force
        Write-Ok "Using local Sysmon config: $SysmonConfigPath"
    } else {
        Invoke-WebRequest -UseBasicParsing -Uri $SysmonConfigUrl -OutFile $smCfg
        Write-Ok 'Downloaded SwiftOnSecurity Sysmon config.'
    }
    # Sysmon prints its banner to stderr; with ErrorActionPreference=Stop a bare
    # `& $smExe` would surface that as a terminating NativeCommandError. Start-Process
    # isolates the native exit code instead.
    $log    = Join-Path $tmp 'sysmon-install.log'
    $logErr = "$log.err"
    if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
        $sp = Start-Process $smExe -Wait -PassThru -WindowStyle Hidden `
              -ArgumentList '-c', $smCfg -RedirectStandardOutput $log -RedirectStandardError $logErr
        if ($sp.ExitCode -ne 0) { throw "Sysmon config refresh failed (exit $($sp.ExitCode)); see $log" }
        Write-Ok 'Sysmon present — config refreshed.'
        $report['sysmon'] = 'config updated'
    } else {
        $sp = Start-Process $smExe -Wait -PassThru -WindowStyle Hidden `
              -ArgumentList '-accepteula', '-i', $smCfg -RedirectStandardOutput $log -RedirectStandardError $logErr
        if ($sp.ExitCode -ne 0) { throw "Sysmon install failed (exit $($sp.ExitCode)); see $log" }
        Start-Sleep 3
        Write-Ok 'Sysmon installed.'
        $report['sysmon'] = 'installed'
    }
}

# ---------------------------------------------------------------------------
# 6. Wazuh agent channels (Sysmon + PowerShell Operational)
# ---------------------------------------------------------------------------
Write-Step 'Wazuh log channels'
$channels = @(
    'Microsoft-Windows-Sysmon/Operational',
    'Microsoft-Windows-PowerShell/Operational'
)
$c = Get-Content $ossecCfg -Raw
$added = @()
foreach ($ch in $channels) {
    if ($SkipSysmon -and $ch -like '*Sysmon*') { continue }
    if ($c -notmatch [regex]::Escape($ch)) {
        $block = "  <localfile>`r`n    <location>$ch</location>`r`n    <log_format>eventchannel</log_format>`r`n  </localfile>`r`n</ossec_config>"
        $c = $c -replace '</ossec_config>', $block
        $added += $ch
    }
}
if ($added.Count) {
    Set-Content -Path $ossecCfg -Value $c -Encoding UTF8
    Write-Ok ("Added channels: {0}" -f ($added -join ', '))
    $report['channels'] = ($added -join ', ')
} else {
    Write-Ok 'Channels already present.'
    $report['channels'] = 'already present'
}

# ---------------------------------------------------------------------------
# 7. Restart + summary
# ---------------------------------------------------------------------------
Write-Step 'Restarting WazuhSvc'
Restart-Service WazuhSvc
Start-Sleep 3
$report['wazuh_service'] = (Get-Service WazuhSvc).Status

Write-Host ''
Write-Host '================ SOC-AI telemetry install summary ================' -ForegroundColor Magenta
$report.GetEnumerator() | ForEach-Object { '{0,-18}: {1}' -f $_.Key, $_.Value } | Write-Host
Write-Host '=================================================================' -ForegroundColor Magenta
Write-Host "Verify on the manager: /var/ossec/bin/agent_control -l  (expect '$AgentName' Active)"
