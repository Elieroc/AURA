<#
    T1003.001 / malware execution - kill a malicious process on this host.
    Windows analog of kill-process.sh.

    extra_args = ["<pid>", "<expected-image>"]   preferred, precise
                 ["<name-or-pid>"]               legacy, name kills every instance

    add -> stop the process ; delete -> no-op (there is no "unkill").

    Two safelists, both enforced here because the AR is also reachable through
    the Wazuh API and the MCP server, which never go through the soc-agent:
      $critical - never killed, whatever the caller asks.
      $generic  - shared host processes (powershell, cmd, net, wsmprovhost...).
                  Killing those BY NAME stops every instance on the machine.
                  The purple-team campaign of 2026-08-02 did exactly that on a
                  domain controller: all admin PowerShell and all WinRM sessions
                  died. They are now killable only by PID, and only when the
                  caller states which image that PID is expected to carry.
#>
. "$PSScriptRoot\_ar-common.ps1"
$in     = Read-ARInput
$target = ($in.Args | Select-Object -First 1)
$expect = ($in.Args | Select-Object -Skip 1 -First 1)

$S = 'win-kill-process'
# The soc-agent stores this action under the target "<image>#<pid>" and matches
# the outcome back on that exact string (soc_agent.mitigate, table mitigations).
# We are called with the pid and the image as two separate arguments, so we
# rebuild that form for reporting. Reporting the bare pid instead would leave
# every kill stuck at status 'emis' forever, which is the reporting bug this
# whole result channel exists to fix.
$reported = if ($expect) { "$expect#$target" } else { $target }
if ($in.Command -eq 'delete') { Write-ARLog $S 'delete: no-op (no unkill)'; Write-ARResult $S 'noop' $reported 'delete command'; exit 0 }
if ($in.Command -ne 'add')    { Write-ARLog $S "invalid command '$($in.Command)'"; Write-ARResult $S 'error' $reported 'invalid command'; exit 1 }
if (-not $target)             { Write-ARLog $S 'ERROR: no target (extra_args empty)'; Write-ARResult $S 'error' '' 'no target'; exit 1 }

$critical = @(
    'system','registry','smss','csrss','wininit','winlogon','services',
    'lsass','lsm','svchost','fontdrvhost','dwm','wazuh-agent','ossec-agent',
    'sysmon','sysmon64','memcompression','idle','msmpeng','securityhealthservice'
)

# Shared host processes: PID-only, never by name.
$generic = @(
    'powershell','powershell_ise','pwsh','cmd','net','net1','wsmprovhost',
    'conhost','explorer','runas','rundll32','regsvr32','mshta','wmic',
    'cscript','wscript','dllhost','taskhostw','werfault','msiexec',
    'schtasks','reg','sc','spoolsv','winrshost','searchindexer'
)

function Get-BaseName([string]$s) {
    if (-not $s) { return '' }
    $b = ($s -replace '/', '\')
    $b = $b.Substring($b.LastIndexOf('\') + 1)
    return ($b -replace '\.exe$', '').ToLower()
}

# Resolve to concrete process objects, by PID if numeric else by name.
$byPid = $false
$procs = @()
if ($target -match '^\d+$') {
    $byPid = $true
    $p = Get-Process -Id ([int]$target) -ErrorAction SilentlyContinue
    if ($p) { $procs = @($p) }
} else {
    $name = Get-BaseName $target
    if ($generic -contains $name) {
        Write-ARLog $S "REFUSED: '$target' is a shared host process, killable by PID only"
        Write-ARResult $S 'refused' $reported 'shared host process, PID required'
        exit 1
    }
    $procs = @(Get-Process -Name $name -ErrorAction SilentlyContinue)
}
if (-not $procs -or $procs.Count -eq 0) {
    Write-ARLog $S "target '$target' not running"
    Write-ARResult $S 'noop' $reported 'not running'
    exit 0
}

# A PID is reused, and minutes pass between the alert and the response. When the
# caller states the expected image, kill only if the PID still carries it.
if ($byPid -and $expect) {
    $want = Get-BaseName $expect
    $got  = Get-BaseName $procs[0].Name
    if ($want -ne $got) {
        Write-ARLog $S "REFUSED: pid $target carries '$got', expected '$want' (pid reused)"
        Write-ARResult $S 'refused' $reported "pid carries $got, expected $want"
        exit 1
    }
}
if ($byPid -and -not $expect -and ($generic -contains (Get-BaseName $procs[0].Name))) {
    Write-ARLog $S "REFUSED: pid $target is a shared host process and no expected image was given"
    Write-ARResult $S 'refused' $reported 'shared host process, expected image required'
    exit 1
}

$killed = 0
$refus  = 0
foreach ($p in $procs) {
    $pn = Get-BaseName $p.Name
    if ($critical -contains $pn -or $p.Id -le 4) {
        Write-ARLog $S "REFUSED: critical process '$($p.Name)' (pid $($p.Id))"
        $refus++
        continue
    }
    try { Stop-Process -Id $p.Id -Force -ErrorAction Stop; $killed++ }
    catch { Write-ARLog $S "failed to kill pid $($p.Id): $($_.Exception.Message)" }
}
Write-ARLog $S "target '$target': $killed process(es) killed"
if ($killed -gt 0) {
    Write-ARResult $S 'applied' $reported "$killed process(es) killed"
    exit 0
}
if ($refus -gt 0) { Write-ARResult $S 'refused' $reported 'critical process' }
else              { Write-ARResult $S 'error'   $reported 'kill failed' }
exit 1
