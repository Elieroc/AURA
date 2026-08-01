<#
    T1003.001 / malware execution - kill a malicious process on this host.
    Windows analog of kill-process.sh. extra_args = ["<name-or-pid>"].

    add -> stop the process ; delete -> no-op (there is no "unkill").
    A local safelist protects critical Windows and Wazuh processes, in addition
    to the soc-agent guardrails - the AR is also reachable via API/MCP.
#>
. "$PSScriptRoot\_ar-common.ps1"
$in     = Read-ARInput
$target = ($in.Args | Select-Object -First 1)

if ($in.Command -eq 'delete') { Write-ARLog 'win-kill-process' 'delete: no-op (no unkill)'; exit 0 }
if ($in.Command -ne 'add')    { Write-ARLog 'win-kill-process' "invalid command '$($in.Command)'"; exit 1 }
if (-not $target)             { Write-ARLog 'win-kill-process' 'ERROR: no target (extra_args empty)'; exit 1 }

$critical = @(
    'system','registry','smss','csrss','wininit','winlogon','services',
    'lsass','lsm','svchost','fontdrvhost','dwm','wazuh-agent','ossec-agent',
    'sysmon','sysmon64','memcompression','idle'
)

# Resolve to concrete process objects, by PID if numeric else by name.
$procs = @()
if ($target -match '^\d+$') {
    $p = Get-Process -Id ([int]$target) -ErrorAction SilentlyContinue
    if ($p) { $procs = @($p) }
} else {
    $name  = ($target -replace '\.exe$', '')
    $procs = @(Get-Process -Name $name -ErrorAction SilentlyContinue)
}
if (-not $procs -or $procs.Count -eq 0) {
    Write-ARLog 'win-kill-process' "target '$target' not running"; exit 0
}

$killed = 0
foreach ($p in $procs) {
    $pn = ($p.Name).ToLower()
    if ($critical -contains $pn -or $p.Id -le 4) {
        Write-ARLog 'win-kill-process' "REFUSED: critical process '$($p.Name)' (pid $($p.Id))"
        continue
    }
    try { Stop-Process -Id $p.Id -Force -ErrorAction Stop; $killed++ }
    catch { Write-ARLog 'win-kill-process' "failed to kill pid $($p.Id): $($_.Exception.Message)" }
}
Write-ARLog 'win-kill-process' "target '$target': $killed process(es) killed"
if ($killed -eq 0) { exit 1 }
exit 0
