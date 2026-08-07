<#
    Network-isolate this Windows host with Windows Firewall. Windows analog of
    host-isolate.sh (nftables). Blocks all inbound+outbound EXCEPT the Wazuh
    manager channel and an allowlist (so the agent stays reporting and the SOC
    can still investigate over WinRM).

    extra_args : ["<managerIp>", "<socIp>", ...]   (allowlist; defaults to the
                 manager 192.168.10.5 if none given)
    add    -> isolate ; delete -> no-op (only win-host-unisolate.ps1 lifts it).

    GUARDRAIL: refuses to isolate a domain controller - cutting a DC off the
    network breaks authentication for the whole domain. That stays a manual call.
#>
. "$PSScriptRoot\_ar-common.ps1"
$in    = Read-ARInput
$allow = @($in.Args | Where-Object { $_ -as [ipaddress] })
if (-not $allow -or $allow.Count -eq 0) { $allow = @('192.168.10.5') }
$stateFile = Join-Path (Split-Path $PSScriptRoot -Parent) 'soc-ai-isolation.state'

$S    = 'win-host-isolate'
$host_name = $env:COMPUTERNAME

if ($in.Command -eq 'delete') { Write-ARLog $S 'delete: no-op (use unisolate)'; Write-ARResult $S 'noop' $host_name 'delete command'; exit 0 }
if ($in.Command -ne 'add')    { Write-ARLog $S "invalid command '$($in.Command)'"; Write-ARResult $S 'error' $host_name 'invalid command'; exit 1 }

if (Confirm-DomainController) {
    Write-ARLog $S 'REFUSED: host is a domain controller - isolation would break the domain'
    Write-ARResult $S 'refused' $host_name 'host is a domain controller'
    exit 1
}

# Remember the current default policy so unisolate can restore it exactly.
try {
    $prior = Get-NetFirewallProfile -All |
             Select-Object Name, DefaultInboundAction, DefaultOutboundAction
    $prior | ConvertTo-Json | Set-Content -Path $stateFile -Encoding utf8
} catch { }

# Allow the manager channel + investigation BEFORE flipping the default to block.
foreach ($ip in ($allow | Select-Object -Unique)) {
    New-NetFirewallRule -DisplayName "Aura-SOC-isolate-allow-out-$ip" -Direction Outbound `
        -RemoteAddress $ip -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "Aura-SOC-isolate-allow-in-$ip"  -Direction Inbound `
        -RemoteAddress $ip -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
}
Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Block

Write-ARLog $S ("host isolated; reachable IPs: {0}" -f ($allow -join ', '))
Write-ARResult $S 'applied' $host_name ("isolated; reachable IPs: {0}" -f ($allow -join ' '))
exit 0
