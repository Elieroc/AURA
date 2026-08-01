<#
    Reverse of win-block-ip.ps1: remove the block rules for an IP.
    extra_args : ["<ip>"]   (command is always treated as apply)
#>
. "$PSScriptRoot\_ar-common.ps1"
$in = Read-ARInput
$ip = ($in.Args | Select-Object -First 1)
if (-not $ip) { Write-ARLog 'win-allow-ip' 'ERROR: no IP (extra_args empty)'; exit 1 }
$rule = "SOC-AI-block-$ip"
Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue
Write-ARLog 'win-allow-ip' "block rules for '$ip' removed"
exit 0
