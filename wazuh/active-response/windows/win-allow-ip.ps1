<#
    Reverse of win-block-ip.ps1: remove the block rules for an IP.
    extra_args : ["<ip>"]   (command is always treated as apply)
#>
. "$PSScriptRoot\_ar-common.ps1"
$in = Read-ARInput
$ip = ($in.Args | Select-Object -First 1)
$S = 'win-allow-ip'
if (-not $ip) { Write-ARLog $S 'ERROR: no IP (extra_args empty)'; Write-ARResult $S 'error' '' 'no target'; exit 1 }
$rule = "SOC-AI-block-$ip"
Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue
Write-ARLog $S "block rules for '$ip' removed"
Write-ARResult $S 'applied' $ip 'block rules removed'
exit 0
