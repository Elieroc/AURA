<#
    T1071/T1041 - block a hostile IP on this Windows host (inbound + outbound)
    with a Windows Firewall rule. Windows analog of firewall-drop.sh.

    extra_args : ["<ip>"]
    add    -> create block rules ; delete (timeout) -> remove them (like the
             Linux firewall-drop timeout). win-allow-ip.ps1 is the explicit reverse.
#>
. "$PSScriptRoot\_ar-common.ps1"
$in  = Read-ARInput
$ip  = ($in.Args | Select-Object -First 1)
$rule = "SOC-AI-block-$ip"

function Test-IpBlockable([string]$x) {
    if (-not ($x -as [ipaddress])) { return $false }
    if ($x -eq '127.0.0.1' -or $x -eq '::1' -or $x -eq '0.0.0.0') { return $false }
    # never block the default gateway / DNS - would sever the host from the net
    try {
        $gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
               Select-Object -ExpandProperty NextHop -Unique)
        if ($gw -contains $x) { return $false }
    } catch { }
    return $true
}

$S = 'win-block-ip'
switch ($in.Command) {
    'delete' {
        Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue |
            Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Write-ARLog $S "rules '$rule' removed (timeout)"
        # Not 'applied': the block is being LIFTED here, reporting applied would
        # read as a successful block on the reconcile side.
        Write-ARResult $S 'noop' $ip 'delete command: block rules removed (timeout)'
        exit 0
    }
    'add' { }
    default {
        Write-ARLog $S "invalid command '$($in.Command)'"
        Write-ARResult $S 'error' $ip 'invalid command'
        exit 1
    }
}

if (-not $ip)                    { Write-ARLog $S 'ERROR: no IP (extra_args empty)'; Write-ARResult $S 'error' '' 'no target'; exit 1 }
if (-not (Test-IpBlockable $ip)) { Write-ARLog $S "REFUSED: '$ip' not a blockable IP"; Write-ARResult $S 'refused' $ip 'not a blockable IP'; exit 1 }

if (-not (Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $rule -Direction Inbound  -RemoteAddress $ip -Action Block -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName $rule -Direction Outbound -RemoteAddress $ip -Action Block -Profile Any | Out-Null
}
Write-ARLog $S "IP '$ip' blocked (inbound+outbound)"
Write-ARResult $S 'applied' $ip 'blocked inbound+outbound'
exit 0
