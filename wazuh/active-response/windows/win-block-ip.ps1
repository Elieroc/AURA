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

switch ($in.Command) {
    'delete' {
        Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue |
            Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Write-ARLog 'win-block-ip' "rules '$rule' removed (timeout)"
        exit 0
    }
    'add' { }
    default { Write-ARLog 'win-block-ip' "invalid command '$($in.Command)'"; exit 1 }
}

if (-not $ip)                    { Write-ARLog 'win-block-ip' 'ERROR: no IP (extra_args empty)'; exit 1 }
if (-not (Test-IpBlockable $ip)) { Write-ARLog 'win-block-ip' "REFUSED: '$ip' not a blockable IP"; exit 1 }

if (-not (Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $rule -Direction Inbound  -RemoteAddress $ip -Action Block -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName $rule -Direction Outbound -RemoteAddress $ip -Action Block -Profile Any | Out-Null
}
Write-ARLog 'win-block-ip' "IP '$ip' blocked (inbound+outbound)"
exit 0
