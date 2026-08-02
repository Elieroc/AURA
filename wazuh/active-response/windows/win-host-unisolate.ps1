<#
    Reverse of win-host-isolate.ps1: lift the network isolation.
    Removes the SOC-AI isolation rules and restores the firewall default policy
    saved at isolation time (falls back to the Windows default: inbound Block,
    outbound Allow).
#>
. "$PSScriptRoot\_ar-common.ps1"
$null      = Read-ARInput   # drain stdin; command is always treated as apply
$stateFile = Join-Path (Split-Path $PSScriptRoot -Parent) 'soc-ai-isolation.state'

Get-NetFirewallRule -DisplayName 'SOC-AI-isolate-*' -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue

$restored = $false
if (Test-Path $stateFile) {
    try {
        $prior = Get-Content $stateFile -Raw | ConvertFrom-Json
        foreach ($p in @($prior)) {
            Set-NetFirewallProfile -Name $p.Name `
                -DefaultInboundAction  $p.DefaultInboundAction `
                -DefaultOutboundAction $p.DefaultOutboundAction
        }
        Remove-Item $stateFile -Force -ErrorAction SilentlyContinue
        $restored = $true
    } catch { }
}
if (-not $restored) {
    Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Allow
}
$S = 'win-host-unisolate'
Write-ARLog $S "isolation lifted (restored from state: $restored)"
Write-ARResult $S 'applied' $env:COMPUTERNAME "isolation lifted (restored from state: $restored)"
exit 0
