<#
    Reverse of ad-disable-account.ps1: re-enable an AD account and clear the
    expiration set at disable time (exactly symmetric: enable + unexpire).
    extra_args = ["<samAccountName>"]. Runs on a domain controller.
#>
. "$PSScriptRoot\_ar-common.ps1"
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
$in   = Read-ARInput
$user = Get-SamName ($in.Args | Select-Object -First 1)
$S = 'ad-enable-account'
if (-not $user) { Write-ARLog $S 'ERROR: no user (extra_args empty)'; Write-ARResult $S 'error' '' 'no target'; exit 1 }
if (-not (Confirm-DomainController)) {
    Write-ARLog $S 'REFUSED: not a domain controller'
    Write-ARResult $S 'refused' $user 'not a domain controller'
    exit 1
}
if (-not (Get-ADUser -Identity $user -ErrorAction SilentlyContinue)) {
    Write-ARLog $S "ERROR: account '$user' not found"
    Write-ARResult $S 'noop' $user 'account not found in AD'
    exit 1
}
Clear-ADAccountExpiration -Identity $user -ErrorAction SilentlyContinue
Enable-ADAccount -Identity $user -ErrorAction Stop
Write-ARLog $S "AD account '$user' re-enabled and un-expired"
Write-ARResult $S 'applied' $user 'enabled and un-expired'
exit 0
