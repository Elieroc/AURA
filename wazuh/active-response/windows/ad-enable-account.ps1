<#
    Reverse of ad-disable-account.ps1: re-enable an AD account and clear the
    expiration set at disable time (exactly symmetric: enable + unexpire).
    extra_args = ["<samAccountName>"]. Runs on a domain controller.
#>
. "$PSScriptRoot\_ar-common.ps1"
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
$in   = Read-ARInput
$user = Get-SamName ($in.Args | Select-Object -First 1)
if (-not $user) { Write-ARLog 'ad-enable-account' 'ERROR: no user (extra_args empty)'; exit 1 }
if (-not (Confirm-DomainController)) {
    Write-ARLog 'ad-enable-account' 'REFUSED: not a domain controller'; exit 1
}
if (-not (Get-ADUser -Identity $user -ErrorAction SilentlyContinue)) {
    Write-ARLog 'ad-enable-account' "ERROR: account '$user' not found"; exit 1
}
Clear-ADAccountExpiration -Identity $user -ErrorAction SilentlyContinue
Enable-ADAccount -Identity $user -ErrorAction Stop
Write-ARLog 'ad-enable-account' "AD account '$user' re-enabled and un-expired"
exit 0
