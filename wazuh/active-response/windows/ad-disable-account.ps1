<#
    T1136.002 / compromised account - disable an Active Directory account.
    Domain analog of disable-account.sh. Runs ON A DOMAIN CONTROLLER (the soc-agent
    routes domain actions to a DC agent, not to the compromised member host).

    extra_args = ["<samAccountName>"].
    add -> disable + expire ; delete -> no-op (only ad-enable-account.ps1 reverses).

    GUARDRAILS (also enforced in the soc-agent, duplicated here because the AR is
    reachable via API/MCP too):
      - protected accounts (builtin Administrator, krbtgt, machine accounts,
        members of Domain/Enterprise/Schema Admins) are never touched;
      - must run on a DC and the account must exist in the directory.
#>
. "$PSScriptRoot\_ar-common.ps1"
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
$in   = Read-ARInput
$user = Get-SamName ($in.Args | Select-Object -First 1)

$S = 'ad-disable-account'
if ($in.Command -eq 'delete') { Write-ARLog $S 'delete: no-op (use ad-enable-account)'; Write-ARResult $S 'noop' $user 'delete command'; exit 0 }
if ($in.Command -ne 'add')    { Write-ARLog $S "invalid command '$($in.Command)'"; Write-ARResult $S 'error' $user 'invalid command'; exit 1 }
if (-not $user)               { Write-ARLog $S 'ERROR: no user (extra_args empty)'; Write-ARResult $S 'error' '' 'no target'; exit 1 }

if (-not (Confirm-DomainController)) {
    Write-ARLog $S 'REFUSED: not a domain controller (domain action mis-routed)'
    Write-ARResult $S 'refused' $user 'not a domain controller'
    exit 1
}
if (Test-ProtectedAccount $user) {
    Write-ARLog $S "REFUSED: '$user' is a protected account"
    Write-ARResult $S 'refused' $user 'protected account'
    exit 1
}
$acct = Get-ADUser -Identity $user -Properties Enabled -ErrorAction SilentlyContinue
if (-not $acct) {
    Write-ARLog $S "ERROR: account '$user' not found in AD"
    Write-ARResult $S 'noop' $user 'account not found in AD'
    exit 1
}

Disable-ADAccount -Identity $user -ErrorAction Stop
# Expire as well: a disabled account can be re-enabled by a co-resident attacker;
# an expiration in the past is a second, independent lock (mirrors chage -E 1).
Set-ADUser -Identity $user -AccountExpirationDate (Get-Date).AddDays(-1) -ErrorAction SilentlyContinue
Write-ARLog $S "AD account '$user' disabled and expired"
Write-ARResult $S 'applied' $user 'disabled and expired'
exit 0
