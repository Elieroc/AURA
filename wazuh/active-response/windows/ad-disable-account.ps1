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

if ($in.Command -eq 'delete') { Write-ARLog 'ad-disable-account' 'delete: no-op (use ad-enable-account)'; exit 0 }
if ($in.Command -ne 'add')    { Write-ARLog 'ad-disable-account' "invalid command '$($in.Command)'"; exit 1 }
if (-not $user)               { Write-ARLog 'ad-disable-account' 'ERROR: no user (extra_args empty)'; exit 1 }

if (-not (Confirm-DomainController)) {
    Write-ARLog 'ad-disable-account' 'REFUSED: not a domain controller (domain action mis-routed)'; exit 1
}
if (Test-ProtectedAccount $user) {
    Write-ARLog 'ad-disable-account' "REFUSED: '$user' is a protected account"; exit 1
}
$acct = Get-ADUser -Identity $user -Properties Enabled -ErrorAction SilentlyContinue
if (-not $acct) { Write-ARLog 'ad-disable-account' "ERROR: account '$user' not found in AD"; exit 1 }

Disable-ADAccount -Identity $user -ErrorAction Stop
# Expire as well: a disabled account can be re-enabled by a co-resident attacker;
# an expiration in the past is a second, independent lock (mirrors chage -E 1).
Set-ADUser -Identity $user -AccountExpirationDate (Get-Date).AddDays(-1) -ErrorAction SilentlyContinue
Write-ARLog 'ad-disable-account' "AD account '$user' disabled and expired"
exit 0
