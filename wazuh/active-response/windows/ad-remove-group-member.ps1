<#
    T1098.007 - remove a member an attacker added to a privileged group
    (e.g. Domain Admins). Runs on a domain controller.

    extra_args = ["<group>", "<member samAccountName>"].
    add -> remove ; delete -> no-op. ad-add-group-member.ps1 is the reverse.

    GUARDRAILS:
      - never remove the built-in Administrator or a machine account;
      - never remove the LAST member of a group (avoid orphaning it);
      - must run on a DC; group and member must exist.

    NOTE: this is high-impact (touches privileged group membership). The soc-agent
    keeps it PROPOSE-ONLY (manual execution) - only ad-disable-account is auto.
#>
. "$PSScriptRoot\_ar-common.ps1"
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
$in     = Read-ARInput
$group  = ($in.Args | Select-Object -First 1)
$member = Get-SamName ($in.Args | Select-Object -Skip 1 -First 1)

$S     = 'ad-remove-group-member'
$cible = "$group/$member"

if ($in.Command -eq 'delete') { Write-ARLog $S 'delete: no-op'; Write-ARResult $S 'noop' $cible 'delete command'; exit 0 }
if ($in.Command -ne 'add')    { Write-ARLog $S "invalid command '$($in.Command)'"; Write-ARResult $S 'error' $cible 'invalid command'; exit 1 }
if (-not $group -or -not $member) { Write-ARLog $S 'ERROR: need <group> <member>'; Write-ARResult $S 'error' $cible 'need group and member'; exit 1 }
if (-not (Confirm-DomainController)) { Write-ARLog $S 'REFUSED: not a DC'; Write-ARResult $S 'refused' $cible 'not a domain controller'; exit 1 }

$member_sam = (Get-SamName $member).ToLower()
if ($member_sam -in @('administrateur','administrator') -or $member_sam.EndsWith('$')) {
    Write-ARLog $S "REFUSED: '$member' is protected"
    Write-ARResult $S 'refused' $cible 'protected member'
    exit 1
}
$g = Get-ADGroup -Identity $group -ErrorAction SilentlyContinue
if (-not $g) { Write-ARLog $S "ERROR: group '$group' not found"; Write-ARResult $S 'noop' $cible 'group not found in AD'; exit 1 }
$members = @(Get-ADGroupMember -Identity $g -ErrorAction SilentlyContinue)
if ($members.Count -le 1) {
    Write-ARLog $S "REFUSED: '$group' has <=1 member - will not empty it"
    Write-ARResult $S 'refused' $cible 'group has <=1 member'
    exit 1
}
if (-not ($members | Where-Object { $_.SamAccountName -ieq $member })) {
    Write-ARLog $S "'$member' not a member of '$group' - nothing to do"
    Write-ARResult $S 'noop' $cible 'not a member of the group'
    exit 0
}
Remove-ADGroupMember -Identity $g -Members $member -Confirm:$false -ErrorAction Stop
Write-ARLog $S "removed '$member' from '$group'"
Write-ARResult $S 'applied' $cible 'member removed from group'
exit 0
