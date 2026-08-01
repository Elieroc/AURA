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

if ($in.Command -eq 'delete') { Write-ARLog 'ad-remove-group-member' 'delete: no-op'; exit 0 }
if ($in.Command -ne 'add')    { Write-ARLog 'ad-remove-group-member' "invalid command '$($in.Command)'"; exit 1 }
if (-not $group -or -not $member) { Write-ARLog 'ad-remove-group-member' 'ERROR: need <group> <member>'; exit 1 }
if (-not (Confirm-DomainController)) { Write-ARLog 'ad-remove-group-member' 'REFUSED: not a DC'; exit 1 }

$member_sam = (Get-SamName $member).ToLower()
if ($member_sam -in @('administrateur','administrator') -or $member_sam.EndsWith('$')) {
    Write-ARLog 'ad-remove-group-member' "REFUSED: '$member' is protected"; exit 1
}
$g = Get-ADGroup -Identity $group -ErrorAction SilentlyContinue
if (-not $g) { Write-ARLog 'ad-remove-group-member' "ERROR: group '$group' not found"; exit 1 }
$members = @(Get-ADGroupMember -Identity $g -ErrorAction SilentlyContinue)
if ($members.Count -le 1) {
    Write-ARLog 'ad-remove-group-member' "REFUSED: '$group' has <=1 member - will not empty it"; exit 1
}
if (-not ($members | Where-Object { $_.SamAccountName -ieq $member })) {
    Write-ARLog 'ad-remove-group-member' "'$member' not a member of '$group' - nothing to do"; exit 0
}
Remove-ADGroupMember -Identity $g -Members $member -Confirm:$false -ErrorAction Stop
Write-ARLog 'ad-remove-group-member' "removed '$member' from '$group'"
exit 0
