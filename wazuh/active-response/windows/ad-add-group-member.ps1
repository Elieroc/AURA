<#
    Reverse of ad-remove-group-member.ps1: put a member back into a group
    (used when an analyst cancels a wrongful removal).
    extra_args = ["<group>", "<member samAccountName>"]. Runs on a domain controller.
#>
. "$PSScriptRoot\_ar-common.ps1"
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
$in     = Read-ARInput
$group  = ($in.Args | Select-Object -First 1)
$member = Get-SamName ($in.Args | Select-Object -Skip 1 -First 1)
$S      = 'ad-add-group-member'
$cible  = "$group/$member"
if (-not $group -or -not $member) { Write-ARLog $S 'ERROR: need <group> <member>'; Write-ARResult $S 'error' $cible 'need group and member'; exit 1 }
if (-not (Confirm-DomainController)) { Write-ARLog $S 'REFUSED: not a DC'; Write-ARResult $S 'refused' $cible 'not a domain controller'; exit 1 }
$g = Get-ADGroup -Identity $group -ErrorAction SilentlyContinue
if (-not $g) { Write-ARLog $S "ERROR: group '$group' not found"; Write-ARResult $S 'noop' $cible 'group not found in AD'; exit 1 }
Add-ADGroupMember -Identity $g -Members $member -Confirm:$false -ErrorAction Stop
Write-ARLog $S "added '$member' back to '$group'"
Write-ARResult $S 'applied' $cible 'member added back to group'
exit 0
