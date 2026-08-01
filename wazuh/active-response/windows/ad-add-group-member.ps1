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
if (-not $group -or -not $member) { Write-ARLog 'ad-add-group-member' 'ERROR: need <group> <member>'; exit 1 }
if (-not (Confirm-DomainController)) { Write-ARLog 'ad-add-group-member' 'REFUSED: not a DC'; exit 1 }
$g = Get-ADGroup -Identity $group -ErrorAction SilentlyContinue
if (-not $g) { Write-ARLog 'ad-add-group-member' "ERROR: group '$group' not found"; exit 1 }
Add-ADGroupMember -Identity $g -Members $member -Confirm:$false -ErrorAction Stop
Write-ARLog 'ad-add-group-member' "added '$member' back to '$group'"
exit 0
