<#
    Shared helpers for the SOC-AI Windows / AD active-response scripts.
    Dot-sourced by every win-*.ps1 and ad-*.ps1 from the same bin directory:
        . "$PSScriptRoot\_ar-common.ps1"

    Mirrors the Linux AR contract (disable-account.sh et al.):
      - stdin JSON {"command":"add|delete","parameters":{"extra_args":[...]}}
      - logs to active-response\active-responses.log
      - `add` applies, `delete` (timeout expiry) is a no-op for high-impact
        actions; only the symmetric reverse script undoes them.
      - Local guardrails duplicate the soc-agent's (actions.appliquer_garde_fous)
        because the AR is ALSO reachable via the Wazuh API and the MCP server,
        which do not go through the Python code.
#>

$ErrorActionPreference = 'Stop'

function Get-ARLog {
    # active-responses.log lives under the agent's active-response dir; this
    # script runs from active-response\bin, so the log is one level up.
    return (Join-Path (Split-Path $PSScriptRoot -Parent) 'active-responses.log')
}

function Write-ARLog {
    param([string]$Tag, [string]$Message)
    $line = ('{0} {1}: {2}' -f (Get-Date -Format 'yyyy/MM/dd HH:mm:ss'), $Tag, $Message)
    try { Add-Content -Path (Get-ARLog) -Value $line -Encoding utf8 } catch { }
}

function Read-ARInput {
    # Returns [pscustomobject]@{ Command; Args } from the stdin JSON.
    $raw = [Console]::In.ReadToEnd()
    if (-not $raw) { return [pscustomobject]@{ Command = ''; Args = @() } }
    try {
        $j = $raw | ConvertFrom-Json
    } catch {
        return [pscustomobject]@{ Command = ''; Args = @() }
    }
    $cmd = [string]$j.command
    $ea  = @()
    if ($j.parameters -and $j.parameters.extra_args) { $ea = @($j.parameters.extra_args) }
    return [pscustomobject]@{ Command = $cmd; Args = $ea }
}

# Local (non-domain) accounts that must never be disabled/altered.
$script:ProtectedLocalNames = @(
    'administrateur', 'administrator', 'krbtgt', 'guest', 'defaultaccount',
    'wdagutilityaccount', 'system', 'localsystem', 'networkservice',
    'localservice', 'wazuh', 'wazuh-admin'
)

# Domain groups whose members are treated as protected (never auto-disabled):
# disabling a legitimate privileged admin caught in the incident would lock out
# administration. High-impact accounts stay a manual analyst decision.
$script:ProtectedGroups = @(
    'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
    'Domain Controllers', 'Enterprise Read-only Domain Controllers',
    'Group Policy Creator Owners', 'Administrateurs',
    'Admins du domaine', 'Administrateurs de l''entreprise'
)

function Get-SamName {
    param([string]$Raw)
    # Strip DOMAIN\ or user@domain forms down to the SAM account name.
    $n = ($Raw -replace '.*\\', '') -replace '@.*$', ''
    return $n.Trim()
}

function Test-ProtectedAccount {
    <#
        True if the account must never be touched automatically:
          - a built-in / system / SOC operator name;
          - a machine account (trailing $);
          - a member of a protected privileged group (best effort via the AD
            module; if the module is absent the name list still applies).
    #>
    param([string]$Raw)
    $sam = (Get-SamName $Raw).ToLower()
    if (-not $sam) { return $true }
    if ($script:ProtectedLocalNames -contains $sam) { return $true }
    if ($sam.EndsWith('$')) { return $true }   # machine / trust account

    if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
        try {
            $groups = Get-ADPrincipalGroupMembership -Identity $sam -ErrorAction Stop |
                      Select-Object -ExpandProperty Name
            foreach ($g in $groups) {
                if ($script:ProtectedGroups -contains $g) {
                    Write-ARLog 'guardrail' "account '$sam' is member of protected group '$g' - refused"
                    return $true
                }
            }
        } catch { }   # not a domain account / no AD module -> name list already applied
    }
    return $false
}

function Confirm-DomainController {
    # True when this host is a DC (ProductType 2). AD write actions must run here.
    try { return ((Get-CimInstance Win32_OperatingSystem).ProductType -eq 2) }
    catch { return $false }
}
