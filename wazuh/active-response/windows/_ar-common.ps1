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

function Write-ARResult {
    <#
        Structured outcome of an active response, on ONE line, machine-readable.

            2026/08/02 09:21:11 ar-result: script=win-kill-process status=refused
            target="cmd.exe" reason="critical process"

        Why this exists. The Wazuh AR channel is fire-and-forget: the API
        returns as soon as the command is queued and the script's exit code
        never comes back. The soc-agent therefore recorded every action as
        'executed'. On 2026-08-02 that produced an IRIS report claiming 26
        quarantines of System32 binaries had succeeded, when the script had
        refused all 26. The analyst read "done" on undone work - the single
        worst defect of that campaign.

        This line is what closes the loop: the agent ships
        active-responses.log, decoder 100930 parses these fields, and
        `soc_agent.reconcile` turns them back into a real status on the
        mitigation and its IRIS task.

        status is a closed set: applied | refused | noop | error.
          applied - the change was made on the host.
          refused - a guardrail declined (protected account, system path...).
          noop    - nothing to do (target absent, already in that state).
          error   - the action was attempted and failed.
    #>
    param(
        [Parameter(Mandatory)][string]$Script,
        [Parameter(Mandatory)][ValidateSet('applied', 'refused', 'noop', 'error')]
        [string]$Status,
        [string]$Target = '',
        [string]$Reason = ''
    )
    $clean = { param($s) ($s -replace '[\r\n"]', ' ').Trim() }
    $line = ('{0} ar-result: script={1} status={2} target="{3}" reason="{4}"' -f `
             (Get-Date -Format 'yyyy/MM/dd HH:mm:ss'), $Script, $Status,
             (& $clean $Target), (& $clean $Reason))
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
    'localservice', 'wazuh', 'wazuh-admin',
    # Well-known identities that show up as the "account" of a 4624/4634 but are
    # not accounts at all. A French-locale DC spells them differently; both
    # spellings are listed. Purple-team 2026-08-02 sent ad-disable-account on
    # 'Systeme', 'SERVICE LOCAL' and 'ANONYMOUS LOGON'.
    'anonymous logon', 'connexion anonyme', 'local service', 'service local',
    'network service', 'service reseau', 'service r' + [char]0xE9 + 'seau',
    'syst' + [char]0xE8 + 'me', 'invit' + [char]0xE9, 'iusr',
    'everyone', 'tout le monde'
)

# Indexed session pseudo-accounts (UMFD-0, DWM-1, ...): never real accounts.
$script:ProtectedNamePattern = '^(umfd|dwm)-\d+$'

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
    if ($sam -match $script:ProtectedNamePattern) { return $true }
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
