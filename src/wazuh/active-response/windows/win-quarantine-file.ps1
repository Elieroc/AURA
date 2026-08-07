<#
    T1105 / dropped malware - quarantine a file: hash it, move it into the
    agent's quarantine folder, and deny all access. Windows analog of
    quarantine.sh. extra_args = ["<full path>"].

    add -> quarantine ; delete -> no-op. win-restore-file.ps1 is the reverse.
    GUARDRAIL: refuses paths under the Windows/system directories.
#>
. "$PSScriptRoot\_ar-common.ps1"
$in   = Read-ARInput
$path = ($in.Args | Select-Object -First 1)
$qdir = Join-Path (Split-Path $PSScriptRoot -Parent) 'quarantine'

$S = 'win-quarantine-file'
if ($in.Command -eq 'delete') { Write-ARLog $S 'delete: no-op'; Write-ARResult $S 'noop' $path 'delete command'; exit 0 }
if ($in.Command -ne 'add')    { Write-ARLog $S "invalid command '$($in.Command)'"; Write-ARResult $S 'error' $path 'invalid command'; exit 1 }
if (-not $path)               { Write-ARLog $S 'ERROR: no path (extra_args empty)'; Write-ARResult $S 'error' '' 'no target'; exit 1 }

$protected = @("$env:SystemRoot", (Join-Path $env:SystemRoot 'System32'),
               "$env:ProgramFiles\ossec-agent", "${env:ProgramFiles(x86)}\ossec-agent")
foreach ($d in $protected) {
    if ($path -like "$d*") {
        Write-ARLog $S "REFUSED: '$path' under protected dir '$d'"
        Write-ARResult $S 'refused' $path "protected directory $d"
        exit 1
    }
}
if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    Write-ARLog $S "file '$path' not found - nothing to quarantine"
    Write-ARResult $S 'noop' $path 'file not found'
    exit 0
}

if (-not (Test-Path $qdir)) { New-Item -ItemType Directory -Path $qdir -Force | Out-Null }
$hash  = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
$qfile = Join-Path $qdir "$hash.quar"
@{ original = $path; hash = $hash; when = (Get-Date -Format o) } |
    ConvertTo-Json | Set-Content -Path "$qfile.json" -Encoding utf8

Move-Item -LiteralPath $path -Destination $qfile -Force
# Strip inheritance and deny everyone: the sample cannot be read or executed.
& icacls.exe $qfile /inheritance:r /deny '*S-1-1-0:(F)' > $null 2>&1
Write-ARLog $S "quarantined '$path' (sha256=$hash) -> $qfile"
Write-ARResult $S 'applied' $path "sha256=$hash"
exit 0
