<#
    Reverse of win-quarantine-file.ps1: move a quarantined file back to its
    original path and restore normal ACL inheritance.
    extra_args = ["<original full path>"].
#>
. "$PSScriptRoot\_ar-common.ps1"
$in   = Read-ARInput
$path = ($in.Args | Select-Object -First 1)
$qdir = Join-Path (Split-Path $PSScriptRoot -Parent) 'quarantine'
$S = 'win-restore-file'
if (-not $path) { Write-ARLog $S 'ERROR: no path (extra_args empty)'; Write-ARResult $S 'error' '' 'no target'; exit 1 }

$meta = Get-ChildItem -Path $qdir -Filter '*.quar.json' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Where-Object { (Get-Content $_.FullName -Raw | ConvertFrom-Json).original -ieq $path } |
        Select-Object -First 1
if (-not $meta) { Write-ARLog $S "no quarantined copy found for '$path'"; Write-ARResult $S 'noop' $path 'no quarantined copy found'; exit 1 }

$qfile = $meta.FullName -replace '\.json$', ''
& icacls.exe $qfile /reset > $null 2>&1
Move-Item -LiteralPath $qfile -Destination $path -Force
Remove-Item -LiteralPath $meta.FullName -Force -ErrorAction SilentlyContinue
Write-ARLog $S "restored '$path' from quarantine"
Write-ARResult $S 'applied' $path 'restored from quarantine'
exit 0
