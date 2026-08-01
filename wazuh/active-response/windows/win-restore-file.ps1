<#
    Reverse of win-quarantine-file.ps1: move a quarantined file back to its
    original path and restore normal ACL inheritance.
    extra_args = ["<original full path>"].
#>
. "$PSScriptRoot\_ar-common.ps1"
$in   = Read-ARInput
$path = ($in.Args | Select-Object -First 1)
$qdir = Join-Path (Split-Path $PSScriptRoot -Parent) 'quarantine'
if (-not $path) { Write-ARLog 'win-restore-file' 'ERROR: no path (extra_args empty)'; exit 1 }

$meta = Get-ChildItem -Path $qdir -Filter '*.quar.json' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Where-Object { (Get-Content $_.FullName -Raw | ConvertFrom-Json).original -ieq $path } |
        Select-Object -First 1
if (-not $meta) { Write-ARLog 'win-restore-file' "no quarantined copy found for '$path'"; exit 1 }

$qfile = $meta.FullName -replace '\.json$', ''
& icacls.exe $qfile /reset > $null 2>&1
Move-Item -LiteralPath $qfile -Destination $path -Force
Remove-Item -LiteralPath $meta.FullName -Force -ErrorAction SilentlyContinue
Write-ARLog 'win-restore-file' "restored '$path' from quarantine"
exit 0
