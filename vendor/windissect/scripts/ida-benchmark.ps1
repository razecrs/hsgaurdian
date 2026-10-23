<#
.SYNOPSIS
Benchmark windissect's no-PDB function recovery against headless IDA.

.DESCRIPTION
For each binary, runs `windissect extract` without a PDB and `idat -Opdb:off`
with ida-export-functions.py, then compares the two with
compare-ida-functions.py. Per-binary results land in <OutDir>/<label>/ and a
summary table in <OutDir>/summary.json and summary.md.

IDA databases are reused when present, so a rerun after a windissect change
only repeats the cheap side.
#>
param(
    [Parameter(Mandatory)] [string[]] $Binaries,
    [Parameter(Mandatory)] [string] $OutDir,
    [string] $Windissect = (Join-Path $PSScriptRoot '..\target\release\windissect.exe'),
    [string] $Idat = 'C:\Program Files\IDA Professional 9.4\idat.exe',
    [string] $Python = 'python'
)

$ErrorActionPreference = 'Stop'
$exporter = Join-Path $PSScriptRoot 'ida-export-functions.py'
$comparer = Join-Path $PSScriptRoot 'compare-ida-functions.py'
New-Item -ItemType Directory -Force $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

$rows = foreach ($binary in $Binaries) {
    $source = Get-Item $binary
    # Label by parent directory too: System32 and SysWOW64 share file names. A
    # binary already inside a result folder keeps that folder's label, so a
    # rerun over earlier copies reuses their IDA output.
    $label = if ($source.Directory.Parent.FullName -eq $OutDir) {
        $source.Directory.Name
    } else {
        '{0}-{1}' -f $source.Directory.Name.ToLowerInvariant(), $source.Name.ToLowerInvariant()
    }
    $work = Join-Path $OutDir $label
    New-Item -ItemType Directory -Force $work | Out-Null
    $target = Join-Path $work $source.Name
    Copy-Item $source.FullName $target -Force

    $ir = Join-Path $work 'windissect.json'
    & $Windissect extract $target -o $ir *> (Join-Path $work 'windissect.log')
    if ($LASTEXITCODE -ne 0) { Write-Warning "${label}: windissect failed"; continue }

    $idaJson = Join-Path $work 'ida.json'
    if (-not (Test-Path $idaJson)) {
        $clock = [Diagnostics.Stopwatch]::StartNew()
        & $Idat -A -Opdb:off "-L$work\ida.log" "-o$work\ida.i64" "-S$exporter $idaJson" $target | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $idaJson)) { Write-Warning "${label}: idat failed"; continue }
        Write-Host ("{0}: IDA analysed in {1:n0}s" -f $label, $clock.Elapsed.TotalSeconds)
    }

    $result = Join-Path $work 'compare.json'
    & $Python -I $comparer $ir $idaJson --json $result | Out-Null
    $data = Get-Content $result -Raw | ConvertFrom-Json
    [pscustomobject]@{
        binary            = $label
        machine           = $data.machine
        ida               = $data.ida_functions
        windissect        = $data.windissect_functions
        matched           = $data.matched_starts
        recall            = $data.recall
        precision         = $data.precision
        windissect_only   = $data.windissect_only
        ida_only          = $data.ida_only
        exact_extents     = $data.identical_extents
        claimed_extents   = $data.claimed_extents
        extent_agreement  = $data.extent_agreement
        identical_sizes   = $data.identical_sizes
        sized_matches     = $data.sized_matches
    }
}

$rows | ConvertTo-Json -Depth 3 | Set-Content (Join-Path $OutDir 'summary.json') -Encoding utf8
$header = '| binary | machine | IDA | windissect | matched | recall | precision | exact extents identical | all sizes identical |'
$rule = '|---|---|---:|---:|---:|---:|---:|---:|---:|'
$lines = foreach ($row in $rows) {
    '| {0} | {1} | {2} | {3} | {4} | {5:p1} | {6:p1} | {7} of {8} | {9} of {10} |' -f $row.binary, $row.machine,
        $row.ida, $row.windissect, $row.matched, $row.recall, $row.precision, $row.exact_extents,
        $row.claimed_extents, $row.identical_sizes, $row.sized_matches
}
@($header, $rule) + $lines | Set-Content (Join-Path $OutDir 'summary.md') -Encoding utf8
$rows | Format-Table binary, machine, ida, windissect, matched, recall, precision, exact_extents, claimed_extents, identical_sizes, sized_matches -AutoSize
