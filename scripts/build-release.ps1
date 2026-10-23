$ErrorActionPreference = "Stop"

Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    cargo build --workspace --release

    $guardian = Join-Path $PWD "target\release\hsgaurdian.exe"
    $windissect = Join-Path $PWD "target\release\windissect.exe"
    if (-not (Test-Path -LiteralPath $guardian)) {
        throw "HS Guardian was not produced at $guardian"
    }
    if (-not (Test-Path -LiteralPath $windissect)) {
        throw "Bundled WinDissect was not produced at $windissect"
    }

    Write-Host "Built HS Guardian and WinDissect:" -ForegroundColor Green
    Write-Host "  $guardian"
    Write-Host "  $windissect"
}
finally {
    Pop-Location
}
