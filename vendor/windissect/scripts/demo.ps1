param(
    [string]$Dll = "$env:windir\System32\amsi.dll",
    [string]$Out = "target\demo\amsi"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Dll)) {
    throw "Windows target not found: $Dll"
}

cargo build --release --locked
$tool = Join-Path $PSScriptRoot "..\target\release\windissect.exe"
$ir = Join-Path $Out "amsi.json"

& $tool extract $Dll --out $ir
if ($LASTEXITCODE -ne 0) { throw "extract failed" }
& $tool verify --ir $ir
if ($LASTEXITCODE -ne 0) { throw "verification failed" }
& $tool emit-evidence --ir $ir --out (Join-Path $Out "evidence")
if ($LASTEXITCODE -ne 0) { throw "evidence emission failed" }
& $tool emit-headers --ir $ir --out (Join-Path $Out "headers")
if ($LASTEXITCODE -ne 0) { throw "C/C++ emission failed" }
& $tool emit-rust --ir $ir --out (Join-Path $Out "rust")
if ($LASTEXITCODE -ne 0) { throw "Rust emission failed" }
& $tool emit-syms --ir $ir --out (Join-Path $Out "syms") --name amsi
if ($LASTEXITCODE -ne 0) { throw "C symbol emission failed" }

$oldRustFlags = $env:RUSTFLAGS
$env:RUSTFLAGS = "-D warnings"
cargo check --manifest-path (Join-Path $Out "rust\Cargo.toml") --offline
$env:RUSTFLAGS = $oldRustFlags
if ($LASTEXITCODE -ne 0) { throw "generated Rust crate failed to compile" }

Write-Host "[PASS] Verified target-independent AMSI demonstration: $Out"
