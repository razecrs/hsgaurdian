# HS Guardian

HS Guardian is a Windows live-code workspace backed by WinDissect exact-build
IR. The complete tracked WinDissect source is vendored as the
`vendor/windissect` workspace crate, excluding only its prebuilt executable and
local generated/scratch files.

## Current features

- Process and loaded-module browser
- Typed value scans for signed/unsigned integers and floating-point values
- Exact, changed, unchanged, increased, and decreased result refinement
- Result editing with the same rollback history used by code patches
- 32/64-bit live instruction disassembly
- Executable-memory byte patches with original-byte snapshots and rollback
- Pointer-chain resolver for 32-bit and 64-bit targets
- Full WinDissect pipeline: extract, verify, semantically refine, inventory,
  record build history, and generate the SDK
- SHA-256 verification between WinDissect IR and the loaded module file
- Live-address symbol navigation with ASLR-aware `module base + RVA` mapping
- Static call, branch, read, and write references from WinDissect instruction IR
- One-click generation of verified C/C++ headers, Rust bindings, C symbol
  tables, evidence, documentation, and annotated assembly
- Windows-native Segoe UI and Cascadia Mono rendering with Unicode fallback

## Run

```powershell
pwsh -File scripts/build-release.ps1
target\release\hsgaurdian.exe
```

For a development build, run `cargo build --workspace`, then launch
`target\debug\hsgaurdian.exe`. The sibling `windissect.exe` is discovered
automatically.

See [docs/hill-climb-racing.md](docs/hill-climb-racing.md) for the validated
target profile, current recovery counts, and the honest no-PDB boundary.

Processes with a higher integrity level may require running HS Guardian as
administrator. Protected processes can remain inaccessible even when elevated.

The bundled sibling `windissect.exe` is preferred automatically. Override it
in the UI or set `WINDISSECT_EXE` when testing another build.

## Patching model

Patches are explicit and local to the current session. Before writing, HS
Guardian snapshots the original bytes, temporarily changes page protection,
writes the replacement, restores protection, and flushes the target's
instruction cache. Patch history can restore the captured bytes.

Use this only on software you own or are authorized to inspect. A bad patch can
crash the target process.

## Scope

The current “find xrefs / writes” feature is static: it consumes WinDissect's
recovered instruction targets. Dynamic “what writes this address” tracing will
require a dedicated Windows debugger loop and hardware data breakpoints.

WinDissect reconstructs verified declarations, types, and annotated assembly;
it does not currently decompile arbitrary native function bodies into editable
C++ or Rust. The UI therefore generates truthful WinDissect artifacts rather
than presenting guessed high-level source as verified code.

The vendored WinDissect component retains its AGPL-3.0-only license in
`vendor/windissect/LICENSE`.
