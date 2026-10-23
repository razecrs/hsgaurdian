# HS Guardian

HS Guardian is a Windows live-code workspace backed by
[WinDissect](https://github.com/razecrs/windissect) exact-build IR.

## Current features

- Process and loaded-module browser
- Typed value scans for signed/unsigned integers and floating-point values
- Exact, changed, unchanged, increased, and decreased result refinement
- Result editing with the same rollback history used by code patches
- 32/64-bit live instruction disassembly
- Executable-memory byte patches with original-byte snapshots and rollback
- Pointer-chain resolver for 32-bit and 64-bit targets
- WinDissect module analysis and existing-IR loading
- SHA-256 verification between WinDissect IR and the loaded module file
- Live-address symbol navigation with ASLR-aware `module base + RVA` mapping
- Static call, branch, read, and write references from WinDissect instruction IR
- One-click generation of verified C/C++ headers, Rust bindings, and annotated assembly

## Run

```powershell
cargo run
```

Processes with a higher integrity level may require running HS Guardian as
administrator. Protected processes can remain inaccessible even when elevated.

The default WinDissect executable is
`D:\Projects\windissect\target\release\windissect.exe`. Override it in the UI
or set `WINDISSECT_EXE`.

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
