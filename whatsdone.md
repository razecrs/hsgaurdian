# What’s Done

## HS Guardian

- Native egui Windows application with a custom dark interface.
- Uses Windows-native Segoe UI and Cascadia Mono fonts.
- Process browser with filtering and read/write attachment status.
- Automatic target bitness detection; Hill Climb Racing is correctly detected
  as a 32-bit process.
- Typed value scanning for signed/unsigned integers, `f32`, and `f64`.
- Scan refinement by exact value, changed, unchanged, increased, or decreased.
- Background scanning so large scans do not freeze the UI.
- Editable scan results with original-value snapshots and rollback history.
- Pointer-chain resolution for 32-bit and 64-bit targets.
- Separate live instruction and hex/data views.
- x86/x64 live disassembly using iced-x86.
- Executable-memory byte patching with temporary page-protection changes,
  instruction-cache flushing, and one-click rollback.
- Static call, branch, read, and write references from retained WinDissect IR.
- Scan results open in the data inspector instead of incorrectly decoding value
  bytes as instructions.

## WinDissect Integration

- The complete tracked WinDissect source is vendored under
  `vendor/windissect` as a Cargo workspace member.
- The old prebuilt executable and very large generated fixture IR files were not
  vendored; source fixtures and tests remain included.
- `cargo build --workspace` builds `hsgaurdian.exe` and `windissect.exe` beside
  each other.
- HS Guardian automatically prefers the bundled sibling `windissect.exe`.
- Full SDK pipeline from the UI:
  1. Exhaustive PE/PDB extraction with retained instructions.
  2. IR verification.
  3. Semantic refinement.
  4. Optional exhaustive inventory.
  5. Exact-build history recording.
  6. C/C++ header generation.
  7. Rust FFI generation when the ABI is proven.
  8. C RVA symbol-table generation.
  9. Annotated assembly, evidence, and API documentation generation.
- Unsupported artifacts are recorded in `artifact-report.txt` instead of
  aborting every other valid output.

## Hill Climb Racing Validation

Validated against the installed Windows build `1.41.1.0`:

- Target architecture: x86.
- 1,374 exact-build symbols/function candidates recovered.
- 1,374 retained function records.
- 12,152 decoded instructions.
- Compact and exhaustive IR pass all 11 verification checks.
- Generated a 1,374-entry C17 RVA symbol table.
- The generated symbol table compiles cleanly with Clang using `-Wall -Wextra
  -Werror`.

The executable advertises `HillClimbRacing.pdb` with GUID/age key
`8AEA44D7979F416BA7740983E1A0A3BA1`. The PDB is not included with the game and
Microsoft’s public symbol server returns 404 for that exact key.

Because the PDB is unavailable, the current trustworthy SDK is based on
exact-build RVAs, recovered functions, instructions, exports, call edges, and
other PE evidence. WinDissect correctly refuses to emit unsafe x86 Rust callable
wrappers until per-function calling conventions are proven.

## Build and Run

```powershell
pwsh -File scripts/build-release.ps1
target\release\hsgaurdian.exe
```

For development:

```powershell
cargo build --workspace
target\debug\hsgaurdian.exe
```

## Next Milestone

- Recover and label gameplay systems from the retained HCR instruction graph.
- Add dynamic data breakpoints for true “what writes/accesses this address”
  tracing.
- Prove x86 calling conventions and parameters for selected functions.
- Generate safe typed wrappers over the exact-build RVA layer.
- Generate a compileable HCR mod project and local loader/runtime.
- Add build guards so a mod refuses to load against an unknown game version.
- Grow this into a local single-player modding SDK capable of substantial
  gameplay changes and, later, private multiplayer experiments.

## Commits

- `c8af605` — Port process memory scanner to Rust.
- `4614845` — Build WinDissect live patching UI.
- `19f9cd4` — Add refined value scanning and custom UI.
- `d9b7aff` — Vendor WinDissect and add the HCR SDK pipeline.
