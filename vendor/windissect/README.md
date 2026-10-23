# Windissect

Windissect turns a Windows PE binary (DLL, EXE or SYS) and its matching
Microsoft PDB into a build-anchored, machine-readable map of that binary's
internals, then generates C, C++ and Rust you can build against.

It only emits what it can prove. Every fact carries its evidence, and anything
that isn't proven stays marked as a candidate instead of showing up as a
callable declaration. When Windows updates, Windissect records the new build
and diffs it against the last one.

## ReWindows

Windissect's output for Windows system DLLs is published in the
[ReWindows](https://github.com/ReWindows) organization, one repository per DLL
(`dwmcore`, `uDWM`, `dcomp`, `twinui`, `twinui.pcshell`, `comctl32`,
`uxtheme`, `taskbar` and 130+ more). Each repository has a `history/` archive
of every build observed, plus C/C++ headers and Rust FFI crates where the
evidence supports them. If you only need the data, start there.

## What it produces

- JSON IR for exports and private PDB procedures, tied to the exact build
  (image SHA-256, timestamp, PDB GUID and age)
- MSVC-demangled signatures parsed into structured C++ types
- function sizes, implementation hashes, call edges and imported APIs
- class layouts, inheritance, vtable slot order and enum values, verified
  against the binary and round-tripped through a compiler
- C/C++ headers and Rust FFI crates, split into verified and candidate output
- typed call helpers for x64, emitted only when both the address and the
  signature are proven
- C symbol tables with RVAs
- per-build history and semantic diffs between Windows builds

Generated headers compile as C17, C23, C26 draft, C++17, C++20, C++23 and
C++26 draft.

## How it compares

On `dui70.dll` (DirectUI), against the hand-maintained DirectUI headers in
ExplorerPatcher:

| | Windissect | ExplorerPatcher |
|---|---:|---:|
| Classes | 766 | 350 |
| Declarations | 7,532 | 4,095 |
| Generated headers | 396 | 159 |
| Verified vtables | 440 | n/a |
| Verified vtable slots | 8,370 | n/a |
| Rust bindings | yes | no |

Extracting the DLL and PDB takes about 2 seconds, and semantic refinement about
14 seconds.

## Quick start

On Windows with Rust installed:

```powershell
pwsh -File scripts/demo.ps1
```

This analyzes your installed `amsi.dll`, verifies the IR, and writes C, C++,
Rust, symbol and evidence output to `target/demo/amsi/`. See
[docs/quickstart.md](docs/quickstart.md) for the full DirectUI run.

## Analyze one binary

```powershell
cargo build --release
$wd = "target\release\windissect"

& $wd extract C:\Windows\System32\dwmapi.dll --pdb dwmapi.pdb --out ir\dwmapi.json
& $wd verify --ir ir\dwmapi.json
& $wd emit-headers --ir ir\dwmapi.json --out headers\dwmapi
& $wd emit-rust --ir ir\dwmapi.json --out rust\dwmapi-sys
& $wd emit-syms --ir ir\dwmapi.json --out syms
& $wd refine --semantic --ir ir\dwmapi.json --binary C:\Windows\System32\dwmapi.dll `
    --out refinement\dwmapi.json --out-ir ir\dwmapi.semantic.json --semantic-out semantic\dwmapi
```

The PDB is optional. Without one you get exports only, and private types are
reported as unavailable rather than guessed.

`emit-headers` writes `<target>.h` with verified ABI metadata and proven call
helpers only. Everything else Windissect reconstructed goes into
`<target>_candidates.h`, which is opt-in and not ABI-safe.

`refine --semantic` also writes a recovery plan (`recovery-plan.json` and
`recovery-plan.md`) listing each unresolved fact and the evidence that would
settle it.

## Track Windows builds

```powershell
& $wd record-build ir\dwmapi.json --history history
& $wd diff ir\old\dwmapi.json ir\new\dwmapi.json --json-out changes.json --markdown-out changes.md
```

The history layout is plain files, so it can be served from any static host:

```text
history/index.json
history/<target>/index.json
history/<target>/builds/<timestamp-guid-age>/ir.json
history/<target>/changes/<old>__<new>.json
history/<target>/changes/<old>__<new>.md
```

Diffs separate added and removed symbols from signature, implementation,
call-graph, import, size and export changes. RVA moves are tracked on their
own, so address churn doesn't look like a behavior change.

## Run the whole fleet

`windissect-fleet` processes a list of binaries in one go: it finds each one
on your machine, downloads the exact PDB from Microsoft's symbol server,
extracts, verifies, records history and generates headers and Rust crates.
Runs are incremental, so after a Windows update the same command picks up only
what changed.

```powershell
cargo build --release
go build -o bin\windissect-fleet.exe .\cmd\windissect

# small test run
bin\windissect-fleet.exe --root corpus --manifest manifests\example.json

# the built-in Windows UI list (33 targets, large PDB downloads the first time)
bin\windissect-fleet.exe --root corpus
```

What it processes is controlled by a JSON manifest. See
[docs/fleet.md](docs/fleet.md) for the manifest format, commands, output layout
and troubleshooting, or run `bin\windissect-fleet.exe help`.

This repository doesn't include any Microsoft binaries or PDBs.

## Documentation

- [Architecture](docs/architecture.md): pipeline, trust rules, module map
- [Output status](docs/output-status.md): what counts as verified and what doesn't
- [Quick start](docs/quickstart.md): AMSI and DUI70 walkthroughs
- [Fleet runs](docs/fleet.md): manifests, batch runs, output layout
- [Known issues](docs/known-issues.md)
- [Release notes](RELEASE.md)

## License

Windissect is licensed under the [GNU Affero General Public License v3.0](LICENSE).

For a commercial license (using Windissect in closed-source products or
services without the AGPL terms), contact raze.crs@proton.me.
