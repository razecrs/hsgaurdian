# Quick start

## AMSI (no PDB needed)

On Windows with Rust installed:

```powershell
pwsh -File scripts/demo.ps1
```

This builds Windissect, analyzes your installed `amsi.dll` without a PDB,
verifies the IR, and writes evidence, C/C++ headers, a C symbol table and a
Rust crate to `target/demo/amsi/`.

AMSI has nothing to do with DirectUI, so this run shows the generic PE and
export path works on its own. Without a PDB there are no private types, and
Windissect reports them as unavailable instead of guessing.

## DUI70 (full run)

Microsoft binaries and PDBs aren't included. With a matching `dui70.dll` and
`DUI70.pdb`:

```powershell
cargo run --release -- extract .\dui70.dll --pdb .\DUI70.pdb --out target\demo\dui70.json
cargo run --release -- verify --ir target\demo\dui70.json --profile dui70
cargo run --release -- emit-evidence --ir target\demo\dui70.json --out target\demo\dui70-evidence
```

The v0.1.0 run on this build produced 12,672 symbols, 2,690 evidence records,
2,690 claims, 2,345 proofs, 39 recorded conflicts, 150 vftables and 1,870
member-access observations.
