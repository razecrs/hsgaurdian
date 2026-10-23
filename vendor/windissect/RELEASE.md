# Windissect v0.1.0

## Verified release gates

- schema-v2 generic and DUI70 profile verification: 18/18
- proof graph: 2,690 evidence records, 2,690 claims, 2,345 proofs,
  39 retained conflicts, and no duplicate or dangling IDs
- Rust tests: 21 passed
- `cargo clippy --all-targets -- -D warnings`: passed
- Go orchestration tests and `go vet ./...`: passed
- 395 generated DUI70 C++ headers compile as C++17
- aggregate output compiles as C17, C23, C26 draft, C++17, C++20, C++23,
  C++26 draft, and the Windissect C20 bridge
- generated DUI70 Rust crate passes `cargo check --offline`
- unrelated AMSI export-only outputs compile in the same suite

## Canonical deep-case artifact

The canonical `ir/dui70.json` is a 143.2 MiB build-anchored schema-v2 corpus
designed for distribution separately from the source repository. The verified
local artifact has SHA-256:

`700E80F5145404C1D6325E071869E3F7FD328420796FB38ADDABF14E418F209F`

Exact input identities:

- `dui70.dll`: `2878ECCC8351F19888DE58271684332F65BC103FC67664436F3DC26C30E16A5F`
- `DUI70.pdb`: `6AEA78E85D4286110DCB4FF1C6B360B196BB3AB82C5E0D9B40CFACBA3EF67091`
- PDB GUID+age: `1F9481899ABD1A4D518D17695D847D90+1`

## Artifact policy

Generated headers, Rust crates, documentation, analysis databases, downloaded
PDBs, and build history are reproducible working outputs and are excluded from
source control. The DUI70 corpus can be published as a release artifact, while
other targets can be reconstructed from locally supplied Windows binaries and
identity-matched PDBs. Manually established evidence under
`analysis/manual-layouts/` and the evidence-pack definitions are maintained as
versioned source material. The included x64 member-access evidence pack remains
draft and does not authorize callable output.
