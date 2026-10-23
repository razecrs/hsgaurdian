# Output status

Every fact has two labels: how well the evidence supports it, and whether an
emitter is allowed to expose it as usable code.

## Verified

- PE/PDB identity and build anchors
- exports, ordinals, forwarders, and procedure names from a matching PDB
- IR graph integrity and passed proof obligations
- x86/x64 instruction decoding
- compatible vftable slots and the call helpers built on them
- `verified.json` from `emit-evidence`
- class sizes, field offsets and widths, bitfields, inheritance offsets,
  virtual slot order, and enum values and underlying types from a full
  matching PDB, after the compiler check passes
- the primary `<target>.h`, which contains only verified ABI metadata and
  proven call helpers

## Candidate or metadata-only

- heuristic member offsets without a certified evidence pack
- reflection properties that haven't been corroborated
- template-derived base classes without proven offsets
- incompatible ICF or vftable candidates
- IDA/r2 observations until an analyzer proves the higher-level claim
- CodeView aliases (`LF_ALIAS`), which the PDB parser doesn't read yet
- ARM64 and ARM64EC semantic recovery
- runtime probing of SYS files (static SYS analysis is supported)
- class declarations in `<target>_candidates.h`

Candidate data is still useful for reversing and in annotated assembly. It just
isn't presented as an ABI-safe declaration.
