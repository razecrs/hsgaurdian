# Semantic recovery fixture

This owned MSVC x64 ABI fixture supplies exact-build ground truth for semantic
precision testing. The checked-in oracle is tied to the SHA-256 of the locally
built DLL; rebuilding requires updating that identity deliberately.

The fixture intentionally covers multiple inheritance, three vtables, a pure
interface, a union, bitfields, an enum, a typedef alias, a callback, overrides,
and exact exported size/offset oracles. The alias is an abstention case rather
than a scored recovery fact because the current parser does not expose
CodeView `LF_ALIAS` records.

The validation pipeline is:

```powershell
cl /nologo /std:c++20 /Zi /Od /EHsc- /GR /c fixture.cpp /Fofixture.obj
link /nologo /dll /noentry /debug /out:semantic_fixture.dll /pdb:semantic_fixture.pdb fixture.obj
windissect extract semantic_fixture.dll --pdb semantic_fixture.pdb --out fixture.json
windissect refine --semantic --ir fixture.json --binary semantic_fixture.dll `
  --out refine.json --out-ir fixture.semantic.json --semantic-out semantic
windissect score-semantic --ir fixture.semantic.json --oracle ground_truth.json `
  --precision-threshold 0.999 --out semantic/score.json
```

`clang-cl` is also useful as an adversarial producer: its default CodeView
output may contain only forward UDT records. Windissect must abstain from
promoting those records as complete layouts.
