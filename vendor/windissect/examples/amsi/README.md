# AMSI validation target

AMSI is the small, unrelated validation target for Windissect's generic path.
It exercises a security component rather than the DirectUI corpus.

Run `pwsh -File scripts/demo.ps1` from the repository root. The input comes
from the local Windows installation; Microsoft binaries are not redistributed.

The v0.1.0 validation machine used `amsi.dll` version
`10.0.26100.7309`, SHA-256
`9df7ad9e6826ab76294a91bef274696ee13d18a8cebabcd5c4c352a3d1141df3`.
The export-only run recovered 14 exports and produced compiling C, C++, and
Rust artifacts. Because no matching PDB was supplied, private types and
procedures are explicitly reported as unavailable rather than inferred.

