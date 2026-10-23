# Known issues

## Verified vtables don't verify the base class relationship

A class can have every vtable slot verified and still stay `candidate` because
its inheritance link is unverified. On `dui70.dll`, `DirectUI::HWNDElement`
and `DirectUI::HWNDHost` both stay candidates because their link to
`DirectUI::ElementWithHWND` isn't proven.

Two of the three evidence routes can't work on this binary. `dui70.dll` has no
RTTI (built with `/GR-`), and the compiler inlined the base constructor, so
there's no constructor call to follow. The PDB base class record is the only
route left, and it isn't wired into base relationship promotion yet.

## Some factory functions never get a callable proof

`DirectUI::Button::Create` has a full signature in the PDB and its class has
all 47 vtable slots verified, but the callable-proof pass never picks it up.
`HWNDElement::Create`, which has the same shape, does get proven. The
selection logic for that pass needs a closer look.

Plain C exports with no PDB type info, like `InitProcessPriv` and
`InitThread`, can't be proven either, since nothing Windissect collects today
describes their arguments. Recovering argument counts from disassembly would
give them an evidence route.
