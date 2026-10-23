# Hill Climb Racing target profile

Validated against the installed Windows build `1.41.1.0` (`x86`).

## Current recovery

The vendored WinDissect build currently recovers from the shipping executable:

- 1,374 exact-build symbols/function candidates
- 1,374 retained function records in exhaustive mode
- 12,152 decoded instructions
- SafeSEH, entry-point, export, direct-call, control-flow, import, and RVA data
- A verified C17 RVA symbol table (`*_syms.c` and `*_syms.h`)

The generated C17 symbol table was compiled with Clang using `-Wall -Wextra
-Werror` during integration testing.

## PDB reality

The PE advertises `HillClimbRacing.pdb` with GUID/age key
`8AEA44D7979F416BA7740983E1A0A3BA1`, but the PDB is not shipped beside the game
and Microsoft's public symbol server returns 404 for that exact key. Therefore
WinDissect correctly marks type recovery as `unavailable-no-pdb`.

That means the current trustworthy SDK surface is RVA/symbol/instruction based.
Named private classes, fields, and calling conventions must be recovered from
independent evidence before they can become compileable typed wrappers.

## Workflow

1. Attach to `HillClimbRacing.exe`; HS Guardian detects the target as 32-bit.
2. Select the main executable module in the WinDissect tab.
3. Keep **exhaustive inventory** enabled and choose **Build full SDK**.
4. Use the generated C symbol table as the exact-build address layer.
5. Name and type recovered functions through evidence-backed refinement rather
   than hard-coding guessed declarations.

Value-search hits open in the hex/data inspector. They are not decoded as code;
use retained WinDissect xrefs or a future dynamic data breakpoint to navigate
from a value to the instruction that accesses it.
