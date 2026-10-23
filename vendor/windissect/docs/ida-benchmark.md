# Function recovery against IDA

Without a PDB, Windissect recovers function entry points and extents from the
binary alone. This page measures that recovery against IDA Professional 9.4
on the same binaries, with IDA's PDB loading turned off so both tools work
from the image only.

## Method

Each binary is copied from a Windows 11 install (build 10.0.26300) and run
through both tools:

- `windissect extract <binary>` with no `--pdb`
- `idat -A -Opdb:off` with `scripts/ida-export-functions.py`, which exports
  every function IDA's auto-analysis created

`scripts/compare-ida-functions.py` matches the two by start RVA.
`scripts/ida-benchmark.ps1` runs the whole set and writes a summary table:

```powershell
.\scripts\ida-benchmark.ps1 -Binaries C:\Windows\System32\uxtheme.dll, C:\Windows\SysWOW64\uxtheme.dll -OutDir bench
```

- **Recall** is the share of IDA's function starts Windissect also reports.
- **Precision** is the share of Windissect's starts that IDA also reports.
- **Exact extents** covers functions whose extent comes from x64 unwind
  records, which Windissect marks exact. x86 images have no such records.
- **All sizes** covers every matched function with a size, including extents
  measured by following control flow.

## Results

| Binary | Arch | IDA functions | Recall | Precision | Exact extents identical | All sizes identical |
|---|---|---:|---:|---:|---:|---:|
| `afd.sys` | x64 | 1,165 | 99.9% | 89.8% | 95.9% | 95.9% |
| `cng.sys` | x64 | 1,643 | 99.9% | 98.6% | 91.7% | 91.7% |
| `comctl32.dll` | x64 | 1,635 | 99.9% | 97.9% | 99.9% | 98.0% |
| `dui70.dll` | x64 | 6,616 | 96.4% | 99.7% | 99.6% | 97.4% |
| `dwmcore.dll` | x64 | 12,132 | 99.5% | 99.9% | 99.7% | 93.6% |
| `kernelbase.dll` | x64 | 5,944 | 96.0% | 97.2% | 98.7% | 94.2% |
| `notepad.exe` | x64 | 521 | 94.4% | 99.4% | 98.2% | 98.0% |
| `ntdll.dll` | x64 | 4,372 | 99.9% | 93.8% | 99.7% | 93.5% |
| `twinapi.dll` | x64 | 5,563 | 91.5% | 99.8% | 98.7% | 97.9% |
| `user32.dll` | x64 | 3,070 | 99.1% | 96.6% | 99.6% | 95.3% |
| `uxtheme.dll` | x64 | 2,015 | 94.8% | 99.5% | 99.5% | 95.6% |
| `comctl32.dll` | x86 | 1,858 | 99.1% | 98.6% | n/a | 97.2% |
| `dui70.dll` | x86 | 6,518 | 99.5% | 99.5% | n/a | 99.5% |
| `kernelbase.dll` | x86 | 7,180 | 97.5% | 98.5% | n/a | 95.5% |
| `notepad.exe` | x86 | 626 | 97.1% | 99.8% | n/a | 92.8% |
| `ntdll.dll` | x86 | 4,452 | 98.0% | 96.0% | n/a | 92.8% |
| `twinapi.dll` | x86 | 5,528 | 97.9% | 94.1% | n/a | 97.1% |
| `user32.dll` | x86 | 6,495 | 53.2% | 99.3% | n/a | 97.0% |
| `uxtheme.dll` | x86 | 2,128 | 97.8% | 96.2% | n/a | 97.8% |

## Where the sources come from

Entry points come from records the linker or loader relies on: the export
table, the image entry point, x64 unwind records and their handlers, the
Guard CF function table and the x86 SafeSEH handler table. Functions reached
from those by following direct calls and thunk jumps are added as `Likely`.
On x64 an unwind record gives the exact extent; anything without one, and
every x86 function, gets the contiguous body found by following its branches.

## Reading the differences

The two tools disagree in both directions, and most of it is policy rather
than error.

- **Starts only Windissect reports** are almost all backed by a primary unwind
  record (x64) or a SafeSEH entry (x86): exception funclets, `__ehhandler`
  stubs, fast-fail stubs and dispatch thunks. IDA folds these into a
  neighbouring function or leaves them unanalysed. This is what lowers
  precision on `afd.sys` and `ntdll.dll`.
- **Starts only IDA reports** are mostly small stubs that nothing in the image
  references: no export, relocation, call or table entry. IDA finds them by
  scanning unclaimed code for prologue patterns. Windissect does not report
  code it has no evidence for, which is why x86 `user32.dll` stops at 53%: it
  has about 2,200 such stubs under 16 bytes.
- **Extent differences** on matched functions are mostly a few bytes at the
  end of exception funclets, where IDA's range runs past the unwind record.

## Open items

- Exact extents on the two drivers agree less often (92% and 96%) than on the
  DLLs (98% and up). The cause hasn't been looked at yet.
- x64 switch tables aren't followed, so a function without an unwind record
  that dispatches through one is measured short.
