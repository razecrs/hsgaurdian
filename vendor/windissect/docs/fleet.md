# Fleet runs

`windissect-fleet` runs Windissect over many binaries at once. For each target
it finds the binary on your machine, downloads the exact matching PDB from
Microsoft's symbol server, extracts and verifies the IR, records it in build
history, and then generates headers and Rust crates. This is how the
[ReWindows](https://github.com/ReWindows) corpus is produced.

## Requirements

- Windows (it reads binaries from your own install)
- Rust, to build `windissect.exe`
- Go 1.26 or newer, to build the fleet
- Internet access to `msdl.microsoft.com` for PDBs

## Build

From the repository root:

```powershell
cargo build --release
go build -o bin\windissect-fleet.exe .\cmd\windissect
```

## First run

Try a small manifest before the full list:

```powershell
bin\windissect-fleet.exe --root corpus --manifest manifests\example.json
```

When it finishes, open `corpus\compat-report.md` to see what was processed.
Leave out `--manifest` to run the built-in Windows UI list of 33 targets.
Some of those PDBs are large, so the first run takes a while.

## What it processes

The fleet picks targets in this order:

1. **Binary arguments.** `windissect-fleet pull dwmapi.dll D:\samples\foo.dll`
   processes only those files. A bare file name is looked up in System32 (and
   then in `<root>\probe`), a path is used as given. All of them are required.
2. **`--manifest FILE`.** The targets listed in that file.
3. **Neither.** The built-in Windows UI list. `manifests/windows-ui.json` has
   the same list if you want to copy and edit it.

`--only id1,id2` narrows options 2 and 3 down to the listed ids. An unknown id
is an error.

## Manifest format

```json
{
  "schema": 1,
  "targets": [
    { "id": "dwmapi", "file": "dwmapi.dll", "source": "system32", "area": "dwm", "required": true },
    { "id": "Taskbar.View", "file": "Taskbar.View.dll", "source": "client-core-system-app", "area": "taskbar", "required": false },
    { "id": "mydriver", "file": "D:\\samples\\mydriver.sys", "required": false }
  ]
}
```

| Field | Meaning |
|---|---|
| `schema` | Always `1` |
| `id` | Unique name. Used for output folders and `--only` |
| `file` | File name, or a full path to use as is (then `source` is ignored) |
| `source` | Where to look for a bare file name (see below). Default `system32` |
| `area` | Free-form label, copied into the report |
| `required` | If `true`, a missing or failed target makes the run exit with 1. If `false`, it's reported and skipped |

| `source` | Looks in |
|---|---|
| `system32` | `%SystemRoot%\System32`, then `<root>\probe` |
| `windows` | `%SystemRoot%` |
| `start-menu-system-app` | `%SystemRoot%\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy` |
| `client-core-system-app` | `%SystemRoot%\SystemApps\MicrosoftWindows.Client.Core_cw5n1h2txyewy` |
| `windows-app-runtime-x64` | Newest `Microsoft.WindowsAppRuntime` package in `WindowsApps` or `SystemApps` |
| `notepad-app-x64` | Installed Notepad app package |

To analyze a binary that isn't installed, copy it into `<root>\probe` and use
`system32` with its file name, or give its full path.

## Commands

| Command | What it does |
|---|---|
| `all` (default) | `pull`, then `emit` |
| `pull` | Extract, download the PDB, extract again with it, verify, write `ir\<id>.json`, record history |
| `emit` | Verify and generate headers and a Rust crate for **every** `.json` in `<root>\ir`, not just the current targets |
| `help` | Print usage |

## Options

| Option | Default | Meaning |
|---|---|---|
| `--root DIR` | repository root | Where all output goes |
| `--extractor PATH` | `target\release\windissect.exe` | Windissect binary to run |
| `--manifest FILE` | built-in list | Target list |
| `--only IDS` | all | Comma-separated ids to process |

Use `--root` so output doesn't mix with the source tree. The default output
folders are gitignored, but a separate folder is easier to publish or delete.

## Output

```text
<root>\
  compat-index.json       every target: status, source path, SHA-256, PDB identity
  compat-report.md        the same as a table
  ir\<id>.json            verified IR
  history\...             per-build snapshots and diffs (see the README)
  headers\<id>\           C/C++ headers
  rust\<id>\              Rust crate
  probe\symbols\<pdb>\<GUID+age>\<pdb>   PDB cache
```

Target statuses:

| Status | Meaning |
|---|---|
| `verified-pdb` | Extracted with the exact PDB and verified |
| `verified-static` | Verified without a PDB (none published for this build) |
| `failed-required` | Required target missing or failed. Run exits with 1 |
| `failed-optional` | Optional target failed |
| `unavailable-optional` | Optional target isn't installed |

## Re-runs and Windows updates

Runs are incremental. A target is skipped when its IR already exists and the
binary's SHA-256 still matches the index. PDBs are cached by GUID and age, so
nothing is downloaded twice. The index merges with earlier runs, so `--only`
doesn't drop other targets from it.

After a Windows update, run the same command again. Changed binaries get
extracted, a new build is added to `history\`, and a diff against the previous
build is written next to it.

## If something fails

- **`extractor not found`**: run `cargo build --release` or pass `--extractor`.
- **`HTTP 404` for a PDB**: Microsoft hasn't published symbols for that exact
  build. The target is still verified without a PDB (`verified-static`).
- **`binary not installed`**: the file isn't on this machine. Mark it
  `"required": false` or remove it from your manifest.
- **`pass 1 failed` / `pass 2 failed`**: the extractor error is printed after
  it. Run `windissect extract <file>` directly to reproduce.
