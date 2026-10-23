//! Archive-side commands: dependency graphs, symbol-server keys, corpus
//! manifests and catalogues.
//!
//! These existed as throwaway scripts beside the tool - an objdump shell-out for
//! a dependency graph, a Python PE parser for symbol keys, another for
//! manifests. Every one of them re-implemented something the extractor already
//! does, and each was one more thing to install before you could use windissect.
//! They belong behind the same binary.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use goblin::pe::PE;
use serde::Serialize;

use crate::model::Database;

/// Extensions the PE loader will map. Anything else is not ours to read.
const PE_EXTENSIONS: &[&str] = &[
    "dll", "exe", "sys", "ocx", "cpl", "scr", "drv", "efi", "ax", "acm", "tsp", "mun", "winmd",
];

fn is_pe_path(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| PE_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
}

fn stem_of(path: &Path) -> String {
    path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string()
}

/// Read an IR database, with the path in the error so a bad file in a batch of
/// two hundred can be identified.
fn load_ir(path: &Path) -> Result<Database> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

/// Collect files under a root, one level deep or recursively, without following
/// symlinks - a link out of the tree would silently widen the scan.
fn collect_files(root: &Path, recursive: bool, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries =
        fs::read_dir(root).with_context(|| format!("read directory {}", root.display()))?;
    for entry in entries {
        let entry = entry?;
        let meta = entry.metadata()?;
        if meta.file_type().is_symlink() {
            continue;
        }
        let path = entry.path();
        if meta.is_dir() {
            if recursive {
                collect_files(&path, recursive, out)?;
            }
        } else if is_pe_path(&path) {
            out.push(path);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// wd deps
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct GraphNode {
    id: String,
    /// Whether this module has an IR in the set, or is only named by an import.
    extracted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    symbols: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    image_size: Option<u64>,
    in_degree: usize,
    out_degree: usize,
}

#[derive(Serialize)]
struct Graph {
    schema: u32,
    nodes: Vec<GraphNode>,
    edges: Vec<[usize; 2]>,
}

/// Build a module dependency graph from a set of IR databases.
pub fn deps_command(irs: &[PathBuf], out: Option<&Path>, recursive: bool) -> Result<()> {
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in irs {
        if entry.is_dir() {
            let mut found = Vec::new();
            collect_json(entry, recursive, &mut found)?;
            files.extend(found);
        } else {
            files.push(entry.clone());
        }
    }
    if files.is_empty() {
        bail!("no IR databases found; pass .json files or a directory containing them");
    }

    // Keyed case-insensitively: an import names "KERNEL32.dll" where the IR
    // says "kernel32.dll", and they are one module.
    let mut index: BTreeMap<String, usize> = BTreeMap::new();
    let mut nodes: Vec<GraphNode> = Vec::new();
    let mut pending: Vec<(usize, Vec<String>)> = Vec::new();

    let node_for =
        |index: &mut BTreeMap<String, usize>, nodes: &mut Vec<GraphNode>, name: &str| -> usize {
            let key = name.to_ascii_lowercase();
            if let Some(&i) = index.get(&key) {
                return i;
            }
            let i = nodes.len();
            nodes.push(GraphNode {
                id: name.to_string(),
                extracted: false,
                symbols: None,
                image_size: None,
                in_degree: 0,
                out_degree: 0,
            });
            index.insert(key, i);
            i
        };

    for path in &files {
        let db = match load_ir(path) {
            Ok(db) => db,
            Err(err) => {
                eprintln!("[!] skipping {}: {err:#}", path.display());
                continue;
            }
        };
        let name = Path::new(&db.binary.file)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(&db.binary.file)
            .to_string();
        let i = node_for(&mut index, &mut nodes, &name);
        nodes[i].extracted = true;
        nodes[i].symbols = Some(db.symbols.len());
        nodes[i].image_size = db.binary.image_size;
        pending.push((i, db.binary.dependencies.clone()));
    }

    let mut seen: BTreeSet<(usize, usize)> = BTreeSet::new();
    let mut edges: Vec<[usize; 2]> = Vec::new();
    for (from, deps) in pending {
        for dep in deps {
            let dep_stem = Path::new(&dep)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or(&dep)
                .to_string();
            let to = node_for(&mut index, &mut nodes, &dep_stem);
            if from == to || !seen.insert((from, to)) {
                continue;
            }
            edges.push([from, to]);
        }
    }
    for e in &edges {
        nodes[e[0]].out_degree += 1;
        nodes[e[1]].in_degree += 1;
    }

    let graph = Graph {
        schema: 1,
        nodes,
        edges,
    };
    let extracted = graph.nodes.iter().filter(|n| n.extracted).count();
    let json = serde_json::to_vec_pretty(&graph)?;
    match out {
        Some(path) => {
            crate::diff::atomic_write(path, &json)?;
            println!(
                "{} nodes ({} extracted, {} referenced only), {} edges -> {}",
                graph.nodes.len(),
                extracted,
                graph.nodes.len() - extracted,
                graph.edges.len(),
                path.display()
            );
        }
        None => println!("{}", String::from_utf8_lossy(&json)),
    }
    Ok(())
}

fn collect_json(root: &Path, recursive: bool, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(root).with_context(|| format!("read {}", root.display()))? {
        let entry = entry?;
        let meta = entry.metadata()?;
        if meta.file_type().is_symlink() {
            continue;
        }
        let path = entry.path();
        if meta.is_dir() {
            if recursive {
                collect_json(&path, recursive, out)?;
            }
        } else if path.extension().and_then(|e| e.to_str()) == Some("json") {
            out.push(path);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// wd symbols
// ---------------------------------------------------------------------------

/// The key Microsoft's symbol server indexes a PDB by: the GUID printed in
/// canonical field order with the age appended in hex.
///
/// A GUID is not sixteen opaque bytes. Its first three fields are stored
/// little-endian, so hexdumping the `CodeView` signature gives 375A541A1EEB9A41...
/// where the server wants 1A545A37EB1E419A... - the same bytes, wrong order,
/// and a 404 every time.
pub fn symbol_key_from_signature(signature: &[u8; 16], age: u32) -> String {
    let d1 = u32::from_le_bytes([signature[0], signature[1], signature[2], signature[3]]);
    let d2 = u16::from_le_bytes([signature[4], signature[5]]);
    let d3 = u16::from_le_bytes([signature[6], signature[7]]);
    let rest = crate::hex::upper(&signature[8..16]);
    format!("{d1:08X}{d2:04X}{d3:04X}{rest}{age:X}")
}

#[derive(Serialize)]
struct SymbolReport {
    file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pdb_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    /// Absent unless the binary carries no `CodeView` record at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

/// Report where each binary's PDB lives on a symbol server.
///
/// Deliberately does no network I/O: it answers "what is the address" so the
/// downloader - which already exists and already retries and caches - can
/// answer "is it there". Splitting those keeps this usable offline and keeps a
/// second HTTP stack out of the analysis binary.
pub fn symbols_command(paths: &[PathBuf], server: &str, json_out: bool) -> Result<()> {
    let mut targets: Vec<PathBuf> = Vec::new();
    for p in paths {
        if p.is_dir() {
            collect_files(p, false, &mut targets)?;
        } else {
            targets.push(p.clone());
        }
    }
    if targets.is_empty() {
        bail!("no PE files found in the given paths");
    }

    let mut reports = Vec::new();
    let (mut have, mut missing) = (0usize, 0usize);
    for path in &targets {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(err) => {
                eprintln!("[!] {}: {err}", path.display());
                continue;
            }
        };
        let pe = match PE::parse(&bytes) {
            Ok(pe) => pe,
            Err(err) => {
                eprintln!("[!] {}: not a PE ({err})", path.display());
                continue;
            }
        };
        let cv = pe
            .debug_data
            .as_ref()
            .and_then(|d| d.codeview_pdb70_debug_info.as_ref());
        let report = cv.map_or_else(
            || SymbolReport {
                file: stem_of(path),
                pdb_name: None,
                key: None,
                url: None,
                note: Some("no CodeView record; this binary ships without symbols".into()),
            },
            |dbg| {
                let name = String::from_utf8_lossy(dbg.filename)
                    .trim_end_matches('\0')
                    .replace('\\', "/");
                let name = Path::new(&name)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown.pdb")
                    .to_string();
                let key = symbol_key_from_signature(&dbg.signature, dbg.age);
                SymbolReport {
                    file: stem_of(path),
                    url: Some(format!(
                        "{}/{name}/{key}/{name}",
                        server.trim_end_matches('/')
                    )),
                    pdb_name: Some(name),
                    key: Some(key),
                    note: None,
                }
            },
        );
        if report.key.is_some() {
            have += 1;
        } else {
            missing += 1;
        }
        if !json_out {
            match (&report.pdb_name, &report.key) {
                (Some(n), Some(k)) => println!("  {:<38} {:<34} {}", report.file, n, k),
                _ => println!("  {:<38} no CodeView record", report.file),
            }
        }
        reports.push(report);
    }

    if json_out {
        println!("{}", serde_json::to_string_pretty(&reports)?);
    } else {
        println!(
            "\n  {have} of {} have symbol keys, {missing} without",
            have + missing
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// wd manifest
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ManifestTarget {
    id: String,
    file: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    area: String,
    required: bool,
}

#[derive(Serialize)]
struct Manifest {
    schema: u32,
    targets: Vec<ManifestTarget>,
}

/// Build a corpus manifest from a directory of binaries.
pub fn manifest_command(
    roots: &[PathBuf],
    area: &str,
    recursive: bool,
    out: Option<&Path>,
) -> Result<()> {
    let mut files = Vec::new();
    for root in roots {
        if root.is_dir() {
            collect_files(root, recursive, &mut files)?;
        } else if is_pe_path(root) {
            files.push(root.clone());
        }
    }
    if files.is_empty() {
        bail!("no PE files found under the given paths");
    }
    files.sort();

    // One target per module. The same DLL under two paths is one target, and
    // taking the first keeps the manifest stable across runs.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut targets = Vec::new();
    for path in files {
        let id = stem_of(&path).to_ascii_lowercase();
        if !seen.insert(id.clone()) {
            continue;
        }
        targets.push(ManifestTarget {
            id,
            file: path.to_string_lossy().replace('\\', "/"),
            area: area.to_string(),
            required: false,
        });
    }

    let manifest = Manifest { schema: 1, targets };
    let json = serde_json::to_vec_pretty(&manifest)?;
    match out {
        Some(path) => {
            crate::diff::atomic_write(path, &json)?;
            println!("{} targets -> {}", manifest.targets.len(), path.display());
        }
        None => println!("{}", String::from_utf8_lossy(&json)),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// wd catalog
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct CatalogBuild {
    key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pdb_guid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    image_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    ir_bytes: u64,
}

#[derive(Serialize)]
struct CatalogModule {
    module: String,
    builds: Vec<CatalogBuild>,
}

#[derive(Serialize)]
struct Catalog {
    schema: u32,
    modules: Vec<CatalogModule>,
}

/// Summarise a history tree: every module, every archived build.
///
/// Reads only each record's header rather than deserialising the whole IR - a
/// full-depth record runs to hundreds of megabytes and a catalogue of two
/// hundred modules would otherwise need tens of gigabytes of memory to build.
pub fn catalog_command(history: &Path, out: Option<&Path>) -> Result<()> {
    if !history.is_dir() {
        bail!("{} is not a directory", history.display());
    }
    let mut modules = Vec::new();
    let mut entries: Vec<PathBuf> = fs::read_dir(history)?
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    entries.sort();

    for dir in entries {
        let builds_dir = dir.join("builds");
        if !builds_dir.is_dir() {
            continue;
        }
        let mut builds: Vec<PathBuf> = fs::read_dir(&builds_dir)?
            .filter_map(std::result::Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        builds.sort();

        let mut out_builds = Vec::new();
        for build in builds {
            let ir = build.join("ir.json");
            let Ok(meta) = fs::metadata(&ir) else {
                continue;
            };
            let head = read_head(&ir, 4096)?;
            out_builds.push(CatalogBuild {
                key: build
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string(),
                timestamp: field(&head, "timestamp"),
                pdb_guid: field(&head, "pdb_guid"),
                sha256: field(&head, "sha256"),
                image_size: field(&head, "image_size").and_then(|v| v.parse().ok()),
                ir_bytes: meta.len(),
            });
        }
        if !out_builds.is_empty() {
            modules.push(CatalogModule {
                module: stem_of(&dir),
                builds: out_builds,
            });
        }
    }

    let total: u64 = modules
        .iter()
        .flat_map(|m| m.builds.iter())
        .map(|b| b.ir_bytes)
        .sum();
    let build_count: usize = modules.iter().map(|m| m.builds.len()).sum();

    let catalog = Catalog { schema: 1, modules };
    let json = serde_json::to_vec_pretty(&catalog)?;
    match out {
        Some(path) => {
            crate::diff::atomic_write(path, &json)?;
            // Integer math for the "N.N GB" figure avoids a lossy u64->f64 cast:
            // whole gigabytes, then one tenth from the remainder.
            let whole = total / 1_000_000_000;
            let tenth = (total % 1_000_000_000) / 100_000_000;
            println!(
                "{} modules, {} builds, {whole}.{tenth} GB of IR -> {}",
                catalog.modules.len(),
                build_count,
                path.display()
            );
        }
        None => println!("{}", String::from_utf8_lossy(&json)),
    }
    Ok(())
}

/// First `n` bytes of a file, for reading a JSON header without loading the body.
fn read_head(path: &Path, n: usize) -> Result<String> {
    use std::io::Read;
    let mut f = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut buf = vec![0u8; n];
    let read = f.read(&mut buf)?;
    buf.truncate(read);
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Pull one scalar JSON field out of a header fragment.
fn field(head: &str, name: &str) -> Option<String> {
    let needle = format!("\"{name}\":");
    let start = head.find(&needle)? + needle.len();
    let rest = head[start..].trim_start();
    if let Some(stripped) = rest.strip_prefix('"') {
        stripped.find('"').map(|end| stripped[..end].to_string())
    } else {
        let end = rest.find([',', '}'])?;
        let value = rest[..end].trim();
        if value == "null" {
            None
        } else {
            Some(value.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The byte order that cost a 404: little-endian fields, printed canonically.
    #[test]
    fn signature_key_reorders_the_guid_fields() {
        let sig: [u8; 16] = [
            0x1A, 0x54, 0x5A, 0x37, 0xEB, 0x1E, 0x41, 0x9A, 0xB8, 0x35, 0xE9, 0x4A, 0x8F, 0x18,
            0xF0, 0x77,
        ];
        // Bytes as written would hexdump to 1A545A37EB1E419A..., and the first
        // three fields read little-endian give the server's key.
        assert_eq!(
            symbol_key_from_signature(&sig, 1),
            "375A541A1EEB9A41B835E94A8F18F0771"
        );
    }

    #[test]
    fn age_is_appended_in_hex_not_decimal() {
        let sig = [0u8; 16];
        assert!(symbol_key_from_signature(&sig, 10).ends_with('A'));
        assert!(symbol_key_from_signature(&sig, 1).ends_with('1'));
    }

    #[test]
    fn field_reads_strings_and_numbers() {
        let head = r#"{"binary":{"file":"a.dll","timestamp":"123","image_size":4096}}"#;
        assert_eq!(field(head, "timestamp").as_deref(), Some("123"));
        assert_eq!(field(head, "image_size").as_deref(), Some("4096"));
        assert_eq!(field(head, "absent"), None);
    }

    #[test]
    fn field_treats_null_as_absent() {
        assert_eq!(field(r#"{"pdb_guid":null}"#, "pdb_guid"), None);
    }

    #[test]
    fn pe_extensions_are_recognised_case_insensitively() {
        assert!(is_pe_path(Path::new("X.DLL")));
        assert!(is_pe_path(Path::new("driver.sys")));
        assert!(is_pe_path(Path::new("Windows.UI.Xaml.winmd")));
        assert!(!is_pe_path(Path::new("icon.png")));
        assert!(!is_pe_path(Path::new("noextension")));
    }
}
