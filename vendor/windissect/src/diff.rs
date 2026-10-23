//! Stable, website-friendly comparison of two Windissect IR databases.

use crate::model::{Database, Symbol};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    pub schema: u32,
    pub target: String,
    pub from: BuildRef,
    pub to: BuildRef,
    pub summary: DiffSummary,
    pub added: Vec<SymbolState>,
    pub removed: Vec<SymbolState>,
    pub modified: Vec<SymbolChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildRef {
    pub file: String,
    pub timestamp: Option<String>,
    pub pdb_guid: Option<String>,
    pub pdb_age: Option<u32>,
    pub machine: Option<String>,
    pub image_base: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiffSummary {
    pub old_symbols: usize,
    pub new_symbols: usize,
    pub added: usize,
    pub removed: usize,
    pub modified: usize,
    pub signature_changes: usize,
    pub implementation_changes: usize,
    pub call_graph_changes: usize,
    pub import_changes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolState {
    pub id: String,
    pub mangled: String,
    pub demangled: Option<String>,
    pub rva: u32,
    pub size: u32,
    pub kind: String,
    pub exported: bool,
    pub signature: String,
    pub body_hash: String,
    pub calls: Vec<String>,
    pub imports: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Changed(bool);

impl Changed {
    const fn new(value: bool) -> Self {
        Self(value)
    }

    const fn get(self) -> bool {
        self.0
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChangeFlags {
    pub signature: Changed,
    pub implementation: Changed,
    pub calls: Changed,
    pub imports: Changed,
    pub size: Changed,
    pub kind: Changed,
    pub export_status: Changed,
    /// Address movement is recorded but deliberately not considered behavioral.
    pub rva: Changed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolChange {
    pub id: String,
    pub flags: ChangeFlags,
    pub before: SymbolState,
    pub after: SymbolState,
}

pub fn compare(old: &Database, new: &Database) -> DiffReport {
    let old_map = symbol_map(old);
    let new_map = symbol_map(new);
    let old_ids: BTreeSet<_> = old_map.keys().cloned().collect();
    let new_ids: BTreeSet<_> = new_map.keys().cloned().collect();

    let added: Vec<_> = new_ids
        .difference(&old_ids)
        .filter_map(|id| new_map.get(id).cloned())
        .collect();
    let removed: Vec<_> = old_ids
        .difference(&new_ids)
        .filter_map(|id| old_map.get(id).cloned())
        .collect();
    let mut modified = Vec::new();

    for id in old_ids.intersection(&new_ids) {
        let before = &old_map[id];
        let after = &new_map[id];
        let flags = ChangeFlags {
            signature: Changed::new(before.signature != after.signature),
            implementation: Changed::new(
                !before.body_hash.is_empty()
                    && !after.body_hash.is_empty()
                    && before.body_hash != after.body_hash,
            ),
            calls: Changed::new(before.calls != after.calls),
            imports: Changed::new(before.imports != after.imports),
            size: Changed::new(before.size != after.size),
            kind: Changed::new(before.kind != after.kind),
            export_status: Changed::new(before.exported != after.exported),
            rva: Changed::new(before.rva != after.rva),
        };
        if flags.signature.get()
            || flags.implementation.get()
            || flags.calls.get()
            || flags.imports.get()
            || flags.size.get()
            || flags.kind.get()
            || flags.export_status.get()
            || flags.rva.get()
        {
            modified.push(SymbolChange {
                id: id.clone(),
                flags,
                before: before.clone(),
                after: after.clone(),
            });
        }
    }

    let summary = DiffSummary {
        old_symbols: old.symbols.len(),
        new_symbols: new.symbols.len(),
        added: added.len(),
        removed: removed.len(),
        modified: modified.len(),
        signature_changes: modified.iter().filter(|c| c.flags.signature.get()).count(),
        implementation_changes: modified
            .iter()
            .filter(|c| c.flags.implementation.get())
            .count(),
        call_graph_changes: modified.iter().filter(|c| c.flags.calls.get()).count(),
        import_changes: modified.iter().filter(|c| c.flags.imports.get()).count(),
    };

    DiffReport {
        schema: 1,
        target: new.binary.file.clone(),
        from: build_ref(old),
        to: build_ref(new),
        summary,
        added,
        removed,
        modified,
    }
}

fn symbol_map(db: &Database) -> BTreeMap<String, SymbolState> {
    let image_base = db.binary.image_base.unwrap_or_else(|| {
        db.symbols
            .iter()
            .filter(|s| s.vaddr != 0)
            .map(|s| s.vaddr)
            .min()
            .map_or(0, |v| v & !0xFFFF)
    });
    let mut groups: BTreeMap<String, Vec<&Symbol>> = BTreeMap::new();
    for symbol in &db.symbols {
        groups.entry(symbol.id.clone()).or_default().push(symbol);
    }
    let mut out = BTreeMap::new();
    for (id, mut symbols) in groups {
        symbols.sort_by_key(|s| (s.rva, s.vaddr, s.demangled.as_deref().unwrap_or("")));
        for (index, symbol) in symbols.into_iter().enumerate() {
            let key = if index == 0 {
                id.clone()
            } else {
                format!("{id}#alias{index}")
            };
            out.insert(key.clone(), state(&key, symbol, image_base));
        }
    }
    out
}

fn state(id: &str, symbol: &Symbol, image_base: u64) -> SymbolState {
    let mut calls = symbol.calls.clone();
    calls.sort();
    calls.dedup();
    let mut imports = symbol.imports.clone();
    imports.sort();
    imports.dedup();
    SymbolState {
        id: id.into(),
        mangled: symbol.mangled.clone(),
        demangled: symbol.demangled.clone(),
        rva: if symbol.rva != 0 {
            symbol.rva
        } else {
            symbol
                .vaddr
                .checked_sub(image_base)
                .and_then(|v| u32::try_from(v).ok())
                .unwrap_or(0)
        },
        size: symbol.size,
        kind: format!("{:?}", symbol.kind),
        exported: symbol.exported,
        signature: serde_json::to_string(&symbol.sig).unwrap_or_default(),
        body_hash: symbol.body_hash.clone(),
        calls,
        imports,
    }
}

fn build_ref(db: &Database) -> BuildRef {
    let raw_guid = db.binary.pdb_guid.as_deref();
    let (pdb_guid, pdb_age) = match raw_guid {
        Some(raw) if db.binary.pdb_age.is_none() && raw.len() > 32 => {
            (Some(raw[..32].to_string()), raw[32..].parse::<u32>().ok())
        }
        _ => (db.binary.pdb_guid.clone(), db.binary.pdb_age),
    };
    BuildRef {
        file: db.binary.file.clone(),
        timestamp: db.binary.timestamp.clone(),
        pdb_guid,
        pdb_age,
        machine: db.binary.machine.clone(),
        image_base: db.binary.image_base,
    }
}

pub fn write_json(report: &DiffReport, path: &Path) -> Result<()> {
    atomic_write(path, &serde_json::to_vec_pretty(report)?)
}

pub fn write_markdown(report: &DiffReport, path: &Path) -> Result<()> {
    atomic_write(path, markdown(report).as_bytes())
}

pub fn markdown(report: &DiffReport) -> String {
    let s = &report.summary;
    let mut out = format!(
        "# {} changes\n\nFrom `{}` to `{}`.\n\n| Metric | Count |\n|---|---:|\n| Added | {} |\n| Removed | {} |\n| Modified | {} |\n| Signature changes | {} |\n| Implementation changes | {} |\n| Call graph changes | {} |\n| Import changes | {} |\n",
        report.target,
        build_label(&report.from),
        build_label(&report.to),
        s.added,
        s.removed,
        s.modified,
        s.signature_changes,
        s.implementation_changes,
        s.call_graph_changes,
        s.import_changes
    );
    section(&mut out, "Added", report.added.iter().map(display_name));
    section(&mut out, "Removed", report.removed.iter().map(display_name));
    if !report.modified.is_empty() {
        out.push_str("\n## Modified\n\n| Symbol | Changes |\n|---|---|\n");
        for change in &report.modified {
            let mut flags = Vec::new();
            if change.flags.signature.get() {
                flags.push("signature");
            }
            if change.flags.implementation.get() {
                flags.push("implementation");
            }
            if change.flags.calls.get() {
                flags.push("calls");
            }
            if change.flags.imports.get() {
                flags.push("imports");
            }
            if change.flags.size.get() {
                flags.push("size");
            }
            if change.flags.kind.get() {
                flags.push("kind");
            }
            if change.flags.export_status.get() {
                flags.push("export-status");
            }
            if change.flags.rva.get() {
                flags.push("rva");
            }
            let _ = writeln!(
                out,
                "| `{}` | {} |",
                display_name(&change.after),
                flags.join(", ")
            );
        }
    }
    out
}

fn build_label(build: &BuildRef) -> String {
    format!(
        "{}+{}",
        build.pdb_guid.as_deref().unwrap_or("no-pdb"),
        build
            .pdb_age
            .map_or_else(|| "?".into(), |v| format!("{v:X}"))
    )
}

fn display_name(symbol: &SymbolState) -> &str {
    symbol.demangled.as_deref().unwrap_or(&symbol.mangled)
}

fn section<'a>(out: &mut String, title: &str, values: impl Iterator<Item = &'a str>) {
    let values: Vec<_> = values.collect();
    if values.is_empty() {
        return;
    }
    let _ = write!(out, "\n## {title}\n\n");
    for value in values {
        let _ = writeln!(out, "- `{value}`");
    }
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension().and_then(|e| e.to_str()).unwrap_or("data")
    ));
    std::fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("committing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, Coverage, Kind, Provenance, Signature, Symbol};

    fn symbol(id: &str, hash: &str, calls: &[&str]) -> Symbol {
        Symbol {
            id: id.into(),
            mangled: id.into(),
            demangled: Some(id.into()),
            vaddr: 0x0001_8000_1000,
            rva: 0x1000,
            ordinal: None,
            size: 4,
            procedure_size: Some(4),
            is_code: true,
            forwarder: None,
            body_hash: hash.into(),
            exported: true,
            library: false,
            kind: Kind::CFunc,
            coverage: Coverage::Auto,
            provenance: Provenance::PeExport,
            confidence: Confidence::Certain,
            sig: Signature::default(),
            callers: vec![],
            calls: calls.iter().map(|v| (*v).into()).collect(),
            imports: vec![],
        }
    }

    #[test]
    fn detects_add_remove_implementation_and_call_changes() {
        let mut old = Database::default();
        old.binary.file = "demo.dll".into();
        old.symbols = vec![
            symbol("kept", "aaa", &["old-call"]),
            symbol("removed", "x", &[]),
        ];
        let mut new = Database::default();
        new.binary.file = "demo.dll".into();
        new.symbols = vec![
            symbol("kept", "bbb", &["new-call"]),
            symbol("added", "y", &[]),
        ];
        let report = compare(&old, &new);
        assert_eq!(report.summary.added, 1);
        assert_eq!(report.summary.removed, 1);
        assert_eq!(report.summary.modified, 1);
        assert_eq!(report.summary.implementation_changes, 1);
        assert_eq!(report.summary.call_graph_changes, 1);
    }
}
