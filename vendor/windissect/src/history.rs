//! Per-target, per-build IR archive and adjacent-build change reports.

use crate::diff::{self, DiffSummary};
use crate::model::Database;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HistoryIndex {
    pub schema: u32,
    pub target: String,
    pub latest: Option<String>,
    pub builds: Vec<BuildEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HistoryCatalog {
    pub schema: u32,
    pub targets: Vec<CatalogTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogTarget {
    pub target: String,
    pub file: String,
    pub index: String,
    pub latest: String,
    pub build_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildEntry {
    pub key: String,
    pub timestamp: Option<String>,
    pub pdb_guid: Option<String>,
    pub pdb_age: Option<u32>,
    pub machine: Option<String>,
    pub ir: String,
    pub previous: Option<String>,
    pub diff_json: Option<String>,
    pub diff_markdown: Option<String>,
    pub summary: Option<DiffSummary>,
}

pub struct RecordResult {
    pub target: String,
    pub key: String,
    pub previous: Option<String>,
    pub directory: PathBuf,
}

pub fn record(db: &Database, root: &Path, source_ir: Option<&Path>) -> Result<RecordResult> {
    let target = target_stem(&db.binary.file);
    let key = build_key(db);
    let target_dir = root.join(&target);
    let build_dir = target_dir.join("builds").join(&key);
    let ir_path = build_dir.join("ir.json");
    let index_path = target_dir.join("index.json");

    let mut index: HistoryIndex = if index_path.exists() {
        serde_json::from_slice(&std::fs::read(&index_path)?)
            .with_context(|| format!("reading {}", index_path.display()))?
    } else {
        HistoryIndex {
            schema: 1,
            target: db.binary.file.clone(),
            ..Default::default()
        }
    };

    let previous = index.latest.clone().filter(|old| old != &key);
    archive_ir(db, source_ir, &ir_path)?;

    let (normalized_guid, normalized_age) = pdb_identity(db);
    let mut entry = BuildEntry {
        key: key.clone(),
        timestamp: db.binary.timestamp.clone(),
        pdb_guid: normalized_guid,
        pdb_age: normalized_age,
        machine: db.binary.machine.clone(),
        ir: relative(&target_dir, &ir_path),
        previous: previous.clone(),
        diff_json: None,
        diff_markdown: None,
        summary: None,
    };

    if let Some(previous_key) = &previous {
        let old_path = target_dir.join("builds").join(previous_key).join("ir.json");
        let old: Database = serde_json::from_slice::<Database>(&std::fs::read(&old_path)?)
            .with_context(|| format!("reading previous build {}", old_path.display()))?;
        let old = old.migrate();
        let report = diff::compare(&old, db);
        let changes_dir = target_dir.join("changes");
        let base = format!("{previous_key}__{key}");
        let json_path = changes_dir.join(format!("{base}.json"));
        let md_path = changes_dir.join(format!("{base}.md"));
        diff::write_json(&report, &json_path)?;
        diff::write_markdown(&report, &md_path)?;
        entry.diff_json = Some(relative(&target_dir, &json_path));
        entry.diff_markdown = Some(relative(&target_dir, &md_path));
        entry.summary = Some(report.summary);
    }

    index.builds.retain(|build| build.key != key);
    index.builds.push(entry);
    index.latest = Some(key.clone());
    diff::atomic_write(&index_path, &serde_json::to_vec_pretty(&index)?)?;
    update_catalog(root, &target, &index)?;

    Ok(RecordResult {
        target,
        key,
        previous,
        directory: build_dir,
    })
}

fn archive_ir(db: &Database, source_ir: Option<&Path>, destination: &Path) -> Result<()> {
    if let Some(source) = source_ir {
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if destination.exists() {
            std::fs::remove_file(destination)?;
        }
        if std::fs::hard_link(source, destination).is_ok() {
            return Ok(());
        }
    }
    diff::atomic_write(destination, &serde_json::to_vec(db)?)
}

fn update_catalog(root: &Path, target: &str, index: &HistoryIndex) -> Result<()> {
    let path = root.join("index.json");
    let mut catalog: HistoryCatalog = if path.exists() {
        serde_json::from_slice(&std::fs::read(&path)?)?
    } else {
        HistoryCatalog {
            schema: 1,
            ..Default::default()
        }
    };
    catalog.targets.retain(|item| item.target != target);
    catalog.targets.push(CatalogTarget {
        target: target.into(),
        file: index.target.clone(),
        index: format!("{target}/index.json"),
        latest: index.latest.clone().unwrap_or_default(),
        build_count: index.builds.len(),
    });
    catalog.targets.sort_by(|a, b| a.target.cmp(&b.target));
    diff::atomic_write(&path, &serde_json::to_vec_pretty(&catalog)?)
}

fn build_key(db: &Database) -> String {
    let (guid, age_value) = pdb_identity(db);
    let guid = guid.as_deref().unwrap_or("no-pdb");
    let age = age_value.map_or_else(|| "0".into(), |v| format!("{v:X}"));
    let timestamp = db.binary.timestamp.as_deref().unwrap_or("unknown-time");
    safe(&format!("{timestamp}-{guid}-{age}"))
}

fn pdb_identity(db: &Database) -> (Option<String>, Option<u32>) {
    let Some(raw) = db.binary.pdb_guid.as_deref() else {
        return (None, db.binary.pdb_age);
    };
    if db.binary.pdb_age.is_none() && raw.len() > 32 {
        return (Some(raw[..32].to_string()), raw[32..].parse::<u32>().ok());
    }
    (Some(raw.to_string()), db.binary.pdb_age)
}

fn target_stem(file: &str) -> String {
    let name = Path::new(file)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");
    safe(name)
}

fn safe(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, Coverage, Kind, Provenance, Signature, Symbol};

    fn database(timestamp: &str, hash: &str) -> Database {
        let mut db = Database::default();
        db.binary.file = "history-test.dll".into();
        db.binary.timestamp = Some(timestamp.into());
        db.binary.pdb_guid = Some(format!("{timestamp:0<32}"));
        db.binary.pdb_age = Some(1);
        db.symbols.push(Symbol {
            id: "fn".into(),
            mangled: "fn".into(),
            demangled: Some("fn".into()),
            vaddr: 0x0001_8000_1000,
            rva: 0x1000,
            ordinal: Some(1),
            size: 1,
            procedure_size: Some(1),
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
            calls: vec![],
            imports: vec![],
        });
        db
    }

    #[test]
    fn archives_builds_and_writes_adjacent_diff() {
        let root = std::env::temp_dir().join(format!("windissect-history-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let first = record(&database("1", "aaa"), &root, None).unwrap();
        assert!(first.previous.is_none());
        let second = record(&database("2", "bbb"), &root, None).unwrap();
        assert!(second.previous.is_some());
        let index: HistoryIndex =
            serde_json::from_slice(&std::fs::read(root.join("history-test/index.json")).unwrap())
                .unwrap();
        assert_eq!(index.builds.len(), 2);
        assert_eq!(
            index.builds[1]
                .summary
                .as_ref()
                .unwrap()
                .implementation_changes,
            1
        );
        let catalog: HistoryCatalog =
            serde_json::from_slice(&std::fs::read(root.join("index.json")).unwrap()).unwrap();
        assert_eq!(catalog.targets[0].target, "history-test");
        assert_eq!(catalog.targets[0].build_count, 2);
        std::fs::remove_dir_all(root).unwrap();
    }
}
