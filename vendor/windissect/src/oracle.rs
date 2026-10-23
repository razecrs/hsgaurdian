//! Normalized, optional imports from manual analysis tools such as IDA and r2.

use crate::model::{
    Capability, CapabilityStatus, Claim, ClaimStatus, ClaimSubject, Database, Evidence,
    EvidenceKind, EvidenceLocation, EvidenceObservation, EvidenceTool, Usability,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug, Deserialize, Serialize)]
pub struct OracleExport {
    pub schema: u32,
    pub tool: EvidenceTool,
    pub tool_version: String,
    pub binary_sha256: String,
    pub observations: Vec<OracleObservation>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OracleObservation {
    pub id: String,
    pub rule_id: String,
    pub rule_version: u32,
    #[serde(default)]
    pub symbol_id: Option<String>,
    pub rva: u32,
    #[serde(default)]
    pub instruction_rvas: Vec<u32>,
    pub category: String,
    pub text: String,
}

pub fn import_path(db: &mut Database, path: &Path) -> Result<usize> {
    let export: OracleExport = serde_json::from_slice(&std::fs::read(path)?)
        .with_context(|| format!("parsing oracle export {}", path.display()))?;
    import(db, export)
}

pub fn import(db: &mut Database, export: OracleExport) -> Result<usize> {
    ensure!(
        export.schema == 1,
        "unsupported oracle schema {}",
        export.schema
    );
    let expected = db
        .binary
        .sha256
        .as_deref()
        .context("IR has no binary SHA-256; re-extract before importing oracle evidence")?;
    ensure!(
        expected.eq_ignore_ascii_case(&export.binary_sha256),
        "oracle binary hash mismatch: IR {expected}, oracle {}",
        export.binary_sha256
    );
    let mut ids: BTreeSet<String> = db.evidence.iter().map(|item| item.id.clone()).collect();
    let count = export.observations.len();
    for observation in export.observations {
        let evidence_id = format!("ev:oracle:{}", observation.id);
        ensure!(
            ids.insert(evidence_id.clone()),
            "duplicate oracle evidence {evidence_id}"
        );
        db.evidence.push(Evidence {
            id: evidence_id.clone(),
            kind: EvidenceKind::OracleImport,
            tool: export.tool.clone(),
            rule_id: observation.rule_id,
            rule_version: observation.rule_version,
            location: EvidenceLocation {
                symbol_id: observation.symbol_id,
                rva: Some(observation.rva),
                size: None,
                instruction_rvas: observation.instruction_rvas,
            },
            observation: EvidenceObservation::Text {
                text: observation.text.clone(),
            },
        });
        db.claims.push(Claim {
            id: format!("claim:oracle:{}", observation.id),
            subject: ClaimSubject::Text {
                category: observation.category,
                text: observation.text,
            },
            status: ClaimStatus::Candidate,
            usability: Usability::MetadataOnly,
            evidence_ids: vec![evidence_id],
            proof_id: None,
        });
    }
    db.capabilities.push(Capability {
        id: format!("oracle-import:{:?}:{}", export.tool, export.tool_version),
        status: CapabilityStatus::Partial,
        analyzer: "oracle-import".into(),
        reason: format!("{count} manual observations imported as metadata-only candidates"),
    });
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_binary() {
        let mut db = Database::default();
        db.binary.sha256 = Some("00".repeat(32));
        let export = OracleExport {
            schema: 1,
            tool: EvidenceTool::Radare2,
            tool_version: "test".into(),
            binary_sha256: "11".repeat(32),
            observations: vec![],
        };
        assert!(import(&mut db, export).is_err());
    }
}
