//! Versioned, reviewable manual corpora that gate automated recovery rules.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Maturity {
    Draft,
    Certified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaseKind {
    Positive,
    Negative,
    Adversarial,
    Contradictory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRecord {
    pub tool: String,
    pub version: String,
    #[serde(default)]
    pub artifact: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualCase {
    pub id: String,
    pub kind: CaseKind,
    pub binary_sha256: String,
    pub binary_file: String,
    pub machine: String,
    pub symbol: String,
    pub rva: u32,
    pub conclusion: String,
    pub expected_rule_result: String,
    #[serde(default)]
    pub instruction_rvas: Vec<u32>,
    #[serde(default)]
    pub rejected_interpretations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePack {
    pub schema: u32,
    pub id: String,
    pub rule_id: String,
    pub rule_version: u32,
    pub maturity: Maturity,
    pub tools: Vec<ToolRecord>,
    pub cases: Vec<ManualCase>,
}

pub struct Validation {
    pub id: String,
    pub maturity: Maturity,
    pub cases: usize,
    pub binaries: usize,
}

pub fn validate_path(path: &Path) -> Result<Validation> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let pack: EvidencePack = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing evidence pack {}", path.display()))?;
    validate(&pack)
}

pub fn validate(pack: &EvidencePack) -> Result<Validation> {
    ensure!(
        pack.schema == 1,
        "unsupported evidence-pack schema {}",
        pack.schema
    );
    ensure!(!pack.id.trim().is_empty(), "evidence pack id is empty");
    ensure!(!pack.rule_id.trim().is_empty(), "rule id is empty");
    ensure!(pack.rule_version > 0, "rule version must be positive");
    ensure!(
        !pack.tools.is_empty(),
        "manual evidence pack records no tools"
    );
    let mut ids = BTreeSet::new();
    let mut binaries = BTreeSet::new();
    let mut positives = 0usize;
    let mut negatives = 0usize;
    for case in &pack.cases {
        ensure!(
            ids.insert(case.id.as_str()),
            "duplicate case id {}",
            case.id
        );
        ensure!(
            case.binary_sha256.len() == 64
                && case.binary_sha256.chars().all(|ch| ch.is_ascii_hexdigit()),
            "case {} has invalid SHA-256",
            case.id
        );
        ensure!(!case.symbol.is_empty(), "case {} has no symbol", case.id);
        ensure!(
            !case.conclusion.is_empty(),
            "case {} has no conclusion",
            case.id
        );
        binaries.insert(case.binary_sha256.as_str());
        match case.kind {
            CaseKind::Positive => positives += 1,
            CaseKind::Negative | CaseKind::Adversarial => negatives += 1,
            CaseKind::Contradictory => {}
        }
    }
    if pack.maturity == Maturity::Certified {
        ensure!(
            positives >= 3,
            "certification requires at least 3 positive cases"
        );
        ensure!(
            negatives >= 2,
            "certification requires at least 2 negative/adversarial cases"
        );
        ensure!(
            binaries.len() >= 2,
            "certification requires at least 2 binaries"
        );
    }
    Ok(Validation {
        id: pack.id.clone(),
        maturity: pack.maturity,
        cases: pack.cases.len(),
        binaries: binaries.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certified_pack_enforces_corpus_gate() {
        let pack = EvidencePack {
            schema: 1,
            id: "test".into(),
            rule_id: "rule".into(),
            rule_version: 1,
            maturity: Maturity::Certified,
            tools: vec![ToolRecord {
                tool: "ida".into(),
                version: "9.4".into(),
                artifact: None,
            }],
            cases: vec![],
        };
        assert!(validate(&pack).is_err());
    }
}
