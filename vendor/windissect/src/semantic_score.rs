//! Deterministic scoring of proof-gated semantic facts against an owned oracle.

use crate::model::{Database, SemanticStatus};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct SemanticOracle {
    pub binary_sha256: String,
    #[serde(default)]
    pub classes: Vec<OracleClass>,
    #[serde(default)]
    pub enums: Vec<OracleEnum>,
}

#[derive(Debug, Deserialize)]
pub struct OracleClass {
    pub name: String,
    pub size: u64,
    #[serde(default)]
    pub fields: Vec<OracleField>,
    #[serde(default)]
    pub bases: Vec<OracleBase>,
    #[serde(default)]
    pub vtable_slots: Vec<u32>,
}

#[derive(Debug, Deserialize)]
pub struct OracleField {
    pub name: String,
    pub offset: u64,
    pub width: u32,
    #[serde(default)]
    pub bit_offset: Option<u8>,
    #[serde(default)]
    pub bit_size: Option<u8>,
}

#[derive(Debug, Deserialize)]
pub struct OracleBase {
    pub name: String,
    pub offset: i64,
    #[serde(default)]
    pub is_virtual: bool,
}

#[derive(Debug, Deserialize)]
pub struct OracleEnum {
    pub name: String,
    pub values: Vec<OracleEnumValue>,
}

#[derive(Debug, Deserialize)]
pub struct OracleEnumValue {
    pub name: String,
    pub value: i64,
}

#[derive(Debug, Serialize)]
pub struct SemanticScore {
    pub expected_facts: usize,
    pub verified_predictions: usize,
    pub true_positive: usize,
    pub false_positive: usize,
    pub false_negative: usize,
    pub precision: f64,
    pub recall: f64,
    pub threshold: f64,
    pub passed: bool,
    pub unexpected_verified: Vec<String>,
    pub missing_verified: Vec<String>,
}

pub fn score(db: &Database, oracle_path: &Path, threshold: f64) -> Result<SemanticScore> {
    anyhow::ensure!(
        (0.0..=1.0).contains(&threshold),
        "threshold must be in [0, 1]"
    );
    let oracle: SemanticOracle = serde_json::from_slice(
        &std::fs::read(oracle_path)
            .with_context(|| format!("read semantic oracle {}", oracle_path.display()))?,
    )?;
    anyhow::ensure!(
        db.binary
            .sha256
            .as_deref()
            .is_some_and(|hash| hash.eq_ignore_ascii_case(&oracle.binary_sha256)),
        "semantic oracle binary SHA-256 does not match the IR"
    );

    let expected = oracle_facts(&oracle);
    let scopes: BTreeSet<String> = oracle
        .classes
        .iter()
        .map(|class| format!("class:{}", class.name))
        .chain(
            oracle
                .enums
                .iter()
                .map(|item| format!("enum:{}", item.name)),
        )
        .collect();
    let predicted = verified_facts(db, &scopes);
    let unexpected_verified = predicted.difference(&expected).cloned().collect::<Vec<_>>();
    let missing_verified = expected.difference(&predicted).cloned().collect::<Vec<_>>();
    let true_positive = predicted.intersection(&expected).count();
    let false_positive = unexpected_verified.len();
    let false_negative = missing_verified.len();
    let precision = if predicted.is_empty() {
        1.0
    } else {
        count_as_f64(true_positive) / count_as_f64(predicted.len())
    };
    let recall = if expected.is_empty() {
        1.0
    } else {
        count_as_f64(true_positive) / count_as_f64(expected.len())
    };
    Ok(SemanticScore {
        expected_facts: expected.len(),
        verified_predictions: predicted.len(),
        true_positive,
        false_positive,
        false_negative,
        precision,
        recall,
        threshold,
        passed: precision >= threshold,
        unexpected_verified,
        missing_verified,
    })
}

fn count_as_f64(value: usize) -> f64 {
    u32::try_from(value).map_or(f64::INFINITY, f64::from)
}

fn oracle_facts(oracle: &SemanticOracle) -> BTreeSet<String> {
    let mut facts = BTreeSet::new();
    for class in &oracle.classes {
        facts.insert(format!("class:{}:size:{}", class.name, class.size));
        for field in &class.fields {
            facts.insert(format!(
                "class:{}:field:{}:{}:{}:{:?}:{:?}",
                class.name, field.name, field.offset, field.width, field.bit_offset, field.bit_size
            ));
        }
        for base in &class.bases {
            facts.insert(format!(
                "class:{}:base:{}:{}:{}",
                class.name, base.name, base.offset, base.is_virtual
            ));
        }
        for slot in &class.vtable_slots {
            facts.insert(format!("class:{}:vslot:{}", class.name, slot));
        }
    }
    for item in &oracle.enums {
        for value in &item.values {
            facts.insert(format!("enum:{}:{}:{}", item.name, value.name, value.value));
        }
    }
    facts
}

fn verified_facts(db: &Database, scopes: &BTreeSet<String>) -> BTreeSet<String> {
    let mut facts = BTreeSet::new();
    for class in &db.semantic.classes {
        if !scopes.contains(&format!("class:{}", class.qualified_name)) {
            continue;
        }
        if class.status == SemanticStatus::Verified
            && let Some(size) = class.size
        {
            facts.insert(format!("class:{}:size:{}", class.qualified_name, size));
        }
        for field in class
            .fields
            .iter()
            .filter(|field| field.status == SemanticStatus::Verified)
        {
            facts.insert(format!(
                "class:{}:field:{}:{}:{}:{:?}:{:?}",
                class.qualified_name,
                field.name.as_deref().unwrap_or("<unnamed>"),
                field.offset,
                field.width,
                field.bit_offset,
                field.bit_size
            ));
        }
        for base in class
            .bases
            .iter()
            .filter(|base| base.status == SemanticStatus::Verified)
        {
            if let Some(offset) = base.offset {
                facts.insert(format!(
                    "class:{}:base:{}:{}:{}",
                    class.qualified_name, base.qualified_name, offset, base.is_virtual
                ));
            }
        }
        for slot in class
            .vtables
            .iter()
            .flat_map(|table| &table.slots)
            .filter(|slot| slot.status == SemanticStatus::Verified)
        {
            facts.insert(format!(
                "class:{}:vslot:{}",
                class.qualified_name, slot.slot
            ));
        }
    }
    for item in &db.semantic.enums {
        if !scopes.contains(&format!("enum:{}", item.qualified_name)) {
            continue;
        }
        for value in item
            .values
            .iter()
            .filter(|value| value.status == SemanticStatus::Verified)
        {
            facts.insert(format!(
                "enum:{}:{}:{}",
                item.qualified_name, value.name, value.value
            ));
        }
    }
    facts
}
