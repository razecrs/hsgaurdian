//! Strict separation between verified claims and evidence-only candidates.

use crate::diff::atomic_write;
use crate::model::{Claim, Database, Usability};
use anyhow::Result;
use serde::Serialize;
use std::path::Path;

#[derive(Serialize)]
struct Surface<'a> {
    schema: u32,
    binary: &'a crate::model::BinaryInfo,
    claims: Vec<&'a Claim>,
}

pub fn emit(db: &Database, out: &Path) -> Result<()> {
    let verified = Surface {
        schema: db.schema,
        binary: &db.binary,
        claims: db
            .claims
            .iter()
            .filter(|claim| db.claim_is_proven(claim))
            .collect(),
    };
    let evidence_only = Surface {
        schema: db.schema,
        binary: &db.binary,
        claims: db
            .claims
            .iter()
            .filter(|claim| claim.usability == Usability::MetadataOnly)
            .collect(),
    };
    atomic_write(
        &out.join("verified.json"),
        &serde_json::to_vec_pretty(&verified)?,
    )?;
    atomic_write(
        &out.join("evidence.json"),
        &serde_json::to_vec_pretty(&evidence_only)?,
    )?;
    atomic_write(
        &out.join("conflicts.json"),
        &serde_json::to_vec_pretty(&db.conflicts)?,
    )?;
    atomic_write(
        &out.join("capabilities.json"),
        &serde_json::to_vec_pretty(&db.capabilities)?,
    )?;
    Ok(())
}
