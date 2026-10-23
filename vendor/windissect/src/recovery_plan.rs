//! Target-independent inventory of semantic and ABI work left by refinement.

use crate::model::{ClaimSubject, Database, SemanticStatus};
use anyhow::Result;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct RecoveryPlan {
    schema: u32,
    binary_sha256: String,
    total_gaps: usize,
    by_kind: BTreeMap<String, usize>,
    by_priority: BTreeMap<u8, usize>,
    gaps: Vec<RecoveryGap>,
}

#[derive(Debug, Serialize)]
pub struct RecoveryGap {
    id: String,
    priority: u8,
    kind: String,
    subject: String,
    reason: String,
    evidence_routes: Vec<String>,
    related_claim_ids: Vec<String>,
    related_symbol_ids: Vec<String>,
}

pub struct RecoverySummary {
    pub total: usize,
    pub critical: usize,
    pub kinds: usize,
}

pub fn emit(db: &Database, root: &Path) -> Result<RecoverySummary> {
    let plan = build(db);
    crate::diff::atomic_write(
        &root.join("recovery-plan.json"),
        &serde_json::to_vec_pretty(&plan)?,
    )?;
    crate::diff::atomic_write(&root.join("recovery-plan.md"), markdown(&plan).as_bytes())?;
    Ok(RecoverySummary {
        total: plan.total_gaps,
        critical: plan.by_priority.get(&0).copied().unwrap_or_default(),
        kinds: plan.by_kind.len(),
    })
}

fn build(db: &Database) -> RecoveryPlan {
    let (callable, signatures) = proven_symbol_facts(db);
    let mut gaps = Vec::new();
    add_conflict_gaps(db, &mut gaps);
    for class in &db.semantic.classes {
        add_class_gaps(class, &mut gaps);
    }
    add_enum_gaps(db, &mut gaps);
    add_symbol_gaps(db, &callable, &signatures, &mut gaps);
    gaps.sort_by(|left, right| {
        left.priority
            .cmp(&right.priority)
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.subject.cmp(&right.subject))
    });
    let mut by_kind = BTreeMap::new();
    let mut by_priority = BTreeMap::new();
    for gap in &gaps {
        *by_kind.entry(gap.kind.clone()).or_insert(0) += 1;
        *by_priority.entry(gap.priority).or_insert(0) += 1;
    }
    RecoveryPlan {
        schema: 1,
        binary_sha256: db.binary.sha256.clone().unwrap_or_default(),
        total_gaps: gaps.len(),
        by_kind,
        by_priority,
        gaps,
    }
}

fn proven_symbol_facts(db: &Database) -> (BTreeSet<&str>, BTreeSet<&str>) {
    let proven = db.proven_claim_ids();
    let mut callable = BTreeSet::new();
    let mut signatures = BTreeSet::new();
    for claim in db
        .claims
        .iter()
        .filter(|claim| proven.contains(claim.id.as_str()))
    {
        match &claim.subject {
            ClaimSubject::Callable { symbol_id, .. } => {
                callable.insert(symbol_id.as_str());
            }
            ClaimSubject::Signature { symbol_id, .. } => {
                signatures.insert(symbol_id.as_str());
            }
            _ => {}
        }
    }
    (callable, signatures)
}

fn add_conflict_gaps(db: &Database, gaps: &mut Vec<RecoveryGap>) {
    for conflict in db.conflicts.iter().filter(|conflict| !conflict.resolved) {
        push_gap(
            gaps,
            gap(
                0,
                "proof-conflict",
                &conflict.id,
                &conflict.reason,
                &[
                    "independent-static-analysis",
                    "pdb-type-record",
                    "runtime-observation",
                ],
            )
            .with_claims(&conflict.claim_ids),
        );
    }
}

fn add_class_gaps(class: &crate::model::SemanticClass, gaps: &mut Vec<RecoveryGap>) {
    if class.size.is_none() {
        push_gap(
            gaps,
            gap(
                1,
                "object-size",
                &class.qualified_name,
                "no object size is available",
                &[
                    "pdb-udt-layout",
                    "constructor-allocation",
                    "rtti-complete-object",
                ],
            )
            .with_claims(&class.claim_ids),
        );
    }
    if class.alignment.is_none() {
        push_gap(
            gaps,
            gap(
                3,
                "object-alignment",
                &class.qualified_name,
                "object alignment is unresolved",
                &[
                    "pdb-udt-layout",
                    "field-offset-constraints",
                    "allocation-site",
                ],
            )
            .with_claims(&class.claim_ids),
        );
    }
    add_field_gaps(class, gaps);
    add_base_gaps(class, gaps);
    add_vtable_gaps(class, gaps);
}

fn add_field_gaps(class: &crate::model::SemanticClass, gaps: &mut Vec<RecoveryGap>) {
    for field in &class.fields {
        let subject = format!("{}+0x{:X}", class.qualified_name, field.offset);
        if field.status != SemanticStatus::Verified {
            push_gap(
                gaps,
                gap(
                    1,
                    "field-proof",
                    &subject,
                    "field/storage observation has not crossed the proof threshold",
                    &[
                        "pdb-member-record",
                        "independent-accessors",
                        "runtime-state-delta",
                    ],
                )
                .with_claims(&field.claim_ids),
            );
        }
        if field.name.is_none() {
            push_gap(
                gaps,
                gap(
                    2,
                    "field-name",
                    &subject,
                    "storage is known without a semantic member name",
                    &[
                        "pdb-member-record",
                        "getter-setter-pair",
                        "reflection-property",
                    ],
                )
                .with_claims(&field.claim_ids),
            );
        }
        if field.type_name.is_none() {
            push_gap(
                gaps,
                gap(
                    2,
                    "field-type",
                    &subject,
                    "member type is unresolved",
                    &[
                        "pdb-member-record",
                        "typed-memory-dataflow",
                        "callsite-constraints",
                    ],
                )
                .with_claims(&field.claim_ids),
            );
        }
    }
}

fn add_base_gaps(class: &crate::model::SemanticClass, gaps: &mut Vec<RecoveryGap>) {
    for base in &class.bases {
        let subject = format!("{} -> {}", class.qualified_name, base.qualified_name);
        if !base.relationship_verified {
            push_gap(
                gaps,
                gap(
                    1,
                    "base-relationship",
                    &subject,
                    "inheritance relationship is not independently verified",
                    &[
                        "pdb-base-record",
                        "rtti-base-descriptor",
                        "constructor-vtable-chain",
                    ],
                )
                .with_claims(&base.claim_ids),
            );
        }
        if base.offset.is_none() || !base.offset_verified {
            push_gap(
                gaps,
                gap(
                    2,
                    "base-offset",
                    &subject,
                    "base-subobject offset is unresolved",
                    &["pdb-base-record", "rtti-pmd", "this-adjusting-thunk"],
                )
                .with_claims(&base.claim_ids),
            );
        }
    }
}

fn add_vtable_gaps(class: &crate::model::SemanticClass, gaps: &mut Vec<RecoveryGap>) {
    for table in &class.vtables {
        let table_subject = format!("{} vtable@0x{:X}", class.qualified_name, table.rva);
        if table.status != SemanticStatus::Verified {
            push_gap(
                gaps,
                gap(
                    1,
                    "vtable-proof",
                    &table_subject,
                    "vtable ownership or shape is not fully verified",
                    &[
                        "pdb-vfptr-record",
                        "rtti-complete-object",
                        "constructor-vftable-store",
                    ],
                ),
            );
        }
        for slot in &table.slots {
            let subject = format!("{table_subject}[{}]", slot.slot);
            let symbols: Vec<_> = slot.symbol_id.iter().cloned().collect();
            if slot.status != SemanticStatus::Verified {
                push_gap(
                    gaps,
                    gap(
                        1,
                        "vtable-slot-proof",
                        &subject,
                        "virtual slot target is not proof-gated",
                        &[
                            "pdb-virtual-shape",
                            "relocation-backed-vtable",
                            "runtime-vtable-read",
                        ],
                    )
                    .with_claims(&slot.claim_ids)
                    .with_symbols(&symbols),
                );
            }
            if slot.symbol_id.is_none() {
                push_gap(
                    gaps,
                    gap(
                        1,
                        "vtable-slot-identity",
                        &subject,
                        "virtual slot has no stable symbol identity",
                        &[
                            "pdb-procedure",
                            "thunk-resolution",
                            "implementation-hash-match",
                        ],
                    )
                    .with_claims(&slot.claim_ids),
                );
            }
            if slot.this_adjustment.is_none() {
                push_gap(
                    gaps,
                    gap(
                        3,
                        "this-adjustment",
                        &subject,
                        "virtual dispatch this-adjustment is unresolved",
                        &["this-adjusting-thunk", "rtti-pmd", "pdb-vbase-record"],
                    )
                    .with_claims(&slot.claim_ids)
                    .with_symbols(&symbols),
                );
            }
        }
    }
}

fn add_enum_gaps(db: &Database, gaps: &mut Vec<RecoveryGap>) {
    for item in &db.semantic.enums {
        if item.values.is_empty() {
            push_gap(
                gaps,
                gap(
                    1,
                    "enum-values",
                    &item.qualified_name,
                    "enum type is known but no enumerators were recovered",
                    &[
                        "pdb-enumerate-record",
                        "switch-table",
                        "constant-propagation",
                    ],
                ),
            );
        }
        for value in item
            .values
            .iter()
            .filter(|value| value.status != SemanticStatus::Verified)
        {
            push_gap(
                gaps,
                gap(
                    2,
                    "enum-value-proof",
                    &format!("{}::{}", item.qualified_name, value.name),
                    "enumerator value is still a candidate",
                    &["pdb-enumerate-record", "independent-constant-use"],
                )
                .with_claims(&value.claim_ids),
            );
        }
    }
}

fn add_symbol_gaps(
    db: &Database,
    callable: &BTreeSet<&str>,
    signatures: &BTreeSet<&str>,
    gaps: &mut Vec<RecoveryGap>,
) {
    for symbol in db.symbols.iter().filter(|symbol| {
        symbol.is_code
            && !symbol.library
            && symbol.sig.class.is_some()
            && symbol.sig.method.is_some()
    }) {
        if !symbol.sig.parse_ok {
            push_gap(
                gaps,
                symbol_gap(
                    symbol,
                    "signature-parse",
                    "method signature could not be represented as a structured ABI",
                    &[
                        "pdb-procedure-type",
                        "demangler-grammar",
                        "callsite-constraints",
                    ],
                ),
            );
            continue;
        }
        if !signatures.contains(symbol.id.as_str()) {
            push_gap(
                gaps,
                symbol_gap(
                    symbol,
                    "signature-proof",
                    "structured signature lacks an independent passing proof",
                    &[
                        "pdb-procedure-type",
                        "caller-callee-dataflow",
                        "runtime-abi-probe",
                    ],
                ),
            );
        }
        if !callable.contains(symbol.id.as_str()) {
            push_gap(
                gaps,
                symbol_gap(
                    symbol,
                    "callable-proof",
                    "method is not eligible for verified callable output",
                    &[
                        "executable-mapping",
                        "exact-build-rva",
                        "runtime-entry-probe",
                    ],
                ),
            );
        }
        if symbol.sig.callconv.is_none() {
            push_gap(
                gaps,
                symbol_gap(
                    symbol,
                    "calling-convention",
                    "calling convention is not explicit",
                    &[
                        "pdb-procedure-type",
                        "architecture-default-abi",
                        "prologue-callsite-analysis",
                    ],
                ),
            );
        }
    }
}

fn symbol_gap(
    symbol: &crate::model::Symbol,
    kind: &str,
    reason: &str,
    routes: &[&str],
) -> RecoveryGap {
    gap(
        if kind == "calling-convention" { 2 } else { 1 },
        kind,
        &symbol.id,
        reason,
        routes,
    )
    .with_symbols(std::slice::from_ref(&symbol.id))
}

fn gap(priority: u8, kind: &str, subject: &str, reason: &str, routes: &[&str]) -> RecoveryGap {
    let digest = Sha256::digest(format!("{kind}\0{subject}").as_bytes());
    RecoveryGap {
        id: format!("gap:{kind}:{}", &crate::hex::lower(&digest)[..16]),
        priority,
        kind: kind.into(),
        subject: subject.into(),
        reason: reason.into(),
        evidence_routes: routes.iter().map(|route| (*route).into()).collect(),
        related_claim_ids: Vec::new(),
        related_symbol_ids: Vec::new(),
    }
}

impl RecoveryGap {
    fn with_claims(mut self, claims: &[String]) -> Self {
        self.related_claim_ids = claims.to_vec();
        self
    }

    fn with_symbols(mut self, symbols: &[String]) -> Self {
        self.related_symbol_ids = symbols.to_vec();
        self
    }
}

fn push_gap(gaps: &mut Vec<RecoveryGap>, gap: RecoveryGap) {
    gaps.push(gap);
}

fn markdown(plan: &RecoveryPlan) -> String {
    let mut text = String::from("# Recovery plan\n\n");
    let _ = writeln!(text, "Binary SHA-256: `{}`\n", plan.binary_sha256);
    let _ = writeln!(text, "Total unresolved facts: {}\n", plan.total_gaps);
    text.push_str("## By evidence gap\n\n| Kind | Count |\n|---|---:|\n");
    for (kind, count) in &plan.by_kind {
        let _ = writeln!(text, "| {kind} | {count} |");
    }
    text.push_str(
        "\n## Priority queue\n\n| Priority | Kind | Subject | Reason |\n|---:|---|---|---|\n",
    );
    for gap in plan.gaps.iter().take(500) {
        let subject = gap.subject.replace('|', "\\|");
        let reason = gap.reason.replace('|', "\\|");
        let _ = writeln!(
            text,
            "| {} | {} | `{subject}` | {reason} |",
            gap.priority, gap.kind
        );
    }
    if plan.gaps.len() > 500 {
        let _ = writeln!(
            text,
            "\nThe complete {}-item queue is stored in `recovery-plan.json`.",
            plan.gaps.len()
        );
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BinaryInfo, SemanticClass, SemanticModel};

    #[test]
    fn candidate_class_creates_target_independent_gaps() {
        let db = Database {
            binary: BinaryInfo {
                sha256: Some("AA".repeat(32)),
                ..Default::default()
            },
            semantic: SemanticModel {
                classes: vec![SemanticClass {
                    qualified_name: "Example::Widget".into(),
                    kind: "class".into(),
                    size: None,
                    alignment: None,
                    status: SemanticStatus::Candidate,
                    fields: Vec::new(),
                    bases: Vec::new(),
                    vtables: Vec::new(),
                    claim_ids: Vec::new(),
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        let plan = build(&db);
        assert_eq!(plan.by_kind.get("object-size"), Some(&1));
        assert_eq!(plan.by_kind.get("object-alignment"), Some(&1));
        assert!(plan.gaps.iter().all(|gap| gap.subject == "Example::Widget"));
    }
}
