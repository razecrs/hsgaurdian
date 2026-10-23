//! Reference-guided, evidence-gated refinement.
//!
//! A reference corpus is a discrepancy oracle, never proof of the target
//! binary. This module therefore reports candidates without mutating the IR.

use crate::model::{
    Claim, ClaimStatus, ClaimSubject, Database, Evidence, EvidenceKind, EvidenceLocation,
    EvidenceObservation, EvidenceTool, Proof, ProofObligation, RecoveryJob, RecoveryJobKind,
    RecoveryJobState, RecoveryRequirement, ReferenceCandidate, Usability,
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Declaration {
    pub class: String,
    pub method: String,
    pub signature: String,
    pub parameter_count: usize,
    pub source_file: String,
    pub source_line: usize,
    pub evidence_kind: &'static str,
}

#[derive(Debug, Serialize)]
pub struct SignatureConflict {
    pub class: String,
    pub method: String,
    pub windissect: Vec<String>,
    pub reference: Vec<Declaration>,
}

#[derive(Debug, Serialize)]
pub struct ClassComparison {
    pub class: String,
    pub windissect_methods: usize,
    pub reference_methods: usize,
    pub common_methods: usize,
    pub windissect_only: Vec<String>,
    pub reference_only: Vec<String>,
}

struct ReferenceCorpus {
    declarations: Vec<Declaration>,
    classes: BTreeSet<String>,
}

type MethodKey = (String, String);
type DeclarationMap = BTreeMap<MethodKey, Vec<Declaration>>;

struct WindissectIndex {
    signatures: BTreeMap<MethodKey, BTreeSet<String>>,
    arities: BTreeMap<MethodKey, BTreeSet<usize>>,
}

struct ReferenceOnlyStats {
    implemented: usize,
    declaration_only: usize,
    stubs: usize,
    inline: usize,
    pure_virtual: usize,
    special_member: usize,
    known_class: usize,
    unknown_class: usize,
}

struct RecoveryCounts {
    unresolved: usize,
    candidates: usize,
    verified: usize,
    withheld: usize,
}

struct RecoveryContext<'a> {
    symbols: BTreeMap<&'a str, &'a crate::model::Symbol>,
    verified_callable: BTreeSet<String>,
    conflicted_symbols: BTreeSet<String>,
    proven_claim_ids: BTreeMap<String, Vec<String>>,
    verified_vslot_claim_ids: BTreeMap<(String, String), Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct RefineReport {
    pub schema: u32,
    pub target: String,
    pub reference_root: String,
    pub policy: &'static str,
    pub generic_recoveries_applied: usize,
    pub windissect_classes: usize,
    pub reference_classes: usize,
    pub common_classes: usize,
    pub windissect_only_classes: Vec<String>,
    pub reference_only_classes: Vec<String>,
    pub windissect_declarations: usize,
    pub reference_declarations: usize,
    pub reference_implemented_declarations: usize,
    pub reference_declaration_only_declarations: usize,
    pub reference_stub_declarations: usize,
    pub reference_inline_declarations: usize,
    pub reference_pure_virtual_declarations: usize,
    pub reference_special_member_declarations: usize,
    pub reference_only_stubs: usize,
    pub reference_only_implemented: usize,
    pub reference_only_declaration_only: usize,
    pub reference_only_inline: usize,
    pub reference_only_pure_virtual: usize,
    pub reference_only_special_member: usize,
    pub reference_only_known_class: usize,
    pub reference_only_unknown_class: usize,
    pub common_methods: usize,
    pub windissect_only: Vec<String>,
    pub reference_only: Vec<Declaration>,
    pub signature_conflicts: Vec<SignatureConflict>,
    pub class_comparisons: Vec<ClassComparison>,
    pub recovery_jobs: usize,
    pub recovery_unresolved: usize,
    pub recovery_candidates: usize,
    pub recovery_verified: usize,
    pub recovery_withheld: usize,
}

pub fn apply_generic_rules(db: &mut Database) -> usize {
    let mut changed = 0;
    for symbol in &mut db.symbols {
        let before = (
            symbol.sig.parse_ok,
            symbol.sig.namespace.clone(),
            symbol.sig.class.clone(),
            symbol.sig.method.clone(),
            symbol.library,
            symbol.kind,
        );
        if let Some(declaration) = &symbol.demangled {
            symbol.sig = crate::demangle::parse_decl(declaration);
        }
        symbol.library = crate::is_library(&symbol.mangled, symbol.demangled.as_deref());
        symbol.kind = crate::demangle::classify(symbol);
        let after = (
            symbol.sig.parse_ok,
            symbol.sig.namespace.clone(),
            symbol.sig.class.clone(),
            symbol.sig.method.clone(),
            symbol.library,
            symbol.kind,
        );
        changed += usize::from(before != after);
    }
    changed
        + recover_pdb_callable_proofs(db)
        + recover_vtable_structure_proofs(db)
        + recover_ctor_base_proofs(db)
}

fn recover_ctor_base_proofs(db: &mut Database) -> usize {
    let proven_claims = db.proven_claim_ids();
    let proven_bases: BTreeSet<(String, String)> = db
        .claims
        .iter()
        .filter(|claim| proven_claims.contains(claim.id.as_str()))
        .filter_map(|claim| match &claim.subject {
            ClaimSubject::Base { derived, base, .. } => Some((derived.clone(), base.clone())),
            _ => None,
        })
        .collect();
    let template_evidence: BTreeMap<&str, (&str, &str)> = db
        .evidence
        .iter()
        .filter_map(|evidence| match &evidence.observation {
            EvidenceObservation::TemplateBase { derived, base, .. } => {
                Some((evidence.id.as_str(), (derived.as_str(), base.as_str())))
            }
            _ => None,
        })
        .collect();
    let mut candidate_evidence = BTreeMap::<(String, String), Vec<String>>::new();
    for claim in &db.claims {
        let ClaimSubject::Base { derived, base, .. } = &claim.subject else {
            continue;
        };
        let key = (derived.clone(), base.clone());
        let evidence_ids = candidate_evidence.entry(key).or_default();
        evidence_ids.extend(claim.evidence_ids.iter().filter_map(|id| {
            template_evidence
                .get(id.as_str())
                .filter(|(observed_derived, observed_base)| {
                    *observed_derived == derived && *observed_base == base
                })
                .map(|_| id.clone())
        }));
    }
    candidate_evidence.retain(|_, evidence_ids| {
        evidence_ids.sort();
        evidence_ids.dedup();
        !evidence_ids.is_empty()
    });
    let symbols: BTreeMap<&str, &crate::model::Symbol> = db
        .symbols
        .iter()
        .map(|symbol| (symbol.id.as_str(), symbol))
        .collect();
    let mut facts = BTreeMap::new();
    for caller in db.symbols.iter().filter(|symbol| {
        matches!(
            symbol.kind,
            crate::model::Kind::Ctor | crate::model::Kind::Dtor
        )
    }) {
        let Some(derived) = symbol_owner(caller) else {
            continue;
        };
        for callee in caller
            .calls
            .iter()
            .filter_map(|id| symbols.get(id.as_str()).copied())
            .filter(|symbol| same_special_member_kind(caller.kind, symbol.kind))
        {
            let Some(base) = symbol_owner(callee) else {
                continue;
            };
            let key = (derived.clone(), base);
            if derived != key.1
                && candidate_evidence.contains_key(&key)
                && !proven_bases.contains(&key)
            {
                facts
                    .entry(key)
                    .or_insert_with(|| (caller.id.clone(), caller.rva, callee.id.clone()));
            }
        }
    }
    let count = facts.len();
    for ((derived, base), (caller_id, caller_rva, callee_id)) in facts {
        add_ctor_base_proof(
            db,
            &derived,
            &base,
            &caller_id,
            caller_rva,
            &callee_id,
            candidate_evidence
                .get(&(derived.clone(), base.clone()))
                .cloned()
                .unwrap_or_default(),
        );
    }
    count
}

const fn same_special_member_kind(
    source_kind: crate::model::Kind,
    target_kind: crate::model::Kind,
) -> bool {
    matches!(
        (source_kind, target_kind),
        (crate::model::Kind::Ctor, crate::model::Kind::Ctor)
            | (crate::model::Kind::Dtor, crate::model::Kind::Dtor)
    )
}

fn symbol_owner(symbol: &crate::model::Symbol) -> Option<String> {
    symbol
        .sig
        .class
        .as_deref()
        .map(|class| qualify(symbol.sig.namespace.as_deref(), class))
}

fn add_ctor_base_proof(
    db: &mut Database,
    derived: &str,
    base: &str,
    source_id: &str,
    caller_rva: u32,
    target_id: &str,
    mut evidence_ids: Vec<String>,
) {
    let evidence_id = format!("ev:ctor-base:{caller_rva:X}:{derived}:{base}");
    let proof_id = format!("proof:ctor-base:{caller_rva:X}:{derived}:{base}");
    evidence_ids.push(evidence_id.clone());
    evidence_ids.sort();
    evidence_ids.dedup();
    db.evidence.push(Evidence {
        id: evidence_id,
        kind: EvidenceKind::Instruction,
        tool: EvidenceTool::Windissect,
        rule_id: "msvc.ctor-base-corroboration".into(),
        rule_version: 1,
        location: EvidenceLocation {
            symbol_id: Some(source_id.into()),
            rva: Some(caller_rva),
            size: None,
            instruction_rvas: Vec::new(),
        },
        observation: EvidenceObservation::Text {
            text: format!("{source_id} directly calls base special member {target_id}"),
        },
    });
    db.proofs.push(Proof {
        id: proof_id.clone(),
        rule_id: "msvc.ctor-base-corroboration".into(),
        rule_version: 1,
        passed: true,
        obligations: vec![
            ProofObligation {
                name: "typed-base-candidate".into(),
                satisfied: evidence_ids.len() > 1,
                detail: format!("independent type evidence names {derived} -> {base}"),
            },
            ProofObligation {
                name: "exact-build-special-member-edge".into(),
                satisfied: true,
                detail: format!("decoded call edge {source_id} -> {target_id}"),
            },
        ],
    });
    db.claims.push(Claim {
        id: format!("claim:ctor-base:{caller_rva:X}:{derived}:{base}"),
        subject: ClaimSubject::Base {
            derived: derived.into(),
            base: base.into(),
            offset: None,
            is_virtual: false,
        },
        status: ClaimStatus::Corroborated,
        usability: Usability::Verified,
        evidence_ids,
        proof_id: Some(proof_id),
    });
}

fn recover_vtable_structure_proofs(db: &mut Database) -> usize {
    let structural_evidence: BTreeSet<&str> = db
        .evidence
        .iter()
        .filter(|evidence| evidence.rule_id == "msvc.pe-vftable-slot")
        .map(|evidence| evidence.id.as_str())
        .collect();
    let passing_proofs: BTreeSet<&str> = db
        .proofs
        .iter()
        .filter(|proof| {
            proof.rule_id == "msvc.pe-vftable-slot"
                && proof.passed
                && proof
                    .obligations
                    .iter()
                    .all(|obligation| obligation.satisfied)
        })
        .map(|proof| proof.id.as_str())
        .collect();
    let mut structural_claim_ids = BTreeSet::new();
    let mut changed = 0;
    for claim in &mut db.claims {
        let ClaimSubject::VtableSlot { owner, .. } = &mut claim.subject else {
            continue;
        };
        let supported = !claim.evidence_ids.is_empty()
            && claim
                .evidence_ids
                .iter()
                .all(|id| structural_evidence.contains(id.as_str()))
            && claim
                .proof_id
                .as_deref()
                .is_some_and(|id| passing_proofs.contains(id));
        if !supported {
            continue;
        }
        structural_claim_ids.insert(claim.id.clone());
        let normalized_owner = normalized_vftable_owner(owner);
        let needs_update = *owner != normalized_owner
            || claim.status != ClaimStatus::Corroborated
            || claim.usability != Usability::Verified;
        *owner = normalized_owner;
        claim.status = ClaimStatus::Corroborated;
        claim.usability = Usability::Verified;
        changed += usize::from(needs_update);
    }
    for conflict in &mut db.conflicts {
        if conflict
            .reason
            .starts_with("ICF aliases disagree on ABI signature")
        {
            conflict
                .claim_ids
                .retain(|id| !structural_claim_ids.contains(id));
        }
    }
    db.conflicts
        .retain(|conflict| !conflict.claim_ids.is_empty());
    changed + recover_vftable_base_proofs(db, &structural_claim_ids)
}

fn recover_vftable_base_proofs(
    db: &mut Database,
    structural_claim_ids: &BTreeSet<String>,
) -> usize {
    let verified_tables: BTreeSet<(String, u32)> = db
        .claims
        .iter()
        .filter(|claim| structural_claim_ids.contains(&claim.id))
        .filter_map(|claim| match &claim.subject {
            ClaimSubject::VtableSlot {
                owner, table_rva, ..
            } => Some((owner.clone(), *table_rva)),
            _ => None,
        })
        .collect();
    let existing_claim_ids: BTreeSet<&str> =
        db.claims.iter().map(|claim| claim.id.as_str()).collect();
    let facts: Vec<_> = db
        .vtables
        .iter()
        .filter_map(|table| {
            let name = table.get("demangled")?.as_str()?;
            let derived = crate::rtti::vftable_derived_name(name)?;
            let base = crate::rtti::vftable_owner_name(name)?;
            let table_rva = value_u32(table, "rva")?;
            (derived != base && verified_tables.contains(&(base.into(), table_rva))).then(|| {
                (
                    derived.to_string(),
                    base.to_string(),
                    table_rva,
                    name.to_string(),
                )
            })
        })
        .filter(|(_, _, table_rva, _)| {
            !existing_claim_ids.contains(format!("claim:vftable-base:{table_rva:X}").as_str())
        })
        .collect();
    let count = facts.len();
    for (derived, base, table_rva, symbol_name) in facts {
        let evidence_id = format!("ev:vftable-base:{table_rva:X}");
        let proof_id = format!("proof:vftable-base:{table_rva:X}");
        db.evidence.push(Evidence {
            id: evidence_id.clone(),
            kind: EvidenceKind::Rtti,
            tool: EvidenceTool::Windissect,
            rule_id: "msvc.secondary-vftable-base".into(),
            rule_version: 1,
            location: EvidenceLocation {
                symbol_id: None,
                rva: Some(table_rva),
                size: None,
                instruction_rvas: Vec::new(),
            },
            observation: EvidenceObservation::Text {
                text: format!("{symbol_name} names the {base} subobject of {derived}"),
            },
        });
        db.proofs.push(Proof {
            id: proof_id.clone(),
            rule_id: "msvc.secondary-vftable-base".into(),
            rule_version: 1,
            passed: true,
            obligations: vec![
                ProofObligation {
                    name: "msvc-for-clause".into(),
                    satisfied: true,
                    detail: "the decorated vftable symbol names derived and base subobject".into(),
                },
                ProofObligation {
                    name: "verified-slot-structure".into(),
                    satisfied: true,
                    detail: format!("table RVA 0x{table_rva:X} has verified executable slots"),
                },
            ],
        });
        db.claims.push(Claim {
            id: format!("claim:vftable-base:{table_rva:X}"),
            subject: ClaimSubject::Base {
                derived,
                base,
                offset: None,
                is_virtual: false,
            },
            status: ClaimStatus::Corroborated,
            usability: Usability::Verified,
            evidence_ids: vec![evidence_id],
            proof_id: Some(proof_id),
        });
    }
    count
}

fn normalized_vftable_owner(value: &str) -> String {
    crate::rtti::vftable_owner_name(value)
        .unwrap_or(value)
        .to_string()
}

fn recover_pdb_callable_proofs(db: &mut Database) -> usize {
    if db.binary.pdb_guid.is_none() || db.binary.pdb_age.is_none() || db.binary.sha256.is_none() {
        return 0;
    }
    let functions: BTreeMap<&str, &crate::model::FunctionAnalysis> = db
        .functions
        .iter()
        .flat_map(|function| {
            function
                .symbol_ids
                .iter()
                .map(move |id| (id.as_str(), function))
        })
        .collect();
    let existing_claim_ids: BTreeSet<&str> =
        db.claims.iter().map(|claim| claim.id.as_str()).collect();
    let mut prepared = BTreeMap::new();
    for symbol in &db.symbols {
        let Some(function) = functions.get(symbol.id.as_str()) else {
            continue;
        };
        if symbol.provenance != crate::model::Provenance::Pdb
            || !symbol.sig.parse_ok
            || !symbol.is_code
            || symbol.rva == 0
            || function.instructions.is_empty()
        {
            continue;
        }
        let suffix = recovery_proof_suffix(&symbol.id, symbol.rva);
        if existing_claim_ids.contains(format!("claim:pdb-callable:{suffix}").as_str()) {
            continue;
        }
        let instruction_rvas = function
            .instructions
            .iter()
            .take(2)
            .map(|instruction| instruction.rva)
            .collect();
        prepared.entry(suffix).or_insert_with(|| {
            (
                symbol.id.clone(),
                symbol.rva,
                symbol.size,
                symbol.sig.clone(),
                instruction_rvas,
            )
        });
    }
    let count = prepared.len();
    for (suffix, (symbol_id, rva, size, signature, instruction_rvas)) in prepared {
        add_pdb_callable_proof(
            db,
            &suffix,
            &symbol_id,
            rva,
            size,
            signature,
            instruction_rvas,
        );
    }
    count
}

fn recovery_proof_suffix(symbol_id: &str, rva: u32) -> String {
    let digest = Sha256::digest(symbol_id.as_bytes());
    format!("{rva:08X}-{}", &crate::hex::lower(&digest)[..16])
}

fn add_pdb_callable_proof(
    db: &mut Database,
    suffix: &str,
    symbol_id: &str,
    rva: u32,
    size: u32,
    signature: crate::model::Signature,
    instruction_rvas: Vec<u32>,
) {
    let signature_evidence_id = format!("ev:pdb-signature:{suffix}");
    let callable_evidence_id = format!("ev:decoded-callable:{suffix}");
    let proof_id = format!("proof:pdb-callable:{suffix}");
    db.evidence.extend([
        Evidence {
            id: signature_evidence_id.clone(),
            kind: EvidenceKind::PdbRecord,
            tool: EvidenceTool::Pdb,
            rule_id: "pdb.function-callable".into(),
            rule_version: 1,
            location: EvidenceLocation {
                symbol_id: Some(symbol_id.into()),
                rva: Some(rva),
                size: Some(size),
                instruction_rvas: Vec::new(),
            },
            observation: EvidenceObservation::Text {
                text: "identity-matched PDB function name contains a structured MSVC ABI signature"
                    .into(),
            },
        },
        Evidence {
            id: callable_evidence_id.clone(),
            kind: EvidenceKind::Instruction,
            tool: EvidenceTool::Windissect,
            rule_id: "pdb.function-callable".into(),
            rule_version: 1,
            location: EvidenceLocation {
                symbol_id: Some(symbol_id.into()),
                rva: Some(rva),
                size: Some(size),
                instruction_rvas,
            },
            observation: EvidenceObservation::Text {
                text: "PDB function RVA maps to a successfully decoded exact-build function body"
                    .into(),
            },
        },
    ]);
    db.proofs.push(Proof {
        id: proof_id.clone(),
        rule_id: "pdb.function-callable".into(),
        rule_version: 1,
        passed: true,
        obligations: vec![
            ProofObligation {
                name: "identity-matched-pdb".into(),
                satisfied: true,
                detail: "PE and PDB GUID+age were validated during extraction".into(),
            },
            ProofObligation {
                name: "pdb-function-record".into(),
                satisfied: true,
                detail: "the PDB supplied a function name and RVA".into(),
            },
            ProofObligation {
                name: "structured-msvc-signature".into(),
                satisfied: true,
                detail: "the PDB function name demangled into the typed signature IR".into(),
            },
            ProofObligation {
                name: "decoded-function-body".into(),
                satisfied: true,
                detail: "static enrichment decoded instructions at the function RVA".into(),
            },
        ],
    });
    db.claims.extend([
        Claim {
            id: format!("claim:pdb-callable:{suffix}"),
            subject: ClaimSubject::Callable {
                symbol_id: symbol_id.into(),
                rva,
            },
            status: ClaimStatus::Corroborated,
            usability: Usability::Verified,
            evidence_ids: vec![callable_evidence_id],
            proof_id: Some(proof_id.clone()),
        },
        Claim {
            id: format!("claim:pdb-signature:{suffix}"),
            subject: ClaimSubject::Signature {
                symbol_id: symbol_id.into(),
                signature,
            },
            status: ClaimStatus::Corroborated,
            usability: Usability::Verified,
            evidence_ids: vec![signature_evidence_id],
            proof_id: Some(proof_id),
        },
    ]);
}

pub fn compare(
    db: &Database,
    reference_root: Option<&Path>,
    generic_recoveries_applied: usize,
) -> Result<RefineReport> {
    if let Some(root) = reference_root {
        ensure!(
            root.is_dir(),
            "reference root is not a directory: {}",
            root.display()
        );
    }
    let reference = match reference_root {
        Some(root) => parse_reference(root)?,
        None => ReferenceCorpus {
            declarations: vec![],
            classes: BTreeSet::new(),
        },
    };
    let reference_classes = reference.classes;
    let reference = reference.declarations;
    let reference_stub_declarations = count_kind(&reference, "reference-stub");
    let reference_implemented_declarations = count_kind(&reference, "reference-implemented");
    let reference_declaration_only_declarations =
        count_kind(&reference, "reference-declaration-only");
    let reference_inline_declarations = count_kind(&reference, "reference-inline");
    let reference_pure_virtual_declarations = count_kind(&reference, "reference-pure-virtual");
    let reference_special_member_declarations = count_kind(&reference, "reference-special-member");
    let ours = index_windissect(db);
    let theirs = group_reference(reference);
    let our_keys: BTreeSet<_> = ours.signatures.keys().cloned().collect();
    let our_classes: BTreeSet<String> = our_keys.iter().map(|(class, _)| class.clone()).collect();
    let common_classes = our_classes.intersection(&reference_classes).count();
    let windissect_only_classes = our_classes
        .difference(&reference_classes)
        .cloned()
        .collect();
    let reference_only_classes = reference_classes
        .difference(&our_classes)
        .cloned()
        .collect();
    let their_keys: BTreeSet<_> = theirs.keys().cloned().collect();
    let common_methods = our_keys.intersection(&their_keys).count();
    let windissect_only = our_keys
        .difference(&their_keys)
        .map(|(class, method)| format!("{class}::{method}"))
        .collect();
    let reference_only: Vec<Declaration> = their_keys
        .difference(&our_keys)
        .flat_map(|key| theirs[key].clone())
        .collect();
    let stats = reference_only_stats(&reference_only, &our_classes);
    let signature_conflicts = signature_conflicts(&our_keys, &their_keys, &theirs, &ours);
    let class_comparisons =
        class_comparisons(&our_classes, &reference_classes, &our_keys, &their_keys);
    let recovery = recovery_counts(&db.recovery_jobs);
    Ok(RefineReport {
        schema: 1,
        target: db.binary.file.clone(),
        reference_root: reference_root
            .map(|path| path.display().to_string())
            .unwrap_or_default(),
        policy: "reference declarations identify candidates only; exact-build evidence is required for IR promotion",
        generic_recoveries_applied,
        windissect_classes: our_classes.len(),
        reference_classes: reference_classes.len(),
        common_classes,
        windissect_only_classes,
        reference_only_classes,
        windissect_declarations: ours.signatures.values().map(BTreeSet::len).sum(),
        reference_declarations: theirs.values().map(Vec::len).sum(),
        reference_implemented_declarations,
        reference_declaration_only_declarations,
        reference_stub_declarations,
        reference_inline_declarations,
        reference_pure_virtual_declarations,
        reference_special_member_declarations,
        reference_only_stubs: stats.stubs,
        reference_only_implemented: stats.implemented,
        reference_only_declaration_only: stats.declaration_only,
        reference_only_inline: stats.inline,
        reference_only_pure_virtual: stats.pure_virtual,
        reference_only_special_member: stats.special_member,
        reference_only_known_class: stats.known_class,
        reference_only_unknown_class: stats.unknown_class,
        common_methods,
        windissect_only,
        reference_only,
        signature_conflicts,
        class_comparisons,
        recovery_jobs: db.recovery_jobs.len(),
        recovery_unresolved: recovery.unresolved,
        recovery_candidates: recovery.candidates,
        recovery_verified: recovery.verified,
        recovery_withheld: recovery.withheld,
    })
}

fn recovery_counts(jobs: &[RecoveryJob]) -> RecoveryCounts {
    RecoveryCounts {
        unresolved: jobs
            .iter()
            .filter(|job| job.state == RecoveryJobState::Unresolved)
            .count(),
        candidates: jobs
            .iter()
            .filter(|job| job.state == RecoveryJobState::Candidate)
            .count(),
        verified: jobs
            .iter()
            .filter(|job| job.state == RecoveryJobState::Verified)
            .count(),
        withheld: jobs
            .iter()
            .filter(|job| job.state == RecoveryJobState::Withheld)
            .count(),
    }
}

fn count_kind(declarations: &[Declaration], kind: &str) -> usize {
    declarations
        .iter()
        .filter(|item| item.evidence_kind == kind)
        .count()
}

fn index_windissect(db: &Database) -> WindissectIndex {
    let mut signatures: BTreeMap<MethodKey, BTreeSet<String>> = BTreeMap::new();
    let mut arities: BTreeMap<MethodKey, BTreeSet<usize>> = BTreeMap::new();
    for symbol in &db.symbols {
        // Class-owned declarations remain relevant even when an older IR has
        // an over-broad library classification. Refinement must expose stale
        // classifier defects rather than allowing them to hide discrepancies.
        if !symbol.sig.parse_ok {
            continue;
        }
        let (Some(class), Some(method)) = (&symbol.sig.class, &symbol.sig.method) else {
            continue;
        };
        let qualified = qualify(symbol.sig.namespace.as_deref(), class);
        let signature = normalize_signature(&format!(
            "{}({})",
            method,
            symbol
                .sig
                .params
                .iter()
                .map(|p| p.text.as_str())
                .collect::<Vec<_>>()
                .join(",")
        ));
        let key = (qualified, method.clone());
        signatures.entry(key.clone()).or_default().insert(signature);
        arities
            .entry(key)
            .or_default()
            .insert(symbol.sig.params.len());
    }

    WindissectIndex {
        signatures,
        arities,
    }
}

fn group_reference(reference: Vec<Declaration>) -> DeclarationMap {
    let mut theirs: DeclarationMap = BTreeMap::new();
    for declaration in reference {
        theirs
            .entry((declaration.class.clone(), declaration.method.clone()))
            .or_default()
            .push(declaration);
    }
    theirs
}

fn reference_only_stats(
    reference_only: &[Declaration],
    our_classes: &BTreeSet<String>,
) -> ReferenceOnlyStats {
    let implemented = count_kind(reference_only, "reference-implemented");
    let declaration_only = count_kind(reference_only, "reference-declaration-only");
    let stubs = count_kind(reference_only, "reference-stub");
    let inline = count_kind(reference_only, "reference-inline");
    let pure_virtual = count_kind(reference_only, "reference-pure-virtual");
    let special_member = count_kind(reference_only, "reference-special-member");
    let known_class = reference_only
        .iter()
        .filter(|item| {
            item.evidence_kind == "reference-implemented" && our_classes.contains(&item.class)
        })
        .count();
    ReferenceOnlyStats {
        implemented,
        declaration_only,
        stubs,
        inline,
        pure_virtual,
        special_member,
        known_class,
        unknown_class: implemented.saturating_sub(known_class),
    }
}

fn signature_conflicts(
    our_keys: &BTreeSet<MethodKey>,
    their_keys: &BTreeSet<MethodKey>,
    theirs: &DeclarationMap,
    ours: &WindissectIndex,
) -> Vec<SignatureConflict> {
    let mut signature_conflicts = Vec::new();
    for key in our_keys.intersection(their_keys) {
        let reference_arities: BTreeSet<usize> = theirs[key]
            .iter()
            .filter(|item| is_out_of_line_reference(item.evidence_kind))
            .map(|item| item.parameter_count)
            .collect();
        if !reference_arities.is_subset(&ours.arities[key]) {
            signature_conflicts.push(SignatureConflict {
                class: key.0.clone(),
                method: key.1.clone(),
                windissect: ours.signatures[key].iter().cloned().collect(),
                reference: theirs[key].clone(),
            });
        }
    }
    signature_conflicts
}

fn is_out_of_line_reference(kind: &str) -> bool {
    matches!(
        kind,
        "reference-implemented" | "reference-declaration-only" | "reference-stub"
    )
}

fn class_comparisons(
    our_classes: &BTreeSet<String>,
    reference_classes: &BTreeSet<String>,
    our_keys: &BTreeSet<MethodKey>,
    their_keys: &BTreeSet<MethodKey>,
) -> Vec<ClassComparison> {
    let all_classes: BTreeSet<String> = our_classes.union(reference_classes).cloned().collect();
    let mut class_comparisons = Vec::new();
    for class in all_classes {
        let our_methods: BTreeSet<String> = our_keys
            .iter()
            .filter(|(owner, _)| owner == &class)
            .map(|(_, method)| method.clone())
            .collect();
        let reference_methods: BTreeSet<String> = their_keys
            .iter()
            .filter(|(owner, _)| owner == &class)
            .map(|(_, method)| method.clone())
            .collect();
        class_comparisons.push(ClassComparison {
            class,
            windissect_methods: our_methods.len(),
            reference_methods: reference_methods.len(),
            common_methods: our_methods.intersection(&reference_methods).count(),
            windissect_only: our_methods
                .difference(&reference_methods)
                .cloned()
                .collect(),
            reference_only: reference_methods
                .difference(&our_methods)
                .cloned()
                .collect(),
        });
    }
    class_comparisons
}

/// Import every reference declaration as a non-callable candidate and attach
/// any exact class/method/arity matches already present in the IR. This makes
/// the gap machine-actionable without treating the reference as proof.
pub fn import_candidates(db: &mut Database, reference_root: &Path) -> Result<usize> {
    let corpus = parse_reference(reference_root)?;
    let symbol_index = recovery_symbol_index(db);
    let virtual_index = virtual_implementation_index(db);
    let mut candidates = Vec::with_capacity(corpus.declarations.len());
    for declaration in corpus.declarations {
        let key = (
            declaration.class.clone(),
            declaration.method.clone(),
            declaration.parameter_count,
        );
        let mut matched_symbol_ids = symbol_index.get(&key).cloned().unwrap_or_default();
        if matched_symbol_ids.is_empty() && declaration.evidence_kind == "reference-pure-virtual" {
            matched_symbol_ids = virtual_index.get(&key).cloned().unwrap_or_default();
        }
        let id = format!(
            "reference:{}:{}:{}:{}",
            declaration.class, declaration.method, declaration.source_file, declaration.source_line
        );
        candidates.push(ReferenceCandidate {
            id,
            class: declaration.class,
            method: declaration.method,
            signature: declaration.signature,
            parameter_count: declaration.parameter_count,
            source_file: declaration.source_file,
            source_line: declaration.source_line,
            evidence_kind: declaration.evidence_kind.into(),
            matched_symbol_ids,
        });
    }
    candidates.sort_by(|a, b| a.id.cmp(&b.id));
    candidates.dedup_by(|a, b| a.id == b.id);
    let count = candidates.len();
    db.reference_candidates = candidates;
    db.recovery_jobs = build_recovery_jobs(db);
    Ok(count)
}

fn virtual_implementation_index(db: &Database) -> BTreeMap<(String, String, usize), Vec<String>> {
    let proven_claims = db.proven_claim_ids();
    let base_ancestors = proven_base_ancestors(db);
    let table_owners = vtable_semantic_owners(db, &base_ancestors);
    let verified_slots: BTreeSet<(String, u32, u32, u32)> = db
        .claims
        .iter()
        .filter(|claim| proven_claims.contains(claim.id.as_str()))
        .filter_map(|claim| match &claim.subject {
            ClaimSubject::VtableSlot {
                owner,
                table_rva,
                slot,
                target_rva,
                ..
            } => Some((owner.clone(), *table_rva, *slot, *target_rva)),
            _ => None,
        })
        .collect();
    let symbols: BTreeMap<&str, &crate::model::Symbol> = db
        .symbols
        .iter()
        .map(|symbol| (symbol.id.as_str(), symbol))
        .collect();
    let mut index: BTreeMap<_, Vec<String>> = BTreeMap::new();
    for table in &db.vtables {
        let Some(owner) = table
            .get("demangled")
            .and_then(serde_json::Value::as_str)
            .and_then(crate::rtti::vftable_owner_name)
        else {
            continue;
        };
        let Some(table_rva) = value_u32(table, "rva") else {
            continue;
        };
        for entry in table
            .get("entries")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            let (Some(slot), Some(target_rva)) =
                (value_u32(entry, "slot"), value_u32(entry, "target_rva"))
            else {
                continue;
            };
            if !verified_slots.contains(&(owner.to_string(), table_rva, slot, target_rva)) {
                continue;
            }
            let Some(symbol) = entry
                .get("target_id")
                .and_then(serde_json::Value::as_str)
                .or_else(|| {
                    entry
                        .get("signature_source_id")
                        .and_then(serde_json::Value::as_str)
                })
                .and_then(|id| symbols.get(id).copied())
                .filter(|symbol| symbol.sig.parse_ok)
            else {
                continue;
            };
            let Some(method) = &symbol.sig.method else {
                continue;
            };
            for indexed_owner in table_owners.get(&table_rva).into_iter().flatten().cloned() {
                index
                    .entry((indexed_owner, method.clone(), symbol.sig.params.len()))
                    .or_default()
                    .push(symbol.id.clone());
            }
        }
    }
    for symbols in index.values_mut() {
        symbols.sort();
        symbols.dedup();
    }
    index
}

fn proven_base_ancestors(db: &Database) -> BTreeMap<String, BTreeSet<String>> {
    let mut ancestors = BTreeMap::<String, BTreeSet<String>>::new();
    for claim in db.claims.iter().filter(|claim| db.claim_is_proven(claim)) {
        if let ClaimSubject::Base { derived, base, .. } = &claim.subject {
            ancestors
                .entry(derived.clone())
                .or_default()
                .insert(base.clone());
        }
    }
    loop {
        let snapshot = ancestors.clone();
        let mut changed = false;
        for bases in ancestors.values_mut() {
            let inherited: Vec<_> = bases
                .iter()
                .filter_map(|base| snapshot.get(base))
                .flatten()
                .cloned()
                .collect();
            let old_len = bases.len();
            bases.extend(inherited);
            changed |= bases.len() != old_len;
        }
        if !changed {
            break;
        }
    }
    ancestors
}

fn vtable_semantic_owners(
    db: &Database,
    base_ancestors: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeMap<u32, BTreeSet<String>> {
    let mut tables = BTreeMap::<u32, BTreeSet<String>>::new();
    for table in &db.vtables {
        let (Some(rva), Some(demangled)) = (
            value_u32(table, "rva"),
            table.get("demangled").and_then(serde_json::Value::as_str),
        ) else {
            continue;
        };
        let mut owners = BTreeSet::new();
        if let Some(owner) = crate::rtti::vftable_owner_name(demangled) {
            owners.insert(owner.to_string());
        }
        if let Some(derived) = crate::rtti::vftable_derived_name(demangled) {
            owners.insert(derived.to_string());
        }
        let inherited: Vec<_> = owners
            .iter()
            .filter_map(|owner| base_ancestors.get(owner))
            .flatten()
            .cloned()
            .collect();
        owners.extend(inherited);
        tables.entry(rva).or_default().extend(owners);
    }
    tables
}

fn value_u32(value: &serde_json::Value, key: &str) -> Option<u32> {
    value
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .and_then(|number| u32::try_from(number).ok())
}

fn recovery_symbol_index(db: &Database) -> BTreeMap<(String, String, usize), Vec<String>> {
    let mut index: BTreeMap<_, Vec<String>> = BTreeMap::new();
    for symbol in &db.symbols {
        let (Some(class), Some(method)) = (&symbol.sig.class, &symbol.sig.method) else {
            continue;
        };
        if !symbol.sig.parse_ok {
            continue;
        }
        let key = (
            qualify(symbol.sig.namespace.as_deref(), class),
            method.clone(),
            symbol.sig.params.len(),
        );
        index.entry(key).or_default().push(symbol.id.clone());
    }
    index
}

fn build_recovery_jobs(db: &Database) -> Vec<RecoveryJob> {
    let context = recovery_context(db);
    let mut jobs: Vec<_> = db
        .reference_candidates
        .iter()
        .map(|candidate| build_recovery_job(candidate, &context))
        .collect();
    jobs.sort_by(|left, right| left.id.cmp(&right.id));
    jobs
}

fn recovery_context(db: &Database) -> RecoveryContext<'_> {
    let symbols = db
        .symbols
        .iter()
        .map(|symbol| (symbol.id.as_str(), symbol))
        .collect();
    let mut callable_symbols = BTreeSet::new();
    let mut signature_symbols = BTreeSet::new();
    let mut proven_claim_ids: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let proven_claims = db.proven_claim_ids();
    let base_ancestors = proven_base_ancestors(db);
    let table_owners = vtable_semantic_owners(db, &base_ancestors);
    let unresolved_claim_ids: BTreeSet<&str> = db
        .conflicts
        .iter()
        .filter(|conflict| !conflict.resolved)
        .flat_map(|conflict| conflict.claim_ids.iter().map(String::as_str))
        .collect();
    for claim in &db.claims {
        if !proven_claims.contains(claim.id.as_str()) {
            continue;
        }
        let Some(symbol_id) = claim_symbol_id(&claim.subject) else {
            continue;
        };
        proven_claim_ids
            .entry(symbol_id.into())
            .or_default()
            .push(claim.id.clone());
        match claim.subject {
            ClaimSubject::Callable { .. } => {
                callable_symbols.insert(symbol_id.to_string());
            }
            ClaimSubject::Signature { .. } => {
                signature_symbols.insert(symbol_id.to_string());
            }
            _ => {}
        }
    }
    let verified_callable = callable_symbols
        .intersection(&signature_symbols)
        .cloned()
        .collect();
    let conflicted_symbols = db
        .claims
        .iter()
        .filter(|claim| unresolved_claim_ids.contains(claim.id.as_str()))
        .filter_map(|claim| claim_symbol_id(&claim.subject).map(str::to_string))
        .collect();
    let mut symbols_by_rva: BTreeMap<u32, Vec<&str>> = BTreeMap::new();
    for symbol in &db.symbols {
        symbols_by_rva
            .entry(symbol.rva)
            .or_default()
            .push(symbol.id.as_str());
    }
    let mut verified_vslot_claim_ids: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for claim in db
        .claims
        .iter()
        .filter(|claim| proven_claims.contains(claim.id.as_str()))
    {
        let ClaimSubject::VtableSlot {
            owner,
            table_rva,
            target_rva,
            ..
        } = &claim.subject
        else {
            continue;
        };
        let indexed_owners = table_owners
            .get(table_rva)
            .into_iter()
            .flatten()
            .cloned()
            .chain(std::iter::once(owner.clone()));
        for indexed_owner in indexed_owners {
            for symbol_id in symbols_by_rva.get(target_rva).into_iter().flatten() {
                verified_vslot_claim_ids
                    .entry((indexed_owner.clone(), (*symbol_id).into()))
                    .or_default()
                    .push(claim.id.clone());
            }
        }
    }
    RecoveryContext {
        symbols,
        verified_callable,
        conflicted_symbols,
        proven_claim_ids,
        verified_vslot_claim_ids,
    }
}

fn build_recovery_job(
    candidate: &ReferenceCandidate,
    context: &RecoveryContext<'_>,
) -> RecoveryJob {
    let matched: Vec<_> = candidate
        .matched_symbol_ids
        .iter()
        .filter_map(|id| context.symbols.get(id.as_str()).copied())
        .collect();
    let exact: Vec<_> = matched
        .iter()
        .copied()
        .filter(|symbol| {
            canonical_signature(&symbol_signature(symbol))
                == canonical_signature(&candidate.signature)
        })
        .collect();
    let verified: Vec<_> = exact
        .iter()
        .copied()
        .filter(|symbol| {
            context.verified_callable.contains(&symbol.id)
                && (candidate.evidence_kind != "reference-pure-virtual"
                    || context
                        .verified_vslot_claim_ids
                        .contains_key(&(candidate.class.clone(), symbol.id.clone())))
        })
        .collect();
    let conflicted = matched
        .iter()
        .any(|symbol| context.conflicted_symbols.contains(&symbol.id));
    let (state, reason) = recovery_state(candidate, &matched, &exact, &verified, conflicted);
    let verified_ids: BTreeSet<&str> = verified.iter().map(|symbol| symbol.id.as_str()).collect();
    let mut satisfied_claim_ids: Vec<_> = verified_ids
        .iter()
        .filter_map(|id| context.proven_claim_ids.get(*id))
        .flatten()
        .cloned()
        .collect();
    satisfied_claim_ids.sort();
    if candidate.evidence_kind == "reference-pure-virtual" {
        for symbol in &verified {
            if let Some(ids) = context
                .verified_vslot_claim_ids
                .get(&(candidate.class.clone(), symbol.id.clone()))
            {
                satisfied_claim_ids.extend(ids.iter().cloned());
            }
        }
        satisfied_claim_ids.sort();
        satisfied_claim_ids.dedup();
    }
    RecoveryJob {
        id: format!("job:{}", candidate.id),
        candidate_id: candidate.id.clone(),
        kind: recovery_kind(&candidate.evidence_kind),
        state,
        class: candidate.class.clone(),
        method: candidate.method.clone(),
        expected_signature: candidate.signature.clone(),
        matched_symbol_ids: candidate.matched_symbol_ids.clone(),
        evidence_requirements: recovery_requirements(&candidate.evidence_kind),
        satisfied_claim_ids,
        reason,
    }
}

fn recovery_state(
    candidate: &ReferenceCandidate,
    matched: &[&crate::model::Symbol],
    exact: &[&crate::model::Symbol],
    verified: &[&crate::model::Symbol],
    conflicted: bool,
) -> (RecoveryJobState, String) {
    if conflicted {
        return (
            RecoveryJobState::Withheld,
            "matching IR symbols have an unresolved ABI conflict".into(),
        );
    }
    if !verified.is_empty() {
        return (
            RecoveryJobState::Verified,
            format!(
                "{} exact signature match(es) have independent callable and signature proofs",
                verified.len()
            ),
        );
    }
    if !exact.is_empty() {
        return (
            RecoveryJobState::Candidate,
            format!(
                "{} exact signature match(es) lack a complete independent callable proof",
                exact.len()
            ),
        );
    }
    if matched.is_empty() {
        return (
            RecoveryJobState::Unresolved,
            "no independently recovered symbol matches class, method, and arity".into(),
        );
    }
    (
        RecoveryJobState::Candidate,
        format!(
            "{} arity match(es) exist, but none reproduce {}",
            matched.len(),
            candidate.signature
        ),
    )
}

fn symbol_signature(symbol: &crate::model::Symbol) -> String {
    normalize_signature(&format!(
        "{}({})",
        symbol.sig.method.as_deref().unwrap_or(""),
        symbol
            .sig
            .params
            .iter()
            .map(|parameter| parameter.text.as_str())
            .collect::<Vec<_>>()
            .join(",")
    ))
}

fn canonical_signature(signature: &str) -> String {
    let normalized = normalize_abi_aliases(&normalize_signature(signature));
    let (Some(open), Some(close)) = (normalized.find('('), normalized.rfind(')')) else {
        return normalized;
    };
    let parameters = &normalized[open + 1..close];
    let canonical_parameters = if parameters.is_empty() || parameters == "void" {
        String::new()
    } else {
        crate::typeparse::split_top(parameters, ',')
            .into_iter()
            .map(canonical_parameter)
            .collect::<Vec<_>>()
            .join(",")
    };
    format!("{}({canonical_parameters})", normalized[..open].trim())
}

fn canonical_parameter(parameter: &str) -> String {
    let parameter = strip_default_argument(parameter).trim();
    let name_start = parameter
        .char_indices()
        .rev()
        .take_while(|(_, character)| character.is_ascii_alphanumeric() || *character == '_')
        .last()
        .map_or(parameter.len(), |(index, _)| index);
    let candidate_name = &parameter[name_start..];
    let type_prefix = parameter[..name_start].trim_end();
    if candidate_name.is_empty()
        || type_prefix.is_empty()
        || is_type_keyword(candidate_name)
        || is_tag_prefix(type_prefix)
        || type_prefix.ends_with("::")
    {
        normalize_abi_aliases(&normalize_signature(parameter))
    } else {
        normalize_abi_aliases(&normalize_signature(type_prefix))
    }
}

fn normalize_abi_aliases(value: &str) -> String {
    value
        .replace("LPCWSTR", "const unsigned short*")
        .replace("HRESULT", "long")
        .replace("ULONG", "unsigned long")
        .replace("DWORD", "unsigned long")
        .replace("UINT", "unsigned int")
        .replace("WCHAR", "unsigned short")
}

fn strip_default_argument(parameter: &str) -> &str {
    let mut depth = 0_u32;
    for (index, character) in parameter.char_indices() {
        match character {
            '<' | '(' | '[' | '{' => depth = depth.saturating_add(1),
            '>' | ')' | ']' | '}' => depth = depth.saturating_sub(1),
            '=' if depth == 0 => return &parameter[..index],
            _ => {}
        }
    }
    parameter
}

fn is_type_keyword(value: &str) -> bool {
    matches!(
        value,
        "auto"
            | "bool"
            | "char"
            | "char8_t"
            | "char16_t"
            | "char32_t"
            | "const"
            | "double"
            | "float"
            | "int"
            | "long"
            | "short"
            | "signed"
            | "unsigned"
            | "void"
            | "volatile"
            | "wchar_t"
    )
}

fn is_tag_prefix(value: &str) -> bool {
    matches!(
        value,
        "class" | "const" | "enum" | "struct" | "union" | "typename" | "volatile"
    )
}

fn claim_symbol_id(subject: &ClaimSubject) -> Option<&str> {
    match subject {
        ClaimSubject::Callable { symbol_id, .. } | ClaimSubject::Signature { symbol_id, .. } => {
            Some(symbol_id)
        }
        _ => None,
    }
}

fn recovery_kind(evidence_kind: &str) -> RecoveryJobKind {
    match evidence_kind {
        "reference-declaration-only" => RecoveryJobKind::DeclarationOnly,
        "reference-inline" => RecoveryJobKind::InlineDeclaration,
        "reference-pure-virtual" => RecoveryJobKind::PureVirtualDeclaration,
        "reference-special-member" => RecoveryJobKind::SpecialMember,
        "reference-stub" => RecoveryJobKind::StubDeclaration,
        _ => RecoveryJobKind::MissingDeclaration,
    }
}

fn recovery_requirements(evidence_kind: &str) -> Vec<RecoveryRequirement> {
    let mut requirements = vec![
        RecoveryRequirement::SymbolIdentity,
        RecoveryRequirement::ExactSignature,
        RecoveryRequirement::CallingConvention,
        RecoveryRequirement::TypeOrCallsiteEvidence,
    ];
    match evidence_kind {
        "reference-inline" | "reference-declaration-only" => {}
        "reference-pure-virtual" => requirements.push(RecoveryRequirement::VtableSlot),
        _ => requirements.extend([
            RecoveryRequirement::Addressability,
            RecoveryRequirement::ExecutableMapping,
        ]),
    }
    requirements.sort();
    requirements.dedup();
    requirements
}

pub fn write(report: &RefineReport, out: &Path) -> Result<()> {
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent)?;
    }
    crate::diff::atomic_write(out, &serde_json::to_vec_pretty(report)?)
}

fn parse_reference(root: &Path) -> Result<ReferenceCorpus> {
    let mut files = Vec::new();
    collect_headers(root, &mut files)?;
    files.sort();
    let mut declarations = Vec::new();
    let mut classes = BTreeSet::new();
    for file in files {
        parse_header(root, &file, &mut declarations, &mut classes)?;
    }
    mark_source_status(root, &mut declarations)?;
    declarations.sort();
    declarations.dedup();
    Ok(ReferenceCorpus {
        declarations,
        classes,
    })
}

fn mark_source_status(root: &Path, declarations: &mut [Declaration]) -> Result<()> {
    let mut files = Vec::new();
    collect_sources(root, &mut files)?;
    let mut source_lines = Vec::new();
    for file in files {
        let bytes = fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
        let text = String::from_utf8_lossy(&bytes);
        source_lines.extend(text.lines().map(compact_source_line));
    }
    for declaration in declarations
        .iter_mut()
        .filter(|item| item.evidence_kind == "reference-corpus")
    {
        declaration.evidence_kind = source_status(declaration, &source_lines);
    }
    Ok(())
}

fn compact_source_line(line: &str) -> String {
    line.split_whitespace().collect()
}

fn source_status(declaration: &Declaration, source_lines: &[String]) -> &'static str {
    let short_class = declaration
        .class
        .rsplit("::")
        .next()
        .unwrap_or(&declaration.class);
    let needle = format!("{short_class}::{}(", declaration.method);
    let matching_line = source_lines.iter().find(|line| line.contains(&needle));
    match matching_line {
        Some(line) if line.contains("STUB_") => "reference-stub",
        Some(_) => "reference-implemented",
        None => "reference-declaration-only",
    }
}

fn collect_sources(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == ".git") {
                continue;
            }
            collect_sources(&path, files)?;
        } else if path
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|ext| {
                ext.eq_ignore_ascii_case("c")
                    || ext.eq_ignore_ascii_case("cpp")
                    || ext.eq_ignore_ascii_case("cc")
                    || ext.eq_ignore_ascii_case("cxx")
            })
        {
            files.push(path);
        }
    }
    Ok(())
}

fn collect_headers(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == ".git") {
                continue;
            }
            collect_headers(&path, files)?;
        } else if path
            .extension()
            .and_then(|v| v.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("h") || ext.eq_ignore_ascii_case("hpp"))
        {
            files.push(path);
        }
    }
    Ok(())
}

fn parse_header(
    root: &Path,
    file: &Path,
    out: &mut Vec<Declaration>,
    classes: &mut BTreeSet<String>,
) -> Result<()> {
    let bytes = fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let text = String::from_utf8_lossy(&bytes);
    let relative = file
        .strip_prefix(root)
        .unwrap_or(file)
        .to_string_lossy()
        .replace('\\', "/");
    let mut namespace = Vec::<String>::new();
    let mut scopes = Vec::<(usize, Scope)>::new();
    let mut depth = 0usize;
    let mut pending_scope: Option<Scope> = None;
    let mut pending = String::new();
    let mut pending_line = 0usize;
    for (index, original) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = original.split("//").next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('{')
            && let Some(scope) = pending_scope.take()
        {
            if let Scope::Namespace(name) = &scope {
                namespace.push(name.clone());
            }
            scopes.push((depth + 1, scope));
        }
        if let Some(name) = namespace_name(line) {
            let scope = Scope::Namespace(name.clone());
            if line.contains('{') {
                namespace.push(name);
                scopes.push((depth + 1, scope));
            } else {
                pending_scope = Some(scope);
            }
        }
        if let Some(name) = class_decl(line) {
            let qualified = if namespace.is_empty() {
                name.clone()
            } else {
                format!("{}::{name}", namespace.join("::"))
            };
            classes.insert(qualified.clone());
            let scope = Scope::Class(qualified);
            if line.contains('{') {
                scopes.push((depth + 1, scope));
            } else {
                pending_scope = Some(scope);
            }
        }
        if current_class(&scopes).is_some()
            && current_class_depth(&scopes) == Some(depth)
            && !line.starts_with("class ")
            && !line.starts_with("struct ")
        {
            if pending.is_empty() {
                pending_line = line_number;
            } else {
                pending.push(' ');
            }
            pending.push_str(line);
            if (line.contains(';') || line.contains('{')) && pending.contains('(') {
                if let Some((class, method, signature)) =
                    method_decl(current_class(&scopes).unwrap(), &pending)
                {
                    let evidence_kind = reference_evidence_kind(&pending);
                    let parameter_count = parameter_count(&signature);
                    out.push(Declaration {
                        class,
                        method,
                        signature,
                        parameter_count,
                        source_file: relative.clone(),
                        source_line: pending_line,
                        evidence_kind,
                    });
                }
                pending.clear();
            } else if pending.len() > 4096 || line.contains(';') {
                pending.clear();
            }
        }
        depth = depth.saturating_add(line.matches('{').count());
        depth = depth.saturating_sub(line.matches('}').count());
        while scopes
            .last()
            .is_some_and(|(scope_depth, _)| *scope_depth > depth)
        {
            if let Some((_, Scope::Namespace(name))) = scopes.pop()
                && namespace.last() == Some(&name)
            {
                namespace.pop();
            }
        }
    }
    Ok(())
}

fn reference_evidence_kind(declaration: &str) -> &'static str {
    let compact: String = declaration.split_whitespace().collect();
    if compact.contains("=delete") || compact.contains("=default") {
        "reference-special-member"
    } else if compact.contains("=0") {
        "reference-pure-virtual"
    } else if declaration.contains('{') {
        "reference-inline"
    } else {
        "reference-corpus"
    }
}

#[derive(Debug)]
enum Scope {
    Namespace(String),
    Class(String),
}

fn current_class(scopes: &[(usize, Scope)]) -> Option<&str> {
    scopes.iter().rev().find_map(|(_, scope)| match scope {
        Scope::Class(name) => Some(name.as_str()),
        Scope::Namespace(_) => None,
    })
}

fn current_class_depth(scopes: &[(usize, Scope)]) -> Option<usize> {
    scopes
        .iter()
        .rev()
        .find_map(|(depth, scope)| matches!(scope, Scope::Class(_)).then_some(*depth))
}

fn namespace_name(line: &str) -> Option<String> {
    let rest = line.strip_prefix("namespace ")?;
    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

fn class_decl(line: &str) -> Option<String> {
    let rest = line
        .strip_prefix("class ")
        .or_else(|| line.strip_prefix("struct "))?;
    if line.ends_with(';') && !line.contains('{') {
        return None;
    }
    let head = rest.split([':', '{']).next()?.trim();
    let name = head.split_whitespace().next_back()?;
    if !name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return None;
    }
    if name.contains('_') && name.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
        return None;
    }
    Some(name.to_string())
}

fn method_decl(class: &str, statement: &str) -> Option<(String, String, String)> {
    let open = statement.find('(')?;
    let before = statement[..open].trim();
    if ["if", "for", "while", "switch", "return", "static_assert"]
        .iter()
        .any(|kw| before.ends_with(kw))
    {
        return None;
    }
    let method = before
        .split_whitespace()
        .last()?
        .trim_matches(|c: char| c == '*' || c == '&');
    let method = method.rsplit("::").next().unwrap_or(method);
    if method.is_empty() || method.starts_with("DECLARE_") || method.starts_with("STDMETHOD") {
        return None;
    }
    let close = statement[open..].find(')')? + open;
    let signature = normalize_signature(&format!("{}{}", method, &statement[open..=close]));
    Some((class.to_string(), method.to_string(), signature))
}

fn qualify(namespace: Option<&str>, class: &str) -> String {
    namespace
        .filter(|value| !value.is_empty() && *value != "global")
        .map_or_else(
            || class.to_string(),
            |namespace| format!("{namespace}::{class}"),
        )
}

fn normalize_signature(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace(" ,", ",")
        .replace("( ", "(")
        .replace(" )", ")")
}

fn parameter_count(signature: &str) -> usize {
    let Some(open) = signature.find('(') else {
        return 0;
    };
    let Some(close) = signature.rfind(')') else {
        return 0;
    };
    let params = signature[open + 1..close].trim();
    if params.is_empty() || params == "void" {
        0
    } else {
        crate::typeparse::split_top(params, ',').len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Claim, ClaimStatus, Confidence, Conflict, Coverage, Evidence, EvidenceKind,
        EvidenceLocation, EvidenceObservation, EvidenceTool, FunctionAnalysis, InstructionRecord,
        Kind, Proof, ProofObligation, Provenance, Signature, Symbol, Usability,
    };

    fn example_symbol() -> Symbol {
        let signature = Signature {
            namespace: Some("Example".into()),
            class: Some("Widget".into()),
            method: Some("Run".into()),
            parse_ok: true,
            ..Signature::default()
        };
        Symbol {
            id: "?Run@Widget@Example@@".into(),
            mangled: "?Run@Widget@Example@@".into(),
            demangled: Some("Example::Widget::Run()".into()),
            vaddr: 0x0000_0001_8000_1000,
            rva: 0x1000,
            ordinal: None,
            size: 8,
            procedure_size: Some(8),
            is_code: true,
            forwarder: None,
            body_hash: String::new(),
            exported: false,
            library: false,
            kind: Kind::Method,
            coverage: Coverage::Auto,
            provenance: Provenance::Pdb,
            confidence: Confidence::Certain,
            sig: signature,
            callers: Vec::new(),
            calls: Vec::new(),
            imports: Vec::new(),
        }
    }

    fn example_candidate(symbol_id: &str) -> ReferenceCandidate {
        ReferenceCandidate {
            id: "reference:widget-run".into(),
            class: "Example::Widget".into(),
            method: "Run".into(),
            signature: "Run()".into(),
            parameter_count: 0,
            source_file: "widget.hpp".into(),
            source_line: 10,
            evidence_kind: "reference-corpus".into(),
            matched_symbol_ids: vec![symbol_id.into()],
        }
    }

    fn proven_claim(id: &str, subject: ClaimSubject) -> (Evidence, Claim, Proof) {
        let evidence_id = format!("evidence:{id}");
        let proof_id = format!("proof:{id}");
        (
            Evidence {
                id: evidence_id.clone(),
                kind: EvidenceKind::PdbRecord,
                tool: EvidenceTool::Pdb,
                rule_id: "test-independent-recovery".into(),
                rule_version: 1,
                location: EvidenceLocation::default(),
                observation: EvidenceObservation::Text {
                    text: "exact-build evidence".into(),
                },
            },
            Claim {
                id: id.into(),
                subject,
                status: ClaimStatus::Corroborated,
                usability: Usability::Verified,
                evidence_ids: vec![evidence_id],
                proof_id: Some(proof_id.clone()),
            },
            Proof {
                id: proof_id,
                rule_id: "test-independent-recovery".into(),
                rule_version: 1,
                passed: true,
                obligations: vec![ProofObligation {
                    name: "exact-build source".into(),
                    satisfied: true,
                    detail: "fixture proof".into(),
                }],
            },
        )
    }

    #[test]
    fn extracts_class_method() {
        assert_eq!(
            method_decl(
                "DirectUI::Button",
                "virtual HRESULT OnClick(Element * value) const;"
            ),
            Some((
                "DirectUI::Button".into(),
                "OnClick".into(),
                "OnClick(Element * value)".into()
            ))
        );
    }

    #[test]
    fn normalizes_ir_qualification() {
        assert_eq!(qualify(Some("DirectUI"), "Element"), "DirectUI::Element");
    }

    #[test]
    fn canonical_signature_ignores_parameter_names_and_defaults() {
        assert_eq!(
            canonical_signature("Run(Element * value, unsigned int flags = 0)"),
            canonical_signature("Run(Element *, unsigned int)")
        );
        assert_eq!(
            canonical_signature("Set(const Example & value)"),
            canonical_signature("Set(const Example &)")
        );
        assert_eq!(
            canonical_signature("Copy(const Example)"),
            "Copy(const Example)"
        );
    }

    #[test]
    fn reference_match_without_ir_proof_stays_candidate() {
        let symbol = example_symbol();
        let candidate = example_candidate(&symbol.id);
        let mut db = Database::default();
        db.symbols.push(symbol);
        db.reference_candidates.push(candidate);

        let jobs = build_recovery_jobs(&db);

        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].state, RecoveryJobState::Candidate);
        assert_eq!(jobs[0].satisfied_claim_ids, Vec::<String>::new());
    }

    #[test]
    fn independent_callable_and_signature_proofs_verify_job() {
        let symbol = example_symbol();
        let candidate = example_candidate(&symbol.id);
        let (callable_evidence, callable_claim, callable_proof) = proven_claim(
            "claim:callable",
            ClaimSubject::Callable {
                symbol_id: symbol.id.clone(),
                rva: symbol.rva,
            },
        );
        let (signature_evidence, signature_claim, signature_proof) = proven_claim(
            "claim:signature",
            ClaimSubject::Signature {
                symbol_id: symbol.id.clone(),
                signature: symbol.sig.clone(),
            },
        );
        let mut db = Database::default();
        db.symbols.push(symbol);
        db.reference_candidates.push(candidate);
        db.evidence.extend([callable_evidence, signature_evidence]);
        db.claims.extend([callable_claim, signature_claim]);
        db.proofs.extend([callable_proof, signature_proof]);

        let jobs = build_recovery_jobs(&db);

        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].state, RecoveryJobState::Verified);
        assert_eq!(jobs[0].satisfied_claim_ids.len(), 2);
    }

    #[test]
    fn pdb_procedure_and_decoded_body_create_idempotent_proof() {
        let symbol = example_symbol();
        let symbol_id = symbol.id.clone();
        let mut db = Database {
            binary: crate::model::BinaryInfo {
                sha256: Some("exact-pe-hash".into()),
                pdb_guid: Some("00112233445566778899AABBCCDDEEFF".into()),
                pdb_age: Some(1),
                ..crate::model::BinaryInfo::default()
            },
            symbols: vec![symbol],
            functions: vec![FunctionAnalysis {
                rva: 0x1000,
                size: 8,
                symbol_ids: vec![symbol_id.clone()],
                instructions: vec![InstructionRecord {
                    rva: 0x1000,
                    length: 1,
                    bytes: "C3".into(),
                    mnemonic: "ret".into(),
                    text: "ret".into(),
                    flow: "return".into(),
                    branch_target_rva: None,
                    memory_target_rva: None,
                }],
                cfg_edges: Vec::new(),
            }],
            ..Database::default()
        };

        assert_eq!(recover_pdb_callable_proofs(&mut db), 1);
        assert_eq!(recover_pdb_callable_proofs(&mut db), 0);
        assert!(db.symbol_is_verified_callable(&symbol_id));
        assert_eq!(db.claims.len(), 2);
        assert_eq!(db.evidence.len(), 2);
        assert_eq!(db.proofs.len(), 1);
    }

    #[test]
    fn pure_virtual_job_requires_vtable_evidence() {
        assert!(
            recovery_requirements("reference-pure-virtual")
                .contains(&RecoveryRequirement::VtableSlot)
        );
    }

    #[test]
    fn distinguishes_implemented_stub_and_declaration_only_references() {
        let declaration = Declaration {
            class: "Example::Widget".into(),
            method: "Run".into(),
            signature: "Run()".into(),
            parameter_count: 0,
            source_file: "widget.hpp".into(),
            source_line: 4,
            evidence_kind: "reference-corpus",
        };
        assert_eq!(
            source_status(&declaration, &["voidWidget::Run(){}".into()]),
            "reference-implemented"
        );
        assert_eq!(
            source_status(&declaration, &["voidWidget::Run()STUB_VOID;".into()]),
            "reference-stub"
        );
        assert_eq!(
            source_status(&declaration, &["voidWidget::Stop(){}".into()]),
            "reference-declaration-only"
        );
    }

    #[test]
    fn upgrades_exact_vtable_structure_without_trusting_target_alias() {
        let evidence_id = "ev:vtable-slot:1000:0".to_string();
        let proof_id = "proof:vtable-slot:1000:0".to_string();
        let claim_id = "claim:vtable-slot:1000:0".to_string();
        let mut db = Database {
            evidence: vec![Evidence {
                id: evidence_id.clone(),
                kind: EvidenceKind::Rtti,
                tool: EvidenceTool::Windissect,
                rule_id: "msvc.pe-vftable-slot".into(),
                rule_version: 1,
                location: EvidenceLocation::default(),
                observation: EvidenceObservation::Text {
                    text: "exact slot bytes".into(),
                },
            }],
            proofs: vec![Proof {
                id: proof_id.clone(),
                rule_id: "msvc.pe-vftable-slot".into(),
                rule_version: 1,
                passed: true,
                obligations: vec![ProofObligation {
                    name: "executable-target".into(),
                    satisfied: true,
                    detail: "fixture".into(),
                }],
            }],
            claims: vec![Claim {
                id: claim_id.clone(),
                subject: ClaimSubject::VtableSlot {
                    owner: "const Example::Widget::`vftable'".into(),
                    table_rva: 0x1000,
                    table_object_offset: None,
                    slot: 0,
                    target_rva: 0x2000,
                },
                status: ClaimStatus::Observed,
                usability: Usability::MetadataOnly,
                evidence_ids: vec![evidence_id],
                proof_id: Some(proof_id),
            }],
            conflicts: vec![Conflict {
                id: "conflict:vtable-slot:1000:0".into(),
                claim_ids: vec![claim_id],
                reason: "ICF aliases disagree on ABI signature; callable identity withheld".into(),
                resolved: false,
            }],
            ..Database::default()
        };

        assert_eq!(recover_vtable_structure_proofs(&mut db), 1);
        assert!(db.conflicts.is_empty());
        assert!(db.claim_is_proven(&db.claims[0]));
        assert!(matches!(
            &db.claims[0].subject,
            ClaimSubject::VtableSlot { owner, .. } if owner == "Example::Widget"
        ));
    }

    #[test]
    fn indexes_verified_override_as_interface_implementation() {
        let symbol = example_symbol();
        let (evidence, claim, proof) = proven_claim(
            "claim:interface-slot",
            ClaimSubject::VtableSlot {
                owner: "Example::Interface".into(),
                table_rva: 0x3000,
                table_object_offset: None,
                slot: 0,
                target_rva: symbol.rva,
            },
        );
        let db = Database {
            symbols: vec![symbol.clone()],
            evidence: vec![evidence],
            claims: vec![claim],
            proofs: vec![proof],
            vtables: vec![serde_json::json!({
                "demangled": "const Example::Impl::`vftable'{for `Example::Interface'}",
                "rva": 0x3000,
                "entries": [{
                    "slot": 0,
                    "target_rva": symbol.rva,
                    "signature_source_id": symbol.id,
                }]
            })],
            ..Database::default()
        };

        let index = virtual_implementation_index(&db);

        assert_eq!(
            index.get(&("Example::Interface".into(), "Run".into(), 0)),
            Some(&vec!["?Run@Widget@Example@@".into()])
        );
    }

    #[test]
    fn propagates_verified_override_through_proven_base_relationship() {
        let symbol = example_symbol();
        let (slot_evidence, slot_claim, slot_proof) = proven_claim(
            "claim:impl-slot",
            ClaimSubject::VtableSlot {
                owner: "Example::Impl".into(),
                table_rva: 0x3000,
                table_object_offset: None,
                slot: 0,
                target_rva: symbol.rva,
            },
        );
        let (base_evidence, base_claim, base_proof) = proven_claim(
            "claim:impl-base",
            ClaimSubject::Base {
                derived: "Example::Impl".into(),
                base: "Example::Interface".into(),
                offset: None,
                is_virtual: false,
            },
        );
        let db = Database {
            symbols: vec![symbol.clone()],
            evidence: vec![slot_evidence, base_evidence],
            claims: vec![slot_claim, base_claim],
            proofs: vec![slot_proof, base_proof],
            vtables: vec![serde_json::json!({
                "demangled": "const Example::Impl::`vftable'",
                "rva": 0x3000,
                "entries": [{
                    "slot": 0,
                    "target_rva": symbol.rva,
                    "signature_source_id": symbol.id,
                }]
            })],
            ..Database::default()
        };

        let index = virtual_implementation_index(&db);

        assert_eq!(
            index.get(&("Example::Interface".into(), "Run".into(), 0)),
            Some(&vec!["?Run@Widget@Example@@".into()])
        );
    }

    #[test]
    fn constructor_edge_corroborates_typed_base_relationship() {
        let mut derived = example_symbol();
        derived.id = "??0Derived@Example@@QEAA@XZ".into();
        derived.mangled.clone_from(&derived.id);
        derived.rva = 0x1100;
        derived.kind = Kind::Ctor;
        derived.sig.class = Some("Derived".into());
        derived.sig.method = Some("Derived".into());
        derived.calls = vec!["??0Base@Example@@QEAA@XZ".into()];
        let mut base = example_symbol();
        base.id = "??0Base@Example@@QEAA@XZ".into();
        base.mangled.clone_from(&base.id);
        base.rva = 0x1200;
        base.kind = Kind::Ctor;
        base.sig.class = Some("Base".into());
        base.sig.method = Some("Base".into());
        let evidence_id = "ev:template-base:fixture".to_string();
        let mut db = Database {
            symbols: vec![derived, base],
            evidence: vec![Evidence {
                id: evidence_id.clone(),
                kind: EvidenceKind::PdbRecord,
                tool: EvidenceTool::Pdb,
                rule_id: "fixture.typed-base".into(),
                rule_version: 1,
                location: EvidenceLocation::default(),
                observation: EvidenceObservation::TemplateBase {
                    derived: "Example::Derived".into(),
                    base: "Example::Base".into(),
                    symbol_id: "fixture".into(),
                },
            }],
            claims: vec![Claim {
                id: "claim:base:fixture".into(),
                subject: ClaimSubject::Base {
                    derived: "Example::Derived".into(),
                    base: "Example::Base".into(),
                    offset: None,
                    is_virtual: false,
                },
                status: ClaimStatus::Candidate,
                usability: Usability::MetadataOnly,
                evidence_ids: vec![evidence_id],
                proof_id: None,
            }],
            ..Database::default()
        };

        assert_eq!(recover_ctor_base_proofs(&mut db), 1);
        assert_eq!(recover_ctor_base_proofs(&mut db), 0);
        let recovered = db
            .claims
            .iter()
            .find(|claim| claim.id.starts_with("claim:ctor-base:"))
            .expect("recovered base claim");
        assert!(db.claim_is_proven(recovered));
        assert!(matches!(
            &recovered.subject,
            ClaimSubject::Base { derived, base, offset: None, .. }
                if derived == "Example::Derived" && base == "Example::Base"
        ));
    }

    #[test]
    fn constructor_to_destructor_edge_does_not_prove_inheritance() {
        let mut derived = example_symbol();
        derived.id = "??0Derived@Example@@QEAA@XZ".into();
        derived.mangled.clone_from(&derived.id);
        derived.kind = Kind::Ctor;
        derived.sig.class = Some("Derived".into());
        derived.calls = vec!["??1Base@Example@@QEAA@XZ".into()];
        let mut base = example_symbol();
        base.id = "??1Base@Example@@QEAA@XZ".into();
        base.mangled.clone_from(&base.id);
        base.kind = Kind::Dtor;
        base.sig.class = Some("Base".into());
        let evidence_id = "ev:template-base:negative".to_string();
        let mut db = Database {
            symbols: vec![derived, base],
            evidence: vec![Evidence {
                id: evidence_id.clone(),
                kind: EvidenceKind::PdbRecord,
                tool: EvidenceTool::Pdb,
                rule_id: "fixture.typed-base".into(),
                rule_version: 1,
                location: EvidenceLocation::default(),
                observation: EvidenceObservation::TemplateBase {
                    derived: "Example::Derived".into(),
                    base: "Example::Base".into(),
                    symbol_id: "fixture".into(),
                },
            }],
            claims: vec![Claim {
                id: "claim:base:negative".into(),
                subject: ClaimSubject::Base {
                    derived: "Example::Derived".into(),
                    base: "Example::Base".into(),
                    offset: None,
                    is_virtual: false,
                },
                status: ClaimStatus::Candidate,
                usability: Usability::MetadataOnly,
                evidence_ids: vec![evidence_id],
                proof_id: None,
            }],
            ..Database::default()
        };

        assert_eq!(recover_ctor_base_proofs(&mut db), 0);
    }
}
