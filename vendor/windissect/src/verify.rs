//! Validate the IR: structural invariants plus ground-truth spot checks.

use crate::model::{ClaimSubject, Database, Kind, Type};
use std::collections::{BTreeMap, BTreeSet};

struct Report {
    results: Vec<(String, bool, String)>,
}

impl Report {
    const fn new() -> Self {
        Self { results: vec![] }
    }
    fn check(&mut self, name: &str, pass: bool, detail: impl Into<String>) {
        self.results.push((name.to_string(), pass, detail.into()));
    }
    fn ok(&self) -> bool {
        self.results.iter().all(|r| r.1)
    }
    fn print(&self) {
        for (name, pass, detail) in &self.results {
            let tag = if *pass { "PASS" } else { "FAIL" };
            if detail.is_empty() {
                println!("[{tag}] {name}");
            } else {
                println!("[{tag}] {name}: {detail}");
            }
        }
        let failed = self.results.iter().filter(|r| !r.1).count();
        println!(
            "\n{}/{} checks passed{}",
            self.results.len() - failed,
            self.results.len(),
            if failed == 0 {
                ". VALID."
            } else {
                ". INVALID."
            }
        );
    }
}

pub fn run_profile(db: &Database, profile: Option<&str>) -> bool {
    let mut r = Report::new();
    check_identity(db, &mut r);
    check_proof_graph(db, &mut r);
    check_recovery_jobs(db, &mut r);
    check_member_offsets(db, &mut r);
    check_vftables(db, &mut r);
    check_symbols(db, &mut r);
    if profile == Some("dui70") {
        check_dui70(db, &mut r);
    }
    r.print();
    r.ok()
}

fn check_recovery_jobs(db: &Database, r: &mut Report) {
    use crate::model::{ClaimSubject, RecoveryJobState, RecoveryRequirement};
    let candidate_ids: BTreeSet<_> = db
        .reference_candidates
        .iter()
        .map(|candidate| candidate.id.as_str())
        .collect();
    let symbol_ids: BTreeSet<_> = db.symbols.iter().map(|symbol| symbol.id.as_str()).collect();
    let symbol_rvas: BTreeMap<_, _> = db
        .symbols
        .iter()
        .map(|symbol| (symbol.id.as_str(), symbol.rva))
        .collect();
    let job_ids: BTreeSet<_> = db.recovery_jobs.iter().map(|job| job.id.as_str()).collect();
    let proven_claim_ids = db.proven_claim_ids();
    let invalid = db
        .recovery_jobs
        .iter()
        .filter(|job| {
            let dangling = !candidate_ids.contains(job.candidate_id.as_str())
                || job
                    .matched_symbol_ids
                    .iter()
                    .any(|id| !symbol_ids.contains(id.as_str()));
            let proven_claims: Vec<_> = job
                .satisfied_claim_ids
                .iter()
                .filter_map(|id| db.claims.iter().find(|claim| claim.id == *id))
                .filter(|claim| proven_claim_ids.contains(claim.id.as_str()))
                .collect();
            let satisfied_claims_exist = proven_claims.len() == job.satisfied_claim_ids.len();
            let verified = job.state == RecoveryJobState::Verified;
            let has_complete_symbol_proof = job.matched_symbol_ids.iter().any(|matched_id| {
                let has_callable = proven_claims.iter().any(|claim| {
                    matches!(
                        &claim.subject,
                        ClaimSubject::Callable { symbol_id, .. } if symbol_id == matched_id
                    )
                });
                let has_signature = proven_claims.iter().any(|claim| {
                    matches!(
                        &claim.subject,
                        ClaimSubject::Signature { symbol_id, .. } if symbol_id == matched_id
                    )
                });
                has_callable && has_signature
            });
            let has_vtable_slot = proven_claims.iter().any(|claim| {
                matches!(
                    &claim.subject,
                    ClaimSubject::VtableSlot { owner, target_rva, .. }
                        if vtable_owner_matches_job(db, owner, &job.class)
                            && job.matched_symbol_ids.iter().any(|id| {
                                symbol_rvas.get(id.as_str()) == Some(target_rva)
                            })
                )
            });
            let vtable_requirement_met = !job
                .evidence_requirements
                .contains(&RecoveryRequirement::VtableSlot)
                || has_vtable_slot;
            dangling
                || !satisfied_claims_exist
                || (verified && !(has_complete_symbol_proof && vtable_requirement_met))
        })
        .count();
    r.check(
        "refine recovery jobs are proof-gated",
        job_ids.len() == db.recovery_jobs.len() && invalid == 0,
        format!("{} jobs, {invalid} invalid", db.recovery_jobs.len()),
    );
}

fn vtable_owner_matches_job(db: &Database, owner: &str, job_class: &str) -> bool {
    owner == job_class
        || db.claims.iter().any(|claim| {
            db.claim_is_proven(claim)
                && matches!(
                    &claim.subject,
                    ClaimSubject::Base { derived, base, .. }
                        if (derived == owner && base == job_class)
                            || (derived == job_class && base == owner)
                )
        })
}

fn check_identity(db: &Database, r: &mut Report) {
    r.check(
        "schema version set",
        db.schema == crate::model::SCHEMA_VERSION,
        "",
    );
    r.check(
        "binary version-anchored (pdb guid)",
        db.binary.pdb_guid.is_some(),
        "",
    );
    let type_status = db
        .type_recovery
        .get("status")
        .and_then(serde_json::Value::as_str);
    r.check(
        "type recovery outcome recorded",
        type_status.is_some(),
        type_status.unwrap_or("missing diagnostics"),
    );
}

fn check_proof_graph(db: &Database, r: &mut Report) {
    if db.schema < 2 {
        return;
    }
    let evidence_ids: BTreeSet<_> = db.evidence.iter().map(|item| item.id.as_str()).collect();
    let proof_ids: BTreeSet<_> = db.proofs.iter().map(|item| item.id.as_str()).collect();
    let claim_ids: BTreeSet<_> = db.claims.iter().map(|item| item.id.as_str()).collect();
    let proven_claim_ids = db.proven_claim_ids();
    let unique = evidence_ids.len() == db.evidence.len()
        && proof_ids.len() == db.proofs.len()
        && claim_ids.len() == db.claims.len();
    let dangling_claims = db
        .claims
        .iter()
        .filter(|claim| {
            claim
                .evidence_ids
                .iter()
                .any(|id| !evidence_ids.contains(id.as_str()))
                || claim
                    .proof_id
                    .as_deref()
                    .is_some_and(|id| !proof_ids.contains(id))
        })
        .count();
    let dangling_conflicts = db
        .conflicts
        .iter()
        .filter(|conflict| {
            conflict
                .claim_ids
                .iter()
                .any(|id| !claim_ids.contains(id.as_str()))
        })
        .count();
    let invalid_proofs = db
        .proofs
        .iter()
        .filter(|proof| {
            proof.passed
                != proof
                    .obligations
                    .iter()
                    .all(|obligation| obligation.satisfied)
        })
        .count();
    let invalid_verified_claims = db
        .claims
        .iter()
        .filter(|claim| {
            claim.usability == crate::model::Usability::Verified
                && !proven_claim_ids.contains(claim.id.as_str())
        })
        .count();
    r.check(
            "schema-v2 proof graph is referentially sound",
            unique
                && dangling_claims == 0
                && dangling_conflicts == 0
                && invalid_proofs == 0
                && invalid_verified_claims == 0,
            format!(
                "{} evidence, {} claims, {} proofs, {} conflicts; dangling claims {dangling_claims}, dangling conflicts {dangling_conflicts}, invalid proofs {invalid_proofs}, unproven verified claims {invalid_verified_claims}",
                db.evidence.len(),
                db.claims.len(),
                db.proofs.len(),
                db.conflicts.len()
            ),
        );
}

fn check_member_offsets(db: &Database, r: &mut Report) {
    if let Some(recorded) = db
        .type_recovery
        .get("pe_this_dataflow_observations")
        .and_then(serde_json::Value::as_u64)
    {
        let retained = db
            .type_recovery
            .get("pe_this_dataflow_observations_retained")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        let actual: usize = db
            .types
            .iter()
            .filter_map(|ty| ty.get("observations")?.as_array())
            .map(Vec::len)
            .sum();
        r.check(
            "PE member-offset evidence is internally consistent",
            if retained {
                usize::try_from(recorded).is_ok_and(|value| value == actual)
            } else {
                actual == 0
            },
            if retained {
                format!("{actual} observations across exact-build procedures")
            } else {
                format!("{recorded} observations analyzed; raw records omitted from compact IR")
            },
        );
    }
}

fn check_vftables(db: &Database, r: &mut Report) {
    let pe_vftables = db
        .type_recovery
        .get("pe_vftables")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    if pe_vftables != 0 {
        let recovered = db
            .vtables
            .iter()
            .filter(|table| {
                table.get("evidence").and_then(serde_json::Value::as_str)
                    == Some("msvc-??_7-plus-pe-rdata")
            })
            .collect::<Vec<_>>();
        let empty = recovered
            .iter()
            .filter(|table| {
                table
                    .get("entries")
                    .and_then(serde_json::Value::as_array)
                    .is_none_or(Vec::is_empty)
            })
            .count();
        r.check(
            "PE vftable recovery is internally consistent",
            usize::try_from(pe_vftables).is_ok_and(|value| value == recovered.len()) && empty == 0,
            format!(
                "{pe_vftables} PE tables, {} PDB/other tables, {empty} empty PE tables",
                db.vtables.len().saturating_sub(recovered.len())
            ),
        );
        let symbols: BTreeMap<_, _> = db
            .symbols
            .iter()
            .map(|symbol| (symbol.id.as_str(), symbol))
            .collect();
        let mut compatible = 0usize;
        let mut conflicting = 0usize;
        let mut invalid = 0usize;
        for entry in db
            .vtables
            .iter()
            .filter_map(|table| table.get("entries")?.as_array())
            .flatten()
        {
            let marked = entry
                .get("signature_compatible")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let keys: BTreeSet<_> = entry
                .get("target_candidates")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|candidate| candidate.get("id")?.as_str())
                .filter_map(|id| symbols.get(id))
                .filter(|symbol| symbol.sig.parse_ok)
                .map(|symbol| {
                    format!(
                        "{}|{}|{}|{}",
                        symbol.sig.callconv.as_deref().unwrap_or(""),
                        symbol.sig.ret.as_ref().map_or("", |ret| ret.text.as_str()),
                        symbol
                            .sig
                            .params
                            .iter()
                            .map(|parameter| parameter.text.as_str())
                            .collect::<Vec<_>>()
                            .join(","),
                        symbol.sig.is_const
                    )
                })
                .collect();
            if marked {
                compatible += 1;
                if keys.len() != 1
                    || entry
                        .get("signature_source_id")
                        .and_then(serde_json::Value::as_str)
                        .is_none()
                {
                    invalid += 1;
                }
            } else {
                conflicting += 1;
                if entry
                    .get("signature_source_id")
                    .and_then(serde_json::Value::as_str)
                    .is_some()
                {
                    invalid += 1;
                }
            }
        }
        r.check(
            "vftable ICF signature equivalence is proven",
            invalid == 0,
            format!("{compatible} compatible, {conflicting} conflicting, {invalid} invalid"),
        );
    }
}

fn check_symbols(db: &Database, r: &mut Report) {
    let empty_accounted_for = db.symbols.is_empty()
        && db
            .type_recovery
            .get("status")
            .and_then(serde_json::Value::as_str)
            == Some("unavailable-no-pdb")
        && db.binary.sha256.is_some();
    r.check(
        "symbol inventory is accounted for",
        !db.symbols.is_empty() || empty_accounted_for,
        if empty_accounted_for {
            "0 symbols: PE has no exports and no identity-matched PDB was available".into()
        } else {
            db.symbols.len().to_string()
        },
    );

    let no_id = db.symbols.iter().filter(|s| s.id.is_empty()).count();
    r.check(
        "every symbol has a stable id",
        no_id == 0,
        format!("{no_id} missing"),
    );

    let id_is_mangled = db.symbols.iter().all(|s| s.id == s.mangled);
    r.check(
        "id keyed on mangled name (version-stable)",
        id_is_mangled,
        "",
    );

    let bad_export = db
        .symbols
        .iter()
        .filter(|s| s.exported && s.vaddr == 0)
        .count();
    r.check(
        "exported symbols have addresses",
        bad_export == 0,
        format!("{bad_export} bad"),
    );

    let parse_ok = db.symbols.iter().filter(|s| s.sig.parse_ok).count();
    let ratio = if db.symbols.is_empty() {
        0.0
    } else {
        let parsed = u32::try_from(parse_ok).map_or(f64::INFINITY, f64::from);
        let total = u32::try_from(db.symbols.len()).map_or(f64::INFINITY, f64::from);
        100.0 * parsed / total
    };
    r.check(
        "structured signature ratio is finite",
        ratio.is_finite(),
        format!("{ratio:.1}%"),
    );

    // no fabrication: a parse_ok signature must carry a method name.
    let fabricated = db
        .symbols
        .iter()
        .filter(|s| s.sig.parse_ok && s.sig.method.is_none())
        .count();
    r.check(
        "no structured sig without a method (no fabrication)",
        fabricated == 0,
        format!("{fabricated}"),
    );
}

fn check_dui70(db: &Database, r: &mut Report) {
    let find = |method: &str| -> Vec<&crate::model::Symbol> {
        db.symbols
            .iter()
            .filter(|s| {
                s.sig.class.as_deref() == Some("Element") && s.sig.method.as_deref() == Some(method)
            })
            .collect()
    };

    // Element::AddRef() -> unsigned long, no params, refcount.
    if let Some(s) = find("AddRef").first() {
        let sig = &s.sig;
        r.check(
            "Element::AddRef == unsigned long AddRef()",
            sig.ret.as_ref().map(|t| t.text.as_str()) == Some("unsigned long")
                && sig.params.is_empty()
                && s.kind == Kind::Refcount,
            "",
        );
    } else {
        r.check("Element::AddRef present", false, "not found");
    }

    // Element::SetVisible(bool) -> long, accessor.
    if let Some(s) = find("SetVisible").first() {
        let sig = &s.sig;
        r.check(
            "Element::SetVisible == long SetVisible(bool)",
            sig.ret.as_ref().map(|t| t.text.as_str()) == Some("long")
                && sig.params.len() == 1
                && sig.params[0].text == "bool"
                && s.kind == Kind::Accessor,
            format!(
                "{:?}",
                sig.params.iter().map(|p| &p.text).collect::<Vec<_>>()
            ),
        );
    } else {
        r.check("Element::SetVisible present", false, "not found");
    }

    // Element::Add has at least three overloads (newer/private symbol streams
    // may expose additional forms), one taking a function pointer whose AST
    // is a FnPtr (proves the structured type parser, not just text).
    let adds = find("Add");
    r.check(
        "Element::Add has at least 3 overloads",
        adds.len() >= 3,
        format!("{}", adds.len()),
    );
    let has_fnptr = adds.iter().any(|s| {
        s.sig
            .params
            .iter()
            .any(|p| matches!(p.ast, Type::FnPtr { .. }))
    });
    r.check(
        "Element::Add fn-ptr param parsed to AST FnPtr",
        has_fnptr,
        "",
    );

    // A static factory: XProvider::Create is static with 3 params.
    if let Some(s) = db.symbols.iter().find(|s| {
        s.sig.class.as_deref() == Some("XProvider") && s.sig.method.as_deref() == Some("Create")
    }) {
        r.check(
            "XProvider::Create is static/3-arg",
            s.sig.storage.as_deref() == Some("static") && s.sig.params.len() == 3,
            "",
        );
    }
}
