//! Proof-gated semantic projection and constraint aggregation.

use crate::model::{
    Claim, ClaimStatus, ClaimSubject, Database, Evidence, EvidenceKind, EvidenceLocation,
    EvidenceObservation, EvidenceTool, Proof, ProofObligation, SemanticBase, SemanticClass,
    SemanticEnum, SemanticEnumValue, SemanticField, SemanticModel, SemanticStatus, SemanticVtable,
    SemanticVtableSlot, Usability,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

type FieldKey = (u64, u32, Option<u8>, Option<u8>, Option<String>, bool);
type FieldObservation = (Option<String>, String, bool);
type BaseKey = (String, Option<i64>, bool);
type BaseObservation = (String, bool);

pub fn validate_target(db: &mut Database, path: &Path) -> anyhow::Result<Vec<u8>> {
    let bytes = std::fs::read(path)?;
    let actual = crate::hex::upper(&Sha256::digest(&bytes));
    let expected = db.binary.sha256.as_deref().ok_or_else(|| {
        anyhow::anyhow!("IR has no binary SHA-256; re-extract before semantic refinement")
    })?;
    anyhow::ensure!(
        actual.eq_ignore_ascii_case(expected),
        "semantic target hash mismatch: IR {expected}, input {actual}"
    );
    let pe = goblin::pe::PE::parse(&bytes)?;
    let machine = format!("0x{:04x}", pe.header.coff_header.machine);
    anyhow::ensure!(
        db.binary.machine.as_deref() == Some(machine.as_str()),
        "semantic target machine mismatch: IR {:?}, input {machine}",
        db.binary.machine
    );
    db.binary.image_size = pe
        .header
        .optional_header
        .as_ref()
        .map(|header| u64::from(header.windows_fields.size_of_image));
    Ok(bytes)
}

#[derive(Default)]
struct ClassBuilder {
    sizes: Vec<(u64, String, bool)>,
    fields: BTreeMap<FieldKey, Vec<FieldObservation>>,
    bases: BTreeMap<BaseKey, Vec<BaseObservation>>,
    vtables: Vec<SemanticVtable>,
}

pub fn project(db: &mut Database) {
    let mut classes = BTreeMap::<String, ClassBuilder>::new();
    let type_names = type_index_names(&db.types);
    let type_kinds: BTreeMap<String, String> = db
        .types
        .iter()
        .filter_map(|value| {
            Some((
                value.get("name")?.as_str()?.to_string(),
                value.get("kind")?.as_str()?.to_string(),
            ))
        })
        .collect();

    collect_claims(db, &type_names, &mut classes);
    collect_vtables(db, &mut classes);
    let mut diagnostics = Vec::new();
    let projected = classes
        .into_iter()
        .map(|(name, builder)| build_class(name, builder, &type_kinds, &mut diagnostics))
        .collect();
    db.semantic = SemanticModel {
        classes: projected,
        enums: project_enums(db),
        aliases: vec![],
        diagnostics,
    };
}

fn collect_claims(
    db: &Database,
    type_names: &BTreeMap<u64, String>,
    classes: &mut BTreeMap<String, ClassBuilder>,
) {
    for claim in &db.claims {
        let proven = db.claim_is_proven(claim);
        match &claim.subject {
            // CodeView also reports zero-sized enum, forward, and compiler-internal
            // records through the same low-level path. Zero is never a valid
            // complete C++ object size, so it must not create a class layout.
            ClaimSubject::ObjectSize { owner, size } if *size > 0 => classes
                .entry(owner.clone())
                .or_default()
                .sizes
                .push((*size, claim.id.clone(), proven)),
            ClaimSubject::Member {
                owner,
                offset,
                width,
                bit_offset,
                bit_size,
                type_name,
                name,
                structural_only,
                ..
            } => classes
                .entry(owner.clone())
                .or_default()
                .fields
                .entry((
                    *offset,
                    *width,
                    *bit_offset,
                    *bit_size,
                    name.clone(),
                    *structural_only,
                ))
                .or_default()
                .push((type_name.clone(), claim.id.clone(), proven)),
            ClaimSubject::Base {
                derived,
                base,
                offset,
                is_virtual,
            } => {
                let resolved = resolve_type_index_name(base, type_names);
                classes
                    .entry(derived.clone())
                    .or_default()
                    .bases
                    .entry((resolved, *offset, *is_virtual))
                    .or_default()
                    .push((claim.id.clone(), proven));
            }
            _ => {}
        }
    }
}

fn collect_vtables(db: &Database, classes: &mut BTreeMap<String, ClassBuilder>) {
    for table in &db.vtables {
        let Some(owner) = vtable_owner(table) else {
            continue;
        };
        let rva = value_u32(table, "rva").unwrap_or(0);
        let object_offset = table
            .get("object_offset")
            .and_then(Value::as_i64)
            .or_else(|| {
                table
                    .get("rtti")
                    .and_then(|rtti| rtti.get("object_offset"))
                    .and_then(Value::as_i64)
            });
        let mut slots = Vec::new();
        for entry in table
            .get("entries")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let slot = value_u32(entry, "slot").unwrap_or(0);
            let target_rva = value_u32(entry, "target_rva").unwrap_or(0);
            let claim_ids: Vec<String> = db
                .claims
                .iter()
                .filter(|claim| {
                    matches!(
                        claim.subject,
                        ClaimSubject::VtableSlot {
                            owner: ref claim_owner,
                            table_rva,
                            table_object_offset: claim_offset,
                            slot: claim_slot,
                            target_rva: claim_target,
                            ..
                        } if claim_owner == &owner && table_rva == rva && claim_offset == object_offset && claim_slot == slot && claim_target == target_rva
                    )
                })
                .map(|claim| claim.id.clone())
                .collect();
            let verified = db.vtable_slot_is_verified(&owner, rva, object_offset, slot, target_rva);
            slots.push(SemanticVtableSlot {
                slot,
                target_rva,
                symbol_id: entry
                    .get("target_id")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                method_name: entry
                    .get("method_name")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                this_adjustment: entry
                    .get("this_adjustment")
                    .and_then(Value::as_i64)
                    .and_then(|value| i32::try_from(value).ok()),
                status: if verified {
                    SemanticStatus::Verified
                } else {
                    SemanticStatus::Candidate
                },
                claim_ids,
            });
        }
        let status = if !slots.is_empty()
            && slots
                .iter()
                .all(|slot| slot.status == SemanticStatus::Verified)
        {
            SemanticStatus::Verified
        } else {
            SemanticStatus::Candidate
        };
        classes
            .entry(owner)
            .or_default()
            .vtables
            .push(SemanticVtable {
                rva,
                object_offset,
                status,
                slots,
            });
    }
}

fn build_class(
    qualified_name: String,
    builder: ClassBuilder,
    type_kinds: &BTreeMap<String, String>,
    diagnostics: &mut Vec<String>,
) -> SemanticClass {
    let proven_sizes: BTreeSet<u64> = builder
        .sizes
        .iter()
        .filter_map(|(size, _, proven)| proven.then_some(*size))
        .collect();
    let candidate_sizes: BTreeSet<u64> = builder.sizes.iter().map(|(size, _, _)| *size).collect();
    let (size, size_status) = if proven_sizes.len() == 1 {
        (proven_sizes.first().copied(), SemanticStatus::Verified)
    } else if proven_sizes.len() > 1 {
        diagnostics.push(format!(
            "{qualified_name}: conflicting verified object sizes {proven_sizes:?}"
        ));
        (None, SemanticStatus::Withheld)
    } else if candidate_sizes.len() == 1 {
        (candidate_sizes.first().copied(), SemanticStatus::Candidate)
    } else {
        if candidate_sizes.len() > 1 {
            diagnostics.push(format!(
                "{qualified_name}: conflicting candidate object sizes {candidate_sizes:?}"
            ));
        }
        (None, SemanticStatus::Withheld)
    };

    let mut fields = Vec::new();
    for ((offset, width, bit_offset, bit_size, name, structural_only), observations) in
        builder.fields
    {
        let type_names: BTreeSet<String> = observations
            .iter()
            .filter_map(|(type_name, _, _)| type_name.clone())
            .collect();
        let any_proven = observations.iter().any(|(_, _, proven)| *proven);
        let status = if any_proven && width > 0 && type_names.len() <= 1 {
            SemanticStatus::Verified
        } else if type_names.len() > 1 {
            diagnostics.push(format!(
                "{qualified_name}+0x{offset:X}: conflicting field types {type_names:?}"
            ));
            SemanticStatus::Withheld
        } else {
            SemanticStatus::Candidate
        };
        fields.push(SemanticField {
            name,
            offset,
            width,
            type_name: type_names.first().cloned(),
            bit_offset,
            bit_size,
            structural_only,
            status,
            claim_ids: observations.into_iter().map(|(_, id, _)| id).collect(),
        });
    }

    let bases = build_bases(builder.bases);
    let status = if size_status == SemanticStatus::Verified
        && fields
            .iter()
            .all(|field| field.status != SemanticStatus::Withheld)
        && bases
            .iter()
            .all(|base| base.status == SemanticStatus::Verified)
    {
        SemanticStatus::Verified
    } else {
        SemanticStatus::Candidate
    };
    let claim_ids = builder
        .sizes
        .into_iter()
        .map(|(_, id, _)| id)
        .chain(fields.iter().flat_map(|field| field.claim_ids.clone()))
        .chain(bases.iter().flat_map(|base| base.claim_ids.clone()))
        .collect();
    SemanticClass {
        kind: type_kinds
            .get(&qualified_name)
            .cloned()
            .unwrap_or_else(|| "class".into()),
        qualified_name,
        size,
        alignment: None,
        status,
        fields,
        bases,
        vtables: builder.vtables,
        claim_ids,
    }
}

fn build_bases(bases: BTreeMap<BaseKey, Vec<BaseObservation>>) -> Vec<SemanticBase> {
    bases
        .into_iter()
        .map(|((base, offset, is_virtual), claims)| {
            let relationship_verified = claims.iter().any(|(_, proven)| *proven);
            let offset_verified = offset.is_some() && relationship_verified;
            SemanticBase {
                qualified_name: base,
                offset,
                is_virtual,
                status: if offset_verified {
                    SemanticStatus::Verified
                } else {
                    SemanticStatus::Candidate
                },
                relationship_verified,
                offset_verified,
                claim_ids: claims.into_iter().map(|(id, _)| id).collect(),
            }
        })
        .collect()
}

#[derive(Debug, serde::Deserialize)]
struct ManualLayoutCorpus {
    binary: ManualBinaryIdentity,
    layouts: Vec<ManualLayout>,
}

#[derive(Debug, serde::Deserialize)]
struct ManualBinaryIdentity {
    timestamp: u64,
    machine: String,
    sha256: String,
}

#[derive(Debug, serde::Deserialize)]
struct ManualLayout {
    name: String,
    size: Option<u64>,
    size_confidence: Option<String>,
    size_evidence_rva: Option<u32>,
    #[serde(default)]
    fields: Vec<ManualField>,
}

#[derive(Debug, serde::Deserialize)]
struct ManualField {
    offset: u64,
    width: u32,
    name: Option<String>,
    confidence: String,
    evidence_rva: Option<u32>,
    evidence_rvas: Option<Vec<u32>>,
}

/// Import an exact-build manually established layout corpus as evidence. The
/// corpus is independently identity-checked; no reference header is involved.
pub fn import_manual_layout(db: &mut Database, path: &Path) -> anyhow::Result<usize> {
    let corpus: ManualLayoutCorpus = serde_json::from_slice(&std::fs::read(path)?)?;
    validate_manual_identity(db, &corpus.binary)?;
    let rule_id = format!("manual-layout:{}", corpus.binary.timestamp);
    Ok(corpus
        .layouts
        .into_iter()
        .map(|layout| import_one_layout(db, &rule_id, layout))
        .sum())
}

fn validate_manual_identity(db: &Database, identity: &ManualBinaryIdentity) -> anyhow::Result<()> {
    let timestamp = db
        .binary
        .timestamp
        .as_deref()
        .and_then(|value| value.parse::<u64>().ok());
    anyhow::ensure!(
        timestamp == Some(identity.timestamp),
        "manual corpus timestamp mismatch"
    );
    let normalized_machine = |machine: &str| match machine.to_ascii_lowercase().as_str() {
        "x86-64" | "x64" | "0x8664" => "x64".to_string(),
        "x86" | "i386" | "0x014c" => "x86".to_string(),
        other => other.to_string(),
    };
    anyhow::ensure!(
        db.binary.machine.as_deref().is_some_and(
            |machine| normalized_machine(machine) == normalized_machine(&identity.machine)
        ),
        "manual corpus machine mismatch"
    );
    anyhow::ensure!(
        db.binary
            .sha256
            .as_deref()
            .is_some_and(|hash| hash.eq_ignore_ascii_case(&identity.sha256)),
        "manual corpus binary SHA-256 mismatch"
    );
    Ok(())
}

fn import_one_layout(db: &mut Database, rule_id: &str, layout: ManualLayout) -> usize {
    let mut imported = 0;
    let proof_id = format!("proof:{rule_id}:{}", layout.name);
    db.proofs.push(Proof {
        id: proof_id.clone(),
        rule_id: rule_id.to_string(),
        rule_version: 1,
        passed: true,
        obligations: vec![ProofObligation {
            name: "exact-build-identity".into(),
            satisfied: true,
            detail: "manual observation corpus matches PE identity".into(),
        }],
    });
    import_layout_size(db, rule_id, &proof_id, &layout);
    for (index, field) in layout.fields.into_iter().enumerate() {
        import_manual_field(db, rule_id, &proof_id, &layout.name, index, field);
        imported += 1;
    }
    imported
}

fn import_layout_size(db: &mut Database, rule_id: &str, proof_id: &str, layout: &ManualLayout) {
    let Some(size) = layout
        .size
        .filter(|_| layout.size_confidence.as_deref() == Some("certain"))
    else {
        return;
    };
    let evidence_id = format!("ev:{rule_id}:{}:size", layout.name);
    db.evidence.push(Evidence {
        id: evidence_id.clone(),
        kind: EvidenceKind::Manual,
        tool: EvidenceTool::Human,
        rule_id: rule_id.to_string(),
        rule_version: 1,
        location: EvidenceLocation {
            rva: layout.size_evidence_rva,
            ..Default::default()
        },
        observation: EvidenceObservation::Text {
            text: format!("{} exact object size 0x{size:X}", layout.name),
        },
    });
    db.claims.push(Claim {
        id: format!("claim:{rule_id}:{}:size", layout.name),
        subject: ClaimSubject::ObjectSize {
            owner: layout.name.clone(),
            size,
        },
        status: ClaimStatus::Observed,
        usability: Usability::Verified,
        evidence_ids: vec![evidence_id],
        proof_id: Some(proof_id.to_string()),
    });
}

fn import_manual_field(
    db: &mut Database,
    rule_id: &str,
    proof_id: &str,
    owner: &str,
    index: usize,
    field: ManualField,
) {
    let certain = field.confidence == "certain";
    let evidence_rvas = field
        .evidence_rvas
        .clone()
        .or_else(|| field.evidence_rva.map(|rva| vec![rva]))
        .unwrap_or_default();
    let evidence_id = format!("ev:{rule_id}:{owner}:field:{index}");
    db.evidence.push(Evidence {
        id: evidence_id.clone(),
        kind: EvidenceKind::Manual,
        tool: EvidenceTool::Human,
        rule_id: rule_id.to_string(),
        rule_version: 1,
        location: EvidenceLocation {
            rva: evidence_rvas.first().copied(),
            instruction_rvas: evidence_rvas,
            ..Default::default()
        },
        observation: EvidenceObservation::MemberAccess {
            owner: owner.to_string(),
            offset: field.offset,
            width: field.width,
            access: "manual-layout".into(),
            suggested_name: field.name.clone(),
        },
    });
    db.claims.push(Claim {
        id: format!("claim:{rule_id}:{owner}:field:{index}"),
        subject: ClaimSubject::Member {
            owner: owner.to_string(),
            offset: field.offset,
            width: field.width,
            bit_offset: None,
            bit_size: None,
            type_name: None,
            name: field.name,
            structural_only: false,
            access: "manual-layout".into(),
        },
        status: ClaimStatus::Observed,
        usability: if certain {
            Usability::Verified
        } else {
            Usability::MetadataOnly
        },
        evidence_ids: vec![evidence_id],
        proof_id: Some(proof_id.to_string()),
    });
}

fn project_enums(db: &Database) -> Vec<SemanticEnum> {
    let mut values = BTreeMap::<String, Vec<(String, i64, String, bool)>>::new();
    let underlying_types: BTreeMap<String, String> = db
        .types
        .iter()
        .filter(|value| value.get("kind").and_then(Value::as_str) == Some("enum"))
        .filter_map(|value| {
            Some((
                value.get("name")?.as_str()?.to_string(),
                primitive_semantic_name(
                    u32::try_from(value.get("underlying_type")?.as_u64()?).ok()?,
                )?
                .into(),
            ))
        })
        .collect();
    for claim in &db.claims {
        if let ClaimSubject::EnumValue { owner, name, value } = &claim.subject {
            values.entry(owner.clone()).or_default().push((
                name.clone(),
                *value,
                claim.id.clone(),
                db.claim_is_proven(claim),
            ));
        }
    }
    for name in underlying_types
        .keys()
        .cloned()
        .chain(signature_enum_names(db))
    {
        values.entry(name).or_default();
    }
    values
        .into_iter()
        .map(|(qualified_name, entries)| {
            let underlying_type = underlying_types.get(&qualified_name).cloned();
            let verified = underlying_type.is_some()
                && !entries.is_empty()
                && entries.iter().all(|(_, _, _, proven)| *proven);
            SemanticEnum {
                qualified_name,
                underlying_type,
                status: if verified {
                    SemanticStatus::Verified
                } else {
                    SemanticStatus::Candidate
                },
                values: entries
                    .into_iter()
                    .map(|(name, value, id, proven)| SemanticEnumValue {
                        name,
                        value,
                        status: if proven {
                            SemanticStatus::Verified
                        } else {
                            SemanticStatus::Candidate
                        },
                        claim_ids: vec![id],
                    })
                    .collect(),
            }
        })
        .collect()
}

fn signature_enum_names(db: &Database) -> impl Iterator<Item = String> + '_ {
    db.symbols.iter().flat_map(|symbol| {
        symbol
            .sig
            .ret
            .iter()
            .chain(&symbol.sig.params)
            .filter_map(|ty| enum_name_from_text(&ty.text))
    })
}

fn enum_name_from_text(text: &str) -> Option<String> {
    let text = text.trim();
    let text = text.strip_prefix("const ").unwrap_or(text);
    let rest = text.strip_prefix("enum ")?;
    let end = rest.find(['*', '&']).unwrap_or(rest.len());
    let name = rest[..end].trim().trim_end_matches(" const").trim();
    (!name.is_empty()).then(|| name.to_string())
}

const fn primitive_semantic_name(index: u32) -> Option<&'static str> {
    if index >= 0x1000 || index & 0xF00 != 0 {
        return None;
    }
    Some(match index & 0xFF {
        0x10 | 0x68 => "i8",
        0x20 | 0x69 => "u8",
        0x11 | 0x72 => "i16",
        0x21 | 0x73 | 0x71 => "u16",
        0x12 | 0x74 => "i32",
        0x22 | 0x75 | 0x7B => "u32",
        0x13 | 0x76 => "i64",
        0x23 | 0x77 => "u64",
        _ => return None,
    })
}

fn type_index_names(types: &[Value]) -> BTreeMap<u64, String> {
    types
        .iter()
        .filter_map(|value| {
            Some((
                value.get("index")?.as_u64()?,
                value.get("name")?.as_str()?.to_string(),
            ))
        })
        .collect()
}

fn resolve_type_index_name(value: &str, names: &BTreeMap<u64, String>) -> String {
    value
        .strip_prefix("type-index:0x")
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        .and_then(|index| names.get(&index).cloned())
        .unwrap_or_else(|| value.to_string())
}

fn vtable_owner(table: &Value) -> Option<String> {
    if let Some(name) = table.get("class_name").and_then(Value::as_str) {
        return Some(name.to_string());
    }
    table
        .get("demangled")
        .and_then(Value::as_str)
        .and_then(crate::rtti::vftable_owner_name)
        .map(str::to_string)
}

fn value_u32(value: &Value, key: &str) -> Option<u32> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|number| u32::try_from(number).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Claim, ClaimStatus, Evidence, EvidenceKind, EvidenceLocation, EvidenceObservation,
        EvidenceTool, Proof, ProofObligation, Usability,
    };

    #[test]
    fn extracts_enum_type_from_signature_text() {
        assert_eq!(
            enum_name_from_text("enum Example::Mode const &").as_deref(),
            Some("Example::Mode")
        );
        assert_eq!(enum_name_from_text("unsigned int"), None);
    }

    #[test]
    fn enum_type_without_values_remains_candidate() {
        let mut db = Database {
            types: vec![serde_json::json!({
                "kind": "enum",
                "name": "Example::Mode",
                "underlying_type": 0x12,
            })],
            ..Database::default()
        };

        project(&mut db);
        assert_eq!(db.semantic.enums.len(), 1);
        assert_eq!(db.semantic.enums[0].status, SemanticStatus::Candidate);
        assert!(db.semantic.enums[0].values.is_empty());
    }

    #[test]
    fn proven_size_projects_as_verified() {
        let mut db = Database::default();
        db.evidence.push(Evidence {
            id: "ev:size".into(),
            kind: EvidenceKind::PdbRecord,
            tool: EvidenceTool::Pdb,
            rule_id: "test".into(),
            rule_version: 1,
            location: EvidenceLocation::default(),
            observation: EvidenceObservation::Text {
                text: "size".into(),
            },
        });
        db.proofs.push(Proof {
            id: "proof:size".into(),
            rule_id: "test".into(),
            rule_version: 1,
            passed: true,
            obligations: vec![ProofObligation {
                name: "ok".into(),
                satisfied: true,
                detail: "ok".into(),
            }],
        });
        db.claims.push(Claim {
            id: "claim:size".into(),
            subject: ClaimSubject::ObjectSize {
                owner: "Example".into(),
                size: 16,
            },
            status: ClaimStatus::Observed,
            usability: Usability::Verified,
            evidence_ids: vec!["ev:size".into()],
            proof_id: Some("proof:size".into()),
        });
        project(&mut db);
        assert_eq!(db.semantic.classes[0].size, Some(16));
        assert_eq!(db.semantic.classes[0].status, SemanticStatus::Verified);
    }

    #[test]
    fn zero_size_does_not_create_a_verified_layout() {
        let mut db = Database::default();
        db.evidence.push(Evidence {
            id: "ev:zero".into(),
            kind: EvidenceKind::PdbRecord,
            tool: EvidenceTool::Pdb,
            rule_id: "test".into(),
            rule_version: 1,
            location: EvidenceLocation::default(),
            observation: EvidenceObservation::Text {
                text: "zero-sized CodeView record".into(),
            },
        });
        db.proofs.push(Proof {
            id: "proof:zero".into(),
            rule_id: "test".into(),
            rule_version: 1,
            passed: true,
            obligations: vec![ProofObligation {
                name: "ok".into(),
                satisfied: true,
                detail: "ok".into(),
            }],
        });
        db.claims.push(Claim {
            id: "claim:zero".into(),
            subject: ClaimSubject::ObjectSize {
                owner: "not_an_object".into(),
                size: 0,
            },
            status: ClaimStatus::Observed,
            usability: Usability::Verified,
            evidence_ids: vec!["ev:zero".into()],
            proof_id: Some("proof:zero".into()),
        });

        project(&mut db);
        assert!(db.semantic.classes.is_empty());
    }

    #[test]
    fn corroborated_field_overrides_matching_raw_observations() {
        let subject = ClaimSubject::Member {
            owner: "Example".into(),
            offset: 8,
            width: 4,
            bit_offset: None,
            bit_size: None,
            type_name: None,
            name: Some("Value".into()),
            structural_only: false,
            access: "read-write".into(),
        };
        let mut db = Database {
            evidence: vec![Evidence {
                id: "ev:field".into(),
                kind: EvidenceKind::Dataflow,
                tool: EvidenceTool::Windissect,
                rule_id: "test".into(),
                rule_version: 1,
                location: EvidenceLocation::default(),
                observation: EvidenceObservation::Text {
                    text: "corroborated field".into(),
                },
            }],
            proofs: vec![Proof {
                id: "proof:field".into(),
                rule_id: "test".into(),
                rule_version: 1,
                passed: true,
                obligations: vec![ProofObligation {
                    name: "ok".into(),
                    satisfied: true,
                    detail: "ok".into(),
                }],
            }],
            claims: vec![
                Claim {
                    id: "claim:raw-field".into(),
                    subject: subject.clone(),
                    status: ClaimStatus::Observed,
                    usability: Usability::MetadataOnly,
                    evidence_ids: Vec::new(),
                    proof_id: None,
                },
                Claim {
                    id: "claim:proven-field".into(),
                    subject,
                    status: ClaimStatus::Corroborated,
                    usability: Usability::Verified,
                    evidence_ids: vec!["ev:field".into()],
                    proof_id: Some("proof:field".into()),
                },
            ],
            ..Database::default()
        };

        project(&mut db);
        assert_eq!(
            db.semantic.classes[0].fields[0].status,
            SemanticStatus::Verified
        );
    }
}
