//! PE-native MSVC vftable recovery for stripped public PDBs.
//!
//! `??_7` symbols identify vftable starts. Entries are consecutive image
//! pointers into executable sections. This pass is deliberately conservative:
//! it stops at the first non-code pointer and never invents missing slots.

use crate::model::{
    Capability, CapabilityStatus, Claim, ClaimStatus, ClaimSubject, Conflict, Database, Evidence,
    EvidenceKind, EvidenceLocation, EvidenceObservation, EvidenceTool, Kind, Proof,
    ProofObligation, Usability,
};
use anyhow::{Context, Result};
use goblin::pe::{PE, section_table};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub fn recover(db: &mut Database, pe_bytes: &[u8]) -> Result<usize> {
    let pe = PE::parse(pe_bytes).context("parse PE for vftable recovery")?;
    let image_base = db.binary.image_base.unwrap_or(pe.image_base);
    let pointer_size = match db.binary.machine.as_deref() {
        Some("0x14c") => 4usize,
        _ => 8usize,
    };
    let code_ranges = executable_ranges(&pe);
    let mut exact = BTreeMap::<u64, Vec<usize>>::new();
    for (index, symbol) in db.symbols.iter().enumerate() {
        if symbol.is_code && symbol.vaddr != 0 {
            exact.entry(symbol.vaddr).or_default().push(index);
        }
    }

    let candidates: Vec<usize> = db
        .symbols
        .iter()
        .enumerate()
        .filter(|(_, s)| s.mangled.starts_with("??_7") && s.rva != 0)
        .map(|(i, _)| i)
        .collect();
    let by_rva: BTreeMap<u32, Vec<usize>> =
        candidates.iter().fold(BTreeMap::new(), |mut map, i| {
            map.entry(db.symbols[*i].rva).or_default().push(*i);
            map
        });
    let starts: BTreeSet<u32> = by_rva.keys().copied().collect();
    let context = RttiContext {
        db,
        pe: &pe,
        pe_bytes,
        image_base,
        pointer_size,
        code_ranges: &code_ranges,
        exact: &exact,
        starts: &starts,
    };
    let (recovered, rtti_types, rtti_locator_count) = recover_tables(&context, by_rva);
    Ok(finish_recovery(
        db,
        recovered,
        rtti_types,
        rtti_locator_count,
    ))
}

struct RttiContext<'a> {
    db: &'a Database,
    pe: &'a PE<'a>,
    pe_bytes: &'a [u8],
    image_base: u64,
    pointer_size: usize,
    code_ranges: &'a [(u32, u32)],
    exact: &'a BTreeMap<u64, Vec<usize>>,
    starts: &'a BTreeSet<u32>,
}

fn recover_tables(
    context: &RttiContext<'_>,
    by_rva: BTreeMap<u32, Vec<usize>>,
) -> (Vec<Value>, BTreeMap<String, Value>, usize) {
    let mut recovered = Vec::new();
    let mut rtti_types = BTreeMap::new();
    let mut locator_count = 0;
    for (table_rva, aliases) in by_rva {
        if let Some(table) = recover_table(
            context,
            table_rva,
            &aliases,
            &mut rtti_types,
            &mut locator_count,
        ) {
            recovered.push(table);
        }
    }
    (recovered, rtti_types, locator_count)
}

fn recover_table(
    context: &RttiContext<'_>,
    table_rva: u32,
    aliases: &[usize],
    rtti_types: &mut BTreeMap<String, Value>,
    locator_count: &mut usize,
) -> Option<Value> {
    let symbol_index = aliases[0];
    let symbol = &context.db.symbols[symbol_index];
    let demangled = symbol.demangled.as_deref();
    let table_class = demangled.and_then(vftable_class_name);
    let mut allowed_classes = table_class
        .map(|class| class_hierarchy(context.db, class))
        .unwrap_or_default();
    for alias in aliases
        .iter()
        .filter_map(|index| context.db.symbols.get(*index))
        .filter_map(|candidate| candidate.demangled.as_deref())
    {
        if let Some(derived) = vftable_derived_name(alias) {
            allowed_classes.insert(class_short_name(derived));
        }
        if let Some(owner) = vftable_owner_name(alias) {
            allowed_classes.insert(class_short_name(owner));
        }
    }
    let start = rva_to_offset(context.pe, table_rva)?;
    let next_table_rva = context
        .starts
        .range((table_rva.saturating_add(1))..)
        .next()
        .copied();
    let entries = recover_entries(
        context,
        table_rva,
        start,
        next_table_rva,
        table_class,
        &allowed_classes,
    );
    if entries.is_empty() {
        return None;
    }
    let rtti = recover_class_hierarchy(
        context.pe,
        context.pe_bytes,
        table_rva,
        context.image_base,
        context.pointer_size,
    );
    if let Some(info) = &rtti
        && let Some(name) = info.get("type_descriptor").and_then(Value::as_str)
    {
        *locator_count += 1;
        rtti_types.entry(name.to_string()).or_insert_with(|| {
            json!({
                "name": name,
                "kind": "class",
                "size": Value::Null,
                "fields": [],
                "bases": info.get("bases").cloned().unwrap_or_else(|| json!([])),
                "source": "pe-msvc-rtti",
                "confidence": "certain",
            })
        });
    }
    Some(json!({
        "mangled": symbol.mangled,
        "demangled": symbol.demangled,
        "aliases": aliases.iter().map(|index| json!({
            "mangled": context.db.symbols[*index].mangled,
            "demangled": context.db.symbols[*index].demangled,
        })).collect::<Vec<_>>(),
        "rva": table_rva,
        "pointer_size": context.pointer_size,
        "entries": entries,
        "rtti": rtti,
        "evidence": "msvc-??_7-plus-pe-rdata",
        "extent": "contiguous-executable-pointer-prefix",
        "confidence": "likely",
    }))
}

fn recover_entries(
    context: &RttiContext<'_>,
    table_rva: u32,
    start: usize,
    next_table_rva: Option<u32>,
    table_class: Option<&str>,
    allowed_classes: &BTreeSet<&str>,
) -> Vec<Value> {
    let mut entries = Vec::new();
    for slot in 0..512u32 {
        let pointer_width = u32::try_from(context.pointer_size).unwrap_or(0);
        let entry_rva = table_rva.saturating_add(slot.saturating_mul(pointer_width));
        if next_table_rva.is_some_and(|next| entry_rva >= next) {
            break;
        }
        let slot_index = usize::try_from(slot).unwrap_or(usize::MAX);
        let offset = start.saturating_add(slot_index.saturating_mul(context.pointer_size));
        let Some(entry) = recover_entry(
            context,
            offset,
            slot,
            slot_index,
            table_class,
            allowed_classes,
        ) else {
            break;
        };
        entries.push(entry);
    }
    entries
}

fn recover_entry(
    context: &RttiContext<'_>,
    offset: usize,
    slot: u32,
    slot_index: usize,
    table_class: Option<&str>,
    allowed_classes: &BTreeSet<&str>,
) -> Option<Value> {
    let target = read_pointer(context.pe_bytes, offset, context.pointer_size)?;
    let target_rva = target
        .checked_sub(context.image_base)
        .and_then(|value| u32::try_from(value).ok())?;
    if !context
        .code_ranges
        .iter()
        .any(|(lo, hi)| target_rva >= *lo && target_rva < *hi)
    {
        return None;
    }
    let targets = context.exact.get(&target).cloned().unwrap_or_default();
    // ICF frequently gives one implementation address many unrelated
    // names. A vftable slot must name a virtual member; never select a
    // random non-virtual alias merely because it was first in the PDB.
    let virtual_targets: Vec<_> = targets
        .iter()
        .filter_map(|index| context.db.symbols.get(*index))
        .filter(|s| s.sig.storage.as_deref() == Some("virtual"))
        .filter(|s| {
            s.sig
                .class
                .as_deref()
                .is_some_and(|candidate| allowed_classes.contains(class_short_name(candidate)))
        })
        .collect();
    let same_class: Vec<_> = virtual_targets
        .iter()
        .copied()
        .filter(|s| {
            table_class.is_some_and(|class| {
                s.sig.class.as_deref().is_some_and(|candidate| {
                    candidate == class || candidate.ends_with(&format!("::{class}"))
                })
            })
        })
        .collect();
    let best = if same_class.len() == 1 {
        Some(same_class[0])
    } else if virtual_targets.len() == 1 {
        Some(virtual_targets[0])
    } else {
        None
    };
    let signature_keys: BTreeSet<_> = virtual_targets
        .iter()
        .filter_map(|symbol| abi_signature_key(symbol))
        .collect();
    let signature_compatible = !virtual_targets.is_empty()
        && signature_keys.len() == 1
        && virtual_targets.iter().all(|symbol| symbol.sig.parse_ok);
    let signature_source = virtual_targets
        .first()
        .copied()
        .filter(|_| signature_compatible);
    let this_adjustment = best
        .filter(|s| s.kind == Kind::Thunk)
        .and_then(|symbol| detect_this_adjustment(context.pe, context.pe_bytes, symbol.rva));
    let target_candidates: Vec<_> = virtual_targets
        .iter()
        .map(|s| {
            json!({
                "id": s.id,
                "name": s.demangled,
                "class": s.sig.class,
            })
        })
        .collect();
    Some(json!({
        "slot": slot,
        "byte_offset": slot_index.saturating_mul(context.pointer_size),
        "target_rva": target_rva,
        "target_id": best.map(|s| s.id.as_str()),
        "target_name": best.and_then(|s| s.demangled.as_deref()),
        "target_candidates": target_candidates,
        "target_ambiguous": best.is_none(),
        "signature_compatible": signature_compatible,
        "signature_source_id": signature_source.map(|s| s.id.as_str()),
        "is_thunk": best.is_some_and(|s| s.kind == Kind::Thunk),
        "this_adjustment": this_adjustment,
        "evidence": "pe-vftable-pointer",
    }))
}

fn finish_recovery(
    db: &mut Database,
    recovered: Vec<Value>,
    rtti_types: BTreeMap<String, Value>,
    rtti_locator_count: usize,
) -> usize {
    for symbol in &mut db.symbols {
        if symbol.mangled.starts_with("??_7") {
            symbol.is_code = false;
            symbol.kind = Kind::Data;
            symbol.body_hash.clear();
            symbol.calls.clear();
            symbol.callers.clear();
        }
    }
    let count = recovered.len();
    add_vtable_proof_graph(db, &recovered);
    db.vtables.extend(recovered);
    let existing: BTreeSet<String> = db
        .types
        .iter()
        .filter_map(|ty| ty.get("name")?.as_str().map(str::to_owned))
        .collect();
    db.types.extend(
        rtti_types
            .into_iter()
            .filter(|(name, _)| !existing.contains(name))
            .map(|(_, ty)| ty),
    );
    if let Some(obj) = db.type_recovery.as_object_mut() {
        obj.insert("pe_vftables".into(), json!(count));
        obj.insert(
            "pe_vftable_status".into(),
            json!(if count == 0 {
                "none-found"
            } else {
                "recovered"
            }),
        );
        obj.insert(
            "pe_rtti_complete_object_locators".into(),
            json!(rtti_locator_count),
        );
        obj.insert(
            "pe_rtti_status".into(),
            json!(if rtti_locator_count == 0 {
                "unavailable-or-disabled"
            } else {
                "recovered"
            }),
        );
    }
    count
}

fn add_vtable_proof_graph(db: &mut Database, recovered: &[Value]) {
    let mut conflicting = 0usize;
    for table in recovered {
        conflicting += add_table_proofs(db, table);
    }
    db.capabilities.push(Capability {
        id: "msvc-pe-vftables".into(),
        status: if conflicting == 0 {
            CapabilityStatus::Supported
        } else {
            CapabilityStatus::Partial
        },
        analyzer: "rtti".into(),
        reason: format!(
            "{} vftables; {conflicting} ABI conflicts retained",
            recovered.len()
        ),
    });
}

fn add_table_proofs(db: &mut Database, table: &Value) -> usize {
    let table_rva = table
        .get("rva")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(0);
    let pointer_size = table
        .get("pointer_size")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(8);
    let owner = table
        .get("demangled")
        .and_then(Value::as_str)
        .or_else(|| table.get("mangled").and_then(Value::as_str))
        .map_or_else(|| "unknown-vftable".into(), normalized_vftable_owner);
    let mut conflicting = 0;
    for entry in table
        .get("entries")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        conflicting += usize::from(add_slot_proof(db, entry, table_rva, pointer_size, &owner));
    }
    conflicting
}

fn add_slot_proof(
    db: &mut Database,
    entry: &Value,
    table_rva: u32,
    pointer_size: u32,
    owner: &str,
) -> bool {
    let slot = entry
        .get("slot")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(0);
    let target_rva = entry
        .get("target_rva")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(0);
    let compatible = entry
        .get("signature_compatible")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let ambiguous = entry
        .get("target_ambiguous")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let identity_candidate_count = entry
        .get("target_candidates")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let evidence_id = format!("ev:vtable-slot:{table_rva:X}:{slot}");
    let proof_id = format!("proof:vtable-slot:{table_rva:X}:{slot}");
    let claim_id = format!("claim:vtable-slot:{table_rva:X}:{slot}");
    db.evidence.push(Evidence {
        id: evidence_id.clone(),
        kind: EvidenceKind::Rtti,
        tool: EvidenceTool::Windissect,
        rule_id: "msvc.pe-vftable-slot".into(),
        rule_version: 1,
        location: EvidenceLocation {
            symbol_id: None,
            rva: Some(table_rva.saturating_add(slot.saturating_mul(pointer_size))),
            size: Some(pointer_size),
            instruction_rvas: vec![],
        },
        observation: EvidenceObservation::Text {
            text: format!("vftable slot {slot} points to RVA 0x{target_rva:X}"),
        },
    });
    db.proofs.push(Proof {
        id: proof_id.clone(),
        rule_id: "msvc.pe-vftable-slot".into(),
        rule_version: 1,
        passed: true,
        obligations: vec![
            ProofObligation {
                name: "symbol-backed-table".into(),
                satisfied: true,
                detail: format!("table RVA 0x{table_rva:X}"),
            },
            ProofObligation {
                name: "executable-target".into(),
                satisfied: target_rva != 0,
                detail: format!("target RVA 0x{target_rva:X}"),
            },
        ],
    });
    db.claims.push(Claim {
        id: claim_id,
        subject: ClaimSubject::VtableSlot {
            owner: owner.to_string(),
            table_rva,
            table_object_offset: None,
            slot,
            target_rva,
        },
        status: ClaimStatus::Corroborated,
        usability: Usability::Verified,
        evidence_ids: vec![evidence_id],
        proof_id: Some(proof_id),
    });
    let conflicting = ambiguous && !compatible && identity_candidate_count > 1;
    if conflicting {
        let identity_claim_id = format!("claim:vtable-target-identity:{table_rva:X}:{slot}");
        db.claims.push(Claim {
            id: identity_claim_id.clone(),
            subject: ClaimSubject::Text {
                category: "vtable-target-identity".into(),
                text: format!(
                    "slot {slot} at table RVA 0x{table_rva:X} has multiple ABI-incompatible symbol aliases"
                ),
            },
            status: ClaimStatus::Candidate,
            usability: Usability::MetadataOnly,
            evidence_ids: vec![],
            proof_id: None,
        });
        db.conflicts.push(Conflict {
            id: format!("conflict:vtable-slot:{table_rva:X}:{slot}"),
            claim_ids: vec![identity_claim_id],
            reason: "ICF aliases disagree on ABI signature; callable identity withheld".into(),
            resolved: false,
        });
    }
    conflicting
}

fn normalized_vftable_owner(value: &str) -> String {
    vftable_owner_name(value).unwrap_or(value).to_string()
}

pub fn vftable_owner_name(value: &str) -> Option<&str> {
    if let Some(start) = value.find("{for `") {
        let subject = &value[start + 6..];
        return Some(&subject[..subject.find("'}")?]);
    }
    let value = value.strip_prefix("const ").unwrap_or(value);
    Some(&value[..value.find("::`vftable'")?])
}

pub fn vftable_derived_name(value: &str) -> Option<&str> {
    let value = value.strip_prefix("const ").unwrap_or(value);
    Some(&value[..value.find("::`vftable'")?])
}

fn vftable_class_name(demangled: &str) -> Option<&str> {
    let prefix = demangled.strip_prefix("const ")?;
    let qualified = &prefix[..prefix.find("::`vftable'")?];
    qualified.rsplit("::").next()
}

fn class_short_name(name: &str) -> &str {
    name.rsplit("::").next().unwrap_or(name)
}

fn class_hierarchy<'a>(db: &'a Database, root: &'a str) -> BTreeSet<&'a str> {
    let mut result = BTreeSet::from([root]);
    let mut pending = vec![root];
    while let Some(current) = pending.pop() {
        let record = db.classes.iter().find(|record| {
            record
                .get("name")
                .or_else(|| record.get("qualified_name"))
                .and_then(Value::as_str)
                .is_some_and(|name| class_short_name(name) == current)
        });
        for base in record
            .and_then(|record| record.get("bases"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(name) = base.get("name").and_then(Value::as_str) {
                let short = class_short_name(name);
                if result.insert(short) {
                    pending.push(short);
                }
            }
        }
    }
    result
}

fn abi_signature_key(symbol: &crate::model::Symbol) -> Option<String> {
    symbol.sig.parse_ok.then(|| {
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
}

/// Parse x64 MSVC RTTI Complete Object Locator and Class Hierarchy structures.
/// The vftable[-1] pointer is the COL address; signature 1 uses image-relative
/// references, which makes validation against `pSelf` deterministic.
fn recover_class_hierarchy(
    pe: &PE<'_>,
    bytes: &[u8],
    table_rva: u32,
    image_base: u64,
    pointer_size: usize,
) -> Option<Value> {
    if pointer_size != 8 || table_rva < 8 {
        return None;
    }
    let locator_ptr_offset = rva_to_offset(pe, table_rva - 8)?;
    let locator_address = read_pointer(bytes, locator_ptr_offset, 8)?;
    let locator_rva = u32::try_from(locator_address.checked_sub(image_base)?).ok()?;
    let locator = rva_to_offset(pe, locator_rva)?;
    let signature = read_u32(bytes, locator)?;
    if signature != 1 {
        return None;
    }
    let object_offset = read_u32(bytes, locator + 4)?;
    let constructor_displacement = read_u32(bytes, locator + 8)?;
    let type_rva = read_u32(bytes, locator + 12)?;
    let hierarchy_rva = read_u32(bytes, locator + 16)?;
    let self_rva = read_u32(bytes, locator + 20)?;
    if self_rva != locator_rva {
        return None;
    }
    let type_descriptor = read_type_descriptor(pe, bytes, type_rva, 8)?;

    let hierarchy = rva_to_offset(pe, hierarchy_rva)?;
    let attributes = read_u32(bytes, hierarchy + 4)?;
    let base_count = read_u32(bytes, hierarchy + 8)?.min(1024);
    let base_array_rva = read_u32(bytes, hierarchy + 12)?;
    let base_array = rva_to_offset(pe, base_array_rva)?;
    let mut bases = Vec::new();
    for index in 0..base_count {
        let descriptor_index = usize::try_from(index).ok()?;
        let descriptor_rva = read_u32(bytes, base_array + descriptor_index.saturating_mul(4))?;
        let descriptor = rva_to_offset(pe, descriptor_rva)?;
        let base_type_rva = read_u32(bytes, descriptor)?;
        let name = read_type_descriptor(pe, bytes, base_type_rva, 8)?;
        let contained_bases = read_u32(bytes, descriptor + 4)?;
        let member_displacement = read_i32(bytes, descriptor + 8)?;
        let vbtable_displacement = read_i32(bytes, descriptor + 12)?;
        let displacement_inside_vbtable = read_i32(bytes, descriptor + 16)?;
        let base_attributes = read_u32(bytes, descriptor + 20)?;
        bases.push(json!({
            "name": name,
            "descriptor_rva": descriptor_rva,
            "contained_bases": contained_bases,
            "member_displacement": member_displacement,
            "vbtable_displacement": vbtable_displacement,
            "displacement_inside_vbtable": displacement_inside_vbtable,
            "attributes": base_attributes,
            "is_virtual": vbtable_displacement >= 0,
            "evidence": "msvc-rtti-base-class-descriptor",
        }));
    }
    Some(json!({
        "complete_object_locator_rva": locator_rva,
        "type_descriptor": type_descriptor,
        "class_hierarchy_descriptor_rva": hierarchy_rva,
        "object_offset": object_offset,
        "constructor_displacement": constructor_displacement,
        "attributes": attributes,
        "bases": bases,
        "evidence": "msvc-rtti-col-signature-1",
        "confidence": "certain",
    }))
}

fn read_type_descriptor(
    pe: &PE<'_>,
    bytes: &[u8],
    rva: u32,
    pointer_size: usize,
) -> Option<String> {
    let offset = rva_to_offset(pe, rva)?.checked_add(pointer_size * 2)?;
    read_c_string(bytes, offset, 4096)
}

fn read_c_string(bytes: &[u8], offset: usize, max: usize) -> Option<String> {
    let tail = bytes.get(offset..offset.saturating_add(max).min(bytes.len()))?;
    let end = tail.iter().position(|b| *b == 0)?;
    if end == 0
        || !tail[..end]
            .iter()
            .all(|b| b.is_ascii_graphic() || *b == b' ')
    {
        return None;
    }
    Some(String::from_utf8_lossy(&tail[..end]).into_owned())
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_i32(bytes: &[u8], offset: usize) -> Option<i32> {
    Some(i32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn executable_ranges(pe: &PE<'_>) -> Vec<(u32, u32)> {
    pe.sections
        .iter()
        .filter(|s| s.characteristics & section_table::IMAGE_SCN_MEM_EXECUTE != 0)
        .filter_map(|s| {
            let size = s.virtual_size.max(s.size_of_raw_data);
            s.virtual_address
                .checked_add(size)
                .map(|end| (s.virtual_address, end))
        })
        .collect()
}

fn rva_to_offset(pe: &PE<'_>, rva: u32) -> Option<usize> {
    pe.sections.iter().find_map(|section| {
        let delta = rva.checked_sub(section.virtual_address)?;
        if delta >= section.size_of_raw_data {
            return None;
        }
        section
            .pointer_to_raw_data
            .checked_add(delta)
            .and_then(|value| usize::try_from(value).ok())
    })
}

fn read_pointer(bytes: &[u8], offset: usize, size: usize) -> Option<u64> {
    match size {
        4 => Some(u64::from(u32::from_le_bytes(
            bytes.get(offset..offset + 4)?.try_into().ok()?,
        ))),
        8 => Some(u64::from_le_bytes(
            bytes.get(offset..offset + 8)?.try_into().ok()?,
        )),
        _ => None,
    }
}

/// Recognize the small MSVC adjustor-thunk prefixes that modify ECX/RCX before
/// a tail jump. The returned value is the signed adjustment applied to `this`.
fn detect_this_adjustment(pe: &PE<'_>, bytes: &[u8], rva: u32) -> Option<i32> {
    let offset = rva_to_offset(pe, rva)?;
    let b = bytes.get(offset..offset.saturating_add(12).min(bytes.len()))?;
    match b {
        // x64: sub/add rcx, imm8; jmp ...
        [0x48, 0x83, 0xE9, imm, 0xE9, ..] | [0x83, 0xE9, imm, 0xE9, ..] => {
            Some(-i32::from(imm.cast_signed()))
        }
        [0x48, 0x83, 0xC1, imm, 0xE9, ..] | [0x83, 0xC1, imm, 0xE9, ..] => {
            Some(i32::from(imm.cast_signed()))
        }
        // x64: lea rcx,[rcx+disp8]; jmp ...
        [0x48, 0x8D, 0x49, disp, 0xE9, ..] => Some(i32::from(disp.cast_signed())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reads_both_pointer_widths() {
        let bytes = 0x1122_3344_5566_7788_u64.to_le_bytes();
        assert_eq!(read_pointer(&bytes, 0, 8), Some(0x1122_3344_5566_7788));
        assert_eq!(read_pointer(&bytes, 0, 4), Some(0x5566_7788));
    }

    #[test]
    fn extracts_vftable_class() {
        assert_eq!(
            vftable_class_name("const DirectUI::HWNDHost::`vftable'"),
            Some("HWNDHost")
        );
        assert_eq!(
            vftable_class_name(
                "const DirectUI::ScrollBar::`vftable'{for `DirectUI::BaseScrollBar'}"
            ),
            Some("ScrollBar")
        );
        assert_eq!(vftable_class_name("not a vftable"), None);
        assert_eq!(
            vftable_owner_name(
                "const DirectUI::ScrollBar::`vftable'{for `DirectUI::BaseScrollBar'}"
            ),
            Some("DirectUI::BaseScrollBar")
        );
        assert_eq!(
            vftable_owner_name("const DirectUI::HWNDHost::`vftable'"),
            Some("DirectUI::HWNDHost")
        );
        assert_eq!(
            vftable_derived_name(
                "const DirectUI::ScrollBar::`vftable'{for `DirectUI::BaseScrollBar'}"
            ),
            Some("DirectUI::ScrollBar")
        );
    }

    #[test]
    fn anonymous_executable_slot_keeps_structure_without_identity_conflict() {
        let mut db = Database::default();
        let entry = json!({
            "slot": 3,
            "target_rva": 0x2200,
            "target_candidates": [],
            "target_ambiguous": true,
            "signature_compatible": false,
        });

        assert!(!add_slot_proof(
            &mut db,
            &entry,
            0x1100,
            8,
            "Example::Widget"
        ));
        assert!(db.conflicts.is_empty());
        assert!(db.claim_is_proven(&db.claims[0]));
    }

    #[test]
    fn adjustment_prefixes_are_signed() {
        // Exercise the byte patterns independently of PE mapping.
        let sub: [u8; 5] = [0x48, 0x83, 0xE9, 0x20, 0xE9];
        let add: [u8; 4] = [0x83, 0xC1, 0xF0, 0xE9];
        assert_eq!(
            match sub {
                [0x48, 0x83, 0xE9, n, 0xE9] => Some(-i32::from(n.cast_signed())),
                _ => None,
            },
            Some(-32)
        );
        assert_eq!(
            match add {
                [0x83, 0xC1, n, 0xE9] => Some(i32::from(n.cast_signed())),
                _ => None,
            },
            Some(-16)
        );
    }
}
