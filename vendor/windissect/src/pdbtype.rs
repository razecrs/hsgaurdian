//! PDB TPI extraction for classes, fields, bases, enums, and virtual slots.
//!
//! Public Microsoft PDBs are often stripped and legitimately contain zero TPI
//! records.  The caller receives explicit stream statistics so that absence is
//! never confused with successful layout recovery.

use crate::model::{
    Capability, CapabilityStatus, Claim, ClaimStatus, ClaimSubject, Database, Evidence,
    EvidenceKind, EvidenceLocation, EvidenceObservation, EvidenceTool, Proof, ProofObligation,
    Usability,
};
use anyhow::{Context, Result};
use pdb::{FallibleIterator, ItemFinder, TypeData, TypeIndex};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TypeKind {
    Class,
    Struct,
    Interface,
    Union,
    Enum,
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldDef {
    pub name: String,
    pub type_index: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_name: Option<String>,
    pub offset: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    pub is_static: bool,
    pub access: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit_offset: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit_size: Option<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BaseClassDef {
    pub type_index: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_name: Option<String>,
    pub offset: u32,
    pub is_virtual: bool,
    pub access: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vbptr_offset: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vbtable_index: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MethodDef {
    pub name: String,
    pub type_index: u32,
    pub is_virtual: bool,
    pub is_pure: bool,
    pub is_static: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vtable_offset: Option<u32>,
    pub this_adjustment: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calling_convention: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnumValue {
    pub name: String,
    pub value: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolvedType {
    pub index: u32,
    pub name: String,
    pub kind: TypeKind,
    pub size: u64,
    pub packed: bool,
    pub fields: Vec<FieldDef>,
    pub bases: Vec<BaseClassDef>,
    pub methods: Vec<MethodDef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub underlying_type: Option<u32>,
    pub enum_values: Vec<EnumValue>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VTableEntry {
    pub slot: u32,
    pub byte_offset: u32,
    pub method_name: String,
    pub method_type_index: u32,
    pub this_adjustment: u32,
    pub is_pure: bool,
    pub is_introducing: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct VTableDef {
    pub class_type_index: u32,
    pub class_name: String,
    pub object_offset: i64,
    pub entries: Vec<VTableEntry>,
    pub evidence: &'static str,
}

#[derive(Debug, Default)]
pub struct ExtractedTypes {
    pub tpi_records: usize,
    pub forward_references: usize,
    pub parse_errors: usize,
    pub types: Vec<ResolvedType>,
    pub vtables: Vec<VTableDef>,
}

pub fn extract_types(pdb_path: &std::path::Path) -> Result<ExtractedTypes> {
    let file = std::fs::File::open(pdb_path)
        .with_context(|| format!("open PDB {}", pdb_path.display()))?;
    let mut pdb = pdb::PDB::open(file).context("open PDB")?;
    let tpi = pdb.type_information().context("read PDB TPI stream")?;
    let mut finder = tpi.finder();

    let mut index_iter = tpi.iter();
    while index_iter.next()?.is_some() {
        finder.update(&index_iter);
    }

    let mut out = initial_extraction(tpi.len());
    let mut index_names = BTreeMap::<u32, String>::new();
    let mut complete_sizes = BTreeMap::<String, u32>::new();
    let mut iter = tpi.iter();
    while let Some(item) = iter.next()? {
        let index = item.index();
        let Ok(data) = item.parse() else {
            out.parse_errors += 1;
            continue;
        };
        match data {
            TypeData::Class(class) => {
                let name = class.name.to_string().into_owned();
                index_names.insert(index.0, name.clone());
                if class.properties.forward_reference() {
                    out.forward_references += 1;
                    continue;
                }
                let kind = match class.kind {
                    pdb::ClassKind::Class => TypeKind::Class,
                    pdb::ClassKind::Struct => TypeKind::Struct,
                    pdb::ClassKind::Interface => TypeKind::Interface,
                };
                let (fields, bases, methods) = collect_fields(&finder, class.fields);
                if let Ok(size) = u32::try_from(class.size) {
                    complete_sizes.insert(name.clone(), size);
                }
                out.types.push(ResolvedType {
                    index: index.0,
                    name,
                    kind,
                    size: class.size,
                    packed: class.properties.packed(),
                    fields,
                    bases,
                    methods,
                    underlying_type: None,
                    enum_values: Vec::new(),
                });
            }
            TypeData::Union(union_) => {
                let name = union_.name.to_string().into_owned();
                index_names.insert(index.0, name.clone());
                if union_.properties.forward_reference() {
                    out.forward_references += 1;
                    continue;
                }
                let (fields, _, _) = collect_fields(&finder, Some(union_.fields));
                if let Ok(size) = u32::try_from(union_.size) {
                    complete_sizes.insert(name.clone(), size);
                }
                out.types.push(ResolvedType {
                    index: index.0,
                    name,
                    kind: TypeKind::Union,
                    size: union_.size,
                    packed: union_.properties.packed(),
                    fields,
                    bases: Vec::new(),
                    methods: Vec::new(),
                    underlying_type: None,
                    enum_values: Vec::new(),
                });
            }
            TypeData::Enumeration(enum_) => {
                let name = enum_.name.to_string().into_owned();
                index_names.insert(index.0, name.clone());
                if enum_.properties.forward_reference() {
                    out.forward_references += 1;
                    continue;
                }
                let values = collect_enumerators(&finder, enum_.fields);
                out.types.push(ResolvedType {
                    index: index.0,
                    name,
                    kind: TypeKind::Enum,
                    size: 0,
                    packed: false,
                    fields: Vec::new(),
                    bases: Vec::new(),
                    methods: Vec::new(),
                    underlying_type: Some(enum_.underlying_type.0),
                    enum_values: values,
                });
            }
            _ => {}
        }
    }
    Ok(finalize_extraction(out, &index_names, &complete_sizes))
}

fn finalize_extraction(
    mut out: ExtractedTypes,
    index_names: &BTreeMap<u32, String>,
    complete_sizes: &BTreeMap<String, u32>,
) -> ExtractedTypes {
    resolve_type_names(&mut out.types, index_names, complete_sizes);
    out.vtables = reconstruct_vtables(&out.types, index_names);
    sort_extracted(&mut out);
    out
}

fn initial_extraction(tpi_records: usize) -> ExtractedTypes {
    ExtractedTypes {
        tpi_records,
        ..Default::default()
    }
}

fn sort_extracted(out: &mut ExtractedTypes) {
    out.types
        .sort_by(|a, b| (&a.name, a.index).cmp(&(&b.name, b.index)));
    out.vtables.sort_by(|a, b| {
        (&a.class_name, a.class_type_index).cmp(&(&b.class_name, b.class_type_index))
    });
}

fn resolve_type_names(
    types: &mut [ResolvedType],
    index_names: &BTreeMap<u32, String>,
    complete_sizes: &BTreeMap<String, u32>,
) {
    for ty in types {
        for field in &mut ty.fields {
            field.type_name = index_names.get(&field.type_index).cloned();
            if field.width.is_none() {
                field.width = field
                    .type_name
                    .as_ref()
                    .and_then(|name| complete_sizes.get(name).copied());
            }
        }
        for base in &mut ty.bases {
            base.type_name = index_names.get(&base.type_index).cloned();
        }
    }
}

fn reconstruct_vtables(
    types: &[ResolvedType],
    index_names: &BTreeMap<u32, String>,
) -> Vec<VTableDef> {
    let complete_by_name: BTreeMap<&str, &ResolvedType> =
        types.iter().map(|ty| (ty.name.as_str(), ty)).collect();
    let mut tables = Vec::new();
    for ty in types {
        let mut groups = BTreeMap::<i64, Vec<VTableEntry>>::new();
        let introduced = virtual_entries(&ty.methods);
        if !introduced.is_empty() {
            groups.entry(0).or_default().extend(introduced);
        }
        for base in &ty.bases {
            let Some(base_name) = base
                .type_name
                .as_deref()
                .or_else(|| index_names.get(&base.type_index).map(String::as_str))
            else {
                continue;
            };
            let Some(base_type) = complete_by_name.get(base_name).copied() else {
                continue;
            };
            for base_method in base_type
                .methods
                .iter()
                .filter(|method| method.is_virtual && method.vtable_offset.is_some())
            {
                let selected = ty
                    .methods
                    .iter()
                    .find(|method| {
                        method.is_virtual
                            && method.name == base_method.name
                            && method.this_adjustment == base.offset
                    })
                    .unwrap_or(base_method);
                let byte_offset = base_method.vtable_offset.unwrap_or(0);
                groups
                    .entry(i64::from(base.offset))
                    .or_default()
                    .push(VTableEntry {
                        slot: byte_offset / 8,
                        byte_offset,
                        method_name: selected.name.clone(),
                        method_type_index: selected.type_index,
                        this_adjustment: selected.this_adjustment,
                        is_pure: selected.is_pure,
                        is_introducing: selected.vtable_offset.is_some(),
                    });
            }
        }
        for (object_offset, mut entries) in groups {
            entries.sort_by_key(|entry| entry.slot);
            entries.dedup_by_key(|entry| entry.slot);
            if !entries.is_empty() {
                tables.push(VTableDef {
                    class_type_index: ty.index,
                    class_name: ty.name.clone(),
                    object_offset,
                    entries,
                    evidence: "pdb-tpi-virtual-method-order",
                });
            }
        }
    }
    tables
}

type ClassParts = (Vec<FieldDef>, Vec<BaseClassDef>, Vec<MethodDef>);

fn collect_fields(finder: &ItemFinder<'_, TypeIndex>, first: Option<TypeIndex>) -> ClassParts {
    let mut fields = Vec::new();
    let mut bases = Vec::new();
    let mut methods = Vec::new();
    let mut next = first;
    let mut seen = BTreeSet::new();
    while let Some(index) = next {
        if index.0 == 0 {
            break;
        }
        if !seen.insert(index.0) {
            break;
        }
        let Ok(item) = finder.find(index) else {
            break;
        };
        let Ok(TypeData::FieldList(list)) = item.parse() else {
            break;
        };
        next = list.continuation;
        for field in list.fields {
            match field {
                TypeData::Member(member) => {
                    let (bit_offset, bit_size) = bitfield(finder, member.field_type);
                    let width = type_size(finder, member.field_type, &mut BTreeSet::new());
                    fields.push(FieldDef {
                        name: member.name.to_string().into_owned(),
                        type_index: member.field_type.0,
                        type_name: None,
                        offset: member.offset,
                        width,
                        is_static: false,
                        access: access(member.attributes.access()),
                        bit_offset,
                        bit_size,
                    });
                }
                TypeData::StaticMember(member) => fields.push(FieldDef {
                    name: member.name.to_string().into_owned(),
                    type_index: member.field_type.0,
                    type_name: None,
                    offset: 0,
                    width: type_size(finder, member.field_type, &mut BTreeSet::new()),
                    is_static: true,
                    access: access(member.attributes.access()),
                    bit_offset: None,
                    bit_size: None,
                }),
                TypeData::BaseClass(base) => bases.push(BaseClassDef {
                    type_index: base.base_class.0,
                    type_name: None,
                    offset: base.offset,
                    is_virtual: false,
                    access: access(base.attributes.access()),
                    vbptr_offset: None,
                    vbtable_index: None,
                }),
                TypeData::VirtualBaseClass(base) => bases.push(BaseClassDef {
                    type_index: base.base_class.0,
                    type_name: None,
                    offset: 0,
                    is_virtual: true,
                    access: access(base.attributes.access()),
                    vbptr_offset: Some(base.base_pointer_offset),
                    vbtable_index: Some(base.virtual_base_offset),
                }),
                TypeData::Method(method) => methods.push(resolve_method(
                    finder,
                    method.name.to_string().into_owned(),
                    method.method_type,
                    method.attributes,
                    method.vtable_offset,
                )),
                TypeData::OverloadedMethod(group) => {
                    if let Ok(item) = finder.find(group.method_list)
                        && let Ok(TypeData::MethodList(list)) = item.parse()
                    {
                        for entry in list.methods {
                            methods.push(resolve_method(
                                finder,
                                group.name.to_string().into_owned(),
                                entry.method_type,
                                entry.attributes,
                                entry.vtable_offset,
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    (fields, bases, methods)
}

fn type_size(
    finder: &ItemFinder<'_, TypeIndex>,
    index: TypeIndex,
    seen: &mut BTreeSet<u32>,
) -> Option<u32> {
    if !seen.insert(index.0) {
        return None;
    }
    let data = finder.find(index).ok()?.parse().ok()?;
    let size = match data {
        TypeData::Primitive(primitive) => {
            use pdb::{Indirection, PrimitiveKind};
            if let Some(indirection) = primitive.indirection {
                Some(match indirection {
                    Indirection::Near16 => 2,
                    Indirection::Far16 | Indirection::Huge16 | Indirection::Near32 => 4,
                    Indirection::Far32 => 6,
                    Indirection::Near64 => 8,
                    Indirection::Near128 => 16,
                })
            } else {
                Some(match primitive.kind {
                    PrimitiveKind::NoType | PrimitiveKind::Void => 0,
                    PrimitiveKind::Char
                    | PrimitiveKind::UChar
                    | PrimitiveKind::RChar
                    | PrimitiveKind::I8
                    | PrimitiveKind::U8
                    | PrimitiveKind::Bool8 => 1,
                    PrimitiveKind::WChar
                    | PrimitiveKind::RChar16
                    | PrimitiveKind::Short
                    | PrimitiveKind::UShort
                    | PrimitiveKind::I16
                    | PrimitiveKind::U16
                    | PrimitiveKind::F16
                    | PrimitiveKind::Bool16 => 2,
                    PrimitiveKind::RChar32
                    | PrimitiveKind::Long
                    | PrimitiveKind::ULong
                    | PrimitiveKind::I32
                    | PrimitiveKind::U32
                    | PrimitiveKind::F32
                    | PrimitiveKind::F32PP
                    | PrimitiveKind::Bool32
                    | PrimitiveKind::HRESULT => 4,
                    PrimitiveKind::F48 => 6,
                    PrimitiveKind::Quad
                    | PrimitiveKind::UQuad
                    | PrimitiveKind::I64
                    | PrimitiveKind::U64
                    | PrimitiveKind::F64
                    | PrimitiveKind::Complex32
                    | PrimitiveKind::Bool64 => 8,
                    PrimitiveKind::F80 => 10,
                    PrimitiveKind::Octa
                    | PrimitiveKind::UOcta
                    | PrimitiveKind::I128
                    | PrimitiveKind::U128
                    | PrimitiveKind::F128
                    | PrimitiveKind::Complex64 => 16,
                    PrimitiveKind::Complex80 => 20,
                    PrimitiveKind::Complex128 => 32,
                    _ => return None,
                })
            }
        }
        TypeData::Pointer(pointer) => Some(u32::from(pointer.attributes.size())),
        TypeData::Modifier(modifier) => type_size(finder, modifier.underlying_type, seen),
        TypeData::Array(array) => array.dimensions.last().copied(),
        TypeData::Class(class) => u32::try_from(class.size).ok(),
        TypeData::Union(union_) => u32::try_from(union_.size).ok(),
        TypeData::Enumeration(enumeration) => type_size(finder, enumeration.underlying_type, seen),
        TypeData::Bitfield(bitfield) => type_size(finder, bitfield.underlying_type, seen),
        _ => None,
    };
    seen.remove(&index.0);
    size.filter(|value| *value > 0)
}

fn resolve_method(
    finder: &ItemFinder<'_, TypeIndex>,
    name: String,
    type_index: TypeIndex,
    attrs: pdb::FieldAttributes,
    vtable_offset: Option<u32>,
) -> MethodDef {
    let (this_adjustment, calling_convention) = finder
        .find(type_index)
        .ok()
        .and_then(|i| i.parse().ok())
        .and_then(|d| match d {
            TypeData::MemberFunction(f) => Some((
                f.this_adjustment,
                callconv(f.attributes.calling_convention()),
            )),
            _ => None,
        })
        .unwrap_or((0, None));
    MethodDef {
        name,
        type_index: type_index.0,
        is_virtual: attrs.is_virtual() || attrs.is_intro_virtual(),
        is_pure: attrs.is_pure_virtual(),
        is_static: attrs.is_static(),
        vtable_offset,
        this_adjustment,
        calling_convention,
    }
}

fn virtual_entries(methods: &[MethodDef]) -> Vec<VTableEntry> {
    let mut ordered: BTreeMap<u32, &MethodDef> = BTreeMap::new();
    for method in methods {
        if method.is_virtual
            && let Some(offset) = method.vtable_offset
        {
            ordered.entry(offset).or_insert(method);
        }
    }
    ordered
        .into_iter()
        .enumerate()
        .map(|(slot, (offset, method))| VTableEntry {
            slot: u32::try_from(slot).unwrap_or(u32::MAX),
            byte_offset: offset,
            method_name: method.name.clone(),
            method_type_index: method.type_index,
            this_adjustment: method.this_adjustment,
            is_pure: method.is_pure,
            is_introducing: true,
        })
        .collect()
}

fn collect_enumerators(finder: &ItemFinder<'_, TypeIndex>, first: TypeIndex) -> Vec<EnumValue> {
    let mut values = Vec::new();
    let mut next = Some(first);
    let mut seen = BTreeSet::new();
    while let Some(index) = next {
        if index.0 == 0 {
            break;
        }
        if !seen.insert(index.0) {
            break;
        }
        let Ok(item) = finder.find(index) else {
            break;
        };
        let Ok(TypeData::FieldList(list)) = item.parse() else {
            break;
        };
        next = list.continuation;
        for field in list.fields {
            if let TypeData::Enumerate(value) = field {
                let number = match value.value {
                    // LF_CHAR is a signed 8-bit numeric leaf. pdb 0.8 exposes
                    // it as U8, so preserve the CodeView signed interpretation.
                    pdb::Variant::U8(number) => i64::from(number.cast_signed()),
                    pdb::Variant::U16(number) => i64::from(number),
                    pdb::Variant::U32(number) => i64::from(number),
                    pdb::Variant::U64(number) => match i64::try_from(number) {
                        Ok(number) => number,
                        Err(_) => continue,
                    },
                    pdb::Variant::I8(number) => i64::from(number),
                    pdb::Variant::I16(number) => i64::from(number),
                    pdb::Variant::I32(number) => i64::from(number),
                    pdb::Variant::I64(number) => number,
                };
                values.push(EnumValue {
                    name: value.name.to_string().into_owned(),
                    value: number,
                });
            }
        }
    }
    values
}

fn bitfield(finder: &ItemFinder<'_, TypeIndex>, index: TypeIndex) -> (Option<u8>, Option<u8>) {
    finder
        .find(index)
        .ok()
        .and_then(|i| i.parse().ok())
        .and_then(|d| match d {
            TypeData::Bitfield(b) => Some((Some(b.position), Some(b.length))),
            _ => None,
        })
        .unwrap_or((None, None))
}

const fn access(value: u8) -> &'static str {
    match value {
        1 => "private",
        2 => "protected",
        3 => "public",
        _ => "unknown",
    }
}

const fn callconv(value: u8) -> Option<&'static str> {
    Some(match value {
        0x00 => "__cdecl",
        0x07 => "__stdcall",
        0x0b => "__thiscall",
        0x04 => "__fastcall",
        0x18 => "__vectorcall",
        _ => return None,
    })
}

pub fn enrich_database_with_types(db: &mut Database, extracted: &ExtractedTypes) {
    db.type_recovery = serde_json::json!({
        "source": "pdb-tpi", "records": extracted.tpi_records,
        "forward_references": extracted.forward_references,
        "parse_errors": extracted.parse_errors,
        "status": if extracted.tpi_records == 0 { "unavailable-stripped-pdb" } else { "recovered" },
        "note": if extracted.tpi_records == 0 { "PDB TPI stream contains zero records" } else { "layouts are PDB-derived; alignment is not inferred" },
    });
    db.types = extracted
        .types
        .iter()
        .map(|t| serde_json::to_value(t).expect("serializable type"))
        .collect();
    db.enums = extracted
        .types
        .iter()
        .filter(|t| matches!(t.kind, TypeKind::Enum))
        .map(|t| serde_json::to_value(t).expect("serializable enum"))
        .collect();
    db.vtables = extracted
        .vtables
        .iter()
        .map(|v| serde_json::to_value(v).expect("serializable vtable"))
        .collect();
    add_pdb_type_proof_graph(db, extracted);
}

fn add_pdb_type_proof_graph(db: &mut Database, extracted: &ExtractedTypes) {
    if extracted.tpi_records == 0 {
        db.capabilities.push(Capability {
            id: "pdb-tpi-layouts".into(),
            status: CapabilityStatus::Unsupported,
            analyzer: "pdbtype".into(),
            reason: "identity-matched PDB contains zero TPI records".into(),
        });
        return;
    }
    for ty in &extracted.types {
        add_type_proof(db, ty);
    }
    add_vtable_proofs(db, &extracted.vtables);
    db.capabilities.push(Capability {
        id: "pdb-tpi-layouts".into(),
        status: CapabilityStatus::Supported,
        analyzer: "pdbtype".into(),
        reason: format!("{} resolved type definitions", extracted.types.len()),
    });
    db.capabilities.push(Capability {
        id: "pdb-tpi-aliases".into(),
        status: CapabilityStatus::Unsupported,
        analyzer: "pdbtype".into(),
        reason: "LF_ALIAS records are not exposed by the current PDB parser; aliases are withheld rather than guessed".into(),
    });
}

fn add_type_proof(db: &mut Database, ty: &ResolvedType) {
    let proof_id = format!("proof:pdb-type:{:X}", ty.index);
    db.proofs.push(Proof {
        id: proof_id.clone(),
        rule_id: "pdb.tpi-layout".into(),
        rule_version: 1,
        passed: true,
        obligations: vec![
            ProofObligation {
                name: "identity-matched-pdb".into(),
                satisfied: db.binary.pdb_guid.is_some() && db.binary.pdb_age.is_some(),
                detail: "PE CodeView GUID+age matched before TPI extraction".into(),
            },
            ProofObligation {
                name: "non-forward-definition".into(),
                satisfied: true,
                detail: format!("TPI type index 0x{:X}", ty.index),
            },
        ],
    });
    let size_evidence = format!("ev:pdb-type-size:{:X}", ty.index);
    db.evidence.push(Evidence {
        id: size_evidence.clone(),
        kind: EvidenceKind::PdbRecord,
        tool: EvidenceTool::Pdb,
        rule_id: "pdb.tpi-layout".into(),
        rule_version: 1,
        location: EvidenceLocation::default(),
        observation: EvidenceObservation::Text {
            text: format!("{} has PDB size 0x{:X}", ty.name, ty.size),
        },
    });
    db.claims.push(Claim {
        id: format!("claim:pdb-object-size:{:X}", ty.index),
        subject: ClaimSubject::ObjectSize {
            owner: ty.name.clone(),
            size: ty.size,
        },
        status: ClaimStatus::Observed,
        usability: Usability::Verified,
        evidence_ids: vec![size_evidence],
        proof_id: Some(proof_id.clone()),
    });
    add_field_proofs(db, ty, &proof_id);
    add_base_proofs(db, ty, &proof_id);
    add_enum_proofs(db, ty, &proof_id);
}

fn add_field_proofs(db: &mut Database, ty: &ResolvedType, proof_id: &str) {
    for (field_index, field) in ty.fields.iter().enumerate() {
        let evidence_id = format!("ev:pdb-field:{:X}:{field_index}", ty.index);
        db.evidence.push(Evidence {
            id: evidence_id.clone(),
            kind: EvidenceKind::PdbRecord,
            tool: EvidenceTool::Pdb,
            rule_id: "pdb.tpi-layout".into(),
            rule_version: 1,
            location: EvidenceLocation::default(),
            observation: EvidenceObservation::MemberAccess {
                owner: ty.name.clone(),
                offset: field.offset,
                width: field.width.unwrap_or(0),
                access: "pdb-layout".into(),
                suggested_name: Some(field.name.clone()),
            },
        });
        db.claims.push(Claim {
            id: format!("claim:pdb-field:{:X}:{field_index}", ty.index),
            subject: ClaimSubject::Member {
                owner: ty.name.clone(),
                offset: field.offset,
                width: field.width.unwrap_or(0),
                bit_offset: field.bit_offset,
                bit_size: field.bit_size,
                type_name: field.type_name.clone(),
                name: Some(field.name.clone()),
                structural_only: false,
                access: "pdb-layout".into(),
            },
            status: ClaimStatus::Observed,
            usability: Usability::Verified,
            evidence_ids: vec![evidence_id],
            proof_id: Some(proof_id.to_string()),
        });
    }
}

fn add_base_proofs(db: &mut Database, ty: &ResolvedType, proof_id: &str) {
    for (base_index, base) in ty.bases.iter().enumerate() {
        let evidence_id = format!("ev:pdb-base:{:X}:{base_index}", ty.index);
        let base_name = base
            .type_name
            .clone()
            .unwrap_or_else(|| format!("type-index:0x{:X}", base.type_index));
        db.evidence.push(Evidence {
            id: evidence_id.clone(),
            kind: EvidenceKind::PdbRecord,
            tool: EvidenceTool::Pdb,
            rule_id: "pdb.tpi-layout".into(),
            rule_version: 1,
            location: EvidenceLocation::default(),
            observation: EvidenceObservation::Text {
                text: format!("{} base {} at +0x{:X}", ty.name, base_name, base.offset),
            },
        });
        db.claims.push(Claim {
            id: format!("claim:pdb-base:{:X}:{base_index}", ty.index),
            subject: ClaimSubject::Base {
                derived: ty.name.clone(),
                base: base_name,
                offset: Some(i64::from(base.offset)),
                is_virtual: base.is_virtual,
            },
            status: ClaimStatus::Observed,
            usability: Usability::Verified,
            evidence_ids: vec![evidence_id],
            proof_id: Some(proof_id.to_string()),
        });
    }
}

fn add_enum_proofs(db: &mut Database, ty: &ResolvedType, proof_id: &str) {
    for (value_index, value) in ty.enum_values.iter().enumerate() {
        let evidence_id = format!("ev:pdb-enum:{:X}:{value_index}", ty.index);
        db.evidence.push(Evidence {
            id: evidence_id.clone(),
            kind: EvidenceKind::PdbRecord,
            tool: EvidenceTool::Pdb,
            rule_id: "pdb.tpi-enum".into(),
            rule_version: 1,
            location: EvidenceLocation::default(),
            observation: EvidenceObservation::Text {
                text: format!("{}::{} = {}", ty.name, value.name, value.value),
            },
        });
        db.claims.push(Claim {
            id: format!("claim:pdb-enum:{:X}:{value_index}", ty.index),
            subject: ClaimSubject::EnumValue {
                owner: ty.name.clone(),
                name: value.name.clone(),
                value: value.value,
            },
            status: ClaimStatus::Observed,
            usability: Usability::Verified,
            evidence_ids: vec![evidence_id],
            proof_id: Some(proof_id.to_string()),
        });
    }
}

fn add_vtable_proofs(db: &mut Database, tables: &[VTableDef]) {
    for table in tables {
        let proof_id = format!("proof:pdb-type:{:X}", table.class_type_index);
        for entry in &table.entries {
            let evidence_id = format!(
                "ev:pdb-vslot:{:X}:{}:{}",
                table.class_type_index, table.object_offset, entry.slot
            );
            db.evidence.push(Evidence {
                id: evidence_id.clone(),
                kind: EvidenceKind::PdbRecord,
                tool: EvidenceTool::Pdb,
                rule_id: "pdb.tpi-vtable-order".into(),
                rule_version: 1,
                location: EvidenceLocation::default(),
                observation: EvidenceObservation::Text {
                    text: format!(
                        "{} subobject {:+#X} vtable slot {} at byte offset 0x{:X}: {}",
                        table.class_name,
                        table.object_offset,
                        entry.slot,
                        entry.byte_offset,
                        entry.method_name
                    ),
                },
            });
            db.claims.push(Claim {
                id: format!(
                    "claim:pdb-vslot:{:X}:{}:{}",
                    table.class_type_index, table.object_offset, entry.slot
                ),
                subject: ClaimSubject::VtableSlot {
                    owner: table.class_name.clone(),
                    table_rva: 0,
                    table_object_offset: Some(table.object_offset),
                    slot: entry.slot,
                    target_rva: 0,
                },
                status: ClaimStatus::Observed,
                usability: Usability::Verified,
                evidence_ids: vec![evidence_id],
                proof_id: Some(proof_id.clone()),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn access_values() {
        assert_eq!(access(1), "private");
        assert_eq!(access(3), "public");
    }
    #[test]
    fn calling_conventions() {
        assert_eq!(callconv(0x0b), Some("__thiscall"));
        assert_eq!(callconv(0xff), None);
    }
    #[test]
    fn virtual_slots_are_ordered_by_byte_offset() {
        let methods = vec![
            MethodDef {
                name: "b".into(),
                type_index: 2,
                is_virtual: true,
                is_pure: false,
                is_static: false,
                vtable_offset: Some(8),
                this_adjustment: 0,
                calling_convention: None,
            },
            MethodDef {
                name: "a".into(),
                type_index: 1,
                is_virtual: true,
                is_pure: false,
                is_static: false,
                vtable_offset: Some(0),
                this_adjustment: 0,
                calling_convention: None,
            },
        ];
        let entries = virtual_entries(&methods);
        assert_eq!(
            entries
                .iter()
                .map(|e| e.method_name.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
    }
}
