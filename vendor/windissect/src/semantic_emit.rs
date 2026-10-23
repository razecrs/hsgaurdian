//! Separate verified and candidate semantic output surfaces.

use crate::model::{Database, SemanticClass, SemanticStatus};
use anyhow::Result;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub struct Summary {
    pub verified_classes: usize,
    pub candidate_classes: usize,
    pub verified_enums: usize,
    pub candidate_enums: usize,
    pub verified_fields: usize,
    pub verified_named_fields: usize,
    pub verified_storage_slots: usize,
    pub verified_bases: usize,
    pub verified_vtables: usize,
    pub verified_vtable_slots: usize,
}

pub fn emit(db: &Database, root: &Path) -> Result<Summary> {
    let verified = root.join("verified");
    let candidates = root.join("candidates");
    fs::create_dir_all(verified.join("include"))?;
    fs::create_dir_all(verified.join("rust/src"))?;
    fs::create_dir_all(candidates.join("include"))?;
    let stem = target_stem(&db.binary.file);

    let verified_classes: Vec<_> = db
        .semantic
        .classes
        .iter()
        .filter(|class| class.status == SemanticStatus::Verified)
        .collect();
    let candidate_classes: Vec<_> = db
        .semantic
        .classes
        .iter()
        .filter(|class| class.status != SemanticStatus::Verified)
        .collect();
    let verified_enums: Vec<_> = db
        .semantic
        .enums
        .iter()
        .filter(|item| item.status == SemanticStatus::Verified)
        .collect();
    let candidate_enums: Vec<_> = db
        .semantic
        .enums
        .iter()
        .filter(|item| item.status != SemanticStatus::Verified)
        .collect();
    let summary = summarize(
        db,
        verified_classes.len(),
        candidate_classes.len(),
        verified_enums.len(),
        candidate_enums.len(),
    );

    crate::diff::atomic_write(
        &verified
            .join("include")
            .join(format!("{stem}_semantic.hpp")),
        verified_cpp(db, &verified_classes, &verified_enums).as_bytes(),
    )?;
    crate::diff::atomic_write(
        &verified
            .join("include")
            .join(format!("{stem}_semantic_facts.hpp")),
        verified_facts_cpp(db).as_bytes(),
    )?;
    crate::diff::atomic_write(
        &candidates
            .join("include")
            .join(format!("{stem}_semantic_candidates.hpp")),
        candidate_cpp(db, &candidate_classes, &candidate_enums).as_bytes(),
    )?;
    crate::diff::atomic_write(
        &root.join("semantic.json"),
        &serde_json::to_vec_pretty(&db.semantic)?,
    )?;
    crate::diff::atomic_write(&root.join("report.md"), markdown(db, &summary).as_bytes())?;
    emit_rust(db, &verified, &stem, &verified_classes, &verified_enums)?;
    Ok(summary)
}

fn summarize(
    db: &Database,
    verified_classes: usize,
    candidate_classes: usize,
    verified_enums: usize,
    candidate_enums: usize,
) -> Summary {
    let verified_fields = db
        .semantic
        .classes
        .iter()
        .flat_map(|class| &class.fields)
        .filter(|field| field.status == SemanticStatus::Verified)
        .count();
    let verified_named_fields = db
        .semantic
        .classes
        .iter()
        .flat_map(|class| &class.fields)
        .filter(|field| {
            field.status == SemanticStatus::Verified
                && !field.structural_only
                && field.name.is_some()
        })
        .count();
    let verified_storage_slots = db
        .semantic
        .classes
        .iter()
        .flat_map(|class| &class.fields)
        .filter(|field| field.status == SemanticStatus::Verified && field.structural_only)
        .count();
    Summary {
        verified_classes,
        candidate_classes,
        verified_enums,
        candidate_enums,
        verified_fields,
        verified_named_fields,
        verified_storage_slots,
        verified_bases: db
            .semantic
            .classes
            .iter()
            .flat_map(|class| &class.bases)
            .filter(|base| base.relationship_verified)
            .count(),
        verified_vtables: db
            .semantic
            .classes
            .iter()
            .flat_map(|class| &class.vtables)
            .filter(|table| table.status == SemanticStatus::Verified)
            .count(),
        verified_vtable_slots: db
            .semantic
            .classes
            .iter()
            .flat_map(|class| &class.vtables)
            .flat_map(|table| &table.slots)
            .filter(|slot| slot.status == SemanticStatus::Verified)
            .count(),
    }
}

fn verified_cpp(
    db: &Database,
    classes: &[&SemanticClass],
    enums: &[&crate::model::SemanticEnum],
) -> String {
    let mut out = preamble(db, false);
    out.push_str("namespace windissect::semantic::verified {\n\n");
    for item in enums {
        let name = sanitize(&item.qualified_name);
        let underlying = cpp_integer_type(item.underlying_type.as_deref().unwrap_or("i64"));
        let _ = writeln!(out, "enum class {name} : {underlying} {{");
        let mut seen = BTreeSet::new();
        for value in &item.values {
            let label = sanitize(&value.name);
            if !seen.insert(label.clone()) {
                continue;
            }
            let enum_value = project_enum_value(
                item.underlying_type.as_deref().unwrap_or("i64"),
                value.value,
            );
            let _ = writeln!(out, "    {label} = {enum_value},");
        }
        out.push_str("};\n\n");
    }
    for class in classes {
        emit_layout(&mut out, class);
    }
    out.push_str("} // namespace windissect::semantic::verified\n");
    out
}

fn verified_facts_cpp(db: &Database) -> String {
    let mut out = preamble(db, false);
    out.push_str("namespace windissect::semantic::verified_facts {\n\n");
    for (class_index, class) in db.semantic.classes.iter().enumerate() {
        let has_facts = class
            .fields
            .iter()
            .any(|field| field.status == SemanticStatus::Verified)
            || class.bases.iter().any(|base| base.relationship_verified)
            || class
                .vtables
                .iter()
                .any(|table| table.status == SemanticStatus::Verified);
        if !has_facts {
            continue;
        }
        let label = sanitize(&class.qualified_name);
        let _ = writeln!(out, "// {}", class.qualified_name);
        let _ = writeln!(out, "struct {label}_facts_{class_index} {{");
        for (field_index, field) in class.fields.iter().enumerate() {
            if field.status != SemanticStatus::Verified {
                continue;
            }
            let prefix = if field.structural_only {
                "storage"
            } else {
                "field"
            };
            let _ = writeln!(
                out,
                "    static constexpr std::size_t {prefix}_{field_index}_offset = 0x{:X};",
                field.offset
            );
            let _ = writeln!(
                out,
                "    static constexpr std::size_t {prefix}_{field_index}_width = {};",
                field.width
            );
        }
        for (base_index, base) in class.bases.iter().enumerate() {
            if !base.relationship_verified {
                continue;
            }
            let base_label = sanitize(&base.qualified_name);
            let _ = writeln!(
                out,
                "    static constexpr bool base_{base_label}_{base_index}_verified = true;"
            );
        }
        for (table_index, table) in class.vtables.iter().enumerate() {
            if table.status != SemanticStatus::Verified {
                continue;
            }
            let _ = writeln!(
                out,
                "    static constexpr std::uint32_t vtable_{table_index}_rva = 0x{:X};",
                table.rva
            );
            for slot in &table.slots {
                if slot.status == SemanticStatus::Verified {
                    let _ = writeln!(
                        out,
                        "    static constexpr std::uint32_t vtable_{table_index}_slot_{}_target_rva = 0x{:X};",
                        slot.slot, slot.target_rva
                    );
                }
            }
        }
        out.push_str("};\n\n");
    }
    out.push_str("} // namespace windissect::semantic::verified_facts\n");
    out
}

fn candidate_cpp(
    db: &Database,
    classes: &[&SemanticClass],
    enums: &[&crate::model::SemanticEnum],
) -> String {
    let mut out = preamble(db, true);
    out.push_str("#ifndef WINDISSECT_ENABLE_CANDIDATE_SEMANTICS\n#error \"Candidate semantics are not ABI-safe; define WINDISSECT_ENABLE_CANDIDATE_SEMANTICS only for inspection\"\n#endif\n\n");
    out.push_str("namespace windissect::semantic::candidate {\n\n");
    for item in enums {
        let name = sanitize(&item.qualified_name);
        let _ = writeln!(out, "struct {name}_enum_observations {{");
        for (index, value) in item.values.iter().enumerate() {
            let label = sanitize(&value.name);
            let _ = writeln!(
                out,
                "    static constexpr std::int64_t {label}_{index} = {};",
                value.value
            );
        }
        out.push_str("};\n\n");
    }
    for class in classes {
        let name = sanitize(&class.qualified_name);
        let _ = writeln!(out, "struct {name}_observations {{");
        if let Some(size) = class.size {
            let _ = writeln!(
                out,
                "    static constexpr std::size_t candidate_size = 0x{size:X};"
            );
        }
        for (index, field) in class.fields.iter().enumerate() {
            let base = field
                .name
                .as_deref()
                .map_or_else(|| format!("field_{index}"), sanitize);
            let label = format!("{base}_{:X}_{index}", field.offset);
            let _ = writeln!(
                out,
                "    static constexpr std::size_t {label}_offset = 0x{:X};",
                field.offset
            );
            let _ = writeln!(
                out,
                "    static constexpr std::size_t {label}_width = {};",
                field.width
            );
        }
        out.push_str("};\n\n");
    }
    out.push_str("} // namespace windissect::semantic::candidate\n");
    out
}

fn emit_layout(out: &mut String, class: &SemanticClass) {
    let Some(size) = class.size else { return };
    if size == 0 {
        return;
    }
    let name = sanitize(&class.qualified_name);
    if class.kind == "union" {
        let _ = writeln!(out, "union {name}_layout {{");
        let mut max_width = 0u64;
        let mut written = false;
        for (index, field) in class.fields.iter().enumerate() {
            if field.status != SemanticStatus::Verified || field.width == 0 || field.structural_only
            {
                continue;
            }
            let width = u64::from(field.width).min(size);
            if width == 0 {
                continue;
            }
            let label = field
                .name
                .as_deref()
                .map_or_else(|| format!("field_{index}"), sanitize);
            let _ = writeln!(out, "    std::byte {label}[0x{width:X}];");
            written = true;
            max_width = max_width.max(width);
        }
        if !written || max_width < size {
            let _ = writeln!(out, "    std::byte _windissect_tail[0x{size:X}];");
        }
        out.push_str("};\n");
        let _ = writeln!(out, "static_assert(sizeof({name}_layout) == 0x{size:X});");
        emit_metadata(out, class, &name);
        return;
    }
    let _ = writeln!(out, "struct {name}_layout {{");
    let mut cursor = 0u64;
    let mut emitted = Vec::<(String, u64)>::new();
    for (index, field) in class.fields.iter().enumerate() {
        if field.status != SemanticStatus::Verified
            || field.width == 0
            || field.structural_only
            || field.offset < cursor
            || field.offset >= size
        {
            continue;
        }
        if field.offset > cursor {
            let _ = writeln!(
                out,
                "    std::byte _padding_{index}[0x{:X}];",
                field.offset - cursor
            );
        }
        let label_base = field
            .name
            .as_deref()
            .map_or_else(|| format!("field_{index}"), sanitize);
        let label = format!("{label_base}_{index}");
        let width = u64::from(field.width).min(size - field.offset);
        let _ = writeln!(out, "    std::byte {label}[0x{width:X}];");
        emitted.push((label, field.offset));
        cursor = field.offset + width;
    }
    if size > cursor {
        let _ = writeln!(out, "    std::byte _tail_padding[0x{:X}];", size - cursor);
    }
    out.push_str("};\n");
    let _ = writeln!(out, "static_assert(sizeof({name}_layout) == 0x{size:X});");
    for (label, offset) in emitted {
        let _ = writeln!(
            out,
            "static_assert(offsetof({name}_layout, {label}) == 0x{offset:X});"
        );
    }
    emit_metadata(out, class, &name);
}

fn emit_metadata(out: &mut String, class: &SemanticClass, name: &str) {
    let _ = writeln!(out, "struct {name}_metadata {{");
    for (index, field) in class.fields.iter().enumerate() {
        let label_base = field
            .name
            .as_deref()
            .map_or_else(|| format!("field_{index}"), sanitize);
        let label = format!("{label_base}_{index}");
        let _ = writeln!(
            out,
            "    static constexpr std::size_t {label}_offset = 0x{:X};",
            field.offset
        );
        if let (Some(bit_offset), Some(bit_size)) = (field.bit_offset, field.bit_size) {
            let mask = if bit_size == 64 {
                u64::MAX
            } else {
                ((1u64 << bit_size) - 1) << bit_offset
            };
            let _ = writeln!(
                out,
                "    static constexpr std::uint64_t {label}_mask = 0x{mask:X}ULL;"
            );
        }
    }
    for (index, base) in class.bases.iter().enumerate() {
        if let Some(offset) = base.offset {
            let label = sanitize(&base.qualified_name);
            let _ = writeln!(
                out,
                "    static constexpr std::ptrdiff_t base_{label}_{index}_offset = {offset};"
            );
        }
    }
    for (table_index, table) in class.vtables.iter().enumerate() {
        if let Some(offset) = table.object_offset {
            let _ = writeln!(
                out,
                "    static constexpr std::ptrdiff_t vtable_{table_index}_object_offset = {offset};"
            );
        }
        for slot in &table.slots {
            let method = slot
                .method_name
                .as_deref()
                .map_or_else(|| "unknown".into(), sanitize);
            let _ = writeln!(
                out,
                "    static constexpr std::size_t vtable_{table_index}_{method}_slot_{} = {};",
                slot.slot, slot.slot
            );
        }
    }
    out.push_str("};\n\n");
}

fn preamble(db: &Database, candidate: bool) -> String {
    format!(
        "#pragma once\n#include <cstddef>\n#include <cstdint>\n\n// Windissect semantic {} surface for {}.\n// PE SHA-256: {}\n\n",
        if candidate { "candidate" } else { "verified" },
        db.binary.file,
        db.binary.sha256.as_deref().unwrap_or("unknown")
    )
}

fn emit_rust(
    db: &Database,
    root: &Path,
    stem: &str,
    classes: &[&SemanticClass],
    enums: &[&crate::model::SemanticEnum],
) -> Result<()> {
    let crate_name = format!("{}-semantic", stem.to_ascii_lowercase().replace('_', "-"));
    let cargo = format!(
        "[package]\nname = {crate_name:?}\nversion = \"0.1.0\"\nedition = \"2021\"\nlicense = \"MIT\"\n\n[dependencies]\n"
    );
    crate::diff::atomic_write(&root.join("rust/Cargo.toml"), cargo.as_bytes())?;
    let mut lib = format!(
        "//! Verified Windissect semantic layouts for {}.\n#![allow(non_camel_case_types, non_snake_case, dead_code)]\n\n",
        db.binary.file
    );
    for item in enums {
        let name = sanitize(&item.qualified_name);
        let underlying = item.underlying_type.as_deref().unwrap_or("i64");
        let _ = writeln!(
            lib,
            "#[repr(transparent)]\n#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct {name}(pub {underlying});"
        );
        let _ = writeln!(lib, "impl {name} {{");
        let mut seen = BTreeSet::new();
        for (index, value) in item.values.iter().enumerate() {
            let value_label = sanitize(&value.name);
            if !seen.insert(value_label.clone()) {
                continue;
            }
            let label = format!("VALUE_{}_{}", value_label.to_ascii_uppercase(), index);
            let _ = writeln!(
                lib,
                "    pub const {label}: Self = Self({});",
                project_enum_value(underlying, value.value)
            );
        }
        lib.push_str("}\n\n");
    }
    for class in classes {
        let Some(size) = class.size else { continue };
        let name = sanitize(&class.qualified_name);
        if class.kind == "union" {
            let _ = writeln!(lib, "#[repr(C)]\npub union {name}_layout {{");
            let mut written = false;
            let mut max_width: u64 = 0;
            for (index, field) in class.fields.iter().enumerate() {
                if field.structural_only {
                    continue;
                }
                let label = rust_ident(field.name.as_deref().unwrap_or("").to_string(), index);
                let _ = writeln!(lib, "    pub {label}: [u8; 0x{:X}],", field.width);
                written = true;
                max_width = max_width.max(u64::from(field.width));
            }
            if !written || max_width < size {
                let _ = writeln!(lib, "    pub _windissect_tail: [u8; 0x{size:X}],");
            }
            lib.push_str("}\n");
        } else {
            let _ = writeln!(
                lib,
                "#[repr(C)]\npub struct {name}_layout {{ pub storage: [u8; 0x{size:X}] }}"
            );
        }
        let _ = writeln!(
            lib,
            "const _: () = assert!(core::mem::size_of::<{name}_layout>() == 0x{size:X});\n"
        );
        let _ = writeln!(lib, "impl {name}_layout {{");
        for (index, field) in class.fields.iter().enumerate() {
            let label_base = field
                .name
                .as_deref()
                .map_or_else(|| format!("field_{index}"), sanitize)
                .to_ascii_uppercase();
            let label = format!("{label_base}_{index}");
            let _ = writeln!(
                lib,
                "    pub const {label}_OFFSET: usize = 0x{:X};",
                field.offset
            );
            if let (Some(bit_offset), Some(bit_size)) = (field.bit_offset, field.bit_size) {
                let mask = if bit_size == 64 {
                    u64::MAX
                } else {
                    ((1u64 << bit_size) - 1) << bit_offset
                };
                let _ = writeln!(lib, "    pub const {label}_MASK: u64 = 0x{mask:X};");
            }
        }
        for (index, base) in class.bases.iter().enumerate() {
            if let Some(offset) = base.offset {
                let label = sanitize(&base.qualified_name).to_ascii_uppercase();
                let _ = writeln!(
                    lib,
                    "    pub const BASE_{label}_{index}_OFFSET: isize = {offset};"
                );
            }
        }
        lib.push_str("}\n\n");
    }
    emit_rust_facts(&mut lib, db);
    crate::diff::atomic_write(&root.join("rust/src/lib.rs"), lib.as_bytes())?;
    Ok(())
}

fn emit_rust_facts(out: &mut String, db: &Database) {
    out.push_str("pub mod verified_facts {\n");
    for (class_index, class) in db.semantic.classes.iter().enumerate() {
        let verified_fields: Vec<_> = class
            .fields
            .iter()
            .filter(|field| field.status == SemanticStatus::Verified)
            .collect();
        let verified_tables: Vec<_> = class
            .vtables
            .iter()
            .filter(|table| table.status == SemanticStatus::Verified)
            .collect();
        let verified_bases: Vec<_> = class
            .bases
            .iter()
            .filter(|base| base.relationship_verified)
            .collect();
        if verified_fields.is_empty() && verified_tables.is_empty() && verified_bases.is_empty() {
            continue;
        }
        let _ = writeln!(out, "    /// Facts for `{}`.", class.qualified_name);
        let _ = writeln!(out, "    pub mod class_{class_index} {{");
        for (field_index, field) in verified_fields.into_iter().enumerate() {
            let prefix = if field.structural_only {
                "STORAGE"
            } else {
                "FIELD"
            };
            let _ = writeln!(
                out,
                "        pub const {prefix}_{field_index}_OFFSET: usize = 0x{:X};",
                field.offset
            );
            let _ = writeln!(
                out,
                "        pub const {prefix}_{field_index}_WIDTH: usize = {};",
                field.width
            );
        }
        for (base_index, _) in verified_bases.into_iter().enumerate() {
            let _ = writeln!(
                out,
                "        pub const BASE_{base_index}_RELATIONSHIP_VERIFIED: bool = true;"
            );
        }
        for (table_index, table) in verified_tables.into_iter().enumerate() {
            let _ = writeln!(
                out,
                "        pub const VTABLE_{table_index}_RVA: u32 = 0x{:X};",
                table.rva
            );
            for slot in &table.slots {
                if slot.status == SemanticStatus::Verified {
                    let _ = writeln!(
                        out,
                        "        pub const VTABLE_{table_index}_SLOT_{}_TARGET_RVA: u32 = 0x{:X};",
                        slot.slot, slot.target_rva
                    );
                }
            }
        }
        out.push_str("    }\n");
    }
    out.push_str("}\n");
}

fn cpp_integer_type(name: &str) -> &'static str {
    match name {
        "i8" => "std::int8_t",
        "u8" => "std::uint8_t",
        "i16" => "std::int16_t",
        "u16" => "std::uint16_t",
        "i32" => "std::int32_t",
        "u32" => "std::uint32_t",
        "u64" => "std::uint64_t",
        _ => "std::int64_t",
    }
}

/// Project an enum value into the declared underlying type's representation.
/// `CodeView` records enumerators with the enum's underlying width and
/// signedness, so a value may only be representable after wrapping into that
/// type's range (e.g. `-4093` stored as `4294963203` under an `i32`).
///
fn project_enum_value(underlying: &str, value: i64) -> i64 {
    let (bits, signed) = match underlying {
        "i8" => (8, true),
        "u8" => (8, false),
        "i16" => (16, true),
        "u16" => (16, false),
        "i32" => (32, true),
        "u32" => (32, false),
        // A 64-bit underlying type already fills the i64 the value is stored in,
        // and an unknown type is passed through - both return the value as-is.
        _ => return value,
    };
    // bits is 8, 16 or 32 here, so the modulus and every intermediate stay well
    // inside i64: no i128 scratch and no narrowing cast are needed.
    let modulus: i64 = 1_i64 << bits;
    let wrapped = value.rem_euclid(modulus);
    if signed && wrapped >= modulus / 2 {
        wrapped - modulus
    } else {
        wrapped
    }
}

/// Render a field name as a Rust identifier, escaping reserved keywords so
/// the emitted union/struct member compiles as-is.
fn rust_ident(name: String, index: usize) -> String {
    const KEYWORDS: &[&str] = &[
        "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn",
        "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
        "return", "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe",
        "use", "where", "while", "async", "await", "dyn",
    ];
    let mut sanitized = name;
    if sanitized.is_empty() {
        sanitized = format!("field_{index}");
    } else {
        sanitized = sanitize(&sanitized);
    }
    if KEYWORDS.contains(&sanitized.as_str()) {
        format!("r#{sanitized}")
    } else {
        sanitized
    }
}

fn markdown(db: &Database, summary: &Summary) -> String {
    format!(
        "# Semantic recovery report\n\nTarget: `{}`  \nVerified complete classes: {}  \nCandidate/withheld complete classes: {}  \nVerified field/storage facts: {}  \nVerified named fields: {}  \nVerified unnamed storage slots: {}  \nVerified bases: {}  \nVerified vtables: {}  \nVerified vtable slots: {}  \nDiagnostics: {}\n\nA class can contain verified component facts while its complete object layout remains a candidate. Unnamed storage slots prove byte ranges observed through `this`; they do not claim a source-level member name. Candidate facts are not ABI-safe and are excluded from normal builds.\n",
        db.binary.file,
        summary.verified_classes,
        summary.candidate_classes,
        summary.verified_fields,
        summary.verified_named_fields,
        summary.verified_storage_slots,
        summary.verified_bases,
        summary.verified_vtables,
        summary.verified_vtable_slots,
        db.semantic.diagnostics.len()
    )
}

fn sanitize(value: &str) -> String {
    let mut result: String = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect();
    if result.is_empty() || result.as_bytes()[0].is_ascii_digit() {
        result.insert(0, '_');
    }
    result
}

pub fn target_stem(file: &str) -> String {
    sanitize(
        Path::new(file)
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("target"),
    )
}
