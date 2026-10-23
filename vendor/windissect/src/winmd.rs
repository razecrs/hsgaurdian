//! Windows metadata (`.winmd`) extraction.
//!
//! A winmd file is ECMA-335 metadata describing `WinRT` types: interfaces,
//! classes, their methods and the order those methods appear in. There is no
//! code and no PDB, so none of the PE pipeline applies - but the result belongs
//! in the same IR, because the question it answers is the one the archive
//! exists for: what did this API surface look like on this build, and what
//! moved since the last one.
//!
//! The reason this is worth having is the vtable slot. A `WinRT` interface is a
//! COM interface whose first six slots are `IInspectable` - `QueryInterface`,
//! `AddRef`, Release, `GetIids`, `GetRuntimeClassName`, `GetTrustLevel` - and whose own
//! methods follow in metadata declaration order. So slot = index + 6, exactly,
//! and that number is what anyone calling the interface by hand needs.
//!
//! That is not a guess. It was verified against a live taskbar: metadata says
//! `IVisualTreeHelperStatics::GetChild` is the fifth declared method, slot 10,
//! and slot 10 is what a working call uses.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::json;
use sha2::{Digest, Sha256};
use windows_metadata::reader::{Index, TypeCategory, TypeDef};

use crate::model::{
    BinaryInfo, Confidence, Coverage, Database, Kind, Provenance, Signature, Symbol,
};

/// Slots occupied by `IInspectable` before an interface's own methods begin.
const IINSPECTABLE_SLOTS: u32 = 6;

/// Vtable slot for the method at declaration index `i`. A type will never have
/// more methods than `u32::MAX`, so the saturating conversion cannot lose a real
/// value; it only avoids an unchecked `as` cast.
fn slot_of(i: usize) -> u32 {
    u32::try_from(i)
        .unwrap_or(u32::MAX)
        .saturating_add(IINSPECTABLE_SLOTS)
}

/// A resolved interface reference as `Namespace.Name`.
///
/// The crate's `Type` prints its whole internal shape under Debug, which is
/// unreadable in a diff; the parts that matter for identity are the namespace
/// and the name.
fn type_name(ty: &windows_metadata::Type) -> String {
    use windows_metadata::Type;
    let named = match ty {
        Type::ClassName(t) | Type::ValueName(t) => t,
        other => return format!("{other:?}"),
    };
    if named.namespace.is_empty() {
        named.name.clone()
    } else {
        format!("{}.{}", named.namespace, named.name)
    }
}

const fn category_name(category: &TypeCategory) -> &'static str {
    match category {
        TypeCategory::Interface => "interface",
        TypeCategory::Class => "class",
        TypeCategory::Enum => "enum",
        TypeCategory::Struct => "struct",
        TypeCategory::Delegate => "delegate",
        TypeCategory::Attribute => "attribute",
    }
}

/// Methods of a type, paired with the vtable slot they occupy.
///
/// Only interfaces and delegates have a meaningful slot: a runtime class is
/// not called through a vtable of its own, it is reached through the interfaces
/// it implements, so numbering its methods would invent a fact.
fn methods_of(ty: &TypeDef<'_>, slotted: bool) -> Vec<serde_json::Value> {
    ty.methods()
        .enumerate()
        .map(|(i, m)| {
            let params: Vec<String> = m
                .params()
                .map(|p| p.name().to_string())
                .filter(|n| !n.is_empty())
                .collect();
            let mut entry = json!({
                "name": m.name(),
                "params": params,
            });
            if slotted {
                entry["slot"] = json!(slot_of(i));
            }
            entry
        })
        .collect()
}

/// One symbol per method of a type, so `wd diff` reports an added, removed or
/// moved API by name rather than as an opaque blob change.
fn method_symbols(ty: &TypeDef<'_>, namespace: &str, name: &str, slotted: bool) -> Vec<Symbol> {
    ty.methods()
        .enumerate()
        .filter(|(_, m)| m.name() != ".ctor")
        .map(|(i, m)| {
            let id = format!("{namespace}.{name}::{}", m.name());
            Symbol {
                mangled: id.clone(),
                demangled: Some(id.clone()),
                id,
                vaddr: 0,
                rva: 0,
                // The slot is the address-equivalent for metadata: it is how you
                // reach the method, and it is what breaks when a type changes.
                ordinal: slotted.then(|| slot_of(i)),
                size: 0,
                procedure_size: None,
                is_code: false,
                forwarder: None,
                body_hash: String::new(),
                exported: true,
                library: false,
                kind: Kind::Method,
                coverage: Coverage::Auto,
                provenance: Provenance::Reflection,
                confidence: Confidence::Certain,
                sig: Signature::default(),
                callers: vec![],
                calls: vec![],
                imports: vec![],
            }
        })
        .collect()
}

/// Read a `.winmd` and write an IR database describing its types.
pub fn winmd_command(path: &Path, out: &Path) -> Result<()> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let sha = crate::hex::lower(&Sha256::digest(&bytes));

    let index = Index::read(path)
        .with_context(|| format!("{} is not readable as ECMA-335 metadata", path.display()))?;

    let mut symbols = Vec::new();
    let mut classes = Vec::new();
    let (mut interfaces, mut runtime_classes, mut enums, mut structs, mut delegates) =
        (0usize, 0usize, 0usize, 0usize, 0usize);

    for ty in index.types() {
        let namespace = ty.namespace();
        let name = ty.name();
        if name == "<Module>" {
            continue;
        }
        let category = ty.category();
        match category {
            TypeCategory::Interface => interfaces += 1,
            TypeCategory::Class => runtime_classes += 1,
            TypeCategory::Enum => enums += 1,
            TypeCategory::Struct => structs += 1,
            TypeCategory::Delegate => delegates += 1,
            TypeCategory::Attribute => {}
        }

        let slotted = matches!(category, TypeCategory::Interface | TypeCategory::Delegate);
        let methods = methods_of(&ty, slotted);

        let required: Vec<String> = ty
            .interface_impls()
            .map(|i| type_name(&i.interface(&[])))
            .collect();

        classes.push(json!({
            "namespace": namespace,
            "name": name,
            "qualified_name": format!("{namespace}.{name}"),
            "category": category_name(&category),
            "methods": methods.len(),
            "interfaces": required,
            "members": methods,
        }));

        symbols.extend(method_symbols(&ty, namespace, name, slotted));
    }

    if classes.is_empty() {
        bail!("{} contained no types", path.display());
    }

    let db = Database {
        schema: 3,
        generated: crate::date_today(),
        tool: "rust: windows-metadata (ECMA-335)".into(),
        binary: BinaryInfo {
            file: path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown.winmd")
                .to_string(),
            sha256: Some(sha),
            image_size: Some(bytes.len() as u64),
            ..Default::default()
        },
        symbols,
        ..Default::default()
    };

    let json = serde_json::to_vec_pretty(&db)?;
    crate::diff::atomic_write(out, &json)?;

    println!(
        "{}: {} types ({} interfaces, {} classes, {} enums, {} structs, {} delegates), \
         {} methods -> {}",
        db.binary.file,
        classes.len(),
        interfaces,
        runtime_classes,
        enums,
        structs,
        delegates,
        db.symbols.len(),
        out.display()
    );
    Ok(())
}
