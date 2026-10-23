//! Modular Rust FFI bindings emitter. Exported functions link via raw-dylib;
//! internal (non-exported) functions resolve by RVA at runtime (ASLR-safe).

use crate::emit;
use crate::model::{ClaimSubject, Database, Kind, TypeText};
use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

const CATEGORIES: &[&str] = &[
    "core",
    "controls",
    "layouts",
    "parsing",
    "animation",
    "accessibility",
    "containers",
    "values",
    "behaviors",
    "utilities",
];

/// Generates a clean, modular Rust FFI crate under `rust/`.
pub fn generate_crate(db: &Database, out_dir: &Path) -> Result<()> {
    anyhow::ensure!(
        db.binary.machine.as_deref() != Some("0x014c"),
        "Rust callable bindings for x86 are disabled until per-symbol calling conventions are fully modeled"
    );
    let target = rust_target(db);
    let (src_dir, class_handles) = prepare_crate(db, out_dir, &target)?;
    let bindings = collect_bindings(db, target.image_base);
    let active_categories =
        write_category_modules(&src_dir, &class_handles, &bindings, &target.link_name)?;
    write_crate_root(
        db,
        &src_dir,
        &class_handles,
        &bindings,
        &active_categories,
        &target,
    )
}

struct RustTarget {
    dll: String,
    link_name: String,
    crate_name: String,
    image_base: u64,
    expected_timestamp: u32,
}

fn rust_target(db: &Database) -> RustTarget {
    let dll = if db.binary.file.is_empty() {
        "unknown.dll"
    } else {
        &db.binary.file
    }
    .to_string();
    let link_name = Path::new(&dll)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(&dll)
        .to_string();
    let crate_name = format!(
        "{}-sys",
        sanitize_ident(&link_name)
            .to_ascii_lowercase()
            .replace('_', "-")
    );
    let image_base = db.binary.image_base.unwrap_or_else(|| {
        db.symbols
            .iter()
            .filter(|s| s.vaddr != 0 && s.rva != 0)
            .map(|s| s.vaddr - u64::from(s.rva))
            .next()
            .unwrap_or_else(|| {
                db.symbols
                    .iter()
                    .filter(|s| s.vaddr != 0)
                    .map(|s| s.vaddr)
                    .min()
                    .map_or(0, |v| v & !0xFFFF)
            })
    });
    let expected_timestamp = db
        .binary
        .timestamp
        .as_deref()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    RustTarget {
        dll,
        link_name,
        crate_name,
        image_base,
        expected_timestamp,
    }
}

fn prepare_crate(
    db: &Database,
    out_dir: &Path,
    target: &RustTarget,
) -> Result<(PathBuf, BTreeSet<String>)> {
    let src_dir = out_dir.join("src");
    if src_dir.exists() {
        let _ = fs::remove_dir_all(&src_dir);
    }
    fs::create_dir_all(&src_dir)?;

    let crate_name = &target.crate_name;
    let dll = &target.dll;
    let cargo_toml = format!(
        r#"[package]
name = "{crate_name}"
version = "0.1.0"
edition = "2021"
description = "Windissect-generated Rust FFI bindings for {dll}. Windows only."
license = "MIT"

[dependencies]
"#
    );
    fs::write(out_dir.join("Cargo.toml"), cargo_toml)?;

    // Opaque class handles.
    let mut class_handles: BTreeSet<String> = BTreeSet::new();
    for s in &db.symbols {
        if s.library || !s.sig.parse_ok {
            continue;
        }
        if let Some(c) = &s.sig.class {
            class_handles.insert(sanitize_ident(&class_ident(s.sig.namespace.as_deref(), c)));
        }
    }
    let mut handles_code = String::from(
        "//! Opaque handles for recovered C++ classes.\n#![allow(non_camel_case_types)]\n\n",
    );
    for h in &class_handles {
        let _ = write!(
            handles_code,
            "#[repr(C)]\npub struct {h} {{ _opaque: [u8; 0] }}\n\n"
        );
    }
    fs::write(src_dir.join("handles.rs"), handles_code)?;
    fs::write(src_dir.join("vtables.rs"), vtable_module(db))?;
    Ok((src_dir, class_handles))
}

struct RustBindings {
    exported: BTreeMap<&'static str, String>,
    internal: BTreeMap<&'static str, String>,
    flat_exported: String,
    flat_internal: String,
}

fn collect_bindings(db: &Database, image_base: u64) -> RustBindings {
    let mut exported: BTreeMap<&'static str, String> =
        CATEGORIES.iter().map(|c| (*c, String::new())).collect();
    let mut internal: BTreeMap<&'static str, String> =
        CATEGORIES.iter().map(|c| (*c, String::new())).collect();
    let mut used: BTreeSet<String> = BTreeSet::new();
    let mut flat_exported = String::new();
    let mut flat_internal = String::new();
    let verified_callable = db.verified_callable_symbol_ids();

    for s in db
        .symbols
        .iter()
        .filter(|symbol| rust_binding_candidate(symbol, &verified_callable))
    {
        let mangled = &s.mangled;
        let Some(rva) = s.vaddr.checked_sub(image_base) else {
            continue;
        };

        let (fn_name, params, ret, cat, structured) = if s.sig.parse_ok {
            let class_name = s
                .sig
                .class
                .as_ref()
                .map(|c| sanitize_ident(&class_ident(s.sig.namespace.as_deref(), c)));
            let method = sanitize_ident(s.sig.method.as_deref().unwrap_or("fn_export"));
            let base = match &class_name {
                Some(c) => format!("{c}_{method}"),
                None => method,
            };
            let mut params: Vec<(String, String)> = Vec::new();
            if let Some(c) = class_name.as_ref().filter(|_| {
                s.sig.storage.as_deref() != Some("static") && !matches!(s.kind, Kind::Ctor)
            }) {
                let m = if s.sig.is_const { "*const" } else { "*mut" };
                params.push(("this".into(), format!("{m} {c}")));
            }
            for (i, p) in s.sig.params.iter().enumerate() {
                params.push((format!("p{i}"), rust_type(Some(p))));
            }
            (
                uniq(&mut used, &base),
                params,
                rust_type(s.sig.ret.as_ref()),
                emit::category_dir(s.sig.class.as_deref().unwrap_or("")),
                true,
            )
        } else {
            continue;
        };
        let _ = structured;

        let decl: String = params
            .iter()
            .map(|(n, t)| format!("{n}: {t}"))
            .collect::<Vec<_>>()
            .join(", ");
        let types: String = params
            .iter()
            .map(|(_, t)| t.clone())
            .collect::<Vec<_>>()
            .join(", ");
        let args: String = params
            .iter()
            .map(|(n, _)| n.clone())
            .collect::<Vec<_>>()
            .join(", ");
        let src = if s.exported {
            "PE Export"
        } else {
            "PDB Internal"
        };
        let abi = s.sig.callconv.as_deref().unwrap_or("unspecified");
        let doc = format!("/// {:?} | {src} | ABI {abi} | {mangled}\n", s.kind);

        if s.exported {
            let block = if cat == "flat" {
                &mut flat_exported
            } else {
                exported.get_mut(cat).unwrap()
            };
            let _ = write!(
                block,
                "    {doc}    #[link_name = \"{mangled}\"]\n    pub fn {fn_name}({decl}) -> {ret};\n\n"
            );
        } else {
            // Not exported: resolve base + RVA at runtime and transmute.
            let block = if cat == "flat" {
                &mut flat_internal
            } else {
                internal.get_mut(cat).unwrap()
            };
            let _ = write!(
                block,
                "{doc}pub unsafe fn {fn_name}({decl}) -> {ret} {{\n    let address = crate::resolve({rva:#x});\n    assert!(!address.is_null(), \"target module is unavailable, mismatched, or RVA is out of bounds\");\n    let f: unsafe extern \"C\" fn({types}) -> {ret} = ::core::mem::transmute(address);\n    f({args})\n}}\n\n"
            );
        }
    }

    RustBindings {
        exported,
        internal,
        flat_exported,
        flat_internal,
    }
}

fn rust_binding_candidate(
    symbol: &crate::model::Symbol,
    verified_callable: &BTreeSet<&str>,
) -> bool {
    !symbol.library
        && verified_callable.contains(symbol.id.as_str())
        && (!symbol.sig.parse_ok || signature_is_rust_abi_safe(&symbol.sig))
}

fn write_category_modules(
    src_dir: &Path,
    class_handles: &BTreeSet<String>,
    bindings: &RustBindings,
    link_name: &str,
) -> Result<Vec<&'static str>> {
    let active_categories: Vec<&str> = CATEGORIES
        .iter()
        .copied()
        .filter(|cat| !bindings.exported[cat].is_empty() || !bindings.internal[cat].is_empty())
        .collect();
    for cat in &active_categories {
        let mut code = format!(
            "//! FFI bindings for `{cat}`.\n#![allow(non_snake_case, non_camel_case_types, dead_code)]\n\n"
        );
        let needs_handles = class_handles.iter().any(|handle| {
            bindings.exported[cat].contains(handle) || bindings.internal[cat].contains(handle)
        });
        if needs_handles {
            code.push_str("use crate::handles::*;\n\n");
        }
        let _ = write!(
            code,
            "#[cfg_attr(target_os = \"windows\", link(name = \"{link_name}\", kind = \"raw-dylib\"))]\nunsafe extern \"C\" {{\n"
        );
        code.push_str(&bindings.exported[cat]);
        code.push_str("}\n\n");
        code.push_str(&bindings.internal[cat]);
        fs::write(src_dir.join(format!("{cat}.rs")), code)?;
    }

    Ok(active_categories)
}

fn write_crate_root(
    db: &Database,
    src_dir: &Path,
    class_handles: &BTreeSet<String>,
    bindings: &RustBindings,
    active_categories: &[&str],
    target: &RustTarget,
) -> Result<()> {
    let dll = &target.dll;
    let link_name = &target.link_name;
    let mut lib = String::from(&format!(
        "//! Windissect-generated Rust FFI bindings for {dll}. Windows only.\n#![allow(non_snake_case, non_camel_case_types, dead_code)]\n\npub mod handles;\npub mod vtables;\n"
    ));
    for cat in active_categories {
        let _ = writeln!(lib, "pub mod {cat};");
    }
    if !class_handles.is_empty() {
        lib.push_str("\npub use handles::*;\n");
    }
    lib.push('\n');
    let _ = write!(
        lib,
        "pub const EXPECTED_PDB_GUID: &str = {:?};\npub const EXPECTED_PDB_AGE: u32 = {};\npub const EXPECTED_PE_TIMESTAMP: u32 = {};\n\n",
        db.binary.pdb_guid.as_deref().unwrap_or("unknown"),
        db.binary.pdb_age.unwrap_or(0),
        target.expected_timestamp,
    );
    lib.push_str(&resolver(dll, target.expected_timestamp));
    if !bindings.flat_exported.is_empty() {
        let _ = write!(
            lib,
            "\n// Flat C exports (signatures unknown; verify before calling).\n#[cfg_attr(target_os = \"windows\", link(name = \"{link_name}\", kind = \"raw-dylib\"))]\nunsafe extern \"C\" {{\n"
        );
        lib.push_str(&bindings.flat_exported);
        lib.push_str("}\n\n");
    }
    lib.push_str(&bindings.flat_internal);
    fs::write(src_dir.join("lib.rs"), lib)?;
    Ok(())
}

fn vtable_module(db: &Database) -> String {
    let mut out = String::from(
        "//! Evidence-labelled vftable metadata and raw slot access.\n\
         //! Slot calls remain the consumer's responsibility until a signature is unique.\n\n\
         use core::ffi::c_void;\n\n\
         #[derive(Clone, Copy, Debug)]\n\
         pub struct VTableInfo { pub name: &'static str, pub rva: u32, pub first_slot: usize, pub slot_count: usize, pub confidence: &'static str }\n\n\
         #[derive(Clone, Copy, Debug)]\n\
         pub struct VTableSlot { pub table_rva: u32, pub slot: u32, pub byte_offset: u32, pub target_rva: u32, pub target_id: Option<&'static str>, pub target_name: Option<&'static str>, pub ambiguous: bool, pub this_adjustment: Option<i32> }\n\n",
    );
    emit_vtable_infos(db, &mut out);
    emit_vtable_slots(db, &mut out);
    out.push_str(
        "];\n\n\
         /// Reads a raw function pointer from an object's primary vftable.\n\
         ///\n\
         /// # Safety\n\
         /// `object` must point to a live object with a readable primary vftable,\n\
         /// and `slot` must be valid for that concrete object. This function does\n\
         /// not invent or transmute a callable signature.\n\
         pub unsafe fn raw_object_slot(object: *const c_void, slot: usize) -> Option<*const ()> {\n\
             if object.is_null() { return None; }\n\
             let table = unsafe { *(object.cast::<*const *const ()>()) };\n\
             if table.is_null() { return None; }\n\
             let target = unsafe { *table.add(slot) };\n\
             (!target.is_null()).then_some(target)\n\
         }\n",
    );
    emit_vtable_wrappers(db, &mut out);
    out
}

fn emit_vtable_infos(db: &Database, out: &mut String) {
    let mut first_slot = 0usize;
    out.push_str("pub static VTABLES: &[VTableInfo] = &[\n");
    for table in &db.vtables {
        let name = table
            .get("demangled")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let rva = table
            .get("rva")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let count = table
            .get("entries")
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len);
        let confidence = table
            .get("confidence")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let _ = writeln!(
            out,
            "    VTableInfo {{ name: {name:?}, rva: 0x{rva:X}, first_slot: {first_slot}, slot_count: {count}, confidence: {confidence:?} }},"
        );
        first_slot += count;
    }
    out.push_str("];\n\n");
}

fn emit_vtable_slots(db: &Database, out: &mut String) {
    out.push_str("pub static VTABLE_SLOTS: &[VTableSlot] = &[\n");
    for table in &db.vtables {
        let table_rva = table
            .get("rva")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        for entry in table
            .get("entries")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            let slot = entry
                .get("slot")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let byte_offset = entry
                .get("byte_offset")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let target_rva = entry
                .get("target_rva")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let id = entry
                .get("target_id")
                .and_then(serde_json::Value::as_str)
                .map_or_else(|| "None".to_string(), |s| format!("Some({s:?})"));
            let name = entry
                .get("target_name")
                .and_then(serde_json::Value::as_str)
                .map_or_else(|| "None".to_string(), |s| format!("Some({s:?})"));
            let ambiguous = entry
                .get("target_ambiguous")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true);
            let adjustment = entry
                .get("this_adjustment")
                .and_then(serde_json::Value::as_i64)
                .map_or_else(|| "None".to_string(), |n| format!("Some({n})"));
            let _ = writeln!(
                out,
                "    VTableSlot {{ table_rva: 0x{table_rva:X}, slot: {slot}, byte_offset: {byte_offset}, target_rva: 0x{target_rva:X}, target_id: {id}, target_name: {name}, ambiguous: {ambiguous}, this_adjustment: {adjustment} }},"
            );
        }
    }
}

fn emit_vtable_wrappers(db: &Database, out: &mut String) {
    let symbols: BTreeMap<&str, &crate::model::Symbol> = db
        .symbols
        .iter()
        .map(|symbol| (symbol.id.as_str(), symbol))
        .collect();
    let verified_callable = db.verified_callable_symbol_ids();
    let proven_claims = db.proven_claim_ids();
    let verified_slots: BTreeSet<VerifiedVtableSlot<'_>> = db
        .claims
        .iter()
        .filter(|claim| proven_claims.contains(claim.id.as_str()))
        .filter_map(|claim| match &claim.subject {
            ClaimSubject::VtableSlot {
                owner,
                table_rva,
                table_object_offset,
                slot,
                target_rva,
            } => Some((
                owner.as_str(),
                *table_rva,
                *table_object_offset,
                *slot,
                *target_rva,
            )),
            _ => None,
        })
        .collect();
    let mut wrapper_names = BTreeSet::new();
    for table in &db.vtables {
        emit_rust_vtable_wrappers(
            table,
            &symbols,
            &verified_callable,
            &verified_slots,
            &mut wrapper_names,
            out,
        );
    }
}

fn emit_rust_vtable_wrappers(
    table: &serde_json::Value,
    symbols: &BTreeMap<&str, &crate::model::Symbol>,
    verified_callable: &BTreeSet<&str>,
    verified_slots: &BTreeSet<VerifiedVtableSlot<'_>>,
    wrapper_names: &mut BTreeSet<String>,
    out: &mut String,
) {
    let table_rva = table
        .get("rva")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(0);
    let claim_owner = table
        .get("demangled")
        .and_then(serde_json::Value::as_str)
        .and_then(vftable_owner)
        .or_else(|| table.get("class_name").and_then(serde_json::Value::as_str))
        .unwrap_or("unknown");
    let owner = sanitize_ident(claim_owner);
    let context = RustVcallContext {
        symbols,
        verified_callable,
        verified_slots,
        table_rva,
        claim_owner,
        owner: &owner,
    };
    for entry in table
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        emit_rust_vcall(entry, &context, wrapper_names, out);
    }
}

fn emit_rust_vcall(
    entry: &serde_json::Value,
    context: &RustVcallContext<'_>,
    wrapper_names: &mut BTreeSet<String>,
    out: &mut String,
) {
    let symbols = context.symbols;
    let table_rva = context.table_rva;
    let claim_owner = context.claim_owner;
    let owner = context.owner;
    let identity_ambiguous = entry
        .get("target_ambiguous")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let signature_compatible = entry
        .get("signature_compatible")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if identity_ambiguous && !signature_compatible {
        return;
    }
    let Some(id) = entry
        .get("target_id")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            entry
                .get("signature_source_id")
                .and_then(serde_json::Value::as_str)
        })
    else {
        return;
    };
    let Some(symbol) = symbols.get(id).copied().filter(|s| s.sig.parse_ok) else {
        return;
    };
    if !signature_is_rust_abi_safe(&symbol.sig) {
        return;
    }
    let slot = entry
        .get("slot")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(0);
    let target_rva = entry
        .get("target_rva")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(0);
    if !context
        .verified_slots
        .contains(&(claim_owner, table_rva, None, slot, target_rva))
        || !context.verified_callable.contains(symbol.id.as_str())
    {
        return;
    }
    let method = if identity_ambiguous {
        "abi_equivalent".to_string()
    } else {
        sanitize_ident(symbol.sig.method.as_deref().unwrap_or("virtual"))
    };
    let wrapper = uniq(wrapper_names, &format!("{owner}_vslot_{slot}_{method}"));
    let this_ty = if symbol.sig.is_const {
        "*const c_void"
    } else {
        "*mut c_void"
    };
    let params: Vec<_> = symbol
        .sig
        .params
        .iter()
        .enumerate()
        .map(|(index, ty)| (format!("p{index}"), rust_type(Some(ty))))
        .collect();
    let decl = params
        .iter()
        .map(|(name, ty)| format!("{name}: {ty}"))
        .collect::<Vec<_>>()
        .join(", ");
    let param_types = params
        .iter()
        .map(|(_, ty)| ty.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let args = params
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let ret = rust_type(symbol.sig.ret.as_ref());
    let comma_decl = comma_prefix(&decl);
    let comma_types = comma_prefix(&param_types);
    let comma_args = comma_prefix(&args);
    let _ = write!(
        out,
        "\n/// Slot {slot}: {}\n/// Identity ambiguity: {identity_ambiguous}; ABI-equivalent candidates: {signature_compatible}.\n///\n/// # Safety\n/// `this` must be a live instance using the expected vftable and all arguments must satisfy the private ABI.\n#[inline]\npub unsafe fn {wrapper}(this: {this_ty}{comma_decl}) -> {ret} {{\n    let target = unsafe {{ raw_object_slot(this.cast(), {slot}) }}.expect(\"null object or vftable slot\");\n    let function: unsafe extern \"C\" fn({this_ty}{comma_types}) -> {ret} = unsafe {{ core::mem::transmute(target) }};\n    unsafe {{ function(this{comma_args}) }}\n}}\n",
        if identity_ambiguous {
            "multiple names share this proven ABI signature"
        } else {
            symbol.demangled.as_deref().unwrap_or(id)
        }
    );
}

fn comma_prefix(value: &str) -> String {
    if value.is_empty() {
        String::new()
    } else {
        format!(", {value}")
    }
}

type VerifiedVtableSlot<'a> = (&'a str, u32, Option<i64>, u32, u32);

struct RustVcallContext<'a> {
    symbols: &'a BTreeMap<&'a str, &'a crate::model::Symbol>,
    verified_callable: &'a BTreeSet<&'a str>,
    verified_slots: &'a BTreeSet<VerifiedVtableSlot<'a>>,
    table_rva: u32,
    claim_owner: &'a str,
    owner: &'a str,
}

fn vftable_owner(name: &str) -> Option<&str> {
    crate::rtti::vftable_owner_name(name)
}

/// Runtime resolver for non-exported functions. ASLR randomizes only the base;
/// the module base is resolved once and combined with a bounds-checked RVA.
fn resolver(dll: &str, timestamp: u32) -> String {
    let wide = dll
        .encode_utf16()
        .chain(std::iter::once(0))
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let len = dll.encode_utf16().count() + 1;
    r#"// --- internal-function resolver (ASLR-safe: live base + fixed RVA) ---
#[cfg(target_os = "windows")]
mod resolver {
    use core::sync::atomic::{AtomicUsize, Ordering};
    static BASE: AtomicUsize = AtomicUsize::new(0);
    #[link(name = "kernel32", kind = "raw-dylib")]
    unsafe extern "system" {
        fn GetModuleHandleW(name: *const u16) -> usize;
    }
    pub fn base() -> usize {
        let b = BASE.load(Ordering::Relaxed);
        if b != 0 {
            return b;
        }
        let name: [u16; __LEN__] = [__WIDE__];
        let h = unsafe { GetModuleHandleW(name.as_ptr()) };
        if h == 0 { return 0; }
        // IMAGE_DOS_HEADER.e_lfanew -> IMAGE_NT_HEADERS.FileHeader.TimeDateStamp.
        let pe_offset = unsafe { core::ptr::read_unaligned((h + 0x3c) as *const u32) } as usize;
        let live_timestamp = unsafe { core::ptr::read_unaligned((h + pe_offset + 8) as *const u32) };
        if live_timestamp != __TIMESTAMP__ { return 0; }
        BASE.store(h, Ordering::Relaxed);
        h
    }
}
#[cfg(not(target_os = "windows"))]
mod resolver {
    pub fn base() -> usize { 0 }
}

/// Absolute address of an internal function from its RVA. Requires the target
/// module to be loaded in the current process.
#[inline]
pub fn resolve(rva: usize) -> *const () {
    let base = resolver::base();
    if base == 0 { return ::core::ptr::null(); }
    let pe_offset = unsafe { ::core::ptr::read_unaligned((base + 0x3c) as *const u32) } as usize;
    let image_size = unsafe { ::core::ptr::read_unaligned((base + pe_offset + 80) as *const u32) } as usize;
    if rva >= image_size { return ::core::ptr::null(); }
    base.checked_add(rva).map_or(::core::ptr::null(), |address| address as *const ())
}
"#
    .replace("__LEN__", &len.to_string())
    .replace("__WIDE__", &wide)
    .replace("__TIMESTAMP__", &timestamp.to_string())
}

fn class_ident(ns: Option<&str>, class: &str) -> String {
    match ns {
        Some(ns) if !ns.is_empty() => format!("{}_{}", ns.replace("::", "_"), class),
        _ => class.to_string(),
    }
}

fn uniq(used: &mut BTreeSet<String>, base: &str) -> String {
    let mut name = base.to_string();
    let mut i = 1;
    while used.contains(&name) {
        i += 1;
        name = format!("{base}_{i}");
    }
    used.insert(name.clone());
    name
}

fn sanitize_ident(s: &str) -> String {
    let clean: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let clean = clean.trim_matches('_');
    if clean.is_empty() {
        return "anon".to_string();
    }
    let mut out = String::new();
    if clean.chars().next().unwrap().is_ascii_digit() {
        out.push('_');
    }
    out.push_str(clean);
    match out.as_str() {
        "type" | "ref" | "mod" | "match" | "fn" | "use" | "pub" | "in" | "override" | "virtual"
        | "crate" | "self" | "Self" | "super" | "const" | "static" | "struct" | "enum"
        | "union" | "impl" | "trait" | "where" | "for" | "loop" | "while" | "if" | "else"
        | "return" | "break" | "continue" | "as" | "unsafe" | "extern" | "move" | "dyn" | "box"
        | "async" => {
            format!("{out}_")
        }
        _ => out,
    }
}

fn rust_type(t: Option<&TypeText>) -> String {
    let Some(t) = t else { return "()".to_string() };
    let text = t.text.as_str();
    if text.contains('*') || text.contains('&') {
        return "*mut ::core::ffi::c_void".to_string();
    }
    match text.trim() {
        "void" => "()".to_string(),
        "bool" => "bool".to_string(),
        "char" | "signed char" => "i8".to_string(),
        "unsigned char" => "u8".to_string(),
        "short" | "__int16" => "i16".to_string(),
        "unsigned short" | "wchar_t" | "__wchar_t" => "u16".to_string(),
        "int" | "long" | "__int32" | "signed long" | "signed int" => "i32".to_string(),
        "unsigned" | "unsigned int" | "unsigned long" => "u32".to_string(),
        "__int64" | "long long" | "signed long long" => "i64".to_string(),
        "unsigned __int64" | "unsigned long long" => "u64".to_string(),
        "float" => "f32".to_string(),
        "double" => "f64".to_string(),
        _ => "*mut ::core::ffi::c_void".to_string(),
    }
}

fn signature_is_rust_abi_safe(signature: &crate::model::Signature) -> bool {
    rust_abi_type(signature.ret.as_ref()).is_some()
        && signature
            .params
            .iter()
            .all(|parameter| rust_abi_type(Some(parameter)).is_some())
}

fn rust_abi_type(t: Option<&TypeText>) -> Option<String> {
    let Some(t) = t else {
        return Some("()".to_string());
    };
    let text = t.text.as_str();
    if text.contains('*') || text.contains('&') {
        return Some("*mut ::core::ffi::c_void".to_string());
    }
    match text.trim() {
        "void" => Some("()".to_string()),
        "bool" => Some("bool".to_string()),
        "char" | "signed char" => Some("i8".to_string()),
        "unsigned char" => Some("u8".to_string()),
        "short" | "__int16" => Some("i16".to_string()),
        "unsigned short" | "wchar_t" | "__wchar_t" => Some("u16".to_string()),
        "int" | "long" | "__int32" | "signed long" | "signed int" => Some("i32".to_string()),
        "unsigned" | "unsigned int" | "unsigned long" => Some("u32".to_string()),
        "__int64" | "long long" | "signed long long" => Some("i64".to_string()),
        "unsigned __int64" | "unsigned long long" => Some("u64".to_string()),
        "float" => Some("f32".to_string()),
        "double" => Some("f64".to_string()),
        _ => None,
    }
}
