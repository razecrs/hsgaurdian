//! Exhaustive, evidence-preserving inventory mode.
//!
//! Progressive mode deliberately records observations and coverage gaps. It does
//! not promote candidates or treat an external corpus as proof.

use crate::model::Database;
use anyhow::Result;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
struct Inventory {
    schema: u32,
    target: String,
    binary_sha256: Option<String>,
    pdb_present: bool,
    symbols: usize,
    functions: usize,
    exports: usize,
    classes: usize,
    enums: usize,
    claims: usize,
    evidence: usize,
    observations: usize,
    call_edges: usize,
    vtables: usize,
    reflection_claims: usize,
    candidates: usize,
    verified_claims: usize,
    pdb_records: usize,
    stages: Vec<&'static str>,
    ir: String,
    coverage: BTreeMap<&'static str, &'static str>,
}

pub fn run(dll: &Path, pdb: Option<&Path>, out: &Path, existing_ir: Option<&Path>) -> Result<()> {
    let (db, ir_path): (Database, PathBuf) = if let Some(path) = existing_ir {
        (
            serde_json::from_slice(&std::fs::read(path)?)?,
            path.to_path_buf(),
        )
    } else {
        std::fs::create_dir_all(out)?;
        let ir_path = out.join("inventory.ir.json");
        crate::extract_to(dll, &ir_path, pdb, true)?;
        (serde_json::from_slice(&std::fs::read(&ir_path)?)?, ir_path)
    };
    let verified_claims = db
        .claims
        .iter()
        .filter(|claim| matches!(claim.usability, crate::model::Usability::Verified))
        .count();
    let inventory = Inventory {
        schema: db.schema,
        target: db.binary.file.clone(),
        binary_sha256: db.binary.sha256.clone(),
        pdb_present: pdb.is_some() || db.type_recovery.get("status").is_none(),
        symbols: db.symbols.len(),
        functions: db.functions.len(),
        exports: db.symbols.iter().filter(|s| s.exported).count(),
        classes: db.classes.len(),
        enums: db.enums.len(),
        claims: db.claims.len(),
        evidence: db.evidence.len(),
        observations: db.evidence.len(),
        call_edges: db.symbols.iter().map(|s| s.calls.len()).sum(),
        vtables: db.vtables.len(),
        reflection_claims: db.properties.len(),
        candidates: db
            .claims
            .iter()
            .filter(|claim| matches!(claim.usability, crate::model::Usability::MetadataOnly))
            .count(),
        verified_claims,
        pdb_records: db.pdb_records.len(),
        stages: vec![
            "pe-identity",
            "sections-exports-imports",
            "pdb-symbols-and-types",
            "instruction-enrichment",
            "rtti-vtables",
            "layout-observations",
            "reflection-observations",
            "evidence-inventory",
        ],
        ir: ir_path.display().to_string(),
        coverage: coverage(&db),
    };
    let report = out.join("inventory.json");
    std::fs::write(&report, serde_json::to_vec_pretty(&inventory)?)?;
    println!(
        "pgressive inventory: {} -> {}",
        inventory.target,
        report.display()
    );
    Ok(())
}

fn coverage(db: &Database) -> BTreeMap<&'static str, &'static str> {
    let mut c = BTreeMap::new();
    c.insert("guid_age_signature_toolchain_build_identity", "collected");
    c.insert(
        "public_private_symbols",
        if db.symbols.is_empty() {
            "empty"
        } else {
            "collected"
        },
    );
    c.insert("section_contributions_module_ownership", "partial");
    c.insert("public_global_symbol_hash_tables", "not-yet-modeled");
    c.insert("local_variables_names", "not-yet-modeled");
    c.insert("lexical_scopes_block_nesting", "not-yet-modeled");
    c.insert("register_stack_locations", "not-yet-modeled");
    c.insert("inline_sites_call_trees", "not-yet-modeled");
    c.insert("caller_callee_line_mappings", "partial");
    c.insert("call_site_parameter_annotations", "not-yet-modeled");
    c.insert("compiler_generated_names_lambdas", "partial");
    c.insert("template_instantiations_specializations", "partial");
    c.insert("type_server_shared_type_records", "not-yet-modeled");
    c.insert("forward_declarations_type_index_graphs", "partial");
    c.insert("bitfields_packing_metadata", "partial");
    c.insert("virtual_base_virtual_function_shape", "partial");
    c.insert("static_data_tls_symbols", "partial");
    c.insert("source_checksums_original_paths", "not-yet-modeled");
    c.insert("embedded_source_source_server_metadata", "not-yet-modeled");
    c.insert("edit_and_continue_records", "not-yet-modeled");
    c.insert("frame_pointer_omission_unwind_data", "partial");
    c.insert("exception_handler_scope_tables", "not-yet-modeled");
    c.insert("omap_address_mappings", "partial");
    c.insert("linker_dia_build_metadata", "partial");
    c.insert("imported_types_other_pdbs", "not-yet-modeled");
    c.insert("pgo_profile_records", "not-yet-modeled");
    c.insert("codeview_annotations_instrumentation", "not-yet-modeled");
    c.insert("resource_compiler_generated_symbols", "partial");
    c.insert("managed_clr_metadata", "not-yet-modeled");
    c.insert("incremental_link_information", "not-yet-modeled");
    if let Some(streams) = db
        .type_recovery
        .get("pdb_stream_coverage")
        .or_else(|| db.type_recovery.get("coverage"))
    {
        let count = |name: &str| {
            streams
                .get(name)
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
        };
        if count("locals") > 0 {
            c.insert("local_variables_names", "collected");
            c.insert("register_stack_locations", "collected");
        }
        if count("blocks") > 0 {
            c.insert("lexical_scopes_block_nesting", "collected");
        }
        if count("inline_sites") > 0 {
            c.insert("inline_sites_call_trees", "collected");
        }
        if count("thunks") > 0 {
            c.insert("virtual_base_virtual_function_shape", "collected");
        }
        if count("data_symbols") > 0 || count("tls_symbols") > 0 {
            c.insert("static_data_tls_symbols", "collected");
        }
        if count("constants") > 0 {
            c.insert("resource_compiler_generated_symbols", "partial");
        }
        if count("build_info") > 0 {
            c.insert("linker_dia_build_metadata", "collected");
        }
        if count("annotations") > 0 {
            c.insert("codeview_annotations_instrumentation", "collected");
        }
    }
    c
}
