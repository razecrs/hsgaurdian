//! Windissect: target-independent Windows PE/PDB dissection pipeline.

mod archive;
mod demangle;
mod descent;
mod diff;
mod docs;
mod emit;
mod emit_asm;
mod emit_evidence;
mod emit_rust;
mod emit_syms;
mod enrich;
mod evidencepack;
mod extract;
mod hex;
mod history;
mod layoutinfer;
mod model;
mod oracle;
mod pdbsym;
mod pdbtype;
mod pgressive;
mod recovery_plan;
mod refine;
mod reflection;
mod rtti;
mod semantic;
mod semantic_emit;
mod semantic_probe;
mod semantic_score;
mod semantic_validate;
mod typeparse;
mod verify;
mod winmd;

use anyhow::Result;
use clap::{Parser, Subcommand};
use model::{Capability, CapabilityStatus, Database, Provenance, SCHEMA_VERSION};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Parser)]
#[command(about = "Dissect Windows PE binaries and matching PDBs into trustworthy IR and bindings")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Extract exports + PDB internals, demangle + structure, write the IR.
    Extract {
        dll: PathBuf,
        #[arg(short, long, default_value = "ir/symbols.json")]
        out: PathBuf,
        /// PDB for internal names; used if present.
        #[arg(long)]
        pdb: Option<PathBuf>,
        /// Exhaustively inventory PE/PDB observations before promotion.
        #[arg(long)]
        pgressive: bool,
    },
    /// Exhaustively collect PE/PDB observations and write a resumable inventory.
    Pgressive {
        dll: PathBuf,
        #[arg(long)]
        pdb: Option<PathBuf>,
        #[arg(short, long, default_value = "pgressive")]
        out: PathBuf,
        /// Reuse an existing IR instead of re-running extraction.
        #[arg(long)]
        ir: Option<PathBuf>,
    },
    /// Extract `WinRT` type metadata from a .winmd into the IR.
    Winmd {
        /// Path to the .winmd file.
        winmd: PathBuf,
        #[arg(short, long, default_value = "ir/winmd.json")]
        out: PathBuf,
    },
    /// Build a module dependency graph from a set of IR databases.
    Deps {
        /// IR files, or directories containing them.
        #[arg(required = true)]
        ir: Vec<PathBuf>,
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Descend into subdirectories.
        #[arg(short, long)]
        recursive: bool,
    },
    /// Report where each binary's PDB lives on a symbol server.
    Symbols {
        /// Binaries, or directories of them.
        #[arg(required = true)]
        files: Vec<PathBuf>,
        #[arg(long, default_value = "https://msdl.microsoft.com/download/symbols")]
        server: String,
        /// Emit JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Build a corpus manifest from directories of binaries.
    Manifest {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Tag every target with an area name.
        #[arg(long, default_value = "")]
        area: String,
        #[arg(short, long)]
        recursive: bool,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Summarise an archive history tree: every module, every build.
    Catalog {
        #[arg(default_value = "history")]
        history: PathBuf,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Emit a reconstructed C++ header for a single class.
    EmitCpp {
        /// e.g. `DirectUI::Element`
        qualified: String,
        #[arg(short, long, default_value = "ir/symbols.json")]
        ir: PathBuf,
    },
    /// Emit C++ header files for all classes into headers/.
    EmitHeaders {
        #[arg(short, long, default_value = "headers")]
        out: PathBuf,
        #[arg(short, long, default_value = "ir/symbols.json")]
        ir: PathBuf,
    },
    /// Emit buildable Rust FFI crate into rust/.
    EmitRust {
        #[arg(short, long, default_value = "rust")]
        out: PathBuf,
        #[arg(short, long, default_value = "ir/symbols.json")]
        ir: PathBuf,
    },
    /// Emit a plain C23 symbol table (mangled name -> RVA) for runtime resolution.
    EmitSyms {
        #[arg(short, long, default_value = "syms")]
        out: PathBuf,
        #[arg(short, long, default_value = "ir/symbols.json")]
        ir: PathBuf,
        /// Symbol table stem name (defaults to the IR filename stem).
        #[arg(long)]
        name: Option<String>,
        /// PE image base for RVA math (verified against the binary).
        #[arg(long)]
        base: Option<u64>,
    },
    /// Emit strict verified claims separately from evidence-only candidates.
    EmitEvidence {
        #[arg(short, long, default_value = "evidence")]
        out: PathBuf,
        #[arg(short, long, default_value = "ir/symbols.json")]
        ir: PathBuf,
    },
    /// Emit annotated native-syntax assembly from canonical instruction IR.
    EmitAsm {
        #[arg(short, long, default_value = "disassembly.asm")]
        out: PathBuf,
        #[arg(short, long, default_value = "ir/symbols.json")]
        ir: PathBuf,
    },
    /// List the classes in the IR by member count.
    Classes {
        #[arg(short, long, default_value = "ir/symbols.json")]
        ir: PathBuf,
    },
    /// Validate the IR against invariants + ground-truth spot checks.
    Verify {
        #[arg(short, long, default_value = "ir/symbols.json")]
        ir: PathBuf,
        /// Optional target-specific golden checks (currently: dui70).
        #[arg(long)]
        profile: Option<String>,
    },
    /// Generate codebase and API markdown documentation (like Doxygen).
    Doc {
        #[arg(short, long, default_value = "docs")]
        out: PathBuf,
        #[arg(short, long, default_value = "ir/symbols.json")]
        ir: PathBuf,
    },
    /// Compare two IR databases and report Windows build changes.
    Diff {
        old: PathBuf,
        new: PathBuf,
        /// JSON report path. Prints JSON to stdout when omitted.
        #[arg(long)]
        json_out: Option<PathBuf>,
        /// Optional human-readable Markdown report path.
        #[arg(long)]
        markdown_out: Option<PathBuf>,
    },
    /// Store an IR in the per-target build archive and diff it from the previous build.
    RecordBuild {
        ir: PathBuf,
        #[arg(long, default_value = "history")]
        history: PathBuf,
    },
    /// Validate a manual evidence corpus used to gate an automated rule.
    ValidateEvidencePack { pack: PathBuf },
    /// Import normalized IDA/r2 observations into an IR proof graph.
    ImportOracle {
        ir: PathBuf,
        oracle: PathBuf,
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Compare generated declarations with a reference corpus without trusting it as proof.
    Refine {
        #[arg(short, long, default_value = "ir/symbols.json")]
        ir: PathBuf,
        /// Directory containing reference .h/.hpp files.
        #[arg(long)]
        reference: Option<PathBuf>,
        /// Build a proof-gated semantic class/interface/enum projection.
        #[arg(long)]
        semantic: bool,
        /// Exact PE input required by --semantic.
        #[arg(long)]
        binary: Option<PathBuf>,
        /// Matching PDB for future semantic passes; identity remains anchored by the IR.
        #[arg(long)]
        pdb: Option<PathBuf>,
        /// Separate verified/candidate semantic output root.
        #[arg(long, default_value = "semantic")]
        semantic_out: PathBuf,
        /// Explicit exact-build proof-gated runtime probe manifest. Windissect
        /// never executes discovered functions automatically.
        #[arg(long)]
        probe_manifest: Option<PathBuf>,
        /// Optional exact-build manual layout evidence corpus.
        #[arg(long)]
        manual_layout: Option<PathBuf>,
        #[arg(short, long, default_value = "refinement/report.json")]
        out: PathBuf,
        /// Optional refined IR containing generic rule recoveries.
        #[arg(long)]
        out_ir: Option<PathBuf>,
    },
    /// Score verified semantic facts against an exact-build owned oracle.
    ScoreSemantic {
        #[arg(short, long)]
        ir: PathBuf,
        #[arg(long)]
        oracle: PathBuf,
        #[arg(long, default_value_t = 0.999)]
        precision_threshold: f64,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    #[command(hide = true)]
    SemanticProbeHelper {
        #[arg(long)]
        binary: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Extract {
            dll,
            out,
            pdb,
            pgressive,
        } => {
            if pgressive {
                pgressive::run(&dll, pdb.as_deref(), &out, None)
            } else {
                extract_to(&dll, &out, pdb.as_deref(), false)
            }
        }
        Cmd::Pgressive { dll, pdb, out, ir } => {
            pgressive::run(&dll, pdb.as_deref(), &out, ir.as_deref())
        }
        Cmd::EmitCpp { qualified, ir } => emit_cpp(&qualified, &ir),
        Cmd::EmitHeaders { out, ir } => emit_headers_command(&ir, &out),
        Cmd::EmitRust { out, ir } => emit_rust_command(&ir, &out),
        Cmd::EmitSyms {
            out,
            ir,
            name,
            base,
        } => emit_syms_command(&ir, &out, name, base),
        Cmd::EmitEvidence { out, ir } => emit_evidence_command(&ir, &out),
        Cmd::EmitAsm { out, ir } => emit_asm_command(&ir, &out),
        Cmd::Winmd { winmd: path, out } => winmd::winmd_command(&path, &out),
        Cmd::Deps { ir, out, recursive } => archive::deps_command(&ir, out.as_deref(), recursive),
        Cmd::Symbols {
            files,
            server,
            json,
        } => archive::symbols_command(&files, &server, json),
        Cmd::Manifest {
            paths,
            area,
            recursive,
            out,
        } => archive::manifest_command(&paths, &area, recursive, out.as_deref()),
        Cmd::Catalog { history, out } => archive::catalog_command(&history, out.as_deref()),
        Cmd::Classes { ir } => list_classes(&ir),
        Cmd::Verify { ir, profile } => verify_command(&ir, profile.as_deref()),
        Cmd::Doc { out, ir } => doc_command(&ir, &out),
        Cmd::Diff {
            old,
            new,
            json_out,
            markdown_out,
        } => diff_command(&old, &new, json_out.as_deref(), markdown_out.as_deref()),
        Cmd::RecordBuild { ir, history: root } => record_build_command(&ir, &root),
        Cmd::ValidateEvidencePack { pack } => validate_pack_command(&pack),
        Cmd::ImportOracle {
            ir,
            oracle: input,
            out,
        } => import_oracle_command(&ir, &input, &out),
        Cmd::Refine {
            ir,
            reference,
            semantic: semantic_mode,
            binary,
            pdb,
            semantic_out,
            probe_manifest,
            manual_layout,
            out,
            out_ir,
        } => refine_command(RefineOptions {
            ir,
            reference,
            semantic_mode,
            binary,
            pdb,
            semantic_out,
            probe_manifest,
            manual_layout,
            out,
            out_ir,
        }),
        Cmd::SemanticProbeHelper {
            binary,
            manifest,
            out,
        } => semantic_probe::helper(&binary, &manifest, &out),
        Cmd::ScoreSemantic {
            ir,
            oracle,
            precision_threshold,
            out,
        } => score_semantic_command(&ir, &oracle, precision_threshold, out.as_deref()),
    }
}

fn emit_headers_command(ir: &Path, out: &Path) -> Result<()> {
    let count = emit::emit_all_headers(&load_ir(ir)?, out)?;
    println!("wrote {count} C++ class headers to {}/", out.display());
    Ok(())
}

fn emit_rust_command(ir: &Path, out: &Path) -> Result<()> {
    emit_rust::generate_crate(&load_ir(ir)?, out)?;
    println!("wrote Rust FFI bindings crate to {}/", out.display());
    Ok(())
}

fn emit_syms_command(ir: &Path, out: &Path, name: Option<String>, base: Option<u64>) -> Result<()> {
    let db = load_ir(ir)?;
    let stem = name.unwrap_or_else(|| {
        ir.file_stem().map_or_else(
            || "syms".into(),
            |value| value.to_string_lossy().into_owned(),
        )
    });
    emit_syms::emit_syms(&db, &stem, out, base.or(db.binary.image_base).unwrap_or(0))
}

fn emit_evidence_command(ir: &Path, out: &Path) -> Result<()> {
    emit_evidence::emit(&load_ir(ir)?, out)?;
    println!("wrote strict evidence surfaces to {}/", out.display());
    Ok(())
}

fn emit_asm_command(ir: &Path, out: &Path) -> Result<()> {
    emit_asm::emit(&load_ir(ir)?, out)?;
    println!("wrote annotated assembly to {}", out.display());
    Ok(())
}

fn verify_command(ir: &Path, profile: Option<&str>) -> Result<()> {
    if !verify::run_profile(&load_ir(ir)?, profile) {
        std::process::exit(1);
    }
    Ok(())
}

fn doc_command(ir: &Path, out: &Path) -> Result<()> {
    docs::generate_all(Some(&load_ir(ir)?), out)?;
    println!("generated documentation in {}/", out.display());
    Ok(())
}

fn diff_command(
    old: &Path,
    new: &Path,
    json_out: Option<&Path>,
    markdown_out: Option<&Path>,
) -> Result<()> {
    let old_db = load_ir(old)?;
    let new_db = load_ir(new)?;
    anyhow::ensure!(
        old_db.binary.file.eq_ignore_ascii_case(&new_db.binary.file),
        "cannot diff different targets: {} vs {}",
        old_db.binary.file,
        new_db.binary.file
    );
    let report = diff::compare(&old_db, &new_db);
    if let Some(path) = json_out {
        diff::write_json(&report, path)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }
    if let Some(path) = markdown_out {
        diff::write_markdown(&report, path)?;
    }
    Ok(())
}

fn record_build_command(ir: &Path, root: &Path) -> Result<()> {
    let result = history::record(&load_ir(ir)?, root, Some(ir))?;
    let previous = result
        .previous
        .as_ref()
        .map(|value| format!(" (changes from {value})"))
        .unwrap_or_default();
    println!(
        "recorded {} build {}{} in {}",
        result.target,
        result.key,
        previous,
        result.directory.display()
    );
    Ok(())
}

fn validate_pack_command(pack: &Path) -> Result<()> {
    let result = evidencepack::validate_path(pack)?;
    println!(
        "{}: {} cases, {} binaries, maturity {:?}",
        result.id, result.cases, result.binaries, result.maturity
    );
    Ok(())
}

fn import_oracle_command(ir: &Path, input: &Path, out: &Path) -> Result<()> {
    let mut db = load_ir(ir)?;
    let count = oracle::import_path(&mut db, input)?;
    diff::atomic_write(out, &serde_json::to_vec_pretty(&db)?)?;
    println!(
        "imported {count} oracle observations into {}",
        out.display()
    );
    Ok(())
}

struct RefineOptions {
    ir: PathBuf,
    reference: Option<PathBuf>,
    semantic_mode: bool,
    binary: Option<PathBuf>,
    pdb: Option<PathBuf>,
    semantic_out: PathBuf,
    probe_manifest: Option<PathBuf>,
    manual_layout: Option<PathBuf>,
    out: PathBuf,
    out_ir: Option<PathBuf>,
}

fn refine_command(options: RefineOptions) -> Result<()> {
    let mut db = load_ir(&options.ir)?;
    let recovered = refine::apply_generic_rules(&mut db);
    if let Some(reference) = options.reference.as_deref() {
        println!(
            "reference candidates: {}",
            refine::import_candidates(&mut db, reference)?
        );
    }
    if options.semantic_mode {
        run_semantic_refinement(&mut db, &options)?;
    }
    let report = refine::compare(&db, options.reference.as_deref(), recovered)?;
    refine::write(&report, &options.out)?;
    if let Some(path) = options.out_ir {
        diff::atomic_write(&path, &serde_json::to_vec_pretty(&db)?)?;
    }
    print_refine_summary(&report, &options.out);
    Ok(())
}

fn run_semantic_refinement(db: &mut Database, options: &RefineOptions) -> Result<()> {
    let binary = options
        .binary
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--binary is required when --semantic is enabled"))?;
    semantic::validate_target(db, binary)?;
    if let Some(path) = &options.pdb {
        anyhow::ensure!(
            path.is_file(),
            "semantic PDB does not exist: {}",
            path.display()
        );
    }
    if let Some(path) = &options.manual_layout {
        let imported = semantic::import_manual_layout(db, path)?;
        println!("manual semantic evidence: {imported} fields");
    }
    semantic::project(db);
    let summary = semantic_emit::emit(db, &options.semantic_out)?;
    let checks = semantic_validate::run(
        &options.semantic_out,
        &semantic_emit::target_stem(&db.binary.file),
    )?;
    anyhow::ensure!(
        checks.iter().all(|check| check.status != "failed"),
        "semantic compiler round-trip failed; see {}/layout-check/compiler-validation.json",
        options.semantic_out.display()
    );
    run_semantic_probe(db, binary, options)?;
    let recovery = recovery_plan::emit(db, &options.semantic_out)?;
    println!(
        "semantic: {} verified/{} candidate complete classes, {} verified field/storage facts ({} named, {} unnamed), {} verified bases, {} verified vtables/{} slots, {} verified/{} candidate enums -> {}",
        summary.verified_classes,
        summary.candidate_classes,
        summary.verified_fields,
        summary.verified_named_fields,
        summary.verified_storage_slots,
        summary.verified_bases,
        summary.verified_vtables,
        summary.verified_vtable_slots,
        summary.verified_enums,
        summary.candidate_enums,
        options.semantic_out.display()
    );
    println!(
        "recovery plan: {} gaps across {} kinds ({} priority-zero) -> {}",
        recovery.total,
        recovery.kinds,
        recovery.critical,
        options.semantic_out.join("recovery-plan.json").display()
    );
    Ok(())
}

fn run_semantic_probe(db: &mut Database, binary: &Path, options: &RefineOptions) -> Result<()> {
    let probe_out = options.semantic_out.join("probe-result.json");
    if let Some(manifest_path) = &options.probe_manifest {
        let manifest = semantic_probe::load_and_validate(db, binary, manifest_path)?;
        semantic_probe::run_isolated(binary, manifest_path, &probe_out, manifest.timeout_ms)?;
        let imported = semantic_probe::import_result(db, &probe_out)?;
        println!(
            "semantic probe: {} operations, {} imported proofs -> {}",
            manifest.operations.len(),
            imported,
            probe_out.display()
        );
        return Ok(());
    }
    semantic_probe::write_static_only(db, &probe_out)?;
    println!(
        "semantic probe: static-only (runtime calls require --probe-manifest) -> {}",
        probe_out.display()
    );
    Ok(())
}

fn print_refine_summary(report: &refine::RefineReport, out: &Path) {
    println!(
        "refine: {} generic recoveries, {} common methods, {} reference-only ({} implementation-backed known-class, {} implementation-backed total, {} declaration-only, {} stubs, {} inline, {} pure-virtual, {} special-member, {} absent-class), {} signature conflicts -> {}",
        report.generic_recoveries_applied,
        report.common_methods,
        report.reference_only.len(),
        report.reference_only_known_class,
        report.reference_only_implemented,
        report.reference_only_declaration_only,
        report.reference_only_stubs,
        report.reference_only_inline,
        report.reference_only_pure_virtual,
        report.reference_only_special_member,
        report.reference_only_unknown_class,
        report.signature_conflicts.len(),
        out.display()
    );
    println!(
        "recovery jobs: {} total, {} verified, {} candidate, {} unresolved, {} withheld",
        report.recovery_jobs,
        report.recovery_verified,
        report.recovery_candidates,
        report.recovery_unresolved,
        report.recovery_withheld
    );
}

fn score_semantic_command(
    ir: &Path,
    oracle_path: &Path,
    precision_threshold: f64,
    out: Option<&Path>,
) -> Result<()> {
    let score = semantic_score::score(&load_ir(ir)?, oracle_path, precision_threshold)?;
    let json = serde_json::to_vec_pretty(&score)?;
    if let Some(path) = out {
        diff::atomic_write(path, &json)?;
    } else {
        println!("{}", String::from_utf8(json)?);
    }
    anyhow::ensure!(
        score.passed,
        "semantic precision {:.6} is below threshold {:.6}",
        score.precision,
        score.threshold
    );
    Ok(())
}

fn load_ir(path: &Path) -> Result<Database> {
    let bytes = std::fs::read(path)?;
    Ok(serde_json::from_slice::<Database>(&bytes)?.migrate())
}

fn emit_cpp(qualified: &str, ir: &Path) -> Result<()> {
    let db = load_ir(ir)?;
    let (ns, class) = qualified.rsplit_once("::").unwrap_or(("", qualified));
    print!("{}", emit::cpp_class(&db, ns, class));
    Ok(())
}

fn list_classes(ir: &Path) -> Result<()> {
    let db = load_ir(ir)?;
    for (ns, class, n) in emit::classes(&db).into_iter().take(30) {
        println!("{n:5}  {ns}::{class}");
    }
    Ok(())
}

pub(crate) fn extract_to(
    dll: &Path,
    out: &Path,
    pdb: Option<&Path>,
    retain_instruction_graph: bool,
) -> Result<()> {
    let extraction_started = Instant::now();
    let mut phase_started = extraction_started;
    if let Some(path) = pdb {
        anyhow::ensure!(path.exists(), "PDB does not exist: {}", path.display());
    }
    let mut ex = extract::from_pe(dll, pdb, retain_instruction_graph)?;
    eprintln!(
        "[timing] pe-and-pdb-symbols: {:.3}s",
        phase_started.elapsed().as_secs_f64()
    );
    phase_started = Instant::now();

    for s in &mut ex.symbols {
        if let Some(d) = demangle::demangle(&s.mangled) {
            s.sig = demangle::parse_decl(&d);
            s.demangled = Some(d);
        }
        s.library = is_library(&s.mangled, s.demangled.as_deref());
        s.kind = demangle::classify(s);
    }
    eprintln!(
        "[timing] demangle-and-signatures: {:.3}s",
        phase_started.elapsed().as_secs_f64()
    );
    phase_started = Instant::now();

    let mut db = Database {
        schema: SCHEMA_VERSION,
        generated: date_today(),
        tool: "rust: goblin + msvc-demangler + pdb".into(),
        binary: ex.info,
        symbols: ex.symbols,
        pdb_records: ex.pdb_records,
        ..Default::default()
    };
    let pdb_coverage = ex.pdb_coverage.take();

    if pdb.is_none() {
        db.type_recovery = serde_json::json!({
            "status": "unavailable-no-pdb",
            "reason": "no PDB was supplied; PE-native analysis remains available"
        });
    }

    // Phase B.5: PDB Type/Layout/VTable Recovery (if PDB provided)
    if let Some(pdb_path) = pdb {
        let extracted_types = pdbtype::extract_types(pdb_path)?;
        pdbtype::enrich_database_with_types(&mut db, &extracted_types);
    }
    eprintln!(
        "[timing] pdb-types: {:.3}s",
        phase_started.elapsed().as_secs_f64()
    );
    phase_started = Instant::now();

    // Phase C: Static Enrichment (function sizes, reloc-normalized body hashes, call graph, Win32 imports)
    let pe_bytes = std::fs::read(dll)?;
    enrich::enrich_database(&mut db, &pe_bytes)?;
    eprintln!(
        "[timing] disassembly-and-cfg: {:.3}s",
        phase_started.elapsed().as_secs_f64()
    );
    phase_started = Instant::now();
    configure_instruction_retention(&mut db, retain_instruction_graph);

    // Phase C.5: recover MSVC vftables directly from PE data. This remains
    // available when Microsoft's public PDB has an empty/stripped TPI stream.
    rtti::recover(&mut db, &pe_bytes)?;
    eprintln!(
        "[timing] pe-rtti: {:.3}s",
        phase_started.elapsed().as_secs_f64()
    );
    phase_started = Instant::now();

    // Phase C.75: conservative exact-build member-offset recovery.  This only
    // records direct `this + displacement` observations; it does not pretend
    // that an observed store is enough to assign a semantic field name.
    layoutinfer::recover(&mut db, &pe_bytes, retain_instruction_graph)?;
    eprintln!(
        "[timing] layout-inference: {:.3}s",
        phase_started.elapsed().as_secs_f64()
    );
    phase_started = Instant::now();

    // Phase D: Reflection System Recovery
    reflection::recover_reflection(&mut db, &pe_bytes);
    eprintln!(
        "[timing] reflection: {:.3}s",
        phase_started.elapsed().as_secs_f64()
    );
    phase_started = Instant::now();

    if let Some(coverage) = pdb_coverage {
        if let Some(object) = db.type_recovery.as_object_mut() {
            object.insert("pdb_stream_coverage".into(), coverage);
        } else {
            db.type_recovery =
                serde_json::json!({ "status": "pdb-stream-inventory", "coverage": coverage });
        }
    }

    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let serialized = serialize_ir(&db, retain_instruction_graph)?;
    eprintln!(
        "[timing] serialize-ir: {:.3}s ({} bytes)",
        phase_started.elapsed().as_secs_f64(),
        serialized.len()
    );
    std::fs::write(out, serialized)?;
    eprintln!(
        "[timing] total-extraction: {:.3}s",
        extraction_started.elapsed().as_secs_f64()
    );
    report(&db, out);
    Ok(())
}

fn serialize_ir(db: &Database, pretty: bool) -> Result<Vec<u8>> {
    Ok(if pretty {
        serde_json::to_vec_pretty(db)?
    } else {
        serde_json::to_vec(db)?
    })
}

fn configure_instruction_retention(db: &mut Database, retain: bool) {
    if !retain {
        db.functions.clear();
        db.functions.shrink_to_fit();
    }
    db.capabilities
        .retain(|capability| capability.id != "canonical-x86-instructions-cfg-retention");
    db.capabilities.push(Capability {
        id: "canonical-x86-instructions-cfg-retention".into(),
        status: if retain {
            CapabilityStatus::Supported
        } else {
            CapabilityStatus::Unsupported
        },
        analyzer: "extract".into(),
        reason: if retain {
            format!(
                "{} decoded function records retained by explicit pgressive mode",
                db.functions.len()
            )
        } else {
            "decoded instructions were consumed by proof recovery and omitted from compact binding IR; use pgressive mode to retain them".into()
        },
    });
}

/// CRT/STL/ETW boilerplate: real code, but not the target's own.
pub(crate) fn is_library(mangled: &str, demangled: Option<&str>) -> bool {
    const DECORATED_MARKERS: &[&str] = &[
        "_tlg",
        "@std@@",
        "@Concurrency@@",
        "@wil@@",
        "_CRT",
        "__scrt",
        "@_Cnd",
        "@_Mtx",
    ];
    const C_RUNTIME_NAMES: &[&str] = &[
        "atexit", "free", "malloc", "realloc", "calloc", "wcscmp", "wcslen", "wcscpy", "memcpy",
        "memset", "memmove", "memcmp", "acosf", "ceilf", "cosf", "expf", "floor", "floorf", "powf",
        "sin", "sinf", "sqrt", "sqrtf", "abs", "labs",
    ];
    if DECORATED_MARKERS
        .iter()
        .any(|pattern| mangled.contains(pattern))
    {
        return true;
    }
    let plain_name = mangled.strip_prefix("__imp_").unwrap_or(mangled);
    let plain_name = plain_name.strip_prefix('_').unwrap_or(plain_name);
    if !mangled.starts_with('?') && C_RUNTIME_NAMES.contains(&plain_name) {
        return true;
    }
    if let Some(d) = demangled {
        const D: &[&str] = &["std::", "Concurrency::", "wil::"];
        return D.iter().any(|p| d.contains(p));
    }
    false
}

fn report(db: &Database, out: &Path) {
    let (mut exported, mut internal, mut library, mut parsed) = (0, 0, 0, 0);
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    for s in &db.symbols {
        if s.exported {
            exported += 1;
        } else {
            internal += 1;
        }
        if s.library {
            library += 1;
        }
        if s.sig.parse_ok {
            parsed += 1;
        }
        if !s.library {
            *by_kind.entry(format!("{:?}", s.kind)).or_default() += 1;
        }
    }
    let n = db.symbols.len();
    println!("wrote {}", out.display());
    println!(
        "binary:     {} · pdb_guid {:?}",
        db.binary.file, db.binary.pdb_guid
    );
    println!("symbols:    {n}  ({exported} exported, {internal} internal)");
    println!("library:    {library} boilerplate (flagged, emitters skip)");
    let parsed_percent = if n == 0 {
        0.0
    } else {
        let total = u32::try_from(n).map_or(f64::INFINITY, f64::from);
        100.0 * f64::from(parsed) / total
    };
    println!("signatures: {parsed} structured ({parsed_percent:.1}%)");
    println!("target-owned symbols, by shape:");
    let mut kinds: Vec<_> = by_kind.into_iter().collect();
    kinds.sort_by_key(|item| std::cmp::Reverse(item.1));
    for (k, c) in kinds {
        println!("  {k:10} {c}");
    }
    // Provenance is preserved as the identity source. Keep the categories
    // explicit: no-PDB recovery adds linker-authored unwind records, so
    // treating every non-PDB symbol as an export would be misleading.
    let provenance_count = |provenance| {
        db.symbols
            .iter()
            .filter(|symbol| symbol.provenance == provenance)
            .count()
    };
    let pdb_named = provenance_count(Provenance::Pdb);
    let exported_symbols = provenance_count(Provenance::PeExport);
    let unwind_functions = provenance_count(Provenance::PeUnwind);
    let unwind_handlers = provenance_count(Provenance::PeUnwindHandler);
    let guard_cf_functions = provenance_count(Provenance::PeGuardCf);
    let call_targets = provenance_count(Provenance::PeCallTarget);
    let tail_targets = provenance_count(Provenance::PeTailTarget);
    let safe_seh_handlers = provenance_count(Provenance::PeSafeSeh);
    let entry_points = provenance_count(Provenance::PeEntryPoint);
    let other = n
        - pdb_named
        - exported_symbols
        - unwind_functions
        - unwind_handlers
        - guard_cf_functions
        - call_targets
        - tail_targets
        - safe_seh_handlers
        - entry_points;
    println!(
        "provenance: {pdb_named} PDB, {exported_symbols} export table, \
         {unwind_functions} PE unwind, {unwind_handlers} unwind handlers, \
         {guard_cf_functions} Guard CF, {safe_seh_handlers} SafeSEH, {entry_points} entry point, \
         {call_targets} direct-call candidates, {tail_targets} tail-target candidates, {other} other"
    );
}

/// UTC yyyy-mm-dd from the system clock, without a chrono dependency.
pub(crate) fn date_today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX);
    let (mut y, mut d) = (1970i64, days);
    loop {
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let dy = if leap { 366 } else { 365 };
        if d < dy {
            break;
        }
        d -= dy;
        y += 1;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let ml = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 0usize;
    while d >= ml[m] {
        d -= ml[m];
        m += 1;
    }
    format!("{y:04}-{:02}-{:02}", m + 1, d + 1)
}

#[cfg(test)]
mod main_tests {
    use super::{configure_instruction_retention, is_library};
    use crate::model::{Database, FunctionAnalysis};

    #[test]
    fn crt_names_require_symbol_boundaries() {
        assert!(is_library("memcpy", None));
        assert!(is_library("__imp_memcpy", None));
        assert!(!is_library(
            "?SetDynamicScaling@DUIXmlParser@DirectUI@@QEAAXW4DynamicScaleParsing@2@@Z",
            Some("DirectUI::DUIXmlParser::SetDynamicScaling(DirectUI::DynamicScaleParsing)")
        ));
        assert!(!is_library("?GetFreeValue@Widget@@QEAAXXZ", None));
    }

    #[test]
    fn compact_ir_discards_only_retained_instruction_records() {
        let mut db = Database {
            functions: vec![FunctionAnalysis {
                rva: 0x1000,
                size: 1,
                symbol_ids: vec!["sample".into()],
                instructions: Vec::new(),
                cfg_edges: Vec::new(),
            }],
            ..Database::default()
        };

        configure_instruction_retention(&mut db, false);

        assert!(db.functions.is_empty());
        assert!(db.capabilities.iter().any(|capability| {
            capability.id == "canonical-x86-instructions-cfg-retention"
                && matches!(
                    capability.status,
                    crate::model::CapabilityStatus::Unsupported
                )
        }));
    }
}
