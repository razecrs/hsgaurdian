//! Exact-build, opt-in semantic runtime probing.

use crate::model::{Database, SemanticEnum, SemanticEnumValue, SemanticStatus};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Deserialize, Serialize)]
pub struct ProbeManifest {
    pub schema: u32,
    pub binary_sha256: String,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    pub operations: Vec<ProbeOperation>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ProbeOperation {
    ReadRva {
        id: String,
        rva: u32,
        size: u32,
    },
    CallNoArgs {
        id: String,
        symbol_id: String,
        rva: u32,
        acknowledge_side_effects: bool,
    },
    /// Construct a verified-layout object via its zero-argument constructor,
    /// call one verified vtable slot across a small integer range (the
    /// candidate enum values), then destroy the object. Used to recover an
    /// enum's actual member values dynamically when the PDB only carries a
    /// forward reference (no `LF_ENUMERATE` records survived to this build).
    CallEnumProbe {
        id: String,
        class_name: String,
        enum_name: String,
        object_size: u32,
        ctor_symbol_id: String,
        ctor_rva: u32,
        dtor_symbol_id: String,
        dtor_rva: u32,
        method_symbol_id: String,
        vtable_rva: u32,
        #[serde(default)]
        vtable_object_offset: i64,
        vtable_slot: u32,
        range_start: i32,
        range_end: i32,
        out_int_params: u8,
        acknowledge_side_effects: bool,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProbeResult {
    pub schema: u32,
    pub binary_sha256: String,
    pub observations: Vec<ProbeObservation>,
}

#[cfg(test)]
pub const fn runtime_supported() -> bool {
    cfg!(windows)
}

pub fn write_static_only(db: &Database, out: &Path) -> Result<()> {
    let mut observations = vec![ProbeObservation {
        id: "runtime-capability".into(),
        status: "static-only".into(),
        detail: "runtime calls require an explicit exact-build probe manifest".into(),
    }];
    observations.extend(
        db.symbols
            .iter()
            .filter(|symbol| symbol.is_code && symbol.sig.class.is_none())
            .filter(|symbol| symbol.sig.params.is_empty())
            .filter(|symbol| db.symbol_is_verified_callable(&symbol.id))
            .map(|symbol| ProbeObservation {
                id: format!("withheld:{:08X}:{}", symbol.rva, symbol.id),
                status: "withheld".into(),
                detail: "addressability and ABI are verified, but host-context preconditions and side effects are not"
                    .into(),
            }),
    );
    let result = ProbeResult {
        schema: 1,
        binary_sha256: db.binary.sha256.clone().unwrap_or_default(),
        observations,
    };
    crate::diff::atomic_write(out, &serde_json::to_vec_pretty(&result)?)
}

pub fn import_result(db: &mut Database, path: &Path) -> Result<usize> {
    let result: ProbeResult = serde_json::from_slice(
        &std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
    )?;
    let mut imported = 0;
    for observation in result.observations {
        if observation.status == "enum-range" {
            imported += import_enum_range(db, &observation, &result.binary_sha256)?;
            continue;
        }
        if observation.status != "returned" {
            continue;
        }
        let digest = Sha256::digest(observation.id.as_bytes());
        let suffix = &crate::hex::lower(&digest)[..16];
        let evidence_id = format!("ev:runtime-return:{suffix}");
        let proof_id = format!("proof:runtime-return:{suffix}");
        let claim_id = format!("claim:runtime-return:{suffix}");
        if db.claims.iter().any(|claim| claim.id == claim_id) {
            continue;
        }
        let text = format!("{} returned {}", observation.id, observation.detail);
        db.evidence.push(crate::model::Evidence {
            id: evidence_id.clone(),
            kind: crate::model::EvidenceKind::Dataflow,
            tool: crate::model::EvidenceTool::Windissect,
            rule_id: "runtime.exact-build-return".into(),
            rule_version: 1,
            location: crate::model::EvidenceLocation::default(),
            observation: crate::model::EvidenceObservation::Text { text: text.clone() },
        });
        db.proofs.push(crate::model::Proof {
            id: proof_id.clone(),
            rule_id: "runtime.exact-build-return".into(),
            rule_version: 1,
            passed: true,
            obligations: vec![crate::model::ProofObligation {
                name: "exact-binary-hash".into(),
                satisfied: true,
                detail: result.binary_sha256.clone(),
            }],
        });
        db.claims.push(crate::model::Claim {
            id: claim_id,
            subject: crate::model::ClaimSubject::Text {
                category: "runtime-return".into(),
                text,
            },
            status: crate::model::ClaimStatus::Derived,
            usability: crate::model::Usability::Verified,
            evidence_ids: vec![evidence_id],
            proof_id: Some(proof_id),
        });
        imported += 1;
    }
    Ok(imported)
}

/// Import a `CallEnumProbe` observation: every candidate value the target
/// accepted (a non-negative HRESULT) becomes a proof-gated `EnumValue` claim,
/// backed by evidence naming this exact binary hash and the probe id.
fn import_enum_range(
    db: &mut Database,
    observation: &ProbeObservation,
    binary_sha256: &str,
) -> Result<usize> {
    let parsed: serde_json::Value =
        serde_json::from_str(&observation.detail).context("parsing enum-range probe detail")?;
    let enum_name = parsed
        .get("enum_name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    if enum_name.is_empty() {
        return Ok(0);
    }
    let empty = Vec::new();
    let results = parsed
        .get("results")
        .and_then(serde_json::Value::as_array)
        .unwrap_or(&empty);

    let mut imported = 0;
    for result in results {
        let succeeded = result
            .get("succeeded")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        if !succeeded {
            continue;
        }
        let Some(value) = result.get("value").and_then(serde_json::Value::as_i64) else {
            continue;
        };

        let digest = Sha256::digest(format!("{enum_name}:{value}:{binary_sha256}").as_bytes());
        let suffix = &crate::hex::lower(&digest)[..16];
        let evidence_id = format!("ev:runtime-enum:{suffix}");
        let proof_id = format!("proof:runtime-enum:{suffix}");
        let claim_id = format!("claim:runtime-enum:{suffix}");
        if db.claims.iter().any(|claim| claim.id == claim_id) {
            continue;
        }

        let member_name = format!("value_{value}");
        db.evidence.push(crate::model::Evidence {
            id: evidence_id.clone(),
            kind: crate::model::EvidenceKind::Dataflow,
            tool: crate::model::EvidenceTool::Windissect,
            rule_id: "runtime.exact-build-enum-range".into(),
            rule_version: 1,
            location: crate::model::EvidenceLocation::default(),
            observation: crate::model::EvidenceObservation::Text {
                text: format!(
                    "{enum_name} value {value} accepted by runtime probe {}",
                    observation.id
                ),
            },
        });
        db.proofs.push(crate::model::Proof {
            id: proof_id.clone(),
            rule_id: "runtime.exact-build-enum-range".into(),
            rule_version: 1,
            passed: true,
            obligations: vec![crate::model::ProofObligation {
                name: "exact-binary-hash".into(),
                satisfied: true,
                detail: binary_sha256.to_string(),
            }],
        });
        db.claims.push(crate::model::Claim {
            id: claim_id.clone(),
            subject: crate::model::ClaimSubject::EnumValue {
                owner: enum_name.clone(),
                name: member_name.clone(),
                value,
            },
            status: crate::model::ClaimStatus::Derived,
            usability: crate::model::Usability::Verified,
            evidence_ids: vec![evidence_id],
            proof_id: Some(proof_id),
        });

        let entry = db
            .semantic
            .enums
            .iter_mut()
            .find(|candidate| candidate.qualified_name == enum_name);
        match entry {
            Some(existing) => existing.values.push(SemanticEnumValue {
                name: member_name,
                value,
                status: SemanticStatus::Verified,
                claim_ids: vec![claim_id],
            }),
            None => db.semantic.enums.push(SemanticEnum {
                qualified_name: enum_name.clone(),
                underlying_type: None,
                status: SemanticStatus::Candidate,
                values: vec![SemanticEnumValue {
                    name: member_name,
                    value,
                    status: SemanticStatus::Verified,
                    claim_ids: vec![claim_id],
                }],
            }),
        }
        imported += 1;
    }
    Ok(imported)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProbeObservation {
    pub id: String,
    pub status: String,
    pub detail: String,
}

const fn default_timeout() -> u64 {
    10_000
}

pub fn load_and_validate(db: &Database, binary: &Path, path: &Path) -> Result<ProbeManifest> {
    ensure!(
        binary
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("dll")),
        "runtime semantic probing is DLL-only; EXE and SYS targets are static-only"
    );
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let manifest: ProbeManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing probe manifest {}", path.display()))?;
    ensure!(
        manifest.schema == 1,
        "unsupported probe manifest schema {}",
        manifest.schema
    );
    let expected = db
        .binary
        .sha256
        .as_deref()
        .context("IR has no binary SHA-256")?;
    ensure!(
        manifest.binary_sha256.eq_ignore_ascii_case(expected),
        "probe manifest hash mismatch: IR {expected}, manifest {}",
        manifest.binary_sha256
    );
    ensure!(
        !manifest.operations.is_empty(),
        "probe manifest has no operations"
    );
    ensure!(
        manifest.timeout_ms > 0 && manifest.timeout_ms <= 30_000,
        "probe timeout must be in 1..=30000 ms"
    );
    let image_size = db.binary.image_size.unwrap_or(0);
    for operation in &manifest.operations {
        validate_operation(db, operation, image_size)?;
    }
    Ok(manifest)
}

/// Validate one probe operation against the exact-build IR.
fn validate_operation(db: &Database, operation: &ProbeOperation, image_size: u64) -> Result<()> {
    match operation {
        ProbeOperation::ReadRva { id, rva, size } => {
            ensure!(!id.is_empty(), "probe operation has an empty id");
            ensure!(
                *size > 0 && *size <= 4096,
                "probe read {id} size must be in 1..=4096"
            );
            ensure!(
                u64::from(*rva) + u64::from(*size) <= image_size,
                "probe read {id} exceeds image bounds"
            );
        }
        ProbeOperation::CallNoArgs {
            id,
            symbol_id,
            rva,
            acknowledge_side_effects,
        } => {
            ensure!(
                *acknowledge_side_effects,
                "probe call {id} must acknowledge side effects"
            );
            let symbol = db
                .symbols
                .iter()
                .find(|symbol| symbol.id == *symbol_id)
                .with_context(|| format!("probe call {id} names unknown symbol {symbol_id}"))?;
            ensure!(
                symbol.rva == *rva,
                "probe call {id} RVA does not match the exact-build IR"
            );
            ensure!(
                db.symbol_is_verified_callable(symbol_id),
                "probe call {id} is not proof-gated callable"
            );
            ensure!(
                symbol.sig.params.is_empty(),
                "probe call {id} is not a zero-argument function"
            );
            ensure!(
                symbol.sig.class.is_none() || symbol.sig.storage.as_deref() == Some("static"),
                "probe call {id} requires a this pointer"
            );
        }
        ProbeOperation::CallEnumProbe { .. } => validate_enum_probe(db, operation)?,
    }
    Ok(())
}

/// Validate a constructor or destructor named by an enum probe: it must exist,
/// match the exact-build RVA, belong to the class, take no arguments, and be
/// proof-gated callable. `role` is "constructor" or "destructor" for messages.
fn validate_probe_member(
    db: &Database,
    id: &str,
    class_name: &str,
    role: &str,
    symbol_id: &str,
    expected_rva: u32,
) -> Result<()> {
    let member = db
        .symbols
        .iter()
        .find(|symbol| symbol.id == *symbol_id)
        .with_context(|| format!("probe call {id} names unknown {role} {symbol_id}"))?;
    ensure!(
        member.rva == expected_rva,
        "probe call {id} {role} RVA does not match the exact-build IR"
    );
    ensure!(
        member.sig.class.as_deref() == Some(class_name),
        "probe call {id} {role} is not a member of {class_name}"
    );
    ensure!(
        member.sig.params.is_empty(),
        "probe call {id} {role} is not zero-argument"
    );
    ensure!(
        db.symbol_is_verified_callable(symbol_id),
        "probe call {id} {role} is not proof-gated callable"
    );
    Ok(())
}

/// Validate a `CallEnumProbe`: its class, constructor, destructor and the exact
/// vtable slot must all be proof-gated in the IR before the runtime probe runs.
fn validate_enum_probe(db: &Database, operation: &ProbeOperation) -> Result<()> {
    let ProbeOperation::CallEnumProbe {
        id,
        class_name,
        enum_name,
        object_size,
        ctor_symbol_id,
        ctor_rva,
        dtor_symbol_id,
        dtor_rva,
        method_symbol_id,
        vtable_rva,
        vtable_object_offset,
        vtable_slot,
        range_start,
        range_end,
        out_int_params,
        acknowledge_side_effects,
    } = operation
    else {
        return Ok(());
    };

    ensure!(!id.is_empty(), "probe operation has an empty id");
    ensure!(
        *acknowledge_side_effects,
        "probe call {id} must acknowledge side effects"
    );
    ensure!(
        !enum_name.is_empty(),
        "probe call {id} needs an enum name to attach recovered values to"
    );
    ensure!(
        *range_end >= *range_start && (*range_end - *range_start) < 64,
        "probe call {id} enum range must be small and non-empty"
    );
    ensure!(
        *out_int_params <= 2,
        "probe call {id} supports at most 2 trailing int* out-params"
    );
    ensure!(
        *object_size > 0 && *object_size <= 4096,
        "probe call {id} object size must be in 1..=4096"
    );

    let class = db
        .semantic
        .classes
        .iter()
        .find(|class| class.qualified_name == *class_name)
        .with_context(|| format!("probe call {id} names unknown class {class_name}"))?;
    ensure!(
        class.status == SemanticStatus::Verified,
        "probe call {id} class {class_name} is not a verified complete class"
    );
    if let Some(size) = class.size {
        ensure!(
            u64::from(*object_size) >= size,
            "probe call {id} object_size is smaller than the verified class size"
        );
    }

    validate_probe_member(db, id, class_name, "constructor", ctor_symbol_id, *ctor_rva)?;
    validate_probe_member(db, id, class_name, "destructor", dtor_symbol_id, *dtor_rva)?;

    let vtable = class
        .vtables
        .iter()
        .find(|vt| vt.rva == *vtable_rva && vt.object_offset.unwrap_or(0) == *vtable_object_offset)
        .with_context(|| format!("probe call {id} names an unknown vtable on {class_name}"))?;
    ensure!(
        vtable.status == SemanticStatus::Verified,
        "probe call {id} vtable is not verified"
    );
    let slot = vtable
        .slots
        .iter()
        .find(|slot| slot.slot == *vtable_slot)
        .with_context(|| format!("probe call {id} names an unknown vtable slot"))?;
    ensure!(
        slot.status == SemanticStatus::Verified,
        "probe call {id} vtable slot is not verified"
    );
    ensure!(
        slot.symbol_id.as_deref() == Some(method_symbol_id.as_str()),
        "probe call {id} vtable slot does not match the named method"
    );
    Ok(())
}

pub fn run_isolated(binary: &Path, manifest: &Path, out: &Path, timeout_ms: u64) -> Result<()> {
    let source: ProbeManifest = serde_json::from_slice(&std::fs::read(manifest)?)?;
    let executable = std::env::current_exe()?;
    let mut observations = Vec::new();
    let mut failed = 0usize;
    let scratch = std::env::temp_dir().join(format!(
        "windissect-probe-{}-{}",
        std::process::id(),
        &crate::hex::lower(&Sha256::digest(manifest.as_os_str().as_encoded_bytes()))[..12]
    ));
    std::fs::create_dir_all(&scratch)?;

    for (index, operation) in source.operations.iter().enumerate() {
        let operation_value = serde_json::to_value(operation)?;
        let operation_id = operation_value
            .get("id")
            .and_then(serde_json::Value::as_str)
            .context("probe operation has no string id")?
            .to_owned();
        let operation_manifest = scratch.join(format!("{index:03}-manifest.json"));
        let operation_out = scratch.join(format!("{index:03}-result.json"));
        let single = serde_json::json!({
            "schema": source.schema,
            "binary_sha256": &source.binary_sha256,
            "timeout_ms": source.timeout_ms,
            "operations": [operation_value],
        });
        crate::diff::atomic_write(&operation_manifest, &serde_json::to_vec(&single)?)?;

        let mut command = std::process::Command::new(&executable);
        command
            .arg("semantic-probe-helper")
            .arg("--binary")
            .arg(binary)
            .arg("--manifest")
            .arg(&operation_manifest)
            .arg("--out")
            .arg(&operation_out);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        let mut child = command.spawn()?;
        let start = std::time::Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break Some(status);
            }
            if start.elapsed() > std::time::Duration::from_millis(timeout_ms) {
                child.kill()?;
                let _ = child.wait();
                break None;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };

        if status.is_some_and(|value| value.success()) {
            let result: ProbeResult = serde_json::from_slice(&std::fs::read(&operation_out)?)?;
            observations.extend(result.observations);
        } else {
            failed += 1;
            let (status, detail) = status.map_or_else(
                || {
                    (
                        "timed-out",
                        format!("isolated helper exceeded {timeout_ms} ms"),
                    )
                },
                |value| ("crashed", format!("isolated helper failed with {value}")),
            );
            eprintln!("semantic probe {operation_id}: {detail}");
            observations.push(ProbeObservation {
                id: operation_id,
                status: status.into(),
                detail,
            });
        }
    }

    let result = ProbeResult {
        schema: 1,
        binary_sha256: source.binary_sha256,
        observations,
    };
    crate::diff::atomic_write(out, &serde_json::to_vec_pretty(&result)?)?;
    let _ = std::fs::remove_dir_all(&scratch);
    if failed > 0 {
        eprintln!(
            "semantic probe: {failed}/{} operations failed safely in isolated helpers",
            source.operations.len()
        );
    }
    Ok(())
}

pub fn helper(binary: &Path, manifest_path: &Path, out: &Path) -> Result<()> {
    let manifest: ProbeManifest = serde_json::from_slice(&std::fs::read(manifest_path)?)?;
    let actual = crate::hex::upper(&Sha256::digest(&std::fs::read(binary)?));
    ensure!(
        actual.eq_ignore_ascii_case(&manifest.binary_sha256),
        "probe helper binary hash mismatch"
    );
    let observations = platform_probe(binary, &manifest)?;
    let result = ProbeResult {
        schema: 1,
        binary_sha256: manifest.binary_sha256,
        observations,
    };
    crate::diff::atomic_write(out, &serde_json::to_vec_pretty(&result)?)
}

// Decomposition debt: the runtime probe is a long unsafe sequence (load, walk
// vtables, call, capture). A later pass can lift the per-object step out; kept
// whole for now so the strict gate stays green without touching probe behavior.
#[cfg(windows)]
fn platform_probe(binary: &Path, manifest: &ProbeManifest) -> Result<Vec<ProbeObservation>> {
    use std::ffi::{OsStr, c_void};
    use std::os::windows::ffi::OsStrExt;
    unsafe extern "system" {
        fn LoadLibraryW(name: *const u16) -> *mut c_void;
        fn FreeLibrary(module: *mut c_void) -> i32;
    }
    let wide: Vec<u16> = OsStr::new(binary.as_os_str())
        .encode_wide()
        .chain(Some(0))
        .collect();
    let module = unsafe { LoadLibraryW(wide.as_ptr()) };
    ensure!(
        !module.is_null(),
        "LoadLibraryW failed for {}",
        binary.display()
    );
    let mut observations = Vec::new();
    for operation in &manifest.operations {
        match operation {
            ProbeOperation::ReadRva { id, rva, size } => {
                let address_offset = usize::try_from(*rva).context("RVA does not fit usize")?;
                let byte_count = usize::try_from(*size).context("probe size does not fit usize")?;
                let bytes = unsafe {
                    std::slice::from_raw_parts(
                        (module as *const u8).add(address_offset),
                        byte_count,
                    )
                };
                observations.push(ProbeObservation {
                    id: id.clone(),
                    status: "observed".into(),
                    detail: crate::hex::upper(bytes),
                });
            }
            ProbeOperation::CallNoArgs { id, rva, .. } => {
                let address_offset = usize::try_from(*rva).context("RVA does not fit usize")?;
                let address = unsafe { (module as *const u8).add(address_offset) };
                let function: unsafe extern "system" fn() -> usize =
                    unsafe { std::mem::transmute(address) };
                let value = unsafe { function() };
                observations.push(ProbeObservation {
                    id: id.clone(),
                    status: "returned".into(),
                    detail: format!("0x{value:X}"),
                });
            }
            ProbeOperation::CallEnumProbe { .. } => {
                observations.push(run_enum_probe(module.cast::<u8>(), operation)?);
            }
        }
    }
    unsafe { FreeLibrary(module) };
    Ok(observations)
}

/// Construct the object, call one method across a small integer range, destruct.
///
/// This is the intrinsic shape of invoking a COM method by vtable slot; every
/// pointer step is deliberate and bounds were validated in `validate_enum_probe`
/// before this runs.
#[cfg(windows)]
fn run_enum_probe(module: *const u8, operation: &ProbeOperation) -> Result<ProbeObservation> {
    let ProbeOperation::CallEnumProbe {
        id,
        class_name,
        enum_name,
        object_size,
        ctor_rva,
        dtor_rva,
        vtable_object_offset,
        vtable_slot,
        range_start,
        range_end,
        out_int_params,
        ..
    } = operation
    else {
        return Err(anyhow::anyhow!(
            "run_enum_probe called on a non-enum operation"
        ));
    };

    let size = usize::try_from(*object_size).context("object size does not fit usize")?;
    let mut buffer = vec![0u8; size];
    let this_ptr = buffer.as_mut_ptr();

    let ctor_offset = usize::try_from(*ctor_rva).context("ctor RVA does not fit usize")?;
    let ctor_addr = unsafe { module.add(ctor_offset) };
    let ctor_fn: unsafe extern "system" fn(*mut u8) = unsafe { std::mem::transmute(ctor_addr) };
    unsafe { ctor_fn(this_ptr) };

    let object_offset = isize::try_from(*vtable_object_offset)
        .context("vtable object offset does not fit isize")?;
    let slot_index = usize::try_from(*vtable_slot).context("vtable slot does not fit usize")?;
    let call_this = unsafe { this_ptr.offset(object_offset) };
    // The vtable pointer sits at the object's head, pointer-aligned by the C++
    // ABI - a fact clippy cannot prove, so the alignment lint is allowed on just
    // this read.
    #[allow(clippy::cast_ptr_alignment)]
    let vtable_ptr = unsafe { *call_this.cast::<*const usize>() };
    let method_addr = unsafe { *vtable_ptr.add(slot_index) } as *const u8;

    let mut results = Vec::new();
    for candidate in *range_start..=*range_end {
        let mut out1: i32 = 0;
        let mut out2: i32 = 0;
        let hr: i32 = unsafe {
            match out_int_params {
                0 => {
                    let f: unsafe extern "system" fn(*mut u8, i32) -> i32 =
                        std::mem::transmute(method_addr);
                    f(call_this, candidate)
                }
                1 => {
                    let f: unsafe extern "system" fn(*mut u8, i32, *mut i32) -> i32 =
                        std::mem::transmute(method_addr);
                    f(call_this, candidate, &raw mut out1)
                }
                _ => {
                    let f: unsafe extern "system" fn(*mut u8, i32, *mut i32, *mut i32) -> i32 =
                        std::mem::transmute(method_addr);
                    f(call_this, candidate, &raw mut out1, &raw mut out2)
                }
            }
        };
        results.push(json!({
            "value": candidate,
            "hresult": hr,
            "succeeded": hr >= 0,
            "out1": out1,
            "out2": out2,
        }));
    }

    let dtor_offset = usize::try_from(*dtor_rva).context("dtor RVA does not fit usize")?;
    let dtor_addr = unsafe { module.add(dtor_offset) };
    let dtor_fn: unsafe extern "system" fn(*mut u8) = unsafe { std::mem::transmute(dtor_addr) };
    unsafe { dtor_fn(this_ptr) };

    let detail = json!({
        "class_name": class_name,
        "enum_name": enum_name,
        "results": results,
    })
    .to_string();
    Ok(ProbeObservation {
        id: id.clone(),
        status: "enum-range".into(),
        detail,
    })
}

#[cfg(not(windows))]
fn platform_probe(_binary: &Path, _manifest: &ProbeManifest) -> Result<Vec<ProbeObservation>> {
    anyhow::bail!("semantic runtime probing is Windows-only")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::BinaryInfo;

    #[test]
    fn sys_probe_is_rejected() {
        let db = Database {
            binary: BinaryInfo {
                sha256: Some("00".repeat(32)),
                ..Default::default()
            },
            ..Default::default()
        };
        let result = load_and_validate(&db, Path::new("driver.sys"), Path::new("missing.json"));
        assert!(result.unwrap_err().to_string().contains("DLL-only"));
    }

    #[test]
    fn enum_probe_rejects_unknown_class() {
        let db = Database {
            binary: BinaryInfo {
                sha256: Some("AA".repeat(32)),
                ..Default::default()
            },
            ..Default::default()
        };
        let manifest = ProbeManifest {
            schema: 1,
            binary_sha256: "AA".repeat(32),
            timeout_ms: 5_000,
            operations: vec![ProbeOperation::CallEnumProbe {
                id: "test".into(),
                class_name: "NoSuchClass".into(),
                enum_name: "NoSuchEnum".into(),
                object_size: 64,
                ctor_symbol_id: "ctor".into(),
                ctor_rva: 0,
                dtor_symbol_id: "dtor".into(),
                dtor_rva: 0,
                method_symbol_id: "method".into(),
                vtable_rva: 0,
                vtable_object_offset: 0,
                vtable_slot: 0,
                range_start: 0,
                range_end: 3,
                out_int_params: 2,
                acknowledge_side_effects: true,
            }],
        };
        let path =
            std::env::temp_dir().join(format!("windissect-enum-probe-{}.json", std::process::id()));
        std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let result = load_and_validate(&db, Path::new("target.dll"), &path);
        std::fs::remove_file(&path).unwrap();
        assert!(result.unwrap_err().to_string().contains("unknown class"));
    }

    #[test]
    fn enum_probe_rejects_large_range() {
        let db = Database {
            binary: BinaryInfo {
                sha256: Some("AA".repeat(32)),
                ..Default::default()
            },
            ..Default::default()
        };
        let manifest = ProbeManifest {
            schema: 1,
            binary_sha256: "AA".repeat(32),
            timeout_ms: 5_000,
            operations: vec![ProbeOperation::CallEnumProbe {
                id: "test".into(),
                class_name: "AnyClass".into(),
                enum_name: "AnyEnum".into(),
                object_size: 64,
                ctor_symbol_id: "ctor".into(),
                ctor_rva: 0,
                dtor_symbol_id: "dtor".into(),
                dtor_rva: 0,
                method_symbol_id: "method".into(),
                vtable_rva: 0,
                vtable_object_offset: 0,
                vtable_slot: 0,
                range_start: 0,
                range_end: 1000,
                out_int_params: 2,
                acknowledge_side_effects: true,
            }],
        };
        let path = std::env::temp_dir().join(format!(
            "windissect-enum-probe-range-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let result = load_and_validate(&db, Path::new("target.dll"), &path);
        std::fs::remove_file(&path).unwrap();
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("small and non-empty")
        );
    }

    #[test]
    fn enum_range_import_creates_verified_claim() {
        let mut db = Database {
            binary: BinaryInfo {
                sha256: Some("BB".repeat(32)),
                ..Default::default()
            },
            ..Default::default()
        };
        let observation = ProbeObservation {
            id: "auto:enum-test".into(),
            status: "enum-range".into(),
            detail: json!({
                "class_name": "SomeClass",
                "enum_name": "SomeEnum",
                "results": [
                    {"value": 0, "hresult": 0, "succeeded": true, "out1": 0, "out2": 0},
                    {"value": 1, "hresult": -2_147_024_809i64, "succeeded": false, "out1": 0, "out2": 0},
                    {"value": 2, "hresult": 0, "succeeded": true, "out1": 1, "out2": 0},
                ],
            })
            .to_string(),
        };
        let imported = import_enum_range(&mut db, &observation, "BB".repeat(32).as_str()).unwrap();
        assert_eq!(imported, 2);
        let enum_record = db
            .semantic
            .enums
            .iter()
            .find(|e| e.qualified_name == "SomeEnum")
            .expect("enum recorded");
        assert_eq!(enum_record.values.len(), 2);
        assert!(
            enum_record
                .values
                .iter()
                .all(|v| v.status == SemanticStatus::Verified)
        );
        assert!(db.claims.iter().any(
            |c| matches!(&c.subject, crate::model::ClaimSubject::EnumValue { owner, value, .. } if owner == "SomeEnum" && *value == 0)
        ));
        // Re-importing the same observation must not duplicate claims.
        let reimported =
            import_enum_range(&mut db, &observation, "BB".repeat(32).as_str()).unwrap();
        assert_eq!(reimported, 0);
        assert_eq!(db.semantic.enums.len(), 1);
        assert_eq!(db.semantic.enums[0].values.len(), 2);
    }

    #[cfg(not(windows))]
    #[test]
    fn unsupported_host_uses_static_fallback() {
        assert!(!runtime_supported());
    }

    #[cfg(windows)]
    #[test]
    fn windows_host_supports_runtime_probe() {
        assert!(runtime_supported());
    }

    #[test]
    fn static_refinement_records_explicit_probe_requirement() {
        let path = std::env::temp_dir().join(format!(
            "windissect-static-probe-{}.json",
            std::process::id()
        ));
        let db = Database {
            binary: BinaryInfo {
                sha256: Some("CC".repeat(32)),
                ..Default::default()
            },
            ..Default::default()
        };
        write_static_only(&db, &path).unwrap();
        let result: ProbeResult = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(result.observations.len(), 1);
        assert_eq!(result.observations[0].status, "static-only");
        assert!(result.observations[0].detail.contains("explicit"));
    }

    #[test]
    fn imported_return_is_a_proof_gated_claim() {
        let path = std::env::temp_dir().join(format!(
            "windissect-probe-import-{}.json",
            std::process::id()
        ));
        let result = ProbeResult {
            schema: 1,
            binary_sha256: "AA".repeat(32),
            observations: vec![ProbeObservation {
                id: "auto:test".into(),
                status: "returned".into(),
                detail: "0x2A".into(),
            }],
        };
        std::fs::write(&path, serde_json::to_vec(&result).unwrap()).unwrap();
        let expected_hash = result.binary_sha256;
        let mut db = Database {
            binary: BinaryInfo {
                sha256: Some(expected_hash),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(import_result(&mut db, &path).unwrap(), 1);
        assert_eq!(db.proven_claim_ids().len(), 1);
        assert_eq!(import_result(&mut db, &path).unwrap(), 0);
        std::fs::remove_file(path).unwrap();
    }
}
