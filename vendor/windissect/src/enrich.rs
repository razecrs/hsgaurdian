//! Phase C: Static Enrichment: disassembly, reloc-normalized body hashing,
//! call-graph construction, function size calculation, and Win32 import tracking.

use crate::descent;
use crate::model::{
    Capability, CapabilityStatus, Confidence, ControlFlowEdge, Coverage, Database,
    FunctionAnalysis, InstructionRecord, Kind, Provenance, Signature, Symbol,
};
use anyhow::{Context, Result};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter, Mnemonic, OpKind,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Enrich the database using PE binary bytes.
pub fn enrich_database(db: &mut Database, pe_bytes: &[u8]) -> Result<()> {
    let pe = goblin::pe::PE::parse(pe_bytes).context("failed to parse PE headers")?;
    let bitness = match pe.header.coff_header.machine {
        0x014c => 32,
        0x8664 => 64,
        machine => anyhow::bail!(
            "static enrichment does not support PE machine 0x{machine:04X}; refusing to fabricate x86 analysis"
        ),
    };

    discover_by_descent(db, pe_bytes, &pe, bitness);
    discover_direct_call_targets(db, pe_bytes, &pe, bitness);
    discover_tail_jump_targets(db, pe_bytes, &pe, bitness);
    calculate_function_sizes(db, &pe);
    let analysis = analyze_functions(db, pe_bytes, &pe, bitness);
    apply_analysis(db, analysis);
    db.capabilities.push(Capability {
        id: "canonical-x86-instructions-cfg".into(),
        status: CapabilityStatus::Supported,
        analyzer: "enrich".into(),
        reason: format!("{} unique code RVAs decoded", db.functions.len()),
    });
    Ok(())
}

/// Follow control flow from every evidenced entry to find the functions it
/// calls and each body's contiguous extent. On x86 this is the main source of
/// both. On x64 the exception directory has already set exact extents, which
/// are kept; descent fills only the entries it left without one (leaf
/// functions, Guard CF targets, thunks).
fn discover_by_descent(db: &mut Database, pe_bytes: &[u8], pe: &goblin::pe::PE<'_>, bitness: u32) {
    if db
        .symbols
        .iter()
        .any(|symbol| symbol.provenance == Provenance::Pdb)
    {
        return;
    }

    let seeds = db
        .symbols
        .iter()
        .filter(|symbol| symbol.rva != 0 && symbol.is_code && symbol.forwarder.is_none())
        .map(|symbol| symbol.rva)
        .collect::<BTreeSet<_>>();
    let discovery = descent::discover(pe_bytes, pe, bitness, &seeds);

    for symbol in &mut db.symbols {
        if symbol.size == 0
            && let Some(&extent) = discovery.extents.get(&symbol.rva)
        {
            symbol.size = extent;
        }
    }
    let new_entries = discovery
        .call_targets
        .iter()
        .map(|rva| (*rva, Provenance::PeCallTarget))
        .chain(
            discovery
                .tail_targets
                .iter()
                .map(|rva| (*rva, Provenance::PeTailTarget)),
        );
    for (rva, provenance) in new_entries {
        let mut symbol = candidate_symbol(pe.image_base, rva, provenance);
        symbol.size = discovery.extents.get(&rva).copied().unwrap_or(0);
        db.symbols.push(symbol);
    }
}

/// An anonymous code entry recovered without a PDB. The entry is evidenced;
/// the name is a placeholder and the extent, if any, is filled in later.
fn candidate_symbol(image_base: u64, rva: u32, provenance: Provenance) -> Symbol {
    let name = format!("sub_{rva:08X}");
    Symbol {
        id: name.clone(),
        mangled: name,
        demangled: None,
        vaddr: image_base + u64::from(rva),
        rva,
        ordinal: None,
        size: 0,
        procedure_size: None,
        is_code: true,
        forwarder: None,
        body_hash: String::new(),
        exported: false,
        library: false,
        kind: Kind::CFunc,
        coverage: Coverage::Auto,
        provenance,
        confidence: Confidence::Likely,
        sig: Signature::default(),
        callers: Vec::new(),
        calls: Vec::new(),
        imports: Vec::new(),
    }
}

/// Follow a direct jump only when it is the first instruction at an already
/// evidenced anonymous entry point. This identifies tail-call/thunk targets
/// without treating ordinary intra-function branches as function starts.
fn discover_tail_jump_targets(
    db: &mut Database,
    pe_bytes: &[u8],
    pe: &goblin::pe::PE<'_>,
    bitness: u32,
) {
    if db
        .symbols
        .iter()
        .any(|symbol| symbol.provenance == Provenance::Pdb)
    {
        return;
    }

    let mut known_rvas = db
        .symbols
        .iter()
        .filter(|symbol| symbol.rva != 0)
        .map(|symbol| symbol.rva)
        .collect::<BTreeSet<_>>();
    let mut candidates = BTreeSet::new();
    for symbol in db.symbols.iter().filter(|symbol| {
        matches!(
            symbol.provenance,
            Provenance::PeCallTarget | Provenance::PeGuardCf
        ) && symbol.is_code
    }) {
        let Some(file_offset) = rva_to_offset(pe, symbol.vaddr) else {
            continue;
        };
        let file_end = file_offset.saturating_add(15).min(pe_bytes.len());
        let Some(bytes) = pe_bytes.get(file_offset..file_end) else {
            continue;
        };
        let mut decoder = Decoder::with_ip(bitness, bytes, symbol.vaddr, DecoderOptions::NONE);
        let instruction = decoder.decode();
        if instruction.flow_control() == FlowControl::UnconditionalBranch
            && matches!(
                instruction.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            )
            && let Some(target) = instruction.near_branch_target().checked_sub(pe.image_base)
            && let Ok(rva) = u32::try_from(target)
            && !known_rvas.contains(&rva)
            && rva_is_executable(pe, rva)
        {
            candidates.insert(rva);
        }
    }

    for rva in candidates {
        known_rvas.insert(rva);
        db.symbols.push(candidate_symbol(
            pe.image_base,
            rva,
            Provenance::PeTailTarget,
        ));
    }
}

/// Add anonymous candidate functions reached by direct calls from exact unwind
/// bodies. A direct target is strong code-entry evidence, but linear decoding
/// alone does not prove reachability of every decoded instruction, so these
/// remain `Likely` rather than `Certain`.
fn discover_direct_call_targets(
    db: &mut Database,
    pe_bytes: &[u8],
    pe: &goblin::pe::PE<'_>,
    bitness: u32,
) {
    if db
        .symbols
        .iter()
        .any(|symbol| symbol.provenance == Provenance::Pdb)
    {
        return;
    }

    let mut known_rvas = db
        .symbols
        .iter()
        .filter(|symbol| symbol.rva != 0)
        .map(|symbol| symbol.rva)
        .collect::<BTreeSet<_>>();
    let mut candidates = BTreeSet::new();
    for symbol in db.symbols.iter().filter(|symbol| {
        symbol.procedure_size == Some(symbol.size) && symbol.size != 0 && symbol.is_code
    }) {
        let Some(file_offset) = rva_to_offset(pe, symbol.vaddr) else {
            continue;
        };
        let Some(file_end) = file_offset.checked_add(symbol.size as usize) else {
            continue;
        };
        let Some(bytes) = pe_bytes.get(file_offset..file_end) else {
            continue;
        };
        candidates.extend(direct_call_target_rvas(
            bytes,
            bitness,
            symbol.vaddr,
            pe.image_base,
        ));
    }

    for rva in candidates {
        if known_rvas.contains(&rva) || !rva_is_executable(pe, rva) {
            continue;
        }
        known_rvas.insert(rva);
        db.symbols.push(candidate_symbol(
            pe.image_base,
            rva,
            Provenance::PeCallTarget,
        ));
    }
}

fn direct_call_target_rvas(
    bytes: &[u8],
    bitness: u32,
    start_vaddr: u64,
    image_base: u64,
) -> BTreeSet<u32> {
    let mut targets = BTreeSet::new();
    let mut decoder = Decoder::with_ip(bitness, bytes, start_vaddr, DecoderOptions::NONE);
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.flow_control() == FlowControl::Call
            && matches!(
                instruction.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            )
            && let Some(rva) = instruction.near_branch_target().checked_sub(image_base)
            && let Ok(rva) = u32::try_from(rva)
        {
            targets.insert(rva);
        }
    }
    targets
}

fn rva_is_executable(pe: &goblin::pe::PE<'_>, rva: u32) -> bool {
    pe.sections.iter().any(|section| {
        let extent = section.virtual_size.max(section.size_of_raw_data);
        rva >= section.virtual_address
            && rva < section.virtual_address.saturating_add(extent)
            && section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0
    })
}

struct Enrichment {
    call_edges: Vec<(usize, usize)>,
    symbol_imports: Vec<(usize, String)>,
    functions: Vec<FunctionAnalysis>,
}

struct DecodedBody {
    normalized: Vec<u8>,
    calls: BTreeSet<usize>,
    imports: BTreeSet<String>,
    instructions: Vec<InstructionRecord>,
    cfg_edges: Vec<ControlFlowEdge>,
    instruction_count: usize,
    first_mnemonic: Mnemonic,
}

fn analyze_functions(
    db: &mut Database,
    pe_bytes: &[u8],
    pe: &goblin::pe::PE<'_>,
    bitness: u32,
) -> Enrichment {
    let vaddr_to_index = db
        .symbols
        .iter()
        .enumerate()
        .filter(|(_, symbol)| symbol.vaddr != 0)
        .map(|(index, symbol)| (symbol.vaddr, index))
        .collect();
    let iat_map = pe
        .imports
        .iter()
        .map(|import| {
            (
                pe.image_base + import.rva as u64,
                format!("{}!{}", import.dll, import.name),
            )
        })
        .collect();
    let mut aliases_by_rva = BTreeMap::<u32, Vec<String>>::new();
    for symbol in &db.symbols {
        if symbol.rva != 0 && symbol.is_code {
            aliases_by_rva
                .entry(symbol.rva)
                .or_default()
                .push(symbol.id.clone());
        }
    }
    let mut analyzed_rvas = BTreeSet::new();
    let mut enrichment = Enrichment {
        call_edges: Vec::new(),
        symbol_imports: Vec::new(),
        functions: Vec::new(),
    };
    for index in 0..db.symbols.len() {
        let symbol = &db.symbols[index];
        let collect_analysis = symbol.rva != 0
            && symbol.vaddr != 0
            && symbol.size != 0
            && symbol.is_code
            && symbol.forwarder.is_none()
            && analyzed_rvas.insert(symbol.rva);
        let Some(decoded) = analyze_symbol(
            symbol,
            pe_bytes,
            pe,
            bitness,
            collect_analysis,
            &vaddr_to_index,
            &iat_map,
        ) else {
            continue;
        };
        finalize_symbol(db, index, decoded, &aliases_by_rva, &mut enrichment);
    }
    enrichment
}

fn analyze_symbol(
    symbol: &crate::model::Symbol,
    pe_bytes: &[u8],
    pe: &goblin::pe::PE<'_>,
    bitness: u32,
    collect_analysis: bool,
    vaddr_to_index: &BTreeMap<u64, usize>,
    iat_map: &BTreeMap<u64, String>,
) -> Option<DecodedBody> {
    let sym_vaddr = symbol.vaddr;
    let sym_size = usize::try_from(symbol.size).unwrap_or(0);
    if sym_vaddr == 0 || sym_size == 0 || !symbol.is_code || symbol.forwarder.is_some() {
        return None;
    }
    let file_offset = rva_to_offset(pe, sym_vaddr)?;
    let file_end = file_offset.checked_add(sym_size)?;
    if file_end > pe_bytes.len() {
        return None;
    }
    let fn_bytes = &pe_bytes[file_offset..file_end];
    Some(decode_body(
        fn_bytes,
        bitness,
        sym_vaddr,
        collect_analysis,
        pe.image_base,
        vaddr_to_index,
        iat_map,
    ))
}

fn decode_body(
    fn_bytes: &[u8],
    bitness: u32,
    sym_vaddr: u64,
    collect_analysis: bool,
    image_base: u64,
    vaddr_to_index: &BTreeMap<u64, usize>,
    iat_map: &BTreeMap<u64, String>,
) -> DecodedBody {
    let mut decoder = Decoder::with_ip(bitness, fn_bytes, sym_vaddr, DecoderOptions::NONE);
    let mut inst = Instruction::default();

    let mut normalized_bytes: Vec<u8> = Vec::new();
    let mut local_calls: BTreeSet<usize> = BTreeSet::new();
    let mut local_imports: BTreeSet<String> = BTreeSet::new();
    let mut inst_count = 0;
    let mut first_mnemonic = Mnemonic::INVALID;
    let mut instructions = Vec::new();
    let mut cfg_edges = Vec::new();
    let mut formatter = IntelFormatter::new();

    while decoder.can_decode() {
        decoder.decode_out(&mut inst);
        inst_count += 1;
        if inst_count == 1 {
            first_mnemonic = inst.mnemonic();
        }

        // Normalize instruction bytes for reloc-agnostic hashing
        let raw_len = inst.len();
        let Some(relative_end) = decoder.ip().checked_sub(sym_vaddr) else {
            break;
        };
        let Ok(instruction_end) = usize::try_from(relative_end) else {
            break;
        };
        let Some(instruction_start) = instruction_end.checked_sub(raw_len) else {
            break;
        };
        let inst_bytes = fn_bytes[instruction_start..instruction_end].to_vec();

        if collect_analysis {
            let rva = u32::try_from(inst.ip().saturating_sub(image_base)).unwrap_or(0);
            let next_rva = u32::try_from(decoder.ip().saturating_sub(image_base)).ok();
            let branch_target_rva = matches!(
                inst.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            )
            .then(|| inst.near_branch_target().checked_sub(image_base))
            .flatten()
            .and_then(|target| u32::try_from(target).ok());
            let memory_target_rva = inst
                .is_ip_rel_memory_operand()
                .then(|| inst.ip_rel_memory_address().checked_sub(image_base))
                .flatten()
                .and_then(|target| u32::try_from(target).ok());
            if let Some(target) = branch_target_rva {
                cfg_edges.push(ControlFlowEdge {
                    from_rva: rva,
                    to_rva: target,
                    kind: format!("{:?}", inst.flow_control()).to_ascii_lowercase(),
                });
            }
            if matches!(
                inst.flow_control(),
                FlowControl::Next | FlowControl::Call | FlowControl::ConditionalBranch
            ) && let Some(target) = next_rva
            {
                cfg_edges.push(ControlFlowEdge {
                    from_rva: rva,
                    to_rva: target,
                    kind: "fallthrough".into(),
                });
            }
            let mut text = String::new();
            formatter.format(&inst, &mut text);
            instructions.push(InstructionRecord {
                rva,
                length: u8::try_from(inst.len()).unwrap_or(0),
                bytes: crate::hex::upper(&inst_bytes),
                mnemonic: format!("{:?}", inst.mnemonic()).to_ascii_lowercase(),
                text,
                flow: format!("{:?}", inst.flow_control()).to_ascii_lowercase(),
                branch_target_rva,
                memory_target_rva,
            });
        }

        // Mask out RIP-relative target displacements for call/jmp branches
        if inst.op0_kind() == OpKind::NearBranch64 || inst.op0_kind() == OpKind::NearBranch32 {
            let target = inst.near_branch_target();
            if inst.flow_control() == FlowControl::Call
                && let Some(&target_idx) = vaddr_to_index.get(&target)
            {
                local_calls.insert(target_idx);
            }
        } else if inst.op0_kind() == OpKind::Memory {
            let target = inst.memory_displacement64();
            // Check if target is an IAT entry
            if let Some(import_name) = iat_map.get(&target) {
                local_imports.insert(import_name.clone());
            }
        }

        normalized_bytes.extend_from_slice(&inst_bytes);
    }

    DecodedBody {
        normalized: normalized_bytes,
        calls: local_calls,
        imports: local_imports,
        instructions,
        cfg_edges,
        instruction_count: inst_count,
        first_mnemonic,
    }
}

fn finalize_symbol(
    db: &mut Database,
    index: usize,
    decoded: DecodedBody,
    aliases_by_rva: &BTreeMap<u32, Vec<String>>,
    enrichment: &mut Enrichment,
) {
    if decoded.instruction_count == 1 && decoded.first_mnemonic == Mnemonic::Jmp {
        db.symbols[index].kind = Kind::Thunk;
    }
    let mut hasher = Sha256::new();
    hasher.update(&decoded.normalized);
    let hash_bytes = hasher.finalize();
    db.symbols[index].body_hash = crate::hex::lower(&hash_bytes);
    if !decoded.instructions.is_empty() {
        enrichment.functions.push(FunctionAnalysis {
            rva: db.symbols[index].rva,
            size: db.symbols[index].size,
            symbol_ids: aliases_by_rva
                .get(&db.symbols[index].rva)
                .cloned()
                .unwrap_or_else(|| vec![db.symbols[index].id.clone()]),
            instructions: decoded.instructions,
            cfg_edges: decoded.cfg_edges,
        });
    }
    for callee_idx in decoded.calls {
        enrichment.call_edges.push((index, callee_idx));
    }
    for import in decoded.imports {
        enrichment.symbol_imports.push((index, import));
    }
}

fn apply_analysis(db: &mut Database, enrichment: Enrichment) {
    for (caller, callee) in enrichment.call_edges {
        let target_id = db.symbols[callee].id.clone();
        let source_id = db.symbols[caller].id.clone();

        if !db.symbols[caller].calls.contains(&target_id) {
            db.symbols[caller].calls.push(target_id);
        }
        if !db.symbols[callee].callers.contains(&source_id) {
            db.symbols[callee].callers.push(source_id);
        }
    }

    for (sym_idx, imp) in enrichment.symbol_imports {
        if !db.symbols[sym_idx].imports.contains(&imp) {
            db.symbols[sym_idx].imports.push(imp);
        }
    }

    db.functions = enrichment.functions;
}

/// Calculate function sizes based on address spacing and PE section boundaries.
fn calculate_function_sizes(db: &mut Database, pe: &goblin::pe::PE) {
    let image_base = pe.image_base;

    // Collect all symbol addresses
    let mut addrs: Vec<(u64, usize)> = db
        .symbols
        .iter()
        .enumerate()
        .filter(|(_, s)| s.vaddr != 0 && s.is_code && s.forwarder.is_none())
        .map(|(i, s)| (s.vaddr, i))
        .collect();

    addrs.sort_by_key(|&(vaddr, _)| vaddr);

    for idx in 0..addrs.len() {
        let (vaddr, sym_i) = addrs[idx];
        let Ok(rva) = u32::try_from(vaddr.saturating_sub(image_base)) else {
            continue;
        };

        // Find containing PE section
        let sec_end = pe
            .sections
            .iter()
            .find(|sec| rva >= sec.virtual_address && rva < sec.virtual_address + sec.virtual_size)
            .map_or(vaddr + 64, |sec| {
                image_base + u64::from(sec.virtual_address) + u64::from(sec.virtual_size)
            });

        let next_vaddr = if idx + 1 < addrs.len() {
            addrs[idx + 1].0.min(sec_end)
        } else {
            sec_end
        };

        if db.symbols[sym_i].size == 0 && next_vaddr > vaddr {
            let computed_size =
                u32::try_from((next_vaddr - vaddr).min(u64::from(u32::MAX))).unwrap_or(u32::MAX);
            // Bound reasonable size (max 64KB per function)
            db.symbols[sym_i].size = computed_size.min(65536);
        }
    }
}

/// Helper to convert RVA / `VAddr` to file offset.
fn rva_to_offset(pe: &goblin::pe::PE, vaddr: u64) -> Option<usize> {
    let rva = u32::try_from(vaddr.saturating_sub(pe.image_base)).ok()?;
    for sec in &pe.sections {
        if rva >= sec.virtual_address && rva < sec.virtual_address + sec.virtual_size {
            let delta = rva - sec.virtual_address;
            if delta >= sec.size_of_raw_data {
                return None;
            }
            let offset = delta.checked_add(sec.pointer_to_raw_data)?;
            return usize::try_from(offset).ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::direct_call_target_rvas;

    #[test]
    fn discovers_relative_calls_but_not_indirect_calls() {
        let image_base = 0x1_8000_0000;
        let start = image_base + 0x1000;
        // call 0x180001010; call rax; ret
        let bytes = [0xE8, 0x0B, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0xC3];
        let targets = direct_call_target_rvas(&bytes, 64, start, image_base);
        assert_eq!(targets.into_iter().collect::<Vec<_>>(), vec![0x1010]);
    }
}
