//! Conservative PE data-flow evidence for class member offsets.
//!
//! This pass intentionally has a narrow proof rule: an instruction must access
//! memory through the incoming Windows x64 `this` register (RCX) or a proven
//! register alias derived from it.
//! Constructor writes and trivial accessor reads are retained as observations,
//! not upgraded into a complete C++ layout.  That makes stripped-PDB output
//! useful without turning optimizer artefacts into invented fields.

use crate::model::{
    Capability, CapabilityStatus, Claim, ClaimStatus, ClaimSubject, Database, Evidence,
    EvidenceKind, EvidenceLocation, EvidenceObservation, EvidenceTool, Kind, Proof,
    ProofObligation, Type, Usability,
};
use anyhow::{Context, Result};
use goblin::pe::PE;
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess,
    OpKind, Register,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Instant;

#[derive(Debug, Clone)]
struct Observation {
    offset: u64,
    width: usize,
    access: &'static str,
    symbol: String,
    rva: u32,
    instruction_rva: u32,
    suggested_name: Option<String>,
    confidence: &'static str,
    direct_accessor: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct BitFieldFact {
    owner: String,
    name: String,
    offset: u64,
    width: u32,
    bit_offset: u8,
    bit_size: u8,
    type_name: Option<String>,
    symbol: String,
    rva: u32,
    instruction_rva: u32,
}

struct AllocationTargets<'a> {
    vftable_addresses: &'a BTreeSet<u64>,
    vftable_owners: &'a BTreeMap<u64, BTreeSet<String>>,
    allocator_addresses: &'a BTreeSet<u64>,
    constructor_owners: &'a BTreeMap<u64, BTreeSet<String>>,
}

pub fn recover(db: &mut Database, pe_bytes: &[u8], retain_raw_observations: bool) -> Result<usize> {
    let mut phase_started = Instant::now();
    let pe = PE::parse(pe_bytes).context("parse PE for layout inference")?;
    if db.binary.machine.as_deref() != Some("0x8664") {
        return Ok(0);
    }
    let image_base = db.binary.image_base.unwrap_or(pe.image_base);
    let mut classes = BTreeMap::<String, Vec<Observation>>::new();
    let mut vftable_owners = BTreeMap::<u64, BTreeSet<String>>::new();
    for symbol in db
        .symbols
        .iter()
        .filter(|symbol| symbol.mangled.starts_with("??_7"))
    {
        let Some(owner) = symbol
            .demangled
            .as_deref()
            .and_then(crate::rtti::vftable_derived_name)
        else {
            continue;
        };
        vftable_owners
            .entry(symbol.vaddr)
            .or_default()
            .insert(owner.to_string());
    }
    let vftable_addresses = vftable_owners.keys().copied().collect();
    let allocator_addresses: BTreeSet<u64> = db
        .symbols
        .iter()
        .filter(|symbol| is_allocator_symbol(symbol))
        .map(|symbol| symbol.vaddr)
        .collect();
    let mut constructor_owners = BTreeMap::<u64, BTreeSet<String>>::new();
    for symbol in db.symbols.iter().filter(|symbol| symbol.kind == Kind::Ctor) {
        if let Some(owner) = qualified_class(symbol) {
            constructor_owners
                .entry(symbol.vaddr)
                .or_default()
                .insert(owner);
        }
    }
    collect_member_observations(db, pe_bytes, &pe, image_base, &mut classes);
    eprintln!(
        "[timing] layout-member-observations: {:.3}s",
        phase_started.elapsed().as_secs_f64()
    );
    phase_started = Instant::now();
    let bitfield_facts = collect_bitfield_facts(db, pe_bytes, &pe, image_base);
    eprintln!(
        "[timing] layout-bitfields: {:.3}s",
        phase_started.elapsed().as_secs_f64()
    );
    phase_started = Instant::now();
    let allocation_sizes = collect_allocation_sizes(
        db,
        pe_bytes,
        &pe,
        image_base,
        &AllocationTargets {
            vftable_addresses: &vftable_addresses,
            vftable_owners: &vftable_owners,
            allocator_addresses: &allocator_addresses,
            constructor_owners: &constructor_owners,
        },
    );
    eprintln!(
        "[timing] layout-allocations: {:.3}s",
        phase_started.elapsed().as_secs_f64()
    );
    phase_started = Instant::now();
    let (count, normalized_classes) =
        materialize_observations(db, classes, retain_raw_observations);
    let bitfield_count = add_bitfield_proofs(db, &bitfield_facts);
    let allocation_count = allocation_sizes.len();
    add_proof_graph(
        db,
        &normalized_classes,
        &allocation_sizes,
        retain_raw_observations,
    );
    eprintln!(
        "[timing] layout-proof-materialization: {:.3}s",
        phase_started.elapsed().as_secs_f64()
    );
    db.types.extend(allocation_sizes.into_values());
    db.type_recovery["pe_this_dataflow_observations"] = json!(count);
    db.type_recovery["pe_this_dataflow_observations_retained"] = json!(retain_raw_observations);
    db.type_recovery["pe_bitfield_proofs"] = json!(bitfield_count);
    db.type_recovery["pe_allocation_size_proofs"] = json!(allocation_count);
    db.capabilities.push(Capability {
        id: "layout-this-dataflow-x64".into(),
        status: CapabilityStatus::Partial,
        analyzer: "layoutinfer".into(),
        reason: format!(
            "{count} member observations, {bitfield_count} exact bitfields, and {allocation_count} allocation-size proofs"
        ),
    });
    Ok(count)
}

fn collect_member_observations(
    db: &Database,
    pe_bytes: &[u8],
    pe: &PE<'_>,
    image_base: u64,
    classes: &mut BTreeMap<String, Vec<Observation>>,
) {
    for symbol in &db.symbols {
        let Some(class) = qualified_class(symbol) else {
            continue;
        };
        if !symbol.is_code || symbol.rva == 0 || symbol.size == 0 {
            continue;
        }
        let is_ctor = symbol.kind == Kind::Ctor;
        let is_accessor = symbol.kind == Kind::Accessor
            && symbol.sig.storage.as_deref() != Some("static")
            && symbol.size <= 64;
        if symbol.sig.storage.as_deref() == Some("static") {
            continue;
        }
        let Some(start) = rva_to_offset(pe, symbol.rva) else {
            continue;
        };
        let len = usize::try_from(symbol.size).unwrap_or(0).min(4096);
        let Some(bytes) = pe_bytes.get(start..start.saturating_add(len)) else {
            continue;
        };
        let observations = analyze_instance_method(symbol, bytes, image_base, is_ctor, is_accessor);
        classes.entry(class).or_default().extend(observations);
    }
}

fn collect_bitfield_facts(
    db: &Database,
    pe_bytes: &[u8],
    pe: &PE<'_>,
    image_base: u64,
) -> Vec<BitFieldFact> {
    let mut facts = Vec::new();
    for symbol in &db.symbols {
        if symbol.kind != Kind::Accessor
            || symbol.sig.storage.as_deref() == Some("static")
            || !symbol.is_code
            || symbol.size == 0
            || symbol.size > 96
        {
            continue;
        }
        let Some(owner) = qualified_class(symbol) else {
            continue;
        };
        let Some(name) = bitfield_accessor_name(symbol) else {
            continue;
        };
        let Some(start) = rva_to_offset(pe, symbol.rva) else {
            continue;
        };
        let len = usize::try_from(symbol.size).unwrap_or(0).min(96);
        let Some(bytes) = pe_bytes.get(start..start.saturating_add(len)) else {
            continue;
        };
        let instructions = decode_instructions(bytes, image_base + u64::from(symbol.rva));
        let states = compute_this_states(&instructions);
        facts.extend(direct_bitfield_facts(
            symbol,
            &owner,
            &name,
            image_base,
            &instructions,
            &states,
        ));
    }
    facts.sort();
    facts.dedup();
    facts
}

fn bitfield_accessor_name(symbol: &crate::model::Symbol) -> Option<String> {
    let method = symbol.sig.method.as_deref()?;
    member_name(Some(method), "read").or_else(|| {
        let returns_bool = symbol
            .sig
            .ret
            .as_ref()
            .is_some_and(|ty| ty.text.trim() == "bool");
        (returns_bool && symbol.sig.params.is_empty()).then(|| method.to_string())
    })
}

fn direct_bitfield_facts(
    symbol: &crate::model::Symbol,
    owner: &str,
    name: &str,
    image_base: u64,
    instructions: &[Instruction],
    states: &[Option<Vec<(Register, i64)>>],
) -> Vec<BitFieldFact> {
    let mut facts = Vec::new();
    let mut info_factory = InstructionInfoFactory::new();
    for (index, (instruction, state)) in instructions.iter().zip(states).enumerate() {
        let Some(this_aliases) = state else {
            continue;
        };
        let bit_shape = shifted_returned_bits(instructions, index).or_else(|| {
            let bit = tested_bit_offset(instruction)?;
            condition_is_returned(instructions, index, instruction.mnemonic()).then_some((bit, 1))
        });
        let Some((bit_offset, bit_size)) = bit_shape else {
            continue;
        };
        for memory in info_factory.info(instruction).used_memory() {
            let Some((offset, access)) = observed_memory(this_aliases, memory) else {
                continue;
            };
            let width = u32::try_from(memory.memory_size().size()).unwrap_or(0);
            if access != "read"
                || width == 0
                || u32::from(bit_offset) + u32::from(bit_size) > width * 8
            {
                continue;
            }
            facts.push(BitFieldFact {
                owner: owner.into(),
                name: name.into(),
                offset,
                width,
                bit_offset,
                bit_size,
                type_name: symbol.sig.ret.as_ref().map(|ty| ty.text.clone()),
                symbol: symbol.id.clone(),
                rva: symbol.rva,
                instruction_rva: u32::try_from(instruction.ip().saturating_sub(image_base))
                    .unwrap_or(symbol.rva),
            });
        }
    }
    facts
}

fn shifted_returned_bits(instructions: &[Instruction], load_index: usize) -> Option<(u8, u8)> {
    let load = instructions.get(load_index)?;
    if !matches!(load.mnemonic(), Mnemonic::Mov | Mnemonic::Movzx)
        || load.op0_kind() != OpKind::Register
        || load.op0_register().full_register() != Register::RAX
        || load.op1_kind() != OpKind::Memory
    {
        return None;
    }
    let mut shift = None;
    let mut mask = None;
    for instruction in instructions.iter().skip(load_index + 1).take(4) {
        if matches!(
            instruction.flow_control(),
            FlowControl::Call | FlowControl::IndirectCall
        ) {
            return None;
        }
        if instruction.mnemonic() == Mnemonic::Shr
            && instruction.op0_kind() == OpKind::Register
            && instruction.op0_register().full_register() == Register::RAX
        {
            shift = instruction_immediate(instruction).and_then(|value| u8::try_from(value).ok());
        } else if instruction.mnemonic() == Mnemonic::And
            && instruction.op0_kind() == OpKind::Register
            && instruction.op0_register().full_register() == Register::RAX
        {
            mask = instruction_immediate(instruction);
        } else if instruction.flow_control() == FlowControl::Return {
            if let Some(mask) = mask {
                let contiguous_low_mask = mask != 0 && mask & mask.saturating_add(1) == 0;
                let bit_size = u8::try_from(mask.count_ones()).ok()?;
                return contiguous_low_mask.then_some((shift.unwrap_or(0), bit_size));
            }
            let shift = shift?;
            let register_width = return_register_width(load.op0_register())?;
            return (shift.checked_add(1) == Some(register_width)).then_some((shift, 1));
        } else if instruction.op0_kind() == OpKind::Register
            && instruction.op0_register().full_register() == Register::RAX
        {
            return None;
        }
    }
    None
}

const fn return_register_width(register: Register) -> Option<u8> {
    match register {
        Register::AL => Some(8),
        Register::AX => Some(16),
        Register::EAX => Some(32),
        Register::RAX => Some(64),
        _ => None,
    }
}

fn tested_bit_offset(instruction: &Instruction) -> Option<u8> {
    if instruction.op0_kind() != OpKind::Memory {
        return None;
    }
    let immediate = instruction_immediate(instruction)?;
    let bit = match instruction.mnemonic() {
        Mnemonic::Bt => immediate,
        Mnemonic::Test if immediate.is_power_of_two() => u64::from(immediate.trailing_zeros()),
        _ => return None,
    };
    u8::try_from(bit).ok()
}

fn instruction_immediate(instruction: &Instruction) -> Option<u64> {
    match instruction.op1_kind() {
        OpKind::Immediate8 => Some(u64::from(instruction.immediate8())),
        OpKind::Immediate16 => Some(u64::from(instruction.immediate16())),
        OpKind::Immediate32 => Some(u64::from(instruction.immediate32())),
        OpKind::Immediate32to64 => u64::try_from(instruction.immediate32to64()).ok(),
        OpKind::Immediate64 => Some(instruction.immediate64()),
        _ => None,
    }
}

fn condition_is_returned(
    instructions: &[Instruction],
    condition_index: usize,
    condition: Mnemonic,
) -> bool {
    instructions
        .iter()
        .skip(condition_index + 1)
        .take(4)
        .take_while(|instruction| instruction.flow_control() != FlowControl::Call)
        .any(|instruction| {
            instruction.op0_kind() == OpKind::Register
                && instruction.op0_register().full_register() == Register::RAX
                && matches!(
                    (condition, instruction.mnemonic()),
                    (Mnemonic::Test, Mnemonic::Sete | Mnemonic::Setne)
                        | (Mnemonic::Bt, Mnemonic::Setb | Mnemonic::Setae)
                )
        })
}

fn analyze_instance_method(
    symbol: &crate::model::Symbol,
    bytes: &[u8],
    image_base: u64,
    is_ctor: bool,
    is_accessor: bool,
) -> Vec<Observation> {
    let instructions = decode_instructions(bytes, image_base + u64::from(symbol.rva));
    let states = compute_this_states(&instructions);
    let mut observations = Vec::new();
    let mut info_factory = InstructionInfoFactory::new();
    for (instruction, state) in instructions.iter().zip(&states) {
        let Some(this_aliases) = state else {
            continue;
        };
        for memory in info_factory.info(instruction).used_memory() {
            let Some((offset, access)) = observed_memory(this_aliases, memory) else {
                continue;
            };
            if is_ctor && !matches!(access, "write" | "read-write") {
                continue;
            }
            observations.push(Observation {
                offset,
                width: memory.memory_size().size(),
                access,
                symbol: symbol.id.clone(),
                rva: symbol.rva,
                instruction_rva: u32::try_from(instruction.ip().saturating_sub(image_base))
                    .unwrap_or(symbol.rva),
                suggested_name: is_accessor
                    .then(|| member_name(symbol.sig.method.as_deref(), access))
                    .flatten(),
                confidence: if is_accessor { "certain" } else { "likely" },
                direct_accessor: false,
            });
        }
    }
    let slots: BTreeSet<_> = observations
        .iter()
        .map(|observation| (observation.offset, observation.width))
        .collect();
    let direct_slots = if is_accessor {
        direct_accessor_slots(&instructions, &states)
    } else {
        BTreeSet::new()
    };
    let single_slot_accessor = is_accessor
        && instructions.len() <= 16
        && slots.len() == 1
        && !instructions.iter().any(|instruction| {
            matches!(
                instruction.flow_control(),
                FlowControl::Call | FlowControl::IndirectCall
            ) || matches!(
                instruction.mnemonic(),
                Mnemonic::And
                    | Mnemonic::Or
                    | Mnemonic::Xor
                    | Mnemonic::Shl
                    | Mnemonic::Shr
                    | Mnemonic::Sar
                    | Mnemonic::Bt
                    | Mnemonic::Btc
                    | Mnemonic::Btr
                    | Mnemonic::Bts
            )
        });
    for observation in &mut observations {
        let is_direct_slot =
            direct_slots.contains(&(observation.offset, observation.width, observation.access));
        observation.direct_accessor =
            (single_slot_accessor || is_direct_slot) && observation.suggested_name.is_some();
        if !direct_slots.is_empty() && !is_direct_slot {
            observation.suggested_name = None;
        }
    }
    observations
}

fn direct_accessor_slots(
    instructions: &[Instruction],
    states: &[Option<Vec<(Register, i64)>>],
) -> BTreeSet<(u64, usize, &'static str)> {
    let mut slots = BTreeSet::new();
    let mut parameter_aliases = BTreeSet::from([Register::RDX, Register::XMM1]);
    let mut info_factory = InstructionInfoFactory::new();
    for (index, (instruction, state)) in instructions.iter().zip(states).enumerate() {
        let Some(this_aliases) = state else {
            continue;
        };
        let returns_loaded_value = matches!(
            instruction.mnemonic(),
            Mnemonic::Mov | Mnemonic::Movsx | Mnemonic::Movsxd | Mnemonic::Movzx
        ) && instruction.op0_kind() == OpKind::Register
            && instruction.op0_register().full_register() == Register::RAX
            && instruction.op1_kind() == OpKind::Memory
            && loaded_member_is_directly_returned(instructions, index);
        let source = instruction.op1_register().full_register();
        let stores_first_parameter = instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Memory
            && instruction.op1_kind() == OpKind::Register
            && parameter_aliases.contains(&source);
        if returns_loaded_value || stores_first_parameter {
            for memory in info_factory.info(instruction).used_memory() {
                let Some((offset, access)) = observed_memory(this_aliases, memory) else {
                    continue;
                };
                if returns_loaded_value && access == "read"
                    || stores_first_parameter && matches!(access, "write" | "read-write")
                {
                    slots.insert((offset, memory.memory_size().size(), access));
                }
            }
        }
        update_parameter_aliases(instruction, &mut parameter_aliases);
    }
    slots
}

fn loaded_member_is_directly_returned(instructions: &[Instruction], load_index: usize) -> bool {
    instructions
        .iter()
        .skip(load_index + 1)
        .take(16)
        .find_map(|instruction| {
            if instruction.flow_control() == FlowControl::Return {
                return Some(true);
            }
            if instruction.flow_control() != FlowControl::Next
                || instruction.op0_kind() == OpKind::Register
                    && instruction.op0_register().full_register() == Register::RAX
            {
                return Some(false);
            }
            None
        })
        .unwrap_or(false)
}

fn update_parameter_aliases(instruction: &Instruction, aliases: &mut BTreeSet<Register>) {
    if instruction.mnemonic() == Mnemonic::Call {
        for volatile in [
            Register::RAX,
            Register::RCX,
            Register::RDX,
            Register::R8,
            Register::R9,
            Register::R10,
            Register::R11,
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
            Register::XMM3,
            Register::XMM4,
            Register::XMM5,
        ] {
            aliases.remove(&volatile);
        }
        return;
    }
    if instruction.op0_kind() != OpKind::Register {
        return;
    }
    let destination = instruction.op0_register().full_register();
    let copied_alias = instruction.mnemonic() == Mnemonic::Mov
        && instruction.op1_kind() == OpKind::Register
        && aliases.contains(&instruction.op1_register().full_register());
    aliases.remove(&destination);
    if copied_alias {
        aliases.insert(destination);
    }
}

fn decode_instructions(bytes: &[u8], ip: u64) -> Vec<Instruction> {
    let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
    let mut instructions = Vec::new();
    while decoder.can_decode() && instructions.len() < 512 {
        instructions.push(decoder.decode());
    }
    instructions
}

fn compute_this_states(instructions: &[Instruction]) -> Vec<Option<Vec<(Register, i64)>>> {
    let mut states = vec![None; instructions.len()];
    if instructions.is_empty() {
        return states;
    }
    let indices: BTreeMap<u64, usize> = instructions
        .iter()
        .enumerate()
        .map(|(index, instruction)| (instruction.ip(), index))
        .collect();
    states[0] = Some(vec![(Register::RCX, 0)]);
    let mut pending = VecDeque::from([0usize]);
    while let Some(index) = pending.pop_front() {
        let mut output = states[index].clone().unwrap_or_default();
        update_this_aliases(&instructions[index], &mut output);
        output.sort_by_key(|(register, offset)| (*register as u32, *offset));
        for successor in instruction_successors(instructions, &indices, index) {
            let changed = merge_this_state(&mut states[successor], &output);
            if changed {
                pending.push_back(successor);
            }
        }
    }
    states
}

fn instruction_successors(
    instructions: &[Instruction],
    indices: &BTreeMap<u64, usize>,
    index: usize,
) -> Vec<usize> {
    let instruction = &instructions[index];
    let next = (index + 1 < instructions.len()).then_some(index + 1);
    let target = indices.get(&instruction.near_branch_target()).copied();
    match instruction.flow_control() {
        FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall => {
            next.into_iter().collect()
        }
        FlowControl::ConditionalBranch | FlowControl::XbeginXabortXend => {
            target.into_iter().chain(next).collect()
        }
        FlowControl::UnconditionalBranch => target.into_iter().collect(),
        FlowControl::IndirectBranch
        | FlowControl::Return
        | FlowControl::Interrupt
        | FlowControl::Exception => Vec::new(),
    }
}

fn merge_this_state(
    destination: &mut Option<Vec<(Register, i64)>>,
    incoming: &[(Register, i64)],
) -> bool {
    let Some(existing) = destination else {
        *destination = Some(incoming.to_vec());
        return true;
    };
    let merged: Vec<_> = existing
        .iter()
        .copied()
        .filter(|alias| incoming.contains(alias))
        .collect();
    if *existing == merged {
        false
    } else {
        *existing = merged;
        true
    }
}

fn observed_memory(
    aliases: &[(Register, i64)],
    memory: &iced_x86::UsedMemory,
) -> Option<(u64, &'static str)> {
    if memory.index() != Register::None {
        return None;
    }
    let base = alias_offset(aliases, memory.base())?;
    let effective = base.checked_add(memory.displacement().cast_signed())?;
    let offset = u64::try_from(effective).ok()?;
    (offset <= 0x10000)
        .then(|| observation_access(memory.access()).map(|access| (offset, access)))
        .flatten()
}

const fn observation_access(access: OpAccess) -> Option<&'static str> {
    match access {
        OpAccess::Read | OpAccess::CondRead => Some("read"),
        OpAccess::Write | OpAccess::CondWrite => Some("write"),
        OpAccess::ReadWrite | OpAccess::ReadCondWrite => Some("read-write"),
        OpAccess::None | OpAccess::NoMemAccess => None,
    }
}

fn collect_allocation_sizes(
    db: &Database,
    pe_bytes: &[u8],
    pe: &PE<'_>,
    image_base: u64,
    targets: &AllocationTargets<'_>,
) -> BTreeMap<String, Value> {
    let mut allocation_sizes = BTreeMap::<String, Value>::new();
    let mut ambiguous_owners = BTreeSet::new();
    for symbol in &db.symbols {
        if !symbol.is_code || symbol.size == 0 {
            continue;
        }
        let Some(start) = rva_to_offset(pe, symbol.rva) else {
            continue;
        };
        let len = usize::try_from(symbol.size).unwrap_or(0).min(1024);
        let Some(bytes) = pe_bytes.get(start..start.saturating_add(len)) else {
            continue;
        };
        let ip = image_base + u64::from(symbol.rva);
        let vftable_fact = allocation_size_proof(
            bytes,
            ip,
            targets.vftable_addresses,
            targets.allocator_addresses,
        )
        .and_then(|(size, vftable)| {
            unique_owner(targets.vftable_owners, vftable)
                .map(|owner| (owner.to_string(), size, "vftable", vftable))
        });
        let constructor_fact = constructor_allocation_size_proof(
            bytes,
            ip,
            targets.allocator_addresses,
            targets.constructor_owners,
        )
        .map(|(size, owner, constructor)| (owner, size, "constructor", constructor));
        if let Some((owner, size, identity, identity_address)) = vftable_fact.or(constructor_fact)
            && !ambiguous_owners.contains(owner.as_str())
        {
            let conflicting = allocation_sizes
                .get(owner.as_str())
                .and_then(|value| value.get("size"))
                .and_then(Value::as_u64)
                .is_some_and(|known_size| known_size != size);
            if conflicting {
                allocation_sizes.remove(owner.as_str());
                ambiguous_owners.insert(owner);
            } else {
                allocation_sizes.entry(owner.clone()).or_insert_with(|| {
                    json!({
                        "kind": "allocation-size-evidence",
                        "name": owner,
                        "size": size,
                        "identity": identity,
                        "identity_address": identity_address,
                        "source": format!("pe-allocation-{identity}-dataflow"),
                        "evidence_symbol": symbol.id,
                        "evidence_rva": symbol.rva,
                        "confidence": "certain",
                    })
                });
            }
        }
    }
    allocation_sizes
}

fn is_allocator_symbol(symbol: &crate::model::Symbol) -> bool {
    symbol.mangled.starts_with("??2@")
        || symbol
            .demangled
            .as_deref()
            .is_some_and(|name| name.contains("operator new("))
        || symbol.sig.method.as_deref().is_some_and(is_allocator_name)
            && symbol
                .sig
                .ret
                .as_ref()
                .is_some_and(|return_type| return_type.text.contains('*'))
            && !symbol.sig.params.is_empty()
}

fn is_allocator_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("alloc") && !lower.contains("dealloc")
}

fn unique_owner(owners_by_address: &BTreeMap<u64, BTreeSet<String>>, address: u64) -> Option<&str> {
    let owners = owners_by_address.get(&address)?;
    if owners.len() == 1 {
        owners.first().map(String::as_str)
    } else {
        None
    }
}

fn materialize_observations(
    db: &mut Database,
    classes: BTreeMap<String, Vec<Observation>>,
    retain_raw_observations: bool,
) -> (usize, BTreeMap<String, Vec<Observation>>) {
    let mut count = 0usize;
    let mut normalized_classes = BTreeMap::new();
    for (class, mut observations) in classes {
        observations.sort_by_key(|o| (o.offset, o.rva, o.symbol.clone()));
        observations.dedup_by(|a, b| {
            a.offset == b.offset
                && a.width == b.width
                && a.access == b.access
                && a.symbol == b.symbol
        });
        count += observations.len();
        if retain_raw_observations {
            let fields: Vec<Value> = observations
                .iter()
                .map(|o| {
                    json!({
                        "offset": o.offset,
                        "width": o.width,
                        "access": o.access,
                        "suggested_name": o.suggested_name,
                        "evidence_symbol": o.symbol,
                        "evidence_rva": o.rva,
                        "instruction_rva": o.instruction_rva,
                        "confidence": o.confidence,
                        "direct_accessor": o.direct_accessor,
                    })
                })
                .collect();
            db.types.push(json!({
                "kind": "layout-evidence",
                "name": class,
                "source": "pe-this-dataflow",
                "complete_layout": false,
                "note": "RCX-derived this-pointer observations only; gaps and object size are not inferred",
                "observations": fields,
            }));
        }
        normalized_classes.insert(class, observations);
    }
    (count, normalized_classes)
}

fn add_proof_graph(
    db: &mut Database,
    classes: &BTreeMap<String, Vec<Observation>>,
    allocation_sizes: &BTreeMap<String, Value>,
    retain_raw_observations: bool,
) {
    let mut phase_started = Instant::now();
    add_member_proofs(db, classes, retain_raw_observations);
    eprintln!(
        "[timing] layout-member-proofs: {:.3}s",
        phase_started.elapsed().as_secs_f64()
    );
    phase_started = Instant::now();
    add_allocation_proofs(db, allocation_sizes);
    eprintln!(
        "[timing] layout-allocation-proofs: {:.3}s",
        phase_started.elapsed().as_secs_f64()
    );
    phase_started = Instant::now();
    add_factory_base_proofs(db, allocation_sizes);
    eprintln!(
        "[timing] layout-factory-base-proofs: {:.3}s",
        phase_started.elapsed().as_secs_f64()
    );
}

fn add_member_proofs(
    db: &mut Database,
    classes: &BTreeMap<String, Vec<Observation>>,
    retain_raw_observations: bool,
) {
    for (owner, observations) in classes {
        let claim_start = db.claims.len();
        let named_slots = add_corroborated_named_field_proofs(db, owner, observations);
        add_corroborated_storage_proofs(db, owner, observations, &named_slots);
        let retained_evidence: BTreeSet<String> = db.claims[claim_start..]
            .iter()
            .flat_map(|claim| claim.evidence_ids.iter().cloned())
            .collect();
        for observation in observations {
            let evidence_id = member_evidence_id(owner, observation);
            if retain_raw_observations || retained_evidence.contains(evidence_id.as_str()) {
                db.evidence
                    .push(member_evidence(owner, observation, evidence_id.clone()));
            }
            if retain_raw_observations {
                add_raw_member_claim(db, owner, observation, evidence_id);
            }
        }
    }
}

fn member_evidence(owner: &str, observation: &Observation, id: String) -> Evidence {
    Evidence {
        id,
        kind: EvidenceKind::Dataflow,
        tool: EvidenceTool::Windissect,
        rule_id: "x64.this-member-access".into(),
        rule_version: 1,
        location: EvidenceLocation {
            symbol_id: Some(observation.symbol.clone()),
            rva: Some(observation.instruction_rva),
            size: None,
            instruction_rvas: vec![observation.instruction_rva],
        },
        observation: EvidenceObservation::MemberAccess {
            owner: owner.into(),
            offset: observation.offset,
            width: u32::try_from(observation.width).unwrap_or(0),
            access: observation.access.into(),
            suggested_name: observation.suggested_name.clone(),
        },
    }
}

fn add_raw_member_claim(
    db: &mut Database,
    owner: &str,
    observation: &Observation,
    evidence_id: String,
) {
    let proof_id = format!(
        "proof:member:{owner}:{:X}:{:X}",
        observation.instruction_rva, observation.offset
    );
    db.proofs.push(raw_member_proof(observation, &proof_id));
    db.claims.push(Claim {
        id: format!(
            "claim:member:{owner}:{:X}:{}:{}:{:X}",
            observation.offset, observation.width, observation.access, observation.instruction_rva
        ),
        subject: ClaimSubject::Member {
            owner: owner.into(),
            offset: observation.offset,
            width: u32::try_from(observation.width).unwrap_or(0),
            bit_offset: None,
            bit_size: None,
            type_name: None,
            name: observation.suggested_name.clone(),
            structural_only: true,
            access: observation.access.into(),
        },
        status: ClaimStatus::Observed,
        usability: Usability::MetadataOnly,
        evidence_ids: vec![evidence_id],
        proof_id: Some(proof_id),
    });
}

fn raw_member_proof(observation: &Observation, id: &str) -> Proof {
    Proof {
        id: id.into(),
        rule_id: "x64.this-member-access".into(),
        rule_version: 1,
        passed: true,
        obligations: vec![
            ProofObligation {
                name: "instance-method".into(),
                satisfied: true,
                detail: "static methods excluded".into(),
            },
            ProofObligation {
                name: "proven-this-alias".into(),
                satisfied: true,
                detail: "memory base derives from incoming RCX".into(),
            },
            ProofObligation {
                name: "bounded-offset".into(),
                satisfied: observation.offset <= 0x10000,
                detail: format!("offset 0x{:X}", observation.offset),
            },
        ],
    }
}

fn add_bitfield_proofs(db: &mut Database, facts: &[BitFieldFact]) -> usize {
    let mut shapes_by_name = BTreeMap::<(&str, &str), BTreeSet<(u64, u32, u8, u8)>>::new();
    let mut names_by_shape = BTreeMap::<(&str, u64, u32, u8, u8), BTreeSet<&str>>::new();
    for fact in facts {
        shapes_by_name
            .entry((&fact.owner, &fact.name))
            .or_default()
            .insert((fact.offset, fact.width, fact.bit_offset, fact.bit_size));
        names_by_shape
            .entry((
                &fact.owner,
                fact.offset,
                fact.width,
                fact.bit_offset,
                fact.bit_size,
            ))
            .or_default()
            .insert(&fact.name);
    }
    let mut count = 0;
    for fact in facts {
        let unique_name = shapes_by_name
            .get(&(fact.owner.as_str(), fact.name.as_str()))
            .is_some_and(|shapes| shapes.len() == 1);
        let unique_shape = names_by_shape
            .get(&(
                fact.owner.as_str(),
                fact.offset,
                fact.width,
                fact.bit_offset,
                fact.bit_size,
            ))
            .is_some_and(|names| names.len() == 1);
        if !unique_name || !unique_shape {
            continue;
        }
        if add_bitfield_proof(db, fact) {
            count += 1;
        }
    }
    count
}

fn add_bitfield_proof(db: &mut Database, fact: &BitFieldFact) -> bool {
    let evidence_id = format!(
        "ev:bitfield:{}:{}:{:X}:{}:{}",
        fact.owner, fact.name, fact.instruction_rva, fact.offset, fact.bit_offset
    );
    let proof_id = format!(
        "proof:bitfield:{}:{}:{:X}:{}",
        fact.owner, fact.name, fact.offset, fact.bit_offset
    );
    let claim_id = format!(
        "claim:bitfield:{}:{}:{:X}:{}:{}:{}",
        fact.owner, fact.name, fact.offset, fact.width, fact.bit_offset, fact.bit_size
    );
    if db.claims.iter().any(|claim| claim.id == claim_id) {
        return false;
    }
    db.evidence.push(bitfield_evidence(fact, &evidence_id));
    db.proofs.push(bitfield_proof(fact, &proof_id));
    db.claims.push(Claim {
        id: claim_id,
        subject: ClaimSubject::Member {
            owner: fact.owner.clone(),
            offset: fact.offset,
            width: fact.width,
            bit_offset: Some(fact.bit_offset),
            bit_size: Some(fact.bit_size),
            type_name: fact.type_name.clone(),
            name: Some(fact.name.clone()),
            structural_only: false,
            access: "read".into(),
        },
        status: ClaimStatus::Corroborated,
        usability: Usability::Verified,
        evidence_ids: vec![evidence_id],
        proof_id: Some(proof_id),
    });
    true
}

fn bitfield_evidence(fact: &BitFieldFact, evidence_id: &str) -> Evidence {
    Evidence {
        id: evidence_id.into(),
        kind: EvidenceKind::Dataflow,
        tool: EvidenceTool::Windissect,
        rule_id: "x64.direct-bitfield-getter".into(),
        rule_version: 1,
        location: EvidenceLocation {
            symbol_id: Some(fact.symbol.clone()),
            rva: Some(fact.rva),
            size: None,
            instruction_rvas: vec![fact.instruction_rva],
        },
        observation: EvidenceObservation::MemberAccess {
            owner: fact.owner.clone(),
            offset: fact.offset,
            width: fact.width,
            access: "read-bit".into(),
            suggested_name: Some(fact.name.clone()),
        },
    }
}

fn bitfield_proof(fact: &BitFieldFact, proof_id: &str) -> Proof {
    Proof {
        id: proof_id.into(),
        rule_id: "x64.direct-bitfield-getter".into(),
        rule_version: 1,
        passed: true,
        obligations: vec![
            ProofObligation {
                name: "proven-this-memory-bit-test".into(),
                satisfied: true,
                detail: format!(
                    "+0x{:X} bits {}..{} in a {}-byte access",
                    fact.offset,
                    fact.bit_offset,
                    fact.bit_offset + fact.bit_size - 1,
                    fact.width
                ),
            },
            ProofObligation {
                name: "condition-returned-by-accessor".into(),
                satisfied: true,
                detail: format!("{}::{} returns the tested condition", fact.owner, fact.name),
            },
            ProofObligation {
                name: "unique-name-and-bit".into(),
                satisfied: true,
                detail: "no conflicting exact getter mapping".into(),
            },
        ],
    }
}

fn member_evidence_id(owner: &str, observation: &Observation) -> String {
    format!(
        "ev:member:{owner}:{:X}:{:X}:{}:{}",
        observation.instruction_rva, observation.offset, observation.access, observation.width
    )
}

fn add_corroborated_storage_proofs(
    db: &mut Database,
    owner: &str,
    observations: &[Observation],
    named_slots: &BTreeSet<(u64, usize)>,
) {
    let mut observations_by_slot = BTreeMap::<(u64, usize), Vec<&Observation>>::new();
    for observation in observations
        .iter()
        .filter(|observation| observation.offset > 0 && (1..=16).contains(&observation.width))
    {
        observations_by_slot
            .entry((observation.offset, observation.width))
            .or_default()
            .push(observation);
    }
    for ((offset, width), slot_observations) in observations_by_slot {
        if named_slots.contains(&(offset, width)) {
            continue;
        }
        let source_functions: BTreeSet<u32> = slot_observations
            .iter()
            .map(|observation| observation.rva)
            .collect();
        let access_modes: BTreeSet<&str> = slot_observations
            .iter()
            .map(|observation| observation.access)
            .collect();
        let read_and_write = access_modes.contains("read-write")
            || (access_modes.contains("read") && access_modes.contains("write"));
        if source_functions.len() < 2 || (!read_and_write && source_functions.len() < 3) {
            continue;
        }
        add_storage_proof(
            db,
            owner,
            offset,
            u32::try_from(width).unwrap_or(0),
            &slot_observations,
            source_functions.len(),
            read_and_write,
        );
    }
}

fn add_corroborated_named_field_proofs(
    db: &mut Database,
    owner: &str,
    observations: &[Observation],
) -> BTreeSet<(u64, usize)> {
    let mut names_by_offset = BTreeMap::<u64, BTreeSet<&str>>::new();
    let mut shapes_by_name = BTreeMap::<&str, BTreeSet<(u64, usize)>>::new();
    let mut observations_by_field = BTreeMap::<(&str, u64, usize), Vec<&Observation>>::new();
    for observation in observations {
        let Some(name) = observation.suggested_name.as_deref() else {
            continue;
        };
        names_by_offset
            .entry(observation.offset)
            .or_default()
            .insert(name);
        shapes_by_name
            .entry(name)
            .or_default()
            .insert((observation.offset, observation.width));
        observations_by_field
            .entry((name, observation.offset, observation.width))
            .or_default()
            .push(observation);
    }
    let mut proven_slots = BTreeSet::new();
    for ((name, offset, width), field_observations) in observations_by_field {
        let source_functions: BTreeSet<u32> = field_observations
            .iter()
            .map(|observation| observation.rva)
            .collect();
        let access_modes: BTreeSet<&str> = field_observations
            .iter()
            .map(|observation| observation.access)
            .collect();
        let read_and_write = access_modes.contains("read-write")
            || (access_modes.contains("read") && access_modes.contains("write"));
        let direct_accessor = field_observations
            .iter()
            .any(|observation| observation.direct_accessor);
        let unique_name_at_offset = names_by_offset
            .get(&offset)
            .is_some_and(|names| names.len() == 1);
        let unique_shape_for_name = shapes_by_name
            .get(name)
            .is_some_and(|shapes| shapes.len() == 1);
        if (!read_and_write || source_functions.len() < 2) && !direct_accessor
            || !unique_name_at_offset
            || !unique_shape_for_name
            || width == 0
        {
            continue;
        }
        let type_name = recovered_field_type(db, &field_observations);
        add_named_field_proof(
            db,
            NamedFieldFact {
                owner,
                name,
                offset,
                width: u32::try_from(width).unwrap_or(0),
                observations: &field_observations,
                type_name: type_name.as_deref(),
                direct_accessor,
                read_and_write,
            },
        );
        proven_slots.insert((offset, width));
    }
    proven_slots
}

fn recovered_field_type(db: &Database, observations: &[&Observation]) -> Option<String> {
    let symbols: BTreeMap<&str, &crate::model::Symbol> = db
        .symbols
        .iter()
        .map(|symbol| (symbol.id.as_str(), symbol))
        .collect();
    let candidates: BTreeSet<String> = observations
        .iter()
        .filter_map(|observation| {
            let symbol = symbols.get(observation.symbol.as_str())?;
            if observation.access == "read" {
                symbol.sig.ret.as_ref().map(|ty| ty.text.trim().to_string())
            } else {
                symbol
                    .sig
                    .params
                    .first()
                    .map(|ty| ty.text.trim().to_string())
            }
        })
        .filter(|candidate| !candidate.is_empty() && candidate != "void")
        .collect();
    if candidates.len() == 1 {
        candidates.into_iter().next()
    } else {
        None
    }
}

#[derive(Clone, Copy)]
struct NamedFieldFact<'a> {
    owner: &'a str,
    name: &'a str,
    offset: u64,
    width: u32,
    observations: &'a [&'a Observation],
    type_name: Option<&'a str>,
    direct_accessor: bool,
    read_and_write: bool,
}

fn add_named_field_proof(db: &mut Database, fact: NamedFieldFact<'_>) {
    let NamedFieldFact {
        owner,
        name,
        offset,
        width,
        observations,
        type_name,
        direct_accessor,
        read_and_write,
    } = fact;
    let proof_id = format!("proof:named-field:{owner}:{name}:{offset:X}:{width}");
    let mut evidence_ids: Vec<String> = observations
        .iter()
        .map(|observation| member_evidence_id(owner, observation))
        .collect();
    evidence_ids.sort();
    evidence_ids.dedup();
    let rule_id = if direct_accessor {
        "x64.direct-accessor-field"
    } else {
        "x64.getter-setter-field"
    };
    let primary_obligation = if direct_accessor {
        ProofObligation {
            name: "straight-line-direct-accessor".into(),
            satisfied: true,
            detail: "call-free short accessor reaches exactly one object storage slot".into(),
        }
    } else {
        ProofObligation {
            name: "independent-getter-setter".into(),
            satisfied: true,
            detail: "distinct function RVAs read and write the same storage".into(),
        }
    };
    db.proofs.push(Proof {
        id: proof_id.clone(),
        rule_id: rule_id.into(),
        rule_version: 1,
        passed: true,
        obligations: vec![
            primary_obligation,
            ProofObligation {
                name: "unique-property-storage".into(),
                satisfied: true,
                detail: format!("{name} uniquely maps to +0x{offset:X} width {width}"),
            },
        ],
    });
    db.claims.push(Claim {
        id: format!("claim:named-field:{owner}:{name}:{offset:X}:{width}"),
        subject: ClaimSubject::Member {
            owner: owner.into(),
            offset,
            width,
            bit_offset: None,
            bit_size: None,
            type_name: type_name.map(str::to_string),
            name: Some(name.into()),
            structural_only: false,
            access: if read_and_write {
                "read-write".into()
            } else {
                observations[0].access.into()
            },
        },
        status: ClaimStatus::Corroborated,
        usability: Usability::Verified,
        evidence_ids,
        proof_id: Some(proof_id),
    });
}

fn add_storage_proof(
    db: &mut Database,
    owner: &str,
    offset: u64,
    width: u32,
    observations: &[&Observation],
    source_count: usize,
    read_and_write: bool,
) {
    let proof_id = format!("proof:storage:{owner}:{offset:X}:{width}");
    let mut evidence_ids: Vec<String> = observations
        .iter()
        .map(|observation| member_evidence_id(owner, observation))
        .collect();
    evidence_ids.sort();
    evidence_ids.dedup();
    db.proofs.push(Proof {
        id: proof_id.clone(),
        rule_id: "x64.corroborated-object-storage".into(),
        rule_version: 1,
        passed: true,
        obligations: vec![
            ProofObligation {
                name: "independent-instance-functions".into(),
                satisfied: source_count >= 2,
                detail: format!("{source_count} distinct functions"),
            },
            ProofObligation {
                name: "read-write-or-three-functions".into(),
                satisfied: read_and_write || source_count >= 3,
                detail: "guards against a repeated optimizer-local access".into(),
            },
            ProofObligation {
                name: "exact-access-width".into(),
                satisfied: true,
                detail: format!("{width}-byte accesses observed at +0x{offset:X}"),
            },
        ],
    });
    db.claims.push(Claim {
        id: format!("claim:storage:{owner}:{offset:X}:{width}"),
        subject: ClaimSubject::Member {
            owner: owner.into(),
            offset,
            width,
            bit_offset: None,
            bit_size: None,
            type_name: None,
            name: None,
            structural_only: true,
            access: if read_and_write {
                "read-write".into()
            } else {
                "observed".into()
            },
        },
        status: ClaimStatus::Corroborated,
        usability: Usability::Verified,
        evidence_ids,
        proof_id: Some(proof_id),
    });
}

fn add_allocation_proofs(db: &mut Database, allocation_sizes: &BTreeMap<String, Value>) {
    for (owner, value) in allocation_sizes {
        let size = value.get("size").and_then(Value::as_u64).unwrap_or(0);
        let identity = value
            .get("identity")
            .and_then(Value::as_str)
            .unwrap_or("vftable");
        let identity_address = value
            .get("identity_address")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let rva = value
            .get("evidence_rva")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(0);
        let symbol = value
            .get("evidence_symbol")
            .and_then(Value::as_str)
            .unwrap_or("");
        let evidence_id = format!("ev:object-size:{owner}:{rva:X}:{size:X}");
        let proof_id = format!("proof:object-size:{owner}:{rva:X}");
        let rule_id = format!("x64.allocation-{identity}-size");
        let observation = if identity == "constructor" {
            EvidenceObservation::AllocationConstructor {
                owner: owner.clone(),
                size,
                constructor: identity_address,
            }
        } else {
            EvidenceObservation::AllocationVtable {
                owner: owner.clone(),
                size,
                vftable: identity_address,
            }
        };
        db.evidence.push(Evidence {
            id: evidence_id.clone(),
            kind: EvidenceKind::Dataflow,
            tool: EvidenceTool::Windissect,
            rule_id: rule_id.clone(),
            rule_version: 1,
            location: EvidenceLocation {
                symbol_id: Some(symbol.into()),
                rva: Some(rva),
                size: None,
                instruction_rvas: vec![],
            },
            observation,
        });
        db.proofs.push(Proof {
            id: proof_id.clone(),
            rule_id,
            rule_version: 1,
            passed: true,
            obligations: vec![
                ProofObligation {
                    name: "bounded-allocation-immediate".into(),
                    satisfied: true,
                    detail: format!("0x{size:X} bytes"),
                },
                ProofObligation {
                    name: "returned-object-alias".into(),
                    satisfied: true,
                    detail: "allocator return tracked into object register".into(),
                },
                ProofObligation {
                    name: format!("same-class-{identity}"),
                    satisfied: identity_address != 0,
                    detail: format!("{owner} {identity} VA 0x{identity_address:X}"),
                },
            ],
        });
        db.claims.push(Claim {
            id: format!("claim:object-size:{owner}"),
            subject: ClaimSubject::ObjectSize {
                owner: owner.clone(),
                size,
            },
            status: ClaimStatus::Derived,
            usability: Usability::Verified,
            evidence_ids: vec![evidence_id],
            proof_id: Some(proof_id),
        });
    }
}

/// Recover a factory's erased interface relationship from its out-parameter.
///
/// MSVC often emits an abstract interface vftable and a concrete implementation
/// vftable without a usable RTTI locator.  A static factory taking `T**` and
/// writing an object whose exact-build allocation proof identifies `Concrete`
/// is still an independent ABI relationship: the factory's PDB signature names
/// the interface, while instruction/dataflow evidence names the implementation.
/// Keep this rule deliberately narrow so a similarly named method cannot invent
/// inheritance on its own.
fn add_factory_base_proofs(db: &mut Database, allocation_sizes: &BTreeMap<String, Value>) {
    let purecall_rvas: BTreeSet<u32> = db
        .symbols
        .iter()
        .filter(|symbol| symbol.mangled.contains("purecall") && symbol.is_code)
        .map(|symbol| symbol.rva)
        .collect();
    let abstract_bases = abstract_vtable_owners(db, &purecall_rvas);
    let object_claims: BTreeSet<String> = allocation_sizes
        .iter()
        .filter(|(owner, _)| value_has_nonzero_identity(allocation_sizes, owner))
        .map(|(owner, _)| owner.clone())
        .collect();
    let existing: BTreeSet<(String, String)> = db
        .claims
        .iter()
        .filter_map(|claim| match &claim.subject {
            ClaimSubject::Base { derived, base, .. } => Some((derived.clone(), base.clone())),
            _ => None,
        })
        .collect();
    let symbols: BTreeMap<&str, &crate::model::Symbol> = db
        .symbols
        .iter()
        .map(|symbol| (symbol.id.as_str(), symbol))
        .collect();
    let mut facts = Vec::new();
    for (derived, value) in allocation_sizes {
        if !object_claims.contains(derived) {
            continue;
        }
        let Some(factory_id) = value.get("evidence_symbol").and_then(Value::as_str) else {
            continue;
        };
        let Some(factory) = symbols.get(factory_id).copied() else {
            continue;
        };
        if factory.sig.storage.as_deref() != Some("static") || !factory.sig.parse_ok {
            continue;
        }
        let Some(base) = factory
            .sig
            .params
            .iter()
            .find_map(|param| output_interface_name(&param.ast))
        else {
            continue;
        };
        if base == *derived
            || !abstract_bases.contains(&base)
            || existing.contains(&(derived.clone(), base.clone()))
        {
            continue;
        }
        facts.push((derived.clone(), base, factory_id.to_string(), factory.rva));
    }
    for (derived, base, factory_id, factory_rva) in facts {
        add_factory_base_proof(
            db,
            allocation_sizes,
            factory_rva,
            &derived,
            &base,
            &factory_id,
        );
    }
}

fn abstract_vtable_owners(db: &Database, purecall_rvas: &BTreeSet<u32>) -> BTreeSet<String> {
    db.vtables
        .iter()
        .filter_map(|table| {
            let owner = table
                .get("demangled")
                .and_then(Value::as_str)
                .and_then(crate::rtti::vftable_derived_name)?;
            let entries = table.get("entries")?.as_array()?;
            (!entries.is_empty()
                && entries.iter().all(|entry| {
                    entry
                        .get("target_rva")
                        .and_then(Value::as_u64)
                        .and_then(|rva| u32::try_from(rva).ok())
                        .is_some_and(|rva| purecall_rvas.contains(&rva))
                }))
            .then(|| owner.to_owned())
        })
        .collect()
}

fn add_factory_base_proof(
    db: &mut Database,
    allocation_sizes: &BTreeMap<String, Value>,
    factory_rva: u32,
    derived: &str,
    base: &str,
    factory_id: &str,
) {
    let Some(object_evidence) = db.evidence.iter().find(|evidence| {
        evidence.rule_id.starts_with("x64.allocation-")
            && matches!(
                &evidence.observation,
                EvidenceObservation::AllocationVtable { owner, .. } if owner == derived
            )
    }) else {
        return;
    };
    let object_evidence = object_evidence.id.clone();
    let suffix = format!("{derived}:{base}:{factory_id}");
    let evidence_id = format!("ev:factory-base:{suffix}");
    let proof_id = format!("proof:factory-base:{suffix}");
    db.evidence.push(Evidence {
        id: evidence_id.clone(),
        kind: EvidenceKind::Dataflow,
        tool: EvidenceTool::Windissect,
        rule_id: "msvc.factory-output-base".into(),
        rule_version: 1,
        location: EvidenceLocation {
            symbol_id: Some(factory_id.into()),
            rva: Some(factory_rva),
            size: None,
            instruction_rvas: Vec::new(),
        },
        observation: EvidenceObservation::Text {
            text: format!("{factory_id} writes a {derived} object through {base}**"),
        },
    });
    let identity_ok = value_has_nonzero_identity(allocation_sizes, derived);
    db.proofs.push(Proof {
        id: proof_id.clone(),
        rule_id: "msvc.factory-output-base".into(),
        rule_version: 1,
        passed: identity_ok,
        obligations: vec![
            ProofObligation {
                name: "identity-matched-factory-signature".into(),
                satisfied: true,
                detail: format!("PDB signature of {factory_id} names {base}**"),
            },
            ProofObligation {
                name: "exact-build-object-allocation".into(),
                satisfied: true,
                detail: format!("allocation dataflow identifies {derived}"),
            },
            ProofObligation {
                name: "vftable-backed-concrete-type".into(),
                satisfied: identity_ok,
                detail: format!("concrete vftable identity for {derived}"),
            },
        ],
    });
    db.claims.push(Claim {
        id: format!("claim:factory-base:{suffix}"),
        subject: ClaimSubject::Base {
            derived: derived.into(),
            base: base.into(),
            offset: Some(0),
            is_virtual: false,
        },
        status: ClaimStatus::Derived,
        usability: Usability::Verified,
        evidence_ids: vec![object_evidence, evidence_id],
        proof_id: Some(proof_id),
    });
}

fn value_has_nonzero_identity(values: &BTreeMap<String, Value>, owner: &str) -> bool {
    values
        .get(owner)
        .and_then(|value| value.get("identity_address"))
        .and_then(Value::as_u64)
        .is_some_and(|address| address != 0)
}

fn output_interface_name(ty: &Type) -> Option<String> {
    let Type::Ptr { to } = ty else { return None };
    let Type::Ptr { to } = to.as_ref() else {
        return None;
    };
    let Type::Named { path, .. } = to.as_ref() else {
        return None;
    };
    (path.len() >= 2).then(|| path.join("::"))
}

fn allocation_size_proof(
    bytes: &[u8],
    ip: u64,
    vftable_addresses: &BTreeSet<u64>,
    allocator_addresses: &BTreeSet<u64>,
) -> Option<(u64, u64)> {
    let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
    let mut size_candidate = None;
    let mut allocation: Option<(u64, usize, Vec<Register>)> = None;
    let mut vftable_registers = Vec::<(Register, u64)>::new();
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Register
            && instruction.op0_register() == Register::ECX
            && matches!(
                instruction.op1_kind(),
                OpKind::Immediate8
                    | OpKind::Immediate16
                    | OpKind::Immediate32
                    | OpKind::Immediate32to64
            )
        {
            let value = u64::try_from(instruction.immediate32to64()).unwrap_or(0);
            if (8..=0x10_0000).contains(&value) {
                size_candidate = Some(value);
            }
        } else if instruction.mnemonic() == Mnemonic::Call
            && allocator_addresses.contains(&instruction.near_branch_target())
        {
            allocation = size_candidate
                .take()
                .map(|size| (size, 0, vec![Register::RAX]));
            vftable_registers.clear();
        }

        if instruction.mnemonic() == Mnemonic::Lea
            && instruction.op0_kind() == OpKind::Register
            && instruction.is_ip_rel_memory_operand()
            && vftable_addresses.contains(&instruction.ip_rel_memory_address())
        {
            vftable_registers.push((
                instruction.op0_register().full_register(),
                instruction.ip_rel_memory_address(),
            ));
        }

        if let Some((size, age, aliases)) = &mut allocation {
            *age += 1;
            if *age > 40 {
                allocation = None;
                continue;
            }
            if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register
                && aliases.contains(&instruction.op1_register().full_register())
            {
                let register = instruction.op0_register().full_register();
                if !aliases.contains(&register) {
                    aliases.push(register);
                }
            }
            if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Memory
                && instruction.memory_displacement64() == 0
                && aliases.contains(&instruction.memory_base().full_register())
                && instruction.op1_kind() == OpKind::Register
                && vftable_registers
                    .iter()
                    .any(|(register, _)| *register == instruction.op1_register().full_register())
            {
                let source = instruction.op1_register().full_register();
                let vftable = vftable_registers
                    .iter()
                    .rev()
                    .find_map(|(register, address)| (*register == source).then_some(*address))
                    .unwrap_or(0);
                return Some((*size, vftable));
            }
        }
    }
    None
}

fn constructor_allocation_size_proof(
    bytes: &[u8],
    ip: u64,
    allocator_addresses: &BTreeSet<u64>,
    constructor_owners: &BTreeMap<u64, BTreeSet<String>>,
) -> Option<(u64, String, u64)> {
    let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
    let mut size_candidate = None;
    let mut allocation: Option<(u64, usize, BTreeSet<Register>)> = None;
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Register
            && instruction.op0_register() == Register::ECX
            && matches!(
                instruction.op1_kind(),
                OpKind::Immediate8
                    | OpKind::Immediate16
                    | OpKind::Immediate32
                    | OpKind::Immediate32to64
            )
        {
            let value = u64::try_from(instruction.immediate32to64()).unwrap_or(0);
            if (8..=0x10_0000).contains(&value) {
                size_candidate = Some(value);
            }
        }

        if instruction.mnemonic() == Mnemonic::Call {
            let target = instruction.near_branch_target();
            if allocator_addresses.contains(&target) {
                allocation = size_candidate
                    .take()
                    .map(|size| (size, 0, BTreeSet::from([Register::RAX])));
                continue;
            }
            if let Some((size, _, aliases)) = &allocation
                && aliases.contains(&Register::RCX)
                && let Some(owner) = unique_owner(constructor_owners, target)
            {
                return Some((*size, owner.to_string(), target));
            }
        }

        let Some((_, age, aliases)) = &mut allocation else {
            continue;
        };
        *age += 1;
        if *age > 40 {
            allocation = None;
            continue;
        }
        update_object_aliases(&instruction, aliases);
    }
    None
}

fn update_object_aliases(instruction: &Instruction, aliases: &mut BTreeSet<Register>) {
    if instruction.mnemonic() == Mnemonic::Call {
        for volatile in [
            Register::RAX,
            Register::RCX,
            Register::RDX,
            Register::R8,
            Register::R9,
            Register::R10,
            Register::R11,
        ] {
            aliases.remove(&volatile);
        }
        return;
    }
    if instruction.op0_kind() != OpKind::Register {
        return;
    }
    let destination = instruction.op0_register().full_register();
    let copied_alias = instruction.mnemonic() == Mnemonic::Mov
        && instruction.op1_kind() == OpKind::Register
        && aliases.contains(&instruction.op1_register().full_register());
    aliases.remove(&destination);
    if copied_alias {
        aliases.insert(destination);
    }
}

fn member_name(method: Option<&str>, access: &str) -> Option<String> {
    let method = method?;
    let stem = if access == "write" {
        method.strip_prefix("Set")?
    } else {
        method
            .strip_prefix("Get")
            .or_else(|| method.strip_prefix("Is"))?
    };
    if stem.is_empty() {
        None
    } else {
        Some(stem.to_string())
    }
}

fn qualified_class(symbol: &crate::model::Symbol) -> Option<String> {
    let class = symbol.sig.class.as_deref()?;
    symbol
        .sig
        .namespace
        .as_deref()
        .filter(|namespace| !namespace.is_empty())
        .map_or_else(
            || Some(class.to_string()),
            |namespace| Some(format!("{namespace}::{class}")),
        )
}

fn alias_offset(aliases: &[(Register, i64)], register: Register) -> Option<i64> {
    let register = register.full_register();
    aliases
        .iter()
        .find_map(|(candidate, offset)| (*candidate == register).then_some(*offset))
}

fn set_alias(aliases: &mut Vec<(Register, i64)>, register: Register, offset: i64) {
    let register = register.full_register();
    aliases.retain(|(candidate, _)| *candidate != register);
    aliases.push((register, offset));
}

fn kill_alias(aliases: &mut Vec<(Register, i64)>, register: Register) {
    let register = register.full_register();
    aliases.retain(|(candidate, _)| *candidate != register);
}

fn update_this_aliases(instruction: &iced_x86::Instruction, aliases: &mut Vec<(Register, i64)>) {
    if instruction.mnemonic() == Mnemonic::Call {
        for volatile in [
            Register::RAX,
            Register::RCX,
            Register::RDX,
            Register::R8,
            Register::R9,
            Register::R10,
            Register::R11,
        ] {
            kill_alias(aliases, volatile);
        }
        return;
    }
    if instruction.op0_kind() != OpKind::Register {
        return;
    }
    let destination = instruction.op0_register().full_register();
    if instruction.mnemonic() == Mnemonic::Mov
        && instruction.op1_kind() == OpKind::Register
        && let Some(offset) = alias_offset(aliases, instruction.op1_register())
    {
        set_alias(aliases, destination, offset);
        return;
    }
    if instruction.mnemonic() == Mnemonic::Lea
        && instruction.op1_kind() == OpKind::Memory
        && instruction.memory_index() == Register::None
        && let Some(base) = alias_offset(aliases, instruction.memory_base())
    {
        let offset = base.wrapping_add(instruction.memory_displacement64().cast_signed());
        set_alias(aliases, destination, offset);
        return;
    }
    kill_alias(aliases, destination);
}

fn rva_to_offset(pe: &PE<'_>, rva: u32) -> Option<usize> {
    pe.sections.iter().find_map(|section| {
        let delta = rva.checked_sub(section.virtual_address)?;
        if delta >= section.size_of_raw_data {
            return None;
        }
        usize::try_from(section.pointer_to_raw_data.checked_add(delta)?).ok()
    })
}

#[cfg(test)]
mod tests {
    use super::{
        Observation, add_member_proofs, alias_offset, allocation_size_proof, compute_this_states,
        condition_is_returned, constructor_allocation_size_proof, decode_instructions,
        direct_accessor_slots, is_allocator_name, loaded_member_is_directly_returned, member_name,
        shifted_returned_bits, tested_bit_offset, unique_owner, update_this_aliases,
    };
    use crate::model::Database;
    use iced_x86::{Decoder, DecoderOptions, Register};
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn allocator_names_are_generic_but_exclude_deallocation() {
        assert!(is_allocator_name("HAllocAndZero"));
        assert!(is_allocator_name("AllocateObject"));
        assert!(is_allocator_name("calloc"));
        assert!(!is_allocator_name("DeallocateObject"));
        assert!(!is_allocator_name("CreateWidget"));
    }

    #[test]
    fn exact_memory_bit_test_return_is_recognized() {
        // test byte ptr [rcx+20h],4; setne al; ret
        let bytes = [0xF6, 0x41, 0x20, 0x04, 0x0F, 0x95, 0xC0, 0xC3];
        let instructions = decode_instructions(&bytes, 0x1000);
        assert_eq!(tested_bit_offset(&instructions[0]), Some(2));
        assert!(condition_is_returned(
            &instructions,
            0,
            instructions[0].mnemonic()
        ));
    }

    #[test]
    fn shifted_masked_member_bit_return_is_recognized() {
        // mov eax,[rcx+98h]; shr eax,6; and al,1; ret
        let bytes = [
            0x8B, 0x81, 0x98, 0, 0, 0, 0xC1, 0xE8, 0x06, 0x24, 0x01, 0xC3,
        ];
        let instructions = decode_instructions(&bytes, 0x1000);
        assert_eq!(shifted_returned_bits(&instructions, 0), Some((6, 1)));

        // mov al,[rcx+95h]; shr al,7; ret
        let top_bit = [0x8A, 0x81, 0x95, 0, 0, 0, 0xC0, 0xE8, 0x07, 0xC3];
        let instructions = decode_instructions(&top_bit, 0x2000);
        assert_eq!(shifted_returned_bits(&instructions, 0), Some((7, 1)));
    }

    #[test]
    fn nested_pointer_predicate_is_not_a_direct_field_getter() {
        // mov rax,[rcx+10h]; test rax,rax; jne nested; ret; mov al,[rax+8]; ret
        let bytes = [
            0x48, 0x8B, 0x41, 0x10, 0x48, 0x85, 0xC0, 0x75, 0x01, 0xC3, 0x8A, 0x40, 0x08, 0xC3,
        ];
        let instructions = decode_instructions(&bytes, 0x1000);
        assert!(!loaded_member_is_directly_returned(&instructions, 0));
    }

    #[test]
    fn direct_accessor_dataflow_ignores_incidental_this_accesses() {
        // mov r8,[rcx+8]; mov eax,[rcx+20h]; mov [rcx+28h],edx;
        // mov r9d,edx; mov [rcx+30h],r9d; ret
        let bytes = [
            0x4C, 0x8B, 0x41, 0x08, 0x8B, 0x41, 0x20, 0x89, 0x51, 0x28, 0x44, 0x8B, 0xCA, 0x44,
            0x89, 0x49, 0x30, 0xC3,
        ];
        let instructions = decode_instructions(&bytes, 0x1000);
        let states = compute_this_states(&instructions);
        let slots = direct_accessor_slots(&instructions, &states);
        assert_eq!(
            slots,
            BTreeSet::from([(0x20, 4, "read"), (0x28, 4, "write"), (0x30, 4, "write"),])
        );
    }

    #[test]
    fn only_names_getters_and_predicates() {
        assert_eq!(
            member_name(Some("GetParent"), "read").as_deref(),
            Some("Parent")
        );
        assert_eq!(
            member_name(Some("IsVisible"), "read").as_deref(),
            Some("Visible")
        );
        assert_eq!(
            member_name(Some("SetParent"), "write").as_deref(),
            Some("Parent")
        );
    }

    #[test]
    fn allocation_requires_vftable_store_into_returned_block() {
        // mov ecx,100h; call; mov rbx,rax; lea rax,[rip+10h]; mov [rbx],rax
        let bytes = [
            0xB9, 0x00, 0x01, 0x00, 0x00, 0xE8, 0, 0, 0, 0, 0x48, 0x8B, 0xD8, 0x48, 0x8D, 0x05,
            0x10, 0, 0, 0, 0x48, 0x89, 0x03,
        ];
        let mut tables = BTreeSet::new();
        tables.insert(0x1024);
        let allocators = BTreeSet::from([0x100A]);
        assert_eq!(
            allocation_size_proof(&bytes, 0x1000, &tables, &allocators),
            Some((0x100, 0x1024))
        );
        assert_eq!(
            allocation_size_proof(&bytes, 0x1000, &BTreeSet::new(), &allocators),
            None
        );
        assert_eq!(
            allocation_size_proof(&bytes, 0x1000, &tables, &BTreeSet::new()),
            None
        );
    }

    #[test]
    fn allocation_vftable_must_have_one_unambiguous_owner() {
        let owners = BTreeMap::from([(0x2000, BTreeSet::from(["Example::Actual".to_string()]))]);
        assert_eq!(unique_owner(&owners, 0x2000), Some("Example::Actual"));
        let ambiguous = BTreeMap::from([(
            0x2000,
            BTreeSet::from(["Example::First".to_string(), "Example::Second".to_string()]),
        )]);
        assert_eq!(unique_owner(&ambiguous, 0x2000), None);
    }

    #[test]
    fn allocation_followed_by_constructor_proves_object_size() {
        // mov ecx,100h; call allocator; mov rcx,rax; call constructor
        let bytes = [
            0xB9, 0x00, 0x01, 0x00, 0x00, 0xE8, 0, 0, 0, 0, 0x48, 0x8B, 0xC8, 0xE8, 0, 0, 0, 0,
        ];
        let allocators = BTreeSet::from([0x100A]);
        let constructors =
            BTreeMap::from([(0x1012, BTreeSet::from(["Example::Widget".to_string()]))]);
        assert_eq!(
            constructor_allocation_size_proof(&bytes, 0x1000, &allocators, &constructors),
            Some((0x100, "Example::Widget".to_string(), 0x1012))
        );
        assert_eq!(
            constructor_allocation_size_proof(&bytes, 0x1000, &BTreeSet::new(), &constructors),
            None
        );
    }

    #[test]
    fn independent_read_and_write_prove_an_unnamed_storage_slot() {
        let observations = vec![
            storage_observation("?Get@Widget@@", 0x1010, "read", 8),
            storage_observation("?Set@Widget@@", 0x1020, "write", 8),
        ];
        let mut db = Database::default();
        add_member_proofs(
            &mut db,
            &BTreeMap::from([("Example::Widget".into(), observations)]),
            false,
        );

        let storage = db
            .claims
            .iter()
            .find(|claim| claim.id.starts_with("claim:storage:"))
            .expect("corroborated storage claim");
        assert!(db.claim_is_proven(storage));
    }

    #[test]
    fn unique_getter_setter_pair_proves_named_field() {
        let mut getter = storage_observation("?GetValue@Widget@@", 0x1010, "read", 8);
        getter.suggested_name = Some("Value".into());
        let mut setter = storage_observation("?SetValue@Widget@@", 0x1020, "write", 8);
        setter.suggested_name = Some("Value".into());
        let mut db = Database::default();
        add_member_proofs(
            &mut db,
            &BTreeMap::from([("Example::Widget".into(), vec![getter, setter])]),
            false,
        );

        let field = db
            .claims
            .iter()
            .find(|claim| claim.id.starts_with("claim:named-field:"))
            .expect("named field claim");
        assert!(db.claim_is_proven(field));
        assert!(matches!(
            &field.subject,
            crate::model::ClaimSubject::Member { name: Some(name), .. } if name == "Value"
        ));
    }

    #[test]
    fn direct_single_slot_accessor_proves_named_field() {
        let mut getter = storage_observation("?GetValue@Widget@@", 0x1010, "read", 8);
        getter.suggested_name = Some("Value".into());
        getter.direct_accessor = true;
        let mut db = Database::default();
        add_member_proofs(
            &mut db,
            &BTreeMap::from([("Example::Widget".into(), vec![getter])]),
            false,
        );

        let field = db
            .claims
            .iter()
            .find(|claim| claim.id.starts_with("claim:named-field:"))
            .expect("direct accessor field claim");
        assert!(db.claim_is_proven(field));
        assert_eq!(
            db.proofs
                .iter()
                .find(|proof| proof.id.starts_with("proof:named-field:"))
                .map(|proof| proof.rule_id.as_str()),
            Some("x64.direct-accessor-field")
        );
    }

    #[test]
    fn competing_property_names_withhold_named_field() {
        let mut getter = storage_observation("?GetFirst@Widget@@", 0x1010, "read", 1);
        getter.suggested_name = Some("First".into());
        let mut setter = storage_observation("?SetFirst@Widget@@", 0x1020, "write", 1);
        setter.suggested_name = Some("First".into());
        let mut competing = storage_observation("?GetSecond@Widget@@", 0x1030, "read", 1);
        competing.suggested_name = Some("Second".into());
        let mut db = Database::default();
        add_member_proofs(
            &mut db,
            &BTreeMap::from([("Example::Widget".into(), vec![getter, setter, competing])]),
            false,
        );

        assert!(
            db.claims
                .iter()
                .all(|claim| !claim.id.starts_with("claim:named-field:"))
        );
    }

    #[test]
    fn independently_corroborated_access_width_survives_overlap() {
        let observations = vec![
            storage_observation("?One@Widget@@", 0x1010, "read", 4),
            storage_observation("?Two@Widget@@", 0x1020, "write", 4),
            storage_observation("?Three@Widget@@", 0x1030, "read", 8),
        ];
        let mut db = Database::default();
        add_member_proofs(
            &mut db,
            &BTreeMap::from([("Example::Widget".into(), observations)]),
            false,
        );

        let storage: Vec<_> = db
            .claims
            .iter()
            .filter(|claim| claim.id.starts_with("claim:storage:"))
            .collect();
        assert_eq!(storage.len(), 1);
        assert!(storage[0].id.ends_with(":4"));
    }

    fn storage_observation(
        symbol: &str,
        instruction_rva: u32,
        access: &'static str,
        width: usize,
    ) -> Observation {
        Observation {
            offset: 0x20,
            width,
            access,
            symbol: symbol.into(),
            rva: instruction_rva,
            instruction_rva,
            suggested_name: None,
            confidence: "certain",
            direct_accessor: false,
        }
    }

    #[test]
    fn calls_preserve_nonvolatile_this_aliases_only() {
        // mov rbx,rcx; mov r8,rcx; call rel32
        let bytes = [0x48, 0x8B, 0xD9, 0x4C, 0x8B, 0xC1, 0xE8, 0, 0, 0, 0];
        let mut decoder = Decoder::with_ip(64, &bytes, 0x1000, DecoderOptions::NONE);
        let mut aliases = vec![(Register::RCX, 0)];
        update_this_aliases(&decoder.decode(), &mut aliases);
        update_this_aliases(&decoder.decode(), &mut aliases);
        assert_eq!(alias_offset(&aliases, Register::RBX), Some(0));
        assert_eq!(alias_offset(&aliases, Register::R8), Some(0));
        update_this_aliases(&decoder.decode(), &mut aliases);
        assert_eq!(alias_offset(&aliases, Register::RBX), Some(0));
        assert_eq!(alias_offset(&aliases, Register::R8), None);
        assert_eq!(alias_offset(&aliases, Register::RCX), None);
    }

    #[test]
    fn cfg_merge_keeps_only_aliases_valid_on_every_path() {
        // mov rbx,rcx; test eax,eax; je join; mov rbx,rdx;
        // join: mov rax,[rbx+8]; ret
        let conflicting = [
            0x48, 0x8B, 0xD9, 0x85, 0xC0, 0x74, 0x03, 0x48, 0x8B, 0xDA, 0x48, 0x8B, 0x43, 0x08,
            0xC3,
        ];
        let instructions = decode_instructions(&conflicting, 0x1000);
        let states = compute_this_states(&instructions);
        let join = instructions
            .iter()
            .position(|instruction| instruction.ip() == 0x100A)
            .expect("join instruction");
        assert_eq!(
            alias_offset(states[join].as_deref().unwrap_or_default(), Register::RBX),
            None
        );

        // Replacing the clobber with equal-length NOPs preserves RBX on both
        // paths, so the join retains the proven this alias.
        let agreeing = [
            0x48, 0x8B, 0xD9, 0x85, 0xC0, 0x74, 0x03, 0x90, 0x90, 0x90, 0x48, 0x8B, 0x43, 0x08,
            0xC3,
        ];
        let instructions = decode_instructions(&agreeing, 0x1000);
        let states = compute_this_states(&instructions);
        let join = instructions
            .iter()
            .position(|instruction| instruction.ip() == 0x100A)
            .expect("join instruction");
        assert_eq!(
            alias_offset(states[join].as_deref().unwrap_or_default(), Register::RBX),
            Some(0)
        );
    }
}
