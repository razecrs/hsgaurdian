//! Recursive-descent function discovery for images without unwind metadata.
//!
//! An x64 image lists every non-leaf function in its exception directory, so
//! entry points and extents come straight from linker-authored records. An x86
//! image has no such table: the only metadata-proven entries are exports, the
//! Guard CF and `SafeSEH` tables and the image entry point. Everything else has
//! to be reached by following control flow from those seeds.
//!
//! Descent follows conditional and unconditional branches inside a function,
//! queues direct call targets as new functions, and stops a path at `ret`,
//! `int3` padding, an undecodable byte, or a jump into another known entry
//! (a tail call). A `jmp [index*4 + table]` switch is followed only through
//! table slots that a base relocation covers, so a table is never read past
//! its relocated entries. The results are evidence of reachable code, not
//! linker records, and callers mark them `Likely`.

use goblin::pe::PE;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind, Register};
use std::collections::{BTreeMap, BTreeSet};

/// Upper bound on instructions decoded for one function; a body larger than
/// this is treated as runaway decoding rather than followed further.
const MAX_FUNCTION_INSTRUCTIONS: usize = 100_000;

/// Upper bound on entries read from one switch table.
const MAX_JUMP_TABLE_ENTRIES: usize = 4096;

/// `IMAGE_REL_BASED_HIGHLOW`: a 32-bit absolute address fixup.
const REL_BASED_HIGHLOW: u8 = 3;

/// `IMAGE_REL_BASED_DIR64`: a 64-bit absolute address fixup.
const REL_BASED_DIR64: u8 = 10;

/// Functions reached by descent.
#[derive(Debug, Default)]
pub struct Discovery {
    /// Entry RVA mapped to the length of the contiguous body that starts there.
    pub extents: BTreeMap<u32, u32>,
    /// Entries that were not seeds and were reached only through direct calls.
    pub call_targets: BTreeSet<u32>,
    /// Entries reached only as the target of a thunk: a function whose first
    /// instruction is a direct `jmp`.
    pub tail_targets: BTreeSet<u32>,
}

struct Image<'a> {
    bytes: &'a [u8],
    pe: &'a PE<'a>,
    bitness: u32,
    relocated_slots: BTreeSet<u32>,
}

/// Discover functions reachable from `seeds` and measure each one's
/// contiguous extent.
///
/// Discovery runs to a fixpoint first, so that extents are measured against
/// the final entry set: a body stops where it would run into another entry.
pub fn discover(bytes: &[u8], pe: &PE<'_>, bitness: u32, seeds: &BTreeSet<u32>) -> Discovery {
    let image = Image {
        bytes,
        pe,
        bitness,
        relocated_slots: relocated_slots(pe),
    };

    let mut entries = seeds
        .iter()
        .copied()
        .filter(|rva| image.is_executable(*rva))
        .collect::<BTreeSet<_>>();
    let mut pending = entries.iter().copied().collect::<Vec<_>>();
    let mut call_targets = BTreeSet::new();
    let mut tail_targets = BTreeSet::new();
    while let Some(entry) = pending.pop() {
        let body = image.explore(entry, &entries);
        for target in body.calls {
            if entries.insert(target) {
                call_targets.insert(target);
                pending.push(target);
            }
        }
        if let Some(target) = body.thunk_target
            && entries.insert(target)
        {
            tail_targets.insert(target);
            pending.push(target);
        }
    }

    let extents = entries
        .iter()
        .map(|entry| (*entry, image.explore(*entry, &entries).extent))
        .collect();
    Discovery {
        extents,
        call_targets,
        tail_targets,
    }
}

struct Body {
    extent: u32,
    calls: BTreeSet<u32>,
    thunk_target: Option<u32>,
}

impl Image<'_> {
    fn explore(&self, entry: u32, entries: &BTreeSet<u32>) -> Body {
        // Instruction start RVA mapped to its end RVA.
        let mut decoded = BTreeMap::<u32, u32>::new();
        let mut calls = BTreeSet::new();
        let mut pending = vec![entry];
        let mut thunk_target = None;
        let mut budget = MAX_FUNCTION_INSTRUCTIONS;

        while let Some(start) = pending.pop() {
            let mut rva = start;
            loop {
                if decoded.contains_key(&rva) || (rva != entry && entries.contains(&rva)) {
                    break;
                }
                let Some(instruction) = self.decode(rva) else {
                    break;
                };
                if budget == 0 {
                    return Body {
                        extent: 0,
                        calls,
                        thunk_target: None,
                    };
                }
                budget -= 1;
                let Ok(length) = u32::try_from(instruction.len()) else {
                    break;
                };
                let end = rva.saturating_add(length);
                decoded.insert(rva, end);

                match instruction.flow_control() {
                    FlowControl::Next
                    | FlowControl::XbeginXabortXend
                    | FlowControl::IndirectCall => {}
                    FlowControl::Call => {
                        if let Some(target) = self.near_target(&instruction) {
                            calls.insert(target);
                        }
                    }
                    FlowControl::ConditionalBranch => {
                        if let Some(target) = self.near_target(&instruction) {
                            pending.push(target);
                        }
                    }
                    FlowControl::UnconditionalBranch => {
                        let target = self.near_target(&instruction);
                        if rva == entry {
                            // A body that is a single jmp is a thunk; its
                            // target is a function of its own.
                            thunk_target = target.filter(|target| *target != entry);
                        } else if let Some(target) = target
                            && (target == entry || !entries.contains(&target))
                        {
                            pending.push(target);
                        }
                        break;
                    }
                    FlowControl::IndirectBranch => {
                        pending.extend(self.jump_table_targets(&instruction));
                        break;
                    }
                    FlowControl::Return | FlowControl::Interrupt | FlowControl::Exception => {
                        break;
                    }
                }
                rva = end;
            }
        }

        // The extent is the run of instructions that is contiguous from the
        // entry. Blocks placed elsewhere (cold paths before the entry or past a
        // gap) belong to the function but are not part of a single extent.
        let mut end = entry;
        for (&start, &stop) in decoded.range(entry..) {
            if start > end {
                break;
            }
            end = end.max(stop);
        }
        Body {
            extent: end - entry,
            calls,
            thunk_target,
        }
    }

    fn decode(&self, rva: u32) -> Option<Instruction> {
        if !self.is_executable(rva) {
            return None;
        }
        let offset = self.file_offset(rva)?;
        let bytes = self
            .bytes
            .get(offset..offset.saturating_add(15).min(self.bytes.len()))?;
        let mut decoder = Decoder::with_ip(
            self.bitness,
            bytes,
            self.pe.image_base + u64::from(rva),
            DecoderOptions::NONE,
        );
        let instruction = decoder.decode();
        (!instruction.is_invalid()).then_some(instruction)
    }

    fn near_target(&self, instruction: &Instruction) -> Option<u32> {
        if !matches!(
            instruction.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        ) {
            return None;
        }
        let rva = u32::try_from(
            instruction
                .near_branch_target()
                .checked_sub(self.pe.image_base)?,
        )
        .ok()?;
        self.is_executable(rva).then_some(rva)
    }

    /// Resolve `jmp [index*4 + table]`, the x86 MSVC switch dispatch. Each
    /// slot must carry a base relocation, which is what marks it as an
    /// absolute code address rather than whatever follows the table.
    fn jump_table_targets(&self, instruction: &Instruction) -> Vec<u32> {
        if self.bitness != 32
            || instruction.op0_kind() != OpKind::Memory
            || instruction.memory_base() != Register::None
            || instruction.memory_index() == Register::None
            || instruction.memory_index_scale() != 4
        {
            return Vec::new();
        }
        let Some(table) = u64::from(instruction.memory_displacement32())
            .checked_sub(self.pe.image_base)
            .and_then(|rva| u32::try_from(rva).ok())
        else {
            return Vec::new();
        };

        let mut targets = Vec::new();
        for index in 0..MAX_JUMP_TABLE_ENTRIES {
            let Some(slot) = u32::try_from(index * 4)
                .ok()
                .and_then(|delta| table.checked_add(delta))
            else {
                break;
            };
            if !self.relocated_slots.contains(&slot) {
                break;
            }
            let Some(target) = self
                .read_u32(slot)
                .and_then(|address| u64::from(address).checked_sub(self.pe.image_base))
                .and_then(|rva| u32::try_from(rva).ok())
                .filter(|rva| self.is_executable(*rva))
            else {
                break;
            };
            targets.push(target);
        }
        targets
    }

    fn read_u32(&self, rva: u32) -> Option<u32> {
        let offset = self.file_offset(rva)?;
        let bytes = self.bytes.get(offset..offset.checked_add(4)?)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn file_offset(&self, rva: u32) -> Option<usize> {
        self.pe.sections.iter().find_map(|section| {
            let delta = rva.checked_sub(section.virtual_address)?;
            if delta >= section.size_of_raw_data {
                return None;
            }
            usize::try_from(section.pointer_to_raw_data.checked_add(delta)?).ok()
        })
    }

    fn is_executable(&self, rva: u32) -> bool {
        self.pe.sections.iter().any(|section| {
            let extent = section.virtual_size.max(section.size_of_raw_data);
            rva >= section.virtual_address
                && rva < section.virtual_address.saturating_add(extent)
                && section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0
        })
    }
}

/// RVAs of every absolute-address fixup in the base relocation table.
fn relocated_slots(pe: &PE<'_>) -> BTreeSet<u32> {
    let Some(relocations) = pe.relocation_data.as_ref() else {
        return BTreeSet::new();
    };
    let mut slots = BTreeSet::new();
    for block in relocations.blocks().flatten() {
        for word in block.words().flatten() {
            if matches!(word.reloc_type(), REL_BASED_HIGHLOW | REL_BASED_DIR64) {
                slots.insert(block.rva.saturating_add(u32::from(word.offset())));
            }
        }
    }
    slots
}

#[cfg(test)]
mod tests {
    use super::discover;
    use goblin::pe::PE;
    use std::collections::BTreeSet;

    const TEXT_RVA: u32 = 0x1000;
    const TEXT_FILE_OFFSET: usize = 0x200;

    /// Build a minimal PE32 image whose single executable section holds `code`
    /// at RVA 0x1000.
    fn x86_image(code: &[u8]) -> Vec<u8> {
        fn put(image: &mut [u8], at: usize, bytes: &[u8]) {
            image[at..at + bytes.len()].copy_from_slice(bytes);
        }
        let mut image = vec![0u8; TEXT_FILE_OFFSET + 0x200];
        put(&mut image, 0, b"MZ");
        put(&mut image, 0x3C, &0x40u32.to_le_bytes());
        put(&mut image, 0x40, b"PE\0\0");
        // COFF header: i386, one section, PE32 optional header, executable DLL.
        put(&mut image, 0x44, &0x014Cu16.to_le_bytes());
        put(&mut image, 0x46, &1u16.to_le_bytes());
        put(&mut image, 0x54, &0xE0u16.to_le_bytes());
        put(&mut image, 0x56, &0x2102u16.to_le_bytes());
        // Optional header.
        let optional = 0x58;
        put(&mut image, optional, &0x010Bu16.to_le_bytes());
        put(&mut image, optional + 28, &0x1000_0000u32.to_le_bytes());
        put(&mut image, optional + 32, &0x1000u32.to_le_bytes());
        put(&mut image, optional + 36, &0x200u32.to_le_bytes());
        put(&mut image, optional + 56, &0x2000u32.to_le_bytes());
        put(&mut image, optional + 60, &0x200u32.to_le_bytes());
        put(&mut image, optional + 92, &16u32.to_le_bytes());
        // Section header: .text, code | execute | read.
        let section = optional + 0xE0;
        put(&mut image, section, b".text\0\0\0");
        put(&mut image, section + 8, &0x200u32.to_le_bytes());
        put(&mut image, section + 12, &TEXT_RVA.to_le_bytes());
        put(&mut image, section + 16, &0x200u32.to_le_bytes());
        put(&mut image, section + 20, &0x200u32.to_le_bytes());
        put(&mut image, section + 36, &0x6000_0020u32.to_le_bytes());
        put(&mut image, TEXT_FILE_OFFSET, code);
        image
    }

    #[test]
    fn follows_calls_branches_and_thunks_to_exact_extents() {
        let mut code = vec![0xCCu8; 0x50];
        // 0x1000: call 0x1010; ret
        code[0x00..0x06].copy_from_slice(&[0xE8, 0x0B, 0x00, 0x00, 0x00, 0xC3]);
        // 0x1010: test eax, eax; jz 0x1015; nop; ret
        code[0x10..0x16].copy_from_slice(&[0x85, 0xC0, 0x74, 0x01, 0x90, 0xC3]);
        // 0x1030: ret (reached only through the thunk below)
        code[0x30] = 0xC3;
        // 0x1040: jmp 0x1030
        code[0x40..0x45].copy_from_slice(&[0xE9, 0xEB, 0xFF, 0xFF, 0xFF]);

        let bytes = x86_image(&code);
        let pe = PE::parse(&bytes).expect("synthetic PE parses");
        let seeds = BTreeSet::from([0x1000, 0x1040]);
        let discovery = discover(&bytes, &pe, 32, &seeds);

        assert_eq!(discovery.call_targets, BTreeSet::from([0x1010]));
        assert_eq!(discovery.tail_targets, BTreeSet::from([0x1030]));
        assert_eq!(
            discovery.extents.into_iter().collect::<Vec<_>>(),
            vec![(0x1000, 6), (0x1010, 6), (0x1030, 1), (0x1040, 5)]
        );
    }

    #[test]
    fn stops_a_body_at_another_known_entry() {
        let mut code = vec![0xCCu8; 0x20];
        // 0x1000: nop; nop -- falls straight into the entry at 0x1002
        code[0x00..0x02].copy_from_slice(&[0x90, 0x90]);
        // 0x1002: ret
        code[0x02] = 0xC3;

        let bytes = x86_image(&code);
        let pe = PE::parse(&bytes).expect("synthetic PE parses");
        let discovery = discover(&bytes, &pe, 32, &BTreeSet::from([0x1000, 0x1002]));

        assert_eq!(discovery.extents.get(&0x1000), Some(&2));
        assert_eq!(discovery.extents.get(&0x1002), Some(&1));
    }
}
