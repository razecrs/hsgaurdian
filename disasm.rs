use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, NasmFormatter};

use crate::memory::format_hex;

#[derive(Clone, Debug)]
pub struct DisassemblyLine {
    pub address: usize,
    pub bytes: Vec<u8>,
    pub text: String,
    pub branch_target: Option<usize>,
    pub is_call: bool,
}

pub fn disassemble(bytes: &[u8], address: usize, bitness: u32) -> Vec<DisassemblyLine> {
    let mut decoder = Decoder::with_ip(bitness, bytes, address as u64, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    let mut output = String::new();
    let mut lines = Vec::new();

    while decoder.can_decode() {
        let instruction = decoder.decode();
        let start = (instruction.ip() as usize).saturating_sub(address);
        let length = instruction.len();
        if length == 0 || start.saturating_add(length) > bytes.len() {
            break;
        }

        output.clear();
        formatter.format(&instruction, &mut output);
        let flow = instruction.flow_control();
        let branch_target = matches!(
            flow,
            FlowControl::Call | FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch
        )
        .then(|| instruction.near_branch_target() as usize);

        lines.push(DisassemblyLine {
            address: instruction.ip() as usize,
            bytes: bytes[start..start + length].to_vec(),
            text: output.clone(),
            branch_target,
            is_call: flow == FlowControl::Call,
        });
    }

    lines
}

pub fn render_line(line: &DisassemblyLine) -> String {
    format!(
        "{:016X}  {:<30} {}",
        line.address,
        format_hex(&line.bytes),
        line.text
    )
}

#[cfg(test)]
mod tests {
    use super::disassemble;

    #[test]
    fn decodes_x64_instructions() {
        let lines = disassemble(&[0x48, 0x89, 0xD8, 0xC3], 0x140001000, 64);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].text.contains("mov"));
        assert_eq!(lines[1].text, "ret");
    }
}
