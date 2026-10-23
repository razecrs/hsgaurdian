use std::{
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    process::Command,
};

use iced_x86::{Decoder, DecoderOptions, InstructionInfoFactory, OpAccess};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::memory::ModuleInfo;

#[derive(Clone, Debug, Deserialize)]
pub struct IrBinary {
    pub file: String,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub image_base: Option<u64>,
    #[serde(default)]
    pub image_size: Option<u64>,
    #[serde(default)]
    pub machine: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct IrSymbol {
    pub id: String,
    pub mangled: String,
    #[serde(default)]
    pub demangled: Option<String>,
    #[serde(default)]
    pub rva: u32,
    #[serde(default)]
    pub size: u32,
    #[serde(default)]
    pub is_code: bool,
    #[serde(default)]
    pub exported: bool,
    #[serde(default)]
    pub confidence: String,
    #[serde(default)]
    pub provenance: String,
}

impl IrSymbol {
    pub fn display_name(&self) -> &str {
        self.demangled.as_deref().unwrap_or(&self.mangled)
    }
}

#[derive(Clone, Debug, Deserialize)]
struct IrInstruction {
    rva: u32,
    #[serde(default)]
    bytes: String,
    #[serde(default)]
    mnemonic: String,
    #[serde(default)]
    text: String,
    #[serde(default)]
    flow: String,
    #[serde(default)]
    branch_target_rva: Option<u32>,
    #[serde(default)]
    memory_target_rva: Option<u32>,
}

#[derive(Clone, Debug, Deserialize)]
struct IrFunction {
    rva: u32,
    #[serde(default)]
    size: u32,
    #[serde(default)]
    symbol_ids: Vec<String>,
    #[serde(default)]
    instructions: Vec<IrInstruction>,
}

#[derive(Deserialize)]
struct IrDatabase {
    schema: u32,
    binary: IrBinary,
    #[serde(default)]
    symbols: Vec<IrSymbol>,
    #[serde(default)]
    functions: Vec<IrFunction>,
}

#[derive(Clone, Debug)]
pub struct Xref {
    pub address: usize,
    pub kind: String,
    pub instruction: String,
    pub function: String,
}

#[derive(Clone, Debug)]
pub struct LoadedIr {
    pub path: PathBuf,
    pub schema: u32,
    pub binary: IrBinary,
    pub symbols: Vec<IrSymbol>,
    functions: Vec<IrFunction>,
    pub module_base: usize,
    pub exact_build_match: Option<bool>,
    pub actual_sha256: Option<String>,
}

impl LoadedIr {
    pub fn load(path: impl AsRef<Path>, module: &ModuleInfo) -> Result<Self, String> {
        let path = path.as_ref();
        let bytes = std::fs::read(path)
            .map_err(|error| format!("could not read {}: {error}", path.display()))?;
        let mut database: IrDatabase = serde_json::from_slice(&bytes)
            .map_err(|error| format!("invalid WinDissect IR: {error}"))?;
        database.symbols.sort_by_key(|symbol| symbol.rva);
        database.functions.sort_by_key(|function| function.rva);

        let actual_sha256 = sha256_file(&module.path).ok();
        let exact_build_match = database
            .binary
            .sha256
            .as_ref()
            .zip(actual_sha256.as_ref())
            .map(|(expected, actual)| expected.eq_ignore_ascii_case(actual));

        Ok(Self {
            path: path.to_path_buf(),
            schema: database.schema,
            binary: database.binary,
            symbols: database.symbols,
            functions: database.functions,
            module_base: module.base,
            exact_build_match,
            actual_sha256,
        })
    }

    pub fn live_address(&self, symbol: &IrSymbol) -> usize {
        self.module_base.saturating_add(symbol.rva as usize)
    }

    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    pub fn instruction_count(&self) -> usize {
        self.functions
            .iter()
            .map(|function| function.instructions.len())
            .sum()
    }

    pub fn symbol_at(&self, address: usize) -> Option<&IrSymbol> {
        let rva = address.checked_sub(self.module_base)? as u32;
        let index = self
            .symbols
            .partition_point(|symbol| symbol.rva <= rva)
            .checked_sub(1)?;
        let symbol = &self.symbols[index];
        let end = symbol.rva.saturating_add(symbol.size.max(1));
        (rva < end).then_some(symbol)
    }

    pub fn xrefs_to(&self, address: usize, bitness: u32) -> Vec<Xref> {
        let Some(target_rva) = address
            .checked_sub(self.module_base)
            .and_then(|value| u32::try_from(value).ok())
        else {
            return Vec::new();
        };

        let mut xrefs = Vec::new();
        for function in &self.functions {
            let function_name = function
                .symbol_ids
                .first()
                .and_then(|id| self.symbols.iter().find(|symbol| &symbol.id == id))
                .map_or_else(
                    || format!("sub_{:X}", function.rva),
                    |symbol| symbol.display_name().to_owned(),
                );

            for instruction in &function.instructions {
                let kind = if instruction.branch_target_rva == Some(target_rva) {
                    if instruction.flow.contains("call") {
                        Some("call")
                    } else {
                        Some("branch")
                    }
                } else if instruction.memory_target_rva == Some(target_rva) {
                    Some(if instruction_writes_memory(instruction, bitness) {
                        "write"
                    } else {
                        "read"
                    })
                } else {
                    None
                };

                if let Some(kind) = kind {
                    xrefs.push(Xref {
                        address: self.module_base.saturating_add(instruction.rva as usize),
                        kind: kind.into(),
                        instruction: if instruction.text.is_empty() {
                            instruction.mnemonic.clone()
                        } else {
                            instruction.text.clone()
                        },
                        function: function_name.clone(),
                    });
                }
            }
        }
        xrefs
    }

    pub fn function_summary(&self, address: usize) -> Option<String> {
        let rva = address.checked_sub(self.module_base)? as u32;
        self.functions
            .iter()
            .find(|function| {
                rva >= function.rva && rva < function.rva.saturating_add(function.size.max(1))
            })
            .map(|function| {
                format!(
                    "RVA 0x{:X} · {} bytes · {} instructions",
                    function.rva,
                    function.size,
                    function.instructions.len()
                )
            })
    }
}

fn instruction_writes_memory(instruction: &IrInstruction, bitness: u32) -> bool {
    let Ok(bytes) = parse_ir_bytes(&instruction.bytes) else {
        return mnemonic_likely_writes(&instruction.mnemonic);
    };
    let mut decoder = Decoder::with_ip(
        bitness,
        &bytes,
        instruction.rva as u64,
        DecoderOptions::NONE,
    );
    let decoded = decoder.decode();
    let mut factory = InstructionInfoFactory::new();
    factory.info(&decoded).used_memory().iter().any(|memory| {
        matches!(
            memory.access(),
            OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
        )
    })
}

fn mnemonic_likely_writes(mnemonic: &str) -> bool {
    matches!(
        mnemonic.to_ascii_lowercase().as_str(),
        "mov" | "add" | "sub" | "inc" | "dec" | "and" | "or" | "xor" | "xchg" | "cmpxchg"
    )
}

fn parse_ir_bytes(text: &str) -> Result<Vec<u8>, ()> {
    let digits: String = text
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .collect();
    if digits.is_empty() || !digits.len().is_multiple_of(2) {
        return Err(());
    }
    (0..digits.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&digits[index..index + 2], 16).map_err(|_| ()))
        .collect()
}

fn sha256_file(path: impl AsRef<Path>) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub fn extract_ir(
    executable: &Path,
    module: &ModuleInfo,
    pdb: Option<&Path>,
    output: &Path,
) -> Result<PathBuf, String> {
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
    }

    let mut command = Command::new(executable);
    command
        .arg("extract")
        .arg(&module.path)
        .arg("--out")
        .arg(output);
    if let Some(pdb) = pdb {
        command.arg("--pdb").arg(pdb);
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }

    let result = command
        .output()
        .map_err(|error| format!("could not launch {}: {error}", executable.display()))?;
    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        let stdout = String::from_utf8_lossy(&result.stdout);
        return Err(format!("WinDissect failed:\n{stderr}{stdout}"));
    }
    Ok(output.to_path_buf())
}

pub fn emit_artifacts(executable: &Path, ir: &Path, output: &Path) -> Result<PathBuf, String> {
    std::fs::create_dir_all(output)
        .map_err(|error| format!("could not create {}: {error}", output.display()))?;
    let mut report = String::from("WinDissect artifact report\n==========================\n");
    let mut succeeded = 0usize;
    macro_rules! attempt {
        ($name:literal, $command:literal, $path:expr) => {
            match run_windissect(executable, [$command, "--ir"], ir, "--out", &$path) {
                Ok(()) => {
                    succeeded += 1;
                    report.push_str(concat!("[generated] ", $name, "\n"));
                }
                Err(error) => {
                    report.push_str(&format!("[unavailable] {}: {}\n", $name, error));
                }
            }
        };
    }

    attempt!("C RVA symbol table", "emit-syms", output.join("symbols"));
    attempt!(
        "C/C++ class headers",
        "emit-headers",
        output.join("headers")
    );
    attempt!("Rust FFI crate", "emit-rust", output.join("rust"));
    attempt!(
        "annotated assembly",
        "emit-asm",
        output.join("disassembly.asm")
    );
    attempt!("proof evidence", "emit-evidence", output.join("evidence"));
    attempt!("API documentation", "doc", output.join("docs"));

    std::fs::write(output.join("artifact-report.txt"), &report)
        .map_err(|error| format!("could not write artifact report: {error}"))?;
    if succeeded == 0 {
        return Err(report);
    }
    Ok(output.to_path_buf())
}

pub fn full_pipeline(
    executable: &Path,
    module: &ModuleInfo,
    pdb: Option<&Path>,
    root: &Path,
    exhaustive_inventory: bool,
) -> Result<PathBuf, String> {
    let ir_directory = root.join("ir");
    let compact_ir = ir_directory.join("raw.json");
    let inventory_directory = root.join("inventory");
    let raw_ir = if exhaustive_inventory {
        inventory_directory.join("inventory.ir.json")
    } else {
        compact_ir
    };
    let semantic_ir = ir_directory.join("semantic.json");
    let refinement = root.join("refinement");
    std::fs::create_dir_all(&ir_directory)
        .map_err(|error| format!("could not create {}: {error}", ir_directory.display()))?;
    std::fs::create_dir_all(&refinement)
        .map_err(|error| format!("could not create {}: {error}", refinement.display()))?;

    if exhaustive_inventory {
        let mut pgressive = Command::new(executable);
        pgressive
            .arg("pgressive")
            .arg(&module.path)
            .arg("--out")
            .arg(&inventory_directory);
        if let Some(pdb) = pdb {
            pgressive.arg("--pdb").arg(pdb);
        }
        run_simple(executable, &mut pgressive)?;
    } else {
        extract_ir(executable, module, pdb, &raw_ir)?;
    }
    run_simple(
        executable,
        Command::new(executable)
            .arg("verify")
            .arg("--ir")
            .arg(&raw_ir),
    )?;

    let mut refine = Command::new(executable);
    refine
        .arg("refine")
        .arg("--semantic")
        .arg("--ir")
        .arg(&raw_ir)
        .arg("--binary")
        .arg(&module.path)
        .arg("--semantic-out")
        .arg(root.join("semantic"))
        .arg("--out")
        .arg(refinement.join("report.json"))
        .arg("--out-ir")
        .arg(&semantic_ir);
    if let Some(pdb) = pdb {
        refine.arg("--pdb").arg(pdb);
    }
    run_simple(executable, &mut refine)?;
    run_simple(
        executable,
        Command::new(executable)
            .arg("verify")
            .arg("--ir")
            .arg(&semantic_ir),
    )?;

    emit_artifacts(executable, &semantic_ir, &root.join("sdk"))?;
    run_simple(
        executable,
        Command::new(executable)
            .arg("record-build")
            .arg(&semantic_ir)
            .arg("--history")
            .arg(root.join("history")),
    )?;

    Ok(semantic_ir)
}

fn run_simple(executable: &Path, command: &mut Command) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let result = command
        .output()
        .map_err(|error| format!("could not launch {}: {error}", executable.display()))?;
    if result.status.success() {
        Ok(())
    } else {
        Err(format!(
            "WinDissect failed:\n{}{}",
            String::from_utf8_lossy(&result.stderr),
            String::from_utf8_lossy(&result.stdout)
        ))
    }
}

fn run_windissect(
    executable: &Path,
    prefix: [&str; 2],
    input: &Path,
    output_flag: &str,
    output: &Path,
) -> Result<(), String> {
    let mut command = Command::new(executable);
    command.args(prefix).arg(input).arg(output_flag).arg(output);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let result = command
        .output()
        .map_err(|error| format!("could not launch {}: {error}", executable.display()))?;
    if result.status.success() {
        Ok(())
    } else {
        Err(format!(
            "WinDissect failed:\n{}{}",
            String::from_utf8_lossy(&result.stderr),
            String::from_utf8_lossy(&result.stdout)
        ))
    }
}

pub fn default_executable() -> PathBuf {
    std::env::var_os("WINDISSECT_EXE")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|path| path.parent().map(|parent| parent.join("windissect.exe")))
                .filter(|path| path.exists())
        })
        .or_else(|| {
            let release = PathBuf::from(r"D:\Projects\windissect\target\release\windissect.exe");
            release.exists().then_some(release)
        })
        .unwrap_or_else(|| PathBuf::from("windissect.exe"))
}

#[cfg(test)]
mod tests {
    use super::parse_ir_bytes;

    #[test]
    fn parses_windissect_instruction_bytes() {
        assert_eq!(parse_ir_bytes("48 89 d8").unwrap(), [0x48, 0x89, 0xD8]);
        assert_eq!(parse_ir_bytes("4889D8").unwrap(), [0x48, 0x89, 0xD8]);
    }
}
