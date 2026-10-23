//! PE export and PDB internal symbol extractor. See `docs/architecture.md` or `cargo doc`.

use crate::model::{BinaryInfo, Confidence, Coverage, Kind, Provenance, Symbol};
use anyhow::{Context, Result};
use goblin::pe::PE;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub struct Extracted {
    pub symbols: Vec<Symbol>,
    pub info: BinaryInfo,
    pub pdb_coverage: Option<serde_json::Value>,
    pub pdb_records: Vec<serde_json::Value>,
}

/// Creates a symbol shell with default flags. See `docs/architecture.md`.
fn blank(id: String, mangled: String, vaddr: u64, exported: bool, prov: Provenance) -> Symbol {
    Symbol {
        id,
        mangled,
        demangled: None,
        vaddr,
        rva: 0,
        ordinal: None,
        size: 0,
        procedure_size: None,
        is_code: false,
        forwarder: None,
        body_hash: String::new(),
        exported,
        library: false,
        kind: Kind::Unknown,
        coverage: Coverage::Auto,
        provenance: prov,
        confidence: Confidence::Certain,
        sig: crate::model::Signature::default(),
        callers: vec![],
        calls: vec![],
        imports: vec![],
    }
}

pub fn from_pe(dll: &Path, pdb: Option<&Path>, retain_pdb_records: bool) -> Result<Extracted> {
    let bytes = std::fs::read(dll).with_context(|| format!("read {}", dll.display()))?;
    let pe = PE::parse(&bytes).context("parse PE")?;
    let base = pe.image_base as u64;
    let (mut symbols, export_rvas) = extract_exports(&pe, base);
    if pdb.is_none() {
        symbols = merge_unwind_symbols(symbols, extract_unwind_functions(&pe, base));
        symbols = merge_new_rvas(symbols, extract_unwind_handlers(&pe, base));
        symbols = merge_new_rvas(symbols, extract_guard_cf_functions(&pe, &bytes, base));
        symbols = merge_new_rvas(symbols, extract_safe_seh_handlers(&pe, &bytes, base));
        symbols = merge_new_rvas(symbols, extract_entry_point(&pe, base));
    }
    let (pdb_symbols, pdb_coverage, pdb_records) =
        merge_pdb(&pe, pdb, base, &export_rvas, retain_pdb_records)?;
    let symbols = merge_exact_symbols(symbols, pdb_symbols);
    let info = binary_info(dll, &bytes, &pe, base);
    Ok(Extracted {
        symbols,
        info,
        pdb_coverage,
        pdb_records,
    })
}

/// Recover exact x64 function extents from the PE exception directory.
///
/// These entries are linker-authored runtime metadata, not heuristic code
/// guesses. They remain anonymous without symbols, but their begin/end RVAs
/// are suitable seeds for disassembly, CFG construction, body hashing and
/// later evidence-based naming. When an entry shares an RVA with an export,
/// [`merge_unwind_symbols`] attaches the exact extent to that export.
///
/// Only primary entries start a function. An entry carrying chained unwind
/// info is a continuation chunk of the primary it chains to, so it is never
/// emitted on its own; when such a chunk begins exactly where its primary ends,
/// the two are one contiguous body and the primary's extent covers both.
fn extract_unwind_functions(pe: &PE<'_>, base: u64) -> Vec<Symbol> {
    if pe.header.coff_header.machine != 0x8664 {
        return Vec::new();
    }
    let Some(exception_data) = pe.exception_data.as_ref() else {
        return Vec::new();
    };

    let mut primaries = BTreeMap::new();
    let mut chunks = BTreeMap::new();
    for function in exception_data.functions().flatten() {
        let begin = function.begin_address;
        let end = function.end_address;
        if begin == 0 || end <= begin || !rva_is_executable(pe, begin) {
            continue;
        }
        let root = unwind_chain_root(exception_data, &pe.sections, function);
        if root == begin {
            primaries.entry(begin).or_insert(end);
        } else {
            chunks.insert(begin, (end, root));
        }
    }

    primaries
        .into_iter()
        .map(|(begin, mut end)| {
            while let Some(&(chunk_end, root)) = chunks.get(&end) {
                if root != begin {
                    break;
                }
                end = chunk_end;
            }
            let name = format!("sub_{begin:08X}");
            let mut symbol = blank(
                name.clone(),
                name,
                base + u64::from(begin),
                false,
                Provenance::PeUnwind,
            );
            symbol.rva = begin;
            symbol.size = end - begin;
            symbol.procedure_size = Some(symbol.size);
            symbol.is_code = true;
            symbol.kind = Kind::CFunc;
            symbol
        })
        .collect()
}

/// Deepest chain the unwinder is expected to follow; anything longer is
/// treated as malformed rather than looped on.
const MAX_UNWIND_CHAIN: usize = 32;

/// Follow chained unwind records to the begin RVA of the primary entry that
/// owns `function`. An entry whose unwind info is unreadable stands as its own
/// primary, which keeps the pre-chain behaviour for damaged metadata.
fn unwind_chain_root(
    exception_data: &goblin::pe::exception::ExceptionData<'_>,
    sections: &[goblin::pe::section_table::SectionTable],
    function: goblin::pe::exception::RuntimeFunction,
) -> u32 {
    let mut current = function;
    for _ in 0..MAX_UNWIND_CHAIN {
        match exception_data
            .get_unwind_info(current, sections)
            .ok()
            .and_then(|info| info.chained_info)
        {
            Some(parent) => current = parent,
            None => break,
        }
    }
    current.begin_address
}

fn merge_unwind_symbols(mut symbols: Vec<Symbol>, unwind_symbols: Vec<Symbol>) -> Vec<Symbol> {
    for unwind in unwind_symbols {
        if let Some(existing) = symbols
            .iter_mut()
            .find(|symbol| symbol.rva == unwind.rva && symbol.is_code)
        {
            existing.size = unwind.size;
            existing.procedure_size = unwind.procedure_size;
        } else {
            symbols.push(unwind);
        }
    }
    symbols
}

fn merge_new_rvas(mut symbols: Vec<Symbol>, new_symbols: Vec<Symbol>) -> Vec<Symbol> {
    let mut known = symbols
        .iter()
        .map(|symbol| symbol.rva)
        .collect::<BTreeSet<_>>();
    for symbol in new_symbols {
        if known.insert(symbol.rva) {
            symbols.push(symbol);
        }
    }
    symbols
}

/// Recover the language-specific handler entry points referenced by x64 unwind
/// metadata. These are callable runtime entry points, not scope-table labels.
fn extract_unwind_handlers(pe: &PE<'_>, base: u64) -> Vec<Symbol> {
    use goblin::pe::exception::UnwindHandler;

    if pe.header.coff_header.machine != 0x8664 {
        return Vec::new();
    }
    let Some(exception_data) = pe.exception_data.as_ref() else {
        return Vec::new();
    };
    let mut handlers = BTreeSet::new();
    for function in exception_data.functions().flatten() {
        let Ok(info) = exception_data.get_unwind_info(function, &pe.sections) else {
            continue;
        };
        let Some(
            UnwindHandler::ExceptionHandler(rva, _) | UnwindHandler::TerminationHandler(rva, _),
        ) = info.handler
        else {
            continue;
        };
        if rva != 0 && rva_is_executable(pe, rva) {
            handlers.insert(rva);
        }
    }
    handlers
        .into_iter()
        .map(|rva| anonymous_code(base, rva, Provenance::PeUnwindHandler))
        .collect()
}

/// Recover linker-declared valid indirect-call targets from the PE load-config
/// Guard CF table. The table proves an entry RVA, but supplies no function
/// extent or source-level name.
fn extract_guard_cf_functions(pe: &PE<'_>, bytes: &[u8], base: u64) -> Vec<Symbol> {
    let Some(load_config) = pe.load_config_data.as_ref() else {
        return Vec::new();
    };
    let directory = &load_config.directory;
    let Some(table_vaddr) = directory
        .guard_cf_function_table
        .filter(|value| *value != 0)
    else {
        return Vec::new();
    };
    let Some(count) = directory
        .guard_cf_function_count
        .and_then(|value| usize::try_from(value).ok())
    else {
        return Vec::new();
    };
    let flags = directory.guard_flags.unwrap_or(0);
    if flags & goblin::pe::load_config::IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT == 0 {
        return Vec::new();
    }
    let stride = 4 + usize::try_from((flags >> 28) & 0xF).unwrap_or(0);
    let Some(table_offset) = vaddr_to_file_offset(pe, table_vaddr) else {
        return Vec::new();
    };

    rva_table(bytes, table_offset, count, stride)
        .into_iter()
        .filter(|rva| *rva != 0 && rva_is_executable(pe, *rva))
        .map(|rva| anonymous_code(base, rva, Provenance::PeGuardCf))
        .collect()
}

/// Recover x86 `SafeSEH` handlers: the load config lists the RVA of every
/// exception handler the image registers, each one a callable entry point.
fn extract_safe_seh_handlers(pe: &PE<'_>, bytes: &[u8], base: u64) -> Vec<Symbol> {
    if pe.header.coff_header.machine != 0x014C {
        return Vec::new();
    }
    let Some(directory) = pe.load_config_data.as_ref().map(|config| &config.directory) else {
        return Vec::new();
    };
    let Some(table_vaddr) = directory.se_handler_table.filter(|value| *value != 0) else {
        return Vec::new();
    };
    let Some(count) = directory
        .se_handler_count
        .and_then(|value| usize::try_from(value).ok())
    else {
        return Vec::new();
    };
    let Some(table_offset) = vaddr_to_file_offset(pe, table_vaddr) else {
        return Vec::new();
    };
    rva_table(bytes, table_offset, count, 4)
        .into_iter()
        .filter(|rva| *rva != 0 && rva_is_executable(pe, *rva))
        .map(|rva| anonymous_code(base, rva, Provenance::PeSafeSeh))
        .collect()
}

/// The optional header's entry point: the loader calls it, so it is a
/// function start on every architecture.
fn extract_entry_point(pe: &PE<'_>, base: u64) -> Vec<Symbol> {
    let rva = pe.entry;
    if rva == 0 || !rva_is_executable(pe, rva) {
        return Vec::new();
    }
    vec![anonymous_code(base, rva, Provenance::PeEntryPoint)]
}

/// An anonymous code entry proven by PE metadata, named by its RVA.
fn anonymous_code(base: u64, rva: u32, provenance: Provenance) -> Symbol {
    let name = format!("sub_{rva:08X}");
    let mut symbol = blank(name.clone(), name, base + u64::from(rva), false, provenance);
    symbol.rva = rva;
    symbol.is_code = true;
    symbol.kind = Kind::CFunc;
    symbol
}

fn rva_table(bytes: &[u8], offset: usize, count: usize, stride: usize) -> BTreeSet<u32> {
    if stride < 4 {
        return BTreeSet::new();
    }
    (0..count)
        .filter_map(|index| offset.checked_add(index.checked_mul(stride)?))
        .filter_map(|start| bytes.get(start..start.checked_add(4)?))
        .map(|entry| u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]))
        .collect()
}

fn vaddr_to_file_offset(pe: &PE<'_>, vaddr: u64) -> Option<usize> {
    let rva = u32::try_from(vaddr.checked_sub(pe.image_base)?).ok()?;
    pe.sections.iter().find_map(|section| {
        let delta = rva.checked_sub(section.virtual_address)?;
        if delta >= section.size_of_raw_data {
            return None;
        }
        usize::try_from(section.pointer_to_raw_data.checked_add(delta)?).ok()
    })
}

fn extract_exports(pe: &PE<'_>, base: u64) -> (Vec<Symbol>, BTreeSet<u32>) {
    let mut symbols = Vec::new();
    let mut export_rvas = BTreeSet::new();
    let ordinal_base = pe
        .export_data
        .as_ref()
        .map_or(0, |d| d.export_directory_table.ordinal_base);
    let export_ordinals = pe.export_data.as_ref().map(|d| &d.export_ordinal_table);
    let mut named_ordinals = BTreeSet::new();
    for (index, e) in pe.exports.iter().enumerate() {
        let Ok(default_ordinal_index) = u16::try_from(index) else {
            continue;
        };
        let ordinal_index = export_ordinals
            .and_then(|items| items.get(index))
            .copied()
            .unwrap_or(default_ordinal_index);
        named_ordinals.insert(ordinal_index);
        let ordinal = ordinal_base + u32::from(ordinal_index);
        let owned_name = e
            .name
            .map_or_else(|| format!("#ordinal{ordinal}"), str::to_owned);
        let name = owned_name.as_str();
        let Ok(rva) = u32::try_from(e.rva) else {
            continue;
        };
        export_rvas.insert(rva);
        let mut symbol = blank(
            name.to_string(),
            name.to_string(),
            base + u64::from(rva),
            true,
            Provenance::PeExport,
        );
        symbol.rva = rva;
        symbol.ordinal = Some(ordinal);
        symbol.is_code = e.reexport.is_none() && rva_is_executable(pe, rva);
        symbol.forwarder = e.reexport.as_ref().map(|r| format!("{r:?}"));
        symbols.push(symbol);
    }
    if let Some(data) = &pe.export_data {
        use goblin::pe::export::ExportAddressTableEntry;
        for (index, entry) in data.export_address_table.iter().enumerate() {
            let Ok(ordinal_index) = u16::try_from(index) else {
                continue;
            };
            if named_ordinals.contains(&ordinal_index) {
                continue;
            }
            let Ok(index_u32) = u32::try_from(index) else {
                continue;
            };
            let ordinal = ordinal_base + index_u32;
            let (rva, forwarder) = match entry {
                ExportAddressTableEntry::ExportRVA(rva) => (*rva, None),
                ExportAddressTableEntry::ForwarderRVA(rva) => (*rva, Some("<forwarded>".into())),
            };
            if rva == 0 {
                continue;
            }
            let name = format!("#ordinal{ordinal}");
            let mut symbol = blank(
                name.clone(),
                name,
                base + u64::from(rva),
                true,
                Provenance::PeExport,
            );
            symbol.rva = rva;
            symbol.ordinal = Some(ordinal);
            symbol.is_code = forwarder.is_none() && rva_is_executable(pe, rva);
            symbol.forwarder = forwarder;
            export_rvas.insert(rva);
            symbols.push(symbol);
        }
    }

    (symbols, export_rvas)
}

fn rva_is_executable(pe: &PE<'_>, rva: u32) -> bool {
    pe.sections.iter().any(|section| {
        let extent = section.virtual_size.max(section.size_of_raw_data);
        rva >= section.virtual_address
            && rva < section.virtual_address.saturating_add(extent)
            && section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0
    })
}

fn merge_exact_symbols(exports: Vec<Symbol>, pdb_symbols: Vec<Symbol>) -> Vec<Symbol> {
    let mut merged = BTreeMap::<(u32, String), Symbol>::new();
    for symbol in exports {
        merged.insert((symbol.rva, symbol.mangled.clone()), symbol);
    }
    for mut symbol in pdb_symbols {
        let key = (symbol.rva, symbol.mangled.clone());
        if let Some(export) = merged.remove(&key) {
            symbol.exported |= export.exported;
            symbol.ordinal = symbol.ordinal.or(export.ordinal);
            symbol.forwarder = symbol.forwarder.or(export.forwarder);
            if symbol.size == 0 {
                symbol.size = export.size;
            }
        }
        merged.insert(key, symbol);
    }
    merged.into_values().collect()
}

fn merge_pdb(
    pe: &PE<'_>,
    pdb: Option<&Path>,
    base: u64,
    export_rvas: &BTreeSet<u32>,
    retain_records: bool,
) -> Result<(
    Vec<Symbol>,
    Option<serde_json::Value>,
    Vec<serde_json::Value>,
)> {
    let Some(pdb_path) = pdb else {
        return Ok((Vec::new(), None, Vec::new()));
    };
    let pdb_data = crate::pdbsym::read(pdb_path, retain_records)?;
    let coverage = Some(serde_json::json!({
            "procedures": pdb_data.coverage.procedures,
            "thunks": pdb_data.coverage.thunks,
            "locals": pdb_data.coverage.locals,
            "blocks": pdb_data.coverage.blocks,
            "inline_sites": pdb_data.coverage.inline_sites,
            "data_symbols": pdb_data.coverage.data_symbols,
            "tls_symbols": pdb_data.coverage.tls_symbols,
            "constants": pdb_data.coverage.constants,
            "build_info": pdb_data.coverage.build_info,
            "annotations": pdb_data.coverage.annotations
            ,"source_lines": pdb_data.coverage.source_lines
    }));
    let dbg = pe
        .debug_data
        .as_ref()
        .and_then(|data| data.codeview_pdb70_debug_info.as_ref())
        .context("cannot prove PDB identity: PE has no RSDS CodeView record")?;
    let expected = codeview_guid(&dbg.signature);
    anyhow::ensure!(
        pdb_data.guid == expected && pdb_data.age == dbg.age,
        "PDB identity mismatch: PE expects {expected}+{:X}, PDB is {}+{:X}",
        dbg.age,
        pdb_data.guid,
        pdb_data.age
    );
    let symbols = pdb_data
        .symbols
        .into_iter()
        .map(|symbol| {
            let mut record = blank(
                symbol.name.clone(),
                symbol.name,
                base + u64::from(symbol.rva),
                false,
                Provenance::Pdb,
            );
            record.rva = symbol.rva;
            record.size = symbol.size;
            record.procedure_size = (symbol.function && symbol.size != 0).then_some(symbol.size);
            record.is_code = symbol.function;
            record.exported = export_rvas.contains(&symbol.rva);
            record
        })
        .collect();
    Ok((symbols, coverage, pdb_data.records))
}

fn binary_info(dll: &Path, bytes: &[u8], pe: &PE<'_>, base: u64) -> BinaryInfo {
    let mut info = BinaryInfo {
        file: dll
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string(),
        timestamp: Some(pe.header.coff_header.time_date_stamp.to_string()),
        sha256: Some(crate::hex::lower(&Sha256::digest(bytes))),
        machine: Some(format!("0x{:04x}", pe.header.coff_header.machine)),
        image_base: Some(base),
        image_size: pe
            .header
            .optional_header
            .as_ref()
            .map(|header| u64::from(header.windows_fields.size_of_image)),
        // API sets are forwarders - recording them hides the module that
        // actually satisfies the import, which is the edge worth having.
        dependencies: {
            let mut libs: Vec<String> = pe
                .libraries
                .iter()
                .map(std::string::ToString::to_string)
                .filter(|l| {
                    let low = l.to_ascii_lowercase();
                    !low.starts_with("api-ms-") && !low.starts_with("ext-ms-")
                })
                .collect();
            libs.sort_unstable();
            libs.dedup();
            libs
        },
        ..Default::default()
    };
    if let Some(dbg) = pe
        .debug_data
        .as_ref()
        .and_then(|d| d.codeview_pdb70_debug_info.as_ref())
    {
        info.pdb_name = Some(
            String::from_utf8_lossy(dbg.filename)
                .trim_end_matches('\0')
                .to_string(),
        );
        info.pdb_guid = Some(codeview_guid(&dbg.signature));
        info.pdb_age = Some(dbg.age);
    }

    info
}

fn codeview_guid(g: &[u8; 16]) -> String {
    format!(
        "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{}",
        g[3],
        g[2],
        g[1],
        g[0],
        g[5],
        g[4],
        g[7],
        g[6],
        crate::hex::upper(&g[8..])
    )
}

#[cfg(test)]
mod tests {
    use super::{blank, merge_exact_symbols, rva_table};
    use crate::model::Provenance;

    #[test]
    fn pdb_data_identity_replaces_export_code_guess() {
        let mut export = blank(
            "??_7Widget@@6B@".into(),
            "??_7Widget@@6B@".into(),
            0x1800_2000,
            true,
            Provenance::PeExport,
        );
        export.rva = 0x2000;
        export.ordinal = Some(7);
        export.is_code = true;
        let mut pdb = blank(
            "??_7Widget@@6B@".into(),
            "??_7Widget@@6B@".into(),
            0x1800_2000,
            false,
            Provenance::Pdb,
        );
        pdb.rva = 0x2000;

        let merged = merge_exact_symbols(vec![export], vec![pdb]);

        assert_eq!(merged.len(), 1);
        assert!(merged[0].exported);
        assert_eq!(merged[0].ordinal, Some(7));
        assert!(!merged[0].is_code);
    }

    #[test]
    fn guard_cf_table_honors_metadata_stride() {
        let bytes = [
            0x10, 0x20, 0x00, 0x00, 0xAA, 0xBB, 0x30, 0x40, 0x00, 0x00, 0xCC, 0xDD,
        ];
        let rvas = rva_table(&bytes, 0, 2, 6);
        assert_eq!(rvas.into_iter().collect::<Vec<_>>(), vec![0x2010, 0x4030]);
    }
}
