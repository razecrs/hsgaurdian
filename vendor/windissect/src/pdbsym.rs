//! Read function names + RVAs from a Microsoft PDB (the `pdb` crate).

use anyhow::{Context, Result};
use pdb::FallibleIterator;
use std::fmt::Display;
use std::path::Path;

/// name + RVA + whether the symbol is a function, keyed for merging by RVA.
pub struct PdbSym {
    pub name: String,
    pub function: bool,
    pub rva: u32,
    pub size: u32,
}

pub struct PdbData {
    pub guid: String,
    pub age: u32,
    pub symbols: Vec<PdbSym>,
    pub coverage: PdbCoverage,
    pub records: Vec<serde_json::Value>,
}

#[derive(Default)]
pub struct PdbCoverage {
    pub procedures: usize,
    pub thunks: usize,
    pub locals: usize,
    pub blocks: usize,
    pub inline_sites: usize,
    pub data_symbols: usize,
    pub tls_symbols: usize,
    pub constants: usize,
    pub build_info: usize,
    pub annotations: usize,
    pub source_lines: usize,
}

fn clean_name(name: impl Display) -> String {
    name.to_string().trim_end_matches('\0').to_owned()
}

fn raw_record(module: &serde_json::Value, data: &pdb::SymbolData<'_>) -> serde_json::Value {
    serde_json::json!({
        "module": module,
        "kind": format!("{data:?}"),
        "name": data.name().map(clean_name),
    })
}

/// Returns public symbols plus private procedures from module streams.
pub fn read(path: &Path, retain_records: bool) -> Result<PdbData> {
    let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut pdb = pdb::PDB::open(file).context("open pdb")?;
    let info = pdb.pdb_information().context("pdb information")?;
    let guid = info.guid.as_simple().to_string().to_ascii_uppercase();
    // PE CodeView / symbol-server identity tracks the DBI age.  The PDB
    // information-stream age can legitimately differ (Microsoft's DUI70 PDB
    // is served under GUID+1 while its PDBI age is 3).
    let dbi = pdb.debug_information().context("debug information")?;
    let age = dbi.age().unwrap_or(info.age);
    let address_map = pdb.address_map().context("address map")?;

    let mut out = Vec::new();
    let mut coverage = PdbCoverage::default();
    let mut records = Vec::new();
    let globals = pdb.global_symbols().context("global symbols")?;
    let mut it = globals.iter();
    while let Some(sym) = it.next()? {
        if retain_records && let Ok(data) = sym.parse() {
            records.push(raw_record(&serde_json::json!("<global>"), &data));
        }
        if let Ok(pdb::SymbolData::Public(d)) = sym.parse()
            && let Some(rva) = d.offset.to_rva(&address_map)
        {
            out.push(PdbSym {
                name: clean_name(d.name),
                function: d.function,
                rva: rva.0,
                size: 0,
            });
        }
    }

    let mut modules = dbi.modules()?;
    let mut module_index = 0usize;
    while let Some(module) = modules.next()? {
        module_index += 1;
        let Some(module_info) = pdb.module_info(&module)? else {
            continue;
        };
        let mut symbols = module_info.symbols()?;
        while let Some(symbol) = symbols.next()? {
            if let Ok(data) = symbol.parse() {
                if retain_records {
                    records.push(raw_record(&serde_json::json!(module_index), &data));
                }
                match data {
                    pdb::SymbolData::Procedure(proc) => {
                        coverage.procedures += 1;
                        if let Some(rva) = proc.offset.to_rva(&address_map) {
                            out.push(PdbSym {
                                name: clean_name(proc.name),
                                function: true,
                                rva: rva.0,
                                size: proc.len,
                            });
                        }
                    }
                    pdb::SymbolData::Thunk(thunk) => {
                        coverage.thunks += 1;
                        let _ = thunk;
                    }
                    pdb::SymbolData::Local(_)
                    | pdb::SymbolData::RegisterVariable(_)
                    | pdb::SymbolData::MultiRegisterVariable(_)
                    | pdb::SymbolData::RegisterRelative(_) => coverage.locals += 1,
                    pdb::SymbolData::Block(_) => coverage.blocks += 1,
                    pdb::SymbolData::InlineSite(_) => coverage.inline_sites += 1,
                    pdb::SymbolData::Data(data) => {
                        coverage.data_symbols += 1;
                        if let Some(rva) = data.offset.to_rva(&address_map) {
                            out.push(PdbSym {
                                name: clean_name(data.name),
                                function: false,
                                rva: rva.0,
                                size: 0,
                            });
                        }
                    }
                    pdb::SymbolData::ThreadStorage(storage) => {
                        coverage.tls_symbols += 1;
                        if let Some(rva) = storage.offset.to_rva(&address_map) {
                            out.push(PdbSym {
                                name: clean_name(storage.name),
                                function: false,
                                rva: rva.0,
                                size: 0,
                            });
                        }
                    }
                    pdb::SymbolData::Constant(_) => coverage.constants += 1,
                    pdb::SymbolData::BuildInfo(_) => coverage.build_info += 1,
                    pdb::SymbolData::AnnotationReference(_) => coverage.annotations += 1,
                    _ => {}
                }
            }
        }
    }
    Ok(finish(guid, age, out, coverage, records))
}

fn finish(
    guid: String,
    age: u32,
    mut symbols: Vec<PdbSym>,
    coverage: PdbCoverage,
    records: Vec<serde_json::Value>,
) -> PdbData {
    symbols.retain(|symbol| !symbol.name.is_empty());
    symbols.sort_by(|a, b| (a.rva, &a.name).cmp(&(b.rva, &b.name)));
    symbols.dedup_by(|a, b| a.rva == b.rva && a.name == b.name);
    PdbData {
        guid,
        age,
        symbols,
        coverage,
        records,
    }
}
