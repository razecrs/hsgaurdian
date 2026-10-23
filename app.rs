use std::{
    path::PathBuf,
    sync::mpsc::{self, Receiver},
    thread,
};

use eframe::egui::{self, Color32, RichText};

use crate::{
    disasm::{DisassemblyLine, disassemble, render_line},
    memory::{
        ModuleInfo, ProcessInfo, ProcessMemory, format_hex, list_modules, list_processes,
        parse_address, parse_hex_bytes, parse_offsets,
    },
    windissect::{LoadedIr, Xref, default_executable, emit_artifacts, extract_ir},
};

const ACCENT: Color32 = Color32::from_rgb(83, 214, 151);
const WARNING: Color32 = Color32::from_rgb(245, 192, 88);
const ERROR: Color32 = Color32::from_rgb(244, 92, 92);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Live,
    Pointer,
    Windissect,
}

struct AttachedProcess {
    info: ProcessInfo,
    memory: ProcessMemory,
    modules: Vec<ModuleInfo>,
    selected_module: usize,
}

struct PatchRecord {
    address: usize,
    original: Vec<u8>,
    replacement: Vec<u8>,
    active: bool,
}

pub struct GuardianApp {
    tab: Tab,
    processes: Vec<ProcessInfo>,
    process_filter: String,
    attached: Option<AttachedProcess>,
    status: String,
    status_error: bool,

    address_text: String,
    disassembly_size: usize,
    bitness: u32,
    disassembly: Vec<DisassemblyLine>,
    patch_text: String,
    patches: Vec<PatchRecord>,
    xrefs: Vec<Xref>,

    pointer_base: String,
    pointer_offsets: String,
    pointer_size: usize,
    pointer_trace: Vec<usize>,

    windissect_exe: String,
    pdb_path: String,
    ir_path: String,
    loaded_ir: Option<LoadedIr>,
    symbol_filter: String,
    selected_symbol: Option<usize>,
    windissect_rx: Option<Receiver<Result<LoadedIr, String>>>,
    artifact_output: String,
    artifact_rx: Option<Receiver<Result<PathBuf, String>>>,
}

impl GuardianApp {
    pub fn new(context: &eframe::CreationContext<'_>) -> Self {
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = Color32::from_rgb(16, 19, 24);
        visuals.window_fill = Color32::from_rgb(20, 24, 30);
        visuals.selection.bg_fill = Color32::from_rgb(39, 91, 72);
        context.egui_ctx.set_visuals(visuals);

        let processes = list_processes().unwrap_or_default();
        Self {
            tab: Tab::Live,
            processes,
            process_filter: String::new(),
            attached: None,
            status: "Select a process to begin".into(),
            status_error: false,
            address_text: String::new(),
            disassembly_size: 384,
            bitness: 64,
            disassembly: Vec::new(),
            patch_text: String::new(),
            patches: Vec::new(),
            xrefs: Vec::new(),
            pointer_base: String::new(),
            pointer_offsets: "0, 0".into(),
            pointer_size: 8,
            pointer_trace: Vec::new(),
            windissect_exe: default_executable().display().to_string(),
            pdb_path: String::new(),
            ir_path: String::new(),
            loaded_ir: None,
            symbol_filter: String::new(),
            selected_symbol: None,
            windissect_rx: None,
            artifact_output: "windissect-generated".into(),
            artifact_rx: None,
        }
    }

    fn set_status(&mut self, message: impl Into<String>, error: bool) {
        self.status = message.into();
        self.status_error = error;
    }

    fn refresh_processes(&mut self) {
        match list_processes() {
            Ok(processes) => {
                self.processes = processes;
                self.set_status("Process list refreshed", false);
            }
            Err(error) => self.set_status(format!("Could not list processes: {error}"), true),
        }
    }

    fn attach(&mut self, info: ProcessInfo) {
        match ProcessMemory::open(info.pid) {
            Ok(memory) => {
                let writable = memory.writable;
                match list_modules(info.pid) {
                    Ok(modules) => {
                        if let Some(module) = modules.first() {
                            self.address_text = format!("0x{:X}", module.base);
                            self.pointer_base = self.address_text.clone();
                        }
                        self.attached = Some(AttachedProcess {
                            info: info.clone(),
                            memory,
                            modules,
                            selected_module: 0,
                        });
                        self.loaded_ir = None;
                        self.disassembly.clear();
                        self.xrefs.clear();
                        self.set_status(
                            format!(
                                "Attached to {} ({}) · {}",
                                info.name,
                                info.pid,
                                if writable { "read/write" } else { "read-only" }
                            ),
                            false,
                        );
                    }
                    Err(error) => self.set_status(
                        format!("Attached, but module listing failed: {error}"),
                        true,
                    ),
                }
            }
            Err(error) => self.set_status(
                format!("Could not attach to {} ({}): {error}", info.name, info.pid),
                true,
            ),
        }
    }

    fn selected_module(&self) -> Option<&ModuleInfo> {
        let attached = self.attached.as_ref()?;
        attached.modules.get(attached.selected_module)
    }

    fn read_disassembly(&mut self) {
        let result = (|| {
            let address = parse_address(&self.address_text)?;
            let attached = self
                .attached
                .as_ref()
                .ok_or_else(|| "attach to a process first".to_owned())?;
            let bytes = attached
                .memory
                .read(address, self.disassembly_size)
                .map_err(|error| format!("read failed at 0x{address:X}: {error}"))?;
            Ok::<_, String>(disassemble(&bytes, address, self.bitness))
        })();

        match result {
            Ok(lines) => {
                self.disassembly = lines;
                self.xrefs.clear();
                self.set_status("Live instructions refreshed", false);
            }
            Err(error) => self.set_status(error, true),
        }
    }

    fn apply_patch(&mut self) {
        let result = (|| {
            let address = parse_address(&self.address_text)?;
            let replacement = parse_hex_bytes(&self.patch_text)?;
            let attached = self
                .attached
                .as_ref()
                .ok_or_else(|| "attach to a process first".to_owned())?;
            let original = attached
                .memory
                .patch(address, &replacement)
                .map_err(|error| format!("patch failed: {error}"))?;
            Ok::<_, String>((address, original, replacement))
        })();

        match result {
            Ok((address, original, replacement)) => {
                self.patches.push(PatchRecord {
                    address,
                    original,
                    replacement,
                    active: true,
                });
                self.set_status(format!("Patched 0x{address:X}"), false);
                self.read_disassembly();
            }
            Err(error) => self.set_status(error, true),
        }
    }

    fn rollback_patch(&mut self, index: usize) {
        let Some(patch) = self.patches.get(index) else {
            return;
        };
        if !patch.active {
            return;
        }
        let address = patch.address;
        let original = patch.original.clone();
        let result = self
            .attached
            .as_ref()
            .ok_or_else(|| "attach to a process first".to_owned())
            .and_then(|attached| {
                attached
                    .memory
                    .patch(address, &original)
                    .map_err(|error| format!("rollback failed: {error}"))
            });

        match result {
            Ok(_) => {
                self.patches[index].active = false;
                self.set_status(format!("Restored original bytes at 0x{address:X}"), false);
                self.read_disassembly();
            }
            Err(error) => self.set_status(error, true),
        }
    }

    fn resolve_pointer(&mut self) {
        let result = (|| {
            let base = parse_address(&self.pointer_base)?;
            let offsets = parse_offsets(&self.pointer_offsets)?;
            let attached = self
                .attached
                .as_ref()
                .ok_or_else(|| "attach to a process first".to_owned())?;
            attached
                .memory
                .resolve_pointer_chain(base, &offsets, self.pointer_size)
                .map_err(|error| format!("pointer resolution failed: {error}"))
        })();

        match result {
            Ok(trace) => {
                if let Some(final_address) = trace.last() {
                    self.address_text = format!("0x{final_address:X}");
                }
                self.pointer_trace = trace;
                self.set_status("Pointer chain resolved", false);
            }
            Err(error) => self.set_status(error, true),
        }
    }

    fn find_xrefs(&mut self) {
        let result = parse_address(&self.address_text).and_then(|address| {
            self.loaded_ir
                .as_ref()
                .ok_or_else(|| "load matching WinDissect IR first".to_owned())
                .map(|ir| ir.xrefs_to(address, self.bitness))
        });
        match result {
            Ok(xrefs) => {
                let count = xrefs.len();
                self.xrefs = xrefs;
                self.set_status(format!("Found {count} static references"), false);
            }
            Err(error) => self.set_status(error, true),
        }
    }

    fn start_ir_load(&mut self, path: PathBuf) {
        let Some(module) = self.selected_module().cloned() else {
            self.set_status("select an attached module first", true);
            return;
        };
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let _ = sender.send(LoadedIr::load(path, &module));
        });
        self.windissect_rx = Some(receiver);
        self.set_status("Loading and verifying WinDissect IR…", false);
    }

    fn start_windissect(&mut self) {
        let Some(module) = self.selected_module().cloned() else {
            self.set_status("select an attached module first", true);
            return;
        };
        let executable = PathBuf::from(self.windissect_exe.trim());
        let pdb = (!self.pdb_path.trim().is_empty()).then(|| PathBuf::from(self.pdb_path.trim()));
        let output = PathBuf::from("windissect-ir").join(format!("{}.json", module.name));
        self.ir_path = output.display().to_string();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let result = extract_ir(&executable, &module, pdb.as_deref(), &output)
                .and_then(|path| LoadedIr::load(path, &module));
            let _ = sender.send(result);
        });
        self.windissect_rx = Some(receiver);
        self.set_status(
            format!(
                "WinDissect is analyzing {}…",
                self.selected_module().unwrap().name
            ),
            false,
        );
    }

    fn poll_windissect(&mut self) {
        let result = self
            .windissect_rx
            .as_ref()
            .and_then(|receiver| receiver.try_recv().ok());
        let Some(result) = result else {
            return;
        };
        self.windissect_rx = None;
        match result {
            Ok(ir) => {
                let count = ir.symbols.len();
                let match_text = match ir.exact_build_match {
                    Some(true) => "exact build verified",
                    Some(false) => "WARNING: binary hash mismatch",
                    None => "build identity unavailable",
                };
                self.ir_path = ir.path.display().to_string();
                self.loaded_ir = Some(ir);
                self.set_status(format!("Loaded {count} symbols · {match_text}"), false);
            }
            Err(error) => self.set_status(error, true),
        }
    }

    fn start_artifact_generation(&mut self) {
        let Some(ir) = self.loaded_ir.as_ref() else {
            self.set_status("load WinDissect IR first", true);
            return;
        };
        let executable = PathBuf::from(self.windissect_exe.trim());
        let ir_path = ir.path.clone();
        let module_name = PathBuf::from(&ir.binary.file)
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or("module")
            .to_owned();
        let output = PathBuf::from(self.artifact_output.trim()).join(module_name);
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let _ = sender.send(emit_artifacts(&executable, &ir_path, &output));
        });
        self.artifact_rx = Some(receiver);
        self.set_status(
            "Generating verified headers, Rust bindings, and assembly…",
            false,
        );
    }

    fn poll_artifacts(&mut self) {
        let result = self
            .artifact_rx
            .as_ref()
            .and_then(|receiver| receiver.try_recv().ok());
        let Some(result) = result else {
            return;
        };
        self.artifact_rx = None;
        match result {
            Ok(path) => self.set_status(
                format!("Generated WinDissect artifacts in {}", path.display()),
                false,
            ),
            Err(error) => self.set_status(error, true),
        }
    }

    fn process_sidebar(&mut self, context: &egui::Context) {
        let mut attach_request = None;
        egui::SidePanel::left("processes")
            .resizable(true)
            .default_width(260.0)
            .show(context, |ui| {
                ui.heading("Processes");
                ui.horizontal(|ui| {
                    ui.text_edit_singleline(&mut self.process_filter);
                    if ui.button("↻").on_hover_text("Refresh processes").clicked() {
                        self.refresh_processes();
                    }
                });
                ui.separator();

                let filter = self.process_filter.to_ascii_lowercase();
                let processes: Vec<_> = self
                    .processes
                    .iter()
                    .filter(|process| {
                        filter.is_empty()
                            || process.name.to_ascii_lowercase().contains(&filter)
                            || process.pid.to_string().contains(&filter)
                    })
                    .cloned()
                    .collect();

                egui::ScrollArea::vertical().show(ui, |ui| {
                    for process in processes {
                        let selected = self
                            .attached
                            .as_ref()
                            .is_some_and(|attached| attached.info.pid == process.pid);
                        let response = ui.selectable_label(
                            selected,
                            format!("{}\nPID {}", process.name, process.pid),
                        );
                        if response.double_clicked() {
                            attach_request = Some(process);
                        }
                    }
                });
            });

        if let Some(process) = attach_request {
            self.attach(process);
        }
    }

    fn top_bar(&mut self, context: &egui::Context) {
        egui::TopBottomPanel::top("top_bar").show(context, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("HS GUARDIAN").strong().color(ACCENT));
                ui.separator();
                ui.selectable_value(&mut self.tab, Tab::Live, "Live code");
                ui.selectable_value(&mut self.tab, Tab::Pointer, "Pointer chain");
                ui.selectable_value(&mut self.tab, Tab::Windissect, "WinDissect");
                ui.separator();
                if let Some(attached) = &self.attached {
                    ui.label(format!("{} · {}", attached.info.name, attached.info.pid));
                    ui.colored_label(
                        if attached.memory.writable {
                            ACCENT
                        } else {
                            WARNING
                        },
                        if attached.memory.writable {
                            "R/W"
                        } else {
                            "READ ONLY"
                        },
                    );
                } else {
                    ui.colored_label(WARNING, "DETACHED");
                }
            });
        });
    }

    fn status_bar(&mut self, context: &egui::Context) {
        egui::TopBottomPanel::bottom("status").show(context, |ui| {
            ui.horizontal(|ui| {
                if self.windissect_rx.is_some() || self.artifact_rx.is_some() {
                    ui.spinner();
                }
                ui.colored_label(
                    if self.status_error {
                        ERROR
                    } else {
                        Color32::GRAY
                    },
                    &self.status,
                );
            });
        });
    }

    fn live_ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Address");
            ui.add(
                egui::TextEdit::singleline(&mut self.address_text)
                    .font(egui::TextStyle::Monospace)
                    .desired_width(180.0),
            );
            ui.label("Bytes");
            ui.add(egui::DragValue::new(&mut self.disassembly_size).range(16..=4096));
            egui::ComboBox::from_id_salt("bitness")
                .selected_text(format!("{}-bit", self.bitness))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.bitness, 64, "64-bit");
                    ui.selectable_value(&mut self.bitness, 32, "32-bit");
                });
            if ui.button("Disassemble").clicked() {
                self.read_disassembly();
            }
            if ui.button("Find xrefs / writes").clicked() {
                self.find_xrefs();
            }
        });

        ui.horizontal(|ui| {
            ui.label("Generated source output");
            ui.text_edit_singleline(&mut self.artifact_output);
            if ui
                .add_enabled(
                    self.artifact_rx.is_none(),
                    egui::Button::new("Generate C/C++ · Rust · ASM"),
                )
                .clicked()
            {
                self.start_artifact_generation();
            }
        });

        if let (Ok(address), Some(ir)) = (parse_address(&self.address_text), &self.loaded_ir) {
            if let Some(symbol) = ir.symbol_at(address) {
                ui.label(RichText::new(symbol.display_name()).color(ACCENT));
            }
            if let Some(summary) = ir.function_summary(address) {
                ui.small(summary);
            }
        }

        ui.separator();
        ui.columns(2, |columns| {
            columns[0].heading("Live instructions");
            egui::ScrollArea::vertical()
                .id_salt("disassembly")
                .show(&mut columns[0], |ui| {
                    let mut navigate = None;
                    for line in &self.disassembly {
                        ui.horizontal(|ui| {
                            if ui
                                .selectable_label(
                                    false,
                                    RichText::new(render_line(line)).monospace(),
                                )
                                .clicked()
                            {
                                self.address_text = format!("0x{:X}", line.address);
                                self.patch_text = format_hex(&line.bytes);
                            }
                            if let Some(target) = line.branch_target
                                && ui
                                    .small_button(if line.is_call {
                                        "call →"
                                    } else {
                                        "jump →"
                                    })
                                    .clicked()
                            {
                                navigate = Some(target);
                            }
                        });
                    }
                    if let Some(target) = navigate {
                        self.address_text = format!("0x{target:X}");
                    }
                });

            columns[1].heading("Patch bytes");
            columns[1].add(
                egui::TextEdit::multiline(&mut self.patch_text)
                    .font(egui::TextStyle::Monospace)
                    .hint_text("90 90 90 or CC"),
            );
            columns[1].horizontal(|ui| {
                if ui.button("Apply patch").clicked() {
                    self.apply_patch();
                }
                if ui.button("NOP selected bytes").clicked() {
                    match parse_hex_bytes(&self.patch_text) {
                        Ok(bytes) => self.patch_text = format_hex(&vec![0x90; bytes.len()]),
                        Err(error) => self.set_status(error, true),
                    }
                }
            });

            columns[1].separator();
            columns[1].heading("Static references");
            let mut navigate = None;
            egui::ScrollArea::vertical()
                .max_height(220.0)
                .show(&mut columns[1], |ui| {
                    for xref in &self.xrefs {
                        if ui
                            .selectable_label(
                                false,
                                format!(
                                    "{} 0x{:X}\n{} · {}",
                                    xref.kind, xref.address, xref.function, xref.instruction
                                ),
                            )
                            .clicked()
                        {
                            navigate = Some(xref.address);
                        }
                    }
                });
            if let Some(address) = navigate {
                self.address_text = format!("0x{address:X}");
                self.read_disassembly();
            }

            columns[1].separator();
            columns[1].heading("Patch history");
            let mut rollback = None;
            for (index, patch) in self.patches.iter().enumerate().rev() {
                columns[1].horizontal(|ui| {
                    ui.monospace(format!("0x{:X}", patch.address));
                    ui.small(format!(
                        "{} → {}",
                        format_hex(&patch.original),
                        format_hex(&patch.replacement)
                    ));
                    if patch.active && ui.small_button("Rollback").clicked() {
                        rollback = Some(index);
                    }
                });
            }
            if let Some(index) = rollback {
                self.rollback_patch(index);
            }
        });
    }

    fn pointer_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Pointer-chain resolver");
        ui.label("Adds each offset; every non-final step is dereferenced.");
        ui.horizontal(|ui| {
            ui.label("Base");
            ui.add(
                egui::TextEdit::singleline(&mut self.pointer_base)
                    .font(egui::TextStyle::Monospace)
                    .desired_width(180.0),
            );
            if let Some(module) = self.selected_module()
                && ui.button(format!("Use {} base", module.name)).clicked()
            {
                self.pointer_base = format!("0x{:X}", module.base);
            }
        });
        ui.horizontal(|ui| {
            ui.label("Offsets");
            ui.add(
                egui::TextEdit::singleline(&mut self.pointer_offsets)
                    .font(egui::TextStyle::Monospace)
                    .desired_width(320.0),
            );
            egui::ComboBox::from_id_salt("pointer_size")
                .selected_text(format!("{}-bit pointers", self.pointer_size * 8))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.pointer_size, 8, "64-bit pointers");
                    ui.selectable_value(&mut self.pointer_size, 4, "32-bit pointers");
                });
            if ui.button("Resolve").clicked() {
                self.resolve_pointer();
            }
        });
        ui.separator();
        for (index, address) in self.pointer_trace.iter().enumerate() {
            ui.monospace(format!("{index:02}  0x{address:016X}"));
        }
        if let Some(address) = self.pointer_trace.last().copied()
            && ui.button("Open final address in Live code").clicked()
        {
            self.address_text = format!("0x{address:X}");
            self.tab = Tab::Live;
            self.read_disassembly();
        }
    }

    fn windissect_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("WinDissect exact-build intelligence");
        ui.label("Analyze a loaded module or open an existing WinDissect JSON IR.");

        if let Some(attached) = &mut self.attached {
            let selected = attached
                .modules
                .get(attached.selected_module)
                .map(|module| module.name.as_str())
                .unwrap_or("No modules");
            egui::ComboBox::from_label("Live module")
                .selected_text(selected)
                .width(360.0)
                .show_ui(ui, |ui| {
                    for (index, module) in attached.modules.iter().enumerate() {
                        ui.selectable_value(
                            &mut attached.selected_module,
                            index,
                            format!("{} · 0x{:X}", module.name, module.base),
                        );
                    }
                });
            if let Some(module) = attached.modules.get(attached.selected_module) {
                ui.monospace(&module.path);
                ui.small(format!("0x{:X} · {} KiB", module.base, module.size / 1024));
            }
        }

        ui.separator();
        egui::Grid::new("windissect_paths")
            .num_columns(2)
            .show(ui, |ui| {
                ui.label("WinDissect executable");
                ui.text_edit_singleline(&mut self.windissect_exe);
                ui.end_row();
                ui.label("Matching PDB (optional)");
                ui.text_edit_singleline(&mut self.pdb_path);
                ui.end_row();
                ui.label("IR JSON");
                ui.text_edit_singleline(&mut self.ir_path);
                ui.end_row();
            });
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    self.windissect_rx.is_none(),
                    egui::Button::new("Analyze module"),
                )
                .clicked()
            {
                self.start_windissect();
            }
            if ui
                .add_enabled(
                    self.windissect_rx.is_none() && !self.ir_path.trim().is_empty(),
                    egui::Button::new("Load IR"),
                )
                .clicked()
            {
                self.start_ir_load(PathBuf::from(self.ir_path.trim()));
            }
        });

        let Some(ir) = &self.loaded_ir else {
            return;
        };
        ui.separator();
        ui.horizontal(|ui| {
            ui.label(format!(
                "Schema {} · {} symbols",
                ir.schema,
                ir.symbols.len()
            ));
            match ir.exact_build_match {
                Some(true) => {
                    ui.colored_label(ACCENT, "SHA-256 exact build match");
                }
                Some(false) => {
                    ui.colored_label(ERROR, "SHA-256 MISMATCH — addresses are unsafe");
                }
                None => {
                    ui.colored_label(WARNING, "Build identity unavailable");
                }
            }
        });
        ui.small(format!(
            "{} · preferred base {} · image size {}",
            ir.binary.file,
            ir.binary
                .image_base
                .map_or_else(|| "unknown".into(), |value| format!("0x{value:X}")),
            ir.binary
                .image_size
                .map_or_else(|| "unknown".into(), |value| format!("{value} bytes"))
        ));
        if let Some(hash) = &ir.actual_sha256 {
            ui.small(format!("Live module file SHA-256: {hash}"));
        }

        ui.horizontal(|ui| {
            ui.label("Symbols");
            ui.text_edit_singleline(&mut self.symbol_filter);
        });
        let filter = self.symbol_filter.to_ascii_lowercase();
        let indices: Vec<_> = ir
            .symbols
            .iter()
            .enumerate()
            .filter(|(_, symbol)| {
                filter.is_empty()
                    || symbol.display_name().to_ascii_lowercase().contains(&filter)
                    || format!("{:X}", symbol.rva)
                        .to_ascii_lowercase()
                        .contains(&filter)
            })
            .map(|(index, _)| index)
            .collect();
        let mut open_address = None;
        egui::ScrollArea::vertical().show_rows(ui, 34.0, indices.len(), |ui, rows| {
            for row in rows {
                let index = indices[row];
                let symbol = &ir.symbols[index];
                let address = ir.live_address(symbol);
                let response = ui.selectable_label(
                    self.selected_symbol == Some(index),
                    format!(
                        "0x{address:016X}  {}\nRVA {:08X} · {} · {} · {}",
                        symbol.display_name(),
                        symbol.rva,
                        match (symbol.is_code, symbol.exported) {
                            (true, true) => "exported code",
                            (true, false) => "code",
                            (false, true) => "exported data",
                            (false, false) => "data",
                        },
                        symbol.confidence,
                        symbol.provenance
                    ),
                );
                if response.clicked() {
                    self.selected_symbol = Some(index);
                }
                if response.double_clicked() {
                    open_address = Some(address);
                }
            }
        });
        if let Some(address) = open_address {
            self.address_text = format!("0x{address:X}");
            self.tab = Tab::Live;
            self.read_disassembly();
        }
    }
}

impl eframe::App for GuardianApp {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_windissect();
        self.poll_artifacts();
        self.top_bar(context);
        self.status_bar(context);
        self.process_sidebar(context);

        egui::CentralPanel::default().show(context, |ui| match self.tab {
            Tab::Live => self.live_ui(ui),
            Tab::Pointer => self.pointer_ui(ui),
            Tab::Windissect => self.windissect_ui(ui),
        });

        if self.windissect_rx.is_some() || self.artifact_rx.is_some() {
            context.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}
