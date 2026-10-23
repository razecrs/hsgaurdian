use std::{
    path::PathBuf,
    sync::{
        Arc,
        mpsc::{self, Receiver},
    },
    thread,
};

use eframe::egui::{self, Color32, RichText};

use crate::{
    disasm::{DisassemblyLine, disassemble, render_line},
    memory::{
        ModuleInfo, ProcessInfo, ProcessMemory, format_hex, list_modules, list_processes,
        parse_address, parse_hex_bytes, parse_offsets,
    },
    scan::{ScanHit, ScanMode, ValueType, first_scan, next_scan},
    windissect::{LoadedIr, Xref, default_executable, emit_artifacts, extract_ir, full_pipeline},
};

const ACCENT: Color32 = Color32::from_rgb(83, 214, 151);
const ACCENT_ALT: Color32 = Color32::from_rgb(126, 108, 255);
const WARNING: Color32 = Color32::from_rgb(245, 192, 88);
const ERROR: Color32 = Color32::from_rgb(244, 92, 92);
const CANVAS: Color32 = Color32::from_rgb(8, 11, 16);
const PANEL: Color32 = Color32::from_rgb(12, 16, 23);
const SURFACE: Color32 = Color32::from_rgb(18, 24, 33);
const SURFACE_HOVER: Color32 = Color32::from_rgb(25, 33, 44);
const BORDER: Color32 = Color32::from_rgb(39, 49, 63);
const MUTED: Color32 = Color32::from_rgb(137, 149, 166);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Scan,
    Live,
    Pointer,
    Windissect,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LiveMode {
    Code,
    Data,
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

    scan_type: ValueType,
    scan_mode: ScanMode,
    scan_value: String,
    scan_edit_value: String,
    scan_limit: usize,
    scan_results: Vec<ScanHit>,
    selected_scan_result: Option<usize>,
    scan_rx: Option<Receiver<Result<Vec<ScanHit>, String>>>,

    address_text: String,
    disassembly_size: usize,
    bitness: u32,
    live_mode: LiveMode,
    disassembly: Vec<DisassemblyLine>,
    memory_dump: Vec<u8>,
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
    pipeline_root: String,
    exhaustive_inventory: bool,
}

impl GuardianApp {
    fn render_hex_dump(address: usize, bytes: &[u8]) -> String {
        bytes
            .chunks(16)
            .enumerate()
            .map(|(row, chunk)| {
                let hex = chunk
                    .iter()
                    .map(|byte| format!("{byte:02X}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let text: String = chunk
                    .iter()
                    .map(|byte| {
                        if byte.is_ascii_graphic() || *byte == b' ' {
                            *byte as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                format!("{:016X}  {:<47}  |{}|", address + row * 16, hex, text)
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn install_windows_fonts(context: &egui::Context) {
        let mut fonts = egui::FontDefinitions::default();
        if let Ok(bytes) = std::fs::read(r"C:\Windows\Fonts\segoeui.ttf") {
            fonts.font_data.insert(
                "Segoe UI".into(),
                Arc::new(egui::FontData::from_owned(bytes)),
            );
            fonts
                .families
                .entry(egui::FontFamily::Proportional)
                .or_default()
                .insert(0, "Segoe UI".into());
        }
        if let Ok(bytes) = std::fs::read(r"C:\Windows\Fonts\CascadiaMono.ttf") {
            fonts.font_data.insert(
                "Cascadia Mono".into(),
                Arc::new(egui::FontData::from_owned(bytes)),
            );
            fonts
                .families
                .entry(egui::FontFamily::Monospace)
                .or_default()
                .insert(0, "Cascadia Mono".into());
        }
        context.set_fonts(fonts);
    }

    fn page_header(ui: &mut egui::Ui, kicker: &str, title: &str, subtitle: &str) {
        ui.label(RichText::new(kicker).size(11.0).strong().color(ACCENT));
        ui.label(RichText::new(title).size(25.0).strong());
        ui.label(RichText::new(subtitle).color(MUTED));
        ui.add_space(8.0);
    }

    fn tab_button(ui: &mut egui::Ui, current: &mut Tab, tab: Tab, label: &str) {
        let selected = *current == tab;
        let button = egui::Button::new(RichText::new(label).strong().color(if selected {
            Color32::BLACK
        } else {
            MUTED
        }))
        .fill(if selected {
            ACCENT
        } else {
            Color32::TRANSPARENT
        })
        .stroke(if selected {
            egui::Stroke::NONE
        } else {
            egui::Stroke::new(1.0_f32, Color32::TRANSPARENT)
        })
        .corner_radius(9);
        if ui.add(button).clicked() {
            *current = tab;
        }
    }

    pub fn new(context: &eframe::CreationContext<'_>) -> Self {
        Self::install_windows_fonts(&context.egui_ctx);
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = CANVAS;
        visuals.window_fill = SURFACE;
        visuals.window_stroke = egui::Stroke::new(1.0_f32, BORDER);
        visuals.window_corner_radius = egui::CornerRadius::same(12);
        visuals.menu_corner_radius = egui::CornerRadius::same(10);
        visuals.extreme_bg_color = Color32::from_rgb(10, 14, 20);
        visuals.text_edit_bg_color = Some(Color32::from_rgb(11, 15, 22));
        visuals.faint_bg_color = Color32::from_rgb(16, 21, 29);
        visuals.code_bg_color = Color32::from_rgb(10, 14, 20);
        visuals.selection.bg_fill = Color32::from_rgb(35, 92, 72);
        visuals.selection.stroke = egui::Stroke::new(1.0_f32, ACCENT);
        visuals.hyperlink_color = ACCENT;
        visuals.warn_fg_color = WARNING;
        visuals.error_fg_color = ERROR;
        visuals.weak_text_color = Some(MUTED);
        visuals.widgets.inactive.bg_fill = SURFACE;
        visuals.widgets.inactive.weak_bg_fill = SURFACE;
        visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0_f32, BORDER);
        visuals.widgets.inactive.corner_radius = egui::CornerRadius::same(8);
        visuals.widgets.hovered.bg_fill = SURFACE_HOVER;
        visuals.widgets.hovered.weak_bg_fill = SURFACE_HOVER;
        visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0_f32, ACCENT);
        visuals.widgets.hovered.corner_radius = egui::CornerRadius::same(8);
        visuals.widgets.active.bg_fill = Color32::from_rgb(34, 79, 66);
        visuals.widgets.active.weak_bg_fill = Color32::from_rgb(34, 79, 66);
        visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0_f32, ACCENT);
        visuals.widgets.active.corner_radius = egui::CornerRadius::same(8);
        visuals.widgets.open.bg_fill = SURFACE_HOVER;
        visuals.widgets.open.weak_bg_fill = SURFACE_HOVER;
        visuals.widgets.open.bg_stroke = egui::Stroke::new(1.0_f32, ACCENT_ALT);
        visuals.widgets.open.corner_radius = egui::CornerRadius::same(8);
        visuals.interact_cursor = Some(egui::CursorIcon::PointingHand);

        let mut style = (*context.egui_ctx.style()).clone();
        style.visuals = visuals;
        style.spacing.item_spacing = egui::vec2(10.0, 8.0);
        style.spacing.button_padding = egui::vec2(12.0, 7.0);
        style.spacing.interact_size.y = 32.0;
        style.text_styles.insert(
            egui::TextStyle::Heading,
            egui::FontId::new(24.0, egui::FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Button,
            egui::FontId::new(14.0, egui::FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Monospace,
            egui::FontId::new(13.0, egui::FontFamily::Monospace),
        );
        context.egui_ctx.set_style(style);

        let processes = list_processes().unwrap_or_default();
        Self {
            tab: Tab::Scan,
            processes,
            process_filter: String::new(),
            attached: None,
            status: "Select a process to begin".into(),
            status_error: false,
            scan_type: ValueType::I32,
            scan_mode: ScanMode::Exact,
            scan_value: String::new(),
            scan_edit_value: String::new(),
            scan_limit: 100_000,
            scan_results: Vec::new(),
            selected_scan_result: None,
            scan_rx: None,
            address_text: String::new(),
            disassembly_size: 384,
            bitness: 64,
            live_mode: LiveMode::Code,
            disassembly: Vec::new(),
            memory_dump: Vec::new(),
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
            pipeline_root: "windissect-workspaces/hill-climb-racing".into(),
            exhaustive_inventory: true,
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
                let bitness = memory.bitness();
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
                        self.bitness = bitness;
                        self.pointer_size = (bitness / 8) as usize;
                        self.scan_rx = None;
                        self.scan_results.clear();
                        self.selected_scan_result = None;
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

    fn read_memory_dump(&mut self) {
        let result = (|| {
            let address = parse_address(&self.address_text)?;
            let attached = self
                .attached
                .as_ref()
                .ok_or_else(|| "attach to a process first".to_owned())?;
            attached
                .memory
                .read(address, self.disassembly_size)
                .map_err(|error| format!("read failed at 0x{address:X}: {error}"))
        })();

        match result {
            Ok(bytes) => {
                self.memory_dump = bytes;
                self.set_status("Memory view refreshed", false);
            }
            Err(error) => self.set_status(error, true),
        }
    }

    fn refresh_live_view(&mut self) {
        match self.live_mode {
            LiveMode::Code => self.read_disassembly(),
            LiveMode::Data => self.read_memory_dump(),
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
                self.refresh_live_view();
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
                self.refresh_live_view();
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

    fn start_first_scan(&mut self) {
        let Some(pid) = self.attached.as_ref().map(|attached| attached.info.pid) else {
            self.set_status("attach to a process first", true);
            return;
        };
        let value = match self.scan_type.parse(&self.scan_value) {
            Ok(value) => value,
            Err(error) => {
                self.set_status(error, true);
                return;
            }
        };
        let value_type = self.scan_type;
        let limit = self.scan_limit;
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let _ = sender.send(first_scan(pid, value_type, &value, limit));
        });
        self.scan_rx = Some(receiver);
        self.scan_results.clear();
        self.selected_scan_result = None;
        self.set_status(
            format!("Scanning process {pid} for {}…", self.scan_value),
            false,
        );
    }

    fn start_next_scan(&mut self) {
        let Some(pid) = self.attached.as_ref().map(|attached| attached.info.pid) else {
            self.set_status("attach to a process first", true);
            return;
        };
        if self.scan_results.is_empty() {
            self.set_status("run a first scan before refining results", true);
            return;
        }
        let exact = if self.scan_mode == ScanMode::Exact {
            match self.scan_type.parse(&self.scan_value) {
                Ok(value) => Some(value),
                Err(error) => {
                    self.set_status(error, true);
                    return;
                }
            }
        } else {
            None
        };
        let hits = self.scan_results.clone();
        let value_type = self.scan_type;
        let mode = self.scan_mode;
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let _ = sender.send(next_scan(pid, value_type, hits, mode, exact));
        });
        self.scan_rx = Some(receiver);
        self.selected_scan_result = None;
        self.set_status(format!("Refining with {}…", mode.label()), false);
    }

    fn poll_scan(&mut self) {
        let result = self
            .scan_rx
            .as_ref()
            .and_then(|receiver| receiver.try_recv().ok());
        let Some(result) = result else {
            return;
        };
        self.scan_rx = None;
        match result {
            Ok(results) => {
                let count = results.len();
                self.scan_results = results;
                self.set_status(format!("Scan complete · {count} results"), false);
            }
            Err(error) => self.set_status(error, true),
        }
    }

    fn write_scan_result(&mut self) {
        let result = (|| {
            let index = self
                .selected_scan_result
                .ok_or_else(|| "select a scan result first".to_owned())?;
            let hit = self
                .scan_results
                .get(index)
                .ok_or_else(|| "the selected result no longer exists".to_owned())?;
            let address = hit.address;
            let replacement = self.scan_type.parse(&self.scan_edit_value)?;
            let attached = self
                .attached
                .as_ref()
                .ok_or_else(|| "attach to a process first".to_owned())?;
            let original = attached
                .memory
                .patch(address, &replacement)
                .map_err(|error| format!("write failed: {error}"))?;
            Ok::<_, String>((index, address, original, replacement))
        })();

        match result {
            Ok((index, address, original, replacement)) => {
                self.patches.push(PatchRecord {
                    address,
                    original: original.clone(),
                    replacement: replacement.clone(),
                    active: true,
                });
                self.scan_results[index].previous = original;
                self.scan_results[index].current = replacement;
                self.set_status(format!("Wrote value at 0x{address:X}"), false);
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

    fn start_full_pipeline(&mut self) {
        let Some(module) = self.selected_module().cloned() else {
            self.set_status("select an attached module first", true);
            return;
        };
        let executable = PathBuf::from(self.windissect_exe.trim());
        let pdb = (!self.pdb_path.trim().is_empty()).then(|| PathBuf::from(self.pdb_path.trim()));
        let module_stem = PathBuf::from(&module.name)
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or("module")
            .to_ascii_lowercase();
        let root = PathBuf::from(self.pipeline_root.trim()).join(module_stem);
        let semantic_ir = root.join("ir").join("semantic.json");
        self.ir_path = semantic_ir.display().to_string();
        let exhaustive = self.exhaustive_inventory;
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let result = full_pipeline(&executable, &module, pdb.as_deref(), &root, exhaustive)
                .and_then(|ir| LoadedIr::load(ir, &module));
            let _ = sender.send(result);
        });
        self.windissect_rx = Some(receiver);
        self.set_status(
            format!(
                "Building the full WinDissect SDK for {}…",
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
            .default_width(276.0)
            .frame(
                egui::Frame::new()
                    .fill(PANEL)
                    .inner_margin(egui::Margin::symmetric(14, 16))
                    .stroke(egui::Stroke::new(1.0_f32, BORDER)),
            )
            .show(context, |ui| {
                ui.label(
                    RichText::new("TARGETS")
                        .size(11.0)
                        .strong()
                        .color(ACCENT_ALT),
                );
                ui.label(RichText::new("Process explorer").size(19.0).strong());
                ui.label(
                    RichText::new("Double-click a process to attach")
                        .size(11.0)
                        .color(MUTED),
                );
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.process_filter)
                            .hint_text("Filter by name or PID…")
                            .desired_width(210.0),
                    );
                    if ui
                        .button(RichText::new("↻").size(18.0))
                        .on_hover_text("Refresh processes")
                        .clicked()
                    {
                        self.refresh_processes();
                    }
                });
                ui.add_space(6.0);

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
                        let card = egui::Frame::new()
                            .fill(if selected {
                                Color32::from_rgb(25, 59, 50)
                            } else {
                                SURFACE
                            })
                            .stroke(egui::Stroke::new(
                                1.0_f32,
                                if selected { ACCENT } else { BORDER },
                            ))
                            .corner_radius(10)
                            .inner_margin(egui::Margin::symmetric(10, 9))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let (rect, _) = ui.allocate_exact_size(
                                        egui::vec2(30.0, 30.0),
                                        egui::Sense::hover(),
                                    );
                                    ui.painter().circle_filled(
                                        rect.center(),
                                        15.0,
                                        if selected { ACCENT } else { SURFACE_HOVER },
                                    );
                                    ui.painter().text(
                                        rect.center(),
                                        egui::Align2::CENTER_CENTER,
                                        process
                                            .name
                                            .chars()
                                            .next()
                                            .unwrap_or('?')
                                            .to_ascii_uppercase(),
                                        egui::FontId::proportional(14.0),
                                        if selected { Color32::BLACK } else { MUTED },
                                    );
                                    ui.vertical(|ui| {
                                        ui.label(RichText::new(&process.name).strong());
                                        ui.label(
                                            RichText::new(format!("PID {}", process.pid))
                                                .size(11.0)
                                                .color(MUTED),
                                        );
                                    });
                                });
                            });
                        let response = card.response.interact(egui::Sense::click());
                        if response.double_clicked() {
                            attach_request = Some(process);
                        }
                        ui.add_space(5.0);
                    }
                });
            });

        if let Some(process) = attach_request {
            self.attach(process);
        }
    }

    fn top_bar(&mut self, context: &egui::Context) {
        egui::TopBottomPanel::top("top_bar")
            .exact_height(66.0)
            .frame(
                egui::Frame::new()
                    .fill(PANEL)
                    .inner_margin(egui::Margin::symmetric(18, 12))
                    .stroke(egui::Stroke::new(1.0_f32, BORDER)),
            )
            .show(context, |ui| {
                ui.horizontal_centered(|ui| {
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(36.0, 36.0), egui::Sense::hover());
                    ui.painter().circle_filled(rect.center(), 18.0, ACCENT);
                    ui.painter().circle_stroke(
                        rect.center(),
                        12.0,
                        egui::Stroke::new(2.0_f32, Color32::BLACK),
                    );
                    ui.painter().line_segment(
                        [
                            rect.center() + egui::vec2(-6.0, 0.0),
                            rect.center() + egui::vec2(6.0, 0.0),
                        ],
                        egui::Stroke::new(2.0_f32, Color32::BLACK),
                    );
                    ui.vertical(|ui| {
                        ui.label(RichText::new("HS GUARDIAN").size(16.0).strong());
                        ui.label(RichText::new("LIVE BINARY LAB").size(9.0).color(MUTED));
                    });
                    ui.add_space(24.0);
                    Self::tab_button(ui, &mut self.tab, Tab::Scan, "Search");
                    Self::tab_button(ui, &mut self.tab, Tab::Live, "Live code");
                    Self::tab_button(ui, &mut self.tab, Tab::Pointer, "Pointers");
                    Self::tab_button(ui, &mut self.tab, Tab::Windissect, "WinDissect");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if let Some(attached) = &self.attached {
                            let access = if attached.memory.writable {
                                "R/W"
                            } else {
                                "READ"
                            };
                            ui.label(RichText::new(access).size(11.0).strong().color(
                                if attached.memory.writable {
                                    ACCENT
                                } else {
                                    WARNING
                                },
                            ));
                            ui.label(
                                RichText::new(format!(
                                    "{} · {}",
                                    attached.info.name, attached.info.pid
                                ))
                                .color(MUTED),
                            );
                            ui.colored_label(ACCENT, "●");
                        } else {
                            ui.label(RichText::new("No target").color(MUTED));
                            ui.colored_label(WARNING, "●");
                        }
                    });
                });
            });
    }

    fn status_bar(&mut self, context: &egui::Context) {
        egui::TopBottomPanel::bottom("status")
            .exact_height(34.0)
            .frame(
                egui::Frame::new()
                    .fill(PANEL)
                    .inner_margin(egui::Margin::symmetric(14, 5))
                    .stroke(egui::Stroke::new(1.0_f32, BORDER)),
            )
            .show(context, |ui| {
                ui.horizontal(|ui| {
                    if self.scan_rx.is_some()
                        || self.windissect_rx.is_some()
                        || self.artifact_rx.is_some()
                    {
                        ui.spinner();
                    }
                    ui.colored_label(if self.status_error { ERROR } else { MUTED }, &self.status);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(RichText::new("USER MODE · LOCAL").size(10.0).color(MUTED));
                    });
                });
            });
    }

    fn scan_ui(&mut self, ui: &mut egui::Ui) {
        Self::page_header(
            ui,
            "MEMORY SEARCH",
            "Track a value through time",
            "Start with a typed value, change it in the target, then keep only what moved.",
        );
        egui::Frame::new()
            .fill(SURFACE)
            .stroke(egui::Stroke::new(1.0_f32, BORDER))
            .corner_radius(12)
            .inner_margin(egui::Margin::same(14))
            .show(ui, |ui| {
                ui.label(
                    RichText::new("SCAN CONTROL")
                        .size(10.0)
                        .strong()
                        .color(MUTED),
                );
                ui.horizontal(|ui| {
                    ui.add_enabled_ui(
                        self.scan_results.is_empty() && self.scan_rx.is_none(),
                        |ui| {
                            egui::ComboBox::from_id_salt("scan_type")
                                .selected_text(self.scan_type.label())
                                .show_ui(ui, |ui| {
                                    for value_type in ValueType::ALL {
                                        ui.selectable_value(
                                            &mut self.scan_type,
                                            value_type,
                                            value_type.label(),
                                        );
                                    }
                                });
                        },
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.scan_value)
                            .font(egui::TextStyle::Monospace)
                            .hint_text("Value")
                            .desired_width(180.0),
                    );
                    ui.label("Max results");
                    ui.add(egui::DragValue::new(&mut self.scan_limit).range(100..=1_000_000));
                    if ui
                        .add_enabled(
                            self.scan_rx.is_none(),
                            egui::Button::new(
                                RichText::new("First scan").strong().color(Color32::BLACK),
                            )
                            .fill(ACCENT)
                            .stroke(egui::Stroke::NONE),
                        )
                        .clicked()
                    {
                        self.start_first_scan();
                    }
                });
                ui.horizontal(|ui| {
                    egui::ComboBox::from_id_salt("scan_mode")
                        .selected_text(self.scan_mode.label())
                        .show_ui(ui, |ui| {
                            for mode in ScanMode::ALL {
                                ui.selectable_value(&mut self.scan_mode, mode, mode.label());
                            }
                        });
                    if ui
                        .add_enabled(
                            self.scan_rx.is_none() && !self.scan_results.is_empty(),
                            egui::Button::new(RichText::new("Next scan").strong())
                                .fill(Color32::from_rgb(54, 46, 112))
                                .stroke(egui::Stroke::new(1.0_f32, ACCENT_ALT)),
                        )
                        .clicked()
                    {
                        self.start_next_scan();
                    }
                    if ui.button("Reset").clicked() {
                        self.scan_results.clear();
                        self.selected_scan_result = None;
                        self.set_status("Scan results cleared", false);
                    }
                    ui.separator();
                    ui.label(format!("{} results", self.scan_results.len()));
                    if self.scan_results.len() == self.scan_limit {
                        ui.colored_label(WARNING, "result limit reached");
                    }
                });
                ui.label(
                    RichText::new(
                        "Changed, increased, and decreased compare against the previous snapshot.",
                    )
                    .size(11.0)
                    .color(MUTED),
                );
            });
        ui.add_space(12.0);

        ui.columns(2, |columns| {
            columns[0].horizontal(|ui| {
                ui.strong("Address");
                ui.add_space(115.0);
                ui.strong("Current");
                ui.add_space(55.0);
                ui.strong("Previous");
            });

            let mut selected = None;
            egui::ScrollArea::vertical()
                .id_salt("scan_results")
                .show_rows(
                    &mut columns[0],
                    24.0,
                    self.scan_results.len(),
                    |ui, rows| {
                        for index in rows {
                            let hit = &self.scan_results[index];
                            let current = self.scan_type.format(&hit.current);
                            let previous = self.scan_type.format(&hit.previous);
                            let changed = hit.current != hit.previous;
                            let label = format!(
                                "0x{:016X}    {:>16}    {:>16}{}",
                                hit.address,
                                current,
                                previous,
                                if changed { "  *" } else { "" }
                            );
                            if ui
                                .selectable_label(
                                    self.selected_scan_result == Some(index),
                                    RichText::new(label).monospace().color(if changed {
                                        ACCENT
                                    } else {
                                        Color32::WHITE
                                    }),
                                )
                                .clicked()
                            {
                                selected = Some(index);
                            }
                        }
                    },
                );

            if let Some(index) = selected {
                self.selected_scan_result = Some(index);
                let hit = &self.scan_results[index];
                self.scan_edit_value = self.scan_type.format(&hit.current);
            }

            columns[1].label(
                RichText::new("RESULT INSPECTOR")
                    .size(11.0)
                    .strong()
                    .color(ACCENT_ALT),
            );
            if let Some(index) = self.selected_scan_result {
                if let Some(hit) = self.scan_results.get(index) {
                    let address = hit.address;
                    columns[1].monospace(format!("0x{address:016X}"));
                    columns[1].label(format!("Current: {}", self.scan_type.format(&hit.current)));
                    columns[1].label(format!(
                        "Previous: {}",
                        self.scan_type.format(&hit.previous)
                    ));
                    columns[1].separator();
                    columns[1].label("New value");
                    columns[1].add(
                        egui::TextEdit::singleline(&mut self.scan_edit_value)
                            .font(egui::TextStyle::Monospace),
                    );
                    columns[1].horizontal(|ui| {
                        if ui.button("Write value").clicked() {
                            self.write_scan_result();
                        }
                        if ui.button("Inspect memory").clicked() {
                            self.address_text = format!("0x{address:X}");
                            self.tab = Tab::Live;
                            self.live_mode = LiveMode::Data;
                            self.read_memory_dump();
                        }
                    });
                }
            } else {
                columns[1].label("Select a result to inspect or edit it.");
            }
        });
    }

    fn live_ui(&mut self, ui: &mut egui::Ui) {
        Self::page_header(
            ui,
            "LIVE CODE",
            "Inspect. Patch. Roll back.",
            "Disassemble the target in place, follow control flow, and keep every byte change reversible.",
        );
        egui::Frame::new()
            .fill(SURFACE)
            .stroke(egui::Stroke::new(1.0_f32, BORDER))
            .corner_radius(12)
            .inner_margin(egui::Margin::symmetric(14, 10))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.live_mode, LiveMode::Code, "Instructions");
                    ui.selectable_value(&mut self.live_mode, LiveMode::Data, "Hex / data");
                    ui.separator();
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
                    if ui
                        .button(match self.live_mode {
                            LiveMode::Code => "Disassemble",
                            LiveMode::Data => "Read memory",
                        })
                        .clicked()
                    {
                        self.refresh_live_view();
                    }
                    if ui.button("Find xrefs / writes").clicked() {
                        self.find_xrefs();
                    }
                });
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
            match self.live_mode {
                LiveMode::Code => {
                    columns[0].heading("Live instructions");
                    egui::ScrollArea::vertical().id_salt("disassembly").show(
                        &mut columns[0],
                        |ui| {
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
                                                "call ->"
                                            } else {
                                                "jump ->"
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
                        },
                    );
                }
                LiveMode::Data => {
                    columns[0].heading("Memory inspector");
                    let address = parse_address(&self.address_text).unwrap_or_default();
                    let dump = Self::render_hex_dump(address, &self.memory_dump);
                    egui::ScrollArea::both()
                        .id_salt("memory_dump")
                        .show(&mut columns[0], |ui| {
                            ui.add(
                                egui::Label::new(RichText::new(dump).monospace())
                                    .selectable(true)
                                    .wrap_mode(egui::TextWrapMode::Extend),
                            );
                        });
                }
            }

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
                self.live_mode = LiveMode::Code;
                self.read_disassembly();
            }

            columns[1].separator();
            columns[1].heading("Patch history");
            let mut rollback = None;
            for (index, patch) in self.patches.iter().enumerate().rev() {
                columns[1].horizontal(|ui| {
                    ui.monospace(format!("0x{:X}", patch.address));
                    ui.small(format!(
                        "{} -> {}",
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
        Self::page_header(
            ui,
            "POINTER LAB",
            "Chase stable paths through memory",
            "Each offset is added in order; every non-final step is dereferenced.",
        );
        egui::Frame::new()
            .fill(SURFACE)
            .stroke(egui::Stroke::new(1.0_f32, BORDER))
            .corner_radius(12)
            .inner_margin(egui::Margin::same(14))
            .show(ui, |ui| {
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
            });
        ui.separator();
        for (index, address) in self.pointer_trace.iter().enumerate() {
            ui.monospace(format!("{index:02}  0x{address:016X}"));
        }
        if let Some(address) = self.pointer_trace.last().copied()
            && ui.button("Inspect final address").clicked()
        {
            self.address_text = format!("0x{address:X}");
            self.tab = Tab::Live;
            self.live_mode = LiveMode::Data;
            self.read_memory_dump();
        }
    }

    fn windissect_ui(&mut self, ui: &mut egui::Ui) {
        Self::page_header(
            ui,
            "WINDISSECT",
            "Exact-build binary intelligence",
            "Anchor live addresses to verified symbols, types, evidence, and generated bindings.",
        );

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
                ui.label("Workspace root");
                ui.text_edit_singleline(&mut self.pipeline_root);
                ui.end_row();
                ui.label("Artifact output");
                ui.text_edit_singleline(&mut self.artifact_output);
                ui.end_row();
            });
        ui.checkbox(
            &mut self.exhaustive_inventory,
            "Include exhaustive PDB/PE inventory (slower, best for SDK work)",
        );
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    self.windissect_rx.is_none(),
                    egui::Button::new(
                        RichText::new("Build full SDK")
                            .strong()
                            .color(Color32::BLACK),
                    )
                    .fill(ACCENT)
                    .stroke(egui::Stroke::NONE),
                )
                .clicked()
            {
                self.start_full_pipeline();
            }
            if ui
                .add_enabled(
                    self.windissect_rx.is_none(),
                    egui::Button::new("Quick extract"),
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
            if ui
                .add_enabled(
                    self.artifact_rx.is_none() && self.loaded_ir.is_some(),
                    egui::Button::new("Regenerate artifacts"),
                )
                .clicked()
            {
                self.start_artifact_generation();
            }
        });

        let Some(ir) = &self.loaded_ir else {
            return;
        };
        ui.separator();
        ui.horizontal(|ui| {
            ui.label(format!(
                "Schema {} · {} symbols · {} functions · {} instructions",
                ir.schema,
                ir.symbols.len(),
                ir.function_count(),
                ir.instruction_count()
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
            "{} · {} · preferred base {} · image size {}",
            ir.binary.file,
            ir.binary.machine.as_deref().unwrap_or("unknown machine"),
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
            self.live_mode = LiveMode::Code;
            self.read_disassembly();
        }
    }
}

impl eframe::App for GuardianApp {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_scan();
        self.poll_windissect();
        self.poll_artifacts();
        self.top_bar(context);
        self.status_bar(context);
        self.process_sidebar(context);

        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(CANVAS)
                    .inner_margin(egui::Margin::same(20)),
            )
            .show(context, |ui| match self.tab {
                Tab::Scan => self.scan_ui(ui),
                Tab::Live => self.live_ui(ui),
                Tab::Pointer => self.pointer_ui(ui),
                Tab::Windissect => self.windissect_ui(ui),
            });

        if self.scan_rx.is_some() || self.windissect_rx.is_some() || self.artifact_rx.is_some() {
            context.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}
