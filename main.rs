#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod disasm;
mod memory;
mod scan;
mod windissect;

use app::GuardianApp;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1440.0, 900.0])
            .with_min_inner_size([1180.0, 720.0]),
        ..Default::default()
    };

    eframe::run_native(
        "HS Guardian",
        options,
        Box::new(|context| Ok(Box::new(GuardianApp::new(context)))),
    )
}
