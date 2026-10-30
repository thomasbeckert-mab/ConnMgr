#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod askpass;
mod crypto;
mod dialogs;
mod launcher;
mod model;
mod rdp;
mod sftp;
mod ssh;
mod terminal;
mod vnc;
mod store;

use std::path::PathBuf;

use eframe::egui;

fn main() -> eframe::Result {
    // ssh startet dieses Programm als SSH_ASKPASS-Helfer, das Prompt steht in argv[1].
    if let Ok(spec) = std::env::var(askpass::ENV_VAR) {
        let prompt = std::env::args().nth(1).unwrap_or_default();
        std::process::exit(askpass::run_helper(&spec, &prompt));
    }

    // Optional: eigener Pfad zur Verbindungsdatei als erstes Argument.
    let path = std::env::args_os().nth(1).map(PathBuf::from).unwrap_or_else(store::default_path);

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_title("ConMgr").with_inner_size([900.0, 560.0]),
        ..Default::default()
    };
    eframe::run_native("ConMgr", options, Box::new(move |_cc| Ok(Box::new(app::ConMgrApp::new(path)))))
}
