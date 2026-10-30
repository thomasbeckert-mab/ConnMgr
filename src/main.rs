#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[macro_use]
mod i18n;
mod app;
mod askpass;
mod biometric;
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
use std::sync::Arc;

use eframe::egui;

/// Logo als Vektorgrafik: App-Icon, Sperrbildschirm und leerer Hintergrund.
pub const LOGO: egui::ImageSource<'static> = egui::include_image!("../assets/logo.svg");

/// Fenster-Icon (Taskleiste unter Windows/Linux, Dock beim Start ohne App-Bundle) aus dem SVG.
fn window_icon() -> Option<Arc<egui::IconData>> {
    let image = egui_extras::image::load_svg_bytes_with_size(include_bytes!("../assets/logo.svg"), Some(egui::SizeHint::Size(256, 256))).ok()?;
    let rgba = image.pixels.iter().flat_map(|c| c.to_srgba_unmultiplied()).collect();
    Some(Arc::new(egui::IconData { rgba, width: 256, height: 256 }))
}

fn main() -> eframe::Result {
    // ssh startet dieses Programm als SSH_ASKPASS-Helfer, das Prompt steht in argv[1].
    if let Ok(spec) = std::env::var(askpass::ENV_VAR) {
        let prompt = std::env::args().nth(1).unwrap_or_default();
        std::process::exit(askpass::run_helper(&spec, &prompt));
    }

    // Optional: eigener Pfad zur Verbindungsdatei als erstes Argument.
    let path = std::env::args_os().nth(1).map(PathBuf::from).unwrap_or_else(store::default_path);

    let mut viewport = egui::ViewportBuilder::default().with_title("ConnMgr").with_inner_size([900.0, 560.0]);
    if let Some(icon) = window_icon() {
        viewport = viewport.with_icon(icon);
    }
    let options = eframe::NativeOptions { viewport, ..Default::default() };
    eframe::run_native(
        "ConnMgr",
        options,
        Box::new(move |cc| {
            egui_extras::install_image_loaders(&cc.egui_ctx);
            Ok(Box::new(app::ConnMgrApp::new(path)))
        }),
    )
}
