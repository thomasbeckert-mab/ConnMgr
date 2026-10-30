//! Rendert assets/logo.svg in die PNG-Größen eines macOS-Iconsets.
//! Aufruf: `cargo run --example render_icon -- <Zielordner.iconset>`

use egui_extras::image::load_svg_bytes_with_size;
use eframe::egui::SizeHint;

const LOGO: &[u8] = include_bytes!("../assets/logo.svg");

fn main() {
    let dir = std::env::args().nth(1).expect("Zielordner angeben, z. B. AppIcon.iconset");
    std::fs::create_dir_all(&dir).expect("Zielordner anlegen");
    // Dateinamen und Pixelgrößen, wie iconutil sie erwartet.
    let sizes = [16, 32, 128, 256, 512];
    for base in sizes {
        for (scale, suffix) in [(1, ""), (2, "@2x")] {
            let px = base * scale;
            let image = load_svg_bytes_with_size(LOGO, Some(SizeHint::Size(px, px))).expect("SVG rendern");
            let rgba: Vec<u8> = image.pixels.iter().flat_map(|c| c.to_srgba_unmultiplied()).collect();
            let path = format!("{dir}/icon_{base}x{base}{suffix}.png");
            image::save_buffer(&path, &rgba, px, px, image::ExtendedColorType::Rgba8).expect("PNG schreiben");
        }
    }
}
