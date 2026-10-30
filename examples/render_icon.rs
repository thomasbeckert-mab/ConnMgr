//! Rendert ein SVG in die PNG-Größen eines macOS-Iconsets.
//! Aufruf: `cargo run --example render_icon -- <Zielordner.iconset> [quelle.svg]`
//! Ohne Quelle wird das randlose macOS-Icon assets/icon-macos.svg verwendet.

use egui_extras::image::load_svg_bytes_with_size;
use eframe::egui::SizeHint;

fn main() {
    let dir = std::env::args().nth(1).expect("Zielordner angeben, z. B. AppIcon.iconset");
    let source = std::env::args().nth(2).unwrap_or_else(|| "assets/icon-macos.svg".into());
    let svg = std::fs::read(&source).expect("SVG lesen");
    std::fs::create_dir_all(&dir).expect("Zielordner anlegen");
    // Dateinamen und Pixelgrößen, wie iconutil sie erwartet.
    let sizes = [16, 32, 128, 256, 512];
    for base in sizes {
        for (scale, suffix) in [(1, ""), (2, "@2x")] {
            let px = base * scale;
            let image = load_svg_bytes_with_size(&svg, Some(SizeHint::Size(px, px))).expect("SVG rendern");
            let rgba: Vec<u8> = image.pixels.iter().flat_map(|c| c.to_srgba_unmultiplied()).collect();
            let path = format!("{dir}/icon_{base}x{base}{suffix}.png");
            image::save_buffer(&path, &rgba, px, px, image::ExtendedColorType::Rgba8).expect("PNG schreiben");
        }
    }
}
