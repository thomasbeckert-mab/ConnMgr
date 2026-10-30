//! Zeichnet einen vt100-Bildschirm mit egui und setzt Eingaben in Terminal-Sequenzen um.

use eframe::egui::{self, Color32, CursorIcon, Event, EventFilter, FontId, Key, Modifiers, Pos2, Rect, Sense, Stroke, Vec2};

use crate::ssh::{SshSession, Status};

const FONT_SIZE: f32 = 13.0;
const BACKGROUND: Color32 = Color32::from_rgb(0x1e, 0x1e, 0x1e);
const FOREGROUND: Color32 = Color32::from_rgb(0xd4, 0xd4, 0xd4);
const SELECTION: Color32 = Color32::from_rgb(0x26, 0x4f, 0x78);

/// Was die Oberfläche nach dem Zeichnen tun soll.
#[derive(Default)]
pub struct TerminalResponse {
    pub reconnect: bool,
    pub close: bool,
}

/// Zustand der Ansicht, der nicht zum Bildschirminhalt gehört.
#[derive(Default)]
pub struct TerminalView {
    size: (u16, u16),
    /// Markierung in sichtbaren Zellen (Zeile, Spalte), Anfang und Ende in Zugreihenfolge.
    selection: Option<((u16, u16), (u16, u16))>,
    scroll_remainder: f32,
    focus_requested: bool,
}

impl TerminalView {
    pub fn show(&mut self, ui: &mut egui::Ui, session: &SshSession) -> TerminalResponse {
        let mut out = TerminalResponse::default();
        let font = FontId::monospace(FONT_SIZE);
        let (cell_w, cell_h) = ui.fonts(|f| (f.glyph_width(&font, 'M'), f.row_height(&font)));

        let rect = ui.available_rect_before_wrap();
        let response = ui.allocate_rect(rect, Sense::click_and_drag());
        let cols = ((rect.width() / cell_w).floor() as u16).max(10);
        let rows = ((rect.height() / cell_h).floor() as u16).max(3);
        if self.size != (cols, rows) {
            self.size = (cols, rows);
            session.resize(cols, rows);
        }

        if !self.focus_requested || response.clicked() || response.drag_started() {
            response.request_focus();
            self.focus_requested = true;
        }
        let focused = response.has_focus();
        if focused {
            // Tab, Pfeile und Escape gehören dem Terminal, nicht der egui-Fokusnavigation.
            let filter = EventFilter { tab: true, horizontal_arrows: true, vertical_arrows: true, escape: true };
            ui.memory_mut(|m| m.set_focus_lock_filter(response.id, filter));
        }
        if response.hovered() {
            ui.ctx().set_cursor_icon(CursorIcon::Text);
        }

        let cell_at = |pos: Pos2| -> (u16, u16) {
            let col = ((pos.x - rect.left()) / cell_w).floor().clamp(0.0, f32::from(cols - 1)) as u16;
            let row = ((pos.y - rect.top()) / cell_h).floor().clamp(0.0, f32::from(rows - 1)) as u16;
            (row, col)
        };
        if response.drag_started() {
            if let Some(pos) = response.interact_pointer_pos() {
                let cell = cell_at(pos);
                self.selection = Some((cell, cell));
            }
        } else if response.dragged() {
            if let (Some(pos), Some((start, _))) = (response.interact_pointer_pos(), self.selection) {
                self.selection = Some((start, cell_at(pos)));
            }
        } else if response.clicked() {
            self.selection = None;
        }

        let mut shared = session.lock();

        // Mausrad blättert im Verlauf (nicht im Vollbildmodus von vim, less & Co.).
        if response.hovered() && !shared.parser.screen().alternate_screen() {
            self.scroll_remainder += ui.input(|i| i.smooth_scroll_delta.y);
            let lines = (self.scroll_remainder / cell_h).trunc();
            if lines != 0.0 {
                self.scroll_remainder -= lines * cell_h;
                let screen = shared.parser.screen_mut();
                let target = (screen.scrollback() as i64 + lines as i64).max(0) as usize;
                screen.set_scrollback(target);
            }
        }

        if focused && matches!(shared.status, Status::Connected) {
            let screen = shared.parser.screen();
            let selected_text = self.selection.map(|(a, b)| {
                let (start, end) = if a <= b { (a, b) } else { (b, a) };
                screen.contents_between(start.0, start.1, end.0, end.1 + 1)
            });
            let mut input = Vec::new();
            for event in ui.input(|i| i.events.clone()) {
                match event {
                    Event::Copy => match &selected_text {
                        Some(text) if !text.is_empty() => ui.ctx().copy_text(text.clone()),
                        // Unter Windows/Linux ist Strg+C sonst nicht erreichbar.
                        _ if !cfg!(target_os = "macos") => input.push(0x03),
                        _ => {}
                    },
                    Event::Cut if !cfg!(target_os = "macos") => input.push(0x18),
                    Event::Paste(text) => input.extend(paste_bytes(&text, screen.bracketed_paste())),
                    Event::Text(text) => input.extend(text.as_bytes()),
                    Event::Key { key, pressed: true, modifiers, .. } => {
                        if let Some(bytes) = key_bytes(key, modifiers, screen.application_cursor()) {
                            input.extend(bytes);
                        }
                    }
                    _ => {}
                }
            }
            if !input.is_empty() {
                shared.parser.screen_mut().set_scrollback(0);
                self.selection = None;
                session.send(input);
            }
        }

        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 0.0, BACKGROUND);
        paint_screen(&painter, shared.parser.screen(), rect.min, (cell_w, cell_h), (rows, cols), self.selection, focused);

        match &shared.status {
            Status::Connecting => overlay_text(&painter, rect, "Verbinde …"),
            Status::Connected => {}
            Status::HostKey { fingerprint, algorithm } => {
                let (fingerprint, algorithm) = (fingerprint.clone(), algorithm.clone());
                drop(shared);
                host_key_dialog(ui, rect, &fingerprint, &algorithm, session, &mut out);
            }
            Status::Closed(message) => {
                let message = message.clone();
                drop(shared);
                closed_bar(ui, rect, &message, &mut out);
            }
        }
        out
    }
}

fn paint_screen(
    painter: &egui::Painter,
    screen: &vt100::Screen,
    origin: Pos2,
    (cell_w, cell_h): (f32, f32),
    (rows, cols): (u16, u16),
    selection: Option<((u16, u16), (u16, u16))>,
    focused: bool,
) {
    let font = FontId::monospace(FONT_SIZE);
    let selection = selection.map(|(a, b)| if a <= b { (a, b) } else { (b, a) });
    let is_selected = |row: u16, col: u16| selection.is_some_and(|(s, e)| (row, col) >= s && (row, col) <= e);

    for row in 0..rows {
        let y = origin.y + f32::from(row) * cell_h;
        // Zellen gleicher Darstellung zu Läufen zusammenfassen und je Lauf einmal zeichnen.
        let mut col = 0;
        while col < cols {
            let style = cell_style(screen.cell(row, col), is_selected(row, col));
            let start = col;
            let mut text = String::new();
            while col < cols {
                let cell = screen.cell(row, col);
                if col > start && (cell_style(cell, is_selected(row, col)) != style || cell.is_some_and(|c| c.is_wide())) {
                    break;
                }
                match cell {
                    Some(c) if c.is_wide_continuation() => {}
                    Some(c) if c.has_contents() => text.push_str(c.contents()),
                    _ => text.push(' '),
                }
                col += 1;
                if cell.is_some_and(|c| c.is_wide()) {
                    break;
                }
            }
            let x = origin.x + f32::from(start) * cell_w;
            let run = Rect::from_min_size(Pos2::new(x, y), Vec2::new(f32::from(col - start) * cell_w, cell_h));
            if style.bg != BACKGROUND {
                painter.rect_filled(run, 0.0, style.bg);
            }
            if !text.trim().is_empty() {
                painter.text(run.min, egui::Align2::LEFT_TOP, &text, font.clone(), style.fg);
            }
            if style.underline {
                painter.line_segment([run.left_bottom(), run.right_bottom()], Stroke::new(1.0_f32, style.fg));
            }
        }
    }

    if !screen.hide_cursor() && screen.scrollback() == 0 {
        let (row, col) = screen.cursor_position();
        let pos = Pos2::new(origin.x + f32::from(col) * cell_w, origin.y + f32::from(row) * cell_h);
        let cursor = Rect::from_min_size(pos, Vec2::new(cell_w, cell_h));
        if focused {
            painter.rect_filled(cursor, 0.0, FOREGROUND.gamma_multiply(0.6));
        } else {
            painter.rect_stroke(cursor, 0.0, Stroke::new(1.0_f32, FOREGROUND));
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
struct CellStyle {
    fg: Color32,
    bg: Color32,
    underline: bool,
}

fn cell_style(cell: Option<&vt100::Cell>, selected: bool) -> CellStyle {
    let Some(cell) = cell else {
        return CellStyle { fg: FOREGROUND, bg: if selected { SELECTION } else { BACKGROUND }, underline: false };
    };
    let mut fg = color(cell.fgcolor(), FOREGROUND, cell.bold());
    let mut bg = color(cell.bgcolor(), BACKGROUND, false);
    if cell.inverse() {
        std::mem::swap(&mut fg, &mut bg);
    }
    if cell.dim() {
        fg = fg.gamma_multiply(0.6);
    }
    if selected {
        bg = SELECTION;
    }
    CellStyle { fg, bg, underline: cell.underline() }
}

/// xterm-256-Farben; fett hebt die acht Grundfarben auf ihre hellen Varianten.
fn color(c: vt100::Color, default: Color32, bold: bool) -> Color32 {
    const BASE: [(u8, u8, u8); 16] = [
        (0x00, 0x00, 0x00), (0xcd, 0x31, 0x31), (0x0d, 0xbc, 0x79), (0xe5, 0xe5, 0x10),
        (0x24, 0x72, 0xc8), (0xbc, 0x3f, 0xbc), (0x11, 0xa8, 0xcd), (0xe5, 0xe5, 0xe5),
        (0x66, 0x66, 0x66), (0xf1, 0x4c, 0x4c), (0x23, 0xd1, 0x8b), (0xf5, 0xf5, 0x43),
        (0x3b, 0x8e, 0xea), (0xd6, 0x70, 0xd6), (0x29, 0xb8, 0xdb), (0xff, 0xff, 0xff),
    ];
    match c {
        vt100::Color::Default => default,
        vt100::Color::Rgb(r, g, b) => Color32::from_rgb(r, g, b),
        vt100::Color::Idx(i) => {
            let i = if bold && i < 8 { i + 8 } else { i };
            match i {
                0..=15 => {
                    let (r, g, b) = BASE[usize::from(i)];
                    Color32::from_rgb(r, g, b)
                }
                16..=231 => {
                    let i = i - 16;
                    let level = |v: u8| if v == 0 { 0 } else { 55 + v * 40 };
                    Color32::from_rgb(level(i / 36), level((i / 6) % 6), level(i % 6))
                }
                232..=255 => {
                    let v = 8 + (i - 232) * 10;
                    Color32::from_rgb(v, v, v)
                }
            }
        }
    }
}

fn paste_bytes(text: &str, bracketed: bool) -> Vec<u8> {
    let text = text.replace("\r\n", "\r").replace('\n', "\r");
    if bracketed {
        format!("\x1b[200~{text}\x1b[201~").into_bytes()
    } else {
        text.into_bytes()
    }
}

/// Tasten, die kein `Event::Text` erzeugen, als Escape-Sequenzen (xterm).
fn key_bytes(key: Key, modifiers: Modifiers, application_cursor: bool) -> Option<Vec<u8>> {
    let csi_or_ss3 = |c: char| {
        if application_cursor {
            format!("\x1bO{c}")
        } else {
            format!("\x1b[{c}")
        }
    };
    let seq = match key {
        Key::Enter => "\r".to_owned(),
        Key::Tab if modifiers.shift => "\x1b[Z".to_owned(),
        Key::Tab => "\t".to_owned(),
        Key::Backspace => "\x7f".to_owned(),
        Key::Escape => "\x1b".to_owned(),
        Key::ArrowUp => csi_or_ss3('A'),
        Key::ArrowDown => csi_or_ss3('B'),
        Key::ArrowRight => csi_or_ss3('C'),
        Key::ArrowLeft => csi_or_ss3('D'),
        Key::Home => csi_or_ss3('H'),
        Key::End => csi_or_ss3('F'),
        Key::Insert => "\x1b[2~".to_owned(),
        Key::Delete => "\x1b[3~".to_owned(),
        Key::PageUp => "\x1b[5~".to_owned(),
        Key::PageDown => "\x1b[6~".to_owned(),
        Key::F1 => "\x1bOP".to_owned(),
        Key::F2 => "\x1bOQ".to_owned(),
        Key::F3 => "\x1bOR".to_owned(),
        Key::F4 => "\x1bOS".to_owned(),
        Key::F5 => "\x1b[15~".to_owned(),
        Key::F6 => "\x1b[17~".to_owned(),
        Key::F7 => "\x1b[18~".to_owned(),
        Key::F8 => "\x1b[19~".to_owned(),
        Key::F9 => "\x1b[20~".to_owned(),
        Key::F10 => "\x1b[21~".to_owned(),
        Key::F11 => "\x1b[23~".to_owned(),
        Key::F12 => "\x1b[24~".to_owned(),
        Key::Space if modifiers.ctrl => "\0".to_owned(),
        // Strg+Buchstabe → Steuerzeichen (Strg+C = 0x03 usw.).
        _ if modifiers.ctrl => {
            let name = key.name();
            let letter = name.chars().next().filter(|c| name.len() == 1 && c.is_ascii_alphabetic())?;
            return Some(vec![letter.to_ascii_uppercase() as u8 - b'A' + 1]);
        }
        _ => return None,
    };
    Some(seq.into_bytes())
}

fn overlay_text(painter: &egui::Painter, rect: Rect, text: &str) {
    painter.text(rect.center(), egui::Align2::CENTER_CENTER, text, FontId::proportional(16.0), FOREGROUND);
}

fn host_key_dialog(
    ui: &mut egui::Ui,
    rect: Rect,
    fingerprint: &str,
    algorithm: &str,
    session: &SshSession,
    out: &mut TerminalResponse,
) {
    let area = Rect::from_center_size(rect.center(), Vec2::new(rect.width().min(560.0), 190.0));
    ui.allocate_new_ui(egui::UiBuilder::new().max_rect(area), |ui| {
        egui::Frame::popup(ui.style()).show(ui, |ui| {
            ui.heading("Unbekannter Host-Key");
            ui.label("Dieser Server ist noch nicht in ~/.ssh/known_hosts eingetragen. Vergleiche den Fingerabdruck mit dem des Servers, bevor du vertraust.");
            ui.add_space(6.0);
            ui.monospace(format!("{algorithm}\n{fingerprint}"));
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("Vertrauen & verbinden").clicked() {
                    session.answer_host_key(true);
                }
                if ui.button("Abbrechen").clicked() {
                    session.answer_host_key(false);
                    out.close = true;
                }
            });
        });
    });
}

fn closed_bar(ui: &mut egui::Ui, rect: Rect, message: &str, out: &mut TerminalResponse) {
    let bar = Rect::from_min_max(Pos2::new(rect.left(), rect.bottom() - 36.0), rect.max);
    ui.allocate_new_ui(egui::UiBuilder::new().max_rect(bar), |ui| {
        egui::Frame::popup(ui.style()).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(message);
                if ui.button("🔄 Neu verbinden").clicked() {
                    out.reconnect = true;
                }
                if ui.button("Tab schließen").clicked() {
                    out.close = true;
                }
            });
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys() {
        let none = Modifiers::NONE;
        assert_eq!(key_bytes(Key::Enter, none, false).unwrap(), b"\r");
        assert_eq!(key_bytes(Key::ArrowUp, none, false).unwrap(), b"\x1b[A");
        assert_eq!(key_bytes(Key::ArrowUp, none, true).unwrap(), b"\x1bOA");
        assert_eq!(key_bytes(Key::C, Modifiers::CTRL, false).unwrap(), [0x03]);
        assert_eq!(key_bytes(Key::D, Modifiers::CTRL, false).unwrap(), [0x04]);
        assert!(key_bytes(Key::A, none, false).is_none(), "Buchstaben kommen als Event::Text");
    }

    #[test]
    fn paste() {
        assert_eq!(paste_bytes("a\nb", false), b"a\rb");
        assert_eq!(paste_bytes("x", true), b"\x1b[200~x\x1b[201~");
    }

    #[test]
    fn colors() {
        assert_eq!(color(vt100::Color::Idx(1), FOREGROUND, true), color(vt100::Color::Idx(9), FOREGROUND, false));
        assert_eq!(color(vt100::Color::Idx(16), FOREGROUND, false), Color32::from_rgb(0, 0, 0));
        assert_eq!(color(vt100::Color::Idx(231), FOREGROUND, false), Color32::from_rgb(255, 255, 255));
        assert_eq!(color(vt100::Color::Default, FOREGROUND, false), FOREGROUND);
    }
}
