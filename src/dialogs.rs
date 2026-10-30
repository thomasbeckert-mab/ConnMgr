//! Dialoge zum Verbindungsaufbau, gemeinsam für Terminal- und SFTP-Tabs.

use eframe::egui::{self, Pos2, Rect, Vec2};
use zeroize::Zeroizing;

use crate::ssh::{Conn, Status};

/// Was der Tab nach dem Zeichnen tun soll.
#[derive(Default)]
pub struct TabResponse {
    pub reconnect: bool,
    pub close: bool,
}

/// Zustand der Eingabe-Abfrage (Passwort, Passphrase).
#[derive(Default)]
pub struct ConnOverlay {
    input: Zeroizing<String>,
    focused: bool,
}

impl ConnOverlay {
    /// Zeigt passend zum Status einen Hinweis, eine Rückfrage oder die Leiste nach Verbindungsende.
    pub fn show(&mut self, ui: &mut egui::Ui, rect: Rect, conn: &Conn, status: &Status, out: &mut TabResponse) {
        match status {
            Status::Connected => {}
            Status::Connecting => centered_frame(ui, rect, Vec2::new(160.0, 40.0), |ui| {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Verbinde …");
                });
            }),
            Status::HostKey { fingerprint, algorithm } => centered_frame(ui, rect, Vec2::new(560.0, 190.0), |ui| {
                ui.heading("Unbekannter Host-Key");
                ui.label(
                    "Dieser Server ist noch nicht in ~/.ssh/known_hosts eingetragen. \
                     Vergleiche den Fingerabdruck mit dem des Servers, bevor du vertraust.",
                );
                ui.add_space(6.0);
                ui.monospace(format!("{algorithm}\n{fingerprint}"));
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Vertrauen & verbinden").clicked() {
                        conn.answer_host_key(true);
                    }
                    if ui.button("Abbrechen").clicked() {
                        conn.answer_host_key(false);
                        out.close = true;
                    }
                });
            }),
            Status::Prompt { message, secret } => centered_frame(ui, rect, Vec2::new(440.0, 130.0), |ui| {
                ui.label(message);
                ui.add_space(4.0);
                let field = ui.add(egui::TextEdit::singleline(&mut *self.input).password(*secret).desired_width(f32::INFINITY));
                if !self.focused {
                    field.request_focus();
                    self.focused = true;
                }
                let enter = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("OK").clicked() || enter {
                        conn.answer_prompt(Some(std::mem::take(&mut self.input)));
                        self.focused = false;
                    }
                    if ui.button("Abbrechen").clicked() {
                        conn.answer_prompt(None);
                        self.input.clear();
                        self.focused = false;
                    }
                });
            }),
            Status::Closed(message) => {
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
        }
    }
}

fn centered_frame(ui: &mut egui::Ui, rect: Rect, size: Vec2, add: impl FnOnce(&mut egui::Ui)) {
    let area = Rect::from_center_size(rect.center(), Vec2::new(size.x.min(rect.width()), size.y));
    ui.allocate_new_ui(egui::UiBuilder::new().max_rect(area), |ui| {
        egui::Frame::popup(ui.style()).show(ui, add);
    });
}
