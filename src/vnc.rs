//! Eingebettete VNC-Sitzung über vnc-rs: Bild als egui-Textur, Maus und Tastatur
//! als RFB-Ereignisse. Unterstützt die klassische VNC-Passwort-Anmeldung.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{anyhow, Result};
use eframe::egui::{self, Color32, Event, EventFilter, Key, Modifiers, PointerButton, Rect, Sense, TextureOptions};
use tokio::sync::mpsc;
use vnc::{PixelFormat, VncConnector, VncEncoding, VncError, VncEvent, X11Event};
use zeroize::Zeroizing;

use crate::dialogs::{ConnOverlay, TabResponse};
use crate::ssh::{connect_error, Conn, Status};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Abstand der inkrementellen Bildanforderungen (~30 Bilder/s).
const REFRESH_INTERVAL: Duration = Duration::from_millis(33);
const MAX_PASTE_CHARS: usize = 10_000;

pub struct VncParams {
    pub host: String,
    pub port: u16,
    pub password: Option<Zeroizing<String>>,
}

/// Bildspeicher in RGBA.
#[derive(Default)]
pub struct Framebuffer {
    pub width: usize,
    pub height: usize,
    pub pixels: Vec<u8>,
    pub dirty: bool,
    /// Text aus der Zwischenablage des Servers, noch nicht übernommen.
    pub clipboard: Option<String>,
}

impl Framebuffer {
    fn resize(&mut self, width: u16, height: u16) {
        self.width = width.into();
        self.height = height.into();
        self.pixels = vec![0; self.width * self.height * 4];
        self.dirty = true;
    }

    /// Kopiert ein Rechteck aus `data` (RGBA, Zeile für Zeile) in den Bildspeicher.
    fn blit(&mut self, r: vnc::Rect, data: &[u8]) {
        let (x, y, w, h) = (usize::from(r.x), usize::from(r.y), usize::from(r.width), usize::from(r.height));
        if x >= self.width || y >= self.height {
            return;
        }
        let visible = w.min(self.width - x);
        for row in 0..h.min(self.height - y) {
            let Some(src) = data.get(row * w * 4..(row * w + visible) * 4) else { break };
            let dst = ((y + row) * self.width + x) * 4;
            let target = &mut self.pixels[dst..dst + visible * 4];
            target.copy_from_slice(src);
            // Der Server lässt das Alpha-Byte meist auf 0.
            target.as_chunks_mut::<4>().0.iter_mut().for_each(|px| px[3] = 255);
        }
        self.dirty = true;
    }

    fn copy(&mut self, dst: vnc::Rect, src: vnc::Rect) {
        let (sx, sy, w, h) = (usize::from(src.x), usize::from(src.y), usize::from(src.width), usize::from(src.height));
        if sx + w > self.width || sy + h > self.height {
            return;
        }
        let mut region = Vec::with_capacity(w * h * 4);
        for row in 0..h {
            let start = ((sy + row) * self.width + sx) * 4;
            region.extend_from_slice(&self.pixels[start..start + w * 4]);
        }
        self.blit(vnc::Rect { width: src.width, height: src.height, ..dst }, &region);
    }
}

pub struct VncSession {
    conn: Arc<Conn>,
    framebuffer: Arc<Mutex<Framebuffer>>,
    input: mpsc::UnboundedSender<X11Event>,
}

impl VncSession {
    pub fn start(runtime: &tokio::runtime::Handle, ctx: egui::Context, params: VncParams) -> Self {
        let conn = Conn::new(ctx);
        let framebuffer = Arc::new(Mutex::new(Framebuffer::default()));
        let (input, rx) = mpsc::unbounded_channel();
        let (task_conn, task_fb) = (Arc::clone(&conn), Arc::clone(&framebuffer));
        runtime.spawn(async move {
            let message = match run(params, &task_conn, &task_fb, rx).await {
                Ok(message) => message,
                Err(e) => t!("Fehler: {e:#}", "Error: {e:#}"),
            };
            task_conn.set_status(Status::Closed(message));
        });
        Self { conn, framebuffer, input }
    }

    pub fn conn(&self) -> &Conn {
        &self.conn
    }

    pub fn framebuffer(&self) -> MutexGuard<'_, Framebuffer> {
        self.framebuffer.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn send(&self, event: X11Event) {
        let _ = self.input.send(event);
    }

    fn key(&self, keysym: u32, down: bool) {
        self.send(X11Event::KeyEvent((keysym, down).into()));
    }

    fn tap(&self, keysym: u32) {
        self.key(keysym, true);
        self.key(keysym, false);
    }
}

impl Drop for VncSession {
    fn drop(&mut self) {
        self.conn.cancel();
    }
}

async fn run(
    params: VncParams,
    conn: &Arc<Conn>,
    framebuffer: &Mutex<Framebuffer>,
    mut input: mpsc::UnboundedReceiver<X11Event>,
) -> Result<String> {
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect((params.host.as_str(), params.port)))
        .await
        .map_err(|_| anyhow!(t!("Zeitüberschreitung beim Verbindungsaufbau zu {}:{}", "Timed out connecting to {}:{}", params.host, params.port)))?
        .map_err(connect_error)?;
    tcp.set_nodelay(true)?;

    // Wird nur aufgerufen, wenn der Server ein Passwort verlangt.
    let (auth_conn, target, password) = (Arc::clone(conn), format!("{}:{}", params.host, params.port), params.password);
    let auth = async move {
        match password {
            Some(pw) => Ok(pw.to_string()),
            None => auth_conn
                .ask(t!("VNC-Passwort für {target}:", "VNC password for {target}:"), true)
                .await
                .map(|pw| pw.to_string())
                .ok_or(VncError::NoPassword),
        }
    };
    let client = VncConnector::new(tcp)
        .set_auth_method(auth)
        .add_encoding(VncEncoding::Zrle)
        .add_encoding(VncEncoding::CopyRect)
        .add_encoding(VncEncoding::Raw)
        .add_encoding(VncEncoding::DesktopSizePseudo)
        .allow_shared(true)
        .set_pixel_format(PixelFormat::rgba())
        .build()
        .map_err(vnc_error)?
        .try_start()
        .await
        .map_err(vnc_error)?
        .finish()
        .map_err(vnc_error)?;
    conn.set_status(Status::Connected);

    let lock = || framebuffer.lock().unwrap_or_else(|e| e.into_inner());
    let mut refresh = tokio::time::interval(REFRESH_INTERVAL);
    let result = loop {
        tokio::select! {
            event = client.recv_event() => {
                match event.map_err(vnc_error)? {
                    VncEvent::SetResolution(screen) => lock().resize(screen.width, screen.height),
                    VncEvent::DesktopUpdate(update) => {
                        if let Some(layout) = update.layout {
                            let mut fb = lock();
                            if (fb.width, fb.height) != (layout.width.into(), layout.height.into()) {
                                fb.resize(layout.width, layout.height);
                            }
                        }
                    }
                    VncEvent::RawImage(rect, data) => lock().blit(rect, &data),
                    VncEvent::Copy(dst, src) => lock().copy(dst, src),
                    VncEvent::Text(text) => lock().clipboard = Some(text),
                    VncEvent::Error(e) => break Err(anyhow!(e)),
                    _ => {}
                }
                conn.repaint();
            }
            event = input.recv() => match event {
                Some(event) => client.input(event).await.map_err(vnc_error)?,
                None => break Ok(t!("Verbindung getrennt", "Disconnected")),
            },
            _ = refresh.tick() => client.input(X11Event::Refresh).await.map_err(vnc_error)?,
        }
    };
    let _ = client.close().await;
    result
}

fn vnc_error(e: VncError) -> anyhow::Error {
    match e {
        VncError::WrongPassword => anyhow!(t!("Falsches VNC-Passwort", "Wrong VNC password")),
        VncError::NoPassword => anyhow!(t!("Anmeldung abgebrochen", "Login cancelled")),
        VncError::InvalidSecurityTyep(kind) => anyhow!(t!(
            "Der Server verlangt eine nicht unterstützte Anmeldung (Typ {kind}). Bei der macOS-Bildschirmfreigabe \
             „VNC-Benutzer dürfen den Bildschirm mit Passwort steuern“ aktivieren.",
            "The server requires an unsupported login (type {kind}). For macOS Screen Sharing, \
             enable \"VNC viewers may control screen with password\"."
        )),
        VncError::IoError(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => anyhow!(t!("Der Server hat die Verbindung beendet", "The server closed the connection")),
        other => anyhow!("{other}"),
    }
}

// ---------------------------------------------------------------- Oberfläche

#[derive(Default)]
pub struct VncView {
    texture: Option<egui::TextureHandle>,
    buttons: u8,
    position: (u16, u16),
    /// Zuletzt an den Server gemeldete Modifikatoren.
    modifiers: Modifiers,
    scroll_remainder: f32,
    focus_requested: bool,
    overlay: ConnOverlay,
}

const BUTTON_LEFT: u8 = 1;
const BUTTON_MIDDLE: u8 = 2;
const BUTTON_RIGHT: u8 = 4;
const WHEEL_UP: u8 = 8;
const WHEEL_DOWN: u8 = 16;
const SCROLL_STEP: f32 = 40.0;

impl VncView {
    pub fn show(&mut self, ui: &mut egui::Ui, session: &VncSession) -> TabResponse {
        let mut out = TabResponse::default();
        let status = session.conn().status();
        let rect = ui.available_rect_before_wrap();
        let response = ui.allocate_rect(rect, Sense::click_and_drag());
        ui.painter_at(rect).rect_filled(rect, 0.0, Color32::BLACK);

        if matches!(status, Status::Connected) {
            if !self.focus_requested || response.clicked() || response.drag_started() {
                response.request_focus();
                self.focus_requested = true;
            }
            if let Some(image_rect) = self.paint(ui, rect, session) {
                self.pointer(ui, &response, image_rect, session);
            }
            if response.has_focus() {
                let filter = EventFilter { tab: true, horizontal_arrows: true, vertical_arrows: true, escape: true };
                ui.memory_mut(|m| m.set_focus_lock_filter(response.id, filter));
                self.keyboard(ui, session);
            } else {
                self.release_modifiers(session);
            }
        }
        self.overlay.show(ui, rect, session.conn(), &status, &mut out);
        out
    }

    /// Lädt geänderte Bilddaten in die Textur und zeichnet sie eingepasst; liefert die Bildfläche.
    fn paint(&mut self, ui: &mut egui::Ui, rect: Rect, session: &VncSession) -> Option<Rect> {
        let mut fb = session.framebuffer();
        if let Some(text) = fb.clipboard.take() {
            ui.ctx().copy_text(text);
        }
        if fb.width == 0 || fb.height == 0 {
            return None;
        }
        let size = [fb.width, fb.height];
        if fb.dirty || self.texture.as_ref().is_none_or(|t| t.size() != size) {
            let image = egui::ColorImage::from_rgba_unmultiplied(size, &fb.pixels);
            match &mut self.texture {
                Some(texture) => texture.set(image, TextureOptions::LINEAR),
                None => self.texture = Some(ui.ctx().load_texture("vnc", image, TextureOptions::LINEAR)),
            }
            fb.dirty = false;
        }
        drop(fb);

        let image_size = egui::vec2(size[0] as f32, size[1] as f32);
        let scale = (rect.width() / image_size.x).min(rect.height() / image_size.y);
        let image_rect = Rect::from_center_size(rect.center(), image_size * scale);
        let texture = self.texture.as_ref()?;
        let uv = Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0));
        ui.painter_at(rect).image(texture.id(), image_rect, uv, Color32::WHITE);
        Some(image_rect)
    }

    fn pointer(&mut self, ui: &egui::Ui, response: &egui::Response, image_rect: Rect, session: &VncSession) {
        let Some(texture) = &self.texture else { return };
        let [w, h] = texture.size();
        let Some(pos) = ui.input(|i| i.pointer.latest_pos()) else { return };
        if !image_rect.contains(pos) && !response.dragged() {
            return;
        }
        let x = ((pos.x - image_rect.left()) / image_rect.width() * w as f32).clamp(0.0, w as f32 - 1.0) as u16;
        let y = ((pos.y - image_rect.top()) / image_rect.height() * h as f32).clamp(0.0, h as f32 - 1.0) as u16;

        let buttons = ui.input(|i| {
            let mut b = 0;
            if i.pointer.button_down(PointerButton::Primary) {
                b |= BUTTON_LEFT;
            }
            if i.pointer.button_down(PointerButton::Middle) {
                b |= BUTTON_MIDDLE;
            }
            if i.pointer.button_down(PointerButton::Secondary) {
                b |= BUTTON_RIGHT;
            }
            b
        });
        if (x, y) != self.position || buttons != self.buttons {
            self.position = (x, y);
            self.buttons = buttons;
            session.send(X11Event::PointerEvent((x, y, buttons).into()));
        }

        // Mausrad: je Raststufe Taste 4/5 drücken und loslassen.
        self.scroll_remainder += ui.input(|i| i.smooth_scroll_delta.y);
        while self.scroll_remainder.abs() >= SCROLL_STEP {
            let wheel = if self.scroll_remainder > 0.0 { WHEEL_UP } else { WHEEL_DOWN };
            self.scroll_remainder -= SCROLL_STEP.copysign(self.scroll_remainder);
            session.send(X11Event::PointerEvent((x, y, buttons | wheel).into()));
            session.send(X11Event::PointerEvent((x, y, buttons).into()));
        }
    }

    fn keyboard(&mut self, ui: &egui::Ui, session: &VncSession) {
        let (events, modifiers) = ui.input(|i| (i.events.clone(), i.modifiers));
        self.sync_modifiers(modifiers, session);
        for event in events {
            match event {
                Event::Text(text) => text.chars().for_each(|c| session.tap(char_keysym(c))),
                // Einfügen tippt den Text auf der Gegenseite; das klappt unabhängig vom Betriebssystem dort.
                Event::Paste(text) => text.chars().take(MAX_PASTE_CHARS).for_each(|c| {
                    session.tap(if c == '\n' { keysym::RETURN } else { char_keysym(c) });
                }),
                // Unter Windows/Linux kommen Strg+C/X als Copy/Cut statt als Tasten.
                Event::Copy if !cfg!(target_os = "macos") => session.tap(u32::from(b'c')),
                Event::Cut if !cfg!(target_os = "macos") => session.tap(u32::from(b'x')),
                Event::Key { key, pressed, modifiers, .. } => {
                    if let Some(sym) = special_keysym(key) {
                        session.key(sym, pressed);
                    } else if modifiers.ctrl || modifiers.mac_cmd {
                        // Mit Strg/Cmd erzeugt egui keinen Text; die Taste selbst schicken.
                        if let Some(sym) = letter_keysym(key) {
                            session.key(sym, pressed);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn sync_modifiers(&mut self, now: Modifiers, session: &VncSession) {
        // Unter macOS erzeugt Option Sonderzeichen (z. B. @) und wird deshalb nicht als Alt gemeldet.
        let alt_is_modifier = !cfg!(target_os = "macos");
        let pairs = [
            (self.modifiers.shift, now.shift, keysym::SHIFT_L),
            (self.modifiers.ctrl, now.ctrl, keysym::CONTROL_L),
            (self.modifiers.alt && alt_is_modifier, now.alt && alt_is_modifier, keysym::ALT_L),
            (self.modifiers.mac_cmd, now.mac_cmd, keysym::SUPER_L),
        ];
        for (before, after, sym) in pairs {
            if before != after {
                session.key(sym, after);
            }
        }
        self.modifiers = now;
    }

    fn release_modifiers(&mut self, session: &VncSession) {
        if self.modifiers != Modifiers::NONE {
            self.sync_modifiers(Modifiers::NONE, session);
        }
    }
}

/// X11-Keysyms (X11/keysymdef.h).
mod keysym {
    pub const RETURN: u32 = 0xff0d;
    pub const SHIFT_L: u32 = 0xffe1;
    pub const CONTROL_L: u32 = 0xffe3;
    pub const ALT_L: u32 = 0xffe9;
    pub const SUPER_L: u32 = 0xffeb;
}

/// Latin-1 direkt, alles andere als Unicode-Keysym.
fn char_keysym(c: char) -> u32 {
    let code = u32::from(c);
    if (0x20..=0x7e).contains(&code) || (0xa0..=0xff).contains(&code) {
        code
    } else {
        0x0100_0000 + code
    }
}

fn special_keysym(key: Key) -> Option<u32> {
    Some(match key {
        Key::Enter => keysym::RETURN,
        Key::Backspace => 0xff08,
        Key::Tab => 0xff09,
        Key::Escape => 0xff1b,
        Key::Delete => 0xffff,
        Key::Insert => 0xff63,
        Key::Home => 0xff50,
        Key::ArrowLeft => 0xff51,
        Key::ArrowUp => 0xff52,
        Key::ArrowRight => 0xff53,
        Key::ArrowDown => 0xff54,
        Key::PageUp => 0xff55,
        Key::PageDown => 0xff56,
        Key::End => 0xff57,
        Key::F1 => 0xffbe,
        Key::F2 => 0xffbf,
        Key::F3 => 0xffc0,
        Key::F4 => 0xffc1,
        Key::F5 => 0xffc2,
        Key::F6 => 0xffc3,
        Key::F7 => 0xffc4,
        Key::F8 => 0xffc5,
        Key::F9 => 0xffc6,
        Key::F10 => 0xffc7,
        Key::F11 => 0xffc8,
        Key::F12 => 0xffc9,
        _ => return None,
    })
}

fn letter_keysym(key: Key) -> Option<u32> {
    let name = key.name();
    let c = name.chars().next().filter(|c| name.len() == 1 && c.is_ascii_alphanumeric())?;
    Some(u32::from(c.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn keysyms() {
        assert_eq!(char_keysym('a'), 0x61);
        assert_eq!(char_keysym('ä'), 0xe4);
        assert_eq!(char_keysym('€'), 0x0100_20ac);
        assert_eq!(special_keysym(Key::Enter), Some(0xff0d));
        assert_eq!(letter_keysym(Key::C), Some(u32::from(b'c')));
        assert_eq!(letter_keysym(Key::Enter), None);
    }

    #[test]
    fn framebuffer_blit_and_copy() {
        let mut fb = Framebuffer::default();
        fb.resize(4, 2);
        let red = [255, 0, 0, 0].repeat(2);
        fb.blit(vnc::Rect { x: 0, y: 0, width: 2, height: 1 }, &red);
        assert_eq!(&fb.pixels[..8], &[255, 0, 0, 255, 255, 0, 0, 255], "Alpha auf 255");
        fb.copy(vnc::Rect { x: 2, y: 1, width: 2, height: 1 }, vnc::Rect { x: 0, y: 0, width: 2, height: 1 });
        assert_eq!(&fb.pixels[24..32], &[255, 0, 0, 255, 255, 0, 0, 255]);
        // Rechtecke über den Rand hinaus werden abgeschnitten statt abzustürzen.
        fb.blit(vnc::Rect { x: 3, y: 1, width: 5, height: 5 }, &[1; 100]);
    }

    /// Was der Test-Server vom Client empfangen hat.
    #[derive(Default, Debug)]
    struct Received {
        auth_response: Option<Vec<u8>>,
        keys: Vec<(u32, bool)>,
        pointer: Vec<(u16, u16, u8)>,
        update_requests: usize,
    }

    /// Minimaler RFB-3.8-Server (RFC 6143): VNC-Passwort-Anmeldung, 8×4-Testbild in Rot,
    /// zeichnet Tasten- und Mausereignisse auf.
    async fn fake_server(listener: tokio::net::TcpListener, received: Arc<Mutex<Received>>) -> std::io::Result<()> {
        let (mut s, _) = listener.accept().await?;
        s.write_all(b"RFB 003.008\n").await?;
        let mut version = [0u8; 12];
        s.read_exact(&mut version).await?;
        s.write_all(&[1, 2]).await?; // eine Methode: VNC-Authentifizierung
        let mut chosen = [0u8; 1];
        s.read_exact(&mut chosen).await?;
        s.write_all(&[7u8; 16]).await?; // Challenge
        let mut response = [0u8; 16];
        s.read_exact(&mut response).await?;
        received.lock().unwrap().auth_response = Some(response.to_vec());
        s.write_all(&0u32.to_be_bytes()).await?; // OK
        let mut shared = [0u8; 1];
        s.read_exact(&mut shared).await?;

        // ServerInit: 8×4, 32 bpp, Tiefe 24, little endian, true colour, BGRA-Standardformat.
        let mut init = Vec::new();
        init.extend(8u16.to_be_bytes());
        init.extend(4u16.to_be_bytes());
        init.extend([32, 24, 0, 1]);
        init.extend(255u16.to_be_bytes());
        init.extend(255u16.to_be_bytes());
        init.extend(255u16.to_be_bytes());
        init.extend([16, 8, 0, 0, 0, 0]);
        init.extend(4u32.to_be_bytes());
        init.extend(b"test");
        s.write_all(&init).await?;

        let mut sent_image = false;
        loop {
            let mut kind = [0u8; 1];
            if s.read_exact(&mut kind).await.is_err() {
                return Ok(());
            }
            match kind[0] {
                0 => {
                    let mut rest = [0u8; 19];
                    s.read_exact(&mut rest).await?;
                }
                2 => {
                    let mut head = [0u8; 3];
                    s.read_exact(&mut head).await?;
                    let n = u16::from_be_bytes([head[1], head[2]]) as usize;
                    let mut encodings = vec![0u8; n * 4];
                    s.read_exact(&mut encodings).await?;
                }
                3 => {
                    let mut rest = [0u8; 9];
                    s.read_exact(&mut rest).await?;
                    received.lock().unwrap().update_requests += 1;
                    if !sent_image {
                        sent_image = true;
                        // Raw-Rechteck 8×4 in Rot; der Client hat RGBA angefordert.
                        let mut msg = vec![0, 0];
                        msg.extend(1u16.to_be_bytes());
                        msg.extend([0, 0, 0, 0]);
                        msg.extend(8u16.to_be_bytes());
                        msg.extend(4u16.to_be_bytes());
                        msg.extend(0i32.to_be_bytes());
                        msg.extend([255, 0, 0, 0].repeat(32));
                        s.write_all(&msg).await?;
                    } else {
                        // Leeres Update, damit der Client weiter anfragt.
                        s.write_all(&[0, 0, 0, 0]).await?;
                    }
                }
                4 => {
                    let mut rest = [0u8; 7];
                    s.read_exact(&mut rest).await?;
                    let sym = u32::from_be_bytes([rest[3], rest[4], rest[5], rest[6]]);
                    received.lock().unwrap().keys.push((sym, rest[0] == 1));
                }
                5 => {
                    let mut rest = [0u8; 5];
                    s.read_exact(&mut rest).await?;
                    let x = u16::from_be_bytes([rest[1], rest[2]]);
                    let y = u16::from_be_bytes([rest[3], rest[4]]);
                    received.lock().unwrap().pointer.push((x, y, rest[0]));
                }
                6 => {
                    let mut head = [0u8; 7];
                    s.read_exact(&mut head).await?;
                    let n = u32::from_be_bytes([head[3], head[4], head[5], head[6]]) as usize;
                    let mut text = vec![0u8; n];
                    s.read_exact(&mut text).await?;
                }
                other => panic!("unbekannte Client-Nachricht {other}"),
            }
        }
    }

    fn wait(what: &str, cond: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !cond() {
            assert!(Instant::now() < deadline, "Zeitüberschreitung: {what}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Ende zu Ende gegen den Test-Server: Passwortabfrage, Bild, Tastatur und Maus.
    #[test]
    fn e2e_fake_server() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let listener = runtime.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
        let port = listener.local_addr().unwrap().port();
        let received = Arc::new(Mutex::new(Received::default()));
        runtime.spawn(fake_server(listener, Arc::clone(&received)));

        let ctx = egui::Context::default();
        let session = VncSession::start(runtime.handle(), ctx.clone(), VncParams { host: "127.0.0.1".into(), port, password: None });
        wait("Passwortabfrage", || matches!(session.conn().status(), Status::Prompt { secret: true, .. }));
        session.conn().answer_prompt(Some(Zeroizing::new("geheim".into())));
        wait("Verbindung", || matches!(session.conn().status(), Status::Connected));
        wait("Testbild", || session.framebuffer().pixels.first() == Some(&255));
        {
            let fb = session.framebuffer();
            assert_eq!((fb.width, fb.height), (8, 4));
            assert_eq!(&fb.pixels[..4], &[255, 0, 0, 255]);
        }
        assert_eq!(received.lock().unwrap().auth_response.as_ref().map(Vec::len), Some(16), "DES-Antwort auf die Challenge");

        // Oberfläche zeichnen und Eingaben simulieren.
        let mut view = VncView::default();
        let frame = |events: Vec<Event>, view: &mut VncView| {
            let input = egui::RawInput {
                events,
                screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(800.0, 400.0))),
                ..Default::default()
            };
            let _ = ctx.run(input, |ctx| {
                egui::CentralPanel::default().frame(egui::Frame::none()).show(ctx, |ui| {
                    view.show(ui, &session);
                });
            });
        };
        frame(vec![], &mut view);
        frame(vec![], &mut view);
        frame(
            vec![
                Event::Text("hä".into()),
                Event::Key { key: Key::Enter, physical_key: None, pressed: true, repeat: false, modifiers: Modifiers::NONE },
                Event::Key { key: Key::Enter, physical_key: None, pressed: false, repeat: false, modifiers: Modifiers::NONE },
                Event::PointerMoved(egui::pos2(400.0, 200.0)),
            ],
            &mut view,
        );
        wait("Tasten", || received.lock().unwrap().keys.len() >= 6);
        wait("Maus", || !received.lock().unwrap().pointer.is_empty());
        let received = received.lock().unwrap();
        assert_eq!(received.keys[..6], [(0x68, true), (0x68, false), (0xe4, true), (0xe4, false), (0xff0d, true), (0xff0d, false)]);
        // Bild (8×4) wird in 800×400 eingepasst und liegt mittig: Fenstermitte = Bildmitte.
        assert_eq!(received.pointer.last().map(|p| (p.0, p.1)), Some((4, 2)));
        assert!(received.update_requests >= 2, "inkrementelle Bildanforderungen laufen");
    }
}
