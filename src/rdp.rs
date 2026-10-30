//! Eingebettete RDP-Sitzung über IronRDP: TLS, NLA (CredSSP/NTLM), Bild als egui-Textur,
//! Maus und Tastatur als Fast-Path-Eingaben.
//!
//! Größenänderungen laufen über den Display-Control-Kanal (MS-RDPEDISP) samt
//! Deaktivierung/Reaktivierung, Text in der Zwischenablage über CLIPRDR in beide Richtungen.
//!
//! TLS-Zertifikate werden wie SSH-Host-Keys behandelt: Lässt sich ein Zertifikat nicht
//! prüfen (bei RDP-Servern meist selbst signiert), fragt ConMgr nach und merkt sich den
//! Fingerabdruck; ein geänderter Fingerabdruck wird abgelehnt.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context as _, Result};
use eframe::egui::{self, Color32, Event, EventFilter, Key, Modifiers, PointerButton, Rect, Sense, TextureOptions};
use ironrdp_async::{FramedWrite as _, NetworkClient};
use ironrdp_cliprdr::backend::CliprdrBackend;
use ironrdp_cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FileContentsRequest, FileContentsResponse,
    FormatDataRequest, FormatDataResponse, LockDataId,
};
use ironrdp_cliprdr::{CliprdrClient, CliprdrSvcMessages};
use ironrdp_connector::connection_activation::{ConnectionActivationSequence, ConnectionActivationState};
use ironrdp_connector::sspi::generator::NetworkRequest;
use ironrdp_connector::{general_err, ClientConnector, ConnectorResult, Credentials, DesktopSize, ServerName};
use ironrdp_core::WriteBuf;
use ironrdp_displaycontrol::client::DisplayControlClient;
use ironrdp_dvc::DrdynvcClient;
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_input::{Database, MouseButton, MousePosition, Operation, Scancode, WheelRotations};
use ironrdp_pdu::gcc::{ConnectionType, KeyboardType};
use ironrdp_pdu::rdp::capability_sets::{MajorPlatformType, RailSupportLevel};
use ironrdp_pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::dialogs::{ConnOverlay, TabResponse};
use crate::ssh::{connect_error, Conn, Status};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Ruhezeit nach dem letzten Größenwechsel, bevor Windows die neue Auflösung bekommt.
const RESIZE_DEBOUNCE: Duration = Duration::from_millis(500);
/// Abstand, in dem die Zwischenablage des Macs auf neuen Text geprüft wird.
const CLIPBOARD_POLL: Duration = Duration::from_millis(700);

pub struct RdpParams {
    pub host: String,
    pub port: u16,
    /// `benutzer` oder `DOMÄNE\benutzer`.
    pub username: String,
    pub password: Option<Zeroizing<String>>,
}

/// Bildspeicher in RGBA, wie ihn IronRDP dekodiert.
#[derive(Default)]
pub struct Framebuffer {
    pub width: usize,
    pub height: usize,
    pub pixels: Vec<u8>,
    pub dirty: bool,
    /// Text aus der Windows-Zwischenablage, noch nicht in die lokale übernommen.
    pub clipboard: Option<String>,
}

enum Input {
    /// Erste Größe der Ansicht in Pixeln samt Skalierung; erst dann wird verbunden.
    Start { width: u16, height: u16, scale_percent: u32 },
    Resize { width: u16, height: u16, scale_percent: u32 },
    Operations(Vec<Operation>),
    /// Neuer Text in der lokalen Zwischenablage.
    LocalClipboard(String),
}

pub struct RdpSession {
    conn: Arc<Conn>,
    framebuffer: Arc<Mutex<Framebuffer>>,
    input: mpsc::UnboundedSender<Input>,
}

impl RdpSession {
    pub fn start(runtime: &tokio::runtime::Handle, ctx: egui::Context, params: RdpParams) -> Self {
        let conn = Conn::new(ctx);
        let framebuffer = Arc::new(Mutex::new(Framebuffer::default()));
        let (input, rx) = mpsc::unbounded_channel();
        let (task_conn, task_fb) = (Arc::clone(&conn), Arc::clone(&framebuffer));
        runtime.spawn(async move {
            let message = match run(params, &task_conn, &task_fb, rx).await {
                Ok(message) => message,
                Err(e) => format!("Fehler: {e:#}"),
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

    fn send(&self, operations: Vec<Operation>) {
        if !operations.is_empty() {
            let _ = self.input.send(Input::Operations(operations));
        }
    }
}

impl Drop for RdpSession {
    fn drop(&mut self) {
        self.conn.cancel();
    }
}

/// Was der CLIPRDR-Kanal während der Verarbeitung meldet; die Sitzungsschleife reagiert darauf,
/// weil die Rückruffunktionen selbst nichts senden können.
#[derive(Debug, PartialEq)]
enum ClipEvent {
    /// Kanal bereit bzw. Server fragt nach unseren Formaten.
    Ready,
    /// In Windows wurde Text kopiert.
    RemoteHasText,
    /// Windows will unseren Inhalt in diesem Format.
    Requested(ClipboardFormatId),
    RemoteText(String),
}

#[derive(Debug)]
struct ClipBackend {
    events: Arc<Mutex<Vec<ClipEvent>>>,
}

ironrdp_core::impl_as_any!(ClipBackend);

impl ClipBackend {
    fn push(&self, event: ClipEvent) {
        self.events.lock().unwrap_or_else(|e| e.into_inner()).push(event);
    }
}

/// Nur Text; Dateien und Bilder werden nicht angeboten und nicht angefordert.
impl CliprdrBackend for ClipBackend {
    fn temporary_directory(&self) -> &str {
        ".cliprdr"
    }

    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::empty()
    }

    fn on_ready(&mut self) {
        self.push(ClipEvent::Ready);
    }

    fn on_request_format_list(&mut self) {
        self.push(ClipEvent::Ready);
    }

    fn on_process_negotiated_capabilities(&mut self, _capabilities: ClipboardGeneralCapabilityFlags) {}

    fn on_remote_copy(&mut self, available_formats: &[ClipboardFormat]) {
        if available_formats.iter().any(|f| f.id() == ClipboardFormatId::CF_UNICODETEXT) {
            self.push(ClipEvent::RemoteHasText);
        }
    }

    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        self.push(ClipEvent::Requested(request.format));
    }

    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        if !response.is_error() {
            if let Ok(text) = response.to_unicode_string() {
                self.push(ClipEvent::RemoteText(text.trim_end_matches('\0').to_owned()));
            }
        }
    }

    fn on_file_contents_request(&mut self, _request: FileContentsRequest) {}

    fn on_file_contents_response(&mut self, _response: FileContentsResponse<'_>) {}

    fn on_lock(&mut self, _data_id: LockDataId) {}

    fn on_unlock(&mut self, _data_id: LockDataId) {}
}

/// Führt eine CLIPRDR-Operation aus und liefert den zu sendenden Rahmen.
fn clipboard_frame(
    stage: &mut ActiveStage,
    op: impl FnOnce(&mut CliprdrClient) -> ironrdp_pdu::PduResult<CliprdrSvcMessages<ironrdp_cliprdr::Client>>,
) -> Result<Option<Vec<u8>>> {
    let Some(cliprdr) = stage.get_svc_processor_mut::<CliprdrClient>() else { return Ok(None) };
    if !cliprdr.is_ready() {
        return Ok(None);
    }
    let messages = op(cliprdr).map_err(|e| anyhow!("Zwischenablage: {e}"))?;
    Ok(Some(stage.process_svc_processor_messages(messages)?))
}

fn announce_text(cliprdr: &mut CliprdrClient, has_text: bool) -> ironrdp_pdu::PduResult<CliprdrSvcMessages<ironrdp_cliprdr::Client>> {
    let formats = if has_text { vec![ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)] } else { Vec::new() };
    cliprdr.initiate_copy(&formats)
}

/// Ohne Kerberos braucht CredSSP (NTLM) keine Netzwerkanfragen an einen KDC.
struct NoKdc;

impl NetworkClient for NoKdc {
    async fn send(&mut self, _request: &NetworkRequest) -> ConnectorResult<Vec<u8>> {
        Err(general_err!("Kerberos wird nicht unterstützt"))
    }
}

async fn run(
    params: RdpParams,
    conn: &Arc<Conn>,
    framebuffer: &Mutex<Framebuffer>,
    mut input: mpsc::UnboundedReceiver<Input>,
) -> Result<String> {
    // Die Desktopgröße richtet sich nach dem Tab; die Ansicht meldet sie beim ersten Zeichnen.
    let (width, height, scale_percent) = loop {
        match input.recv().await {
            Some(Input::Start { width, height, scale_percent }) => break (width, height, scale_percent),
            Some(_) => {}
            None => return Ok("Verbindung getrennt".into()),
        }
    };

    let target = format!("{}:{}", params.host, params.port);
    let mut username = params.username.clone();
    if username.is_empty() {
        username = conn.ask(format!("Benutzer für {target}:"), false).await.ok_or_else(|| anyhow!("Anmeldung abgebrochen"))?.to_string();
    }
    let password = match params.password {
        Some(pw) => pw,
        None => conn.ask(format!("Passwort für {username} auf {target}:"), true).await.ok_or_else(|| anyhow!("Anmeldung abgebrochen"))?,
    };
    let (domain, user) = match username.split_once('\\') {
        Some((domain, user)) => (Some(domain.to_owned()), user.to_owned()),
        None => (None, username.clone()),
    };
    let config = build_config(user, password.to_string(), domain, width, height, scale_percent);
    let clip_events: Arc<Mutex<Vec<ClipEvent>>> = Arc::default();

    let (result, framed) = connect(&params.host, params.port, config.clone(), &clip_events, conn).await?;
    conn.set_status(Status::Connected);

    let size = result.desktop_size;
    let mut image = DecodedImage::new(PixelFormat::RgbA32, size.width, size.height);
    publish_size(framebuffer, &image);
    let mut stage: ActiveStage = ActiveStageBuilder {
        static_channels: result.static_channels,
        user_channel_id: result.user_channel_id,
        io_channel_id: result.io_channel_id,
        message_channel_id: result.message_channel_id,
        share_id: result.share_id,
        compression_type: result.compression_type,
        enable_server_pointer: false,
        pointer_software_rendering: false,
    }
    .build();

    let (io_channel_id, user_channel_id) = (result.io_channel_id, result.user_channel_id);
    let (mut reader, mut writer) = ironrdp_tokio::split_tokio_framed(framed);
    let mut database = Database::new();
    let mut requested_size = (size.width, size.height, scale_percent);
    let mut local_text: Option<String> = None;
    loop {
        let outputs = tokio::select! {
            pdu = reader.read_pdu() => {
                let (action, payload) = match pdu {
                    Ok(pdu) => pdu,
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok("Der Server hat die Verbindung beendet".into()),
                    Err(e) => return Err(e).context("Lesen vom Server"),
                };
                stage.process(&mut image, action, &payload, None)?
            }
            cmd = input.recv() => match cmd {
                Some(Input::Operations(ops)) => {
                    let events = database.apply(ops);
                    stage.process_fastpath_input(&mut image, &events)?
                }
                Some(Input::Resize { width, height, scale_percent }) => {
                    // Windows verlangt eine gerade Breite zwischen 200 und 8192 Pixeln.
                    let (width, height) = ((width & !1).clamp(200, 8192), height.clamp(200, 8192));
                    requested_size = (width, height, scale_percent);
                    // Ist der Kanal (noch) nicht verfügbar, bleibt die Größe, bis neu verbunden wird.
                    if let Some(Ok(frame)) = stage.encode_resize(width.into(), height.into(), Some(scale_percent), None) {
                        writer.write_all(&frame).await.context("Senden an den Server")?;
                    }
                    Vec::new()
                }
                Some(Input::LocalClipboard(text)) => {
                    local_text = Some(text);
                    if let Some(frame) = clipboard_frame(&mut stage, |c| announce_text(c, true))? {
                        writer.write_all(&frame).await.context("Senden an den Server")?;
                    }
                    Vec::new()
                }
                Some(Input::Start { .. }) => Vec::new(),
                None => {
                    // Tab geschlossen: sauber abmelden, Fehler dabei sind egal.
                    if let Ok(outputs) = stage.graceful_shutdown() {
                        for output in outputs {
                            if let ActiveStageOutput::ResponseFrame(frame) = output {
                                let _ = writer.write_all(&frame).await;
                            }
                        }
                    }
                    return Ok("Verbindung getrennt".into());
                }
            },
        };

        let mut updated = false;
        for output in outputs {
            match output {
                ActiveStageOutput::ResponseFrame(frame) => writer.write_all(&frame).await.context("Senden an den Server")?,
                ActiveStageOutput::GraphicsUpdate(_) => updated = true,
                ActiveStageOutput::Terminate(reason) => return Ok(format!("Sitzung beendet ({reason})")),
                ActiveStageOutput::DeactivateAll => {
                    // Neue Auflösung: Aktivierung mit der angeforderten Größe neu durchlaufen.
                    let mut activation_config = config.clone();
                    activation_config.desktop_size = DesktopSize { width: requested_size.0, height: requested_size.1 };
                    activation_config.desktop_scale_factor = requested_size.2;
                    let mut activation = ConnectionActivationSequence::new(activation_config, io_channel_id, user_channel_id);
                    let mut buf = WriteBuf::new();
                    loop {
                        let written = ironrdp_async::single_sequence_step_read(&mut reader, &mut activation, &mut buf)
                            .await
                            .map_err(|e| anyhow!("Reaktivierung: {e}"))?;
                        if let Some(len) = written.size() {
                            writer.write_all(&buf.filled()[..len]).await.context("Senden an den Server")?;
                        }
                        if let ConnectionActivationState::Finalized {
                            desktop_size,
                            share_id,
                            static_channel_chunk_size,
                            enable_server_pointer,
                            pointer_software_rendering,
                            ..
                        } = activation.connection_activation_state()
                        {
                            image = DecodedImage::new(PixelFormat::RgbA32, desktop_size.width, desktop_size.height);
                            if !stage.reactivate(
                                io_channel_id,
                                user_channel_id,
                                share_id,
                                enable_server_pointer,
                                pointer_software_rendering,
                                static_channel_chunk_size,
                            ) {
                                bail!("Reaktivierung fehlgeschlagen");
                            }
                            publish_size(framebuffer, &image);
                            break;
                        }
                    }
                }
                _ => {}
            }
        }

        let events = std::mem::take(&mut *clip_events.lock().unwrap_or_else(|e| e.into_inner()));
        for event in events {
            let frame = match event {
                ClipEvent::Ready => clipboard_frame(&mut stage, |c| announce_text(c, local_text.is_some()))?,
                ClipEvent::RemoteHasText => clipboard_frame(&mut stage, |c| c.initiate_paste(ClipboardFormatId::CF_UNICODETEXT))?,
                ClipEvent::Requested(format) => {
                    let response = match (&local_text, format == ClipboardFormatId::CF_UNICODETEXT) {
                        (Some(text), true) => FormatDataResponse::new_unicode_string(text),
                        _ => FormatDataResponse::new_error(),
                    };
                    clipboard_frame(&mut stage, |c| c.submit_format_data(response))?
                }
                ClipEvent::RemoteText(text) => {
                    framebuffer.lock().unwrap_or_else(|e| e.into_inner()).clipboard = Some(text);
                    conn.repaint();
                    None
                }
            };
            if let Some(frame) = frame {
                writer.write_all(&frame).await.context("Senden an den Server")?;
            }
        }

        if updated {
            let mut fb = framebuffer.lock().unwrap_or_else(|e| e.into_inner());
            fb.pixels.copy_from_slice(image.data());
            fb.dirty = true;
            drop(fb);
            conn.repaint();
        }
    }
}

/// Übernimmt Größe und Inhalt eines (neuen) Bildspeichers für die Oberfläche.
fn publish_size(framebuffer: &Mutex<Framebuffer>, image: &DecodedImage) {
    let mut fb = framebuffer.lock().unwrap_or_else(|e| e.into_inner());
    fb.width = image.width().into();
    fb.height = image.height().into();
    fb.pixels = image.data().to_vec();
    fb.dirty = true;
}

type Upgraded = ironrdp_tokio::TokioFramed<ironrdp_tls::TlsStream<tokio::net::TcpStream>>;

/// X.224-Aushandlung, TLS mit Zertifikatsprüfung (s. Moduldoku) und CredSSP.
async fn connect(
    host: &str,
    port: u16,
    config: ironrdp_connector::Config,
    clip_events: &Arc<Mutex<Vec<ClipEvent>>>,
    conn: &Conn,
) -> Result<(ironrdp_connector::ConnectionResult, Upgraded)> {
    let endpoint = format!("{host}:{port}");
    // Höchstens zwei Durchläufe: einmal mit Rückfrage zum Zertifikat, einmal mit dem gemerkten.
    for _ in 0..2 {
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect((host, port)))
            .await
            .map_err(|_| anyhow!("Zeitüberschreitung beim Verbindungsaufbau zu {endpoint}"))?
            .map_err(connect_error)?;
        tcp.set_nodelay(true)?;
        let client_addr: SocketAddr = tcp.local_addr()?;
        let mut framed = ironrdp_tokio::TokioFramed::new(tcp);
        let mut connector = ClientConnector::new(config.clone(), client_addr)
            // Display Control: Größe während der Sitzung ändern; die Fähigkeiten des Servers braucht es nicht zu beantworten.
            .with_static_channel(DrdynvcClient::new().with_dynamic_channel(DisplayControlClient::new(|_| Ok(Vec::new()))))
            .with_static_channel(CliprdrClient::new(Box::new(ClipBackend { events: Arc::clone(clip_events) })));
        let should_upgrade = ironrdp_async::connect_begin(&mut framed, &mut connector).await.map_err(|e| anyhow!("{e}"))?;

        let known = known_certificates();
        let rejected: Arc<Mutex<Option<(String, String)>>> = Arc::default();
        let callback = {
            let (known, rejected) = (known.clone(), Arc::clone(&rejected));
            Arc::new(move |der: &[u8], endpoint: &str, reason: &str| {
                let fingerprint = fingerprint(der);
                if known.get(endpoint) == Some(&fingerprint) {
                    return true;
                }
                *rejected.lock().unwrap_or_else(|e| e.into_inner()) = Some((fingerprint, reason.to_owned()));
                false
            })
        };
        let stream = framed.into_inner_no_leftover();
        let upgrade = ironrdp_tls::upgrade_with_certificate_validation_callback_for_endpoint(stream, host, &endpoint, callback).await;
        let (tls, certificate) = match upgrade {
            Ok(upgraded) => upgraded,
            Err(e) => {
                let Some((fingerprint, reason)) = rejected.lock().unwrap_or_else(|e| e.into_inner()).take() else {
                    return Err(anyhow!("TLS-Verbindung fehlgeschlagen: {e}"));
                };
                if known.contains_key(&endpoint) {
                    bail!(
                        "WARNUNG: Das TLS-Zertifikat von {endpoint} hat sich geändert (jetzt {fingerprint}). \
                         Möglicherweise wird die Verbindung abgehört — abgebrochen."
                    );
                }
                if !conn.ask_host_key(fingerprint.clone(), format!("TLS-Zertifikat (SHA-256) — {reason}")).await {
                    bail!("Zertifikat nicht bestätigt — Verbindung abgebrochen");
                }
                remember_certificate(&endpoint, &fingerprint)?;
                continue;
            }
        };

        let server_public_key = ironrdp_tls::extract_tls_server_public_key(&certificate)
            .ok_or_else(|| anyhow!("Öffentlicher Schlüssel im Zertifikat fehlt"))?
            .to_vec();
        let upgraded = ironrdp_async::mark_as_upgraded(should_upgrade, &mut connector);
        let mut framed = ironrdp_tokio::TokioFramed::new(tls);
        let outcome = ironrdp_async::connect_finalize(
            upgraded,
            connector,
            &mut framed,
            &mut NoKdc,
            ServerName::new(host),
            server_public_key,
            None,
        )
        .await
        .map_err(login_error)?;
        let result = outcome.into_connected().map_err(|e| anyhow!("{e}"))?;
        return Ok((result, framed));
    }
    bail!("Zertifikat konnte nicht bestätigt werden")
}

fn login_error(e: ironrdp_connector::ConnectorError) -> anyhow::Error {
    let text = format!("{e:#}");
    if text.contains("LOGON_FAILURE") || text.contains("0x8009030C") || text.to_lowercase().contains("logon") {
        anyhow!("Anmeldung fehlgeschlagen: Benutzer oder Passwort falsch ({text})")
    } else {
        anyhow!("{text}")
    }
}

fn build_config(
    username: String,
    password: String,
    domain: Option<String>,
    width: u16,
    height: u16,
    scale_percent: u32,
) -> ironrdp_connector::Config {
    ironrdp_connector::Config {
        credentials: Credentials::UsernamePassword { username, password },
        domain,
        enable_tls: true,
        enable_credssp: true,
        enable_standard_rdp_security: false,
        keyboard_type: KeyboardType::IBM_ENHANCED,
        keyboard_subtype: 0,
        // 0 = Tastaturlayout des Servers. Text wird ohnehin als Unicode übertragen.
        keyboard_layout: 0,
        keyboard_functional_keys_count: 12,
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        // Windows verlangt eine gerade Breite.
        desktop_size: DesktopSize { width: width & !1, height },
        monitor_layout: None,
        desktop_scale_factor: scale_percent,
        bitmap: None,
        client_build: 0,
        client_name: "ConMgr".to_owned(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_owned(),
        platform: if cfg!(target_os = "macos") {
            MajorPlatformType::MACINTOSH
        } else if cfg!(windows) {
            MajorPlatformType::WINDOWS
        } else {
            MajorPlatformType::UNIX
        },
        hardware_id: None,
        request_data: None,
        autologon: false,
        enable_audio_playback: false,
        enable_audio_capture: false,
        performance_flags: PerformanceFlags::default(),
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
        compression_type: None,
        enable_server_pointer: false,
        pointer_software_rendering: false,
        multitransport_flags: None,
        connection_type: ConnectionType::Lan,
        alternate_shell: String::new(),
        work_dir: String::new(),
        remote_application_mode: false,
        rail_support_level: RailSupportLevel::empty(),
        // Ohne GFX-Kanal schickt der Server klassische Bitmap-Updates, die IronRDP selbst dekodiert.
        support_dyn_vc_gfx_protocol: false,
    }
}

// ---------------------------------------------------------------- bekannte Zertifikate

fn fingerprint(der: &[u8]) -> String {
    let hash = Sha256::digest(der);
    hash.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

#[cfg(test)]
static TEST_CERTIFICATES_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);

fn certificates_path() -> PathBuf {
    #[cfg(test)]
    if let Some(path) = TEST_CERTIFICATES_PATH.lock().unwrap().clone() {
        return path;
    }
    directories::ProjectDirs::from("", "", "ConMgr")
        .map(|d| d.config_dir().join("rdp_certificates.json"))
        .unwrap_or_else(|| PathBuf::from("rdp_certificates.json"))
}

/// `host:port` → SHA-256-Fingerabdruck des bestätigten Zertifikats.
fn known_certificates() -> BTreeMap<String, String> {
    std::fs::read_to_string(certificates_path()).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn remember_certificate(endpoint: &str, fingerprint: &str) -> Result<()> {
    let path = certificates_path();
    let mut known = known_certificates();
    known.insert(endpoint.to_owned(), fingerprint.to_owned());
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(&known)?).context("Zertifikat konnte nicht gespeichert werden")
}

// ---------------------------------------------------------------- Oberfläche

#[derive(Default)]
pub struct RdpView {
    started: bool,
    /// Zuletzt an Windows gemeldete Größe und eine noch nicht gemeldete Änderung.
    sent_size: (u16, u16),
    pending_size: Option<((u16, u16), Instant)>,
    clipboard: Option<arboard::Clipboard>,
    /// Zuletzt gesehener Text der lokalen Zwischenablage (auch aus Windows übernommener).
    clipboard_seen: Option<String>,
    clipboard_polled: Option<Instant>,
    texture: Option<egui::TextureHandle>,
    buttons: [bool; 3],
    position: (u16, u16),
    modifiers: Modifiers,
    scroll_remainder: f32,
    focus_requested: bool,
    overlay: ConnOverlay,
}

const SCROLL_STEP: f32 = 40.0;
/// Eine Raststufe des Mausrads in RDP-Einheiten.
const WHEEL_DELTA: i16 = 120;

impl RdpView {
    pub fn show(&mut self, ui: &mut egui::Ui, session: &RdpSession) -> TabResponse {
        let mut out = TabResponse::default();
        let rect = ui.available_rect_before_wrap();
        let response = ui.allocate_rect(rect, Sense::click_and_drag());
        ui.painter_at(rect).rect_filled(rect, 0.0, Color32::BLACK);

        // Desktop in physischen Pixeln anlegen und Windows die Skalierung mitteilen (z. B. 200 % auf Retina).
        let ppp = ui.ctx().pixels_per_point();
        let size = ((rect.width() * ppp).clamp(640.0, 8192.0) as u16, (rect.height() * ppp).clamp(480.0, 8192.0) as u16);
        let scale_percent = ((ppp * 100.0).round() as u32).clamp(100, 500);
        if !self.started {
            let _ = session.input.send(Input::Start { width: size.0, height: size.1, scale_percent });
            self.started = true;
            self.sent_size = size;
        }

        let status = session.conn().status();
        if matches!(status, Status::Connected) {
            self.resize(ui, size, scale_percent, session);
            self.sync_clipboard(ui, session);
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

    /// Meldet eine neue Tab-Größe erst, wenn sie eine Weile stabil ist (z. B. nach dem Ziehen am Fensterrand).
    fn resize(&mut self, ui: &egui::Ui, size: (u16, u16), scale_percent: u32, session: &RdpSession) {
        if size == self.sent_size {
            self.pending_size = None;
            return;
        }
        match self.pending_size {
            Some((pending, since)) if pending == size => {
                if since.elapsed() >= RESIZE_DEBOUNCE {
                    let _ = session.input.send(Input::Resize { width: size.0, height: size.1, scale_percent });
                    self.sent_size = size;
                    self.pending_size = None;
                } else {
                    ui.ctx().request_repaint_after(RESIZE_DEBOUNCE - since.elapsed());
                }
            }
            _ => {
                self.pending_size = Some((size, Instant::now()));
                ui.ctx().request_repaint_after(RESIZE_DEBOUNCE);
            }
        }
    }

    /// Text aus Windows in die lokale Zwischenablage, neuer lokaler Text an Windows.
    fn sync_clipboard(&mut self, ui: &egui::Ui, session: &RdpSession) {
        if let Some(text) = session.framebuffer().clipboard.take() {
            ui.ctx().copy_text(text.clone());
            self.clipboard_seen = Some(text);
        }
        if self.clipboard_polled.is_some_and(|t| t.elapsed() < CLIPBOARD_POLL) {
            return;
        }
        self.clipboard_polled = Some(Instant::now());
        ui.ctx().request_repaint_after(CLIPBOARD_POLL);
        if self.clipboard.is_none() {
            self.clipboard = arboard::Clipboard::new().ok();
        }
        let Some(text) = self.clipboard.as_mut().and_then(|c| c.get_text().ok()) else { return };
        self.offer_local_text(text, session);
    }

    fn offer_local_text(&mut self, text: String, session: &RdpSession) {
        if self.clipboard_seen.as_ref() != Some(&text) {
            self.clipboard_seen = Some(text.clone());
            let _ = session.input.send(Input::LocalClipboard(text));
        }
    }

    fn paint(&mut self, ui: &mut egui::Ui, rect: Rect, session: &RdpSession) -> Option<Rect> {
        let mut fb = session.framebuffer();
        if fb.width == 0 || fb.height == 0 {
            return None;
        }
        let size = [fb.width, fb.height];
        if fb.dirty || self.texture.as_ref().is_none_or(|t| t.size() != size) {
            // IronRDP liefert das Alpha-Byte nicht zuverlässig; das Bild ist immer deckend.
            let image = egui::ColorImage::from_rgb(
                size,
                &fb.pixels.as_chunks::<4>().0.iter().flat_map(|px| [px[0], px[1], px[2]]).collect::<Vec<_>>(),
            );
            match &mut self.texture {
                Some(texture) => texture.set(image, TextureOptions::LINEAR),
                None => self.texture = Some(ui.ctx().load_texture("rdp", image, TextureOptions::LINEAR)),
            }
            fb.dirty = false;
        }
        drop(fb);

        let image_size = egui::vec2(size[0] as f32, size[1] as f32);
        let scale = (rect.width() / image_size.x).min(rect.height() / image_size.y);
        let image_rect = Rect::from_center_size(rect.center(), image_size * scale);
        let uv = Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0));
        ui.painter_at(rect).image(self.texture.as_ref()?.id(), image_rect, uv, Color32::WHITE);
        Some(image_rect)
    }

    fn pointer(&mut self, ui: &egui::Ui, response: &egui::Response, image_rect: Rect, session: &RdpSession) {
        let Some(texture) = &self.texture else { return };
        let [w, h] = texture.size();
        let Some(pos) = ui.input(|i| i.pointer.latest_pos()) else { return };
        if !image_rect.contains(pos) && !response.dragged() {
            return;
        }
        let x = ((pos.x - image_rect.left()) / image_rect.width() * w as f32).clamp(0.0, w as f32 - 1.0) as u16;
        let y = ((pos.y - image_rect.top()) / image_rect.height() * h as f32).clamp(0.0, h as f32 - 1.0) as u16;

        let mut ops = Vec::new();
        if (x, y) != self.position {
            self.position = (x, y);
            ops.push(Operation::MouseMove(MousePosition { x, y }));
        }
        let buttons = [(PointerButton::Primary, MouseButton::Left), (PointerButton::Middle, MouseButton::Middle), (PointerButton::Secondary, MouseButton::Right)];
        for (i, (egui_button, rdp_button)) in buttons.into_iter().enumerate() {
            let down = ui.input(|input| input.pointer.button_down(egui_button));
            if down != self.buttons[i] {
                self.buttons[i] = down;
                ops.push(if down { Operation::MouseButtonPressed(rdp_button) } else { Operation::MouseButtonReleased(rdp_button) });
            }
        }
        self.scroll_remainder += ui.input(|i| i.smooth_scroll_delta.y);
        let steps = (self.scroll_remainder / SCROLL_STEP).trunc();
        if steps != 0.0 {
            self.scroll_remainder -= steps * SCROLL_STEP;
            ops.push(Operation::WheelRotations(WheelRotations { is_vertical: true, rotation_units: steps as i16 * WHEEL_DELTA }));
        }
        session.send(ops);
    }

    fn keyboard(&mut self, ui: &egui::Ui, session: &RdpSession) {
        let (events, modifiers) = ui.input(|i| (i.events.clone(), i.modifiers));
        let mut ops = self.sync_modifiers(modifiers);
        for event in events {
            match event {
                // Text als Unicode: unabhängig vom Tastaturlayout auf beiden Seiten.
                Event::Text(text) => text.chars().for_each(|c| unicode_tap(&mut ops, c)),
                // ⌘/Strg+C, X und V kommen als Copy/Cut/Paste statt als Tasten. Die Strg-Taste ist
                // schon gedrückt gemeldet (⌘ → Strg), also nur die Buchstabentaste schicken.
                // Beim Einfügen vorher den Text anbieten, damit Windows aus der abgeglichenen Ablage einfügt.
                Event::Paste(text) => {
                    self.offer_local_text(text, session);
                    tap(&mut ops, letter_scancode('v').expect("v"));
                }
                Event::Copy => tap(&mut ops, letter_scancode('c').expect("c")),
                Event::Cut => tap(&mut ops, letter_scancode('x').expect("x")),
                Event::Key { key, physical_key, pressed, modifiers, .. } => {
                    let code = special_scancode(key).or_else(|| {
                        // Mit Strg/Cmd erzeugt egui keinen Text; die physische Taste schicken,
                        // damit das Tastaturlayout des Servers sie richtig deutet.
                        (modifiers.ctrl || modifiers.mac_cmd)
                            .then(|| physical_key.unwrap_or(key))
                            .and_then(|k| k.name().chars().next().filter(|_| k.name().len() == 1))
                            .and_then(letter_scancode)
                    });
                    if let Some(code) = code {
                        ops.push(if pressed { Operation::KeyPressed(code) } else { Operation::KeyReleased(code) });
                    }
                }
                _ => {}
            }
        }
        session.send(ops);
    }

    fn sync_modifiers(&mut self, now: Modifiers) -> Vec<Operation> {
        // Unter macOS erzeugt Option Sonderzeichen (z. B. @) und wird deshalb nicht als Alt gemeldet;
        // Cmd wird zur Strg-Taste, damit ⌘C/⌘V auf Windows wie gewohnt wirken.
        let alt_is_modifier = !cfg!(target_os = "macos");
        let pairs = [
            (self.modifiers.shift, now.shift, scancode::SHIFT_L),
            (self.modifiers.ctrl || self.modifiers.mac_cmd, now.ctrl || now.mac_cmd, scancode::CONTROL_L),
            (self.modifiers.alt && alt_is_modifier, now.alt && alt_is_modifier, scancode::ALT_L),
        ];
        self.modifiers = now;
        pairs
            .into_iter()
            .filter(|(before, after, _)| before != after)
            .map(|(_, after, code)| if after { Operation::KeyPressed(code) } else { Operation::KeyReleased(code) })
            .collect()
    }

    fn release_modifiers(&mut self, session: &RdpSession) {
        if self.modifiers != Modifiers::NONE {
            let ops = self.sync_modifiers(Modifiers::NONE);
            session.send(ops);
        }
    }
}

fn tap(ops: &mut Vec<Operation>, code: Scancode) {
    ops.push(Operation::KeyPressed(code));
    ops.push(Operation::KeyReleased(code));
}

fn unicode_tap(ops: &mut Vec<Operation>, c: char) {
    ops.push(Operation::UnicodeKeyPressed(c));
    ops.push(Operation::UnicodeKeyReleased(c));
}

/// PC/AT-Scancodes (Set 1); erweiterte Tasten mit Präfix 0xE0.
mod scancode {
    use ironrdp_input::Scancode;

    pub const SHIFT_L: Scancode = Scancode::from_u8(false, 0x2A);
    pub const CONTROL_L: Scancode = Scancode::from_u8(false, 0x1D);
    pub const ALT_L: Scancode = Scancode::from_u8(false, 0x38);
}

fn special_scancode(key: Key) -> Option<Scancode> {
    let (extended, code) = match key {
        Key::Enter => (false, 0x1C),
        Key::Backspace => (false, 0x0E),
        Key::Tab => (false, 0x0F),
        Key::Escape => (false, 0x01),
        Key::Space => (false, 0x39),
        Key::Insert => (true, 0x52),
        Key::Delete => (true, 0x53),
        Key::Home => (true, 0x47),
        Key::End => (true, 0x4F),
        Key::PageUp => (true, 0x49),
        Key::PageDown => (true, 0x51),
        Key::ArrowUp => (true, 0x48),
        Key::ArrowDown => (true, 0x50),
        Key::ArrowLeft => (true, 0x4B),
        Key::ArrowRight => (true, 0x4D),
        Key::F1 => (false, 0x3B),
        Key::F2 => (false, 0x3C),
        Key::F3 => (false, 0x3D),
        Key::F4 => (false, 0x3E),
        Key::F5 => (false, 0x3F),
        Key::F6 => (false, 0x40),
        Key::F7 => (false, 0x41),
        Key::F8 => (false, 0x42),
        Key::F9 => (false, 0x43),
        Key::F10 => (false, 0x44),
        Key::F11 => (false, 0x57),
        Key::F12 => (false, 0x58),
        _ => return None,
    };
    Some(Scancode::from_u8(extended, code))
}

/// Scancode einer Buchstaben- oder Zifferntaste nach ihrer Position auf einer US-Tastatur.
fn letter_scancode(c: char) -> Option<Scancode> {
    const ROWS: [(&str, u8); 4] = [("1234567890", 0x02), ("qwertyuiop", 0x10), ("asdfghjkl", 0x1E), ("zxcvbnm", 0x2C)];
    let c = c.to_ascii_lowercase();
    ROWS.iter()
        .find_map(|(row, first)| row.find(c).map(|i| first + i as u8))
        .map(|code| Scancode::from_u8(false, code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scancodes() {
        assert_eq!(letter_scancode('q'), Some(Scancode::from_u8(false, 0x10)));
        assert_eq!(letter_scancode('C'), Some(Scancode::from_u8(false, 0x2E)));
        assert_eq!(letter_scancode('0'), Some(Scancode::from_u8(false, 0x0B)));
        assert_eq!(letter_scancode('ä'), None);
        assert_eq!(special_scancode(Key::ArrowUp), Some(Scancode::from_u8(true, 0x48)));
        assert_eq!(special_scancode(Key::A), None);
    }

    #[test]
    fn modifier_sync() {
        let mut view = RdpView::default();
        let ops = view.sync_modifiers(Modifiers { shift: true, ..Modifiers::NONE });
        assert!(matches!(ops.as_slice(), [Operation::KeyPressed(code)] if *code == scancode::SHIFT_L));
        assert!(view.sync_modifiers(Modifiers { shift: true, ..Modifiers::NONE }).is_empty(), "keine Wiederholung");
        let ops = view.sync_modifiers(Modifiers::NONE);
        assert!(matches!(ops.as_slice(), [Operation::KeyReleased(code)] if *code == scancode::SHIFT_L));
    }

    #[test]
    fn fingerprint_format() {
        let fp = fingerprint(b"abc");
        assert!(fp.starts_with("BA:78:16:BF"), "{fp}");
        assert_eq!(fp.len(), 32 * 3 - 1);
    }

    #[test]
    fn config_has_even_width_and_scale() {
        let config = build_config("u".into(), "p".into(), Some("D".into()), 1001, 700, 200);
        assert_eq!(config.desktop_size.width, 1000);
        assert_eq!(config.desktop_scale_factor, 200);
        assert!(config.enable_tls && config.enable_credssp);
    }

    /// Minimaler RDP-Server bis einschließlich TLS: beantwortet die X.224-Anfrage mit
    /// „NLA gewählt“, macht TLS mit `cert`/`key` und schließt danach (CredSSP schlägt dann fehl).
    async fn fake_tls_server(listener: tokio::net::TcpListener, cert: PathBuf, key: PathBuf) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_rustls::rustls;
        use tokio_rustls::rustls::pki_types::pem::PemObject;
        use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from_pem_file(&cert).unwrap()], PrivateKeyDer::from_pem_file(&key).unwrap())
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        loop {
            let Ok((mut tcp, _)) = listener.accept().await else { return };
            let mut header = [0u8; 4];
            if tcp.read_exact(&mut header).await.is_err() {
                continue;
            }
            let mut rest = vec![0u8; usize::from(u16::from_be_bytes([header[2], header[3]])) - 4];
            tcp.read_exact(&mut rest).await.unwrap();
            // TPKT + X.224 Connection Confirm + RDP_NEG_RSP (PROTOCOL_HYBRID).
            let confirm = [3, 0, 0, 19, 14, 0xD0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00];
            tcp.write_all(&confirm).await.unwrap();
            if let Ok(mut tls) = acceptor.accept(tcp).await {
                let _ = tls.shutdown().await;
            }
        }
    }

    fn openssl_cert(dir: &std::path::Path, name: &str) -> Option<(PathBuf, PathBuf, String)> {
        let (cert, key) = (dir.join(format!("{name}.pem")), dir.join(format!("{name}.key")));
        let ok = std::process::Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=rdp-test"])
            .arg("-keyout")
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .output()
            .is_ok_and(|o| o.status.success());
        if !ok {
            return None;
        }
        use tokio_rustls::rustls::pki_types::pem::PemObject;
        let der = tokio_rustls::rustls::pki_types::CertificateDer::from_pem_file(&cert).unwrap();
        Some((cert, key, fingerprint(&der)))
    }

    fn wait_status(session: &RdpSession, what: &str, done: impl Fn(&Status) -> bool) -> Status {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let status = session.conn().status();
            if done(&status) {
                return status;
            }
            assert!(std::time::Instant::now() < deadline, "Zeitüberschreitung: {what}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Zertifikat bestätigen, merken, beim nächsten Mal ohne Rückfrage; anderes Zertifikat ablehnen.
    #[test]
    fn tls_certificate_trust_on_first_use() {
        let dir = std::env::temp_dir().join(format!("conmgr-rdp-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let Some((cert, key, expected)) = openssl_cert(&dir, "a") else {
            eprintln!("openssl fehlt – Test übersprungen");
            return;
        };
        let (cert_b, key_b, _) = openssl_cert(&dir, "b").unwrap();
        *TEST_CERTIFICATES_PATH.lock().unwrap() = Some(dir.join("known.json"));

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let listener = runtime.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
        let port = listener.local_addr().unwrap().port();
        runtime.spawn(fake_tls_server(listener, cert, key));
        let start = |port| {
            let session = RdpSession::start(
                runtime.handle(),
                egui::Context::default(),
                RdpParams { host: "127.0.0.1".into(), port, username: "u".into(), password: Some(Zeroizing::new("p".into())) },
            );
            let _ = session.input.send(Input::Start { width: 800, height: 600, scale_percent: 100 });
            session
        };

        let first = start(port);
        let Status::HostKey { fingerprint: shown, .. } = wait_status(&first, "Zertifikatsabfrage", |s| matches!(s, Status::HostKey { .. })) else {
            unreachable!()
        };
        assert_eq!(shown, expected, "angezeigter Fingerabdruck = Zertifikat des Servers");
        first.conn().answer_host_key(true);
        let Status::Closed(msg) = wait_status(&first, "Ende nach TLS", |s| matches!(s, Status::Closed(_))) else { unreachable!() };
        assert!(!msg.contains("Zertifikat"), "nach Bestätigung kein Zertifikatsfehler mehr: {msg}");
        assert!(known_certificates().get(&format!("127.0.0.1:{port}")) == Some(&expected), "Fingerabdruck gespeichert");

        let second = start(port);
        let status = wait_status(&second, "zweiter Versuch", |s| matches!(s, Status::Closed(_) | Status::HostKey { .. }));
        assert!(matches!(status, Status::Closed(_)), "keine erneute Rückfrage");

        // Gleicher Endpunkt, anderes Zertifikat: ablehnen ohne Rückfrage.
        let listener = runtime.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
        let other_port = listener.local_addr().unwrap().port();
        runtime.spawn(fake_tls_server(listener, cert_b, key_b));
        remember_certificate(&format!("127.0.0.1:{other_port}"), &expected).unwrap();
        let third = start(other_port);
        let status = wait_status(&third, "Ablehnung", |s| matches!(s, Status::Closed(_) | Status::HostKey { .. }));
        let Status::Closed(msg) = status else { panic!("geändertes Zertifikat führte zu einer Rückfrage") };
        assert!(msg.contains("hat sich geändert"), "{msg}");

        *TEST_CERTIFICATES_PATH.lock().unwrap() = None;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn renders_view_with_input() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let ctx = egui::Context::default();
        let session = RdpSession::start(
            runtime.handle(),
            ctx.clone(),
            RdpParams { host: "127.0.0.1".into(), port: 1, username: "u".into(), password: Some(Zeroizing::new("p".into())) },
        );
        let mut view = RdpView::default();
        let frame = |view: &mut RdpView, events: Vec<Event>| {
            let input = egui::RawInput {
                events,
                screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(800.0, 600.0))),
                ..Default::default()
            };
            let _ = ctx.run(input, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    view.show(ui, &session);
                });
            });
        };
        frame(&mut view, vec![]);
        assert!(view.started, "Größe an die Sitzung gemeldet");
        wait_status(&session, "Fehlschlag", |s| matches!(s, Status::Closed(_)));

        session.conn().set_status(Status::Connected);
        {
            let mut fb = session.framebuffer();
            (fb.width, fb.height) = (64, 48);
            fb.pixels = [10, 20, 30, 0].repeat(64 * 48);
            fb.dirty = true;
        }
        frame(&mut view, vec![]);
        frame(
            &mut view,
            vec![
                Event::PointerMoved(egui::pos2(400.0, 300.0)),
                Event::Text("ä".into()),
                Event::Key { key: Key::Enter, physical_key: None, pressed: true, repeat: false, modifiers: Modifiers::NONE },
            ],
        );
        assert!(view.texture.is_some());
        assert!(!session.framebuffer().dirty, "Bild in die Textur übernommen");
    }

    #[test]
    fn clipboard_backend_events() {
        let events: Arc<Mutex<Vec<ClipEvent>>> = Arc::default();
        let mut backend = ClipBackend { events: Arc::clone(&events) };
        backend.on_remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]);
        backend.on_remote_copy(&[ClipboardFormat::new(ClipboardFormatId::new(2))]);
        backend.on_format_data_response(FormatDataResponse::new_unicode_string("Grüße ✓"));
        backend.on_format_data_response(FormatDataResponse::new_error());
        assert_eq!(
            *events.lock().unwrap(),
            [ClipEvent::RemoteHasText, ClipEvent::RemoteText("Grüße ✓".into())],
            "nur Text, ohne abschließende Null; Fehlerantworten ignoriert"
        );
    }

    /// Prüft, was die Ansicht an die Sitzungsschleife schickt (ohne laufende Verbindung).
    fn view_with_channel() -> (RdpView, RdpSession, mpsc::UnboundedReceiver<Input>) {
        let (input, rx) = mpsc::unbounded_channel();
        let session = RdpSession {
            conn: Conn::new(egui::Context::default()),
            framebuffer: Arc::default(),
            input,
        };
        (RdpView::default(), session, rx)
    }

    #[test]
    fn local_clipboard_is_offered_once() {
        let (mut view, session, mut rx) = view_with_channel();
        view.offer_local_text("a".into(), &session);
        view.offer_local_text("a".into(), &session);
        // Aus Windows übernommener Text wird nicht zurückgeschickt.
        view.clipboard_seen = Some("von Windows".into());
        view.offer_local_text("von Windows".into(), &session);
        view.offer_local_text("b".into(), &session);
        let mut sent = Vec::new();
        while let Ok(Input::LocalClipboard(text)) = rx.try_recv() {
            sent.push(text);
        }
        assert_eq!(sent, ["a", "b"]);
    }

    #[test]
    fn resize_is_debounced() {
        let (mut view, session, mut rx) = view_with_channel();
        let ctx = egui::Context::default();
        view.sent_size = (1000, 800);
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                view.resize(ui, (1200, 800), 200, &session);
                view.resize(ui, (1300, 800), 200, &session);
                assert!(rx.try_recv().is_err(), "während des Ziehens nichts senden");
                // Größe stabil und Ruhezeit vorbei → senden.
                view.pending_size = Some(((1300, 800), Instant::now() - RESIZE_DEBOUNCE));
                view.resize(ui, (1300, 800), 200, &session);
            });
        });
        assert!(matches!(rx.try_recv(), Ok(Input::Resize { width: 1300, height: 800, scale_percent: 200 })));
        assert_eq!(view.sent_size, (1300, 800));
    }

    /// Verbindungsversuch zu einem geschlossenen Port: sauberer Fehler, keine Hänger.
    #[test]
    fn closed_port_reports_error() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let session = RdpSession::start(
            runtime.handle(),
            egui::Context::default(),
            RdpParams { host: "127.0.0.1".into(), port: 1, username: "u".into(), password: Some(Zeroizing::new("p".into())) },
        );
        let _ = session.input.send(Input::Start { width: 800, height: 600, scale_percent: 100 });
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if let Status::Closed(msg) = session.conn().status() {
                assert!(msg.starts_with("Fehler"), "{msg}");
                break;
            }
            assert!(std::time::Instant::now() < deadline, "hängt");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
