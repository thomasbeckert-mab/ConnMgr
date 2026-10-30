//! Eingebettete SSH-Sitzung: russh für das Protokoll, vt100 als Terminal-Emulator.
//!
//! Jede Sitzung läuft als eigene Tokio-Aufgabe. Die Oberfläche liest den Bildschirm
//! über `Shared` und schickt Tastatureingaben und Größenänderungen über einen Kanal.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use eframe::egui;
use russh::client::{self, AuthResult, KeyboardInteractiveAuthResponse};
use russh::keys::{self, HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect};
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const SCROLLBACK_LINES: usize = 5000;

pub enum Status {
    Connecting,
    /// Unbekannter Host-Key, der Benutzer muss entscheiden.
    HostKey { fingerprint: String, algorithm: String },
    Connected,
    Closed(String),
}

pub struct Shared {
    pub parser: vt100::Parser,
    pub status: Status,
    host_key_reply: Option<oneshot::Sender<bool>>,
}

pub struct ConnectParams {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<Zeroizing<String>>,
    pub cols: u16,
    pub rows: u16,
}

enum Input {
    Data(Vec<u8>),
    Resize { cols: u16, rows: u16 },
    Close,
}

pub struct SshSession {
    shared: Arc<Mutex<Shared>>,
    input: mpsc::UnboundedSender<Input>,
}

impl SshSession {
    pub fn start(runtime: &tokio::runtime::Handle, ctx: egui::Context, params: ConnectParams) -> Self {
        let shared = Arc::new(Mutex::new(Shared {
            parser: vt100::Parser::new(params.rows, params.cols, SCROLLBACK_LINES),
            status: Status::Connecting,
            host_key_reply: None,
        }));
        let (input, input_rx) = mpsc::unbounded_channel();
        runtime.spawn(run(params, Arc::clone(&shared), ctx, input_rx));
        Self { shared, input }
    }

    pub fn lock(&self) -> MutexGuard<'_, Shared> {
        self.shared.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn send(&self, bytes: Vec<u8>) {
        let _ = self.input.send(Input::Data(bytes));
    }

    pub fn resize(&self, cols: u16, rows: u16) {
        self.lock().parser.screen_mut().set_size(rows, cols);
        let _ = self.input.send(Input::Resize { cols, rows });
    }

    pub fn answer_host_key(&self, trust: bool) {
        if let Some(reply) = self.lock().host_key_reply.take() {
            let _ = reply.send(trust);
        }
    }
}

impl Drop for SshSession {
    fn drop(&mut self) {
        self.answer_host_key(false);
        let _ = self.input.send(Input::Close);
    }
}

fn set_status(shared: &Mutex<Shared>, ctx: &egui::Context, status: Status) {
    shared.lock().unwrap_or_else(|e| e.into_inner()).status = status;
    ctx.request_repaint();
}

async fn run(params: ConnectParams, shared: Arc<Mutex<Shared>>, ctx: egui::Context, input: mpsc::UnboundedReceiver<Input>) {
    let message = match session(params, &shared, &ctx, input).await {
        Ok(message) => message,
        Err(e) => format!("Fehler: {e:#}"),
    };
    set_status(&shared, &ctx, Status::Closed(message));
}

async fn session(
    params: ConnectParams,
    shared: &Arc<Mutex<Shared>>,
    ctx: &egui::Context,
    mut input: mpsc::UnboundedReceiver<Input>,
) -> Result<String> {
    let config = Arc::new(client::Config {
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(30)),
        ..Default::default()
    });
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect((params.host.as_str(), params.port)))
        .await
        .map_err(|_| anyhow!("Zeitüberschreitung beim Verbindungsaufbau zu {}:{}", params.host, params.port))?
        .map_err(connect_error)?;
    stream.set_nodelay(true)?;
    let handler = Client { host: params.host.clone(), port: params.port, shared: Arc::clone(shared), ctx: ctx.clone() };
    let mut handle = client::connect_stream(config, stream, handler).await?;

    let username = if params.username.is_empty() { local_username() } else { params.username.clone() };
    authenticate(&mut handle, &username, params.password.as_ref().map(|p| p.as_str())).await?;

    let (mut reader, writer) = handle.channel_open_session().await?.split();
    writer.request_pty(false, "xterm-256color", params.cols.into(), params.rows.into(), 0, 0, &[]).await?;
    writer.request_shell(false).await?;
    set_status(shared, ctx, Status::Connected);

    let mut exit_status = None;
    loop {
        tokio::select! {
            msg = reader.wait() => match msg {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                    shared.lock().unwrap_or_else(|e| e.into_inner()).parser.process(&data);
                    ctx.request_repaint();
                }
                Some(ChannelMsg::ExitStatus { exit_status: code }) => exit_status = Some(code),
                // Nach EOF schickt der Server noch den Exit-Status, erst Close beendet den Kanal.
                Some(ChannelMsg::Close) | None => break,
                Some(_) => {}
            },
            cmd = input.recv() => match cmd {
                Some(Input::Data(bytes)) => writer.data_bytes(bytes).await?,
                Some(Input::Resize { cols, rows }) => writer.window_change(cols.into(), rows.into(), 0, 0).await?,
                Some(Input::Close) | None => {
                    let _ = writer.eof().await;
                    let _ = handle.disconnect(Disconnect::ByApplication, "", "de").await;
                    return Ok("Verbindung getrennt".into());
                }
            },
        }
    }
    let _ = handle.disconnect(Disconnect::ByApplication, "", "de").await;
    Ok(match exit_status {
        Some(code) => format!("Sitzung beendet (Exit-Code {code})"),
        None => "Sitzung beendet".into(),
    })
}

/// Reihenfolge wie bei OpenSSH: Standardschlüssel aus ~/.ssh, dann Passwort,
/// dann Keyboard-Interactive (manche Server erlauben nur das).
async fn authenticate(handle: &mut client::Handle<Client>, user: &str, password: Option<&str>) -> Result<()> {
    for path in default_key_files() {
        // Verschlüsselte Schlüssel lassen sich ohne Passphrase nicht laden und werden übersprungen.
        let Ok(key) = keys::load_secret_key(&path, None) else { continue };
        let hash = if key.algorithm().is_rsa() { handle.best_supported_rsa_hash().await?.flatten() } else { None };
        let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash);
        if handle.authenticate_publickey(user, key).await?.success() {
            return Ok(());
        }
    }

    let Some(password) = password else {
        bail!("Anmeldung als „{user}“ fehlgeschlagen: kein passender Schlüssel in ~/.ssh und kein Passwort hinterlegt");
    };
    if let AuthResult::Success = handle.authenticate_password(user, password).await? {
        return Ok(());
    }

    let mut response = handle.authenticate_keyboard_interactive_start(user, None).await?;
    for _ in 0..5 {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(()),
            KeyboardInteractiveAuthResponse::Failure { .. } => break,
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                // Verdeckte Abfragen sind Passwortabfragen; andere können wir nicht beantworten.
                let answers = prompts.iter().map(|p| if p.echo { String::new() } else { password.to_owned() }).collect();
                response = handle.authenticate_keyboard_interactive_respond(answers).await?;
            }
        }
    }
    bail!("Anmeldung als „{user}“ fehlgeschlagen: Passwort falsch oder vom Server nicht akzeptiert")
}

/// macOS meldet eine fehlende Berechtigung „Lokales Netzwerk“ als „No route to host“.
fn connect_error(e: std::io::Error) -> anyhow::Error {
    const EHOSTUNREACH_MACOS: i32 = 65;
    if cfg!(target_os = "macos") && e.raw_os_error() == Some(EHOSTUNREACH_MACOS) {
        return anyhow!(
            "{e}. Vermutlich blockiert macOS den Zugriff aufs lokale Netzwerk: ConMgr als App starten \
             (scripts/bundle-macos.sh) und den Zugriff erlauben, oder unter Systemeinstellungen → \
             Datenschutz & Sicherheit → Lokales Netzwerk freigeben."
        );
    }
    e.into()
}

fn default_key_files() -> Vec<PathBuf> {
    let Some(dirs) = directories::BaseDirs::new() else { return Vec::new() };
    let ssh = dirs.home_dir().join(".ssh");
    ["id_ed25519", "id_ecdsa", "id_rsa"].iter().map(|name| ssh.join(name)).filter(|p| p.exists()).collect()
}

fn local_username() -> String {
    std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_default()
}

#[derive(Debug)]
enum ClientError {
    Ssh(russh::Error),
    HostKey(String),
}

impl From<russh::Error> for ClientError {
    fn from(e: russh::Error) -> Self {
        ClientError::Ssh(e)
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Ssh(e) => write!(f, "{e}"),
            ClientError::HostKey(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for ClientError {}

struct Client {
    host: String,
    port: u16,
    shared: Arc<Mutex<Shared>>,
    ctx: egui::Context,
}

impl client::Handler for Client {
    type Error = ClientError;

    /// Prüft gegen ~/.ssh/known_hosts (dieselbe Datei wie OpenSSH). Unbekannte Keys
    /// muss der Benutzer bestätigen, geänderte Keys werden immer abgelehnt.
    async fn check_server_key(&mut self, server_key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = server_key else {
            return Err(ClientError::HostKey("Host-Zertifikate werden noch nicht unterstützt".into()));
        };
        match keys::check_known_hosts(&self.host, self.port, key) {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(keys::Error::KeyChanged { line }) => {
                return Err(ClientError::HostKey(format!(
                    "WARNUNG: Der Host-Key von {} hat sich geändert (~/.ssh/known_hosts, Zeile {line}). \
                     Möglicherweise wird die Verbindung abgehört — abgebrochen.",
                    self.host
                )));
            }
            Err(e) => return Err(ClientError::HostKey(format!("known_hosts kann nicht gelesen werden: {e}"))),
        }

        let (reply, answer) = oneshot::channel();
        {
            let mut shared = self.shared.lock().unwrap_or_else(|e| e.into_inner());
            shared.status = Status::HostKey {
                fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
                algorithm: key.algorithm().to_string(),
            };
            shared.host_key_reply = Some(reply);
        }
        self.ctx.request_repaint();

        if !answer.await.unwrap_or(false) {
            return Err(ClientError::HostKey("Host-Key nicht bestätigt — Verbindung abgebrochen".into()));
        }
        set_status(&self.shared, &self.ctx, Status::Connecting);
        keys::known_hosts::learn_known_hosts(&self.host, self.port, key)
            .map_err(|e| ClientError::HostKey(format!("Host-Key konnte nicht gespeichert werden: {e}")))?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn wait_for(session: &SshSession, what: &str, mut done: impl FnMut(&Shared) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done(&session.lock()) {
            if let Status::Closed(msg) = &session.lock().status {
                panic!("beendet beim Warten auf {what}: {msg}");
            }
            assert!(Instant::now() < deadline, "Zeitüberschreitung beim Warten auf {what}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Gegen einen echten sshd: `CONMGR_E2E_SSH_PORT=2222 HOME=<test-home> cargo test e2e -- --ignored`.
    /// HOME muss auf ein Testverzeichnis zeigen (Schlüssel in .ssh, known_hosts wird dort angelegt).
    #[test]
    #[ignore]
    fn e2e_real_server() {
        let port: u16 = std::env::var("CONMGR_E2E_SSH_PORT").expect("CONMGR_E2E_SSH_PORT").parse().unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let params = || ConnectParams {
            host: "127.0.0.1".into(),
            port,
            username: String::new(),
            password: None,
            cols: 80,
            rows: 24,
        };

        let session = SshSession::start(runtime.handle(), egui::Context::default(), params());
        wait_for(&session, "Host-Key-Abfrage", |s| matches!(s.status, Status::HostKey { .. }));
        session.answer_host_key(true);
        wait_for(&session, "Verbindung", |s| matches!(s.status, Status::Connected));

        session.resize(100, 30);
        session.send(b"echo conmgr-ok-$((40+2)); stty size\r".to_vec());
        wait_for(&session, "Befehlsausgabe", |s| {
            let text = s.parser.screen().contents();
            text.contains("conmgr-ok-42") && text.contains("30 100")
        });

        session.send(b"exit\r".to_vec());
        wait_for(&session, "Sitzungsende", |s| matches!(s.status, Status::Closed(_)));
        if let Status::Closed(msg) = &session.lock().status {
            assert!(msg.contains("Exit-Code 0"), "{msg}");
        }

        // Jetzt bekannt: keine erneute Abfrage.
        let again = SshSession::start(runtime.handle(), egui::Context::default(), params());
        wait_for(&again, "zweite Verbindung", |s| {
            assert!(!matches!(s.status, Status::HostKey { .. }), "Host-Key wurde nicht gespeichert");
            matches!(s.status, Status::Connected)
        });
        drop(again);

        // Geänderter Host-Key (anderer Schlüssel in known_hosts) muss abgelehnt werden.
        let home = directories::BaseDirs::new().unwrap().home_dir().to_owned();
        let other_key = std::fs::read_to_string(home.join(".ssh/id_ed25519.pub")).unwrap();
        let fake_entry = format!("[127.0.0.1]:{port} {}", other_key.split_whitespace().take(2).collect::<Vec<_>>().join(" "));
        std::fs::write(home.join(".ssh/known_hosts"), fake_entry + "\n").unwrap();
        let tampered = SshSession::start(runtime.handle(), egui::Context::default(), params());
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Status::Closed(msg) = &tampered.lock().status {
                assert!(msg.contains("hat sich geändert"), "{msg}");
                break;
            }
            assert!(!matches!(tampered.lock().status, Status::Connected | Status::HostKey { .. }), "geänderter Key akzeptiert");
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
