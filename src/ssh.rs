//! SSH-Verbindungen: Aufbau, Host-Key-Prüfung und Anmeldung (für Terminal- und
//! SFTP-Tabs) sowie die eingebettete Terminal-Sitzung mit vt100 als Emulator.
//!
//! Jede Verbindung läuft als eigene Tokio-Aufgabe. Zustand und Rückfragen an den
//! Benutzer (Host-Key, Passphrase, Passwort) laufen über `Conn`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use eframe::egui;
use russh::client::{self, AuthResult, KeyboardInteractiveAuthResponse};
use russh::keys::agent::client::AgentClient;
use russh::keys::{self, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect, MethodKind, MethodSet};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const SCROLLBACK_LINES: usize = 5000;
const MAX_PROMPTS: usize = 3;

#[derive(Clone)]
pub enum Status {
    Connecting,
    /// Unbekannter Host-Key, der Benutzer muss entscheiden.
    HostKey { fingerprint: String, algorithm: String },
    /// Eingabe nötig (Passwort, Passphrase, Keyboard-Interactive).
    Prompt { message: String, secret: bool },
    Connected,
    Closed(String),
}

type PromptReply = oneshot::Sender<Option<Zeroizing<String>>>;

/// Verbindungszustand und offene Rückfragen, geteilt zwischen Oberfläche und Hintergrundaufgabe.
pub struct Conn {
    state: Mutex<ConnState>,
    ctx: egui::Context,
}

struct ConnState {
    status: Status,
    host_key_reply: Option<oneshot::Sender<bool>>,
    prompt_reply: Option<PromptReply>,
}

impl Conn {
    pub fn new(ctx: egui::Context) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(ConnState { status: Status::Connecting, host_key_reply: None, prompt_reply: None }),
            ctx,
        })
    }

    fn state(&self) -> MutexGuard<'_, ConnState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn status(&self) -> Status {
        self.state().status.clone()
    }

    pub fn set_status(&self, status: Status) {
        self.state().status = status;
        self.ctx.request_repaint();
    }

    pub fn repaint(&self) {
        self.ctx.request_repaint();
    }

    pub fn answer_host_key(&self, trust: bool) {
        if let Some(reply) = self.state().host_key_reply.take() {
            let _ = reply.send(trust);
        }
    }

    /// `None` bricht die Rückfrage ab.
    pub fn answer_prompt(&self, answer: Option<Zeroizing<String>>) {
        if let Some(reply) = self.state().prompt_reply.take() {
            let _ = reply.send(answer);
        }
    }

    /// Beantwortet offene Rückfragen ablehnend, damit die Aufgabe endet.
    pub fn cancel(&self) {
        self.answer_host_key(false);
        self.answer_prompt(None);
    }

    async fn ask_host_key(&self, fingerprint: String, algorithm: String) -> bool {
        let (reply, answer) = oneshot::channel();
        {
            let mut state = self.state();
            state.status = Status::HostKey { fingerprint, algorithm };
            state.host_key_reply = Some(reply);
        }
        self.repaint();
        let trust = answer.await.unwrap_or(false);
        self.set_status(Status::Connecting);
        trust
    }

    async fn ask(&self, message: String, secret: bool) -> Option<Zeroizing<String>> {
        let (reply, answer) = oneshot::channel();
        {
            let mut state = self.state();
            state.status = Status::Prompt { message, secret };
            state.prompt_reply = Some(reply);
        }
        self.repaint();
        let result = answer.await.ok().flatten();
        self.set_status(Status::Connecting);
        result
    }
}

pub struct ConnectParams {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<Zeroizing<String>>,
    /// Privater Schlüssel aus den Zugangsdaten (Text) und dessen Passphrase.
    pub private_key: Option<Zeroizing<String>>,
    pub passphrase: Option<Zeroizing<String>>,
}

/// Baut die Verbindung auf, prüft den Host-Key und meldet sich an.
pub async fn establish(params: &ConnectParams, conn: &Arc<Conn>) -> Result<client::Handle<Client>> {
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
    let handler = Client { host: params.host.clone(), port: params.port, conn: Arc::clone(conn) };
    let mut handle = client::connect_stream(config, stream, handler).await?;

    let username = if params.username.is_empty() { local_username() } else { params.username.clone() };
    authenticate(&mut handle, &username, params, conn).await?;
    Ok(handle)
}

/// Reihenfolge wie bei OpenSSH: Schlüssel aus den Zugangsdaten, SSH-Agent,
/// Standardschlüssel aus ~/.ssh, dann Passwort und Keyboard-Interactive.
async fn authenticate(handle: &mut client::Handle<Client>, user: &str, params: &ConnectParams, conn: &Conn) -> Result<()> {
    let target = format!("{user}@{}", params.host);
    let mut methods: Option<MethodSet> = None;

    if let Some(pem) = &params.private_key {
        let key = load_key(pem, params.passphrase.as_ref().map(|p| p.as_str()), "den hinterlegten Schlüssel", conn)
            .await
            .map_err(|e| anyhow!("Hinterlegter Schlüssel ist ungültig: {e}"))?;
        if let Some(key) = key {
            match try_key(handle, user, key).await? {
                AuthResult::Success => return Ok(()),
                AuthResult::Failure { remaining_methods, .. } => methods = Some(remaining_methods),
            }
        }
    }

    if try_agent(handle, user).await {
        return Ok(());
    }

    for path in default_key_files() {
        let Ok(pem) = std::fs::read_to_string(&path) else { continue };
        let label = format!("~/.ssh/{}", path.file_name().unwrap_or_default().to_string_lossy());
        // Unlesbare Dateien sind keine Schlüssel und werden übersprungen.
        let Ok(Some(key)) = load_key(&pem, None, &label, conn).await else { continue };
        match try_key(handle, user, key).await? {
            AuthResult::Success => return Ok(()),
            AuthResult::Failure { remaining_methods, .. } => methods = Some(remaining_methods),
        }
    }

    let allows = |kind: MethodKind| methods.as_ref().is_none_or(|m| m.contains(&kind));
    if !allows(MethodKind::Password) && !allows(MethodKind::KeyboardInteractive) {
        bail!("Anmeldung als „{user}“ fehlgeschlagen: Der Server akzeptiert nur Schlüssel, und keiner passte");
    }

    let mut password = params.password.clone();
    let mut rejected = false;
    for _ in 0..MAX_PROMPTS {
        let pw = match password.take() {
            Some(pw) => pw,
            None => {
                let message = if rejected {
                    format!("Passwort für {target} wurde abgelehnt. Erneut eingeben:")
                } else {
                    format!("Passwort für {target}:")
                };
                conn.ask(message, true).await.ok_or_else(|| anyhow!("Anmeldung abgebrochen"))?
            }
        };
        if allows(MethodKind::Password) && handle.authenticate_password(user, pw.as_str()).await?.success() {
            return Ok(());
        }
        if allows(MethodKind::KeyboardInteractive) && keyboard_interactive(handle, user, &pw, conn).await? {
            return Ok(());
        }
        rejected = true;
    }
    bail!("Anmeldung als „{user}“ fehlgeschlagen: Passwort falsch oder vom Server nicht akzeptiert")
}

async fn try_key(handle: &mut client::Handle<Client>, user: &str, key: PrivateKey) -> Result<AuthResult> {
    let hash = if key.algorithm().is_rsa() { handle.best_supported_rsa_hash().await?.flatten() } else { None };
    Ok(handle.authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), hash)).await?)
}

/// Lädt einen Schlüssel; fragt bei verschlüsselten Schlüsseln nach der Passphrase.
/// `Ok(None)`, wenn der Benutzer abbricht.
async fn load_key(pem: &str, passphrase: Option<&str>, label: &str, conn: &Conn) -> Result<Option<PrivateKey>> {
    match keys::decode_secret_key(pem, passphrase) {
        Ok(key) => return Ok(Some(key)),
        Err(keys::Error::KeyIsEncrypted) => {}
        // Mit falscher Passphrase scheitert das Entschlüsseln mit einem anderen Fehler.
        Err(_) if passphrase.is_some() => {}
        Err(e) => return Err(e.into()),
    }
    let mut message = format!("Passphrase für {label}:");
    for _ in 0..MAX_PROMPTS {
        let Some(answer) = conn.ask(message.clone(), true).await else { return Ok(None) };
        if let Ok(key) = keys::decode_secret_key(pem, Some(&answer)) {
            return Ok(Some(key));
        }
        message = format!("Passphrase für {label} ist falsch. Erneut eingeben:");
    }
    Ok(None)
}

async fn try_agent(handle: &mut client::Handle<Client>, user: &str) -> bool {
    #[cfg(unix)]
    {
        match AgentClient::connect_env().await {
            Ok(agent) => agent_auth(handle, user, agent).await,
            Err(_) => false,
        }
    }
    #[cfg(windows)]
    {
        if let Ok(agent) = AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await {
            if agent_auth(handle, user, agent).await {
                return true;
            }
        }
        match AgentClient::connect_pageant().await {
            Ok(agent) => agent_auth(handle, user, agent).await,
            Err(_) => false,
        }
    }
}

async fn agent_auth<S>(handle: &mut client::Handle<Client>, user: &str, mut agent: AgentClient<S>) -> bool
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let Ok(identities) = agent.request_identities().await else { return false };
    for identity in identities {
        let key = identity.public_key().into_owned();
        let hash = if key.algorithm().is_rsa() { handle.best_supported_rsa_hash().await.ok().flatten().flatten() } else { None };
        if let Ok(AuthResult::Success) = handle.authenticate_publickey_with(user, key, hash, &mut agent).await {
            return true;
        }
    }
    false
}

/// Beantwortet verdeckte Abfragen mit dem Passwort; andere fragt der Benutzer selbst.
async fn keyboard_interactive(handle: &mut client::Handle<Client>, user: &str, password: &str, conn: &Conn) -> Result<bool> {
    let mut response = handle.authenticate_keyboard_interactive_start(user, None).await?;
    let mut password_used = false;
    for _ in 0..5 {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                let mut answers = Vec::new();
                for prompt in prompts {
                    if !prompt.echo && !password_used {
                        password_used = true;
                        answers.push(password.to_owned());
                    } else {
                        let answer = conn.ask(prompt.prompt.trim().to_owned(), !prompt.echo).await;
                        answers.push(answer.map(|a| a.to_string()).ok_or_else(|| anyhow!("Anmeldung abgebrochen"))?);
                    }
                }
                response = handle.authenticate_keyboard_interactive_respond(answers).await?;
            }
        }
    }
    Ok(false)
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
pub enum ClientError {
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

pub struct Client {
    host: String,
    port: u16,
    conn: Arc<Conn>,
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

        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        if !self.conn.ask_host_key(fingerprint, key.algorithm().to_string()).await {
            return Err(ClientError::HostKey("Host-Key nicht bestätigt — Verbindung abgebrochen".into()));
        }
        keys::known_hosts::learn_known_hosts(&self.host, self.port, key)
            .map_err(|e| ClientError::HostKey(format!("Host-Key konnte nicht gespeichert werden: {e}")))?;
        Ok(true)
    }
}

// ---------------------------------------------------------------- Terminal-Sitzung

enum Input {
    Data(Vec<u8>),
    Resize { cols: u16, rows: u16 },
    Close,
}

pub struct SshSession {
    conn: Arc<Conn>,
    parser: Arc<Mutex<vt100::Parser>>,
    input: mpsc::UnboundedSender<Input>,
}

impl SshSession {
    pub fn start(runtime: &tokio::runtime::Handle, ctx: egui::Context, params: ConnectParams) -> Self {
        let (cols, rows) = (80, 24);
        let conn = Conn::new(ctx);
        let parser = Arc::new(Mutex::new(vt100::Parser::new(rows, cols, SCROLLBACK_LINES)));
        let (input, input_rx) = mpsc::unbounded_channel();
        let (task_conn, task_parser) = (Arc::clone(&conn), Arc::clone(&parser));
        runtime.spawn(async move {
            let message = match run_shell(params, &task_conn, &task_parser, input_rx).await {
                Ok(message) => message,
                Err(e) => format!("Fehler: {e:#}"),
            };
            task_conn.set_status(Status::Closed(message));
        });
        Self { conn, parser, input }
    }

    pub fn conn(&self) -> &Conn {
        &self.conn
    }

    pub fn parser(&self) -> MutexGuard<'_, vt100::Parser> {
        self.parser.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn send(&self, bytes: Vec<u8>) {
        let _ = self.input.send(Input::Data(bytes));
    }

    pub fn resize(&self, cols: u16, rows: u16) {
        self.parser().screen_mut().set_size(rows, cols);
        let _ = self.input.send(Input::Resize { cols, rows });
    }
}

impl Drop for SshSession {
    fn drop(&mut self) {
        self.conn.cancel();
        let _ = self.input.send(Input::Close);
    }
}

async fn run_shell(
    params: ConnectParams,
    conn: &Arc<Conn>,
    parser: &Mutex<vt100::Parser>,
    mut input: mpsc::UnboundedReceiver<Input>,
) -> Result<String> {
    let handle = establish(&params, conn).await?;
    let (mut reader, writer) = handle.channel_open_session().await?.split();
    // Die Oberfläche hat die Größe inzwischen meist schon an das Fenster angepasst.
    let (rows, cols) = parser.lock().unwrap_or_else(|e| e.into_inner()).screen().size();
    writer.request_pty(false, "xterm-256color", cols.into(), rows.into(), 0, 0, &[]).await?;
    writer.request_shell(false).await?;
    conn.set_status(Status::Connected);

    let mut exit_status = None;
    loop {
        tokio::select! {
            msg = reader.wait() => match msg {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                    parser.lock().unwrap_or_else(|e| e.into_inner()).process(&data);
                    conn.repaint();
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

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::time::Instant;

    pub fn wait_for(conn: &Conn, what: &str, mut done: impl FnMut(&Status) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let status = conn.status();
            if done(&status) {
                return;
            }
            // Unbekannte Test-Server automatisch bestätigen, solange nicht genau darauf gewartet wird.
            if matches!(status, Status::HostKey { .. }) {
                conn.answer_host_key(true);
            }
            if let Status::Closed(msg) = &status {
                panic!("beendet beim Warten auf {what}: {msg}");
            }
            assert!(Instant::now() < deadline, "Zeitüberschreitung beim Warten auf {what}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn e2e_params(port: u16) -> ConnectParams {
        ConnectParams {
            host: "127.0.0.1".into(),
            port,
            username: String::new(),
            password: None,
            private_key: None,
            passphrase: None,
        }
    }

    pub fn e2e_port() -> u16 {
        std::env::var("CONMGR_E2E_SSH_PORT").expect("CONMGR_E2E_SSH_PORT").parse().unwrap()
    }

    fn home() -> PathBuf {
        directories::BaseDirs::new().unwrap().home_dir().to_owned()
    }

    /// Gegen einen echten sshd: `CONMGR_E2E_SSH_PORT=2222 HOME=<test-home> cargo test e2e -- --ignored --test-threads=1`.
    /// HOME muss auf ein Testverzeichnis zeigen (Schlüssel in .ssh, known_hosts wird dort angelegt).
    #[test]
    #[ignore]
    fn e2e_shell() {
        let port = e2e_port();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let _ = std::fs::remove_file(home().join(".ssh/known_hosts"));

        let session = SshSession::start(runtime.handle(), egui::Context::default(), e2e_params(port));
        wait_for(session.conn(), "Host-Key-Abfrage", |s| matches!(s, Status::HostKey { .. }));
        session.conn().answer_host_key(true);
        wait_for(session.conn(), "Verbindung", |s| matches!(s, Status::Connected));

        session.resize(100, 30);
        session.send(b"echo conmgr-ok-$((40+2)); stty size\r".to_vec());
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let text = session.parser().screen().contents();
            if text.contains("conmgr-ok-42") && text.contains("30 100") {
                break;
            }
            assert!(Instant::now() < deadline, "keine Befehlsausgabe: {text}");
            std::thread::sleep(Duration::from_millis(20));
        }

        session.send(b"exit\r".to_vec());
        wait_for(session.conn(), "Sitzungsende", |s| matches!(s, Status::Closed(_)));
        if let Status::Closed(msg) = session.conn().status() {
            assert!(msg.contains("Exit-Code 0"), "{msg}");
        }

        // Jetzt bekannt: keine erneute Abfrage.
        let again = SshSession::start(runtime.handle(), egui::Context::default(), e2e_params(port));
        wait_for(again.conn(), "zweite Verbindung", |s| {
            assert!(!matches!(s, Status::HostKey { .. }), "Host-Key wurde nicht gespeichert");
            matches!(s, Status::Connected)
        });
    }

    /// Schlüssel mit Passphrase aus den Zugangsdaten (ohne Agent und ohne Standardschlüssel):
    /// erst falsche Passphrase gespeichert → Abfrage, dann richtige Eingabe.
    #[test]
    #[ignore]
    fn e2e_encrypted_key_from_credentials() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let pem = std::fs::read_to_string(home().join("enc_key")).expect("enc_key im Test-HOME");
        let mut params = e2e_params(e2e_port());
        params.private_key = Some(Zeroizing::new(pem));
        params.passphrase = Some(Zeroizing::new("falsch".into()));

        let session = SshSession::start(runtime.handle(), egui::Context::default(), params);
        wait_for(session.conn(), "Passphrase-Abfrage", |s| matches!(s, Status::Prompt { secret: true, .. }));
        session.conn().answer_prompt(Some(Zeroizing::new("geheim123".into())));
        wait_for(session.conn(), "Verbindung", |s| matches!(s, Status::Connected));
    }

    /// Kein Schlüssel passt: der Server nimmt nur Schlüssel → klare Meldung statt Passwortabfrage.
    #[test]
    #[ignore]
    fn e2e_no_key_and_keys_only_server() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let mut params = e2e_params(e2e_port());
        params.username = "niemand".into();
        let session = SshSession::start(runtime.handle(), egui::Context::default(), params);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match session.conn().status() {
                Status::Closed(msg) => {
                    assert!(msg.contains("nur Schlüssel"), "{msg}");
                    break;
                }
                Status::Prompt { message, .. } => panic!("unnötige Abfrage: {message}"),
                Status::HostKey { .. } => session.conn().answer_host_key(true),
                _ => {}
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Geänderter Host-Key (anderer Schlüssel in known_hosts) muss abgelehnt werden.
    #[test]
    #[ignore]
    fn e2e_changed_host_key() {
        let port = e2e_port();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let known_hosts = home().join(".ssh/known_hosts");
        let saved = std::fs::read_to_string(&known_hosts).ok();
        let other_key = std::fs::read_to_string(home().join(".ssh/id_ed25519.pub")).unwrap();
        let fake = format!("[127.0.0.1]:{port} {}\n", other_key.split_whitespace().take(2).collect::<Vec<_>>().join(" "));
        std::fs::write(&known_hosts, fake).unwrap();

        let session = SshSession::start(runtime.handle(), egui::Context::default(), e2e_params(port));
        let deadline = Instant::now() + Duration::from_secs(10);
        let result = loop {
            match session.conn().status() {
                Status::Closed(msg) => break msg,
                Status::Connected | Status::HostKey { .. } => break "geänderter Key akzeptiert".into(),
                _ => {}
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(20));
        };
        match saved {
            Some(content) => std::fs::write(&known_hosts, content).unwrap(),
            None => std::fs::remove_file(&known_hosts).unwrap(),
        }
        assert!(result.contains("hat sich geändert"), "{result}");
    }
}
