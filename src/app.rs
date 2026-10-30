use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use eframe::egui::{self, Color32, RichText, Sense};
use zeroize::Zeroizing;

use crate::askpass;
use crate::crypto::Vault;
use crate::launcher;
use crate::model::{self, Connection, Credential, CredentialSource, DisplayProtocol, Folder, Node, Protocol, SecretField, Target};
use crate::rdp::{RdpParams, RdpSession, RdpView};
use crate::sftp::{SftpSessionHandle, SftpView};
use crate::ssh::{self, Conn, ConnectParams, SshSession};
use crate::i18n::{self, Language};
use crate::store::{self, Settings, StoreFile, Theme};
use crate::terminal::TerminalView;
use crate::vnc::{VncParams, VncSession, VncView};

const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(30);
const MIN_MASTER_LEN: usize = 8;
const ICONS: &[&str] = &["📁", "🏠", "🏢", "☁", "🧪", "⚡", "🔒", "🔑", "👤", "💻", "🖥", "🗄", "📺", "🌐", "🐧", "🔧", "🚀", "⭐"];

pub struct ConnMgrApp {
    path: PathBuf,
    state: State,
    status: String,
    clipboard: Option<arboard::Clipboard>,
    /// Zeitpunkt, zu dem ein kopiertes Passwort wieder aus der Zwischenablage entfernt wird.
    clipboard_secret: Option<(Instant, Zeroizing<String>)>,
    /// Liefert ssh/sftp das Passwort über SSH_ASKPASS; wird beim ersten Bedarf gestartet.
    askpass: Option<askpass::Server>,
    /// Führt die eingebetteten SSH-Sitzungen aus; wird beim ersten Bedarf gestartet.
    runtime: Option<tokio::runtime::Runtime>,
    /// Verbindung (ID, Name), auf die sich die Statuszeile bezieht; endet sie, wird die Zeile geleert.
    status_conn: Option<(String, String)>,
    /// Aktuelle Einstellungen; vor dem Entsperren aus der Datei gelesen.
    settings: Settings,
    applied_theme: Option<Theme>,
}

enum State {
    Locked(LockScreen),
    Unlocked(Box<Session>),
}

#[derive(Default)]
struct LockScreen {
    master: Zeroizing<String>,
    confirm: Zeroizing<String>,
    error: Option<String>,
    focused: bool,
}

struct Session {
    vault: Vault,
    store: StoreFile,
    filter: String,
    favorites_only: bool,
    selected: Option<String>,
    editor: Option<Editor>,
    /// Ausgeblendeter Baum gerade eingeblendet (nur wenn nicht fixiert) und wann er wieder verschwindet.
    tree_overlay: bool,
    tree_hide_at: Option<Instant>,
    /// Eingabe im Schnellverbindungsfeld.
    quick_input: String,
    /// Offene SSH-Sitzungen; beim Sperren werden sie mit der Session getrennt.
    tabs: Vec<Tab>,
    /// `None` = Eigenschaften-Tab.
    active_tab: Option<usize>,
    dialog: Option<Dialog>,
}

/// Modale Dialoge für Datei-Operationen.
enum Dialog {
    ChangeMaster { old: Zeroizing<String>, new: Zeroizing<String>, confirm: Zeroizing<String>, error: Option<String> },
    /// `scope = None` exportiert alles.
    Export { scope: Option<String>, password: Zeroizing<String>, confirm: Zeroizing<String>, error: Option<String> },
    Import { path: PathBuf, password: Zeroizing<String>, error: Option<String> },
    Delete { id: String, question: String, error: Option<String> },
    Settings,
}

/// Effektive Zugangsdaten einer Verbindung, entschlüsselt.
#[derive(Default)]
struct Effective {
    username: String,
    password: Option<Zeroizing<String>>,
    private_key: Option<Zeroizing<String>>,
    passphrase: Option<Zeroizing<String>>,
}

/// Ergebnis der Schlüsselprüfung im Editor; wird nur bei Änderungen neu berechnet,
/// weil das Entschlüsseln (bcrypt) teuer ist.
#[derive(Clone)]
enum KeyInfo {
    None,
    Valid { summary: String, public: String },
    Encrypted,
    Invalid(String),
}

fn inspect_key(pem: &str, passphrase: &str) -> KeyInfo {
    use russh::keys::{self, HashAlg};
    if pem.trim().is_empty() {
        return KeyInfo::None;
    }
    match keys::decode_secret_key(pem, Some(passphrase).filter(|p| !p.is_empty())) {
        Ok(key) => {
            let public = key.public_key();
            KeyInfo::Valid {
                summary: format!("{} · {}", public.algorithm(), public.fingerprint(HashAlg::Sha256)),
                public: public.to_openssh().unwrap_or_default(),
            }
        }
        Err(keys::Error::KeyIsEncrypted) => KeyInfo::Encrypted,
        Err(_) if !passphrase.is_empty() => KeyInfo::Invalid(t!("Passphrase falsch oder Schlüssel ungültig", "Wrong passphrase or invalid key")),
        Err(e) => KeyInfo::Invalid(e.to_string()),
    }
}

struct Tab {
    conn_id: String,
    title: String,
    tooltip: String,
    color: Option<Color32>,
    content: TabContent,
    /// Schnellverbindung ohne Eintrag im Baum; bleibt hier für Neuverbinden und Speichern.
    adhoc: Option<Connection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TabKind {
    Terminal,
    Sftp,
    Vnc,
    Rdp,
}

enum TabContent {
    Terminal { session: SshSession, view: TerminalView },
    Sftp { session: SftpSessionHandle, view: SftpView },
    Vnc { session: VncSession, view: VncView },
    Rdp { session: RdpSession, view: RdpView },
}

impl Tab {
    fn conn(&self) -> &Conn {
        match &self.content {
            TabContent::Terminal { session, .. } => session.conn(),
            TabContent::Sftp { session, .. } => session.conn(),
            TabContent::Vnc { session, .. } => session.conn(),
            TabContent::Rdp { session, .. } => session.conn(),
        }
    }

    fn kind(&self) -> TabKind {
        match self.content {
            TabContent::Terminal { .. } => TabKind::Terminal,
            TabContent::Sftp { .. } => TabKind::Sftp,
            TabContent::Vnc { .. } => TabKind::Vnc,
            TabContent::Rdp { .. } => TabKind::Rdp,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Folder,
    Connection,
    Credential,
}

/// Formular für einen Eintrag; `id == None` bedeutet neu anlegen.
struct Editor {
    id: Option<String>,
    /// Elternordner: Ziel beim Anlegen und Ausgangspunkt für geerbte Zugangsdaten.
    parent: Option<String>,
    name: String,
    icon: String,
    color: Option<[u8; 3]>,
    body: EditorBody,
}

enum EditorBody {
    Folder {
        credential_id: Option<String>,
    },
    Connection {
        host: String,
        port: String,
        protocol: Protocol,
        credentials: CredentialSource,
        username: String,
        password: Zeroizing<String>,
        show_password: bool,
        favorite: bool,
        /// Horizon: Desktop/App und Anzeigeprotokoll.
        resource: String,
        display_protocol: Option<DisplayProtocol>,
    },
    Credential {
        username: String,
        password: Zeroizing<String>,
        show_password: bool,
        private_key: Zeroizing<String>,
        passphrase: Zeroizing<String>,
        show_key: bool,
        /// Hash von Schlüssel und Passphrase zum zuletzt geprüften Ergebnis.
        key_info: Option<(u64, KeyInfo)>,
    },
}

impl Editor {
    fn new(kind: Kind, parent: Option<String>) -> Self {
        let body = match kind {
            Kind::Folder => EditorBody::Folder { credential_id: None },
            Kind::Connection => EditorBody::Connection {
                host: String::new(),
                port: Protocol::Ssh.default_port().to_string(),
                protocol: Protocol::Ssh,
                // In einem Ordner ist Erben der naheliegende Standard.
                credentials: if parent.is_some() { CredentialSource::Inherit } else { CredentialSource::Own },
                username: String::new(),
                password: Zeroizing::default(),
                show_password: false,
                favorite: false,
                resource: String::new(),
                display_protocol: None,
            },
            Kind::Credential => EditorBody::Credential {
                username: String::new(),
                password: Zeroizing::default(),
                show_password: false,
                private_key: Zeroizing::default(),
                passphrase: Zeroizing::default(),
                show_key: false,
                key_info: None,
            },
        };
        Self { id: None, parent, name: String::new(), icon: String::new(), color: None, body }
    }

    fn load(s: &Session, id: &str) -> Result<Self> {
        let node = model::find(&s.store.items, id).ok_or_else(|| anyhow!(t!("Eintrag nicht gefunden", "Entry not found")))?;
        let (icon, color, body) = match node {
            Node::Folder(f) => (&f.icon, &f.color, EditorBody::Folder { credential_id: f.credential_id.clone() }),
            Node::Connection(c) => (
                &c.icon,
                &c.color,
                EditorBody::Connection {
                    host: c.host.clone(),
                    port: c.port.to_string(),
                    protocol: c.protocol,
                    credentials: c.credentials.clone(),
                    username: c.username.clone(),
                    password: store::decrypt_secret(&s.vault, &c.id, c.password.as_ref())?.unwrap_or_default(),
                    show_password: false,
                    favorite: c.favorite,
                    resource: c.resource.clone(),
                    display_protocol: c.display_protocol,
                },
            ),
            Node::Credential(c) => (
                &c.icon,
                &c.color,
                EditorBody::Credential {
                    username: c.username.clone(),
                    password: store::decrypt_secret(&s.vault, &c.id, c.password.as_ref())?.unwrap_or_default(),
                    show_password: false,
                    private_key: store::decrypt_field(&s.vault, &c.id, SecretField::PrivateKey, c.private_key.as_ref())?
                        .unwrap_or_default(),
                    passphrase: store::decrypt_field(&s.vault, &c.id, SecretField::Passphrase, c.passphrase.as_ref())?
                        .unwrap_or_default(),
                    show_key: false,
                    key_info: None,
                },
            ),
        };
        Ok(Self {
            id: Some(id.to_owned()),
            parent: model::parent_id(&s.store.items, id),
            name: node.name().to_owned(),
            icon: icon.clone().unwrap_or_default(),
            color: color.as_deref().and_then(model::parse_color),
            body,
        })
    }

    fn kind(&self) -> Kind {
        match self.body {
            EditorBody::Folder { .. } => Kind::Folder,
            EditorBody::Connection { .. } => Kind::Connection,
            EditorBody::Credential { .. } => Kind::Credential,
        }
    }
}

enum Action {
    Unlock,
    Lock,
    New(Kind, Option<String>),
    Select(String),
    Save,
    AskDelete(String),
    Connect(String),
    /// SSH im Terminal des Betriebssystems statt im Tab.
    ConnectExternal(String),
    /// Auswählen und zum Eigenschaften-Tab wechseln.
    Edit(String),
    CopyPassword(String),
    ActivateTab(Option<usize>),
    CloseTab(usize),
    /// Alle Sitzungs-Tabs außer diesem schließen.
    CloseOtherTabs(usize),
    CloseAllTabs,
    Reconnect(usize),
    /// SFTP-Browser für eine SSH-Verbindung.
    OpenSftp(String),
    CloseProperties,
    /// Zusätzliche Sitzung, auch wenn schon ein Tab für die Verbindung offen ist.
    ConnectNew(String),
    /// Schnellverbindung zu einer eingetippten Adresse.
    QuickConnect(String),
    /// Schnellverbindung des Tabs als Eintrag im Baum speichern.
    SaveAdhoc(usize),
    ToggleTreePin,
    /// `None` = Sprache des Betriebssystems.
    SetLanguage(Option<Language>),
    SetTheme(Theme),
    OpenDialog(Dialog),
    CloseDialog,
    /// Führt den offenen Dialog aus.
    SubmitDialog,
    ToggleExpanded(String),
    ToggleFavorite(String),
    Move(String, Target),
    Duplicate(String),
}

fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

impl ConnMgrApp {
    pub fn new(path: PathBuf) -> Self {
        let settings = Settings::read(&path).unwrap_or_default();
        i18n::set_language(settings.effective_language());
        Self {
            settings,
            applied_theme: None,
            path,
            state: State::Locked(LockScreen::default()),
            status: String::new(),
            clipboard: None,
            clipboard_secret: None,
            askpass: None,
            runtime: None,
            status_conn: None,
        }
    }

    fn handle(&mut self, ctx: &egui::Context, action: Action) {
        let result = match action {
            Action::Unlock => self.unlock(),
            Action::Lock => {
                self.state = State::Locked(LockScreen::default());
                self.status = t!("Gesperrt", "Locked");
                Ok(())
            }
            Action::Connect(id) if self.focus_open_tab(&id) => Ok(()),
            Action::Connect(id) | Action::ConnectNew(id) => match self.session().ok().and_then(|s| model::find_connection(&s.store.items, &id)) {
                Some(c) if c.protocol == Protocol::Ssh => self.open_tab(ctx, &id, TabKind::Terminal, None),
                Some(c) if c.protocol == Protocol::Sftp => self.open_tab(ctx, &id, TabKind::Sftp, None),
                Some(c) if c.protocol == Protocol::Vnc => self.open_tab(ctx, &id, TabKind::Vnc, None),
                Some(c) if c.protocol == Protocol::Rdp => self.open_tab(ctx, &id, TabKind::Rdp, None),
                _ => self.connect(&id),
            },
            Action::ConnectExternal(id) => self.connect(&id),
            Action::OpenSftp(id) => self.open_tab(ctx, &id, TabKind::Sftp, None),
            Action::QuickConnect(input) => self.quick_connect(ctx, &input),
            Action::Reconnect(index) => match &self.state {
                State::Unlocked(s) => match s.tabs.get(index) {
                    Some(tab) => match tab.adhoc.clone() {
                        Some(conn) => self.open_adhoc_tab(ctx, conn, Some(index)),
                        None => {
                            let (id, kind) = (tab.conn_id.clone(), tab.kind());
                            self.open_tab(ctx, &id, kind, Some(index))
                        }
                    },
                    None => Ok(()),
                },
                State::Locked(_) => Ok(()),
            },
            Action::CopyPassword(id) => self.copy_password(&id),
            other => {
                let State::Unlocked(session) = &mut self.state else { return };
                session.apply(other, &self.path).map(|msg| {
                    if let Some(msg) = msg {
                        self.status = msg;
                    }
                })
            }
        };
        if let Err(e) = result {
            self.status = t!("Fehler: {e}", "Error: {e}");
        }
    }

    fn unlock(&mut self) -> Result<()> {
        let State::Locked(lock) = &mut self.state else { return Ok(()) };
        let outcome = if self.path.exists() {
            StoreFile::load(&self.path).and_then(|store| store.unlock(&lock.master).map(|vault| (store, vault)))
        } else if lock.master.chars().count() < MIN_MASTER_LEN {
            Err(anyhow!(t!("Das Master-Passwort muss mindestens {MIN_MASTER_LEN} Zeichen lang sein", "The master password must be at least {MIN_MASTER_LEN} characters long")))
        } else if *lock.master != *lock.confirm {
            Err(anyhow!(t!("Die Passwörter stimmen nicht überein", "The passwords do not match")))
        } else {
            StoreFile::create(&lock.master).and_then(|(mut store, vault)| {
                store.settings = self.settings.clone();
                store.save(&self.path).map(|()| (store, vault))
            })
        };
        match outcome {
            Ok((store, vault)) => {
                self.status = t!("Entsperrt", "Unlocked");
                self.state = State::Unlocked(Box::new(Session {
                    vault,
                    store,
                    filter: String::new(),
                    favorites_only: false,
                    selected: None,
                    editor: None,
                    tree_overlay: false,
                    tree_hide_at: None,
                    quick_input: String::new(),
                    tabs: Vec::new(),
                    active_tab: None,
                    dialog: None,
                }));
            }
            Err(e) => {
                lock.error = Some(e.to_string());
                lock.master.clear();
                lock.confirm.clear();
                lock.focused = false;
            }
        }
        Ok(())
    }

    fn session(&self) -> Result<&Session> {
        match &self.state {
            State::Unlocked(s) => Ok(s),
            State::Locked(_) => Err(anyhow!(t!("Gesperrt", "Locked"))),
        }
    }

    fn connect(&mut self, id: &str) -> Result<()> {
        let session = self.session()?;
        let conn = model::find_connection(&session.store.items, id).ok_or_else(|| anyhow!(t!("Verbindung nicht gefunden", "Connection not found")))?.clone();
        let Effective { username, password, .. } = session.credentials_for(&conn)?;
        let ssh_env = match (&password, conn.protocol) {
            (Some(pw), Protocol::Ssh | Protocol::Sftp) => self.askpass()?.issue(pw.clone())?,
            _ => Vec::new(),
        };
        let launched = launcher::launch(&conn, &username, password.as_deref().map(String::as_str), &ssh_env)?;
        self.status = format!("{}: {}", conn.name, launched.info);
        if let (Some(pw), false) = (password, launched.password_consumed) {
            self.copy_secret(pw)?;
            self.status.push_str(&t!(" — Passwort für {}s in der Zwischenablage", " — password in clipboard for {}s", CLIPBOARD_CLEAR_AFTER.as_secs()));
        }
        Ok(())
    }

    /// Öffnet eine eingebettete Sitzung in einem neuen Tab oder ersetzt die in `replace`.
    fn open_tab(&mut self, ctx: &egui::Context, id: &str, kind: TabKind, replace: Option<usize>) -> Result<()> {
        let State::Unlocked(session) = &self.state else { bail!(t!("Gesperrt", "Locked")) };
        let node = model::find(&session.store.items, id).ok_or_else(|| anyhow!(t!("Verbindung nicht gefunden", "Connection not found")))?;
        let Node::Connection(conn) = node else { bail!(t!("Kein Verbindungseintrag", "Not a connection")) };
        let credentials = session.credentials_for(conn)?;
        let look = (node.icon().to_owned(), node.color().and_then(model::parse_color).map(|[r, g, b]| Color32::from_rgb(r, g, b)));
        let conn = conn.clone();
        self.start_tab(ctx, conn, credentials, kind, look, None, replace)
    }

    /// Schnellverbindung: Adresse verstehen, Tab öffnen, Eingabe für den Verlauf merken.
    fn quick_connect(&mut self, ctx: &egui::Context, input: &str) -> Result<()> {
        let target = model::parse_quick(input).map_err(|e| anyhow!(e))?;
        let conn = Connection {
            id: format!("quick:{}", new_id()),
            name: input.trim().trim_end_matches('/').to_owned(),
            host: target.host,
            port: target.port,
            protocol: target.protocol,
            credentials: CredentialSource::Own,
            username: target.username,
            password: None,
            icon: None,
            color: None,
            favorite: false,
            resource: target.resource,
            display_protocol: None,
        };
        if conn.protocol == Protocol::Horizon {
            // Horizon läuft im eigenen Client; kein Tab.
            let launched = launcher::launch(&conn, &conn.username, None, &[])?;
            self.status = format!("{}: {}", conn.name, launched.info);
        } else {
            self.open_adhoc_tab(ctx, conn, None)?;
        }
        if let State::Unlocked(session) = &mut self.state {
            session.store.settings.remember_quick(input.trim());
            session.store.save(&self.path)?;
        }
        Ok(())
    }

    fn open_adhoc_tab(&mut self, ctx: &egui::Context, conn: Connection, replace: Option<usize>) -> Result<()> {
        let kind = match conn.protocol {
            Protocol::Ssh => TabKind::Terminal,
            Protocol::Sftp => TabKind::Sftp,
            Protocol::Rdp => TabKind::Rdp,
            Protocol::Vnc => TabKind::Vnc,
            Protocol::Horizon => bail!(t!("Horizon läuft im Horizon Client, nicht im Tab", "Horizon runs in the Horizon Client, not in a tab")),
        };
        // Fehlende Angaben (Passwort, bei RDP auch der Benutzer) fragt der Tab ab.
        let credentials = Effective { username: conn.username.clone(), ..Effective::default() };
        self.start_tab(ctx, conn.clone(), credentials, kind, ("⚡".to_owned(), None), Some(conn), replace)
    }

    #[allow(clippy::too_many_arguments)]
    fn start_tab(
        &mut self,
        ctx: &egui::Context,
        conn: Connection,
        credentials: Effective,
        kind: TabKind,
        (icon, color): (String, Option<Color32>),
        adhoc: Option<Connection>,
        replace: Option<usize>,
    ) -> Result<()> {
        let runtime = self.runtime()?.handle().clone();
        let State::Unlocked(session) = &mut self.state else { bail!(t!("Gesperrt", "Locked")) };
        let Effective { username, password, private_key, passphrase } = credentials;
        model::validate_host(&conn.host).map_err(|e| anyhow!(e))?;
        model::validate_username(&username).map_err(|e| anyhow!(e))?;

        let tooltip = if username.is_empty() { conn.host_port() } else { format!("{username}@{}", conn.host_port()) };
        let params = ConnectParams { host: conn.host.clone(), port: conn.port, username, password, private_key, passphrase };
        let (title, content) = match kind {
            TabKind::Terminal => (
                format!("{icon}  {}", conn.name),
                TabContent::Terminal { session: SshSession::start(&runtime, ctx.clone(), params), view: TerminalView::default() },
            ),
            TabKind::Sftp => (
                format!("📂  {}", conn.name),
                TabContent::Sftp { session: SftpSessionHandle::start(&runtime, ctx.clone(), params), view: SftpView::default() },
            ),
            TabKind::Rdp => {
                let params = RdpParams { host: params.host, port: params.port, username: params.username, password: params.password };
                (
                    format!("{icon}  {}", conn.name),
                    TabContent::Rdp { session: RdpSession::start(&runtime, ctx.clone(), params), view: RdpView::default() },
                )
            }
            TabKind::Vnc => {
                let params = VncParams { host: params.host, port: params.port, password: params.password };
                (
                    format!("{icon}  {}", conn.name),
                    TabContent::Vnc { session: VncSession::start(&runtime, ctx.clone(), params), view: VncView::default() },
                )
            }
        };
        let tab = Tab { conn_id: conn.id.clone(), title, tooltip, color, content, adhoc };
        self.status = t!("{}: verbinde …", "{}: connecting …", conn.name);
        self.status_conn = Some((conn.id.clone(), conn.name.clone()));
        let index = match replace {
            Some(i) if i < session.tabs.len() => {
                session.tabs[i] = tab;
                i
            }
            _ => {
                session.tabs.push(tab);
                session.tabs.len() - 1
            }
        };
        session.active_tab = Some(index);
        Ok(())
    }

    /// Wechselt zum offenen Tab dieser Verbindung, falls es einen gibt, und markiert sie im Baum.
    fn focus_open_tab(&mut self, id: &str) -> bool {
        let State::Unlocked(session) = &mut self.state else { return false };
        session.mark(id);
        let open = session.tabs.iter().position(|t| t.conn_id == id && !matches!(t.conn().status(), ssh::Status::Closed(_)));
        if let Some(index) = open {
            session.active_tab = Some(index);
        }
        open.is_some()
    }

    /// Sprache und Design aus den Einstellungen übernehmen (nach dem Entsperren aus der Datei).
    fn apply_settings(&mut self, ctx: &egui::Context) {
        if let State::Unlocked(session) = &self.state {
            self.settings = session.store.settings.clone();
        }
        i18n::set_language(self.settings.effective_language());
        if self.applied_theme != Some(self.settings.theme) {
            ctx.set_theme(self.settings.theme.preference());
            self.applied_theme = Some(self.settings.theme);
        }
    }

    /// Statuszeile an den Zustand der zuletzt gestarteten Verbindung anpassen.
    fn refresh_status(&mut self) {
        let (State::Unlocked(session), Some((id, name))) = (&self.state, &self.status_conn) else { return };
        let states: Vec<_> = session.tabs.iter().filter(|t| &t.conn_id == id).map(|t| t.conn().status()).collect();
        if states.iter().any(|s| matches!(s, ssh::Status::Connected)) {
            self.status = t!("{name}: verbunden", "{name}: connected");
        } else if states.iter().all(|s| matches!(s, ssh::Status::Closed(_))) {
            // Tab geschlossen oder Verbindung beendet: Meldung steht im Tab selbst.
            self.status.clear();
            self.status_conn = None;
        }
    }

    fn runtime(&mut self) -> Result<&tokio::runtime::Runtime> {
        if self.runtime.is_none() {
            let runtime =
                tokio::runtime::Builder::new_multi_thread().worker_threads(2).thread_name("connmgr-ssh").enable_all().build()?;
            self.runtime = Some(runtime);
        }
        Ok(self.runtime.as_ref().expect("gerade gestartet"))
    }

    fn askpass(&mut self) -> Result<&askpass::Server> {
        if self.askpass.is_none() {
            self.askpass = Some(askpass::Server::start()?);
        }
        Ok(self.askpass.as_ref().expect("gerade gestartet"))
    }

    fn copy_password(&mut self, id: &str) -> Result<()> {
        let session = self.session()?;
        let password = match model::find(&session.store.items, id) {
            Some(Node::Connection(c)) => session.credentials_for(c)?.password,
            Some(Node::Credential(c)) => store::decrypt_secret(&session.vault, &c.id, c.password.as_ref())?,
            _ => bail!(t!("Eintrag hat kein Passwort", "Entry has no password")),
        };
        match password {
            Some(pw) => {
                self.copy_secret(pw)?;
                self.status = t!("Passwort für {}s in der Zwischenablage", "Password in clipboard for {}s", CLIPBOARD_CLEAR_AFTER.as_secs());
            }
            None => self.status = t!("Kein Passwort hinterlegt", "No password stored"),
        }
        Ok(())
    }

    fn copy_secret(&mut self, secret: Zeroizing<String>) -> Result<()> {
        if self.clipboard.is_none() {
            self.clipboard = Some(arboard::Clipboard::new()?);
        }
        if let Some(cb) = &mut self.clipboard {
            cb.set_text(secret.as_str())?;
        }
        self.clipboard_secret = Some((Instant::now() + CLIPBOARD_CLEAR_AFTER, secret));
        Ok(())
    }

    /// Leert die Zwischenablage nur, wenn sie noch unser Passwort enthält.
    fn clear_clipboard_secret(&mut self) {
        if let (Some((_, secret)), Some(cb)) = (self.clipboard_secret.take(), &mut self.clipboard) {
            if cb.get_text().ok().as_deref() == Some(secret.as_str()) {
                let _ = cb.clear();
            }
        }
    }

    fn expire_clipboard(&mut self, ctx: &egui::Context) {
        if let Some((deadline, _)) = &self.clipboard_secret {
            let now = Instant::now();
            if now >= *deadline {
                self.clear_clipboard_secret();
            } else {
                ctx.request_repaint_after(*deadline - now);
            }
        }
    }
}

impl Drop for ConnMgrApp {
    fn drop(&mut self) {
        self.clear_clipboard_secret();
    }
}

impl Session {
    /// Führt eine Aktion am Baum aus; liefert ggf. eine Statusmeldung.
    fn apply(&mut self, action: Action, path: &Path) -> Result<Option<String>> {
        match action {
            Action::New(kind, parent) => {
                self.editor = Some(Editor::new(kind, parent));
                self.selected = None;
                self.active_tab = None;
                Ok(None)
            }
            Action::Edit(id) => {
                self.open_properties(&id)?;
                self.active_tab = None;
                Ok(None)
            }
            Action::CloseProperties => {
                self.editor = None;
                if self.active_tab.is_none() && !self.tabs.is_empty() {
                    self.active_tab = Some(self.tabs.len() - 1);
                }
                Ok(None)
            }
            Action::ActivateTab(index) => {
                self.active_tab = index.filter(|&i| i < self.tabs.len());
                Ok(None)
            }
            Action::CloseTab(index) => {
                if index < self.tabs.len() {
                    self.tabs.remove(index);
                    self.active_tab = match self.active_tab {
                        Some(a) if a == index => (!self.tabs.is_empty()).then(|| index.min(self.tabs.len() - 1)),
                        Some(a) if a > index => Some(a - 1),
                        other => other,
                    };
                }
                Ok(None)
            }
            Action::CloseOtherTabs(index) => {
                if index < self.tabs.len() {
                    let keep = self.tabs.swap_remove(index);
                    self.tabs = vec![keep];
                    if self.active_tab.is_some() {
                        self.active_tab = Some(0);
                    }
                }
                Ok(None)
            }
            Action::CloseAllTabs => {
                let count = self.tabs.len();
                self.tabs.clear();
                self.active_tab = None;
                Ok(Some(t!("{count} Verbindungen geschlossen", "Closed {count} connections")))
            }
            Action::Select(id) => {
                self.mark(&id);
                Ok(None)
            }
            Action::Save => self.save(path).map(Some),
            Action::AskDelete(id) => {
                if model::find(&self.store.items, &id).is_some() {
                    let question = delete_question(&self.store.items, &id);
                    self.dialog = Some(Dialog::Delete { id, question, error: None });
                }
                Ok(None)
            }
            Action::SetLanguage(language) => {
                self.store.settings.language = language;
                self.store.save(path)?;
                Ok(None)
            }
            Action::SetTheme(theme) => {
                self.store.settings.theme = theme;
                self.store.save(path)?;
                Ok(None)
            }
            Action::SaveAdhoc(index) => {
                let parent = self.default_parent();
                let Some(tab) = self.tabs.get_mut(index) else { return Ok(None) };
                let Some(mut conn) = tab.adhoc.take() else { return Ok(None) };
                conn.id = new_id();
                tab.conn_id = conn.id.clone();
                tab.title = format!("{}  {}", conn.protocol.default_icon(), conn.name);
                let name = conn.name.clone();
                let id = conn.id.clone();
                let target = parent.map_or(Target::Root, Target::Into);
                if let Err(node) = model::insert(&mut self.store.items, &target, Node::Connection(conn)) {
                    self.store.items.push(node);
                }
                self.store.save(path)?;
                self.mark(&id);
                Ok(Some(t!("„{name}“ gespeichert", "\"{name}\" saved")))
            }
            Action::ToggleTreePin => {
                self.store.settings.tree_pinned = !self.store.settings.tree_pinned;
                self.tree_overlay = false;
                self.store.save(path)?;
                Ok(None)
            }
            Action::ToggleExpanded(id) => {
                if let Some(Node::Folder(f)) = model::find_mut(&mut self.store.items, &id) {
                    f.expanded = !f.expanded;
                }
                self.store.save(path)?;
                Ok(None)
            }
            Action::ToggleFavorite(id) => {
                if let Some(Node::Connection(c)) = model::find_mut(&mut self.store.items, &id) {
                    c.favorite = !c.favorite;
                    if let Some(Editor { id: Some(eid), body: EditorBody::Connection { favorite, .. }, .. }) = &mut self.editor {
                        if *eid == id {
                            *favorite = c.favorite;
                        }
                    }
                }
                self.store.save(path)?;
                Ok(None)
            }
            Action::Move(id, target) => {
                model::move_node(&mut self.store.items, &id, &target).map_err(|e| anyhow!(e))?;
                self.store.save(path)?;
                if let Some(ed) = &mut self.editor {
                    if ed.id.as_deref() == Some(id.as_str()) {
                        ed.parent = model::parent_id(&self.store.items, &id);
                    }
                }
                Ok(Some(t!("Verschoben", "Moved")))
            }
            Action::Duplicate(id) => self.duplicate(&id, path).map(Some),
            Action::OpenDialog(dialog) => {
                self.dialog = Some(dialog);
                Ok(None)
            }
            Action::CloseDialog => {
                self.dialog = None;
                Ok(None)
            }
            Action::SubmitDialog => self.submit_dialog(path),
            Action::Unlock
            | Action::Lock
            | Action::Connect(_)
            | Action::ConnectExternal(_)
            | Action::Reconnect(_)
            | Action::OpenSftp(_)
            | Action::QuickConnect(_)
            | Action::ConnectNew(_)
            | Action::CopyPassword(_) => Ok(None),
        }
    }

    /// Lädt den Eintrag in den Eigenschaften-Tab.
    fn open_properties(&mut self, id: &str) -> Result<()> {
        self.editor = Some(Editor::load(self, id)?);
        self.selected = Some(id.to_owned());
        Ok(())
    }

    /// Markiert den Eintrag im Baum, ohne die Eigenschaften zu öffnen.
    fn mark(&mut self, id: &str) {
        self.selected = Some(id.to_owned());
    }

    fn credentials_for(&self, conn: &Connection) -> Result<Effective> {
        let Some(r) = model::resolve(&self.store.items, conn).map_err(|e| anyhow!(e))? else {
            return Ok(Effective::default());
        };
        let decrypt = |field, enc| store::decrypt_field(&self.vault, r.owner_id, field, enc);
        Ok(Effective {
            username: r.username.to_owned(),
            password: decrypt(SecretField::Password, r.password)?,
            private_key: decrypt(SecretField::PrivateKey, r.private_key)?,
            passphrase: decrypt(SecretField::Passphrase, r.passphrase)?,
        })
    }

    fn save(&mut self, path: &Path) -> Result<String> {
        let ed = self.editor.as_mut().ok_or_else(|| anyhow!(t!("Kein Eintrag geöffnet", "No entry open")))?;
        let name = ed.name.trim().to_owned();
        if name.is_empty() {
            bail!(t!("Name darf nicht leer sein", "Name must not be empty"));
        }
        let id = ed.id.clone().unwrap_or_else(new_id);
        let icon = Some(ed.icon.trim().to_owned()).filter(|s| !s.is_empty());
        let color = ed.color.map(model::format_color);

        let node = match &ed.body {
            EditorBody::Folder { credential_id } => {
                let (expanded, children) = match model::find(&self.store.items, &id) {
                    Some(Node::Folder(f)) => (f.expanded, f.children.clone()),
                    _ => (true, Vec::new()),
                };
                Node::Folder(Folder {
                    id: id.clone(),
                    name: name.clone(),
                    icon,
                    color,
                    credential_id: credential_id.clone(),
                    expanded,
                    children,
                })
            }
            EditorBody::Connection { host, port, protocol, credentials, username, password, favorite, resource, display_protocol, .. } => {
                let host = host.trim().to_owned();
                model::validate_host(&host).map_err(|e| anyhow!(e))?;
                let port: u16 = match port.trim().parse() {
                    Ok(p) if p > 0 => p,
                    _ => bail!(t!("Ungültiger Port: {port}", "Invalid port: {port}")),
                };
                // Eigene Zugangsdaten nur speichern, wenn sie auch verwendet werden.
                let own = *credentials == CredentialSource::Own;
                let username = if own { username.trim().to_owned() } else { String::new() };
                model::validate_username(&username).map_err(|e| anyhow!(e))?;
                let password = if own { store::encrypt_secret(&self.vault, &id, password)? } else { None };
                Node::Connection(Connection {
                    id: id.clone(),
                    name: name.clone(),
                    host,
                    port,
                    protocol: *protocol,
                    credentials: credentials.clone(),
                    username,
                    password,
                    icon,
                    color,
                    favorite: *favorite,
                    resource: if *protocol == Protocol::Horizon { resource.trim().to_owned() } else { String::new() },
                    display_protocol: if *protocol == Protocol::Horizon { *display_protocol } else { None },
                })
            }
            EditorBody::Credential { username, password, private_key, passphrase, .. } => {
                let username = username.trim().to_owned();
                model::validate_username(&username).map_err(|e| anyhow!(e))?;
                if let KeyInfo::Invalid(e) = inspect_key(private_key, passphrase) {
                    bail!(t!("SSH-Schlüssel: {e}", "SSH key: {e}"));
                }
                let mut key = private_key.trim().to_owned();
                if !key.is_empty() {
                    key.push('\n');
                }
                Node::Credential(Credential {
                    id: id.clone(),
                    name: name.clone(),
                    username,
                    password: store::encrypt_field(&self.vault, &id, SecretField::Password, password)?,
                    private_key: store::encrypt_field(&self.vault, &id, SecretField::PrivateKey, &Zeroizing::new(key))?,
                    passphrase: store::encrypt_field(&self.vault, &id, SecretField::Passphrase, passphrase)?,
                    icon,
                    color,
                })
            }
        };

        match model::find_mut(&mut self.store.items, &id) {
            Some(existing) => *existing = node,
            None => {
                let target = ed.parent.clone().map_or(Target::Root, Target::Into);
                if let Err(node) = model::insert(&mut self.store.items, &target, node) {
                    self.store.items.push(node);
                }
            }
        }
        self.store.save(path)?;
        ed.id = Some(id.clone());
        self.selected = Some(id);
        Ok(t!("„{name}“ gespeichert", "\"{name}\" saved"))
    }

    fn delete(&mut self, id: &str, path: &Path) -> Result<String> {
        let removed = model::remove(&mut self.store.items, id).ok_or_else(|| anyhow!(t!("Eintrag nicht gefunden", "Entry not found")))?;
        // Auch Zugangsdaten innerhalb eines gelöschten Ordners können anderswo verwendet werden.
        for cred in model::credentials(std::slice::from_ref(&removed)) {
            model::clear_credential_references(&mut self.store.items, &cred.id);
        }
        self.store.save(path)?;
        // Eigenschaften nur schließen, wenn sie den gelöschten Eintrag (oder etwas darin) zeigen.
        if self.editor.as_ref().and_then(|ed| ed.id.as_deref()).is_some_and(|eid| model::contains(&removed, eid)) {
            self.editor = None;
        }
        self.selected = None;
        Ok(t!("„{}“ gelöscht", "\"{}\" deleted", removed.name()))
    }

    /// Kopiert einen Eintrag samt Inhalt; Geheimnisse werden für die neuen IDs neu verschlüsselt.
    fn duplicate(&mut self, id: &str, path: &Path) -> Result<String> {
        let node = model::find(&self.store.items, id).ok_or_else(|| anyhow!(t!("Eintrag nicht gefunden", "Entry not found")))?;
        let mut copy = store::copy_subtree(node, &self.vault, &self.vault)?;
        let name = t!("{} (Kopie)", "{} (copy)", copy.name());
        *copy.name_mut() = name.clone();
        let copy_id = copy.id().to_owned();
        if let Err(copy) = model::insert(&mut self.store.items, &Target::After(id.to_owned()), copy) {
            self.store.items.push(copy);
        }
        self.store.save(path)?;
        self.mark(&copy_id);
        Ok(t!("„{name}“ angelegt", "\"{name}\" created"))
    }

    fn submit_dialog(&mut self, path: &Path) -> Result<Option<String>> {
        let Some(dialog) = &mut self.dialog else { return Ok(None) };
        let outcome = match dialog {
            // Einstellungen wirken sofort; hier gibt es nichts abzuschicken.
            Dialog::Settings => Ok(String::new()),
            Dialog::ChangeMaster { old, new, confirm, .. } => {
                if self.store.unlock(old).is_err() {
                    Err(anyhow!(t!("Das bisherige Master-Passwort ist falsch", "The current master password is wrong")))
                } else if new.chars().count() < MIN_MASTER_LEN {
                    Err(anyhow!(t!("Das neue Master-Passwort muss mindestens {MIN_MASTER_LEN} Zeichen lang sein", "The new master password must be at least {MIN_MASTER_LEN} characters long")))
                } else if **new != **confirm {
                    Err(anyhow!(t!("Die neuen Passwörter stimmen nicht überein", "The new passwords do not match")))
                } else {
                    let mut store = self.store.clone();
                    store.change_master(&self.vault, new).and_then(|vault| {
                        store.save(path)?;
                        self.store = store;
                        self.vault = vault;
                        Ok(t!("Master-Passwort geändert", "Master password changed"))
                    })
                }
            }
            Dialog::Export { scope, password, confirm, .. } => {
                let nodes: Vec<Node> = match scope {
                    Some(id) => model::find(&self.store.items, id).cloned().into_iter().collect(),
                    None => self.store.items.clone(),
                };
                if password.chars().count() < MIN_MASTER_LEN {
                    Err(anyhow!(t!("Das Export-Passwort muss mindestens {MIN_MASTER_LEN} Zeichen lang sein", "The export password must be at least {MIN_MASTER_LEN} characters long")))
                } else if **password != **confirm {
                    Err(anyhow!(t!("Die Passwörter stimmen nicht überein", "The passwords do not match")))
                } else {
                    let default_name = match nodes.as_slice() {
                        [single] if scope.is_some() => format!("{}.connmgr.json", single.name()),
                        _ => "connmgr-export.connmgr.json".to_owned(),
                    };
                    match rfd::FileDialog::new().set_file_name(default_name).add_filter("ConnMgr", &["json"]).save_file() {
                        None => return Ok(None),
                        Some(target) => StoreFile::export(&nodes, &self.vault, password, &target)
                            .map(|()| t!("{} Einträge nach {} exportiert", "Exported {} entries to {}", nodes.iter().map(model::count).sum::<usize>(), target.display())),
                    }
                }
            }
            Dialog::Delete { id, .. } => {
                let id = id.clone();
                // Offene Tabs dieses Eintrags bleiben verbunden; sie verweisen nur nicht mehr auf den Baum.
                self.delete(&id, path)
            }
            Dialog::Import { path: source, password, .. } => StoreFile::import(source, password, &self.vault).and_then(|items| {
                let name = source.file_stem().map(|s| s.to_string_lossy().trim_end_matches(".connmgr").trim_end_matches(".conmgr").to_owned()).unwrap_or_default();
                let count: usize = items.iter().map(model::count).sum();
                let folder = Node::Folder(Folder {
                    id: new_id(),
                    name: t!("Import {name}", "Import {name}"),
                    icon: None,
                    color: None,
                    credential_id: None,
                    expanded: true,
                    children: items,
                });
                self.store.items.push(folder);
                model::drop_dangling_references(&mut self.store.items);
                self.store.save(path)?;
                Ok(t!("{count} Einträge importiert", "Imported {count} entries"))
            }),
        };
        match outcome {
            Ok(message) => {
                self.dialog = None;
                Ok(Some(message))
            }
            Err(e) => {
                if let Some(
                    Dialog::ChangeMaster { error, .. }
                    | Dialog::Export { error, .. }
                    | Dialog::Import { error, .. }
                    | Dialog::Delete { error, .. },
                ) = &mut self.dialog
                {
                    *error = Some(e.to_string());
                }
                Ok(None)
            }
        }
    }

    /// Zielordner für neue Einträge: der ausgewählte Ordner bzw. der Ordner des ausgewählten Eintrags.
    fn default_parent(&self) -> Option<String> {
        let sel = self.selected.as_deref()?;
        match model::find(&self.store.items, sel)? {
            Node::Folder(f) => Some(f.id.clone()),
            _ => model::parent_id(&self.store.items, sel),
        }
    }
}

impl eframe::App for ConnMgrApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.expire_clipboard(ctx);
        self.apply_settings(ctx);
        self.refresh_status();
        let action = match &mut self.state {
            State::Locked(lock) => lock_ui(ctx, lock, !self.path.exists(), &self.path),
            State::Unlocked(session) => session_ui(ctx, session, &self.status, &self.path),
        };
        if let Some(action) = action {
            self.handle(ctx, action);
        }
    }
}

// ---------------------------------------------------------------- Sperrbildschirm

fn lock_ui(ctx: &egui::Context, lock: &mut LockScreen, new_file: bool, path: &Path) -> Option<Action> {
    let mut action = None;
    egui::CentralPanel::default().show(ctx, |ui| {
        ui.vertical_centered(|ui| {
            ui.add_space(80.0);
            ui.add(egui::Image::new(crate::LOGO).fit_to_exact_size(egui::vec2(96.0, 96.0)));
            ui.heading("ConnMgr");
            ui.add_space(8.0);
            ui.label(if new_file { ts!("Neue Verbindungsdatei — Master-Passwort festlegen", "New connection file — set a master password") } else { ts!("Master-Passwort eingeben", "Enter master password") });
            ui.add_space(12.0);

            let master = ui.add(
                egui::TextEdit::singleline(&mut *lock.master).password(true).hint_text(ts!("Master-Passwort", "Master password")).desired_width(260.0),
            );
            if !lock.focused {
                master.request_focus();
                lock.focused = true;
            }
            let mut submit = master.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if new_file {
                let confirm = ui.add(
                    egui::TextEdit::singleline(&mut *lock.confirm).password(true).hint_text(ts!("Wiederholen", "Repeat")).desired_width(260.0),
                );
                submit = confirm.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            }
            ui.add_space(8.0);
            if ui.button(if new_file { ts!("Anlegen", "Create") } else { ts!("Entsperren", "Unlock") }).clicked() || submit {
                action = Some(Action::Unlock);
            }
            if let Some(err) = &lock.error {
                ui.add_space(8.0);
                ui.colored_label(ui.visuals().error_fg_color, err);
            }
            ui.add_space(24.0);
            ui.small(path.display().to_string());
        });
    });
    action
}

// ---------------------------------------------------------------- Hauptansicht

fn session_ui(ctx: &egui::Context, s: &mut Session, status: &str, path: &Path) -> Option<Action> {
    let mut action = None;

    // Im Terminal gehört Strg+S (XOFF) dem Server.
    if s.active_tab.is_none() && s.editor.is_some() && ctx.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::S)) {
        action = Some(Action::Save);
    }

    egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            // Menü ganz links, danach die Schnellverbindung, damit beides auch bei schmalem Fenster sichtbar bleibt.
            ui.menu_button("☰", |ui| {
                menu_item(ui, ts!("⚙ Einstellungen …", "⚙ Settings …"), &mut action, || Action::OpenDialog(Dialog::Settings));
                ui.separator();
                menu_item(ui, ts!("Master-Passwort ändern …", "Change master password …"), &mut action, || Action::OpenDialog(Dialog::change_master()));
                ui.separator();
                menu_item(ui, ts!("Alles exportieren …", "Export everything …"), &mut action, || Action::OpenDialog(Dialog::export(None)));
                if ui.button(ts!("Importieren …", "Import …")).clicked() {
                    ui.close_menu();
                    let picked = rfd::FileDialog::new().set_title(ts!("ConnMgr-Datei importieren", "Import ConnMgr file")).add_filter("ConnMgr", &["json"]).pick_file();
                    if let Some(path) = picked {
                        action = Some(Action::OpenDialog(Dialog::Import { path, password: Zeroizing::default(), error: None }));
                    }
                }
            });
            ui.separator();
            quick_connect_field(ui, s, &mut action);
            ui.separator();
            let parent = s.default_parent();
            if ui.button(ts!("➕ Verbindung", "➕ Connection")).clicked() {
                action = Some(Action::New(Kind::Connection, parent.clone()));
            }
            if ui.button(ts!("📁 Ordner", "📁 Folder")).clicked() {
                action = Some(Action::New(Kind::Folder, parent.clone()));
            }
            if ui.button(ts!("🔑 Zugangsdaten", "🔑 Credentials")).clicked() {
                action = Some(Action::New(Kind::Credential, parent));
            }
            ui.separator();
            ui.add(egui::TextEdit::singleline(&mut s.filter).hint_text(ts!("🔍 Suchen …", "🔍 Search …")).desired_width(150.0));
            ui.toggle_value(&mut s.favorites_only, ts!("⭐ Favoriten", "⭐ Favorites"));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button(ts!("🔒 Sperren", "🔒 Lock")).clicked() {
                    action = Some(Action::Lock);
                }
            });
        });
        ui.add_space(2.0);
    });

    egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
        ui.horizontal(|ui| {
            ui.label(status);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.small(path.display().to_string());
            });
        });
    });

    // Entf (bzw. ⌘⌫ auf dem Mac) löscht den markierten Eintrag, solange kein Eingabefeld oder Tab die Tastatur hat.
    let delete_key = ctx.input(|i| i.key_pressed(egui::Key::Delete) || (i.modifiers.command && i.key_pressed(egui::Key::Backspace)));
    if delete_key && !ctx.wants_keyboard_input() && s.dialog.is_none() {
        if let Some(id) = s.selected.clone() {
            action = Some(Action::AskDelete(id));
        }
    }

    if s.store.settings.tree_pinned {
        egui::SidePanel::left("tree").resizable(true).default_width(300.0).show(ctx, |ui| tree_ui(ui, s, &mut action));
    } else {
        tree_overlay(ctx, s, &mut action);
    }

    if !s.tabs.is_empty() || s.editor.is_some() {
        egui::TopBottomPanel::top("tabbar").show(ctx, |ui| {
            egui::ScrollArea::horizontal().show(ui, |ui| {
                ui.horizontal(|ui| tab_bar(ui, s, &mut action));
            });
        });
    }

    egui::CentralPanel::default().show(ctx, |ui| {
        if let Some(index) = s.active_tab {
            if let Some(tab) = s.tabs.get_mut(index) {
                let response = match &mut tab.content {
                    TabContent::Terminal { session, view } => view.show(ui, session),
                    TabContent::Sftp { session, view } => view.show(ui, session),
                    TabContent::Vnc { session, view } => view.show(ui, session),
                    TabContent::Rdp { session, view } => view.show(ui, session),
                };
                if response.reconnect {
                    action = Some(Action::Reconnect(index));
                }
                if response.close {
                    action = Some(Action::CloseTab(index));
                }
                return;
            }
        }
        let Some(ed) = &mut s.editor else {
            empty_background(ui);
            return;
        };
        egui::ScrollArea::vertical().show(ui, |ui| {
            editor_ui(ui, ed, &s.store.items, &mut action);
        });
    });

    match &mut s.dialog {
        Some(Dialog::Settings) => settings_ui(ctx, &s.store.settings, &mut action),
        Some(dialog) => dialog_ui(ctx, dialog, &mut action),
        None => {}
    }

    action
}

impl Dialog {
    fn change_master() -> Self {
        Dialog::ChangeMaster { old: Zeroizing::default(), new: Zeroizing::default(), confirm: Zeroizing::default(), error: None }
    }

    fn export(scope: Option<String>) -> Self {
        Dialog::Export { scope, password: Zeroizing::default(), confirm: Zeroizing::default(), error: None }
    }
}

/// Einstellungen wirken sofort und werden gespeichert.
fn settings_ui(ctx: &egui::Context, settings: &Settings, action: &mut Option<Action>) {
    let mut open = true;
    egui::Window::new(ts!("Einstellungen", "Settings"))
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .open(&mut open)
        .show(ctx, |ui| {
            egui::Grid::new("settings").num_columns(2).spacing([16.0, 10.0]).show(ui, |ui| {
                ui.label(ts!("Sprache", "Language"));
                ui.horizontal(|ui| {
                    let options = [
                        (None, ts!("Wie System", "System default")),
                        (Some(Language::German), "Deutsch"),
                        (Some(Language::English), "English"),
                    ];
                    for (value, label) in options {
                        if ui.radio(settings.language == value, label).clicked() {
                            *action = Some(Action::SetLanguage(value));
                        }
                    }
                });
                ui.end_row();

                ui.label(ts!("Darstellung", "Appearance"));
                ui.horizontal(|ui| {
                    let options = [
                        (Theme::System, ts!("Wie System", "System default")),
                        (Theme::Light, ts!("Hell", "Light")),
                        (Theme::Dark, ts!("Dunkel", "Dark")),
                    ];
                    for (value, label) in options {
                        if ui.radio(settings.theme == value, label).clicked() {
                            *action = Some(Action::SetTheme(value));
                        }
                    }
                });
                ui.end_row();
            });
            ui.add_space(8.0);
            if ui.button(ts!("Schließen", "Close")).clicked() {
                *action = Some(Action::CloseDialog);
            }
        });
    if !open {
        *action = Some(Action::CloseDialog);
    }
}

/// Dialoge mit Eingabefeldern; die Einstellungen zeichnet `settings_ui`.
fn dialog_ui(ctx: &egui::Context, dialog: &mut Dialog, action: &mut Option<Action>) {
    let (title, hint) = match dialog {
        Dialog::Settings => return,
        Dialog::ChangeMaster { .. } => (
            ts!("Master-Passwort ändern", "Change master password"),
            ts!("Alle Passwörter und Schlüssel werden mit dem neuen Master-Passwort neu verschlüsselt.", "All passwords and keys are re-encrypted with the new master password."),
        ),
        Dialog::Export { scope: Some(_), .. } => (
            ts!("Exportieren", "Export"),
            ts!("Der Eintrag wird samt Inhalt in eine eigene Datei mit eigenem Passwort geschrieben.", "The entry and its contents are written to a separate file with its own password."),
        ),
        Dialog::Export { scope: None, .. } => (
            ts!("Alles exportieren", "Export everything"),
            ts!("Alle Einträge werden in eine eigene Datei mit eigenem Passwort geschrieben.", "All entries are written to a separate file with its own password."),
        ),
        Dialog::Import { .. } => (ts!("Importieren", "Import"), ts!("Die Einträge landen in einem neuen Ordner „Import …“.", "The entries are placed in a new folder \"Import …\".")),
        Dialog::Delete { .. } => (ts!("Eintrag entfernen", "Remove entry"), ""),
    };
    let mut open = true;
    egui::Window::new(title)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .open(&mut open)
        .show(ctx, |ui| {
            if !hint.is_empty() {
                ui.label(hint);
                ui.add_space(8.0);
            }
            let mut enter = false;
            let mut field = |ui: &mut egui::Ui, label: &str, value: &mut Zeroizing<String>| {
                ui.label(label);
                let r = ui.add(egui::TextEdit::singleline(&mut **value).password(true).desired_width(260.0));
                enter |= r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                ui.end_row();
            };
            let error = egui::Grid::new("dialog").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| match dialog {
                Dialog::ChangeMaster { old, new, confirm, error } => {
                    field(ui, ts!("Bisheriges", "Current"), old);
                    field(ui, ts!("Neues", "New"), new);
                    field(ui, ts!("Wiederholen", "Repeat"), confirm);
                    error.clone()
                }
                Dialog::Export { password, confirm, error, .. } => {
                    field(ui, ts!("Export-Passwort", "Export password"), password);
                    field(ui, ts!("Wiederholen", "Repeat"), confirm);
                    error.clone()
                }
                Dialog::Import { path, password, error } => {
                    ui.label(ts!("Datei", "File"));
                    ui.label(path.display().to_string());
                    ui.end_row();
                    field(ui, ts!("Passwort der Datei", "File password"), password);
                    error.clone()
                }
                Dialog::Delete { question, error, .. } => {
                    ui.label(question.as_str());
                    ui.end_row();
                    error.clone()
                }
                Dialog::Settings => None,
            });
            // Ohne Eingabefeld bestätigt Enter direkt.
            if matches!(dialog, Dialog::Delete { .. }) && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                enter = true;
            }
            if let Some(error) = error.inner {
                ui.colored_label(ui.visuals().error_fg_color, error);
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let ok = match dialog {
                    Dialog::Export { .. } => ts!("Speichern unter …", "Save as …"),
                    Dialog::Import { .. } => ts!("Importieren", "Import"),
                    Dialog::ChangeMaster { .. } => ts!("Ändern", "Change"),
                    Dialog::Delete { .. } => ts!("Löschen", "Delete"),
                    Dialog::Settings => "OK",
                };
                if ui.button(ok).clicked() || enter {
                    *action = Some(Action::SubmitDialog);
                }
                if ui.button(ts!("Abbrechen", "Cancel")).clicked() {
                    *action = Some(Action::CloseDialog);
                }
            });
        });
    if !open {
        *action = Some(Action::CloseDialog);
    }
}

/// Schnellverbindung: Adresse eintippen, Enter verbindet; ⌘K/Strg+K springt ins Feld, ▾ zeigt den Verlauf.
fn quick_connect_field(ui: &mut egui::Ui, s: &mut Session, action: &mut Option<Action>) {
    let id = egui::Id::new("quick_connect");
    if ui.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::K)) {
        ui.memory_mut(|m| m.request_focus(id));
    }
    let field = ui.add(
        egui::TextEdit::singleline(&mut s.quick_input)
            .id(id)
            .hint_text(ts!("⚡ Schnellverbindung (⌘K)", "⚡ Quick connect (⌘K)"))
            .desired_width(200.0),
    );
    let field = field.on_hover_text(ts!(
        "z. B. rdp://server, admin@host, vnc://host:5901, host:3389 — Enter verbindet",
        "e.g. rdp://server, admin@host, vnc://host:5901, host:3389 — Enter connects"
    ));
    if field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) && !s.quick_input.trim().is_empty() {
        *action = Some(Action::QuickConnect(std::mem::take(&mut s.quick_input)));
    }
    if !s.store.settings.quick_history.is_empty() {
        ui.menu_button("▾", |ui| {
            for entry in &s.store.settings.quick_history {
                if ui.button(entry).clicked() {
                    *action = Some(Action::QuickConnect(entry.clone()));
                    ui.close_menu();
                }
            }
        })
        .response
        .on_hover_text(ts!("Letzte Schnellverbindungen", "Recent quick connections"));
    }
}

/// Hintergrund, solange keine Sitzung und keine Eigenschaften offen sind: Logo, Name und Hinweis.
fn empty_background(ui: &mut egui::Ui) {
    let size = (ui.available_height() * 0.35).clamp(96.0, 220.0);
    ui.vertical_centered(|ui| {
        ui.add_space(((ui.available_height() - size - 90.0) / 2.0).max(16.0));
        ui.add(egui::Image::new(crate::LOGO).fit_to_exact_size(egui::vec2(size, size)));
        ui.add_space(8.0);
        ui.heading("ConnMgr");
        ui.add_space(6.0);
        ui.weak(ts!(
            "Klick auf eine Verbindung verbindet — Rechtsklick öffnet das Menü (Eigenschaften, Löschen …), Ziehen verschiebt.",
            "Click a connection to connect — right-click opens the menu (properties, delete …), drag to move."
        ));
    });
}

/// Kopfzeile mit Fixieren-Schalter und der Baum selbst.
fn tree_ui(ui: &mut egui::Ui, s: &Session, action: &mut Option<Action>) {
    ui.horizontal(|ui| {
        ui.strong(ts!("Verbindungen", "Connections"));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let pinned = s.store.settings.tree_pinned;
            let hint = if pinned { ts!("Automatisch ausblenden", "Hide automatically") } else { ts!("Fixieren", "Pin") };
            if ui.selectable_label(pinned, "📌").on_hover_text(hint).clicked() {
                *action = Some(Action::ToggleTreePin);
            }
        });
    });
    ui.separator();
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        let view = TreeView { filter: s.filter.to_lowercase(), favorites_only: s.favorites_only, selected: s.selected.as_deref() };
        view.nodes(ui, &s.store.items, None, 0, action);
        if s.store.items.is_empty() {
            ui.weak(ts!("Noch leer — oben eine Verbindung, einen Ordner oder Zugangsdaten anlegen.", "Empty — add a connection, folder or credentials above."));
        }
        root_drop_zone(ui, action);
    });
}

const TREE_OVERLAY_WIDTH: f32 = 300.0;
const TREE_HIDE_DELAY: Duration = Duration::from_millis(400);

/// Nicht fixierter Baum: schmale Leiste am linken Rand; beim Darüberfahren schwebt der Baum
/// über dem Inhalt (die Sitzung behält ihre Größe) und verschwindet wieder, wenn die Maus ihn verlässt.
fn tree_overlay(ctx: &egui::Context, s: &mut Session, action: &mut Option<Action>) {
    let strip = egui::SidePanel::left("tree_strip").exact_width(26.0).resizable(false).show(ctx, |ui| {
        ui.vertical_centered(|ui| {
            if ui.button("»").on_hover_text(ts!("Verbindungen einblenden", "Show connections")).clicked() {
                s.tree_overlay = true;
            }
        });
    });
    if strip.response.contains_pointer() {
        s.tree_overlay = true;
        s.tree_hide_at = None;
    }
    if !s.tree_overlay {
        return;
    }

    let area_rect = egui::Rect::from_min_size(
        egui::pos2(strip.response.rect.right(), strip.response.rect.top()),
        egui::vec2(TREE_OVERLAY_WIDTH, strip.response.rect.height()),
    );
    let area = egui::Area::new(egui::Id::new("tree_overlay")).order(egui::Order::Foreground).fixed_pos(area_rect.min).show(ctx, |ui| {
        egui::Frame::side_top_panel(ui.style()).shadow(ui.visuals().popup_shadow).show(ui, |ui| {
            ui.set_width(TREE_OVERLAY_WIDTH - 16.0);
            ui.set_height(area_rect.height() - 16.0);
            tree_ui(ui, s, action);
        });
    });

    // Nach einem Klick auf eine Verbindung den Baum wieder wegräumen.
    if matches!(action, Some(Action::Connect(_) | Action::ConnectNew(_) | Action::OpenSftp(_))) {
        s.tree_overlay = false;
        return;
    }
    let busy = ctx.is_context_menu_open() || ctx.dragged_id().is_some() || s.dialog.is_some();
    if area.response.contains_pointer() || busy {
        s.tree_hide_at = None;
    } else {
        let deadline = *s.tree_hide_at.get_or_insert_with(|| Instant::now() + TREE_HIDE_DELAY);
        if Instant::now() >= deadline {
            s.tree_overlay = false;
            s.tree_hide_at = None;
        } else {
            ctx.request_repaint_after(deadline - Instant::now());
        }
    }
}

fn tab_bar(ui: &mut egui::Ui, s: &Session, action: &mut Option<Action>) {
    if let Some(ed) = &s.editor {
        let name = if ed.name.trim().is_empty() { t!("Neu", "New") } else { ed.name.trim().to_owned() };
        if ui.selectable_label(s.active_tab.is_none(), t!("📝 Eigenschaften – {name}", "📝 Properties – {name}")).clicked() {
            *action = Some(Action::ActivateTab(None));
        }
        if ui.small_button("✖").on_hover_text(ts!("Eigenschaften schließen", "Close properties")).clicked() {
            *action = Some(Action::CloseProperties);
        }
    }
    for (index, tab) in s.tabs.iter().enumerate() {
        if index > 0 || s.editor.is_some() {
            ui.separator();
        }
        let (dot, dot_color) = match tab.conn().status() {
            ssh::Status::Connected => ("●", Color32::from_rgb(0x23, 0xd1, 0x8b)),
            ssh::Status::Connecting | ssh::Status::HostKey { .. } | ssh::Status::Prompt { .. } => {
                ("●", Color32::from_rgb(0xf5, 0xb0, 0x41))
            }
            ssh::Status::Closed(_) => ("○", ui.visuals().weak_text_color()),
        };
        ui.colored_label(dot_color, dot);
        let mut title = RichText::new(&tab.title);
        if let Some(color) = tab.color {
            title = title.color(color);
        }
        let label = ui.selectable_label(s.active_tab == Some(index), title).on_hover_text(&tab.tooltip);
        if label.clicked() {
            *action = Some(Action::ActivateTab(Some(index)));
        }
        if tab.adhoc.is_some()
            && ui.small_button("💾").on_hover_text(ts!("Als Verbindung im Baum speichern", "Save as connection in the tree")).clicked()
        {
            *action = Some(Action::SaveAdhoc(index));
        }
        if label.middle_clicked() || ui.small_button("✖").on_hover_text(ts!("Tab schließen", "Close tab")).clicked() {
            *action = Some(Action::CloseTab(index));
        }
        label.context_menu(|ui| {
            menu_item(ui, ts!("🔄 Neu verbinden", "🔄 Reconnect"), action, || Action::Reconnect(index));
            ui.separator();
            menu_item(ui, ts!("Schließen", "Close"), action, || Action::CloseTab(index));
            if s.tabs.len() > 1 {
                menu_item(ui, ts!("Andere schließen", "Close others"), action, || Action::CloseOtherTabs(index));
            }
            menu_item(ui, ts!("Alle Verbindungen schließen", "Close all connections"), action, || Action::CloseAllTabs);
        });
    }
}

/// Freie Fläche unter dem Baum: Ablegen verschiebt auf die oberste Ebene, Rechtsklick legt dort an.
fn root_drop_zone(ui: &mut egui::Ui, action: &mut Option<Action>) {
    let height = ui.available_height();
    let height = if height.is_finite() { height.max(40.0) } else { 40.0 };
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), height), Sense::click());
    if resp.dnd_hover_payload::<String>().is_some() {
        ui.painter().hline(rect.x_range(), rect.top(), ui.visuals().selection.stroke);
    }
    if let Some(dragged) = resp.dnd_release_payload::<String>() {
        *action = Some(Action::Move(dragged.to_string(), Target::Root));
    }
    resp.context_menu(|ui| new_menu_items(ui, None, action));
}

struct TreeView<'a> {
    filter: String,
    favorites_only: bool,
    selected: Option<&'a str>,
}

impl TreeView<'_> {
    fn filtering(&self) -> bool {
        !self.filter.is_empty() || self.favorites_only
    }

    fn text_match(&self, fields: &[&str]) -> bool {
        self.filter.is_empty() || fields.iter().any(|f| f.to_lowercase().contains(&self.filter))
    }

    fn visible(&self, node: &Node) -> bool {
        match node {
            Node::Folder(f) => {
                (!self.favorites_only && self.text_match(&[&f.name])) || f.children.iter().any(|c| self.visible(c))
            }
            Node::Connection(c) => (!self.favorites_only || c.favorite) && self.text_match(&[&c.name, &c.host, &c.username]),
            Node::Credential(c) => !self.favorites_only && self.text_match(&[&c.name, &c.username]),
        }
    }

    fn nodes(&self, ui: &mut egui::Ui, nodes: &[Node], parent: Option<&str>, depth: usize, action: &mut Option<Action>) {
        for node in nodes.iter().filter(|n| self.visible(n)) {
            self.row(ui, node, parent, depth, action);
            if let Node::Folder(f) = node {
                if f.expanded || self.filtering() {
                    self.nodes(ui, &f.children, Some(&f.id), depth + 1, action);
                }
            }
        }
    }

    fn row(&self, ui: &mut egui::Ui, node: &Node, parent: Option<&str>, depth: usize, action: &mut Option<Action>) {
        let id = node.id();
        let is_folder = matches!(node, Node::Folder(_));

        let label = ui
            .horizontal(|ui| {
                ui.add_space(depth as f32 * 16.0);
                let (_, arrow) = ui.allocate_exact_size(egui::vec2(14.0, 14.0), if is_folder { Sense::click() } else { Sense::hover() });
                if let Node::Folder(f) = node {
                    let openness = if f.expanded || self.filtering() { 1.0 } else { 0.0 };
                    egui::collapsing_header::paint_default_icon(ui, openness, &arrow);
                    if arrow.clicked() {
                        *action = Some(Action::ToggleExpanded(id.to_owned()));
                    }
                }
                let mut text = RichText::new(format!("{}  {}", node.icon(), node.name()));
                if let Some([r, g, b]) = node.color().and_then(model::parse_color) {
                    text = text.color(Color32::from_rgb(r, g, b));
                }
                let label = ui.add(egui::SelectableLabel::new(self.selected == Some(id), text)).interact(Sense::drag());
                if let Node::Connection(c) = node {
                    if c.favorite {
                        ui.label(RichText::new("⭐").small());
                    }
                }
                label
            })
            .inner;

        let label = match node {
            Node::Connection(c) => label.on_hover_text(t!("{}  {} — Klick verbindet", "{}  {} — click to connect", c.protocol.label(), c.host_port())),
            _ => label,
        };

        // Verbindungen: ein Klick verbindet (bzw. wechselt zum offenen Tab). Bearbeiten über das Kontextmenü.
        match node {
            Node::Connection(_) if label.clicked() => *action = Some(Action::Connect(id.to_owned())),
            Node::Folder(_) if label.double_clicked() => *action = Some(Action::ToggleExpanded(id.to_owned())),
            Node::Folder(_) | Node::Credential(_) if label.clicked() => *action = Some(Action::Select(id.to_owned())),
            _ => {}
        }

        // Ziehen & Ablegen: auf einen Ordner = hinein, auf einen Eintrag = davor.
        label.dnd_set_drag_payload(id.to_owned());
        if let Some(dragged) = label.dnd_hover_payload::<String>() {
            if dragged.as_str() != id {
                let stroke = ui.visuals().selection.stroke;
                if is_folder {
                    ui.painter().rect_stroke(label.rect.expand(2.0), 3.0, stroke);
                } else {
                    ui.painter().hline(label.rect.x_range(), label.rect.top() - 1.0, stroke);
                }
            }
        }
        if let Some(dragged) = label.dnd_release_payload::<String>() {
            if dragged.as_str() != id {
                let target = if is_folder { Target::Into(id.to_owned()) } else { Target::Before(id.to_owned()) };
                *action = Some(Action::Move(dragged.to_string(), target));
            }
        }

        label.context_menu(|ui| {
            match node {
                Node::Connection(c) => {
                    menu_item(ui, ts!("▶ Verbinden", "▶ Connect"), action, || Action::Connect(id.to_owned()));
                    menu_item(ui, ts!("Weitere Sitzung öffnen", "Open another session"), action, || Action::ConnectNew(id.to_owned()));
                    match c.protocol {
                        Protocol::Ssh => {
                            menu_item(ui, ts!("📂 SFTP-Browser", "📂 SFTP browser"), action, || Action::OpenSftp(id.to_owned()));
                            menu_item(ui, ts!("In externem Terminal öffnen", "Open in external terminal"), action, || Action::ConnectExternal(id.to_owned()));
                        }
                        Protocol::Sftp => {
                            menu_item(ui, ts!("Mit externem sftp öffnen", "Open with external sftp"), action, || Action::ConnectExternal(id.to_owned()));
                        }
                        Protocol::Vnc => {
                            menu_item(ui, ts!("Mit externem Viewer öffnen", "Open with external viewer"), action, || Action::ConnectExternal(id.to_owned()));
                        }
                        Protocol::Rdp => {
                            menu_item(ui, ts!("Mit externem RDP-Client öffnen", "Open with external RDP client"), action, || Action::ConnectExternal(id.to_owned()));
                        }
                        // Horizon startet ohnehin den Horizon Client.
                        Protocol::Horizon => {}
                    }
                    menu_item(ui, ts!("📋 Passwort kopieren", "📋 Copy password"), action, || Action::CopyPassword(id.to_owned()));
                    let fav = if c.favorite { ts!("☆ Kein Favorit mehr", "☆ Remove favorite") } else { ts!("⭐ Als Favorit", "⭐ Add to favorites") };
                    menu_item(ui, fav, action, || Action::ToggleFavorite(id.to_owned()));
                }
                Node::Credential(_) => {
                    menu_item(ui, ts!("📋 Passwort kopieren", "📋 Copy password"), action, || Action::CopyPassword(id.to_owned()));
                }
                Node::Folder(_) => {}
            }
            if !is_folder {
                ui.separator();
            }
            let new_parent = if is_folder { Some(id) } else { parent };
            new_menu_items(ui, new_parent, action);
            ui.separator();
            menu_item(ui, ts!("📝 Eigenschaften", "📝 Properties"), action, || Action::Edit(id.to_owned()));
            menu_item(ui, ts!("Duplizieren", "Duplicate"), action, || Action::Duplicate(id.to_owned()));
            menu_item(ui, ts!("Exportieren …", "Export …"), action, || Action::OpenDialog(Dialog::export(Some(id.to_owned()))));
            menu_item(ui, ts!("🗑 Löschen", "🗑 Delete"), action, || Action::AskDelete(id.to_owned()));
        });
    }
}

fn new_menu_items(ui: &mut egui::Ui, parent: Option<&str>, action: &mut Option<Action>) {
    let parent = parent.map(str::to_owned);
    menu_item(ui, ts!("➕ Neue Verbindung", "➕ New connection"), action, || Action::New(Kind::Connection, parent.clone()));
    menu_item(ui, ts!("📁 Neuer Ordner", "📁 New folder"), action, || Action::New(Kind::Folder, parent.clone()));
    menu_item(ui, ts!("🔑 Neue Zugangsdaten", "🔑 New credentials"), action, || Action::New(Kind::Credential, parent.clone()));
}

fn menu_item(ui: &mut egui::Ui, label: &str, action: &mut Option<Action>, make: impl FnOnce() -> Action) {
    if ui.button(label).clicked() {
        *action = Some(make());
        ui.close_menu();
    }
}

// ---------------------------------------------------------------- Editor

fn editor_ui(ui: &mut egui::Ui, ed: &mut Editor, items: &[Node], action: &mut Option<Action>) {
    let kind = ed.kind();
    let title = match (kind, ed.id.is_some()) {
        (Kind::Folder, false) => ts!("Neuer Ordner", "New folder"),
        (Kind::Folder, true) => ts!("Ordner", "Folder"),
        (Kind::Connection, false) => ts!("Neue Verbindung", "New connection"),
        (Kind::Connection, true) => ts!("Verbindung", "Connection"),
        (Kind::Credential, false) => ts!("Neue Zugangsdaten", "New credentials"),
        (Kind::Credential, true) => ts!("Zugangsdaten", "Credentials"),
    };
    ui.heading(title);
    if let Some(parent) = ed.parent.as_deref().and_then(|p| model::find(items, p)) {
        ui.weak(t!("in {}  {}", "in {}  {}", parent.icon(), parent.name()));
    }
    ui.add_space(12.0);

    let creds: Vec<(String, String, String)> =
        model::credentials(items).iter().map(|c| (c.id.clone(), c.name.clone(), c.username.clone())).collect();
    let cred_label = |id: &str| {
        creds.iter().find(|(cid, ..)| cid == id).map(|(_, name, _)| format!("🔑 {name}")).unwrap_or_else(|| t!("⚠ fehlt", "⚠ missing"))
    };

    egui::Grid::new("editor").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
        ui.label("Name");
        ui.add(egui::TextEdit::singleline(&mut ed.name).desired_width(300.0));
        ui.end_row();

        match &mut ed.body {
            EditorBody::Folder { credential_id } => {
                ui.label(ts!("Zugangsdaten", "Credentials"));
                let text = credential_id.as_deref().map_or_else(|| t!("— keine —", "— none —"), cred_label);
                egui::ComboBox::from_id_salt("folder_cred").selected_text(text).width(300.0).show_ui(ui, |ui| {
                    ui.selectable_value(credential_id, None, ts!("— keine —", "— none —"));
                    for (cid, name, _) in &creds {
                        ui.selectable_value(credential_id, Some(cid.clone()), format!("🔑 {name}"));
                    }
                });
                ui.end_row();
                ui.label("");
                ui.weak(ts!("Verbindungen mit „Vom Ordner erben“ verwenden diese Zugangsdaten.", "Connections set to \"Inherit from folder\" use these credentials."));
                ui.end_row();
            }
            EditorBody::Connection {
                host,
                port,
                protocol,
                credentials,
                username,
                password,
                show_password,
                favorite,
                resource,
                display_protocol,
            } => {
                ui.label(ts!("Typ", "Type"));
                let previous = *protocol;
                egui::ComboBox::from_id_salt("protocol").selected_text(protocol.label()).show_ui(ui, |ui| {
                    for p in Protocol::ALL {
                        ui.selectable_value(protocol, p, p.label());
                    }
                });
                // Port mitziehen, solange er noch dem Standard des alten Protokolls entspricht.
                if *protocol != previous && (port.trim().is_empty() || port.trim() == previous.default_port().to_string()) {
                    *port = protocol.default_port().to_string();
                }
                ui.end_row();

                let horizon = *protocol == Protocol::Horizon;
                ui.label(if horizon { ts!("Connection Server", "Connection Server") } else { ts!("Host / IP", "Host / IP") });
                ui.add(egui::TextEdit::singleline(host).desired_width(300.0));
                ui.end_row();

                ui.label("Port");
                ui.add(egui::TextEdit::singleline(port).desired_width(80.0));
                ui.end_row();

                if horizon {
                    ui.label(ts!("Desktop / App", "Desktop / app"));
                    ui.add(
                        egui::TextEdit::singleline(resource)
                            .desired_width(300.0)
                            .hint_text(ts!("leer = Auswahl im Horizon Client", "empty = choose in Horizon Client")),
                    );
                    ui.end_row();

                    ui.label(ts!("Anzeigeprotokoll", "Display protocol"));
                    let text = display_protocol.map_or(ts!("Standard", "Default"), DisplayProtocol::label);
                    egui::ComboBox::from_id_salt("display_protocol").selected_text(text).show_ui(ui, |ui| {
                        ui.selectable_value(display_protocol, None, ts!("Standard", "Default"));
                        ui.selectable_value(display_protocol, Some(DisplayProtocol::Blast), "Blast");
                        ui.selectable_value(display_protocol, Some(DisplayProtocol::Pcoip), "PCoIP");
                    });
                    ui.end_row();

                    ui.label("");
                    ui.weak(ts!(
                        "Startet den Omnissa Horizon Client. Benutzer und Domäne (DOMÄNE\\benutzer) werden vorbelegt, das Passwort liegt 30 s in der Zwischenablage.",
                        "Starts the Omnissa Horizon Client. User and domain (DOMAIN\\user) are pre-filled; the password is in the clipboard for 30 s."
                    ));
                    ui.end_row();
                }

                ui.label(ts!("Zugangsdaten", "Credentials"));
                let text = match &*credentials {
                    CredentialSource::Own => t!("Eigene", "Own"),
                    CredentialSource::Inherit => t!("Vom Ordner erben", "Inherit from folder"),
                    CredentialSource::Stored { id } => cred_label(id),
                };
                egui::ComboBox::from_id_salt("conn_cred").selected_text(text).width(300.0).show_ui(ui, |ui| {
                    ui.selectable_value(credentials, CredentialSource::Own, ts!("Eigene", "Own"));
                    ui.selectable_value(credentials, CredentialSource::Inherit, ts!("Vom Ordner erben", "Inherit from folder"));
                    for (cid, name, _) in &creds {
                        ui.selectable_value(credentials, CredentialSource::Stored { id: cid.clone() }, format!("🔑 {name}"));
                    }
                });
                ui.end_row();

                match &*credentials {
                    CredentialSource::Own => {
                        username_password_rows(ui, username, password, show_password);
                    }
                    CredentialSource::Inherit => {
                        ui.label("");
                        match model::inherited_credential(items, ed.parent.as_deref()) {
                            Some(c) => ui.weak(format!("→ 🔑 {} ({})", c.name, display_user(&c.username))),
                            None => ui.colored_label(ui.visuals().warn_fg_color, ts!("Kein übergeordneter Ordner hat Zugangsdaten", "No parent folder has credentials")),
                        };
                        ui.end_row();
                    }
                    CredentialSource::Stored { id } => {
                        ui.label("");
                        if let Some((_, _, user)) = creds.iter().find(|(cid, ..)| cid == id) {
                            ui.weak(t!("→ Benutzer {}", "→ user {}", display_user(user)));
                        }
                        ui.end_row();
                    }
                }

                ui.label(ts!("Favorit", "Favorite"));
                ui.checkbox(favorite, "⭐");
                ui.end_row();
            }
            EditorBody::Credential { username, password, show_password, private_key, passphrase, show_key, key_info } => {
                username_password_rows(ui, username, password, show_password);
                key_rows(ui, private_key, passphrase, show_key, key_info);
            }
        }

        ui.label("Icon");
        ui.horizontal_wrapped(|ui| {
            ui.add(egui::TextEdit::singleline(&mut ed.icon).desired_width(36.0).hint_text("auto"));
            for icon in ICONS {
                if ui.add(egui::Button::new(*icon).frame(false)).clicked() {
                    ed.icon = (*icon).to_owned();
                }
            }
            if ui.small_button("auto").clicked() {
                ed.icon.clear();
            }
        });
        ui.end_row();

        ui.label(ts!("Farbe", "Color"));
        ui.horizontal(|ui| {
            let mut custom = ed.color.is_some();
            if ui.checkbox(&mut custom, ts!("eigene Farbe", "custom color")).changed() {
                ed.color = custom.then_some([0x1e, 0x88, 0xe5]);
            }
            if let Some(rgb) = &mut ed.color {
                egui::color_picker::color_edit_button_srgb(ui, rgb);
            }
        });
        ui.end_row();
    });

    ui.add_space(16.0);
    ui.horizontal(|ui| {
        if ui.button(ts!("💾 Speichern", "💾 Save")).on_hover_text(ts!("⌘S / Strg+S", "⌘S / Ctrl+S")).clicked() {
            *action = Some(Action::Save);
        }
        let Some(id) = &ed.id else { return };
        if kind == Kind::Connection && ui.button(ts!("▶ Verbinden", "▶ Connect")).clicked() {
            *action = Some(Action::Connect(id.clone()));
        }
        let protocol = match &ed.body {
            EditorBody::Connection { protocol, .. } => Some(*protocol),
            _ => None,
        };
        if protocol == Some(Protocol::Ssh) && ui.button("📂 SFTP").on_hover_text(ts!("Dateibrowser für diesen Server", "File browser for this server")).clicked() {
            *action = Some(Action::OpenSftp(id.clone()));
        }
        if protocol.is_some_and(|p| p != Protocol::Horizon)
            && ui.button(ts!("Extern", "External")).on_hover_text(ts!("Mit dem Programm des Betriebssystems öffnen", "Open with the operating system's program")).clicked()
        {
            *action = Some(Action::ConnectExternal(id.clone()));
        }
        if kind != Kind::Folder && ui.button(ts!("📋 Passwort kopieren", "📋 Copy password")).clicked() {
            *action = Some(Action::CopyPassword(id.clone()));
        }
        ui.separator();
        if ui.button(ts!("🗑 Löschen …", "🗑 Delete …")).clicked() {
            *action = Some(Action::AskDelete(id.clone()));
        }
    });
    if kind == Kind::Connection && ed.id.is_some() {
        ui.add_space(8.0);
        ui.weak(ts!("„Verbinden“ nutzt den gespeicherten Stand — Änderungen vorher speichern.", "\"Connect\" uses the saved state — save changes first."));
    }
}

fn key_rows(
    ui: &mut egui::Ui,
    private_key: &mut Zeroizing<String>,
    passphrase: &mut Zeroizing<String>,
    show_key: &mut bool,
    key_info: &mut Option<(u64, KeyInfo)>,
) {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    (private_key.as_str(), passphrase.as_str()).hash(&mut hasher);
    let hash = hasher.finish();
    if key_info.as_ref().is_none_or(|(h, _)| *h != hash) {
        *key_info = Some((hash, inspect_key(private_key, passphrase)));
    }
    let info = key_info.as_ref().map(|(_, i)| i.clone()).unwrap_or(KeyInfo::None);

    ui.label(ts!("SSH-Schlüssel", "SSH key"));
    ui.vertical(|ui| {
        match &info {
            KeyInfo::None => ui.weak(ts!("Kein Schlüssel hinterlegt", "No key stored")),
            KeyInfo::Valid { summary, .. } => ui.label(format!("🔑 {summary}")),
            KeyInfo::Encrypted => ui.label(ts!("🔒 Verschlüsselt — Passphrase eintragen oder beim Verbinden eingeben", "🔒 Encrypted — enter the passphrase here or when connecting")),
            KeyInfo::Invalid(e) => ui.colored_label(ui.visuals().error_fg_color, format!("⚠ {e}")),
        };
        ui.horizontal(|ui| {
            if ui.button(ts!("Aus Datei laden …", "Load from file …")).clicked() {
                let mut picker = rfd::FileDialog::new().set_title(ts!("Privaten SSH-Schlüssel wählen", "Choose private SSH key"));
                if let Some(dirs) = directories::BaseDirs::new() {
                    picker = picker.set_directory(dirs.home_dir().join(".ssh"));
                }
                if let Some(text) = picker.pick_file().and_then(|path| std::fs::read_to_string(path).ok()) {
                    **private_key = text;
                }
            }
            if !private_key.is_empty() {
                ui.checkbox(show_key, ts!("Text anzeigen", "Show text"));
                if ui.button(ts!("Entfernen", "Remove")).clicked() {
                    private_key.clear();
                    passphrase.clear();
                }
            }
            if let KeyInfo::Valid { public, .. } = &info {
                if ui.button(ts!("📋 Öffentlichen Schlüssel kopieren", "📋 Copy public key")).on_hover_text(ts!("Für ~/.ssh/authorized_keys auf dem Server", "For ~/.ssh/authorized_keys on the server")).clicked() {
                    ui.ctx().copy_text(public.clone());
                }
            }
        });
        if *show_key || private_key.is_empty() {
            ui.add(
                egui::TextEdit::multiline(&mut **private_key)
                    .font(egui::TextStyle::Monospace)
                    .desired_rows(3)
                    .desired_width(420.0)
                    .hint_text(ts!("-----BEGIN OPENSSH PRIVATE KEY-----  (einfügen oder aus Datei laden)", "-----BEGIN OPENSSH PRIVATE KEY-----  (paste or load from file)")),
            );
        }
    });
    ui.end_row();

    ui.label("Passphrase");
    ui.add(egui::TextEdit::singleline(&mut **passphrase).password(true).desired_width(220.0).hint_text(ts!("optional", "optional")));
    ui.end_row();
}

fn username_password_rows(ui: &mut egui::Ui, username: &mut String, password: &mut Zeroizing<String>, show: &mut bool) {
    ui.label(ts!("Benutzer", "User"));
    ui.add(egui::TextEdit::singleline(username).desired_width(300.0));
    ui.end_row();

    ui.label(ts!("Passwort", "Password"));
    ui.horizontal(|ui| {
        ui.add(egui::TextEdit::singleline(&mut **password).password(!*show).desired_width(220.0));
        ui.checkbox(show, ts!("anzeigen", "show"));
    });
    ui.end_row();
}

fn display_user(user: &str) -> &str {
    if user.is_empty() {
        ts!("ohne Benutzer", "no user")
    } else {
        user
    }
}

fn delete_question(items: &[Node], id: &str) -> String {
    let question: String = match model::find(items, id) {
        Some(node @ Node::Folder(_)) if model::count(node) > 1 => {
            t!("Ordner mit {} Einträgen löschen?", "Delete folder with {} entries?", model::count(node) - 1)
        }
        Some(Node::Credential(c)) => match model::references_to(items, &c.id) {
            0 => t!("Wirklich löschen?", "Really delete?"),
            n => t!("Wird von {n} Einträgen verwendet — trotzdem löschen?", "Used by {n} entries — delete anyway?"),
        },
        _ => t!("Wirklich löschen?", "Really delete?"),
    };
    let name = model::find(items, id).map(Node::name).unwrap_or_default();
    t!("„{name}“: {question}", "\"{name}\": {question}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::tests::{conn, cred, folder};

    fn session() -> Session {
        let (mut store, vault) = StoreFile::create("master-pw").unwrap();
        store.items = vec![
            folder("Credentials", None, vec![cred("admin", "root")]),
            folder(
                "Production",
                Some("admin"),
                vec![conn("web01", CredentialSource::Inherit), folder("db", None, vec![conn("db01", CredentialSource::Own)])],
            ),
            conn("lonely", CredentialSource::Stored { id: "admin".into() }),
        ];
        Session {
            vault,
            store,
            filter: String::new(),
            favorites_only: false,
            selected: None,
            editor: None,
            tree_overlay: false,
            tree_hide_at: None,
            quick_input: String::new(),
            tabs: Vec::new(),
            active_tab: None,
            dialog: None,
        }
    }

    fn render(s: &mut Session) {
        let ctx = egui::Context::default();
        for _ in 0..3 {
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                session_ui(ctx, s, "Status", Path::new("test.json"));
            });
        }
    }

    /// Bedient die Oberfläche wie ein Mensch: Elemente per Name (AccessKit) finden und anklicken.
    struct UiDriver {
        ctx: egui::Context,
        events: Vec<egui::Event>,
        widgets: Vec<(String, egui::Rect)>,
        path: PathBuf,
        started: Instant,
    }

    impl UiDriver {
        fn new(path: PathBuf) -> Self {
            let ctx = egui::Context::default();
            ctx.enable_accesskit();
            egui_extras::install_image_loaders(&ctx);
            crate::i18n::tests::force_english(Some(false));
            Self { ctx, events: Vec::new(), widgets: Vec::new(), path, started: Instant::now() }
        }

        /// Zeichnet ein Bild, wendet die ausgelöste Aktion an und liefert sie zurück (zur Kontrolle).
        fn frame(&mut self, s: &mut Session) -> Option<String> {
            let input = egui::RawInput {
                events: std::mem::take(&mut self.events),
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1200.0, 800.0))),
                // Echte Zeit, sonst wertet egui zwei Klicks im Abstand weniger Bilder als Doppelklick.
                time: Some(self.started.elapsed().as_secs_f64()),
                ..Default::default()
            };
            let mut action = None;
            let output = self.ctx.run(input, |ctx| action = session_ui(ctx, s, "", &self.path));
            self.widgets = output
                .platform_output
                .accesskit_update
                .map(|update| {
                    update
                        .nodes
                        .iter()
                        .filter_map(|(_, node)| {
                            let b = node.bounds()?;
                            let rect = egui::Rect::from_min_max(egui::pos2(b.x0 as f32, b.y0 as f32), egui::pos2(b.x1 as f32, b.y1 as f32));
                            Some((node.name()?.to_string(), rect))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let action = action?;
            let name = format!("{:?}", std::mem::discriminant(&action));
            let label = action_name(&action);
            let _ = name;
            s.apply(action, &self.path).unwrap();
            Some(label)
        }

        fn has(&self, name: &str) -> bool {
            self.widgets.iter().any(|(n, _)| n.contains(name))
        }

        /// Exakter Name bevorzugt, sonst Teiltreffer.
        fn find(&self, name: &str) -> egui::Pos2 {
            self.widgets
                .iter()
                .find(|(n, _)| n == name)
                .or_else(|| self.widgets.iter().find(|(n, _)| n.contains(name)))
                .unwrap_or_else(|| panic!("„{name}“ nicht gefunden in {:?}", self.widgets.iter().map(|w| &w.0).collect::<Vec<_>>()))
                .1
                .center()
        }

        /// Klickt (Drücken und Loslassen in zwei Bildern) und liefert die ausgelöste Aktion.
        /// Vorher kurz warten, damit egui zwei Klicks nicht als Doppelklick wertet,
        /// und ein Bild zeichnen, damit neue Fenster ihre endgültige Position haben.
        fn click(&mut self, s: &mut Session, name: &str, button: egui::PointerButton) -> Option<String> {
            std::thread::sleep(Duration::from_millis(350));
            self.frame(s);
            let pos = self.find(name);
            let modifiers = egui::Modifiers::NONE;
            self.events.push(egui::Event::PointerMoved(pos));
            self.events.push(egui::Event::PointerButton { pos, button, pressed: true, modifiers });
            let first = self.frame(s);
            self.events.push(egui::Event::PointerButton { pos, button, pressed: false, modifiers });
            let second = self.frame(s);
            second.or(first)
        }
    }

    fn action_name(action: &Action) -> String {
        match action {
            Action::Select(_) => "Select",
            Action::Edit(_) => "Edit",
            Action::CloseProperties => "CloseProperties",
            Action::Connect(_) => "Connect",
            Action::AskDelete(_) => "AskDelete",
            Action::CloseDialog => "CloseDialog",
            Action::SubmitDialog => "SubmitDialog",
            Action::ToggleTreePin => "ToggleTreePin",
            _ => "andere",
        }
        .to_owned()
    }

    #[test]
    fn delete_via_tree_context_menu() {
        let dir = std::env::temp_dir().join(format!("connmgr-test-{}", uuid::Uuid::new_v4()));
        let mut s = session();
        let mut ui = UiDriver::new(dir.join("c.json"));
        ui.frame(&mut s);
        ui.frame(&mut s);
        ui.click(&mut s, "lonely", egui::PointerButton::Secondary);
        ui.frame(&mut s);
        let action = ui.click(&mut s, "🗑 Löschen", egui::PointerButton::Primary);
        assert_eq!(action.as_deref(), Some("AskDelete"));
        ui.frame(&mut s);
        assert!(ui.has("„lonely“: Wirklich löschen?"), "Dialog zeigt, was gelöscht wird");
        let action = ui.click(&mut s, "Löschen", egui::PointerButton::Primary);
        assert_eq!(action.as_deref(), Some("SubmitDialog"));
        assert!(model::find(&s.store.items, "lonely").is_none(), "Eintrag gelöscht");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn delete_via_tree_context_menu_with_open_tab() {
        let dir = std::env::temp_dir().join(format!("connmgr-test-{}", uuid::Uuid::new_v4()));
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let mut s = session();
        let mut ui = UiDriver::new(dir.join("c.json"));
        let session = SshSession::start(
            runtime.handle(),
            ui.ctx.clone(),
            ConnectParams { host: "127.0.0.1".into(), port: 1, username: "x".into(), password: None, private_key: None, passphrase: None },
        );
        s.tabs.push(Tab {
            conn_id: "web01".into(),
            title: "web01".into(),
            tooltip: String::new(),
            color: None,
            content: TabContent::Terminal { session, view: TerminalView::default() },
            adhoc: None,
        });
        s.active_tab = Some(0);
        ui.frame(&mut s);
        ui.frame(&mut s);
        ui.click(&mut s, "lonely", egui::PointerButton::Secondary);
        ui.frame(&mut s);
        let action = ui.click(&mut s, "🗑 Löschen", egui::PointerButton::Primary);
        assert_eq!(action.as_deref(), Some("AskDelete"));
        ui.frame(&mut s);
        assert!(ui.has("„lonely“: Wirklich löschen?"), "Dialog zeigt, was gelöscht wird");
        let action = ui.click(&mut s, "Löschen", egui::PointerButton::Primary);
        assert_eq!(action.as_deref(), Some("SubmitDialog"));
        assert!(model::find(&s.store.items, "lonely").is_none(), "Eintrag gelöscht");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn single_click_connects_and_folder_click_selects() {
        let mut s = session();
        let mut ui = UiDriver::new(std::env::temp_dir().join("unbenutzt.json"));
        ui.frame(&mut s);
        ui.frame(&mut s);
        assert_eq!(ui.click(&mut s, "lonely", egui::PointerButton::Primary).as_deref(), Some("Connect"));
        assert_eq!(ui.click(&mut s, "Production", egui::PointerButton::Primary).as_deref(), Some("Select"));
    }

    #[test]
    fn properties_only_via_context_menu_and_closable() {
        let mut s = session();
        let mut ui = UiDriver::new(std::env::temp_dir().join("unbenutzt.json"));
        ui.frame(&mut s);
        ui.frame(&mut s);
        ui.click(&mut s, "Production", egui::PointerButton::Primary);
        ui.frame(&mut s);
        assert!(s.editor.is_none() && !ui.has("📝 Eigenschaften"), "Klick markiert nur");
        assert_eq!(s.selected.as_deref(), Some("Production"));

        ui.click(&mut s, "Production", egui::PointerButton::Secondary);
        ui.frame(&mut s);
        assert_eq!(ui.click(&mut s, "📝 Eigenschaften", egui::PointerButton::Primary).as_deref(), Some("Edit"));
        ui.frame(&mut s);
        assert!(ui.has("📝 Eigenschaften – Production"), "Tab mit Namen");
        assert!(ui.has("💾 Speichern"), "Editor sichtbar");

        ui.click(&mut s, "✖", egui::PointerButton::Primary);
        ui.frame(&mut s);
        assert!(s.editor.is_none() && !ui.has("💾 Speichern"), "geschlossen");
    }

    #[test]
    fn settings_dialog_switches_language_and_theme() {
        let dir = std::env::temp_dir().join(format!("connmgr-test-{}", uuid::Uuid::new_v4()));
        let mut s = session();
        let mut ui = UiDriver::new(dir.join("c.json"));
        ui.frame(&mut s);
        ui.click(&mut s, "☰", egui::PointerButton::Primary);
        ui.frame(&mut s);
        ui.click(&mut s, "⚙ Einstellungen …", egui::PointerButton::Primary);
        ui.frame(&mut s);
        ui.click(&mut s, "English", egui::PointerButton::Primary);
        assert_eq!(s.store.settings.language, Some(Language::English));
        ui.click(&mut s, "Dunkel", egui::PointerButton::Primary);
        assert_eq!(s.store.settings.theme, Theme::Dark);
        let saved = StoreFile::load(&dir.join("c.json")).unwrap().settings;
        assert_eq!((saved.language, saved.theme), (Some(Language::English), Theme::Dark), "gespeichert");

        // Oberfläche auf Englisch (in der App übernimmt `apply_settings` die Sprache).
        crate::i18n::tests::force_english(Some(true));
        ui.frame(&mut s);
        ui.frame(&mut s);
        assert!(ui.has("🔒 Lock") && ui.has("Appearance") && ui.has("Click a connection to connect"), "{:?}", ui.widgets.iter().map(|w| &w.0).collect::<Vec<_>>());
        crate::i18n::tests::force_english(Some(false));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn logo_renders_and_background_shows_it() {
        let image = egui_extras::image::load_svg_bytes_with_size(include_bytes!("../assets/logo.svg"), Some(egui::SizeHint::Size(64, 64)))
            .expect("Logo rendert");
        assert_eq!(image.size, [64, 64]);
        let center = image.pixels[32 * 64 + 32];
        assert!(center.a() == 255 && center != egui::Color32::WHITE, "Mitte deckend (Terminal), nicht leer");

        let mut s = session();
        let mut ui = UiDriver::new(std::env::temp_dir().join("unbenutzt.json"));
        for _ in 0..3 {
            ui.frame(&mut s);
        }
        assert!(ui.has("ConnMgr") && ui.has("Klick auf eine Verbindung verbindet"), "Hintergrund mit Name und Hinweis");
    }

    #[test]
    fn quick_connect_field_with_shortcut_and_enter() {
        let mut s = session();
        let mut ui = UiDriver::new(std::env::temp_dir().join("unbenutzt.json"));
        ui.frame(&mut s);
        let key = |key, modifiers| egui::Event::Key { key, physical_key: None, pressed: true, repeat: false, modifiers };
        ui.events.push(key(egui::Key::K, egui::Modifiers::COMMAND));
        ui.frame(&mut s);
        ui.events.push(egui::Event::Text("admin@web01".into()));
        ui.frame(&mut s);
        ui.events.push(key(egui::Key::Enter, egui::Modifiers::NONE));
        // Aktion direkt abgreifen (der Treiber würde sie sonst schon anwenden).
        let mut action = None;
        let _ = ui.ctx.run(egui::RawInput { events: std::mem::take(&mut ui.events), ..Default::default() }, |ctx| {
            action = session_ui(ctx, &mut s, "", &ui.path);
        });
        assert!(matches!(action, Some(Action::QuickConnect(ref input)) if input == "admin@web01"));
        assert!(s.quick_input.is_empty(), "Feld nach dem Verbinden geleert");
    }

    #[test]
    fn quick_connect_opens_adhoc_tab_and_saves_it() {
        let dir = std::env::temp_dir().join(format!("connmgr-test-{}", uuid::Uuid::new_v4()));
        let path = dir.join("c.json");
        let ctx = egui::Context::default();
        let mut app = ConnMgrApp::new(path.clone());
        app.state = State::Unlocked(Box::new(session()));

        app.handle(&ctx, Action::QuickConnect("admin@127.0.0.1:1".into()));
        let State::Unlocked(s) = &app.state else { unreachable!() };
        assert_eq!(s.tabs.len(), 1, "{}", app.status);
        let tab = &s.tabs[0];
        assert!(tab.title.starts_with('⚡') && tab.kind() == TabKind::Terminal);
        let adhoc = tab.adhoc.as_ref().expect("Schnellverbindung");
        assert_eq!((adhoc.host.as_str(), adhoc.port, adhoc.username.as_str()), ("127.0.0.1", 1, "admin"));
        assert_eq!(s.store.settings.quick_history, ["admin@127.0.0.1:1"]);

        // Neu verbinden behält die Schnellverbindung.
        app.handle(&ctx, Action::Reconnect(0));
        let State::Unlocked(s) = &app.state else { unreachable!() };
        assert!(s.tabs[0].adhoc.is_some() && s.tabs.len() == 1);

        // Speichern legt einen Eintrag im Baum an.
        app.handle(&ctx, Action::SaveAdhoc(0));
        let State::Unlocked(s) = &app.state else { unreachable!() };
        assert!(s.tabs[0].adhoc.is_none());
        let saved = model::find_connection(&s.store.items, &s.tabs[0].conn_id).expect("im Baum");
        assert_eq!((saved.host.as_str(), saved.username.as_str()), ("127.0.0.1", "admin"));
        assert!(model::find_connection(&StoreFile::load(&path).unwrap().items, &saved.id).is_some(), "in der Datei");

        // Ungültige Eingabe: Fehlermeldung, kein Tab.
        app.handle(&ctx, Action::QuickConnect("http://x".into()));
        assert!(app.status.contains("Unbekanntes Protokoll"), "{}", app.status);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn horizon_editor_fields_and_save() {
        let dir = std::env::temp_dir().join(format!("connmgr-test-{}", uuid::Uuid::new_v4()));
        let mut s = session();
        let mut ed = Editor::new(Kind::Connection, None);
        ed.name = "VDI".into();
        if let EditorBody::Connection { host, port, protocol, resource, display_protocol, username, .. } = &mut ed.body {
            *host = "view.firma.de".into();
            *protocol = Protocol::Horizon;
            *port = "443".into();
            *resource = "Finance Desktop".into();
            *display_protocol = Some(DisplayProtocol::Blast);
            *username = "FIRMA\\fred".into();
        }
        s.editor = Some(ed);
        let mut ui = UiDriver::new(dir.join("c.json"));
        ui.frame(&mut s);
        ui.frame(&mut s);
        assert!(ui.has("Connection Server") && ui.has("Desktop / App") && ui.has("Anzeigeprotokoll"), "Horizon-Felder sichtbar");
        assert!(!ui.has("Extern"), "kein Extern-Knopf bei Horizon (läuft ohnehin extern)");

        s.apply(Action::Save, &dir.join("c.json")).unwrap();
        let id = s.selected.clone().unwrap();
        let conn = model::find_connection(&s.store.items, &id).unwrap();
        assert_eq!((conn.resource.as_str(), conn.display_protocol), ("Finance Desktop", Some(DisplayProtocol::Blast)));
        assert_eq!(
            launcher::horizon_uri(conn),
            "horizon-client://fred@view.firma.de/Finance%20Desktop?domainName=FIRMA&desktopProtocol=BLAST"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn tab_context_menu_closes_others_and_all() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let mut s = session();
        let mut ui = UiDriver::new(std::env::temp_dir().join("unbenutzt.json"));
        let ctx = ui.ctx.clone();
        let add_tab = |s: &mut Session, title: &str| {
            let session = SshSession::start(
                runtime.handle(),
                ctx.clone(),
                ConnectParams { host: "127.0.0.1".into(), port: 1, username: "x".into(), password: None, private_key: None, passphrase: None },
            );
            s.tabs.push(Tab {
                conn_id: title.into(),
                title: title.into(),
                tooltip: String::new(),
                color: None,
                content: TabContent::Terminal { session, view: TerminalView::default() },
                adhoc: None,
            });
        };
        for title in ["Tab A", "Tab B", "Tab C"] {
            add_tab(&mut s, title);
        }
        s.active_tab = Some(1);
        ui.frame(&mut s);
        ui.frame(&mut s);

        ui.click(&mut s, "Tab B", egui::PointerButton::Secondary);
        ui.frame(&mut s);
        ui.click(&mut s, "Andere schließen", egui::PointerButton::Primary);
        assert_eq!(s.tabs.iter().map(|t| t.title.as_str()).collect::<Vec<_>>(), ["Tab B"]);
        assert_eq!(s.active_tab, Some(0));

        add_tab(&mut s, "Tab D");
        ui.frame(&mut s);
        ui.click(&mut s, "Tab D", egui::PointerButton::Secondary);
        ui.frame(&mut s);
        ui.click(&mut s, "Alle Verbindungen schließen", egui::PointerButton::Primary);
        assert!(s.tabs.is_empty() && s.active_tab.is_none());
    }

    #[test]
    fn delete_key_asks_for_selected_entry() {
        let mut s = session();
        let mut ui = UiDriver::new(std::env::temp_dir().join("unbenutzt.json"));
        s.mark("Credentials");
        ui.frame(&mut s);
        ui.events.push(egui::Event::Key {
            key: egui::Key::Delete,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });
        assert_eq!(ui.frame(&mut s).as_deref(), Some("AskDelete"));
        ui.frame(&mut s);
        assert!(ui.has("„Credentials“: Ordner mit 1 Einträgen löschen?"));
    }

    #[test]
    fn unpinned_tree_shows_on_hover_and_hides_again() {
        let mut s = session();
        s.store.settings.tree_pinned = false;
        let mut ui = UiDriver::new(std::env::temp_dir().join("unbenutzt.json"));
        ui.frame(&mut s);
        ui.frame(&mut s);
        assert!(ui.has("»") && !ui.has("lonely"), "nur die Leiste sichtbar");

        let strip = ui.find("»");
        ui.events.push(egui::Event::PointerMoved(strip));
        ui.frame(&mut s);
        ui.frame(&mut s);
        assert!(ui.has("lonely"), "Baum schwebt beim Darüberfahren ein: {:?}", ui.widgets.iter().map(|w| &w.0).collect::<Vec<_>>());

        // Maus weit weg: nach der Verzögerung wieder ausgeblendet.
        ui.events.push(egui::Event::PointerMoved(egui::pos2(1100.0, 700.0)));
        ui.frame(&mut s);
        std::thread::sleep(TREE_HIDE_DELAY + Duration::from_millis(50));
        ui.frame(&mut s);
        ui.frame(&mut s);
        assert!(!ui.has("lonely"), "Baum wieder ausgeblendet");

        // Fixieren-Schalter im eingeblendeten Baum.
        ui.events.push(egui::Event::PointerMoved(strip));
        ui.frame(&mut s);
        ui.frame(&mut s);
        let dir = std::env::temp_dir().join(format!("connmgr-test-{}", uuid::Uuid::new_v4()));
        ui.path = dir.join("c.json");
        ui.click(&mut s, "📌", egui::PointerButton::Primary);
        assert!(s.store.settings.tree_pinned);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn status_line_clears_when_connection_ends() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let mut app = ConnMgrApp::new(PathBuf::from("unbenutzt.json"));
        let mut s = session();
        let session = SshSession::start(
            runtime.handle(),
            egui::Context::default(),
            ConnectParams { host: "127.0.0.1".into(), port: 1, username: "x".into(), password: None, private_key: None, passphrase: None },
        );
        s.tabs.push(Tab {
            conn_id: "web01".into(),
            title: "web01".into(),
            tooltip: String::new(),
            color: None,
            content: TabContent::Terminal { session, view: TerminalView::default() },
            adhoc: None,
        });
        app.state = State::Unlocked(Box::new(s));
        app.status = "web01: verbinde …".into();
        app.status_conn = Some(("web01".into(), "web01".into()));

        let deadline = Instant::now() + Duration::from_secs(5);
        while !app.status.is_empty() {
            app.refresh_status();
            assert!(Instant::now() < deadline, "Statuszeile nicht geleert: {}", app.status);
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(app.status_conn.is_none());
    }

    #[test]
    fn renders_tree_and_all_editors() {
        let mut s = session();
        render(&mut s);
        for id in ["Production", "web01", "admin", "lonely"] {
            s.open_properties(id).unwrap();
            s.apply(Action::AskDelete(id.into()), Path::new("unused.json")).unwrap();
            render(&mut s);
            s.dialog = None;
        }
        for kind in [Kind::Folder, Kind::Connection, Kind::Credential] {
            s.editor = Some(Editor::new(kind, Some("Production".into())));
            render(&mut s);
        }
        s.filter = "db".into();
        s.favorites_only = true;
        render(&mut s);
    }

    /// Öffnet einen echten SSH-Tab zu einem geschlossenen Port und rendert ihn bis zur Fehlermeldung.
    #[test]
    fn renders_ssh_tab_until_closed() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let ctx = egui::Context::default();
        let mut s = session();
        let session = SshSession::start(
            runtime.handle(),
            ctx.clone(),
            ConnectParams {
                host: "127.0.0.1".into(),
                port: 1,
                username: "x".into(),
                password: None,
                private_key: None,
                passphrase: None,
            },
        );
        session.parser().process(b"\x1b[1;31mrot\x1b[0m \x1b[7minvers\x1b[0m \xe4\xb8\xad\xe6\x96\x87\r\n");
        s.tabs.push(Tab {
            conn_id: "web01".into(),
            title: "web01".into(),
            tooltip: String::new(),
            color: None,
            content: TabContent::Terminal { session, view: TerminalView::default() },
            adhoc: None,
        });
        s.active_tab = Some(0);

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                session_ui(ctx, &mut s, "Status", Path::new("test.json"));
            });
            if let ssh::Status::Closed(msg) = &s.tabs[0].conn().status() {
                assert!(msg.starts_with("Fehler"), "{msg}");
                break;
            }
            assert!(Instant::now() < deadline, "Verbindung wurde nicht beendet");
            std::thread::sleep(Duration::from_millis(20));
        }
        let TabContent::Terminal { session, .. } = &s.tabs[0].content else { unreachable!() };
        assert_ne!(session.parser().screen().size(), (24, 80), "Terminal passt sich der Fläche an");

        s.apply(Action::CloseTab(0), Path::new("unused.json")).unwrap();
        assert!(s.tabs.is_empty());
        assert_eq!(s.active_tab, None);
    }

    #[test]
    fn save_new_connection_into_folder_and_duplicate() {
        let dir = std::env::temp_dir().join(format!("connmgr-test-{}", uuid::Uuid::new_v4()));
        let path = dir.join("c.json");
        let mut s = session();

        let mut ed = Editor::new(Kind::Connection, Some("db".into()));
        ed.name = "db02".into();
        if let EditorBody::Connection { host, .. } = &mut ed.body {
            *host = "10.0.0.2".into();
        }
        s.editor = Some(ed);
        s.apply(Action::Save, &path).unwrap();
        let id = s.selected.clone().unwrap();
        assert_eq!(model::parent_id(&s.store.items, &id).as_deref(), Some("db"));
        let c = model::find_connection(&s.store.items, &id).unwrap().clone();
        assert_eq!(c.credentials, CredentialSource::Inherit);
        assert_eq!(s.credentials_for(&c).unwrap().username, "root", "erbt von Production");

        s.apply(Action::Duplicate("admin".into()), &path).unwrap();
        assert_eq!(model::credentials(&s.store.items).len(), 2);

        s.delete("admin", &path).unwrap();
        let web01 = model::find_connection(&s.store.items, "web01").unwrap().clone();
        assert_eq!(s.credentials_for(&web01).unwrap().username, "", "Verweis entfernt");

        std::fs::remove_dir_all(dir).unwrap();
    }
}
