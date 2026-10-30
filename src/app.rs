use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use eframe::egui::{self, Color32, RichText, Sense};
use zeroize::Zeroizing;

use crate::askpass;
use crate::crypto::Vault;
use crate::launcher;
use crate::model::{self, Connection, Credential, CredentialSource, Folder, Node, Protocol, Target};
use crate::ssh::{self, ConnectParams, SshSession};
use crate::store::{self, StoreFile};
use crate::terminal::TerminalView;

const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(30);
const MIN_MASTER_LEN: usize = 8;
const ICONS: &[&str] = &["📁", "🏠", "🏢", "☁", "🧪", "⚡", "🔒", "🔑", "👤", "💻", "🖥", "🗄", "📺", "🌐", "🐧", "🔧", "🚀", "⭐"];

pub struct ConMgrApp {
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
    confirm_delete: bool,
    /// Offene SSH-Sitzungen; beim Sperren werden sie mit der Session getrennt.
    tabs: Vec<Tab>,
    /// `None` = Eigenschaften-Tab.
    active_tab: Option<usize>,
}

struct Tab {
    conn_id: String,
    title: String,
    tooltip: String,
    color: Option<Color32>,
    session: SshSession,
    view: TerminalView,
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
    },
    Credential {
        username: String,
        password: Zeroizing<String>,
        show_password: bool,
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
            },
            Kind::Credential => {
                EditorBody::Credential { username: String::new(), password: Zeroizing::default(), show_password: false }
            }
        };
        Self { id: None, parent, name: String::new(), icon: String::new(), color: None, body }
    }

    fn load(s: &Session, id: &str) -> Result<Self> {
        let node = model::find(&s.store.items, id).ok_or_else(|| anyhow!("Eintrag nicht gefunden"))?;
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
                },
            ),
            Node::Credential(c) => (
                &c.icon,
                &c.color,
                EditorBody::Credential {
                    username: c.username.clone(),
                    password: store::decrypt_secret(&s.vault, &c.id, c.password.as_ref())?.unwrap_or_default(),
                    show_password: false,
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
    Delete(String),
    Connect(String),
    /// SSH im Terminal des Betriebssystems statt im Tab.
    ConnectExternal(String),
    /// Auswählen und zum Eigenschaften-Tab wechseln.
    Edit(String),
    CopyPassword(String),
    ActivateTab(Option<usize>),
    CloseTab(usize),
    Reconnect(usize),
    ToggleExpanded(String),
    ToggleFavorite(String),
    Move(String, Target),
    Duplicate(String),
}

fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

impl ConMgrApp {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            state: State::Locked(LockScreen::default()),
            status: String::new(),
            clipboard: None,
            clipboard_secret: None,
            askpass: None,
            runtime: None,
        }
    }

    fn handle(&mut self, ctx: &egui::Context, action: Action) {
        let result = match action {
            Action::Unlock => self.unlock(),
            Action::Lock => {
                self.state = State::Locked(LockScreen::default());
                self.status = "Gesperrt".into();
                Ok(())
            }
            Action::Connect(id) => match self.session().ok().and_then(|s| model::find_connection(&s.store.items, &id)) {
                Some(c) if c.protocol == Protocol::Ssh => self.open_ssh_tab(ctx, &id, None),
                _ => self.connect(&id),
            },
            Action::ConnectExternal(id) => self.connect(&id),
            Action::Reconnect(index) => match &self.state {
                State::Unlocked(s) => match s.tabs.get(index) {
                    Some(tab) => {
                        let id = tab.conn_id.clone();
                        self.open_ssh_tab(ctx, &id, Some(index))
                    }
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
            self.status = format!("Fehler: {e}");
        }
    }

    fn unlock(&mut self) -> Result<()> {
        let State::Locked(lock) = &mut self.state else { return Ok(()) };
        let outcome = if self.path.exists() {
            StoreFile::load(&self.path).and_then(|store| store.unlock(&lock.master).map(|vault| (store, vault)))
        } else if lock.master.chars().count() < MIN_MASTER_LEN {
            Err(anyhow!("Das Master-Passwort muss mindestens {MIN_MASTER_LEN} Zeichen lang sein"))
        } else if *lock.master != *lock.confirm {
            Err(anyhow!("Die Passwörter stimmen nicht überein"))
        } else {
            StoreFile::create(&lock.master).and_then(|(store, vault)| store.save(&self.path).map(|()| (store, vault)))
        };
        match outcome {
            Ok((store, vault)) => {
                self.status = "Entsperrt".into();
                self.state = State::Unlocked(Box::new(Session {
                    vault,
                    store,
                    filter: String::new(),
                    favorites_only: false,
                    selected: None,
                    editor: None,
                    confirm_delete: false,
                    tabs: Vec::new(),
                    active_tab: None,
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
            State::Locked(_) => Err(anyhow!("Gesperrt")),
        }
    }

    fn connect(&mut self, id: &str) -> Result<()> {
        let session = self.session()?;
        let conn = model::find_connection(&session.store.items, id).ok_or_else(|| anyhow!("Verbindung nicht gefunden"))?.clone();
        let (username, password) = session.credentials_for(&conn)?;
        let ssh_env = match (&password, conn.protocol) {
            (Some(pw), Protocol::Ssh | Protocol::Sftp) => self.askpass()?.issue(pw.clone())?,
            _ => Vec::new(),
        };
        let launched = launcher::launch(&conn, &username, password.as_deref().map(String::as_str), &ssh_env)?;
        self.status = format!("{}: {}", conn.name, launched.info);
        if let (Some(pw), false) = (password, launched.password_consumed) {
            self.copy_secret(pw)?;
            self.status.push_str(&format!(" — Passwort für {}s in der Zwischenablage", CLIPBOARD_CLEAR_AFTER.as_secs()));
        }
        Ok(())
    }

    /// Öffnet eine eingebettete SSH-Sitzung in einem neuen Tab oder ersetzt die in `replace`.
    fn open_ssh_tab(&mut self, ctx: &egui::Context, id: &str, replace: Option<usize>) -> Result<()> {
        let runtime = self.runtime()?.handle().clone();
        let State::Unlocked(session) = &mut self.state else { bail!("Gesperrt") };
        let node = model::find(&session.store.items, id).ok_or_else(|| anyhow!("Verbindung nicht gefunden"))?;
        let Node::Connection(conn) = node else { bail!("Kein Verbindungseintrag") };
        let (username, password) = session.credentials_for(conn)?;
        model::validate_host(&conn.host).map_err(|e| anyhow!(e))?;
        model::validate_username(&username).map_err(|e| anyhow!(e))?;

        let tab = Tab {
            conn_id: conn.id.clone(),
            title: format!("{}  {}", node.icon(), conn.name),
            tooltip: if username.is_empty() { conn.host_port() } else { format!("{username}@{}", conn.host_port()) },
            color: node.color().and_then(model::parse_color).map(|[r, g, b]| Color32::from_rgb(r, g, b)),
            session: SshSession::start(
                &runtime,
                ctx.clone(),
                ConnectParams { host: conn.host.clone(), port: conn.port, username, password, cols: 80, rows: 24 },
            ),
            view: TerminalView::default(),
        };
        self.status = format!("{}: verbinde …", conn.name);
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

    fn runtime(&mut self) -> Result<&tokio::runtime::Runtime> {
        if self.runtime.is_none() {
            let runtime =
                tokio::runtime::Builder::new_multi_thread().worker_threads(2).thread_name("conmgr-ssh").enable_all().build()?;
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
            Some(Node::Connection(c)) => session.credentials_for(c)?.1,
            Some(Node::Credential(c)) => store::decrypt_secret(&session.vault, &c.id, c.password.as_ref())?,
            _ => bail!("Eintrag hat kein Passwort"),
        };
        match password {
            Some(pw) => {
                self.copy_secret(pw)?;
                self.status = format!("Passwort für {}s in der Zwischenablage", CLIPBOARD_CLEAR_AFTER.as_secs());
            }
            None => self.status = "Kein Passwort hinterlegt".into(),
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

impl Drop for ConMgrApp {
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
                self.confirm_delete = false;
                self.active_tab = None;
                Ok(None)
            }
            Action::Edit(id) => {
                self.select(&id)?;
                self.active_tab = None;
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
            Action::Select(id) => {
                self.select(&id)?;
                Ok(None)
            }
            Action::Save => self.save(path).map(Some),
            Action::AskDelete(id) => {
                self.select(&id)?;
                self.confirm_delete = true;
                self.active_tab = None;
                Ok(None)
            }
            Action::Delete(id) => self.delete(&id, path).map(Some),
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
                Ok(Some("Verschoben".into()))
            }
            Action::Duplicate(id) => self.duplicate(&id, path).map(Some),
            Action::Unlock
            | Action::Lock
            | Action::Connect(_)
            | Action::ConnectExternal(_)
            | Action::Reconnect(_)
            | Action::CopyPassword(_) => Ok(None),
        }
    }

    fn select(&mut self, id: &str) -> Result<()> {
        self.editor = Some(Editor::load(self, id)?);
        self.selected = Some(id.to_owned());
        self.confirm_delete = false;
        Ok(())
    }

    fn credentials_for(&self, conn: &Connection) -> Result<(String, Option<Zeroizing<String>>)> {
        match model::resolve(&self.store.items, conn).map_err(|e| anyhow!(e))? {
            Some(r) => Ok((r.username.to_owned(), store::decrypt_secret(&self.vault, r.aad, r.password)?)),
            None => Ok((String::new(), None)),
        }
    }

    fn save(&mut self, path: &Path) -> Result<String> {
        let ed = self.editor.as_mut().ok_or_else(|| anyhow!("Kein Eintrag geöffnet"))?;
        let name = ed.name.trim().to_owned();
        if name.is_empty() {
            bail!("Name darf nicht leer sein");
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
            EditorBody::Connection { host, port, protocol, credentials, username, password, favorite, .. } => {
                let host = host.trim().to_owned();
                model::validate_host(&host).map_err(|e| anyhow!(e))?;
                let port: u16 = match port.trim().parse() {
                    Ok(p) if p > 0 => p,
                    _ => bail!("Ungültiger Port: {port}"),
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
                })
            }
            EditorBody::Credential { username, password, .. } => {
                let username = username.trim().to_owned();
                model::validate_username(&username).map_err(|e| anyhow!(e))?;
                Node::Credential(Credential {
                    id: id.clone(),
                    name: name.clone(),
                    username,
                    password: store::encrypt_secret(&self.vault, &id, password)?,
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
        Ok(format!("„{name}“ gespeichert"))
    }

    fn delete(&mut self, id: &str, path: &Path) -> Result<String> {
        let removed = model::remove(&mut self.store.items, id).ok_or_else(|| anyhow!("Eintrag nicht gefunden"))?;
        // Auch Zugangsdaten innerhalb eines gelöschten Ordners können anderswo verwendet werden.
        for cred in model::credentials(std::slice::from_ref(&removed)) {
            model::clear_credential_references(&mut self.store.items, &cred.id);
        }
        self.store.save(path)?;
        self.editor = None;
        self.selected = None;
        self.confirm_delete = false;
        Ok(format!("„{}“ gelöscht", removed.name()))
    }

    /// Kopiert Verbindung oder Zugangsdaten; das Passwort wird für die neue ID neu verschlüsselt.
    fn duplicate(&mut self, id: &str, path: &Path) -> Result<String> {
        let node = model::find(&self.store.items, id).cloned().ok_or_else(|| anyhow!("Eintrag nicht gefunden"))?;
        let copy_id = new_id();
        let reencrypt = |old_id: &str, enc: Option<&crate::crypto::Encrypted>| -> Result<_> {
            match store::decrypt_secret(&self.vault, old_id, enc)? {
                Some(pw) => store::encrypt_secret(&self.vault, &copy_id, &pw),
                None => Ok(None),
            }
        };
        let copy = match node {
            Node::Connection(mut c) => {
                c.password = reencrypt(&c.id, c.password.as_ref())?;
                c.id = copy_id.clone();
                c.name = format!("{} (Kopie)", c.name);
                Node::Connection(c)
            }
            Node::Credential(mut c) => {
                c.password = reencrypt(&c.id, c.password.as_ref())?;
                c.id = copy_id.clone();
                c.name = format!("{} (Kopie)", c.name);
                Node::Credential(c)
            }
            Node::Folder(_) => bail!("Ordner können nicht dupliziert werden"),
        };
        let name = copy.name().to_owned();
        if let Err(copy) = model::insert(&mut self.store.items, &Target::After(id.to_owned()), copy) {
            self.store.items.push(copy);
        }
        self.store.save(path)?;
        self.select(&copy_id)?;
        Ok(format!("„{name}“ angelegt"))
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

impl eframe::App for ConMgrApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.expire_clipboard(ctx);
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
            ui.heading("🔐 ConMgr");
            ui.add_space(8.0);
            ui.label(if new_file { "Neue Verbindungsdatei — Master-Passwort festlegen" } else { "Master-Passwort eingeben" });
            ui.add_space(12.0);

            let master = ui.add(
                egui::TextEdit::singleline(&mut *lock.master).password(true).hint_text("Master-Passwort").desired_width(260.0),
            );
            if !lock.focused {
                master.request_focus();
                lock.focused = true;
            }
            let mut submit = master.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if new_file {
                let confirm = ui.add(
                    egui::TextEdit::singleline(&mut *lock.confirm).password(true).hint_text("Wiederholen").desired_width(260.0),
                );
                submit = confirm.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            }
            ui.add_space(8.0);
            if ui.button(if new_file { "Anlegen" } else { "Entsperren" }).clicked() || submit {
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
            let parent = s.default_parent();
            if ui.button("➕ Verbindung").clicked() {
                action = Some(Action::New(Kind::Connection, parent.clone()));
            }
            if ui.button("📁 Ordner").clicked() {
                action = Some(Action::New(Kind::Folder, parent.clone()));
            }
            if ui.button("🔑 Zugangsdaten").clicked() {
                action = Some(Action::New(Kind::Credential, parent));
            }
            ui.separator();
            ui.add(egui::TextEdit::singleline(&mut s.filter).hint_text("🔍 Suchen …").desired_width(180.0));
            ui.toggle_value(&mut s.favorites_only, "⭐ Favoriten");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("🔒 Sperren").clicked() {
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

    egui::SidePanel::left("tree").resizable(true).default_width(300.0).show(ctx, |ui| {
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            let view = TreeView { filter: s.filter.to_lowercase(), favorites_only: s.favorites_only, selected: s.selected.as_deref() };
            view.nodes(ui, &s.store.items, None, 0, &mut action);
            if s.store.items.is_empty() {
                ui.weak("Noch leer — oben eine Verbindung, einen Ordner oder Zugangsdaten anlegen.");
            }
            root_drop_zone(ui, &mut action);
        });
    });

    if !s.tabs.is_empty() {
        egui::TopBottomPanel::top("tabbar").show(ctx, |ui| {
            egui::ScrollArea::horizontal().show(ui, |ui| {
                ui.horizontal(|ui| tab_bar(ui, s, &mut action));
            });
        });
    }

    egui::CentralPanel::default().show(ctx, |ui| {
        if let Some(index) = s.active_tab {
            if let Some(tab) = s.tabs.get_mut(index) {
                let response = tab.view.show(ui, &tab.session);
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
            ui.centered_and_justified(|ui| {
                ui.weak("Eintrag auswählen — Doppelklick verbindet, Rechtsklick öffnet das Menü, Ziehen verschiebt.");
            });
            return;
        };
        egui::ScrollArea::vertical().show(ui, |ui| {
            editor_ui(ui, ed, &s.store.items, &mut s.confirm_delete, &mut action);
        });
    });

    action
}

fn tab_bar(ui: &mut egui::Ui, s: &Session, action: &mut Option<Action>) {
    if ui.selectable_label(s.active_tab.is_none(), "📝 Eigenschaften").clicked() {
        *action = Some(Action::ActivateTab(None));
    }
    for (index, tab) in s.tabs.iter().enumerate() {
        ui.separator();
        let (dot, dot_color) = match tab.session.lock().status {
            ssh::Status::Connected => ("●", Color32::from_rgb(0x23, 0xd1, 0x8b)),
            ssh::Status::Connecting | ssh::Status::HostKey { .. } => ("●", Color32::from_rgb(0xf5, 0xb0, 0x41)),
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
        if label.middle_clicked() || ui.small_button("✖").on_hover_text("Tab schließen").clicked() {
            *action = Some(Action::CloseTab(index));
        }
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
            Node::Connection(c) => label.on_hover_text(format!("{}  {}", c.protocol.label(), c.host_port())),
            _ => label,
        };

        if label.double_clicked() {
            *action = Some(match node {
                Node::Connection(_) => Action::Connect(id.to_owned()),
                Node::Folder(_) => Action::ToggleExpanded(id.to_owned()),
                Node::Credential(_) => Action::Select(id.to_owned()),
            });
        } else if label.clicked() {
            *action = Some(Action::Select(id.to_owned()));
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
                    menu_item(ui, "▶ Verbinden", action, || Action::Connect(id.to_owned()));
                    if c.protocol == Protocol::Ssh {
                        menu_item(ui, "In externem Terminal öffnen", action, || Action::ConnectExternal(id.to_owned()));
                    }
                    menu_item(ui, "📋 Passwort kopieren", action, || Action::CopyPassword(id.to_owned()));
                    let fav = if c.favorite { "☆ Kein Favorit mehr" } else { "⭐ Als Favorit" };
                    menu_item(ui, fav, action, || Action::ToggleFavorite(id.to_owned()));
                    menu_item(ui, "Duplizieren", action, || Action::Duplicate(id.to_owned()));
                }
                Node::Credential(_) => {
                    menu_item(ui, "📋 Passwort kopieren", action, || Action::CopyPassword(id.to_owned()));
                    menu_item(ui, "Duplizieren", action, || Action::Duplicate(id.to_owned()));
                }
                Node::Folder(_) => {}
            }
            if !is_folder {
                ui.separator();
            }
            let new_parent = if is_folder { Some(id) } else { parent };
            new_menu_items(ui, new_parent, action);
            ui.separator();
            menu_item(ui, "✏ Bearbeiten", action, || Action::Edit(id.to_owned()));
            menu_item(ui, "🗑 Löschen", action, || Action::AskDelete(id.to_owned()));
        });
    }
}

fn new_menu_items(ui: &mut egui::Ui, parent: Option<&str>, action: &mut Option<Action>) {
    let parent = parent.map(str::to_owned);
    menu_item(ui, "➕ Neue Verbindung", action, || Action::New(Kind::Connection, parent.clone()));
    menu_item(ui, "📁 Neuer Ordner", action, || Action::New(Kind::Folder, parent.clone()));
    menu_item(ui, "🔑 Neue Zugangsdaten", action, || Action::New(Kind::Credential, parent.clone()));
}

fn menu_item(ui: &mut egui::Ui, label: &str, action: &mut Option<Action>, make: impl FnOnce() -> Action) {
    if ui.button(label).clicked() {
        *action = Some(make());
        ui.close_menu();
    }
}

// ---------------------------------------------------------------- Editor

fn editor_ui(ui: &mut egui::Ui, ed: &mut Editor, items: &[Node], confirm_delete: &mut bool, action: &mut Option<Action>) {
    let kind = ed.kind();
    let title = match (kind, ed.id.is_some()) {
        (Kind::Folder, false) => "Neuer Ordner",
        (Kind::Folder, true) => "Ordner",
        (Kind::Connection, false) => "Neue Verbindung",
        (Kind::Connection, true) => "Verbindung",
        (Kind::Credential, false) => "Neue Zugangsdaten",
        (Kind::Credential, true) => "Zugangsdaten",
    };
    ui.heading(title);
    if let Some(parent) = ed.parent.as_deref().and_then(|p| model::find(items, p)) {
        ui.weak(format!("in {}  {}", parent.icon(), parent.name()));
    }
    ui.add_space(12.0);

    let creds: Vec<(String, String, String)> =
        model::credentials(items).iter().map(|c| (c.id.clone(), c.name.clone(), c.username.clone())).collect();
    let cred_label = |id: &str| {
        creds.iter().find(|(cid, ..)| cid == id).map(|(_, name, _)| format!("🔑 {name}")).unwrap_or_else(|| "⚠ fehlt".into())
    };

    egui::Grid::new("editor").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
        ui.label("Name");
        ui.add(egui::TextEdit::singleline(&mut ed.name).desired_width(300.0));
        ui.end_row();

        match &mut ed.body {
            EditorBody::Folder { credential_id } => {
                ui.label("Zugangsdaten");
                let text = credential_id.as_deref().map_or_else(|| "— keine —".to_owned(), cred_label);
                egui::ComboBox::from_id_salt("folder_cred").selected_text(text).width(300.0).show_ui(ui, |ui| {
                    ui.selectable_value(credential_id, None, "— keine —");
                    for (cid, name, _) in &creds {
                        ui.selectable_value(credential_id, Some(cid.clone()), format!("🔑 {name}"));
                    }
                });
                ui.end_row();
                ui.label("");
                ui.weak("Verbindungen mit „Vom Ordner erben“ verwenden diese Zugangsdaten.");
                ui.end_row();
            }
            EditorBody::Connection { host, port, protocol, credentials, username, password, show_password, favorite } => {
                ui.label("Typ");
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

                ui.label("Host / IP");
                ui.add(egui::TextEdit::singleline(host).desired_width(300.0));
                ui.end_row();

                ui.label("Port");
                ui.add(egui::TextEdit::singleline(port).desired_width(80.0));
                ui.end_row();

                ui.label("Zugangsdaten");
                let text = match &*credentials {
                    CredentialSource::Own => "Eigene".to_owned(),
                    CredentialSource::Inherit => "Vom Ordner erben".to_owned(),
                    CredentialSource::Stored { id } => cred_label(id),
                };
                egui::ComboBox::from_id_salt("conn_cred").selected_text(text).width(300.0).show_ui(ui, |ui| {
                    ui.selectable_value(credentials, CredentialSource::Own, "Eigene");
                    ui.selectable_value(credentials, CredentialSource::Inherit, "Vom Ordner erben");
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
                            None => ui.colored_label(ui.visuals().warn_fg_color, "Kein übergeordneter Ordner hat Zugangsdaten"),
                        };
                        ui.end_row();
                    }
                    CredentialSource::Stored { id } => {
                        ui.label("");
                        if let Some((_, _, user)) = creds.iter().find(|(cid, ..)| cid == id) {
                            ui.weak(format!("→ Benutzer {}", display_user(user)));
                        }
                        ui.end_row();
                    }
                }

                ui.label("Favorit");
                ui.checkbox(favorite, "⭐");
                ui.end_row();
            }
            EditorBody::Credential { username, password, show_password } => {
                username_password_rows(ui, username, password, show_password);
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

        ui.label("Farbe");
        ui.horizontal(|ui| {
            let mut custom = ed.color.is_some();
            if ui.checkbox(&mut custom, "eigene Farbe").changed() {
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
        if ui.button("💾 Speichern").on_hover_text("⌘S / Strg+S").clicked() {
            *action = Some(Action::Save);
        }
        let Some(id) = &ed.id else { return };
        if kind == Kind::Connection && ui.button("▶ Verbinden").clicked() {
            *action = Some(Action::Connect(id.clone()));
        }
        let is_ssh = matches!(&ed.body, EditorBody::Connection { protocol: Protocol::Ssh, .. });
        if is_ssh && ui.button("Extern").on_hover_text("Im Terminal des Betriebssystems öffnen").clicked() {
            *action = Some(Action::ConnectExternal(id.clone()));
        }
        if kind != Kind::Folder && ui.button("📋 Passwort kopieren").clicked() {
            *action = Some(Action::CopyPassword(id.clone()));
        }
        ui.separator();
        if *confirm_delete {
            ui.label(delete_question(items, id));
            if ui.button("Ja, löschen").clicked() {
                *action = Some(Action::Delete(id.clone()));
            }
            if ui.button("Abbrechen").clicked() {
                *confirm_delete = false;
            }
        } else if ui.button("🗑 Löschen").clicked() {
            *confirm_delete = true;
        }
    });
    if kind == Kind::Connection && ed.id.is_some() {
        ui.add_space(8.0);
        ui.weak("„Verbinden“ nutzt den gespeicherten Stand — Änderungen vorher speichern.");
    }
}

fn username_password_rows(ui: &mut egui::Ui, username: &mut String, password: &mut Zeroizing<String>, show: &mut bool) {
    ui.label("Benutzer");
    ui.add(egui::TextEdit::singleline(username).desired_width(300.0));
    ui.end_row();

    ui.label("Passwort");
    ui.horizontal(|ui| {
        ui.add(egui::TextEdit::singleline(&mut **password).password(!*show).desired_width(220.0));
        ui.checkbox(show, "anzeigen");
    });
    ui.end_row();
}

fn display_user(user: &str) -> &str {
    if user.is_empty() {
        "ohne Benutzer"
    } else {
        user
    }
}

fn delete_question(items: &[Node], id: &str) -> String {
    match model::find(items, id) {
        Some(node @ Node::Folder(_)) if model::count(node) > 1 => {
            format!("Ordner mit {} Einträgen löschen?", model::count(node) - 1)
        }
        Some(Node::Credential(c)) => match model::references_to(items, &c.id) {
            0 => "Wirklich löschen?".into(),
            n => format!("Wird von {n} Einträgen verwendet — trotzdem löschen?"),
        },
        _ => "Wirklich löschen?".into(),
    }
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
            confirm_delete: false,
            tabs: Vec::new(),
            active_tab: None,
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

    #[test]
    fn renders_tree_and_all_editors() {
        let mut s = session();
        render(&mut s);
        for id in ["Production", "web01", "admin", "lonely"] {
            s.select(id).unwrap();
            s.confirm_delete = true;
            render(&mut s);
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
            ConnectParams { host: "127.0.0.1".into(), port: 1, username: "x".into(), password: None, cols: 80, rows: 24 },
        );
        session.lock().parser.process(b"\x1b[1;31mrot\x1b[0m \x1b[7minvers\x1b[0m \xe4\xb8\xad\xe6\x96\x87\r\n");
        s.tabs.push(Tab {
            conn_id: "web01".into(),
            title: "web01".into(),
            tooltip: String::new(),
            color: None,
            session,
            view: TerminalView::default(),
        });
        s.active_tab = Some(0);

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                session_ui(ctx, &mut s, "Status", Path::new("test.json"));
            });
            if let ssh::Status::Closed(msg) = &s.tabs[0].session.lock().status {
                assert!(msg.starts_with("Fehler"), "{msg}");
                break;
            }
            assert!(Instant::now() < deadline, "Verbindung wurde nicht beendet");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_ne!(s.tabs[0].session.lock().parser.screen().size(), (24, 80), "Terminal passt sich der Fläche an");

        s.apply(Action::CloseTab(0), Path::new("unused.json")).unwrap();
        assert!(s.tabs.is_empty());
        assert_eq!(s.active_tab, None);
    }

    #[test]
    fn save_new_connection_into_folder_and_duplicate() {
        let dir = std::env::temp_dir().join(format!("conmgr-test-{}", uuid::Uuid::new_v4()));
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
        assert_eq!(s.credentials_for(&c).unwrap().0, "root", "erbt von Production");

        s.apply(Action::Duplicate("admin".into()), &path).unwrap();
        assert_eq!(model::credentials(&s.store.items).len(), 2);

        s.apply(Action::Delete("admin".into()), &path).unwrap();
        let web01 = model::find_connection(&s.store.items, "web01").unwrap().clone();
        assert_eq!(s.credentials_for(&web01).unwrap().0, "", "Verweis entfernt");

        std::fs::remove_dir_all(dir).unwrap();
    }
}
