//! SFTP-Dateibrowser im Tab. Verbindungsaufbau und Anmeldung wie beim Terminal
//! (`ssh::establish`), danach das Subsystem „sftp“ über russh-sftp.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::SystemTime;

use anyhow::{anyhow, bail, Result};
use eframe::egui;
use egui_extras::{Column, TableBuilder};
use russh::ChannelMsg;
use russh_sftp::client::SftpSession;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::dialogs::{ConnOverlay, TabResponse};
use crate::ssh::{self, Conn, ConnectParams, Status};

const CHUNK: usize = 256 * 1024;
const INIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

#[derive(Clone)]
pub struct Entry {
    pub name: String,
    pub is_dir: bool,
    pub is_link: bool,
    pub size: u64,
    pub modified: Option<SystemTime>,
    pub permissions: Option<u32>,
}

#[derive(Clone)]
pub enum TransferState {
    Running,
    Done,
    Failed(String),
}

#[derive(Clone)]
pub struct Transfer {
    pub label: String,
    pub done: u64,
    pub total: u64,
    pub state: TransferState,
}

#[derive(Default)]
pub struct Listing {
    pub path: String,
    pub home: String,
    pub entries: Vec<Entry>,
    pub loading: bool,
    pub error: Option<String>,
    pub transfers: Vec<Transfer>,
}

enum Cmd {
    List(String),
    Download { remote: String, local: PathBuf },
    Upload { local: PathBuf, remote_dir: String },
    Mkdir(String),
    Rename { from: String, to: String },
    Delete { path: String, is_dir: bool },
    Close,
}

pub struct SftpSessionHandle {
    conn: Arc<Conn>,
    listing: Arc<Mutex<Listing>>,
    cmds: mpsc::UnboundedSender<Cmd>,
}

impl SftpSessionHandle {
    pub fn start(runtime: &tokio::runtime::Handle, ctx: egui::Context, params: ConnectParams) -> Self {
        let conn = Conn::new(ctx);
        let listing = Arc::new(Mutex::new(Listing { loading: true, ..Default::default() }));
        let (cmds, rx) = mpsc::unbounded_channel();
        let (task_conn, task_listing) = (Arc::clone(&conn), Arc::clone(&listing));
        runtime.spawn(async move {
            let message = match run(params, &task_conn, task_listing, rx).await {
                Ok(()) => t!("Verbindung getrennt", "Disconnected"),
                Err(e) => t!("Fehler: {e:#}", "Error: {e:#}"),
            };
            task_conn.set_status(Status::Closed(message));
        });
        Self { conn, listing, cmds }
    }

    pub fn conn(&self) -> &Conn {
        &self.conn
    }

    fn listing(&self) -> MutexGuard<'_, Listing> {
        self.listing.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn send(&self, cmd: Cmd) {
        let _ = self.cmds.send(cmd);
    }
}

impl Drop for SftpSessionHandle {
    fn drop(&mut self) {
        self.conn.cancel();
        let _ = self.cmds.send(Cmd::Close);
    }
}

pub fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

pub fn parent(path: &str) -> String {
    match path.trim_end_matches('/').rsplit_once('/') {
        Some(("", _)) | None => "/".to_owned(),
        Some((parent, _)) => parent.to_owned(),
    }
}

fn lock(listing: &Mutex<Listing>) -> MutexGuard<'_, Listing> {
    listing.lock().unwrap_or_else(|e| e.into_inner())
}

async fn run(
    params: ConnectParams,
    conn: &Arc<Conn>,
    listing: Arc<Mutex<Listing>>,
    mut cmds: mpsc::UnboundedReceiver<Cmd>,
) -> Result<()> {
    let handle = ssh::establish(&params, conn).await?;
    let mut channel = handle.channel_open_session().await?;
    channel.request_subsystem(true, "sftp").await?;
    // Ohne auf die Antwort zu warten, hinge ein Server ohne SFTP für immer.
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => break,
            Some(ChannelMsg::Failure) => bail!(t!("Der Server bietet kein SFTP an (Subsystem „sftp“ fehlt)", "The server does not offer SFTP (subsystem \"sftp\" missing)")),
            Some(_) => {}
            None => bail!(t!("Der Server hat den Kanal geschlossen", "The server closed the channel")),
        }
    }
    let sftp = tokio::time::timeout(INIT_TIMEOUT, SftpSession::new(channel.into_stream()))
        .await
        .map_err(|_| anyhow!(t!("Zeitüberschreitung beim Start von SFTP", "Timed out starting SFTP")))?
        .map_err(|e| anyhow!(t!("SFTP nicht verfügbar: {e}", "SFTP not available: {e}")))?;
    let sftp = Arc::new(sftp);
    let home = sftp.canonicalize(".").await.unwrap_or_else(|_| "/".into());
    lock(&listing).home = home.clone();
    conn.set_status(Status::Connected);
    list(&sftp, &listing, conn, home).await;

    while let Some(cmd) = cmds.recv().await {
        let current = lock(&listing).path.clone();
        let result = match cmd {
            Cmd::Close => break,
            Cmd::List(path) => {
                list(&sftp, &listing, conn, path).await;
                continue;
            }
            Cmd::Download { remote, local } => {
                spawn_transfer(&sftp, &listing, conn, Direction::Download { remote, local }, current.clone());
                continue;
            }
            Cmd::Upload { local, remote_dir } => {
                spawn_transfer(&sftp, &listing, conn, Direction::Upload { local, remote_dir }, current.clone());
                // Die Liste aktualisiert sich nach Ende der Übertragung selbst.
                continue;
            }
            Cmd::Mkdir(path) => sftp.create_dir(path).await.map_err(Into::into),
            Cmd::Rename { from, to } => sftp.rename(from, to).await.map_err(Into::into),
            Cmd::Delete { path, is_dir: true } => {
                sftp.remove_dir(path).await.map_err(|e| anyhow!(t!("{e} (nur leere Ordner lassen sich löschen)", "{e} (only empty folders can be deleted)")))
            }
            Cmd::Delete { path, is_dir: false } => sftp.remove_file(path).await.map_err(Into::into),
        };
        match result {
            Ok(()) => list(&sftp, &listing, conn, current).await,
            Err(e) => {
                lock(&listing).error = Some(e.to_string());
                conn.repaint();
            }
        }
    }
    let _ = sftp.close().await;
    Ok(())
}

async fn list(sftp: &SftpSession, listing: &Mutex<Listing>, conn: &Conn, path: String) {
    lock(listing).loading = true;
    conn.repaint();
    let result = async {
        let path = sftp.canonicalize(path).await?;
        let mut entries: Vec<Entry> = sftp
            .read_dir(path.clone())
            .await?
            .map(|e| {
                let meta = e.metadata();
                let file_type = e.file_type();
                Entry {
                    name: e.file_name(),
                    is_dir: file_type.is_dir(),
                    is_link: file_type.is_symlink(),
                    size: meta.size.unwrap_or(0),
                    modified: meta.modified().ok(),
                    permissions: meta.permissions,
                }
            })
            .collect();
        entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
        Ok::<_, russh_sftp::client::error::Error>((path, entries))
    }
    .await;
    let mut state = lock(listing);
    state.loading = false;
    match result {
        Ok((path, entries)) => {
            state.path = path;
            state.entries = entries;
            state.error = None;
        }
        Err(e) => state.error = Some(e.to_string()),
    }
    drop(state);
    conn.repaint();
}

enum Direction {
    Download { remote: String, local: PathBuf },
    Upload { local: PathBuf, remote_dir: String },
}

/// Übertragungen laufen nebenher, damit man weiter blättern kann.
fn spawn_transfer(sftp: &Arc<SftpSession>, listing: &Arc<Mutex<Listing>>, conn: &Arc<Conn>, dir: Direction, current: String) {
    let label = match &dir {
        Direction::Download { remote, .. } => format!("⬇ {}", remote.rsplit('/').next().unwrap_or(remote)),
        Direction::Upload { local, .. } => format!("⬆ {}", local.file_name().unwrap_or_default().to_string_lossy()),
    };
    let index = {
        let mut state = lock(listing);
        state.transfers.push(Transfer { label, done: 0, total: 0, state: TransferState::Running });
        state.transfers.len() - 1
    };
    let (sftp, listing, conn) = (Arc::clone(sftp), Arc::clone(listing), Arc::clone(conn));
    tokio::spawn(async move {
        let progress = |done: u64, total: u64| {
            let mut state = lock(&listing);
            state.transfers[index].done = done;
            state.transfers[index].total = total;
            drop(state);
            conn.repaint();
        };
        let upload_dir = match &dir {
            Direction::Upload { remote_dir, .. } => Some(remote_dir.clone()),
            Direction::Download { .. } => None,
        };
        let result = transfer(&sftp, dir, progress).await;
        lock(&listing).transfers[index].state = match result {
            Ok(()) => TransferState::Done,
            Err(e) => TransferState::Failed(e.to_string()),
        };
        // Hochgeladene Datei sofort anzeigen, wenn der Ordner noch offen ist.
        if upload_dir.as_deref() == Some(current.as_str()) && lock(&listing).path == current {
            list(&sftp, &listing, &conn, current).await;
        }
        conn.repaint();
    });
}

async fn transfer(sftp: &SftpSession, dir: Direction, progress: impl Fn(u64, u64)) -> Result<()> {
    let mut buf = vec![0u8; CHUNK];
    let mut done = 0u64;
    match dir {
        Direction::Download { remote, local } => {
            let total = sftp.metadata(remote.clone()).await?.size.unwrap_or(0);
            let mut source = sftp.open(remote).await?;
            let mut target = tokio::fs::File::create(&local).await?;
            loop {
                let n = source.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                target.write_all(&buf[..n]).await?;
                done += n as u64;
                progress(done, total);
            }
            target.flush().await?;
        }
        Direction::Upload { local, remote_dir } => {
            let name = local.file_name().ok_or_else(|| anyhow!(t!("Ungültiger Dateiname", "Invalid file name")))?.to_string_lossy().into_owned();
            let total = tokio::fs::metadata(&local).await?.len();
            let mut source = tokio::fs::File::open(&local).await?;
            let mut target = sftp.create(join(&remote_dir, &name)).await?;
            loop {
                let n = source.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                target.write_all(&buf[..n]).await?;
                done += n as u64;
                progress(done, total);
            }
            target.shutdown().await?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- Oberfläche

/// Kleine Eingabedialoge des Browsers.
enum Edit {
    Mkdir(String),
    Rename { from: String, to: String },
    Delete { name: String, is_dir: bool },
}

#[derive(Default)]
pub struct SftpView {
    path_input: String,
    path_shown: String,
    selected: Option<String>,
    edit: Option<Edit>,
    overlay: ConnOverlay,
}

impl SftpView {
    pub fn show(&mut self, ui: &mut egui::Ui, session: &SftpSessionHandle) -> TabResponse {
        let mut out = TabResponse::default();
        let status = session.conn().status();
        let rect = ui.available_rect_before_wrap();
        if matches!(status, Status::Connected) {
            self.browser(ui, session);
        } else {
            ui.allocate_rect(rect, egui::Sense::hover());
        }
        self.overlay.show(ui, rect, session.conn(), &status, &mut out);
        out
    }

    fn browser(&mut self, ui: &mut egui::Ui, session: &SftpSessionHandle) {
        let (path, home, entries, loading, error, transfers) = {
            let l = session.listing();
            (l.path.clone(), l.home.clone(), l.entries.clone(), l.loading, l.error.clone(), l.transfers.clone())
        };
        if self.path_shown != path {
            self.path_shown = path.clone();
            self.path_input = path.clone();
            self.selected = None;
        }

        // Dateien aus dem Finder/Explorer ins Fenster ziehen = hochladen.
        for file in ui.ctx().input(|i| i.raw.dropped_files.clone()) {
            if let Some(local) = file.path {
                session.send(Cmd::Upload { local, remote_dir: path.clone() });
            }
        }

        ui.horizontal(|ui| {
            if ui.button("⬆").on_hover_text(ts!("Übergeordneter Ordner", "Parent folder")).clicked() {
                session.send(Cmd::List(parent(&path)));
            }
            if ui.button("🏠").on_hover_text(ts!("Home-Verzeichnis", "Home directory")).clicked() {
                session.send(Cmd::List(home.clone()));
            }
            if ui.button("🔄").on_hover_text(ts!("Aktualisieren", "Refresh")).clicked() {
                session.send(Cmd::List(path.clone()));
            }
            let field = ui.add(egui::TextEdit::singleline(&mut self.path_input).desired_width(ui.available_width() - 230.0));
            if field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                session.send(Cmd::List(self.path_input.clone()));
            }
            if ui.button(ts!("📁 Neuer Ordner", "📁 New folder")).clicked() {
                self.edit = Some(Edit::Mkdir(String::new()));
            }
            if ui.button(ts!("⬆ Hochladen …", "⬆ Upload …")).clicked() {
                for local in rfd::FileDialog::new().set_title(ts!("Dateien hochladen", "Upload files")).pick_files().unwrap_or_default() {
                    session.send(Cmd::Upload { local, remote_dir: path.clone() });
                }
            }
            if loading {
                ui.spinner();
            }
        });
        if let Some(error) = &error {
            ui.colored_label(ui.visuals().error_fg_color, format!("⚠ {error}"));
        }
        ui.separator();

        let transfer_height = if transfers.is_empty() { 0.0 } else { 24.0 * transfers.len().min(4) as f32 + 12.0 };
        let table_height = (ui.available_height() - transfer_height).max(80.0);
        ui.allocate_ui(egui::vec2(ui.available_width(), table_height), |ui| self.table(ui, session, &path, &entries));

        if !transfers.is_empty() {
            ui.separator();
            egui::ScrollArea::vertical().id_salt("transfers").max_height(transfer_height).show(ui, |ui| {
                for t in transfers.iter().rev() {
                    ui.horizontal(|ui| {
                        ui.label(&t.label);
                        match &t.state {
                            TransferState::Running => {
                                let fraction = if t.total > 0 { t.done as f32 / t.total as f32 } else { 0.0 };
                                ui.add(egui::ProgressBar::new(fraction).desired_width(200.0).text(format!(
                                    "{} / {}",
                                    human_size(t.done),
                                    human_size(t.total)
                                )));
                            }
                            TransferState::Done => {
                                ui.weak(format!("✔ {}", human_size(t.done)));
                            }
                            TransferState::Failed(e) => {
                                ui.colored_label(ui.visuals().error_fg_color, format!("✖ {e}"));
                            }
                        }
                    });
                }
            });
        }

        self.edit_dialog(ui.ctx(), session, &path);
    }

    fn table(&mut self, ui: &mut egui::Ui, session: &SftpSessionHandle, path: &str, entries: &[Entry]) {
        TableBuilder::new(ui)
            .striped(true)
            .sense(egui::Sense::click())
            .column(Column::remainder().at_least(200.0).clip(true))
            .column(Column::auto().at_least(80.0))
            .column(Column::auto().at_least(130.0))
            .column(Column::auto().at_least(90.0))
            .header(20.0, |mut header| {
                for title in [ts!("Name", "Name"), ts!("Größe", "Size"), ts!("Geändert", "Modified"), ts!("Rechte", "Permissions")] {
                    header.col(|ui| {
                        ui.strong(title);
                    });
                }
            })
            .body(|body| {
                body.rows(20.0, entries.len(), |mut row| {
                    let entry = &entries[row.index()];
                    row.set_selected(self.selected.as_deref() == Some(entry.name.as_str()));
                    row.col(|ui| {
                        let icon = if entry.is_dir {
                            "📁"
                        } else if entry.is_link {
                            "🔗"
                        } else {
                            "📄"
                        };
                        ui.label(format!("{icon}  {}", entry.name));
                    });
                    row.col(|ui| {
                        if !entry.is_dir {
                            ui.label(human_size(entry.size));
                        }
                    });
                    row.col(|ui| {
                        ui.label(entry.modified.map(format_time).unwrap_or_default());
                    });
                    row.col(|ui| {
                        ui.monospace(entry.permissions.map(format_mode).unwrap_or_default());
                    });

                    let response = row.response();
                    let remote = join(path, &entry.name);
                    if response.double_clicked() {
                        if entry.is_dir || entry.is_link {
                            session.send(Cmd::List(remote.clone()));
                        } else {
                            download(session, &remote, &entry.name);
                        }
                    } else if response.clicked() {
                        self.selected = Some(entry.name.clone());
                    }
                    response.context_menu(|ui| {
                        if entry.is_dir && ui.button(ts!("Öffnen", "Open")).clicked() {
                            session.send(Cmd::List(remote.clone()));
                            ui.close_menu();
                        }
                        if !entry.is_dir && ui.button(ts!("⬇ Herunterladen …", "⬇ Download …")).clicked() {
                            download(session, &remote, &entry.name);
                            ui.close_menu();
                        }
                        if ui.button(ts!("✏ Umbenennen …", "✏ Rename …")).clicked() {
                            self.edit = Some(Edit::Rename { from: entry.name.clone(), to: entry.name.clone() });
                            ui.close_menu();
                        }
                        if ui.button(ts!("🗑 Löschen …", "🗑 Delete …")).clicked() {
                            self.edit = Some(Edit::Delete { name: entry.name.clone(), is_dir: entry.is_dir });
                            ui.close_menu();
                        }
                    });
                });
            });
    }

    fn edit_dialog(&mut self, ctx: &egui::Context, session: &SftpSessionHandle, path: &str) {
        let Some(edit) = &mut self.edit else { return };
        let title = match edit {
            Edit::Mkdir(_) => ts!("Neuer Ordner", "New folder"),
            Edit::Rename { .. } => ts!("Umbenennen", "Rename"),
            Edit::Delete { .. } => ts!("Löschen", "Delete"),
        };
        let mut close = false;
        egui::Window::new(title).collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(ctx, |ui| {
            let mut submit = false;
            match edit {
                Edit::Mkdir(name) | Edit::Rename { to: name, .. } => {
                    let field = ui.add(egui::TextEdit::singleline(name).desired_width(280.0));
                    field.request_focus();
                    submit = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                }
                Edit::Delete { name, is_dir } => {
                    ui.label(if *is_dir {
                        t!("Ordner „{name}“ wirklich löschen?", "Really delete folder \"{name}\"?")
                    } else {
                        t!("Datei „{name}“ wirklich löschen?", "Really delete file \"{name}\"?")
                    });
                }
            }
            ui.horizontal(|ui| {
                let ok = if matches!(edit, Edit::Delete { .. }) { ts!("Löschen", "Delete") } else { "OK" };
                if ui.button(ok).clicked() || submit {
                    match edit {
                        Edit::Mkdir(name) if !name.trim().is_empty() => session.send(Cmd::Mkdir(join(path, name.trim()))),
                        Edit::Rename { from, to } if !to.trim().is_empty() && from != to => {
                            session.send(Cmd::Rename { from: join(path, from), to: join(path, to.trim()) })
                        }
                        Edit::Delete { name, is_dir } => session.send(Cmd::Delete { path: join(path, name), is_dir: *is_dir }),
                        _ => {}
                    }
                    close = true;
                }
                if ui.button(ts!("Abbrechen", "Cancel")).clicked() {
                    close = true;
                }
            });
        });
        if close {
            self.edit = None;
        }
    }
}

fn download(session: &SftpSessionHandle, remote: &str, name: &str) {
    let mut dialog = rfd::FileDialog::new().set_file_name(name);
    if let Some(dirs) = directories::UserDirs::new() {
        if let Some(downloads) = dirs.download_dir() {
            dialog = dialog.set_directory(downloads);
        }
    }
    if let Some(local) = dialog.save_file() {
        session.send(Cmd::Download { remote: remote.to_owned(), local });
    }
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn format_time(time: SystemTime) -> String {
    chrono::DateTime::<chrono::Local>::from(time).format("%d.%m.%Y %H:%M").to_string()
}

/// Unix-Rechte als `rwxr-xr-x`.
pub fn format_mode(mode: u32) -> String {
    let bits = [(0o400, 'r'), (0o200, 'w'), (0o100, 'x'), (0o040, 'r'), (0o020, 'w'), (0o010, 'x'), (0o004, 'r'), (0o002, 'w'), (0o001, 'x')];
    bits.iter().map(|&(bit, c)| if mode & bit != 0 { c } else { '-' }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(join("/home/u", "a.txt"), "/home/u/a.txt");
        assert_eq!(join("/", "etc"), "/etc");
        assert_eq!(parent("/home/u"), "/home");
        assert_eq!(parent("/home"), "/");
        assert_eq!(parent("/"), "/");
    }

    #[test]
    fn formatting() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1536), "1.5 KB");
        assert_eq!(format_mode(0o755), "rwxr-xr-x");
        assert_eq!(format_mode(0o640), "rw-r-----");
    }

    /// Gegen einen echten sshd (siehe ssh::tests): auflisten, hochladen, herunterladen,
    /// Ordner anlegen, umbenennen und löschen.
    #[test]
    fn renders_browser() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let ctx = egui::Context::default();
        let session = SftpSessionHandle::start(runtime.handle(), ctx.clone(), crate::ssh::tests::e2e_params(1));
        // Erst den Verbindungsversuch zu Port 1 scheitern lassen, dann Zustand von Hand setzen.
        crate::ssh::tests::wait_for(session.conn(), "Fehlschlag", |s| matches!(s, Status::Closed(_)));
        session.conn().set_status(Status::Connected);
        {
            let mut l = session.listing();
            l.path = "/home/u".into();
            l.home = "/home/u".into();
            l.loading = false;
            l.entries = vec![
                Entry { name: "ordner".into(), is_dir: true, is_link: false, size: 0, modified: Some(SystemTime::now()), permissions: Some(0o755) },
                Entry { name: "datei.txt".into(), is_dir: false, is_link: false, size: 12345, modified: None, permissions: Some(0o644) },
            ];
            l.transfers = vec![
                Transfer { label: "⬆ a".into(), done: 5, total: 10, state: TransferState::Running },
                Transfer { label: "⬇ b".into(), done: 10, total: 10, state: TransferState::Done },
                Transfer { label: "⬇ c".into(), done: 0, total: 0, state: TransferState::Failed("kaputt".into()) },
            ];
        }
        let mut view = SftpView::default();
        for edit in [None, Some(Edit::Mkdir(String::new())), Some(Edit::Delete { name: "x".into(), is_dir: false })] {
            view.edit = edit;
            for _ in 0..2 {
                let _ = ctx.run(egui::RawInput::default(), |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        view.show(ui, &session);
                    });
                });
            }
        }
        assert_eq!(view.path_input, "/home/u");
    }

    /// Server ohne SFTP-Subsystem: klare Fehlermeldung statt endlosem „Verbinde …“.
    /// Läuft gegen einen sshd ohne `Subsystem sftp` (Port in CONNMGR_E2E_NOSFTP_PORT).
    #[test]
    #[ignore]
    fn e2e_sftp_missing_subsystem() {
        use crate::ssh::tests::e2e_params;
        let port: u16 = std::env::var("CONNMGR_E2E_NOSFTP_PORT").expect("CONNMGR_E2E_NOSFTP_PORT").parse().unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let session = SftpSessionHandle::start(runtime.handle(), egui::Context::default(), e2e_params(port));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match session.conn().status() {
                Status::Closed(msg) => {
                    assert!(msg.contains("kein SFTP"), "{msg}");
                    break;
                }
                Status::HostKey { .. } => session.conn().answer_host_key(true),
                Status::Connected => panic!("ohne Subsystem verbunden"),
                _ => {}
            }
            assert!(std::time::Instant::now() < deadline, "hängt");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[test]
    #[ignore]
    fn e2e_sftp() {
        use crate::ssh::tests::{e2e_params, e2e_port, wait_for};
        use std::time::{Duration, Instant};

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let session = SftpSessionHandle::start(runtime.handle(), egui::Context::default(), e2e_params(e2e_port()));
        wait_for(session.conn(), "SFTP-Verbindung", |s| matches!(s, Status::Connected));

        let until = |what: &str, cond: &dyn Fn(&Listing) -> bool| {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !cond(&session.listing()) {
                assert!(Instant::now() < deadline, "Zeitüberschreitung: {what} — {:?}", session.listing().error);
                std::thread::sleep(Duration::from_millis(20));
            }
        };
        until("Home-Liste", &|l| !l.loading && !l.path.is_empty());

        let work = std::env::temp_dir().join(format!("connmgr-sftp-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&work).unwrap();
        let remote_dir = join(&session.listing().path, &format!("connmgr-e2e-{}", uuid::Uuid::new_v4()));

        session.send(Cmd::Mkdir(remote_dir.clone()));
        session.send(Cmd::List(remote_dir.clone()));
        until("leerer Testordner", &|l| l.path == remote_dir && !l.loading);

        let data: Vec<u8> = (0..700_000u32).map(|i| (i % 251) as u8).collect();
        let local = work.join("daten.bin");
        std::fs::write(&local, &data).unwrap();
        session.send(Cmd::Upload { local, remote_dir: remote_dir.clone() });
        until("Upload sichtbar", &|l| l.entries.iter().any(|e| e.name == "daten.bin" && e.size == data.len() as u64));

        session.send(Cmd::Rename { from: join(&remote_dir, "daten.bin"), to: join(&remote_dir, "umbenannt.bin") });
        until("Umbenennung", &|l| l.entries.iter().any(|e| e.name == "umbenannt.bin"));

        let back = work.join("zurueck.bin");
        session.send(Cmd::Download { remote: join(&remote_dir, "umbenannt.bin"), local: back.clone() });
        until("Download", &|l| l.transfers.iter().filter(|t| matches!(t.state, TransferState::Done)).count() == 2);
        assert_eq!(std::fs::read(&back).unwrap(), data, "Inhalt nach Hin- und Rückweg identisch");

        session.send(Cmd::Delete { path: join(&remote_dir, "umbenannt.bin"), is_dir: false });
        until("Datei gelöscht", &|l| l.entries.is_empty());
        let parent_dir = parent(&remote_dir);
        session.send(Cmd::Delete { path: remote_dir.clone(), is_dir: true });
        session.send(Cmd::List(parent_dir.clone()));
        let name = remote_dir.rsplit('/').next().unwrap().to_owned();
        until("Ordner gelöscht", &|l| l.path == parent_dir && !l.entries.iter().any(|e| e.name == name));

        std::fs::remove_dir_all(work).unwrap();
    }
}
