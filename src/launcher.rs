//! Startet den jeweils passenden externen Client des Betriebssystems.

use std::io;
use std::process::Command;

use anyhow::{anyhow, Result};

use crate::model::{validate_host, validate_username, Connection, Protocol};

pub struct Launched {
    /// true, wenn der Client das Passwort direkt erhalten hat;
    /// sonst kopiert die App es in die Zwischenablage.
    pub password_consumed: bool,
    pub info: String,
}

/// `username`/`password` sind die effektiven Zugangsdaten (eigene, geerbte oder zugewiesene).
/// `ssh_env` sind zusätzliche Umgebungsvariablen für ssh/sftp (Askpass), leer = keine.
pub fn launch(conn: &Connection, username: &str, password: Option<&str>, ssh_env: &[(String, String)]) -> Result<Launched> {
    let conn = &Connection { username: username.to_owned(), ..conn.clone() };
    validate_host(&conn.host).map_err(|e| anyhow!(e))?;
    validate_username(&conn.username).map_err(|e| anyhow!(e))?;

    match conn.protocol {
        Protocol::Ssh => {
            open_terminal("ssh", &["-p".into(), conn.port.to_string(), ssh_target(conn)], ssh_env)?;
            Ok(Launched { password_consumed: !ssh_env.is_empty(), info: t!("SSH-Sitzung im Terminal gestartet", "SSH session started in terminal") })
        }
        Protocol::Sftp => {
            open_terminal("sftp", &["-P".into(), conn.port.to_string(), ssh_target(conn)], ssh_env)?;
            Ok(Launched { password_consumed: !ssh_env.is_empty(), info: t!("SFTP-Sitzung im Terminal gestartet", "SFTP session started in terminal") })
        }
        Protocol::Rdp => rdp(conn, password),
        Protocol::Vnc => vnc(conn),
    }
}

fn ssh_target(conn: &Connection) -> String {
    if conn.username.is_empty() {
        conn.host.clone()
    } else {
        format!("{}@{}", conn.username, conn.host)
    }
}

/// Startet einen Prozess und räumt ihn im Hintergrund ab, damit keine Zombies bleiben.
fn spawn_detached(cmd: &mut Command) -> io::Result<()> {
    let mut child = cmd.spawn()?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

fn not_found<'a>(program: &'a str, hint: &str) -> impl FnOnce(io::Error) -> anyhow::Error + 'a {
    let hint = hint.to_owned();
    move |e| {
        if e.kind() == io::ErrorKind::NotFound {
            anyhow!(t!("{program} nicht gefunden. {hint}", "{program} not found. {hint}"))
        } else {
            anyhow!(t!("{program} konnte nicht gestartet werden: {e}", "Could not start {program}: {e}"))
        }
    }
}

// ---------------------------------------------------------------- Terminal

#[cfg(target_os = "macos")]
fn open_terminal(program: &str, args: &[String], env: &[(String, String)]) -> Result<()> {
    let env_prefix = if env.is_empty() { None } else { Some("env".to_owned()) };
    let cmd = env_prefix
        .into_iter()
        .chain(env.iter().map(|(k, v)| shell_quote(&format!("{k}={v}"))))
        .chain(std::iter::once(program.to_owned()))
        .chain(args.iter().map(|a| shell_quote(a)))
        .collect::<Vec<_>>()
        .join(" ");
    let script = format!(
        "tell application \"Terminal\"\n  activate\n  do script \"{}\"\nend tell",
        cmd.replace('\\', "\\\\").replace('"', "\\\"")
    );
    spawn_detached(Command::new("osascript").arg("-e").arg(script).stdout(std::process::Stdio::null())).map_err(not_found("osascript", ""))
}

#[cfg(target_os = "macos")]
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(target_os = "windows")]
const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[cfg(target_os = "windows")]
fn open_terminal(program: &str, args: &[String], env: &[(String, String)]) -> Result<()> {
    use std::os::windows::process::CommandExt;
    spawn_detached(Command::new(program).args(args).envs(env.iter().map(|(k, v)| (k, v))).creation_flags(CREATE_NEW_CONSOLE))
        .map_err(not_found(program, ts!("OpenSSH-Client unter Einstellungen → Optionale Features installieren.", "Install the OpenSSH client under Settings → Optional features.")))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn open_terminal(program: &str, args: &[String], env: &[(String, String)]) -> Result<()> {
    // Viele Terminals reichen ihre Umgebung nicht an neue Fenster durch, daher `env`.
    let env_args: Vec<String> = env.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let (program, args): (&str, Vec<&str>) = if env.is_empty() {
        (program, args.iter().map(String::as_str).collect())
    } else {
        ("env", env_args.iter().map(String::as_str).chain([program]).chain(args.iter().map(String::as_str)).collect())
    };
    const TERMINALS: &[(&str, &[&str])] = &[
        ("x-terminal-emulator", &["-e"]),
        ("gnome-terminal", &["--"]),
        ("konsole", &["-e"]),
        ("xfce4-terminal", &["-x"]),
        ("alacritty", &["-e"]),
        ("kitty", &[]),
        ("wezterm", &["start", "--"]),
        ("xterm", &["-e"]),
    ];
    for (term, prefix) in TERMINALS {
        match spawn_detached(Command::new(term).args(*prefix).arg(program).args(&args)) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(anyhow!(t!("{term} konnte nicht gestartet werden: {e}", "Could not start {term}: {e}"))),
        }
    }
    Err(anyhow!(t!("Kein Terminal-Emulator gefunden", "No terminal emulator found")))
}

// ---------------------------------------------------------------- RDP

#[cfg(target_os = "windows")]
fn rdp(conn: &Connection, password: Option<&str>) -> Result<Launched> {
    use std::os::windows::process::CommandExt;
    // mstsc nimmt kein Passwort an; cmdkey hinterlegt es in der Windows-Anmeldeinformationsverwaltung.
    let mut consumed = false;
    if let (Some(pw), false) = (password, conn.username.is_empty()) {
        let status = Command::new("cmdkey")
            .arg(format!("/generic:TERMSRV/{}", conn.host))
            .arg(format!("/user:{}", conn.username))
            .arg(format!("/pass:{pw}"))
            .creation_flags(CREATE_NO_WINDOW)
            .status()?;
        consumed = status.success();
    }
    spawn_detached(Command::new("mstsc").arg(format!("/v:{}", conn.host_port()))).map_err(not_found("mstsc", ""))?;
    Ok(Launched { password_consumed: consumed, info: t!("Remotedesktopverbindung gestartet", "Remote Desktop Connection started") })
}

#[cfg(target_os = "macos")]
fn rdp(conn: &Connection, _password: Option<&str>) -> Result<Launched> {
    // .rdp-Dateien öffnet die "Windows App" (ehem. Microsoft Remote Desktop); sie nimmt kein Passwort entgegen.
    let safe_id: String = conn.id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').collect();
    let path = std::env::temp_dir().join(format!("connmgr-{safe_id}.rdp"));
    let mut content = format!("full address:s:{}\r\n", conn.host_port());
    if !conn.username.is_empty() {
        content.push_str(&format!("username:s:{}\r\n", conn.username));
    }
    std::fs::write(&path, content)?;
    spawn_detached(Command::new("open").arg(&path)).map_err(not_found("open", ""))?;
    Ok(Launched {
        password_consumed: false,
        info: t!("RDP-Datei geöffnet (benötigt die Microsoft \"Windows App\")", "RDP file opened (requires the Microsoft \"Windows App\")"),
    })
}

#[cfg(all(unix, not(target_os = "macos")))]
fn rdp(conn: &Connection, password: Option<&str>) -> Result<Launched> {
    // FreeRDP überschreibt /p: nach dem Parsen in argv, das Passwort ist danach nicht mehr in `ps` sichtbar.
    for bin in ["xfreerdp3", "xfreerdp", "wlfreerdp"] {
        let mut cmd = Command::new(bin);
        cmd.arg(format!("/v:{}", conn.host_port()));
        if !conn.username.is_empty() {
            cmd.arg(format!("/u:{}", conn.username));
        }
        if let Some(pw) = password {
            cmd.arg(format!("/p:{pw}"));
        }
        match spawn_detached(&mut cmd) {
            Ok(()) => {
                return Ok(Launched { password_consumed: password.is_some(), info: t!("{bin} gestartet", "{bin} started") });
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(anyhow!(t!("{bin} konnte nicht gestartet werden: {e}", "Could not start {bin}: {e}"))),
        }
    }
    Err(anyhow!(t!("FreeRDP nicht gefunden. Paket freerdp3-x11 oder freerdp2-x11 installieren.", "FreeRDP not found. Install the freerdp3-x11 or freerdp2-x11 package.")))
}

// ---------------------------------------------------------------- VNC

#[cfg(target_os = "macos")]
fn vnc(conn: &Connection) -> Result<Launched> {
    // Öffnet die eingebaute Bildschirmfreigabe.
    let user = if conn.username.is_empty() { String::new() } else { format!("{}@", percent_encode(&conn.username)) };
    let url = format!("vnc://{user}{}", conn.host_port());
    spawn_detached(Command::new("open").arg(url)).map_err(not_found("open", ""))?;
    Ok(Launched { password_consumed: false, info: t!("Bildschirmfreigabe geöffnet", "Screen Sharing opened") })
}

#[cfg(target_os = "macos")]
fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(not(target_os = "macos"))]
fn vnc(conn: &Connection) -> Result<Launched> {
    // TigerVNC/TightVNC/RealVNC: "host::port" bezeichnet einen TCP-Port statt einer Display-Nummer.
    let host = if conn.host.contains(':') { format!("[{}]", conn.host) } else { conn.host.clone() };
    spawn_detached(Command::new("vncviewer").arg(format!("{host}::{}", conn.port)))
        .map_err(not_found("vncviewer", ts!("TigerVNC Viewer installieren und in den PATH aufnehmen.", "Install TigerVNC Viewer and add it to PATH.")))?;
    Ok(Launched { password_consumed: false, info: t!("VNC-Viewer gestartet", "VNC viewer started") })
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
        assert_eq!(percent_encode("max mü"), "max%20m%C3%BC");
    }
}
