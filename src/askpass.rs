//! Übergibt Passwörter an `ssh`/`sftp` über `SSH_ASKPASS`.
//!
//! Die App startet einen lokalen Server (nur 127.0.0.1) und gibt pro Verbindung ein
//! einmaliges Zufallstoken aus. ssh ruft dann dieses Programm selbst als Askpass-Helfer
//! auf; der Helfer tauscht das Token gegen das Passwort. Alle anderen Rückfragen
//! (Host-Key, Passphrase, zweiter Versuch) beantwortet der Benutzer im Terminal.

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

/// Gesetzt, wenn dieses Programm als Askpass-Helfer läuft: `<adresse>/<token>`.
pub const ENV_VAR: &str = "CONMGR_ASKPASS";
const TICKET_TTL: Duration = Duration::from_secs(120);
const IO_TIMEOUT: Duration = Duration::from_secs(5);

type Tickets = Arc<Mutex<HashMap<String, (Instant, Zeroizing<String>)>>>;

pub struct Server {
    addr: SocketAddr,
    tickets: Tickets,
}

impl Server {
    pub fn start() -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let addr = listener.local_addr()?;
        let tickets: Tickets = Arc::default();
        let shared = Arc::clone(&tickets);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let _ = serve(stream, &shared);
            }
        });
        Ok(Self { addr, tickets })
    }

    /// Hinterlegt das Passwort und liefert die Umgebungsvariablen für den ssh-Prozess.
    pub fn issue(&self, password: Zeroizing<String>) -> io::Result<Vec<(String, String)>> {
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let mut tickets = self.tickets.lock().unwrap();
        tickets.retain(|_, (created, _)| created.elapsed() < TICKET_TTL);
        tickets.insert(token.clone(), (Instant::now(), password));
        drop(tickets);

        let exe = std::env::current_exe()?.to_string_lossy().into_owned();
        Ok(vec![
            ("SSH_ASKPASS".into(), exe),
            ("SSH_ASKPASS_REQUIRE".into(), "force".into()),
            (ENV_VAR.into(), format!("{}/{token}", self.addr)),
        ])
    }
}

/// Protokoll: Token + `\n` hin, Passwort zurück (leer, wenn unbekannt oder abgelaufen).
fn serve(stream: TcpStream, tickets: &Tickets) -> io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    let mut token = String::new();
    BufReader::new((&stream).take(128)).read_line(&mut token)?;
    let ticket = tickets.lock().unwrap().remove(token.trim());
    if let Some((created, password)) = ticket {
        if created.elapsed() < TICKET_TTL {
            (&stream).write_all(password.as_bytes())?;
        }
    }
    Ok(())
}

fn fetch(spec: &str) -> io::Result<Option<Zeroizing<String>>> {
    let (addr, token) = spec.split_once('/').ok_or_else(|| io::Error::other(ts!("ungültige Askpass-Angabe", "invalid askpass spec")))?;
    let addr: SocketAddr = addr.parse().map_err(io::Error::other)?;
    let mut stream = TcpStream::connect_timeout(&addr, IO_TIMEOUT)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.write_all(format!("{token}\n").as_bytes())?;
    let mut password = Zeroizing::new(String::new());
    stream.read_to_string(&mut password)?;
    Ok(Some(password).filter(|p| !p.is_empty()))
}

fn is_password_prompt(prompt: &str) -> bool {
    let p = prompt.to_lowercase();
    p.contains("password") && !p.contains("passphrase")
}

/// Einstieg, wenn ssh dieses Programm als Askpass-Helfer startet. Liefert den Exit-Code.
pub fn run_helper(spec: &str, prompt: &str) -> i32 {
    if is_password_prompt(prompt) {
        if let Ok(Some(password)) = fetch(spec) {
            println!("{}", password.as_str());
            return 0;
        }
    }
    match prompt_terminal(prompt) {
        Ok(answer) => {
            println!("{}", answer.as_str());
            0
        }
        Err(_) => 1,
    }
}

/// Fragt im Terminal nach, in dem ssh läuft. Ja/Nein-Fragen mit Echo, alles andere verdeckt.
fn prompt_terminal(prompt: &str) -> io::Result<Zeroizing<String>> {
    #[cfg(windows)]
    attach_parent_console();
    if prompt.contains("(yes/no") {
        read_line_from_terminal(prompt)
    } else {
        rpassword::prompt_password(prompt).map(Zeroizing::new)
    }
}

#[cfg(unix)]
fn read_line_from_terminal(prompt: &str) -> io::Result<Zeroizing<String>> {
    let mut tty = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    tty.write_all(prompt.as_bytes())?;
    tty.flush()?;
    let mut line = String::new();
    BufReader::new(tty).read_line(&mut line)?;
    Ok(Zeroizing::new(line.trim_end().to_owned()))
}

#[cfg(windows)]
fn read_line_from_terminal(prompt: &str) -> io::Result<Zeroizing<String>> {
    let mut out = std::fs::OpenOptions::new().write(true).open("CONOUT$")?;
    out.write_all(prompt.as_bytes())?;
    let mut line = String::new();
    BufReader::new(std::fs::File::open("CONIN$")?).read_line(&mut line)?;
    Ok(Zeroizing::new(line.trim_end().to_owned()))
}

/// Das Release-Programm hat unter Windows keine eigene Konsole; die von ssh übernehmen.
#[cfg(windows)]
fn attach_parent_console() {
    extern "system" {
        fn AttachConsole(process_id: u32) -> i32;
    }
    const ATTACH_PARENT_PROCESS: u32 = u32::MAX;
    unsafe {
        AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_of(env: &[(String, String)]) -> String {
        env.iter().find(|(k, _)| k == ENV_VAR).unwrap().1.clone()
    }

    #[test]
    fn ticket_is_single_use() {
        let server = Server::start().unwrap();
        let env = server.issue(Zeroizing::new("s3cret".into())).unwrap();
        let spec = spec_of(&env);
        assert_eq!(fetch(&spec).unwrap().unwrap().as_str(), "s3cret");
        assert!(fetch(&spec).unwrap().is_none(), "Token darf nur einmal gelten");
    }

    #[test]
    fn unknown_token_gets_nothing() {
        let server = Server::start().unwrap();
        let spec = spec_of(&server.issue(Zeroizing::new("x".into())).unwrap());
        let (addr, _) = spec.split_once('/').unwrap();
        assert!(fetch(&format!("{addr}/falsch")).unwrap().is_none());
    }

    /// Startet das gebaute Programm so, wie ssh es als Askpass-Helfer aufruft.
    #[test]
    fn helper_binary_end_to_end() {
        let exe = std::env::current_exe().unwrap().parent().unwrap().parent().unwrap().join("conmgr");
        assert!(exe.exists(), "{} fehlt — vorher `cargo build` ausführen", exe.display());
        let server = Server::start().unwrap();
        let env = server.issue(Zeroizing::new("s3cret".into())).unwrap();
        let run = || {
            std::process::Command::new(&exe)
                .envs(env.iter().map(|(k, v)| (k, v)))
                .arg("root@10.0.0.1's password: ")
                .stdin(std::process::Stdio::null())
                .output()
                .unwrap()
        };
        let first = run();
        assert!(first.status.success());
        assert_eq!(String::from_utf8_lossy(&first.stdout), "s3cret\n");
        // Token verbraucht, kein Terminal vorhanden → Helfer scheitert, ssh fragt nicht endlos.
        assert!(!run().status.success());
    }

    #[test]
    fn prompt_classification() {
        assert!(is_password_prompt("root@10.0.0.1's password: "));
        assert!(is_password_prompt("(root@host) Password: "));
        assert!(!is_password_prompt("Enter passphrase for key '/Users/x/.ssh/id_ed25519': "));
        assert!(!is_password_prompt("Are you sure you want to continue connecting (yes/no/[fingerprint])? "));
    }
}
