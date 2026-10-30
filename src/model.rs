use serde::{Deserialize, Serialize};

use crate::crypto::Encrypted;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Ssh,
    Sftp,
    Rdp,
    Vnc,
}

impl Protocol {
    pub const ALL: [Protocol; 4] = [Protocol::Ssh, Protocol::Sftp, Protocol::Rdp, Protocol::Vnc];

    pub fn default_port(self) -> u16 {
        match self {
            Protocol::Ssh | Protocol::Sftp => 22,
            Protocol::Rdp => 3389,
            Protocol::Vnc => 5900,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Protocol::Ssh => "SSH",
            Protocol::Sftp => "SFTP",
            Protocol::Rdp => "RDP",
            Protocol::Vnc => "VNC",
        }
    }

    pub fn default_icon(self) -> &'static str {
        match self {
            Protocol::Ssh => "💻",
            Protocol::Sftp => "🗄",
            Protocol::Rdp => "🖥",
            Protocol::Vnc => "📺",
        }
    }
}

/// Woher eine Verbindung Benutzer und Passwort bezieht.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum CredentialSource {
    /// Benutzer/Passwort direkt an der Verbindung.
    #[default]
    Own,
    /// Zugangsdaten des nächsten übergeordneten Ordners, der welche zugewiesen hat.
    Inherit,
    /// Ein bestimmtes Zugangsdaten-Objekt.
    Stored { id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub protocol: Protocol,
    #[serde(default)]
    pub credentials: CredentialSource,
    #[serde(default)]
    pub username: String,
    /// AES-256-GCM-verschlüsselt, die Verbindungs-ID dient als Associated Data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Encrypted>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub favorite: bool,
}

impl Connection {
    /// Host als `host:port`, IPv6-Adressen in eckigen Klammern.
    pub fn host_port(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub username: String,
    /// Verschlüsselt mit der Zugangsdaten-ID als Associated Data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Encrypted>,
    /// Privater SSH-Schlüssel (OpenSSH-/PEM-/PuTTY-Text), verschlüsselt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<Encrypted>,
    /// Passphrase des Schlüssels, verschlüsselt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<Encrypted>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
}

/// Verschlüsselte Felder eines Eintrags. Jedes hat eigene Associated Data,
/// damit sich Chiffrate weder zwischen Einträgen noch zwischen Feldern vertauschen lassen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretField {
    Password,
    PrivateKey,
    Passphrase,
}

impl SecretField {
    pub fn aad(self, owner_id: &str) -> String {
        match self {
            // Passwörter nutzen seit Format 1 die reine ID.
            SecretField::Password => owner_id.to_owned(),
            SecretField::PrivateKey => format!("{owner_id}/private_key"),
            SecretField::Passphrase => format!("{owner_id}/passphrase"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Folder {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    /// Zugangsdaten, die Verbindungen mit `CredentialSource::Inherit` erben.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(default = "default_true")]
    pub expanded: bool,
    #[serde(default)]
    pub children: Vec<Node>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Node {
    Folder(Folder),
    Connection(Connection),
    Credential(Credential),
}

impl Node {
    pub fn id(&self) -> &str {
        match self {
            Node::Folder(f) => &f.id,
            Node::Connection(c) => &c.id,
            Node::Credential(c) => &c.id,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Node::Folder(f) => &f.name,
            Node::Connection(c) => &c.name,
            Node::Credential(c) => &c.name,
        }
    }

    pub fn icon(&self) -> &str {
        let custom = match self {
            Node::Folder(f) => &f.icon,
            Node::Connection(c) => &c.icon,
            Node::Credential(c) => &c.icon,
        };
        match (custom.as_deref(), self) {
            (Some(icon), _) if !icon.is_empty() => icon,
            (_, Node::Folder(f)) if f.expanded => "📂",
            (_, Node::Folder(_)) => "📁",
            (_, Node::Connection(c)) => c.protocol.default_icon(),
            (_, Node::Credential(_)) => "🔑",
        }
    }

    /// Alle verschlüsselten Felder dieses Eintrags (ohne Kinder).
    pub fn secrets_mut(&mut self) -> Vec<(SecretField, &mut Option<Encrypted>)> {
        match self {
            Node::Folder(_) => Vec::new(),
            Node::Connection(c) => vec![(SecretField::Password, &mut c.password)],
            Node::Credential(c) => vec![
                (SecretField::Password, &mut c.password),
                (SecretField::PrivateKey, &mut c.private_key),
                (SecretField::Passphrase, &mut c.passphrase),
            ],
        }
    }

    pub fn name_mut(&mut self) -> &mut String {
        match self {
            Node::Folder(f) => &mut f.name,
            Node::Connection(c) => &mut c.name,
            Node::Credential(c) => &mut c.name,
        }
    }

    pub fn set_id(&mut self, id: String) {
        match self {
            Node::Folder(f) => f.id = id,
            Node::Connection(c) => c.id = id,
            Node::Credential(c) => c.id = id,
        }
    }

    pub fn color(&self) -> Option<&str> {
        match self {
            Node::Folder(f) => f.color.as_deref(),
            Node::Connection(c) => c.color.as_deref(),
            Node::Credential(c) => c.color.as_deref(),
        }
    }
}

// ---------------------------------------------------------------- Baum-Operationen

pub fn find<'a>(nodes: &'a [Node], id: &str) -> Option<&'a Node> {
    for node in nodes {
        if node.id() == id {
            return Some(node);
        }
        if let Node::Folder(f) = node {
            if let Some(found) = find(&f.children, id) {
                return Some(found);
            }
        }
    }
    None
}

pub fn find_mut<'a>(nodes: &'a mut [Node], id: &str) -> Option<&'a mut Node> {
    for node in nodes.iter_mut() {
        if node.id() == id {
            return Some(node);
        }
        if let Node::Folder(f) = node {
            if let Some(found) = find_mut(&mut f.children, id) {
                return Some(found);
            }
        }
    }
    None
}

pub fn find_connection<'a>(nodes: &'a [Node], id: &str) -> Option<&'a Connection> {
    match find(nodes, id) {
        Some(Node::Connection(c)) => Some(c),
        _ => None,
    }
}

pub fn find_credential<'a>(nodes: &'a [Node], id: &str) -> Option<&'a Credential> {
    match find(nodes, id) {
        Some(Node::Credential(c)) => Some(c),
        _ => None,
    }
}

/// Ordnerpfad von der Wurzel bis zum direkten Elternordner von `id`.
pub fn path_to<'a>(nodes: &'a [Node], id: &str) -> Option<Vec<&'a Folder>> {
    for node in nodes {
        if node.id() == id {
            return Some(Vec::new());
        }
        if let Node::Folder(f) = node {
            if let Some(mut path) = path_to(&f.children, id) {
                path.insert(0, f);
                return Some(path);
            }
        }
    }
    None
}

/// ID des Elternordners; `None` für Einträge auf oberster Ebene.
pub fn parent_id(nodes: &[Node], id: &str) -> Option<String> {
    path_to(nodes, id).and_then(|p| p.last().map(|f| f.id.clone()))
}

/// Alle Zugangsdaten-Objekte im Baum, in Baumreihenfolge.
pub fn credentials(nodes: &[Node]) -> Vec<&Credential> {
    let mut out = Vec::new();
    fn walk<'a>(nodes: &'a [Node], out: &mut Vec<&'a Credential>) {
        for node in nodes {
            match node {
                Node::Credential(c) => out.push(c),
                Node::Folder(f) => walk(&f.children, out),
                Node::Connection(_) => {}
            }
        }
    }
    walk(nodes, &mut out);
    out
}

pub fn contains(node: &Node, id: &str) -> bool {
    node.id() == id || matches!(node, Node::Folder(f) if f.children.iter().any(|c| contains(c, id)))
}

pub fn count(node: &Node) -> usize {
    match node {
        Node::Folder(f) => 1 + f.children.iter().map(count).sum::<usize>(),
        _ => 1,
    }
}

pub fn remove(nodes: &mut Vec<Node>, id: &str) -> Option<Node> {
    if let Some(pos) = nodes.iter().position(|n| n.id() == id) {
        return Some(nodes.remove(pos));
    }
    for node in nodes.iter_mut() {
        if let Node::Folder(f) = node {
            if let Some(removed) = remove(&mut f.children, id) {
                return Some(removed);
            }
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Root,
    /// Als letztes Kind in diesen Ordner.
    Into(String),
    /// Vor diesem Eintrag, auf derselben Ebene.
    Before(String),
    /// Nach diesem Eintrag, auf derselben Ebene.
    After(String),
}

// Bei Fehlschlag kommt der Knoten zurück, damit er nicht verloren geht.
#[allow(clippy::result_large_err)]
pub fn insert(nodes: &mut Vec<Node>, target: &Target, node: Node) -> Result<(), Node> {
    match target {
        Target::Root => {
            nodes.push(node);
            Ok(())
        }
        Target::Into(folder_id) => match find_mut(nodes, folder_id) {
            Some(Node::Folder(f)) => {
                f.children.push(node);
                f.expanded = true;
                Ok(())
            }
            _ => Err(node),
        },
        Target::Before(sibling) => insert_next_to(nodes, sibling, 0, node),
        Target::After(sibling) => insert_next_to(nodes, sibling, 1, node),
    }
}

#[allow(clippy::result_large_err)]
fn insert_next_to(nodes: &mut Vec<Node>, sibling: &str, offset: usize, node: Node) -> Result<(), Node> {
    if let Some(pos) = nodes.iter().position(|n| n.id() == sibling) {
        nodes.insert(pos + offset, node);
        return Ok(());
    }
    let mut node = node;
    for n in nodes.iter_mut() {
        if let Node::Folder(f) = n {
            match insert_next_to(&mut f.children, sibling, offset, node) {
                Ok(()) => return Ok(()),
                Err(back) => node = back,
            }
        }
    }
    Err(node)
}

/// Verschiebt einen Eintrag; ein Ordner kann nicht in sich selbst verschoben werden.
pub fn move_node(nodes: &mut Vec<Node>, id: &str, target: &Target) -> Result<(), String> {
    let moving = find(nodes, id).ok_or_else(|| t!("Eintrag nicht gefunden", "Entry not found"))?;
    if let Target::Into(t) | Target::Before(t) | Target::After(t) = target {
        if contains(moving, t) {
            return Err(t!("Ein Ordner kann nicht in sich selbst verschoben werden", "A folder cannot be moved into itself"));
        }
    }
    let node = remove(nodes, id).ok_or_else(|| t!("Eintrag nicht gefunden", "Entry not found"))?;
    if let Err(node) = insert(nodes, target, node) {
        nodes.push(node);
        return Err(t!("Ziel nicht gefunden, Eintrag auf oberste Ebene verschoben", "Target not found, entry moved to the top level"));
    }
    Ok(())
}

/// Anzahl der Ordner und Verbindungen, die auf diese Zugangsdaten verweisen.
pub fn references_to(nodes: &[Node], cred_id: &str) -> usize {
    nodes
        .iter()
        .map(|n| match n {
            Node::Folder(f) => usize::from(f.credential_id.as_deref() == Some(cred_id)) + references_to(&f.children, cred_id),
            Node::Connection(c) => usize::from(matches!(&c.credentials, CredentialSource::Stored { id } if id == cred_id)),
            Node::Credential(_) => 0,
        })
        .sum()
}

/// Entfernt Verweise auf gelöschte Zugangsdaten. Betroffene Verbindungen fallen auf
/// leere eigene Zugangsdaten zurück, damit sie nicht stillschweigend andere erben.
pub fn clear_credential_references(nodes: &mut [Node], cred_id: &str) {
    for node in nodes {
        match node {
            Node::Folder(f) => {
                if f.credential_id.as_deref() == Some(cred_id) {
                    f.credential_id = None;
                }
                clear_credential_references(&mut f.children, cred_id);
            }
            Node::Connection(c) => {
                if matches!(&c.credentials, CredentialSource::Stored { id } if id == cred_id) {
                    c.credentials = CredentialSource::Own;
                }
            }
            Node::Credential(_) => {}
        }
    }
}

/// Entfernt Verweise auf Zugangsdaten, die es im Baum nicht gibt (z. B. nach einem Import).
pub fn drop_dangling_references(nodes: &mut [Node]) {
    fn referenced(nodes: &[Node], out: &mut Vec<String>) {
        for node in nodes {
            match node {
                Node::Folder(f) => {
                    out.extend(f.credential_id.clone());
                    referenced(&f.children, out);
                }
                Node::Connection(c) => {
                    if let CredentialSource::Stored { id } = &c.credentials {
                        out.push(id.clone());
                    }
                }
                Node::Credential(_) => {}
            }
        }
    }
    let mut ids = Vec::new();
    referenced(nodes, &mut ids);
    for id in ids {
        if find_credential(nodes, &id).is_none() {
            clear_credential_references(nodes, &id);
        }
    }
}

// ---------------------------------------------------------------- Zugangsdaten auflösen

/// Effektive Zugangsdaten einer Verbindung.
pub struct Resolved<'a> {
    pub username: &'a str,
    /// ID des Eintrags, dem die Geheimnisse gehören (für die Associated Data).
    pub owner_id: &'a str,
    pub password: Option<&'a Encrypted>,
    pub private_key: Option<&'a Encrypted>,
    pub passphrase: Option<&'a Encrypted>,
}

/// Erste Zugangsdaten entlang der Ordner oberhalb von `parent` (einschließlich `parent`).
pub fn inherited_credential<'a>(nodes: &'a [Node], parent: Option<&str>) -> Option<&'a Credential> {
    let parent = parent?;
    let mut chain = path_to(nodes, parent)?;
    if let Some(Node::Folder(f)) = find(nodes, parent) {
        chain.push(f);
    }
    chain.iter().rev().find_map(|f| f.credential_id.as_deref().and_then(|cid| find_credential(nodes, cid)))
}

pub fn resolve<'a>(nodes: &'a [Node], conn: &'a Connection) -> Result<Option<Resolved<'a>>, String> {
    let from_credential = |c: &'a Credential| Resolved {
        username: &c.username,
        owner_id: &c.id,
        password: c.password.as_ref(),
        private_key: c.private_key.as_ref(),
        passphrase: c.passphrase.as_ref(),
    };
    match &conn.credentials {
        CredentialSource::Own => {
            if conn.username.is_empty() && conn.password.is_none() {
                return Ok(None);
            }
            Ok(Some(Resolved {
                username: &conn.username,
                owner_id: &conn.id,
                password: conn.password.as_ref(),
                private_key: None,
                passphrase: None,
            }))
        }
        CredentialSource::Stored { id } => find_credential(nodes, id)
            .map(|c| Some(from_credential(c)))
            .ok_or_else(|| t!("Zugangsdaten für „{}“ nicht gefunden", "Credentials for \"{}\" not found", conn.name)),
        CredentialSource::Inherit => {
            let parent = parent_id(nodes, &conn.id);
            Ok(inherited_credential(nodes, parent.as_deref()).map(from_credential))
        }
    }
}

// ---------------------------------------------------------------- Validierung

/// Verhindert, dass Host oder Benutzer als Kommandozeilenoption interpretiert werden.
pub fn validate_host(host: &str) -> Result<(), String> {
    if host.is_empty() {
        return Err(t!("Host/IP darf nicht leer sein", "Host/IP must not be empty"));
    }
    if host.starts_with('-') || !host.chars().all(|c| c.is_ascii_alphanumeric() || ".-_:%".contains(c)) {
        return Err(t!("Ungültiger Host: {host}", "Invalid host: {host}"));
    }
    Ok(())
}

pub fn validate_username(user: &str) -> Result<(), String> {
    // `@` ist erlaubt (UPN wie benutzer@firma.de); ssh trennt Benutzer und Host am letzten `@`.
    if user.starts_with('-') || user.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(t!("Ungültiger Benutzername: {user}", "Invalid user name: {user}"));
    }
    Ok(())
}

/// Ziel einer Schnellverbindung (ohne gespeicherten Eintrag).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickTarget {
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub username: String,
}

/// Versteht `rdp://host`, `ssh://user@host:2222`, `user@host`, `host:3389`, `[::1]:22` usw.
/// Ohne Schema entscheidet der Port: 3389 = RDP, 5900–5999 = VNC, sonst SSH.
pub fn parse_quick(input: &str) -> Result<QuickTarget, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err(t!("Bitte eine Adresse eingeben", "Please enter an address"));
    }
    let (scheme, rest) = match input.split_once("://") {
        Some((scheme, rest)) => (Some(scheme.to_lowercase()), rest),
        None => (None, input),
    };
    let explicit = match scheme.as_deref() {
        None => None,
        Some("ssh") => Some(Protocol::Ssh),
        Some("sftp") => Some(Protocol::Sftp),
        Some("rdp") => Some(Protocol::Rdp),
        Some("vnc") => Some(Protocol::Vnc),
        Some(other) => return Err(t!("Unbekanntes Protokoll: {other}", "Unknown protocol: {other}")),
    };
    let rest = rest.trim_end_matches('/');
    let (username, host_port) = match rest.rsplit_once('@') {
        Some((user, host)) => (user.to_owned(), host),
        None => (String::new(), rest),
    };
    let invalid_port = |p: &str| t!("Ungültiger Port: {p}", "Invalid port: {p}");
    let parse_port = |p: &str| p.parse::<u16>().ok().filter(|&p| p > 0).ok_or_else(|| invalid_port(p));
    let (host, port) = if let Some(bracketed) = host_port.strip_prefix('[') {
        let (host, after) = bracketed.split_once(']').ok_or_else(|| t!("Fehlende „]“", "Missing \"]\""))?;
        (host, after.strip_prefix(':').map(parse_port).transpose()?)
    } else if host_port.matches(':').count() == 1 {
        let (host, port) = host_port.split_once(':').expect("ein Doppelpunkt");
        (host, Some(parse_port(port)?))
    } else {
        // Ohne Klammern ist eine IPv6-Adresse nur Host, nicht Host:Port.
        (host_port, None)
    };
    let protocol = explicit.unwrap_or(match port {
        Some(3389) => Protocol::Rdp,
        Some(p) if (5900..=5999).contains(&p) => Protocol::Vnc,
        _ => Protocol::Ssh,
    });
    validate_host(host)?;
    validate_username(&username)?;
    Ok(QuickTarget { protocol, host: host.to_owned(), port: port.unwrap_or(protocol.default_port()), username })
}

pub fn parse_color(hex: &str) -> Option<[u8; 3]> {
    let hex = hex.strip_prefix('#')?;
    if hex.len() != 6 {
        return None;
    }
    let v = u32::from_str_radix(hex, 16).ok()?;
    Some([(v >> 16) as u8, (v >> 8) as u8, v as u8])
}

pub fn format_color(rgb: [u8; 3]) -> String {
    format!("#{:02x}{:02x}{:02x}", rgb[0], rgb[1], rgb[2])
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn conn(id: &str, credentials: CredentialSource) -> Node {
        Node::Connection(Connection {
            id: id.into(),
            name: id.into(),
            host: "10.0.0.1".into(),
            port: 22,
            protocol: Protocol::Ssh,
            credentials,
            username: String::new(),
            password: None,
            icon: None,
            color: None,
            favorite: false,
        })
    }

    pub fn folder(id: &str, credential_id: Option<&str>, children: Vec<Node>) -> Node {
        Node::Folder(Folder {
            id: id.into(),
            name: id.into(),
            icon: None,
            color: None,
            credential_id: credential_id.map(Into::into),
            expanded: true,
            children,
        })
    }

    pub fn cred(id: &str, user: &str) -> Node {
        Node::Credential(Credential {
            id: id.into(),
            name: id.into(),
            username: user.into(),
            password: None,
            private_key: None,
            passphrase: None,
            icon: None,
            color: None,
        })
    }

    fn sample() -> Vec<Node> {
        vec![
            folder("creds", None, vec![cred("admin", "root"), cred("deploy", "deploy")]),
            folder(
                "prod",
                Some("admin"),
                vec![
                    conn("web01", CredentialSource::Inherit),
                    folder("db", None, vec![conn("db01", CredentialSource::Inherit)]),
                    conn("web02", CredentialSource::Stored { id: "deploy".into() }),
                ],
            ),
            conn("lonely", CredentialSource::Inherit),
        ]
    }

    fn user_of(nodes: &[Node], id: &str) -> Option<String> {
        let c = find_connection(nodes, id).unwrap();
        resolve(nodes, c).unwrap().map(|r| r.username.to_owned())
    }

    #[test]
    fn credential_resolution() {
        let nodes = sample();
        assert_eq!(user_of(&nodes, "web01").as_deref(), Some("root"));
        assert_eq!(user_of(&nodes, "db01").as_deref(), Some("root"), "über zwei Ebenen geerbt");
        assert_eq!(user_of(&nodes, "web02").as_deref(), Some("deploy"));
        assert_eq!(user_of(&nodes, "lonely"), None);
    }

    #[test]
    fn missing_stored_credential_is_error() {
        let nodes = vec![conn("x", CredentialSource::Stored { id: "nope".into() })];
        assert!(resolve(&nodes, find_connection(&nodes, "x").unwrap()).is_err());
    }

    #[test]
    fn move_into_and_before() {
        let mut nodes = sample();
        move_node(&mut nodes, "lonely", &Target::Into("db".into())).unwrap();
        assert_eq!(parent_id(&nodes, "lonely").as_deref(), Some("db"));
        assert_eq!(user_of(&nodes, "lonely").as_deref(), Some("root"), "erbt nach dem Verschieben");

        move_node(&mut nodes, "web02", &Target::Before("creds".into())).unwrap();
        assert_eq!(nodes[0].id(), "web02");

        move_node(&mut nodes, "web02", &Target::After("creds".into())).unwrap();
        assert_eq!(nodes[1].id(), "web02");
    }

    #[test]
    fn deleting_credential_clears_references() {
        let mut nodes = sample();
        assert_eq!(references_to(&nodes, "admin"), 1);
        assert_eq!(references_to(&nodes, "deploy"), 1);
        remove(&mut nodes, "deploy");
        clear_credential_references(&mut nodes, "deploy");
        assert_eq!(find_connection(&nodes, "web02").unwrap().credentials, CredentialSource::Own);
        clear_credential_references(&mut nodes, "admin");
        assert_eq!(user_of(&nodes, "web01"), None);
    }

    #[test]
    fn cannot_move_folder_into_itself() {
        let mut nodes = sample();
        assert!(move_node(&mut nodes, "prod", &Target::Into("db".into())).is_err());
        assert!(move_node(&mut nodes, "prod", &Target::Into("prod".into())).is_err());
        assert!(find(&nodes, "db01").is_some(), "Baum unverändert");
    }

    #[test]
    fn credentials_listing_and_count() {
        let nodes = sample();
        let ids: Vec<_> = credentials(&nodes).iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, ["admin", "deploy"]);
        assert_eq!(count(find(&nodes, "prod").unwrap()), 5);
    }

    #[test]
    fn dangling_references_are_dropped() {
        let mut nodes = vec![folder("f", Some("weg"), vec![conn("x", CredentialSource::Stored { id: "weg".into() })]), cred("da", "u")];
        nodes.push(conn("y", CredentialSource::Stored { id: "da".into() }));
        drop_dangling_references(&mut nodes);
        let Node::Folder(f) = &nodes[0] else { unreachable!() };
        assert!(f.credential_id.is_none());
        assert_eq!(find_connection(&nodes, "x").unwrap().credentials, CredentialSource::Own);
        assert_eq!(find_connection(&nodes, "y").unwrap().credentials, CredentialSource::Stored { id: "da".into() });
    }

    #[test]
    fn host_validation() {
        assert!(validate_host("192.168.1.10").is_ok());
        assert!(validate_host("server.example.com").is_ok());
        assert!(validate_host("fe80::1%en0").is_ok());
        assert!(validate_host("").is_err());
        assert!(validate_host("-oProxyCommand=x").is_err());
        assert!(validate_host("a b").is_err());
        assert!(validate_host("a;rm").is_err());
    }

    #[test]
    fn username_validation() {
        assert!(validate_username("root").is_ok());
        assert!(validate_username("FIRMA\\admin").is_ok());
        assert!(validate_username("admin@firma.de").is_ok());
        assert!(validate_username("-oProxyCommand=x").is_err());
        assert!(validate_username("a b").is_err());
    }

    #[test]
    fn ipv6_host_port() {
        let Node::Connection(mut c) = conn("x", CredentialSource::Own) else { unreachable!() };
        c.host = "::1".into();
        c.port = 3389;
        assert_eq!(c.host_port(), "[::1]:3389");
    }

    #[test]
    fn quick_connect_parsing() {
        let q = |input: &str| parse_quick(input).map(|t| (t.protocol, t.host, t.port, t.username));
        assert_eq!(q("rdp://server"), Ok((Protocol::Rdp, "server".into(), 3389, String::new())));
        assert_eq!(q("ssh://admin@10.0.0.5:2222"), Ok((Protocol::Ssh, "10.0.0.5".into(), 2222, "admin".into())));
        assert_eq!(q("admin@web01"), Ok((Protocol::Ssh, "web01".into(), 22, "admin".into())));
        assert_eq!(q("host:3389"), Ok((Protocol::Rdp, "host".into(), 3389, String::new())));
        assert_eq!(q("host:5901"), Ok((Protocol::Vnc, "host".into(), 5901, String::new())));
        assert_eq!(q("SFTP://host/"), Ok((Protocol::Sftp, "host".into(), 22, String::new())));
        assert_eq!(q("[::1]:2222"), Ok((Protocol::Ssh, "::1".into(), 2222, String::new())));
        assert_eq!(q("fe80::1"), Ok((Protocol::Ssh, "fe80::1".into(), 22, String::new())));
        assert_eq!(q("FIRMA\\admin@dc01:3389"), Ok((Protocol::Rdp, "dc01".into(), 3389, "FIRMA\\admin".into())));
        assert!(q("").is_err());
        assert!(q("http://x").is_err());
        assert!(q("host:0").is_err());
        assert!(q("host:abc").is_err());
        assert!(q("-oProxyCommand=x").is_err());
    }

    #[test]
    fn colors() {
        assert_eq!(parse_color("#ff8000"), Some([255, 128, 0]));
        assert_eq!(format_color([255, 128, 0]), "#ff8000");
        assert_eq!(parse_color("red"), None);
    }
}
