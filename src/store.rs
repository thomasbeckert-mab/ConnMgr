use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{Encrypted, KdfParams, Vault};
use crate::i18n::Language;
use crate::model::{Connection, CredentialSource, Node, SecretField};

const FORMAT_VERSION: u32 = 2;
const VERIFIER_PLAINTEXT: &str = "conmgr-verifier-v1";
const VERIFIER_AAD: &str = "verifier";

/// Inhalt der Verbindungsdatei. Nur die Passwörter sind verschlüsselt,
/// alles andere bleibt lesbares JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreFile {
    pub version: u32,
    pub kdf: KdfParams,
    /// Bekannter Klartext, verschlüsselt — prüft das Master-Passwort beim Entsperren.
    pub verifier: Encrypted,
    /// Baum aus Ordnern, Verbindungen und Zugangsdaten.
    pub items: Vec<Node>,
    #[serde(default)]
    pub settings: Settings,
}

/// Oberflächen-Einstellungen, die mit der Datei wandern (unverschlüsselt, schon vor dem Entsperren lesbar).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// `false`: Der Verbindungsbaum blendet sich aus und erscheint beim Darüberfahren am linken Rand.
    #[serde(default = "default_true")]
    pub tree_pinned: bool,
    /// `None` = Sprache des Betriebssystems.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<Language>,
    #[serde(default)]
    pub theme: Theme,
    /// Letzte Schnellverbindungen (nur Adressen, keine Passwörter), neueste zuerst.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quick_history: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self { tree_pinned: true, language: None, theme: Theme::System, quick_history: Vec::new() }
    }
}

impl Settings {
    const QUICK_HISTORY_LEN: usize = 10;

    pub fn remember_quick(&mut self, input: &str) {
        self.quick_history.retain(|entry| entry != input);
        self.quick_history.insert(0, input.to_owned());
        self.quick_history.truncate(Self::QUICK_HISTORY_LEN);
    }

    pub fn effective_language(&self) -> Language {
        self.language.unwrap_or_else(Language::system)
    }

    /// Liest nur die Einstellungen aus einer (noch gesperrten) Verbindungsdatei.
    pub fn read(path: &Path) -> Option<Self> {
        StoreFile::load(path).ok().map(|store| store.settings)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    /// Hell oder dunkel wie das Betriebssystem.
    #[default]
    System,
    Light,
    Dark,
}

impl Theme {
    pub fn preference(self) -> eframe::egui::ThemePreference {
        match self {
            Theme::System => eframe::egui::ThemePreference::System,
            Theme::Light => eframe::egui::ThemePreference::Light,
            Theme::Dark => eframe::egui::ThemePreference::Dark,
        }
    }
}

fn default_true() -> bool {
    true
}

/// Format 1: flache Verbindungsliste ohne Ordner und Zugangsdaten-Objekte.
#[derive(Deserialize)]
struct StoreFileV1 {
    kdf: KdfParams,
    verifier: Encrypted,
    connections: Vec<Connection>,
}

#[derive(Deserialize)]
struct VersionOnly {
    version: u32,
}

impl StoreFile {
    pub fn create(master: &str) -> Result<(Self, Vault)> {
        let kdf = KdfParams::new_random();
        let vault = Vault::derive(master, &kdf)?;
        let verifier = vault.encrypt_str(VERIFIER_PLAINTEXT, VERIFIER_AAD)?;
        let store = Self { version: FORMAT_VERSION, kdf, verifier, items: Vec::new(), settings: Settings::default() };
        Ok((store, vault))
    }

    pub fn unlock(&self, master: &str) -> Result<Vault> {
        let vault = Vault::derive(master, &self.kdf)?;
        match vault.decrypt_str(&self.verifier, VERIFIER_AAD) {
            Ok(pt) if pt.as_str() == VERIFIER_PLAINTEXT => Ok(vault),
            _ => Err(anyhow!(t!("Falsches Master-Passwort", "Wrong master password"))),
        }
    }

    /// Lädt die Datei; Format 1 wird beim Laden in Format 2 überführt.
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path).with_context(|| t!("{} kann nicht gelesen werden", "Cannot read {}", path.display()))?;
        let corrupt = || t!("{} ist beschädigt", "{} is corrupt", path.display());
        let VersionOnly { version } = serde_json::from_str(&text).with_context(corrupt)?;
        match version {
            1 => {
                let v1: StoreFileV1 = serde_json::from_str(&text).with_context(corrupt)?;
                Ok(Self {
                    version: FORMAT_VERSION,
                    kdf: v1.kdf,
                    verifier: v1.verifier,
                    items: v1.connections.into_iter().map(Node::Connection).collect(),
                    settings: Settings::default(),
                })
            }
            FORMAT_VERSION => serde_json::from_str(&text).with_context(corrupt),
            other => bail!(t!("Nicht unterstützte Dateiversion {other}", "Unsupported file version {other}")),
        }
    }

    /// Schreibt atomar (temporäre Datei + rename), unter Unix mit Rechten 0600.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_string_pretty(self)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        }
        fs::rename(&tmp, path)?;
        Ok(())
    }
}

/// Verschlüsselt ein Passwort; ein leeres Passwort wird nicht gespeichert.
/// `owner_id` (ID der Verbindung bzw. Zugangsdaten) ist die Associated Data.
pub fn encrypt_secret(vault: &Vault, owner_id: &str, password: &str) -> Result<Option<Encrypted>> {
    if password.is_empty() {
        return Ok(None);
    }
    Ok(Some(vault.encrypt_str(password, owner_id)?))
}

pub fn decrypt_secret(vault: &Vault, owner_id: &str, enc: Option<&Encrypted>) -> Result<Option<Zeroizing<String>>> {
    enc.map(|e| vault.decrypt_str(e, owner_id)).transpose()
}

/// Entschlüsselt alle Geheimnisse eines Eintrags (ohne Kinder) mit `from` und der
/// bisherigen ID und verschlüsselt sie mit `to` für die aktuelle ID des Eintrags neu.
/// Dient zum Duplizieren, Master-Passwort-Wechsel sowie Import und Export.
pub fn reencrypt(node: &mut Node, old_id: &str, from: &Vault, to: &Vault) -> Result<()> {
    let new_id = node.id().to_owned();
    for (field, secret) in node.secrets_mut() {
        if let Some(enc) = secret.as_ref() {
            let plain = from.decrypt_str(enc, &field.aad(old_id))?;
            *secret = Some(to.encrypt_str(&plain, &field.aad(&new_id))?);
        }
    }
    Ok(())
}

/// Tiefe Kopie mit neuen IDs. Geheimnisse werden von `from` nach `to` umverschlüsselt,
/// Verweise innerhalb der Kopie auf mitkopierte Zugangsdaten zeigen auf deren Kopien.
pub fn copy_subtree(node: &Node, from: &Vault, to: &Vault) -> Result<Node> {
    fn assign(node: &mut Node, ids: &mut HashMap<String, String>, from: &Vault, to: &Vault) -> Result<()> {
        let old_id = node.id().to_owned();
        let new_id = uuid::Uuid::new_v4().to_string();
        node.set_id(new_id.clone());
        reencrypt(node, &old_id, from, to)?;
        ids.insert(old_id, new_id);
        if let Node::Folder(f) = node {
            for child in &mut f.children {
                assign(child, ids, from, to)?;
            }
        }
        Ok(())
    }
    fn remap(node: &mut Node, ids: &HashMap<String, String>) {
        match node {
            Node::Folder(f) => {
                if let Some(new) = f.credential_id.as_ref().and_then(|id| ids.get(id)) {
                    f.credential_id = Some(new.clone());
                }
                f.children.iter_mut().for_each(|c| remap(c, ids));
            }
            Node::Connection(c) => {
                if let CredentialSource::Stored { id } = &mut c.credentials {
                    if let Some(new) = ids.get(id) {
                        *id = new.clone();
                    }
                }
            }
            Node::Credential(_) => {}
        }
    }
    let mut copy = node.clone();
    let mut ids = HashMap::new();
    assign(&mut copy, &mut ids, from, to)?;
    remap(&mut copy, &ids);
    Ok(copy)
}

/// Verschlüsselt alle Geheimnisse im Baum mit `to` neu (IDs bleiben).
pub fn reencrypt_tree(nodes: &mut [Node], from: &Vault, to: &Vault) -> Result<()> {
    for node in nodes {
        let id = node.id().to_owned();
        reencrypt(node, &id, from, to)?;
        if let Node::Folder(f) = node {
            reencrypt_tree(&mut f.children, from, to)?;
        }
    }
    Ok(())
}

impl StoreFile {
    /// Neues Master-Passwort: neues Salt, neuer Schlüssel, alle Geheimnisse umverschlüsselt.
    pub fn change_master(&mut self, old: &Vault, new_master: &str) -> Result<Vault> {
        let (fresh, vault) = StoreFile::create(new_master)?;
        let mut items = self.items.clone();
        reencrypt_tree(&mut items, old, &vault)?;
        *self = StoreFile { items, settings: self.settings.clone(), ..fresh };
        Ok(vault)
    }

    /// Schreibt die Einträge in eine eigene, mit `password` geschützte Datei.
    pub fn export(nodes: &[Node], vault: &Vault, password: &str, path: &Path) -> Result<()> {
        let (mut export, export_vault) = StoreFile::create(password)?;
        export.items = nodes.iter().map(|n| copy_subtree(n, vault, &export_vault)).collect::<Result<_>>()?;
        export.save(path)
    }

    /// Liest eine Export- oder Verbindungsdatei und liefert ihre Einträge,
    /// mit neuen IDs und für `vault` umverschlüsselt.
    pub fn import(path: &Path, password: &str, vault: &Vault) -> Result<Vec<Node>> {
        let file = StoreFile::load(path)?;
        let file_vault = file.unlock(password).map_err(|_| anyhow!(t!("Falsches Passwort für {}", "Wrong password for {}", path.display())))?;
        file.items.iter().map(|n| copy_subtree(n, &file_vault, vault)).collect()
    }
}

/// Verschlüsselt ein Geheimnis eines Eintrags; leer = nicht speichern.
pub fn encrypt_field(vault: &Vault, owner_id: &str, field: SecretField, value: &str) -> Result<Option<Encrypted>> {
    encrypt_secret(vault, &field.aad(owner_id), value)
}

pub fn decrypt_field(
    vault: &Vault,
    owner_id: &str,
    field: SecretField,
    enc: Option<&Encrypted>,
) -> Result<Option<Zeroizing<String>>> {
    decrypt_secret(vault, &field.aad(owner_id), enc)
}

/// z. B. ~/Library/Application Support/ConMgr/connections.json (macOS),
/// ~/.config/conmgr/connections.json (Linux), %APPDATA%\ConMgr\config\connections.json (Windows).
pub fn default_path() -> PathBuf {
    directories::ProjectDirs::from("", "", "ConMgr")
        .map(|d| d.config_dir().join("connections.json"))
        .unwrap_or_else(|| PathBuf::from("connections.json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{self, CredentialSource, Credential};

    fn temp_path() -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("conmgr-test-{}", uuid::Uuid::new_v4()));
        let path = dir.join("connections.json");
        (dir, path)
    }

    #[test]
    fn save_load_unlock() {
        let (dir, path) = temp_path();
        let (mut store, vault) = StoreFile::create("master").unwrap();
        store.items.push(Node::Credential(Credential {
            id: "cred".into(),
            name: "Admin".into(),
            username: "root".into(),
            password: encrypt_secret(&vault, "cred", "s3cret").unwrap(),
            private_key: None,
            passphrase: None,
            icon: None,
            color: None,
        }));
        store.items.push(model::tests::conn("web", CredentialSource::Stored { id: "cred".into() }));
        store.save(&path).unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("s3cret"), "Passwort darf nicht im Klartext gespeichert werden");

        let loaded = StoreFile::load(&path).unwrap();
        assert!(loaded.unlock("falsch").is_err());
        let vault = loaded.unlock("master").unwrap();
        let conn = model::find_connection(&loaded.items, "web").unwrap();
        let resolved = model::resolve(&loaded.items, conn).unwrap().unwrap();
        let pw = decrypt_field(&vault, resolved.owner_id, SecretField::Password, resolved.password).unwrap().unwrap();
        assert_eq!(pw.as_str(), "s3cret");

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reencrypt_moves_secrets_to_new_id_and_vault() {
        let (_, old) = StoreFile::create("alt").unwrap();
        let (_, new) = StoreFile::create("neu").unwrap();
        let mut node = Node::Credential(Credential {
            id: "a".into(),
            name: "x".into(),
            username: "u".into(),
            password: encrypt_field(&old, "a", SecretField::Password, "pw").unwrap(),
            private_key: encrypt_field(&old, "a", SecretField::PrivateKey, "KEY").unwrap(),
            passphrase: None,
            icon: None,
            color: None,
        });
        node.set_id("b".into());
        reencrypt(&mut node, "a", &old, &new).unwrap();
        let Node::Credential(c) = &node else { unreachable!() };
        let key = decrypt_field(&new, "b", SecretField::PrivateKey, c.private_key.as_ref()).unwrap().unwrap();
        assert_eq!(key.as_str(), "KEY");
        assert!(c.passphrase.is_none());
        // Feld-AAD verhindert Vertauschen: Schlüssel-Chiffrat ist kein gültiges Passwort.
        assert!(decrypt_field(&new, "b", SecretField::Password, c.private_key.as_ref()).is_err());
    }

    fn sample_tree(vault: &Vault) -> Vec<Node> {
        let mut cred = Credential {
            id: "c".into(),
            name: "Admin".into(),
            username: "root".into(),
            password: None,
            private_key: None,
            passphrase: None,
            icon: None,
            color: None,
        };
        cred.password = encrypt_field(vault, "c", SecretField::Password, "pw").unwrap();
        vec![
            model::tests::folder(
                "f",
                Some("c"),
                vec![Node::Credential(cred), model::tests::conn("x", CredentialSource::Stored { id: "c".into() })],
            ),
            model::tests::conn("outside", CredentialSource::Stored { id: "c".into() }),
        ]
    }

    #[test]
    fn copy_subtree_remaps_ids_and_references() {
        let (_, vault) = StoreFile::create("m").unwrap();
        let tree = sample_tree(&vault);
        let copy = copy_subtree(&tree[0], &vault, &vault).unwrap();
        let Node::Folder(f) = &copy else { unreachable!() };
        assert_ne!(f.id, "f");
        let new_cred = model::credentials(std::slice::from_ref(&copy))[0].clone();
        assert_ne!(new_cred.id, "c");
        assert_eq!(f.credential_id.as_deref(), Some(new_cred.id.as_str()));
        let Node::Connection(x) = &f.children[1] else { unreachable!() };
        assert_eq!(x.credentials, CredentialSource::Stored { id: new_cred.id.clone() });
        let pw = decrypt_field(&vault, &new_cred.id, SecretField::Password, new_cred.password.as_ref()).unwrap().unwrap();
        assert_eq!(pw.as_str(), "pw");
    }

    #[test]
    fn change_master_and_export_import() {
        let (dir, path) = temp_path();
        let (mut store, vault) = StoreFile::create("alt").unwrap();
        store.items = sample_tree(&vault);
        let new_vault = store.change_master(&vault, "neu").unwrap();
        store.save(&path).unwrap();
        let loaded = StoreFile::load(&path).unwrap();
        assert!(loaded.unlock("alt").is_err());
        let vault = loaded.unlock("neu").unwrap();
        let c = model::find_credential(&loaded.items, "c").unwrap();
        assert_eq!(decrypt_field(&vault, "c", SecretField::Password, c.password.as_ref()).unwrap().unwrap().as_str(), "pw");
        drop(new_vault);

        let export_path = dir.join("export.json");
        StoreFile::export(&loaded.items[..1], &vault, "export-pw", &export_path).unwrap();
        assert!(StoreFile::import(&export_path, "falsch", &vault).is_err());
        let (_, other) = StoreFile::create("anderer").unwrap();
        let imported = StoreFile::import(&export_path, "export-pw", &other).unwrap();
        let cred = model::credentials(&imported)[0];
        let pw = decrypt_field(&other, &cred.id, SecretField::Password, cred.password.as_ref()).unwrap().unwrap();
        assert_eq!(pw.as_str(), "pw");

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn migrates_v1() {
        let (dir, path) = temp_path();
        let (store, vault) = StoreFile::create("master").unwrap();
        let password = encrypt_secret(&vault, "abc", "alt").unwrap().unwrap();
        let v1 = serde_json::json!({
            "version": 1,
            "kdf": store.kdf,
            "verifier": store.verifier,
            "connections": [{
                "id": "abc", "name": "Alt", "host": "10.0.0.1", "port": 22,
                "protocol": "ssh", "username": "root", "password": password
            }]
        });
        fs::create_dir_all(&dir).unwrap();
        fs::write(&path, v1.to_string()).unwrap();

        let loaded = StoreFile::load(&path).unwrap();
        assert_eq!(loaded.version, 2);
        let vault = loaded.unlock("master").unwrap();
        let conn = model::find_connection(&loaded.items, "abc").unwrap();
        assert_eq!(conn.credentials, CredentialSource::Own);
        let pw = decrypt_secret(&vault, &conn.id, conn.password.as_ref()).unwrap().unwrap();
        assert_eq!(pw.as_str(), "alt");

        fs::remove_dir_all(dir).unwrap();
    }
}
