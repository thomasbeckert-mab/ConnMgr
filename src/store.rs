use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{Encrypted, KdfParams, Vault};
use crate::model::{Connection, Node};

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
        let store = Self { version: FORMAT_VERSION, kdf, verifier, items: Vec::new() };
        Ok((store, vault))
    }

    pub fn unlock(&self, master: &str) -> Result<Vault> {
        let vault = Vault::derive(master, &self.kdf)?;
        match vault.decrypt_str(&self.verifier, VERIFIER_AAD) {
            Ok(pt) if pt.as_str() == VERIFIER_PLAINTEXT => Ok(vault),
            _ => Err(anyhow!("Falsches Master-Passwort")),
        }
    }

    /// Lädt die Datei; Format 1 wird beim Laden in Format 2 überführt.
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path).with_context(|| format!("{} kann nicht gelesen werden", path.display()))?;
        let corrupt = || format!("{} ist beschädigt", path.display());
        let VersionOnly { version } = serde_json::from_str(&text).with_context(corrupt)?;
        match version {
            1 => {
                let v1: StoreFileV1 = serde_json::from_str(&text).with_context(corrupt)?;
                Ok(Self {
                    version: FORMAT_VERSION,
                    kdf: v1.kdf,
                    verifier: v1.verifier,
                    items: v1.connections.into_iter().map(Node::Connection).collect(),
                })
            }
            FORMAT_VERSION => serde_json::from_str(&text).with_context(corrupt),
            other => bail!("Nicht unterstützte Dateiversion {other}"),
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
        let pw = decrypt_secret(&vault, resolved.aad, resolved.password).unwrap().unwrap();
        assert_eq!(pw.as_str(), "s3cret");

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
