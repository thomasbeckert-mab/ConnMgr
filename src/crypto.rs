use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, bail, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Parameter der Schlüsselableitung aus dem Master-Passwort (Argon2id).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: String,
    pub salt: String,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// OWASP-Empfehlung für Argon2id: 19 MiB, 2 Iterationen, 1 Thread.
    pub fn new_random() -> Self {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        Self {
            algorithm: "argon2id".into(),
            salt: B64.encode(salt),
            m_cost: 19 * 1024,
            t_cost: 2,
            p_cost: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Encrypted {
    pub nonce: String,
    pub data: String,
}

/// Hält den abgeleiteten Schlüssel; wird beim Drop genullt.
pub struct Vault {
    key: Zeroizing<[u8; 32]>,
}

impl Vault {
    pub fn derive(master: &str, kdf: &KdfParams) -> Result<Self> {
        if kdf.algorithm != "argon2id" {
            bail!(t!("Unbekannter KDF-Algorithmus: {}", "Unknown KDF algorithm: {}", kdf.algorithm));
        }
        let salt = B64.decode(&kdf.salt)?;
        let params = Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(32)).map_err(|e| anyhow!("{e}"))?;
        let mut key = Zeroizing::new([0u8; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(master.as_bytes(), &salt, &mut key[..])
            .map_err(|e| anyhow!("{e}"))?;
        Ok(Self { key })
    }

    /// Für das Entsperren per Touch ID: Schlüssel im Schlüsselbund ablegen und wiederherstellen.
    pub fn key_bytes(&self) -> &[u8] {
        &self.key[..]
    }

    pub fn from_key(bytes: &[u8]) -> Result<Self> {
        let key: [u8; 32] = bytes.try_into().map_err(|_| anyhow!(t!("Ungültige Schlüssellänge", "Invalid key length")))?;
        Ok(Self { key: Zeroizing::new(key) })
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new_from_slice(&self.key[..]).expect("Schlüssel ist 32 Byte lang")
    }

    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Encrypted> {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let data = self
            .cipher()
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })
            .map_err(|_| anyhow!(t!("Verschlüsselung fehlgeschlagen", "Encryption failed")))?;
        Ok(Encrypted { nonce: B64.encode(nonce), data: B64.encode(data) })
    }

    pub fn decrypt(&self, enc: &Encrypted, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let nonce = B64.decode(&enc.nonce)?;
        if nonce.len() != 12 {
            bail!(t!("Ungültige Nonce-Länge", "Invalid nonce length"));
        }
        let data = B64.decode(&enc.data)?;
        let plaintext = self
            .cipher()
            .decrypt(Nonce::from_slice(&nonce), Payload { msg: &data, aad })
            .map_err(|_| anyhow!(t!("Entschlüsselung fehlgeschlagen (falscher Schlüssel oder beschädigte Daten)", "Decryption failed (wrong key or corrupt data)")))?;
        Ok(Zeroizing::new(plaintext))
    }

    pub fn encrypt_str(&self, plaintext: &str, aad: &str) -> Result<Encrypted> {
        self.encrypt(plaintext.as_bytes(), aad.as_bytes())
    }

    pub fn decrypt_str(&self, enc: &Encrypted, aad: &str) -> Result<Zeroizing<String>> {
        let bytes = self.decrypt(enc, aad.as_bytes())?;
        let s = std::str::from_utf8(&bytes).map_err(|_| anyhow!(t!("Passwort ist kein gültiges UTF-8", "Password is not valid UTF-8")))?;
        Ok(Zeroizing::new(s.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let kdf = KdfParams::new_random();
        let vault = Vault::derive("geheim", &kdf).unwrap();
        let enc = vault.encrypt_str("p@ssw0rd", "id-1").unwrap();
        assert_eq!(vault.decrypt_str(&enc, "id-1").unwrap().as_str(), "p@ssw0rd");
    }

    #[test]
    fn wrong_key_or_aad_fails() {
        let kdf = KdfParams::new_random();
        let vault = Vault::derive("geheim", &kdf).unwrap();
        let enc = vault.encrypt_str("p@ssw0rd", "id-1").unwrap();
        assert!(vault.decrypt_str(&enc, "id-2").is_err());
        let other = Vault::derive("falsch", &kdf).unwrap();
        assert!(other.decrypt_str(&enc, "id-1").is_err());
    }

    #[test]
    fn nonces_are_unique() {
        let vault = Vault::derive("geheim", &KdfParams::new_random()).unwrap();
        let a = vault.encrypt_str("x", "id").unwrap();
        let b = vault.encrypt_str("x", "id").unwrap();
        assert_ne!(a.nonce, b.nonce);
    }
}
