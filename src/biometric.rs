//! Entsperren per Touch ID (macOS).
//!
//! Den Schlüssel der Verbindungsdatei (nicht das Master-Passwort) legt ConnMgr im
//! Anmelde-Schlüsselbund ab; herausgegeben wird er erst nach erfolgreicher Touch-ID-Abfrage.
//! Einträge, an denen macOS selbst den Fingerabdruck erzwingt, verlangen eine Apple-Developer-ID
//! (sonst Fehler -34018). Bei unserer selbst signierten App erzwingt deshalb ConnMgr die Abfrage;
//! der Eintrag ist für andere Programme nur nach Rückfrage von macOS lesbar.

use std::path::Path;

use zeroize::Zeroizing;

#[cfg(target_os = "macos")]
mod imp {
    use std::path::Path;
    use std::sync::mpsc;

    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};
    use security_framework::passwords::{delete_generic_password, generic_password, set_generic_password, PasswordOptions};
    use zeroize::Zeroizing;

    const SERVICE: &str = "app.connmgr.unlock";
    /// errSecItemNotFound
    const NOT_FOUND: i32 = -25300;
    /// LAErrorUserCancel, LAErrorUserFallback („Passwort eingeben“), LAErrorSystemCancel, LAErrorAppCancel
    const CANCELLED: [isize; 4] = [-2, -3, -4, -9];

    /// Ein Eintrag pro Verbindungsdatei.
    fn account(file: &Path) -> String {
        file.canonicalize().unwrap_or_else(|_| file.to_owned()).display().to_string()
    }

    pub fn available() -> bool {
        unsafe { LAContext::new().canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics).is_ok() }
    }

    /// Blockiert bis zur Antwort; nicht im Haupt-Thread aufrufen. `Err(None)` = abgebrochen.
    pub fn authenticate(reason: &str) -> Result<(), Option<String>> {
        let (tx, rx) = mpsc::channel();
        let context = unsafe { LAContext::new() };
        let reply = RcBlock::new(move |success: Bool, error: *mut NSError| {
            let result = if success.as_bool() {
                Ok(())
            } else {
                match unsafe { error.as_ref() } {
                    Some(e) if CANCELLED.contains(&e.code()) => Err(None),
                    Some(e) => Err(Some(e.localizedDescription().to_string())),
                    None => Err(None),
                }
            };
            let _ = tx.send(result);
        });
        unsafe {
            context.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
                &NSString::from_str(reason),
                &reply,
            );
        }
        rx.recv().unwrap_or(Err(None))
    }

    pub fn store_key(file: &Path, key: &[u8]) -> Result<(), String> {
        set_generic_password(SERVICE, &account(file), key).map_err(|e| e.to_string())
    }

    pub fn load_key(file: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        match generic_password(PasswordOptions::new_generic_password(SERVICE, &account(file))) {
            Ok(key) => Ok(Some(Zeroizing::new(key))),
            Err(e) if e.code() == NOT_FOUND => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn delete_key(file: &Path) {
        let _ = delete_generic_password(SERVICE, &account(file));
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use std::path::Path;

    use zeroize::Zeroizing;

    pub fn available() -> bool {
        false
    }

    pub fn authenticate(_reason: &str) -> Result<(), Option<String>> {
        Err(None)
    }

    pub fn store_key(_file: &Path, _key: &[u8]) -> Result<(), String> {
        Err("Touch ID gibt es nur unter macOS".into())
    }

    pub fn load_key(_file: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        Ok(None)
    }

    pub fn delete_key(_file: &Path) {}
}

/// Touch ID eingerichtet und nutzbar?
pub fn available() -> bool {
    imp::available()
}

/// Fragt den Fingerabdruck ab und liefert danach den gespeicherten Schlüssel.
/// `Err(None)` heißt abgebrochen (z. B. „Passwort eingeben“ gewählt).
pub fn unlock(file: &Path) -> Result<Zeroizing<Vec<u8>>, Option<String>> {
    imp::authenticate(ts!("ConnMgr entsperren", "unlock ConnMgr"))?;
    match imp::load_key(file) {
        Ok(Some(key)) => Ok(key),
        Ok(None) => Err(Some(t!("Kein gespeicherter Schlüssel — bitte Master-Passwort eingeben", "No stored key — please enter the master password"))),
        Err(e) => Err(Some(e)),
    }
}

pub fn store_key(file: &Path, key: &[u8]) -> Result<(), String> {
    imp::store_key(file, key)
}

pub fn delete_key(file: &Path) {
    imp::delete_key(file);
}
