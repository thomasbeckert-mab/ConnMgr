//! Zweisprachige Oberfläche (Deutsch/Englisch). Texte stehen direkt an der Verwendungsstelle:
//! `t!("Deutsch {x}", "English {x}")` liefert einen `String` (Platzhalter wie bei `format!`),
//! `ts!("Deutsch", "English")` einen `&'static str` für Texte ohne Platzhalter.

use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    German,
    English,
}

impl Language {
    /// Sprache des Betriebssystems; alles außer Deutsch wird Englisch.
    pub fn system() -> Self {
        // Tests prüfen deutsche Texte und sollen nicht von der Sprache des Rechners abhängen.
        if cfg!(test) {
            return Language::German;
        }
        match sys_locale::get_locale() {
            Some(locale) if locale.to_lowercase().starts_with("de") => Language::German,
            _ => Language::English,
        }
    }
}

static ENGLISH: AtomicBool = AtomicBool::new(false);

pub fn set_language(language: Language) {
    ENGLISH.store(language == Language::English, Ordering::Relaxed);
}

pub fn is_english() -> bool {
    #[cfg(test)]
    if let Some(english) = tests::THREAD_OVERRIDE.with(std::cell::Cell::get) {
        return english;
    }
    ENGLISH.load(Ordering::Relaxed)
}

pub fn pick(de: &'static str, en: &'static str) -> &'static str {
    if is_english() {
        en
    } else {
        de
    }
}

#[macro_export]
macro_rules! t {
    ($de:literal, $en:literal $(,)?) => {
        if $crate::i18n::is_english() { format!($en) } else { format!($de) }
    };
    ($de:literal, $en:literal, $($arg:tt)+) => {
        if $crate::i18n::is_english() { format!($en, $($arg)+) } else { format!($de, $($arg)+) }
    };
}

#[macro_export]
macro_rules! ts {
    ($de:literal, $en:literal $(,)?) => {
        $crate::i18n::pick($de, $en)
    };
}

#[cfg(test)]
pub mod tests {
    use std::cell::Cell;

    thread_local! {
        /// Sprache nur für den aktuellen Test-Thread. Die globale Einstellung bleibt Deutsch,
        /// damit parallel laufende Tests deutsche Meldungen prüfen können.
        pub static THREAD_OVERRIDE: Cell<Option<bool>> = const { Cell::new(None) };
    }

    pub fn force_english(english: Option<bool>) {
        THREAD_OVERRIDE.with(|o| o.set(english));
    }

    #[test]
    fn macros_switch_language_and_capture_arguments() {
        let name = "web01";
        force_english(Some(false));
        assert_eq!(t!("„{name}“ gespeichert", "\"{name}\" saved"), "„web01“ gespeichert");
        assert_eq!(t!("{} von {}", "{} of {}", 1, 2), "1 von 2");
        assert_eq!(ts!("Speichern", "Save"), "Speichern");
        force_english(Some(true));
        assert_eq!(t!("„{name}“ gespeichert", "\"{name}\" saved"), "\"web01\" saved");
        assert_eq!(ts!("Speichern", "Save"), "Save");
        force_english(None);
    }
}
