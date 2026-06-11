//! # PW
//!
//! A command line password manager.
//!
//! Layering: [`scrypt_format`] is the pure byte codec, [`vault`] is encrypted
//! file storage, and this module holds the domain operations. Nothing here
//! ever prompts or assumes a terminal — the passphrase enters every operation
//! as a [`Passphrase`] parameter, so the same functions serve the CLI and any
//! future non-interactive host.

pub mod scrypt_format;
pub mod vault;

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};

use rand::rngs::SysRng;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub use scrypt_format::Params;
pub use vault::Passphrase;

/// Longest accepted entry name or username, in characters.
pub const MAX_NAME_LEN: usize = 256;
/// Longest password [`generate_password`] will produce.
pub const MAX_PASSWORD_LEN: u32 = 1024;

#[derive(thiserror::Error, Debug)]
pub enum PwError {
    #[error("no vault at {0} - run `pw init`")]
    FileNotFound(PathBuf),
    #[error("vault {0} already exists")]
    FileAlreadyExists(PathBuf),
    #[error("incorrect passphrase")]
    WrongPassphrase,
    #[error("no entry '{name}' in {file} - try `pw list`")]
    NotFound { name: String, file: PathBuf },
    #[error("entry '{name}' already exists in {file} - use `pw update`")]
    AlreadyExists { name: String, file: PathBuf },
    #[error("invalid {what}: {reason}")]
    InvalidInput { what: &'static str, reason: String },
    #[error(transparent)]
    Io(vault::Error),
    #[error("cannot use vault {file}")]
    CorruptVault {
        file: PathBuf,
        #[source]
        source: vault::Error,
    },
}

/// A stored password: zeroized on drop, redacted by `Debug`, serialized
/// transparently as a JSON string.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        Secret(value)
    }

    /// Named so that every place the secret leaves the type is greppable.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Secret(value)
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Secret(value.to_string())
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PasswordEntry {
    pub name: String,
    pub username: String,
    pub password: Secret,
}

/// Create a new empty vault. Fails if the file already exists.
pub fn init(file: &Path, passphrase: &Passphrase, params: &Params) -> Result<(), PwError> {
    if file.exists() {
        return Err(PwError::FileAlreadyExists(file.to_path_buf()));
    }
    store(file, passphrase, &[], params)
}

/// Look up the entry named `name`.
pub fn get(file: &Path, passphrase: &Passphrase, name: &str) -> Result<PasswordEntry, PwError> {
    let entries = load(file, passphrase)?;
    entries
        .into_iter()
        .find(|e| e.name == name)
        .ok_or_else(|| PwError::NotFound {
            name: name.to_string(),
            file: file.to_path_buf(),
        })
}

/// All entries in the vault.
pub fn list(file: &Path, passphrase: &Passphrase) -> Result<Vec<PasswordEntry>, PwError> {
    load(file, passphrase)
}

/// Add a new entry. Fails if an entry with the same name exists.
pub fn add(
    file: &Path,
    passphrase: &Passphrase,
    new_entry: PasswordEntry,
    params: &Params,
) -> Result<(), PwError> {
    validate_name(&new_entry.name)?;
    validate_username(&new_entry.username)?;
    let mut entries = load(file, passphrase)?;
    if entries.iter().any(|e| e.name == new_entry.name) {
        return Err(PwError::AlreadyExists {
            name: new_entry.name.clone(),
            file: file.to_path_buf(),
        });
    }
    entries.push(new_entry);
    store(file, passphrase, &entries, params)
}

/// Replace the username and password of an existing entry.
pub fn update(
    file: &Path,
    passphrase: &Passphrase,
    new_entry: PasswordEntry,
    params: &Params,
) -> Result<(), PwError> {
    validate_name(&new_entry.name)?;
    validate_username(&new_entry.username)?;
    let mut entries = load(file, passphrase)?;
    let Some(entry) = entries.iter_mut().find(|e| e.name == new_entry.name) else {
        return Err(PwError::NotFound {
            name: new_entry.name.clone(),
            file: file.to_path_buf(),
        });
    };
    *entry = new_entry;
    store(file, passphrase, &entries, params)
}

/// Remove the entry named `name`.
pub fn remove(
    file: &Path,
    passphrase: &Passphrase,
    name: &str,
    params: &Params,
) -> Result<(), PwError> {
    let mut entries = load(file, passphrase)?;
    let original_len = entries.len();
    entries.retain(|e| e.name != name);
    if entries.len() == original_len {
        return Err(PwError::NotFound {
            name: name.to_string(),
            file: file.to_path_buf(),
        });
    }
    store(file, passphrase, &entries, params)
}

/// The decrypted vault as JSON (the same envelope that is stored encrypted),
/// for backup and migration.
pub fn export(file: &Path, passphrase: &Passphrase) -> Result<Zeroizing<String>, PwError> {
    let entries = load(file, passphrase)?;
    vault::to_json(&entries).map_err(|e| vault_err(file, e))
}

fn load(file: &Path, passphrase: &Passphrase) -> Result<Vec<PasswordEntry>, PwError> {
    if !file.exists() {
        return Err(PwError::FileNotFound(file.to_path_buf()));
    }
    vault::load(file, passphrase).map_err(|e| vault_err(file, e))
}

fn store(
    file: &Path,
    passphrase: &Passphrase,
    entries: &[PasswordEntry],
    params: &Params,
) -> Result<(), PwError> {
    vault::store(file, passphrase, entries, params).map_err(|e| vault_err(file, e))
}

fn vault_err(file: &Path, err: vault::Error) -> PwError {
    match err {
        vault::Error::Format(scrypt_format::Error::WrongPassphrase) => PwError::WrongPassphrase,
        e @ (vault::Error::Read { .. } | vault::Error::Write { .. }) => PwError::Io(e),
        e => PwError::CorruptVault {
            file: file.to_path_buf(),
            source: e,
        },
    }
}

/// Returns true for Unicode bidirectional control and zero-width code points
/// that can reorder or disguise how text renders without being "control"
/// characters per [`char::is_control`] (a Trojan-Source / homoglyph style
/// display spoof). Used both to reject such characters on input and to
/// replace them on output.
pub fn is_display_spoofing_char(c: char) -> bool {
    matches!(c,
        // Bidirectional embeddings, overrides and isolates
        '\u{202A}'..='\u{202E}'   // LRE, RLE, PDF, LRO, RLO
        | '\u{2066}'..='\u{2069}' // LRI, RLI, FSI, PDI
        // Bidirectional marks
        | '\u{200E}' | '\u{200F}' // LRM, RLM
        | '\u{061C}'              // Arabic Letter Mark
        // Zero-width characters
        | '\u{200B}'              // Zero Width Space
        | '\u{200C}' | '\u{200D}' // ZWNJ, ZWJ
        | '\u{2060}'              // Word Joiner
        | '\u{FEFF}'              // Zero Width No-Break Space / BOM
    )
}

/// Entry names must be non-empty, at most [`MAX_NAME_LEN`] characters and
/// free of control, bidirectional and zero-width characters. Everything a
/// hostname can contain is allowed.
pub fn validate_name(name: &str) -> Result<(), PwError> {
    if name.is_empty() {
        return Err(PwError::InvalidInput {
            what: "entry name",
            reason: "must not be empty".to_string(),
        });
    }
    validate_text("entry name", name)
}

/// Usernames may be empty, but obey the same length and character rules as
/// entry names.
pub fn validate_username(username: &str) -> Result<(), PwError> {
    validate_text("username", username)
}

fn validate_text(what: &'static str, value: &str) -> Result<(), PwError> {
    if value.chars().count() > MAX_NAME_LEN {
        return Err(PwError::InvalidInput {
            what,
            reason: format!("longer than {MAX_NAME_LEN} characters"),
        });
    }
    if value.chars().any(char::is_control) {
        return Err(PwError::InvalidInput {
            what,
            reason: "contains control characters".to_string(),
        });
    }
    if value.chars().any(is_display_spoofing_char) {
        return Err(PwError::InvalidInput {
            what,
            reason: "contains bidirectional or zero-width characters".to_string(),
        });
    }
    Ok(())
}

/// Generate a random password of `length` characters from `charset`,
/// using a cryptographically secure generator.
pub fn generate_password(length: u32, charset: &str) -> Result<Secret, PwError> {
    if length == 0 || length > MAX_PASSWORD_LEN {
        return Err(PwError::InvalidInput {
            what: "password length",
            reason: format!("must be between 1 and {MAX_PASSWORD_LEN}"),
        });
    }
    let chars: Vec<char> = charset.chars().collect();
    let unique: HashSet<&char> = chars.iter().collect();
    if unique.len() < 2 {
        return Err(PwError::InvalidInput {
            what: "password charset",
            reason: "must contain at least 2 distinct characters".to_string(),
        });
    }
    let mut rng =
        ChaCha20Rng::try_from_rng(&mut SysRng).expect("failed to read from the OS random source");
    // random_range uses rejection sampling: no modulo bias.
    let password: String = (0..length)
        .map(|_| chars[rng.random_range(0..chars.len())])
        .collect();
    Ok(Secret::new(password))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSPHRASE: &str = "test passphrase";
    // Small KDF parameters so debug-mode tests stay fast.
    const TEST_PARAMS: Params = Params {
        log_n: 12,
        r: 8,
        p: 1,
    };

    fn passphrase() -> Passphrase {
        Passphrase::new(PASSPHRASE.to_string())
    }

    fn entry(name: &str, password: &str) -> PasswordEntry {
        PasswordEntry {
            name: name.to_string(),
            username: format!("{name}-user"),
            password: password.into(),
        }
    }

    fn new_vault(entries: &[(&str, &str)]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("pw.scrypt");
        init(&file, &passphrase(), &TEST_PARAMS).unwrap();
        for (name, password) in entries {
            add(&file, &passphrase(), entry(name, password), &TEST_PARAMS).unwrap();
        }
        (dir, file)
    }

    #[test]
    fn init_then_list_empty() {
        let (_dir, file) = new_vault(&[]);
        assert_eq!(list(&file, &passphrase()).unwrap(), Vec::new());
    }

    #[test]
    fn init_refuses_existing_file() {
        let (_dir, file) = new_vault(&[]);
        let err = init(&file, &passphrase(), &TEST_PARAMS).unwrap_err();
        assert!(matches!(err, PwError::FileAlreadyExists(_)));
    }

    #[test]
    fn add_then_get() {
        let (_dir, file) = new_vault(&[("a", "pw-a"), ("b", "pw-b")]);
        let got = get(&file, &passphrase(), "b").unwrap();
        assert_eq!(got, entry("b", "pw-b"));
    }

    #[test]
    fn get_unknown_name() {
        let (_dir, file) = new_vault(&[("a", "pw-a")]);
        let err = get(&file, &passphrase(), "nope").unwrap_err();
        assert!(matches!(err, PwError::NotFound { name, .. } if name == "nope"));
    }

    #[test]
    fn add_duplicate_name() {
        let (_dir, file) = new_vault(&[("a", "pw-a")]);
        let err = add(&file, &passphrase(), entry("a", "other"), &TEST_PARAMS).unwrap_err();
        assert!(matches!(err, PwError::AlreadyExists { name, .. } if name == "a"));
    }

    #[test]
    fn update_existing() {
        let (_dir, file) = new_vault(&[("a", "pw-a")]);
        update(&file, &passphrase(), entry("a", "pw-new"), &TEST_PARAMS).unwrap();
        assert_eq!(
            get(&file, &passphrase(), "a").unwrap().password,
            "pw-new".into()
        );
    }

    #[test]
    fn update_unknown_name() {
        let (_dir, file) = new_vault(&[]);
        let err = update(&file, &passphrase(), entry("a", "pw"), &TEST_PARAMS).unwrap_err();
        assert!(matches!(err, PwError::NotFound { .. }));
    }

    #[test]
    fn remove_existing() {
        let (_dir, file) = new_vault(&[("a", "pw-a"), ("b", "pw-b")]);
        remove(&file, &passphrase(), "a", &TEST_PARAMS).unwrap();
        let names: Vec<String> = list(&file, &passphrase())
            .unwrap()
            .into_iter()
            .map(|e| e.name.clone())
            .collect();
        assert_eq!(names, vec!["b"]);
    }

    #[test]
    fn remove_unknown_name() {
        let (_dir, file) = new_vault(&[]);
        let err = remove(&file, &passphrase(), "a", &TEST_PARAMS).unwrap_err();
        assert!(matches!(err, PwError::NotFound { .. }));
    }

    #[test]
    fn missing_vault_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("pw.scrypt");
        for err in [
            get(&file, &passphrase(), "a").unwrap_err(),
            list(&file, &passphrase()).map(|_| ()).unwrap_err(),
            add(&file, &passphrase(), entry("a", "pw"), &TEST_PARAMS).unwrap_err(),
        ] {
            assert!(matches!(err, PwError::FileNotFound(_)));
        }
    }

    #[test]
    fn wrong_passphrase_is_distinct() {
        let (_dir, file) = new_vault(&[]);
        let err = list(&file, &Passphrase::new("wrong".to_string())).unwrap_err();
        assert!(matches!(err, PwError::WrongPassphrase));
    }

    #[test]
    fn export_round_trips_as_json() {
        let (_dir, file) = new_vault(&[("a", "pw-a")]);
        let json = export(&file, &passphrase()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["version"], 1);
        assert_eq!(value["entries"][0]["password"], "pw-a");
    }

    #[test]
    fn rejects_invalid_names() {
        let (_dir, file) = new_vault(&[]);
        for name in ["", "with\nnewline", "with\x1b[31mescape", &"x".repeat(257)] {
            let err = add(&file, &passphrase(), entry(name, "pw"), &TEST_PARAMS).unwrap_err();
            assert!(matches!(err, PwError::InvalidInput { .. }), "name {name:?}");
        }
    }

    #[test]
    fn allows_hostname_names() {
        for name in ["example.com", "xn--bcher-kva.example", "sub.host-1.example.org"] {
            assert!(validate_name(name).is_ok(), "name {name:?}");
        }
    }

    #[test]
    fn rejects_control_chars_in_username() {
        let (_dir, file) = new_vault(&[]);
        let bad = PasswordEntry {
            name: "a".to_string(),
            username: "user\r\n".to_string(),
            password: "pw".into(),
        };
        let err = add(&file, &passphrase(), bad, &TEST_PARAMS).unwrap_err();
        assert!(matches!(err, PwError::InvalidInput { .. }));
    }

    #[test]
    fn rejects_bidi_and_zero_width_chars() {
        // Right-to-Left Override, Left-to-Right Isolate, Zero Width Space,
        // Zero Width Joiner and BOM must all be rejected in names and usernames.
        for spoof in ["a\u{202E}b", "a\u{2066}b", "a\u{200B}b", "a\u{200D}b", "a\u{FEFF}b"] {
            assert!(
                matches!(validate_name(spoof), Err(PwError::InvalidInput { .. })),
                "name {spoof:?}"
            );
            assert!(
                matches!(validate_username(spoof), Err(PwError::InvalidInput { .. })),
                "username {spoof:?}"
            );
        }
    }

    #[test]
    fn empty_username_is_allowed() {
        let (_dir, file) = new_vault(&[]);
        let e = PasswordEntry {
            name: "a".to_string(),
            username: String::new(),
            password: "pw".into(),
        };
        add(&file, &passphrase(), e, &TEST_PARAMS).unwrap();
        assert_eq!(get(&file, &passphrase(), "a").unwrap().username, "");
    }

    #[test]
    fn generate_uses_charset_and_length() {
        let pw = generate_password(16, "0123456789").unwrap();
        assert_eq!(pw.expose().chars().count(), 16);
        assert!(pw.expose().chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn generate_rejects_bad_input() {
        assert!(matches!(
            generate_password(0, "abc").unwrap_err(),
            PwError::InvalidInput { what: "password length", .. }
        ));
        assert!(matches!(
            generate_password(2000, "abc").unwrap_err(),
            PwError::InvalidInput { what: "password length", .. }
        ));
        for charset in ["", "a", "aaaa"] {
            assert!(matches!(
                generate_password(8, charset).unwrap_err(),
                PwError::InvalidInput { what: "password charset", .. }
            ));
        }
    }

    #[test]
    fn debug_redacts_secrets() {
        let e = entry("a", "super secret");
        let debug = format!("{e:?}");
        assert!(debug.contains("[redacted]"), "{debug}");
        assert!(!debug.contains("super secret"), "{debug}");
    }
}
