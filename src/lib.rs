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
    /// Optional site the entry is for. It is the sole association between an
    /// entry and a website: the browser integration releases this entry to a
    /// visited origin when the origin's host matches the `url`'s host. An entry
    /// must have a `url` set to be usable in a web browser; the entry `name` is
    /// never matched against the visited host. May be a bare hostname
    /// (`github.com`) or a full URL (`https://github.com/login`); only the host
    /// part is used for matching.
    /// Absent on entries written before this field existed, and not serialized
    /// when absent, so url-less entries stay byte-identical to the pre-`url`
    /// format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
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
    validate_entry(&new_entry)?;
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

/// Replace the username, password and `url` of an existing entry.
pub fn update(
    file: &Path,
    passphrase: &Passphrase,
    new_entry: PasswordEntry,
    params: &Params,
) -> Result<(), PwError> {
    validate_entry(&new_entry)?;
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

/// Replace the username and `url` of an existing entry while keeping its
/// current password, so the user can re-point an entry at another site (or
/// relabel it) without rotating the secret. Fails if no entry is named `name`.
pub fn update_keep_password(
    file: &Path,
    passphrase: &Passphrase,
    name: &str,
    username: String,
    url: Option<String>,
    params: &Params,
) -> Result<(), PwError> {
    validate_name(name)?;
    validate_username(&username)?;
    if let Some(url) = &url {
        validate_url(url)?;
    }
    let mut entries = load(file, passphrase)?;
    let Some(entry) = entries.iter_mut().find(|e| e.name == name) else {
        return Err(PwError::NotFound {
            name: name.to_string(),
            file: file.to_path_buf(),
        });
    };
    entry.username = username;
    entry.url = url;
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

/// The optional `url` matching hint, when present, must be non-empty and obey
/// the same length and character rules as entry names. Callers map "no url"
/// to `None`, so an empty string is rejected rather than stored.
pub fn validate_url(url: &str) -> Result<(), PwError> {
    if url.is_empty() {
        return Err(PwError::InvalidInput {
            what: "url",
            reason: "must not be empty".to_string(),
        });
    }
    validate_text("url", url)
}

/// Validate the user-supplied fields of an entry before it is stored.
fn validate_entry(entry: &PasswordEntry) -> Result<(), PwError> {
    validate_name(&entry.name)?;
    validate_username(&entry.username)?;
    if let Some(url) = &entry.url {
        validate_url(url)?;
    }
    Ok(())
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

/// Extract the hostname from a web origin, applying the eligibility rules of
/// the browser integration: only `https:`
/// origins are accepted, plus `http://localhost` and `http://127.0.0.1` for
/// local development. The returned hostname is IDNA/punycode-normalized and
/// lowercased. Any ineligible or unparsable origin yields `None` (mapped to
/// the `invalid-origin` error by the browser host); no other scheme,
/// including `http:` on a real host, `file:` or `moz-extension:`, is accepted.
pub fn origin_hostname(origin: &str) -> Option<String> {
    let (scheme, rest) = origin.split_once("://")?;
    let host = normalize_host(host_from_authority(rest))?;
    match scheme.to_ascii_lowercase().as_str() {
        "https" => Some(host),
        "http" if host == "localhost" || host == "127.0.0.1" => Some(host),
        _ => None,
    }
}

/// Reduce the part of a URL after `scheme://` to its bare host: drop any
/// path/query/fragment, then any userinfo, then the port. A bracketed IPv6
/// literal is never an eligible host in this integration, so a plain
/// rightmost-colon split for the port is sufficient.
fn host_from_authority(after_scheme: &str) -> &str {
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host)
}

/// Entries that match `hostname`. An entry matches when the host part of its
/// `url` field equals the hostname (exact match) or is a parent domain of it
/// at a label boundary, climbing no further than the registrable domain
/// (eTLD+1, via the Public Suffix List). All values are IDNA/punycode-
/// normalized and compared case-insensitively, so `example.co.uk` matches
/// `login.example.co.uk` but `co.uk` matches nothing. Only entries with a
/// `url` set are eligible for web browser use; the entry `name` is never
/// matched against the hostname.
pub fn matching_entries<'a>(
    hostname: &str,
    entries: &'a [PasswordEntry],
) -> Vec<&'a PasswordEntry> {
    let Some(host) = normalize_host(hostname) else {
        return Vec::new();
    };
    // The registrable domain bounds how far a parent-domain match may climb.
    // A host with no registrable domain — a bare IP, `localhost`, or a public
    // suffix itself — admits only an exact match.
    let min_labels = psl::domain_str(&host).map_or_else(|| label_count(&host), label_count);
    let candidate_matches =
        |candidate: Option<String>| candidate.is_some_and(|c| host_matches(&host, &c, min_labels));
    entries
        .iter()
        .filter(|e| candidate_matches(e.url.as_deref().and_then(url_host)))
        .collect()
}

/// IDNA/punycode-normalize a hostname to lowercase ASCII, or `None` if it is
/// not a usable domain. `domain_to_ascii` already lowercases and rejects the
/// empty string and malformed labels.
fn normalize_host(host: &str) -> Option<String> {
    idna::domain_to_ascii(host).ok().filter(|h| !h.is_empty())
}

/// Extract and normalize the host from an entry's `url` field, which may be a
/// bare hostname (`github.com`), a host:port, or a full URL
/// (`https://github.com/login`). Unlike [`origin_hostname`] this places no
/// constraint on the scheme — it is a stored matching hint, not an incoming
/// request — so any scheme (or none) is accepted and only the host is kept.
fn url_host(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    normalize_host(host_from_authority(after_scheme))
}

fn label_count(domain: &str) -> usize {
    domain.split('.').filter(|label| !label.is_empty()).count()
}

/// Whether `name` (already normalized) matches `host` (already normalized):
/// an exact match, or a parent-domain match landing on a label boundary and
/// having at least `min_labels` labels so it never climbs past the
/// registrable domain.
fn host_matches(host: &str, name: &str, min_labels: usize) -> bool {
    if name == host {
        return true;
    }
    label_count(name) >= min_labels
        && host.len() > name.len()
        && host.ends_with(name)
        && host.as_bytes()[host.len() - name.len() - 1] == b'.'
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
            url: None,
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
        for name in [
            "example.com",
            "xn--bcher-kva.example",
            "sub.host-1.example.org",
        ] {
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
            url: None,
        };
        let err = add(&file, &passphrase(), bad, &TEST_PARAMS).unwrap_err();
        assert!(matches!(err, PwError::InvalidInput { .. }));
    }

    #[test]
    fn rejects_bidi_and_zero_width_chars() {
        // Right-to-Left Override, Left-to-Right Isolate, Zero Width Space,
        // Zero Width Joiner and BOM must all be rejected in names and usernames.
        for spoof in [
            "a\u{202E}b",
            "a\u{2066}b",
            "a\u{200B}b",
            "a\u{200D}b",
            "a\u{FEFF}b",
        ] {
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
            url: None,
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
            PwError::InvalidInput {
                what: "password length",
                ..
            }
        ));
        assert!(matches!(
            generate_password(2000, "abc").unwrap_err(),
            PwError::InvalidInput {
                what: "password length",
                ..
            }
        ));
        for charset in ["", "a", "aaaa"] {
            assert!(matches!(
                generate_password(8, charset).unwrap_err(),
                PwError::InvalidInput {
                    what: "password charset",
                    ..
                }
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

    fn with_url(name: &str, url: &str) -> PasswordEntry {
        PasswordEntry {
            name: name.to_string(),
            username: "user".to_string(),
            password: "pw".into(),
            url: Some(url.to_string()),
        }
    }

    /// Run `matching_entries` for `hostname` over entries whose `url` is each of
    /// `urls`. The entry name is deliberately unrelated to the host (matching is
    /// on `url` only), and the returned strings are the matched `url`s.
    fn matches(hostname: &str, urls: &[&str]) -> Vec<String> {
        let entries: Vec<PasswordEntry> = urls
            .iter()
            .enumerate()
            .map(|(i, u)| with_url(&format!("entry-{i}"), u))
            .collect();
        matching_entries(hostname, &entries)
            .into_iter()
            .filter_map(|e| e.url.clone())
            .collect()
    }

    #[test]
    fn matches_exact_hostname() {
        assert_eq!(matches("github.com", &["github.com"]), vec!["github.com"]);
    }

    #[test]
    fn matches_parent_domain_at_label_boundary() {
        assert_eq!(
            matches("login.example.co.uk", &["example.co.uk"]),
            vec!["example.co.uk"]
        );
        // A subdomain entry never matches a shorter requested host.
        assert!(matches("example.co.uk", &["login.example.co.uk"]).is_empty());
    }

    #[test]
    fn does_not_match_across_public_suffix() {
        // The registrable-domain cut-off stops `co.uk` / `com` matching, so a
        // shared suffix cannot leak credentials between sites.
        assert!(matches("login.example.co.uk", &["co.uk"]).is_empty());
        assert!(matches("github.com", &["com"]).is_empty());
    }

    #[test]
    fn does_not_match_non_boundary_or_sibling() {
        // Not a label boundary: `hub.com` is a suffix of `github.com` only as
        // a substring, never as a parent domain.
        assert!(matches("github.com", &["hub.com"]).is_empty());
        // A phishing host cannot borrow the victim's entry.
        assert!(matches("github.com.evil.example", &["github.com"]).is_empty());
        // ...and only `evil.example`'s own entry matches it.
        assert_eq!(
            matches("github.com.evil.example", &["evil.example"]),
            vec!["evil.example"]
        );
    }

    #[test]
    fn matches_case_insensitively() {
        assert_eq!(matches("github.com", &["GitHub.COM"]), vec!["GitHub.COM"]);
    }

    #[test]
    fn matches_after_idna_normalization() {
        // The request arrives as punycode (as a browser reports it); the entry
        // is named in Unicode. Both normalize to the same ASCII form.
        assert_eq!(
            matches("xn--bcher-kva.example", &["bücher.example"]),
            vec!["bücher.example"]
        );
    }

    #[test]
    fn localhost_matches_only_exactly() {
        assert_eq!(matches("localhost", &["localhost"]), vec!["localhost"]);
        assert!(matches("localhost", &["host"]).is_empty());
        assert_eq!(matches("127.0.0.1", &["127.0.0.1"]), vec!["127.0.0.1"]);
    }

    #[test]
    fn returns_all_candidates() {
        let got = matches(
            "login.github.com",
            &["github.com", "login.github.com", "other.com"],
        );
        assert_eq!(got, vec!["github.com", "login.github.com"]);
    }

    #[test]
    fn url_field_matches_when_name_does_not() {
        // The entry's name is not the hostname, but its url declares the site.
        let entries = vec![with_url("work-github", "github.com")];
        let got: Vec<String> = matching_entries("github.com", &entries)
            .into_iter()
            .map(|e| e.name.clone())
            .collect();
        assert_eq!(got, vec!["work-github"]);
    }

    #[test]
    fn entry_without_url_never_matches() {
        // An entry whose name is the hostname but which has no url is not
        // eligible for browser use.
        let entries = vec![PasswordEntry {
            name: "github.com".to_string(),
            username: "user".to_string(),
            password: "pw".into(),
            url: None,
        }];
        assert!(matching_entries("github.com", &entries).is_empty());
    }

    #[test]
    fn name_is_not_matched_against_host() {
        // The name equals the host, but the url points elsewhere: no match.
        let entries = vec![with_url("github.com", "example.com")];
        assert!(matching_entries("github.com", &entries).is_empty());
    }

    #[test]
    fn url_field_accepts_full_url() {
        // A full URL is accepted; only its host is used for matching, and the
        // parent-domain rule still applies to subdomains of the request.
        let entries = vec![with_url("work", "https://github.com/login?next=/")];
        assert_eq!(matching_entries("login.github.com", &entries).len(), 1);
    }

    #[test]
    fn url_field_respects_public_suffix_boundary() {
        // A url of `co.uk` must not match across the registrable domain.
        let entries = vec![with_url("anything", "co.uk")];
        assert!(matching_entries("login.example.co.uk", &entries).is_empty());
    }

    #[test]
    fn url_field_does_not_match_unrelated_host() {
        let entries = vec![with_url("work", "github.com")];
        assert!(matching_entries("example.com", &entries).is_empty());
    }

    #[test]
    fn url_round_trips_and_is_omitted_when_absent() {
        let (_dir, file) = new_vault(&[("plain", "pw-plain")]);
        add(
            &file,
            &passphrase(),
            with_url("work", "github.com"),
            &TEST_PARAMS,
        )
        .unwrap();
        let json = export(&file, &passphrase()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        // A url-less entry carries no "url" key, so it stays byte-identical to
        // the pre-`url` on-disk format.
        assert!(value["entries"][0].get("url").is_none());
        // An entry with a url keeps it across the encrypt/decrypt round-trip.
        assert_eq!(value["entries"][1]["url"], "github.com");
        assert_eq!(
            get(&file, &passphrase(), "work").unwrap().url.as_deref(),
            Some("github.com")
        );
    }

    #[test]
    fn rejects_invalid_url() {
        let (_dir, file) = new_vault(&[]);
        let bad = PasswordEntry {
            name: "a".to_string(),
            username: String::new(),
            password: "pw".into(),
            url: Some("with\nnewline".to_string()),
        };
        let err = add(&file, &passphrase(), bad, &TEST_PARAMS).unwrap_err();
        assert!(matches!(err, PwError::InvalidInput { what: "url", .. }));
    }

    #[test]
    fn update_keep_password_changes_metadata_only() {
        let (_dir, file) = new_vault(&[("a", "pw-a")]);
        update_keep_password(
            &file,
            &passphrase(),
            "a",
            "new-user".to_string(),
            Some("github.com".to_string()),
            &TEST_PARAMS,
        )
        .unwrap();
        let e = get(&file, &passphrase(), "a").unwrap();
        // The password is untouched; the username and url are replaced.
        assert_eq!(e.password, "pw-a".into());
        assert_eq!(e.username, "new-user");
        assert_eq!(e.url.as_deref(), Some("github.com"));
    }

    #[test]
    fn update_keep_password_unknown_name() {
        let (_dir, file) = new_vault(&[]);
        let err =
            update_keep_password(&file, &passphrase(), "a", String::new(), None, &TEST_PARAMS)
                .unwrap_err();
        assert!(matches!(err, PwError::NotFound { .. }));
    }

    #[test]
    fn origin_hostname_accepts_https() {
        assert_eq!(
            origin_hostname("https://github.com").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            origin_hostname("https://login.example.co.uk:8443").as_deref(),
            Some("login.example.co.uk")
        );
        assert_eq!(
            origin_hostname("https://GitHub.com").as_deref(),
            Some("github.com")
        );
    }

    #[test]
    fn origin_hostname_rejects_non_https() {
        for origin in [
            "http://github.com",
            "file:///etc/passwd",
            "moz-extension://abc/page.html",
            "ftp://example.com",
            "https://",
            "not-a-url",
        ] {
            assert!(origin_hostname(origin).is_none(), "origin {origin:?}");
        }
    }

    #[test]
    fn origin_hostname_allows_local_http_for_dev() {
        assert_eq!(
            origin_hostname("http://localhost:3000").as_deref(),
            Some("localhost")
        );
        assert_eq!(
            origin_hostname("http://127.0.0.1:8080").as_deref(),
            Some("127.0.0.1")
        );
    }
}
