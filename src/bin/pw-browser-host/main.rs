//! `pw-browser-host` — the native-messaging host for the Firefox integration.
//! Started by Firefox (directly, or via the
//! WebExtensions XDG portal under the snap) when the extension connects, it
//! reads length-prefixed JSON requests on stdin and writes responses on
//! stdout. It owns all secret handling: it prompts for the master passphrase
//! via `pinentry`, decrypts the vault in-process, matches entries against the
//! requesting origin by their `url`, and returns only the matching entries. It
//! never lists the whole vault and never writes to it.

mod config;
mod debug_log;
mod pinentry;
mod protocol;

use std::io;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use pw::{Passphrase, PasswordEntry, PwError};

use config::Config;
use protocol::{read_message, write_message, Login, Request, Response};

/// Reported in `status.version` and used to evolve the protocol.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum passphrase attempts before giving up with `scrypt-failed` (§6).
const MAX_UNLOCK_ATTEMPTS: u32 = 3;

fn main() -> ExitCode {
    harden_process();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pw-browser-host: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> anyhow::Result<()> {
    let mut host = Host::new()?;
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    while let Some(message) = read_message(&mut stdin)? {
        let response = host.handle(&message);
        write_message(&mut stdout, &response)?;
        // With caching disabled, drop the decrypted entries as soon as the
        // request that needed them is answered.
        if host.cache_minutes == 0 {
            host.relock();
        }
    }
    Ok(())
}

/// Decrypted entries held in memory under the cache policy (§4.3). Zeroized on
/// drop because [`PasswordEntry`] is `ZeroizeOnDrop`.
struct Cache {
    entries: Vec<PasswordEntry>,
    expires_at: Instant,
}

struct Host {
    file: PathBuf,
    cache_minutes: u64,
    cache: Option<Cache>,
}

/// Why an unlock could not produce decrypted entries; each maps to a protocol
/// error code (§6).
enum UnlockError {
    Cancelled,
    ScryptFailed,
    DbMissing,
    Internal(String),
}

impl Host {
    fn new() -> anyhow::Result<Host> {
        let config = Config::load()?;
        debug_log::init(config.log_file());
        log_startup(&config);
        Ok(Host {
            file: config.vault_file(),
            cache_minutes: config.cache_minutes,
            cache: None,
        })
    }

    fn handle(&mut self, message: &[u8]) -> Vec<u8> {
        let request: Request = match serde_json::from_slice(message) {
            Ok(request) => request,
            Err(e) => {
                return Response::Error {
                    id: 0,
                    code: "internal",
                    message: format!("malformed request: {e}"),
                }
                .to_bytes()
            }
        };
        let id = request.id;
        if debug_log::enabled() {
            debug_log::log(&format!(
                "request id={id} type={:?} origin={:?}",
                request.typ.as_deref().unwrap_or("(missing)"),
                request.origin.as_deref().unwrap_or("(none)"),
            ));
        }
        match request.typ.as_deref() {
            Some("get-logins") => self.get_logins(id, request.origin.as_deref()),
            Some("lock") => {
                self.relock();
                Response::Ok { id }.to_bytes()
            }
            Some("status") => Response::Status {
                id,
                locked: !self.is_unlocked(),
                version: VERSION,
            }
            .to_bytes(),
            other => Response::Error {
                id,
                code: "internal",
                message: format!("unknown request type {:?}", other.unwrap_or("(missing)")),
            }
            .to_bytes(),
        }
    }

    fn get_logins(&mut self, id: u64, origin: Option<&str>) -> Vec<u8> {
        let Some(origin) = origin else {
            return error(id, "invalid-origin", "request has no origin");
        };
        // The hostname drives `url` matching. It comes from the tab's
        // origin, never from anything the page reports.
        let Some(hostname) = pw::origin_hostname(origin) else {
            return error(id, "invalid-origin", format!("ineligible origin {origin}"));
        };

        debug_log::log(&format!(
            "get-logins eligible hostname={hostname} unlocked={}",
            self.is_unlocked()
        ));
        if let Err(e) = self.ensure_unlocked() {
            debug_log::log("unlock failed");
            return unlock_error(id, e);
        }

        let entries = &self.cache.as_ref().expect("unlocked").entries;
        let matched = pw::matching_entries(&hostname, entries);
        debug_log::log(&format!(
            "unlocked: {} entries, {} match {hostname}",
            entries.len(),
            matched.len()
        ));
        if matched.is_empty() {
            return error(id, "no-match", format!("no entry matches {hostname}"));
        }

        // Release every entry whose `url` matches the visited site.
        let selected: Vec<Login> = matched.iter().map(|e| Login::from(*e)).collect();
        Response::Logins {
            id,
            entries: selected,
        }
        .to_bytes()
    }

    fn is_unlocked(&self) -> bool {
        self.cache
            .as_ref()
            .is_some_and(|c| Instant::now() < c.expires_at)
    }

    /// Ensure the cache holds non-expired decrypted entries, unlocking via
    /// pinentry if needed, and (re)set the lock timer on success.
    fn ensure_unlocked(&mut self) -> Result<(), UnlockError> {
        if !self.is_unlocked() {
            self.relock(); // zeroize any expired entries first
            let entries = self.decrypt()?;
            self.cache = Some(Cache {
                entries,
                expires_at: Instant::now(),
            });
        }
        if let Some(cache) = &mut self.cache {
            cache.expires_at = Instant::now() + Duration::from_secs(self.cache_minutes * 60);
        }
        Ok(())
    }

    /// Prompt for the passphrase and decrypt, retrying up to
    /// [`MAX_UNLOCK_ATTEMPTS`] on a wrong passphrase.
    fn decrypt(&self) -> Result<Vec<PasswordEntry>, UnlockError> {
        if !self.file.exists() {
            return Err(UnlockError::DbMissing);
        }
        let desc = format!("Unlock {}", self.file.display());
        let mut error_hint: Option<&str> = None;
        for attempt in 1..=MAX_UNLOCK_ATTEMPTS {
            debug_log::log(&format!("pinentry: prompting (attempt {attempt})"));
            let pin = match pinentry::get_passphrase(&desc, "Passphrase:", error_hint) {
                Ok(pin) => pin,
                Err(pinentry::Error::Cancelled) => {
                    debug_log::log("pinentry: cancelled");
                    return Err(UnlockError::Cancelled);
                }
                Err(pinentry::Error::Failed(m)) => {
                    debug_log::log(&format!("pinentry: failed: {m}"));
                    return Err(UnlockError::Internal(m));
                }
            };
            debug_log::log("pinentry: got passphrase, decrypting");
            let mut pin = pin;
            let passphrase = Passphrase::new(std::mem::take(&mut *pin));
            match pw::list(&self.file, &passphrase) {
                Ok(entries) => {
                    debug_log::log("decrypt: success");
                    return Ok(entries);
                }
                Err(PwError::WrongPassphrase) => {
                    debug_log::log("decrypt: wrong passphrase");
                    error_hint = Some("Incorrect passphrase, try again");
                }
                Err(PwError::FileNotFound(_)) => return Err(UnlockError::DbMissing),
                Err(e) => return Err(UnlockError::Internal(e.to_string())),
            }
        }
        Err(UnlockError::ScryptFailed)
    }

    /// Drop and zeroize any cached entries.
    fn relock(&mut self) {
        self.cache = None;
    }
}

/// Log the version and the parts of the environment pinentry depends on. This
/// is the key diagnostic for the Firefox/snap case, where the native host is
/// launched by a portal that may strip `DISPLAY`/`WAYLAND_DISPLAY`/
/// `DBUS_SESSION_BUS_ADDRESS`, leaving pinentry unable to show or return a
/// usable dialog. No secret is involved. A no-op when logging is disabled.
fn log_startup(config: &Config) {
    if !debug_log::enabled() {
        return;
    }
    debug_log::log(&format!("=== pw-browser-host {VERSION} starting ==="));
    debug_log::log(&format!(
        "config: vault={} cache_minutes={}",
        config.vault_file().display(),
        config.cache_minutes,
    ));
    for var in [
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_RUNTIME_DIR",
        "GPG_TTY",
        "TERM",
        "LANG",
        "PATH",
    ] {
        match std::env::var(var) {
            Ok(value) => debug_log::log(&format!("env {var}={value}")),
            Err(_) => debug_log::log(&format!("env {var}=(unset)")),
        }
    }
}

fn error(id: u64, code: &'static str, message: impl Into<String>) -> Vec<u8> {
    Response::Error {
        id,
        code,
        message: message.into(),
    }
    .to_bytes()
}

fn unlock_error(id: u64, e: UnlockError) -> Vec<u8> {
    match e {
        UnlockError::Cancelled => error(id, "unlock-cancelled", "passphrase entry cancelled"),
        UnlockError::ScryptFailed => error(id, "scrypt-failed", "could not decrypt the vault"),
        UnlockError::DbMissing => error(id, "db-missing", "no vault file"),
        UnlockError::Internal(m) => error(id, "internal", m),
    }
}

/// Best-effort process hardening mirroring the `pw` binary: disable core dumps
/// so a crash cannot persist decrypted data, and mark the process
/// non-dumpable on Linux to block `ptrace` from same-user processes. Failures
/// are ignored (defense in depth, not a correctness requirement).
#[cfg(unix)]
fn harden_process() {
    // SAFETY: both calls take plain scalars and have no memory effects;
    // ignoring the result is intentional (best-effort hardening).
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &limit);

        #[cfg(target_os = "linux")]
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }
}

#[cfg(not(unix))]
fn harden_process() {}
