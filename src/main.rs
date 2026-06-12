//! # PW
//!
//! A command line password manager. All prompting, terminal and clipboard
//! handling lives here; the library never assumes a terminal.

use std::io::{self, BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use clap::{Args, Parser, Subcommand};
use clippers::Clipboard;
use dirs::home_dir;
use zeroize::Zeroizing;

use pw::{Params, Passphrase, PasswordEntry, Secret};

const DEFAULT_CHARSET: &str =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-";

#[derive(Parser)]
#[command(version, about = "A command line password manager")]
struct Cli {
    /// The encrypted vault file, ~/pw.scrypt by default
    #[arg(long, global = true)]
    file: Option<PathBuf>,

    /// Read the passphrase as a single line from stdin instead of prompting
    #[arg(long, global = true)]
    passphrase_stdin: bool,

    /// Seconds to keep a copied password on the clipboard before clearing it
    /// (cleared only if still unchanged); 0 leaves the clipboard untouched
    #[arg(long, global = true, default_value_t = 20)]
    clear_timeout: u64,

    /// Override the scrypt CPU/memory cost (log2 of N) when writing;
    /// intended for tests
    #[arg(long, global = true, hide = true)]
    scrypt_log_n: Option<u8>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Args)]
struct PasswordOptions {
    /// Type the password to save, instead of generating one
    #[arg(long)]
    input_password: bool,

    /// Length of the generated password
    #[arg(long, default_value_t = 16)]
    password_length: u32,

    /// Characters to use in the generated password
    #[arg(long, default_value = DEFAULT_CHARSET)]
    password_charset: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new empty vault
    Init {},

    /// Look up a password and copy it to the clipboard
    Get {
        /// The password entry
        name: String,
        /// Print the password to stdout instead of copying it
        #[arg(long)]
        show: bool,
    },

    /// List entries
    List {
        /// Only show entries whose name contains this (case-insensitive)
        pattern: Option<String>,
    },

    /// Add a password
    Add {
        /// The password entry
        name: String,
        /// Username (free-form label, may be omitted)
        username: Option<String>,
        #[command(flatten)]
        password: PasswordOptions,
        /// Print the new password to stdout instead of copying it
        #[arg(long)]
        show: bool,
    },

    /// Update a password
    Update {
        /// The password entry
        name: String,
        /// Username (free-form label, may be omitted)
        username: Option<String>,
        #[command(flatten)]
        password: PasswordOptions,
        /// Print the new password to stdout instead of copying it
        #[arg(long)]
        show: bool,
    },

    /// Remove a password
    Remove {
        /// The password entry
        name: String,
        /// Do not ask for confirmation
        #[arg(long)]
        yes: bool,
    },

    /// Generate a password without storing it
    Generate {
        /// Length of the generated password
        #[arg(long, default_value_t = 16)]
        password_length: u32,

        /// Characters to use in the generated password
        #[arg(long, default_value = DEFAULT_CHARSET)]
        password_charset: String,

        /// Print the password to stdout instead of copying it
        #[arg(long)]
        show: bool,
    },

    /// Print the decrypted vault as JSON, for backup or migration
    Export {},
}

fn main() -> ExitCode {
    harden_process();
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

/// Best-effort process hardening, run once before any secret is read.
///
/// Disables core dumps so a crash cannot persist the derived key or the
/// decrypted vault to disk, and on Linux marks the process non-dumpable,
/// which additionally blocks `ptrace` attaches from same-user processes.
/// This does not protect against swap; see the README on encrypted swap.
/// Failures are ignored: this is defense in depth, not a correctness
/// requirement, and the kernel may forbid these on some configurations.
#[cfg(unix)]
fn harden_process() {
    // SAFETY: both calls take plain scalars/POD and have no memory effects;
    // ignoring the return value is intentional (best-effort hardening).
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

fn run() -> anyhow::Result<ExitCode> {
    let cli = Cli::parse();

    let file = cli.file.unwrap_or_else(|| {
        home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("pw.scrypt")
    });
    let params = Params {
        log_n: cli.scrypt_log_n.unwrap_or(Params::default().log_n),
        ..Params::default()
    };
    let clear_timeout = cli.clear_timeout;

    // Holds the value copied to the clipboard, if any, so it can be cleared
    // after `clear_timeout` once the command has otherwise finished.
    let mut pending_clear: Option<Zeroizing<String>> = None;

    match cli.command {
        Commands::Init {} => {
            let passphrase = obtain_passphrase(cli.passphrase_stdin, true)?;
            pw::init(&file, &passphrase, &params)?;
            println!("Initialized empty vault at {}", file.display());
        }
        Commands::Get { name, show } => {
            let passphrase = obtain_passphrase(cli.passphrase_stdin, false)?;
            let entry = pw::get(&file, &passphrase, &name)?;
            if !entry.username.is_empty() {
                println!("{}", sanitize(&entry.username));
            }
            if show {
                println!("{}", entry.password.expose());
            } else {
                pending_clear = Some(copy_to_clipboard(entry.password.expose())?);
                announce_copied(&format!("Password for '{}'", sanitize(&name)), clear_timeout);
            }
        }
        Commands::List { pattern } => {
            let passphrase = obtain_passphrase(cli.passphrase_stdin, false)?;
            let entries = pw::list(&file, &passphrase)?;
            println!("Vault: {} ({} entries)", file.display(), entries.len());
            let pattern = pattern.unwrap_or_default().to_lowercase();
            for entry in entries
                .iter()
                .filter(|e| e.name.to_lowercase().contains(&pattern))
            {
                println!("{}: {}", sanitize(&entry.name), sanitize(&entry.username));
            }
        }
        Commands::Add {
            name,
            username,
            password,
            show,
        } => {
            let password = obtain_password(&password)?;
            let passphrase = obtain_passphrase(cli.passphrase_stdin, false)?;
            if show {
                println!("{}", password.expose());
            } else {
                pending_clear = Some(copy_to_clipboard(password.expose())?);
            }
            let entry = PasswordEntry {
                name: name.clone(),
                username: username.unwrap_or_default(),
                password,
            };
            pw::add(&file, &passphrase, entry, &params)?;
            if !show {
                announce_copied(&format!("Password for '{}'", sanitize(&name)), clear_timeout);
            }
        }
        Commands::Update {
            name,
            username,
            password,
            show,
        } => {
            let password = obtain_password(&password)?;
            let passphrase = obtain_passphrase(cli.passphrase_stdin, false)?;
            if show {
                println!("{}", password.expose());
            } else {
                pending_clear = Some(copy_to_clipboard(password.expose())?);
            }
            let entry = PasswordEntry {
                name: name.clone(),
                username: username.unwrap_or_default(),
                password,
            };
            pw::update(&file, &passphrase, entry, &params)?;
            if !show {
                announce_copied(&format!("Password for '{}'", sanitize(&name)), clear_timeout);
            }
        }
        Commands::Remove { name, yes } => {
            if !yes && !confirm(&format!("Remove entry '{}'? [y/N] ", sanitize(&name)))? {
                eprintln!("Aborted.");
                return Ok(ExitCode::FAILURE);
            }
            let passphrase = obtain_passphrase(cli.passphrase_stdin, false)?;
            pw::remove(&file, &passphrase, &name, &params)?;
            println!("Removed entry '{}'.", sanitize(&name));
        }
        Commands::Generate {
            password_length,
            password_charset,
            show,
        } => {
            let password = generate(password_length, &password_charset)?;
            if show {
                println!("{}", password.expose());
            } else {
                pending_clear = Some(copy_to_clipboard(password.expose())?);
                announce_copied("Generated password", clear_timeout);
            }
        }
        Commands::Export {} => {
            let passphrase = obtain_passphrase(cli.passphrase_stdin, false)?;
            let json = pw::export(&file, &passphrase)?;
            eprintln!("Warning: the decrypted vault follows on stdout.");
            println!("{}", json.as_str());
        }
    }

    if let Some(secret) = pending_clear {
        wait_and_clear(&secret, clear_timeout);
    }

    Ok(ExitCode::SUCCESS)
}

/// Read the passphrase, either from stdin (`--passphrase-stdin`) or by
/// prompting on the terminal. `confirm` asks twice (vault creation).
fn obtain_passphrase(from_stdin: bool, confirm: bool) -> anyhow::Result<Passphrase> {
    if from_stdin {
        let mut line = Zeroizing::new(String::new());
        let n = io::stdin()
            .lock()
            .read_line(&mut line)
            .context("cannot read passphrase from stdin")?;
        if n == 0 {
            bail!("no passphrase on stdin");
        }
        while line.ends_with('\n') || line.ends_with('\r') {
            line.pop();
        }
        Ok(Passphrase::new(std::mem::take(&mut *line)))
    } else {
        let first = Passphrase::new(
            rpassword::prompt_password("Passphrase: ").context("cannot read passphrase")?,
        );
        if confirm {
            let second = Passphrase::new(
                rpassword::prompt_password("Confirm passphrase: ")
                    .context("cannot read passphrase")?,
            );
            if first.as_bytes() != second.as_bytes() {
                bail!("passphrases do not match");
            }
        }
        Ok(first)
    }
}

/// The password for an add/update: typed in, or generated.
fn obtain_password(options: &PasswordOptions) -> anyhow::Result<Secret> {
    if options.input_password {
        Ok(Secret::new(
            rpassword::prompt_password("Password to save: ").context("cannot read password")?,
        ))
    } else {
        generate(options.password_length, &options.password_charset)
    }
}

fn generate(length: u32, charset: &str) -> anyhow::Result<Secret> {
    if length < 8 {
        eprintln!("Warning: {length} characters is a short password.");
    }
    Ok(pw::generate_password(length, charset)?)
}

/// Write `text` to the system clipboard, returning a zeroizing copy of it so
/// the caller can later clear the clipboard only if it is still unchanged.
fn copy_to_clipboard(text: &str) -> anyhow::Result<Zeroizing<String>> {
    let mut clipboard = Clipboard::get();
    clipboard
        .write_text(text)
        .map_err(|e| anyhow::anyhow!("cannot write to clipboard: {e}"))?;
    Ok(Zeroizing::new(text.to_string()))
}

/// Tell the user a password was copied, mentioning the auto-clear when enabled.
fn announce_copied(what: &str, timeout: u64) {
    if timeout == 0 {
        eprintln!("{what} copied to clipboard.");
    } else if io::stdin().is_terminal() {
        eprintln!("{what} copied to clipboard; clearing in {timeout}s (press ENTER to clear now).");
    } else {
        eprintln!("{what} copied to clipboard; clearing in {timeout}s.");
    }
}

/// Hold the copied password on the clipboard for `timeout` seconds, then clear
/// it. Pressing ENTER during the wait clears immediately; Ctrl-C exits without
/// clearing. The clipboard is only cleared when it still holds our value, so a
/// password the user copied in the meantime is preserved. With `timeout` 0 the
/// clipboard is left untouched.
fn wait_and_clear(secret: &str, timeout: u64) {
    if timeout == 0 {
        return;
    }

    // Pressing ENTER clears immediately. Only watch stdin when it is a
    // terminal, so piped input (e.g. --passphrase-stdin) is left untouched.
    // The reader thread is abandoned when the process exits after the wait.
    let entered = Arc::new(AtomicBool::new(false));
    if io::stdin().is_terminal() {
        let flag = Arc::clone(&entered);
        std::thread::spawn(move || {
            let mut line = String::new();
            if io::stdin().lock().read_line(&mut line).is_ok() {
                flag.store(true, Ordering::SeqCst);
            }
        });
    }

    let deadline = Instant::now() + Duration::from_secs(timeout);
    while Instant::now() < deadline && !entered.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
    }

    if clear_if_unchanged(secret) {
        eprintln!("Clipboard cleared.");
    } else {
        eprintln!("Clipboard changed since copy; left as-is.");
    }
}

/// Wipe our password from the clipboard, but only while it still holds that
/// value, so anything the user copied during the wait is left untouched.
/// Returns whether we wiped it.
///
/// We overwrite with a single space rather than emptying the clipboard. The
/// `clip` library behind `clippers` keeps a process-global owner and only
/// hands the clipboard contents to the desktop clipboard manager (e.g.
/// GNOME/mutter) at exit, and *only when its buffer is non-empty*. An empty
/// clear is therefore never propagated: the manager keeps serving the cached
/// password even though this process owned an empty selection. A one-character
/// value makes the hand-off fire and evicts the password.
fn clear_if_unchanged(secret: &str) -> bool {
    let mut clipboard = Clipboard::get();
    let still_ours = clipboard
        .read()
        .and_then(|data| data.into_text())
        .is_some_and(|text| text == secret);
    still_ours && clipboard.write_text(" ").is_ok()
}

fn confirm(prompt: &str) -> anyhow::Result<bool> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "Yes"))
}

/// Replace control, bidirectional and zero-width characters before echoing
/// vault content to a terminal, in case a vault contains names this version
/// would not accept (an old, imported or shared vault). This blocks
/// Trojan-Source / homoglyph style display spoofing.
fn sanitize(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() || pw::is_display_spoofing_char(c) {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
}
