//! # PW
//!
//! A command line password manager. All prompting, terminal and clipboard
//! handling lives here; the library never assumes a terminal.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

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
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

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
                copy_to_clipboard(entry.password.expose())?;
                eprintln!("Password for '{}' copied to clipboard.", sanitize(&name));
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
                copy_to_clipboard(password.expose())?;
            }
            let entry = PasswordEntry {
                name: name.clone(),
                username: username.unwrap_or_default(),
                password,
            };
            pw::add(&file, &passphrase, entry, &params)?;
            if !show {
                eprintln!("Password for '{}' copied to clipboard.", sanitize(&name));
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
                copy_to_clipboard(password.expose())?;
            }
            let entry = PasswordEntry {
                name: name.clone(),
                username: username.unwrap_or_default(),
                password,
            };
            pw::update(&file, &passphrase, entry, &params)?;
            if !show {
                eprintln!("Password for '{}' copied to clipboard.", sanitize(&name));
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
                copy_to_clipboard(password.expose())?;
                eprintln!("Generated password copied to clipboard.");
            }
        }
        Commands::Export {} => {
            let passphrase = obtain_passphrase(cli.passphrase_stdin, false)?;
            let json = pw::export(&file, &passphrase)?;
            eprintln!("Warning: the decrypted vault follows on stdout.");
            println!("{}", json.as_str());
        }
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

fn copy_to_clipboard(text: &str) -> anyhow::Result<()> {
    let mut clipboard = Clipboard::get();
    clipboard
        .write_text(text)
        .map_err(|e| anyhow::anyhow!("cannot write to clipboard: {e}"))
}

fn confirm(prompt: &str) -> anyhow::Result<bool> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "Yes"))
}

/// Replace control characters before echoing vault content to a terminal,
/// in case an old vault contains names this version would not accept.
fn sanitize(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .collect()
}
