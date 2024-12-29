//! # PW
//!
//! A command line password manager

use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version)]
struct Cli {
    /// The encrypted passwords file, ~/pw.scrypt by default
    #[arg(long)]
    file: Option<std::path::PathBuf>,

    /// Password length
    #[arg(long, default_value = "16")]
    password_length: u8,

    /// Password charset
    #[arg(long, default_value = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")]
    password_charset: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create an empty encrypted passwords file
    Init {
    },

    /// Lookup a password
    Get {
        /// The password entry
        name: String,
    },

    /// List all passwords
    List {
    },

    /// Add a password
    Add {
        /// The password entry
        name: String,
        /// Username
        username: String,
    },

    /// Update a password
    Update {
        /// The password entry
        name: String,
        /// Username
        username: String,
    },

    /// Remove a password
    Remove {
        /// The password entry
        name: String,
    },

    /// Generates a password without storing it
    Generate {
    },
}

fn main() -> Result<ExitCode, anyhow::Error> {
    let cli = Cli::parse();

    let file = cli.file.unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("pw.scrypt")
    });

    match &cli.command {
        Commands::Init { } => {
            pw::init(&file)?;
            println!("{} initialized", file.display());
        }
        Commands::Get { name } => {
            let entry = pw::get(&file, name)?;
            if !entry.username.is_empty() {
                println!("{}", entry.username);
            }
            let mut clipboard = clippers::Clipboard::get();
            clipboard.write_text(entry.password)?;
        }
        Commands::List { } => {
            let entries = pw::list(&file)?;
            for entry in entries {
                println!("{}: {}", entry.name, entry.username);
            }
        }
        Commands::Add { name, username } => {
            let password = pw::generate_password(
                cli.password_length as usize, cli.password_charset);
            pw::add(&file, pw::PasswordEntry {
                name: name.clone(),
                username: username.clone(),
                password: password.clone(),
            })?;
            let mut clipboard = clippers::Clipboard::get();
            clipboard.write_text(password)?;
        }
        Commands::Update { name, username } => {
            let password = pw::generate_password(
                cli.password_length as usize, cli.password_charset);
            pw::update(&file, pw::PasswordEntry {
                name: name.clone(),
                username: username.clone(),
                password: password.clone(),
            })?;
            let mut clipboard = clippers::Clipboard::get();
            clipboard.write_text(password)?;
        }
        Commands::Remove { name } => {
            pw::remove(&file, name)?;
        }
        Commands::Generate { } => {
            let password = pw::generate_password(
                cli.password_length as usize, cli.password_charset);
            let mut clipboard = clippers::Clipboard::get();
            clipboard.write_text(password)?;
        }
    }

    Ok(ExitCode::SUCCESS)
}
