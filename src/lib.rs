//! # PW
//!
//! A command line password manager

use crate::PwError::{
    AlreadyExists, FileAlreadyExists, FileNotFound, InvalidJson, NotFound, ScryptError,
};
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::{Command, Stdio};

#[derive(thiserror::Error, Debug)]
pub enum PwError {
    #[error("File not found: {0}")]
    FileNotFound(String),
    #[error("File already exists: {0}")]
    FileAlreadyExists(String),
    #[error("Scrypt error")]
    ScryptError(),
    #[error("Invalid JSON {0}")]
    InvalidJson(String, #[source] serde_json::Error),
    #[error("Password not found")]
    NotFound(),
    #[error("Password already exists")]
    AlreadyExists(),
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct PasswordEntry {
    pub name: String,
    pub username: String,
    pub password: String,
}

pub fn init(file: &Path) -> Result<(), PwError> {
    if file.exists() {
        return Err(FileAlreadyExists(file.display().to_string()));
    }

    write(file, &Vec::<PasswordEntry>::new())
}

pub fn get(file: &Path, name: &str) -> Result<PasswordEntry, PwError> {
    if !file.exists() {
        return Err(FileNotFound(file.display().to_string()));
    }

    let data = read(file)?;

    data.into_iter().find(|e| e.name == name).ok_or(NotFound())
}

pub fn list(file: &Path) -> Result<Vec<PasswordEntry>, PwError> {
    if !file.exists() {
        return Err(FileNotFound(file.display().to_string()));
    }

    read(file)
}

pub fn add(file: &Path, new_entry: PasswordEntry) -> Result<(), PwError> {
    if !file.exists() {
        return Err(FileNotFound(file.display().to_string()));
    }

    let mut data = read(file)?;

    if data.iter().any(|e| e.name == new_entry.name) {
        return Err(AlreadyExists());
    }

    data.push(new_entry);

    write(file, &data)
}

pub fn update(file: &Path, new_entry: PasswordEntry) -> Result<(), PwError> {
    if !file.exists() {
        return Err(FileNotFound(file.display().to_string()));
    }

    let mut data = read(file)?;

    if let Some(entry) = data.iter_mut().find(|e| e.name == new_entry.name) {
        entry.username = new_entry.username;
        entry.password = new_entry.password;
    } else {
        return Err(NotFound());
    }

    write(file, &data)
}

pub fn remove(file: &Path, name: &str) -> Result<(), PwError> {
    if !file.exists() {
        return Err(FileNotFound(file.display().to_string()));
    }

    let mut data = read(file)?;

    let original_len = data.len();
    data.retain(|e| e.name != name);
    if data.len() == original_len {
        return Err(NotFound());
    }

    write(file, &data)
}

fn read(file: &Path) -> Result<Vec<PasswordEntry>, PwError> {
    let command = Command::new("scrypt")
        .arg("dec")
        .arg(file.as_os_str())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to start scrypt");

    let output = command.wait_with_output().expect("failed to run scrypt");

    if !output.status.success() {
        return Err(ScryptError().into());
    }

    serde_json::from_slice(&output.stdout).map_err(|err| {
        InvalidJson(
            String::from_utf8(output.stdout).unwrap_or(String::from("")),
            err,
        )
    })
}

fn write(file: &Path, data: &Vec<PasswordEntry>) -> Result<(), PwError> {
    let mut command = Command::new("scrypt")
        .arg("enc")
        .arg("-")
        .arg(file.as_os_str())
        .stdin(Stdio::piped())
        .spawn()
        .expect("failed to start scrypt");

    if let Some(stdin) = command.stdin.as_mut() {
        serde_json::to_writer(stdin, data).map_err(|err| InvalidJson(String::from(""), err))?;
    }

    let status = command.wait().expect("failed to run scrypt");

    if !status.success() {
        return Err(ScryptError().into());
    }

    Ok(())
}

pub fn generate_password(length: usize, charset: String) -> String {
    let charset: Vec<char> = charset.chars().collect();
    let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
    (0..length)
        .map(|_| charset[rng.gen_range(0..charset.len())])
        .collect()
}

#[cfg(test)]
mod tests {
    use assertables::assert_len_eq_x;
    use super::*;

    #[test]
    fn generate() {
        let pw = generate_password(16, "0123456789".to_string());
        assert_len_eq_x!(pw, 16);
    }
}
