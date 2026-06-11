use std::path::{Path, PathBuf};

use assert_cmd::Command;
use assert_fs::TempDir;
use predicates::prelude::*;
use predicates::str::contains;

const PASSPHRASE: &str = "test passphrase\n";

/// A `pw` command against `vault`, with the passphrase taken from stdin and
/// small scrypt parameters so debug-mode tests stay fast.
fn pw(vault: &Path) -> Command {
    let mut cmd = Command::cargo_bin("pw").unwrap();
    cmd.arg("--file")
        .arg(vault)
        .args(["--passphrase-stdin", "--scrypt-log-n", "12"]);
    cmd
}

fn init_vault(dir: &TempDir) -> PathBuf {
    let vault = dir.path().join("pw.scrypt");
    pw(&vault)
        .arg("init")
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout(contains("Initialized empty vault"));
    vault
}

/// Add an entry with a generated password and return that password.
fn add_entry(vault: &Path, name: &str, username: &str) -> String {
    let assert = pw(vault)
        .args(["add", name, username, "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    stdout.trim_end().to_string()
}

#[test]
fn init_creates_vault() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    assert!(vault.exists());
}

#[test]
fn init_fails_if_vault_already_exists() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    pw(&vault)
        .arg("init")
        .write_stdin(PASSPHRASE)
        .assert()
        .failure()
        .stderr(contains("already exists"));
}

#[test]
fn get_fails_if_vault_does_not_exist() {
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("pw.scrypt");
    pw(&vault)
        .args(["get", "bogus"])
        .write_stdin(PASSPHRASE)
        .assert()
        .failure()
        .stderr(contains("run `pw init`"));
}

#[test]
fn add_then_get_round_trip() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    let password = add_entry(&vault, "foo", "user1");
    assert_eq!(password.chars().count(), 16);

    pw(&vault)
        .args(["get", "foo", "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout(format!("user1\n{password}\n"));
}

#[test]
fn add_without_username() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    let password = add_entry(&vault, "foo", "");

    // No username line, just the password.
    pw(&vault)
        .args(["get", "foo", "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout(format!("{password}\n"));
}

#[test]
fn get_unknown_entry() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    pw(&vault)
        .args(["get", "bogus", "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .failure()
        .stderr(contains("no entry 'bogus'").and(contains("try `pw list`")));
}

#[test]
fn add_duplicate_entry() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    add_entry(&vault, "foo", "user1");
    pw(&vault)
        .args(["add", "foo", "user2", "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .failure()
        .stderr(contains("already exists").and(contains("use `pw update`")));
}

#[test]
fn update_changes_the_password() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    add_entry(&vault, "foo", "user1");

    let assert = pw(&vault)
        .args(["update", "foo", "user2", "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .success();
    let new_password = String::from_utf8(assert.get_output().stdout.clone())
        .unwrap()
        .trim_end()
        .to_string();

    pw(&vault)
        .args(["get", "foo", "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout(format!("user2\n{new_password}\n"));
}

#[test]
fn update_unknown_entry() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    pw(&vault)
        .args(["update", "bogus", "user", "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .failure()
        .stderr(contains("no entry 'bogus'"));
}

#[test]
fn remove_with_yes() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    add_entry(&vault, "foo", "user1");

    pw(&vault)
        .args(["remove", "foo", "--yes"])
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout(contains("Removed entry 'foo'"));

    pw(&vault)
        .args(["get", "foo", "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .failure()
        .stderr(contains("no entry 'foo'"));
}

#[test]
fn remove_confirmed_interactively() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    add_entry(&vault, "foo", "user1");

    // First stdin line answers the confirmation, the second is the passphrase.
    pw(&vault)
        .args(["remove", "foo"])
        .write_stdin(format!("y\n{PASSPHRASE}"))
        .assert()
        .success()
        .stdout(contains("Removed entry 'foo'"));
}

#[test]
fn remove_aborts_without_confirmation() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    add_entry(&vault, "foo", "user1");

    pw(&vault)
        .args(["remove", "foo"])
        .write_stdin("n\n")
        .assert()
        .failure()
        .stderr(contains("Aborted"));

    // The entry is still there.
    pw(&vault)
        .args(["get", "foo", "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .success();
}

#[test]
fn list_shows_vault_path_and_filters() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    add_entry(&vault, "foo", "user1");
    add_entry(&vault, "bar", "user2");

    pw(&vault)
        .arg("list")
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout(
            contains("Vault: ")
                .and(contains("(2 entries)"))
                .and(contains("foo: user1"))
                .and(contains("bar: user2")),
        );

    pw(&vault)
        .args(["list", "FO"])
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout(contains("foo: user1").and(contains("bar").not()));
}

#[test]
fn wrong_passphrase() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    pw(&vault)
        .arg("list")
        .write_stdin("not the passphrase\n")
        .assert()
        .failure()
        .stderr(contains("incorrect passphrase"));
}

#[test]
fn export_prints_the_vault_as_json() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    let password = add_entry(&vault, "foo", "user1");

    pw(&vault)
        .arg("export")
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout(contains(r#""version":1"#).and(contains(format!(
            r#"{{"name":"foo","username":"user1","password":"{password}"}}"#
        ))))
        .stderr(contains("Warning"));
}

#[test]
fn backup_is_kept_after_rewrite() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    add_entry(&vault, "foo", "user1");

    let backup = dir.path().join("pw.scrypt.bak");
    assert!(backup.exists());

    // The backup holds the previous generation: an empty vault.
    pw(&backup)
        .arg("list")
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout(contains("(0 entries)"));
}

#[test]
fn rejects_control_characters_in_name() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    pw(&vault)
        .args(["add", "bad\x1bname", "user", "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .failure()
        .stderr(contains("invalid entry name"));
}

#[test]
fn generate_prints_password_of_requested_length() {
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("pw.scrypt"); // not created; generate is stateless
    let assert = pw(&vault)
        .args(["generate", "--password-length", "32", "--show"])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert_eq!(stdout.trim_end().chars().count(), 32);
}

#[test]
fn generate_rejects_bad_charset() {
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("pw.scrypt");
    pw(&vault)
        .args(["generate", "--password-charset", "aaa", "--show"])
        .assert()
        .failure()
        .stderr(contains("invalid password charset"));
}

#[cfg(unix)]
#[test]
fn vault_created_with_restrictive_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    let mode = std::fs::metadata(&vault).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}
