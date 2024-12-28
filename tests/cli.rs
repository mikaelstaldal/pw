use assert_cmd::Command;
use assert_fs::fixture::FileWriteStr;
use assert_fs::NamedTempFile;
use predicates::str::contains;

#[test]
fn init_fails_if_pw_file_already_exists() {
    let mut cmd = Command::cargo_bin("pw").unwrap();

    let pw_file = NamedTempFile::new("pw.scrypt").unwrap();
    pw_file.write_str("").unwrap();

    cmd.arg("--file").arg(pw_file.path()).arg("init");
    cmd.assert()
        .failure()
        .stderr(contains("Error: File already exists: "));

    pw_file.close().unwrap();
}

#[test]
fn get_fails_if_pw_file_does_not_exist() {
    let mut cmd = Command::cargo_bin("pw").unwrap();

    let pw_file = NamedTempFile::new("pw.scrypt").unwrap();

    cmd.arg("--file").arg(pw_file.path()).arg("get").arg("bogus");
    cmd.assert()
        .failure()
        .stderr(contains("Error: File not found: "));

    pw_file.close().unwrap();
}
