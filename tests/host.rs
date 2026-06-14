//! Wire-protocol tests for `pw-browser-host`. These
//! exercise the framing, request dispatch and error paths that do not need a
//! `pinentry` dialog or a real vault: `status`, `lock`, an ineligible origin,
//! a request with no origin, and an unknown request type.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// The package version is reported in `status.version`.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Locate the `pw-browser-host` binary next to this test executable. The test
/// is built into `<target>/debug/deps/`; the binary targets live one level up.
fn host_bin() -> PathBuf {
    let mut path = std::env::current_exe().expect("current exe");
    path.pop(); // drop the test executable
    if path.ends_with("deps") {
        path.pop();
    }
    path.push("pw-browser-host");
    path
}

struct Host {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl Host {
    fn spawn() -> Host {
        // Point the host at a config path that does not exist so it uses
        // built-in defaults and never reads a developer's real vault.
        let mut child = Command::new(host_bin())
            .env(
                "PW_BROWSER_CONFIG",
                "/nonexistent/pw-browser-host-test.json",
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn pw-browser-host");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        Host {
            child,
            stdin,
            stdout,
        }
    }

    fn request(&mut self, json: &str) -> String {
        let bytes = json.as_bytes();
        self.stdin
            .write_all(&(bytes.len() as u32).to_ne_bytes())
            .unwrap();
        self.stdin.write_all(bytes).unwrap();
        self.stdin.flush().unwrap();

        let mut len = [0u8; 4];
        self.stdout.read_exact(&mut len).unwrap();
        let n = u32::from_ne_bytes(len) as usize;
        let mut buf = vec![0u8; n];
        self.stdout.read_exact(&mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    fn finish(mut self) {
        drop(self.stdin); // EOF -> the host exits its read loop
        let status = self.child.wait().unwrap();
        assert!(status.success(), "host exited with {status:?}");
    }
}

#[test]
fn status_reports_locked_and_version() {
    let mut host = Host::spawn();
    let resp = host.request(r#"{"id":1,"type":"status"}"#);
    assert!(resp.contains(r#""type":"status""#), "{resp}");
    assert!(resp.contains(r#""id":1"#), "{resp}");
    assert!(resp.contains(r#""locked":true"#), "{resp}");
    assert!(
        resp.contains(&format!(r#""version":"{VERSION}""#)),
        "{resp}"
    );
    host.finish();
}

#[test]
fn lock_is_acknowledged() {
    let mut host = Host::spawn();
    let resp = host.request(r#"{"id":2,"type":"lock"}"#);
    assert!(resp.contains(r#""type":"ok""#), "{resp}");
    assert!(resp.contains(r#""id":2"#), "{resp}");
    host.finish();
}

#[test]
fn non_https_origin_is_rejected_without_unlocking() {
    let mut host = Host::spawn();
    let resp = host.request(r#"{"id":3,"type":"get-logins","origin":"http://example.com"}"#);
    assert!(resp.contains(r#""type":"error""#), "{resp}");
    assert!(resp.contains(r#""code":"invalid-origin""#), "{resp}");
    assert!(resp.contains(r#""id":3"#), "{resp}");
    host.finish();
}

#[test]
fn missing_origin_is_rejected() {
    let mut host = Host::spawn();
    let resp = host.request(r#"{"id":4,"type":"get-logins"}"#);
    assert!(resp.contains(r#""code":"invalid-origin""#), "{resp}");
    host.finish();
}

#[test]
fn unknown_request_type_is_an_internal_error() {
    let mut host = Host::spawn();
    let resp = host.request(r#"{"id":5,"type":"frobnicate"}"#);
    assert!(resp.contains(r#""type":"error""#), "{resp}");
    assert!(resp.contains(r#""code":"internal""#), "{resp}");
    assert!(resp.contains(r#""id":5"#), "{resp}");
    host.finish();
}

#[test]
fn several_requests_on_one_connection() {
    let mut host = Host::spawn();
    assert!(host
        .request(r#"{"id":1,"type":"status"}"#)
        .contains(r#""type":"status""#));
    assert!(host
        .request(r#"{"id":2,"type":"lock"}"#)
        .contains(r#""type":"ok""#));
    assert!(host
        .request(r#"{"id":3,"type":"status"}"#)
        .contains(r#""locked":true"#));
    host.finish();
}

/// A `get-logins` that has to unlock must first tell pinentry where the user's
/// display/terminal and locale are (the `OPTION` commands `gpg-agent` sends),
/// or a pinentry launched outside a terminal — as it always is here — can put
/// up a dialog it never completes, hanging the host on `GETPIN`. This drives
/// the full unlock path against a stub pinentry that records what it received.
#[cfg(unix)]
#[test]
fn get_logins_forwards_environment_to_pinentry() {
    use pw::{add, init, Params, Passphrase, PasswordEntry};
    use std::os::unix::fs::PermissionsExt;

    // Small KDF parameters keep the unlock fast in debug builds.
    const PARAMS: Params = Params {
        log_n: 12,
        r: 8,
        p: 1,
    };
    let passphrase = Passphrase::new("test passphrase".to_string());

    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.scrypt");
    init(&vault, &passphrase, &PARAMS).unwrap();
    add(
        &vault,
        &passphrase,
        PasswordEntry {
            name: "example.com".to_string(),
            username: "alice".to_string(),
            password: "s3cret".into(),
            url: Some("example.com".to_string()),
        },
        &PARAMS,
    )
    .unwrap();

    // `cache_minutes:0` so the unlock is exercised on every request.
    let config = dir.path().join("browser.json");
    std::fs::write(
        &config,
        format!(
            r#"{{"file":{:?},"cache_minutes":0}}"#,
            vault.to_str().unwrap()
        ),
    )
    .unwrap();

    // A stub pinentry: it logs every command it is sent and answers GETPIN
    // with the test passphrase. The data line uses Assuan percent-encoding
    // (`%20` for the space) just as a real pinentry would.
    let cmdlog = dir.path().join("pinentry-cmds.log");
    let stub = dir.path().join("stub-pinentry");
    std::fs::write(
        &stub,
        "#!/bin/sh\n\
         printf 'OK ready\\n'\n\
         while IFS= read -r line; do\n\
           printf '%s\\n' \"$line\" >> \"$PW_TEST_CMDLOG\"\n\
           case \"$line\" in\n\
             GETPIN) printf 'D test%%20passphrase\\n'; printf 'OK\\n' ;;\n\
             BYE) printf 'OK\\n'; exit 0 ;;\n\
             *) printf 'OK\\n' ;;\n\
           esac\n\
         done\n",
    )
    .unwrap();
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();

    let mut child = Command::new(host_bin())
        .env("PW_BROWSER_CONFIG", &config)
        .env("PW_PINENTRY", &stub)
        .env("PW_TEST_CMDLOG", &cmdlog)
        // The environment a pinentry needs to locate the session.
        .env("DISPLAY", ":0")
        .env("TERM", "xterm-256color")
        .env("LANG", "en_US.UTF-8")
        .env_remove("GPG_TTY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn pw-browser-host");
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    let json = r#"{"id":7,"type":"get-logins","origin":"https://example.com"}"#;
    stdin.write_all(&(json.len() as u32).to_ne_bytes()).unwrap();
    stdin.write_all(json.as_bytes()).unwrap();
    stdin.flush().unwrap();

    let mut len = [0u8; 4];
    stdout.read_exact(&mut len).unwrap();
    let mut buf = vec![0u8; u32::from_ne_bytes(len) as usize];
    stdout.read_exact(&mut buf).unwrap();
    let resp = String::from_utf8(buf).unwrap();

    drop(stdin);
    child.wait().unwrap();

    // The unlock succeeded and the entry was released.
    assert!(resp.contains(r#""type":"logins""#), "{resp}");
    assert!(resp.contains(r#""name":"example.com""#), "{resp}");

    // pinentry was told the environment, before any SET* command.
    let cmds = std::fs::read_to_string(&cmdlog).unwrap();
    assert!(cmds.contains("OPTION display=:0"), "{cmds}");
    assert!(cmds.contains("OPTION ttytype=xterm-256color"), "{cmds}");
    assert!(cmds.contains("OPTION lc-ctype=en_US.UTF-8"), "{cmds}");
    assert!(cmds.contains("OPTION lc-messages=en_US.UTF-8"), "{cmds}");
    // No terminal was advertised (GPG_TTY unset), so the GUI path is kept.
    assert!(!cmds.contains("OPTION ttyname"), "{cmds}");
    let display_at = cmds.find("OPTION display").unwrap();
    let settitle_at = cmds.find("SETTITLE").unwrap();
    assert!(
        display_at < settitle_at,
        "options must precede SET*: {cmds}"
    );
}
