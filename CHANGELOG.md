# Changelog

## 0.2.2 (2026-06-12)

- A password copied to the clipboard is now removed after a timeout (default
  20 seconds), instead of lingering indefinitely. `pw` waits in the
  foreground and then overwrites the clipboard if it still holds the password;
  pressing ENTER removes it immediately (Ctrl-C exits without removing). To
  evict the password from the desktop clipboard manager the slot is
  overwritten with a single space rather than emptied. The new global
  `--clear-timeout <secs>` flag tunes the
  delay, and `--clear-timeout 0` restores the previous never-clear behaviour.
  Note that a clipboard *history* manager may retain its own copy that `pw`
  cannot clear — see the README security notes.

## 0.2.1 (2026-06-11)

Filter out strange Unicode characters which can be used for spoofing.

## 0.2.0 (2026-06-11)

Complete rewrite. **The vault file format is unchanged** — existing vaults
keep working as-is, and the file remains recoverable with the standard
`scrypt` tool (`scrypt dec ~/pw.scrypt`).

### Breaking CLI changes

- `--password-length`, `--password-charset` and `--input-password` are no
  longer global flags; they moved onto the `add`, `update` and `generate`
  subcommands (e.g. `pw add example.com user --password-length 24`).
- The username argument of `add`/`update` is now optional.
- `remove` asks for confirmation; pass `--yes` to skip it (scripts).
- Error message texts have changed.

### New

- All cryptography is done in-process; the external `scrypt` binary is no
  longer needed (and is no longer looked up on `PATH`).
- The passphrase is prompted at most once per operation (twice for `init`),
  instead of up to three times.
- `--passphrase-stdin` for non-interactive use.
- `pw get --show` prints the password instead of copying it to the clipboard
  (also available on `add`, `update` and `generate`).
- `pw list [PATTERN]` filters entries; `list` shows which vault file is in
  use.
- `pw export` prints the decrypted vault as JSON for backup/migration.
- A notice is printed whenever something is copied to the clipboard.

### Fixed

- Vault writes are now atomic, with the previous vault kept as
  `pw.scrypt.bak`; a crash can no longer destroy the vault.
- The vault file is created with mode `0600` from the start (Unix).
- Secrets are zeroized in memory and redacted from debug output.
- Wrong passphrase, corrupt vault and missing file are now distinct, helpful
  errors instead of panics.
- `generate` validates the password length (1–1024) and charset (at least 2
  distinct characters) instead of panicking.
- Entry names and usernames are validated (no control characters, at most
  256 characters).
