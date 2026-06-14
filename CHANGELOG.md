# Changelog

## 0.3.0 (2026-06-14)

### Firefox web integration

- New `pw-browser-host` binary: a Firefox native-messaging host that fills
  usernames and passwords into login forms **without the clipboard** and
  **without giving the browser the whole vault**. It prompts for the master
  passphrase via `pinentry` (outside the browser), decrypts in-process, and
  releases only an entry matching the visited site. It is **strictly
  read-only** — it never writes the vault.
- Which sites may receive an entry is set entirely from the CLI: the host
  releases an entry only to a site matching the entry's `url`, which requires
  the master passphrase to set. Only entries with a `url` are usable in the
  browser. A compromised browser cannot associate new sites, which is what
  keeps the host read-only.
- New `pw install-browser` subcommand writes the native-messaging manifest(s),
  detecting the snap and non-snap Firefox layouts (overridable with
  `--snap`/`--no-snap`), and creates a default `~/.config/pw/browser.json`.
  `--uninstall` removes the manifest(s).
- New `webextension/` Firefox add-on (MV2): a background script holding the
  native-messaging port, a toolbar popup that picks among multiple matches,
  and an on-demand fill script. It contains no crypto and stores no secrets.
- Library: `pw::matching_entries` and `pw::origin_hostname` match a site's
  origin to entry urls by the eTLD+1 rule (Public Suffix List), with
  IDNA normalization and https-only eligibility.
- New optional `url` field on entries (`pw add --url` / `pw update --url`),
  which the browser integration matches against the visited site; the entry
  `name` is never matched. It is omitted from the stored JSON when empty, so
  existing vaults stay byte-identical to the previous format.
- New `apparmor-profile-browser-host` template confining `pw-browser-host` to
  read-only access (the vault and its config) plus launching `pinentry`.

### Other

- `pw update <name> --keep-password` changes an entry's username and url while
  keeping its current password, for re-pointing or relabelling an entry without
  rotating the secret.

## 0.2.2 (2026-06-12)

- On startup `pw` now disables core dumps and, on Linux, marks itself
  non-dumpable (which also blocks `ptrace` attaches from same-user processes),
  so a crash can no longer persist the derived key or decrypted vault to disk.
  Swap is still an OS concern — see the README security notes on encrypted
  swap.
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
