# pw — a command line password manager

`pw` keeps your passwords in a single encrypted file (`~/pw.scrypt` by
default). All cryptography happens in-process; there are no runtime
dependencies on external programs.

## Installation

```sh
cargo install --path .
```

## Quick start

```sh
pw init                      # create an empty vault at ~/pw.scrypt
pw add github.com mikael     # generate a password for an entry, copy it to the clipboard
pw get github.com            # copy the password to the clipboard again
pw list                      # show all entries
```

## Commands

| Command | Description |
|---|---|
| `pw init` | Create a new empty vault. Asks for the passphrase twice. |
| `pw get <name> [--show]` | Copy the password to the clipboard, or print it with `--show`. Prints the username first, if there is one. |
| `pw list [PATTERN]` | List entries, optionally filtered by a case-insensitive substring of the name. |
| `pw add <name> [username] [options]` | Add an entry. The password is generated (and copied to the clipboard) unless `--input-password` is given. |
| `pw update <name> [username] [options]` | Replace the username and password of an existing entry. |
| `pw remove <name> [--yes]` | Remove an entry, after confirmation (`--yes` skips it). |
| `pw generate [options]` | Generate a password without storing it. |
| `pw export` | Print the decrypted vault as JSON on stdout, for backup or migration. |

Options for `add`, `update` and `generate`:

- `--password-length <n>` — length of the generated password (default 16)
- `--password-charset <chars>` — characters to generate from
  (default: letters, digits and `-`)
- `--input-password` — type the password instead of generating one
  (`add`/`update` only)
- `--show` — print the password to stdout instead of copying it to the
  clipboard

Global options:

- `--file <path>` — use another vault file than `~/pw.scrypt`
- `--passphrase-stdin` — read the passphrase as a single line from stdin
  instead of prompting; for scripts and other non-interactive use

The *username* is a free-form label stored alongside the password; it may be
omitted. Generated passwords use a cryptographically secure random number
generator (ChaCha20, OS-seeded) without modulo bias.

## File format and recovery

The vault is a standard [scrypt encrypted-data format](https://github.com/Tarsnap/scrypt/blob/master/FORMAT)
(version 0) file: scrypt KDF (`N=2^17, r=8, p=1` when writing), AES-256-CTR
encryption and HMAC-SHA256 integrity protection. Inside is a small JSON
document:

```json
{"version":1,"entries":[{"name":"github.com","username":"mikael","password":"..."}]}
```

Because the container is the standard format, the vault can always be
recovered without `pw`, using the common
[scrypt](https://www.tarsnap.com/scrypt.html) tool:

```sh
scrypt dec ~/pw.scrypt
```

which prints the JSON above. `pw export` does the same from within `pw`.

Writes are atomic (write-to-temp, fsync, rename), and the previous version of
the vault is kept as `pw.scrypt.bak` next to it. A crash mid-write can never
leave a truncated vault.

## Security notes

- On Unix, the vault and its backup are created with mode `0600` from the
  start. **On Windows, file permissions are not restricted** — keep the vault
  in a directory only your user can read.
- Passwords copied to the clipboard stay there until something else is
  copied; `pw` tells you whenever it writes to the clipboard.
- Secrets are zeroized in memory when no longer needed, and never appear in
  debug output.
