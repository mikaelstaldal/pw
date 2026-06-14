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

| Command                                 | Description                                                                                                |
|-----------------------------------------|------------------------------------------------------------------------------------------------------------|
| `pw init`                               | Create a new empty vault. Asks for the passphrase twice.                                                   |
| `pw get <name> [--show]`                | Copy the password to the clipboard, or print it with `--show`. Prints the username first, if there is one. |
| `pw list [PATTERN]`                     | List entries, optionally filtered by a case-insensitive substring of the name.                             |
| `pw add <name> [username] [options]`    | Add an entry. The password is generated (and copied to the clipboard) unless `--input-password` is given.  |
| `pw update <name> [username] [options]` | Replace the username and password of an existing entry, or just the username/url with `--keep-password`.   |
| `pw remove <name> [--yes]`              | Remove an entry, after confirmation (`--yes` skips it).                                                    |
| `pw generate [options]`                 | Generate a password without storing it.                                                                    |
| `pw export`                             | Print the decrypted vault as JSON on stdout, for backup or migration.                                      |
| `pw install-browser [--uninstall]`      | Install (or remove) the Firefox native-messaging manifest for the browser integration. See below.          |

Options for `add`, `update` and `generate`:

- `--password-length <n>` — length of the generated password (default 16)
- `--password-charset <chars>` — characters to generate from
  (default: letters, digits and `-`)
- `--input-password` — type the password instead of generating one
  (`add`/`update` only)
- `--url <url>` — the site this entry is for, used by the Firefox integration
  when the entry name is not the hostname (`add`/`update` only); omitting it on
  `update` clears it, like the username
- `--keep-password` — on `update`, keep the existing password and change only
  the username and url (`update` only)
- `--show` — print the password to stdout instead of copying it to the
  clipboard

Global options:

- `--file <path>` — use another vault file than `~/pw.scrypt`
- `--passphrase-stdin` — read the passphrase as a single line from stdin
  instead of prompting; for scripts and other non-interactive use
- `--clear-timeout <secs>` — how long a copied password stays on the
  clipboard before `pw` clears it (default 20). `pw` waits this long, then
  clears the clipboard unless you have copied something else in the meantime;
  press ENTER to clear immediately, or Ctrl-C to exit without clearing. Use
  `0` to leave the clipboard untouched (the old behaviour)

The *username* is a free-form label stored alongside the password; it may be
omitted. Generated passwords use a cryptographically secure random number
generator (ChaCha20, OS-seeded) without modulo bias.

## Firefox integration

`pw` can fill usernames and passwords into login forms in Firefox **without
using the clipboard** and **without handing Firefox the whole vault**. A
companion binary, `pw-browser-host`, decrypts the vault in-process, releases
only the single entry matching the site you are on, and prompts for the master
passphrase in a `pinentry` dialog *outside* the browser. Only entries with a
`url` set are used in the browser: set the site explicitly with
`pw add <name> --url github.com` (or `pw update <name> --url …`). An entry's
`name` is never matched against the visited site, so it can be anything you
like — useful when you keep two accounts on one site.

**Origin matching** uses a layered rule: an entry matches a request for
`https://login.example.co.uk` when the host part of its `url`
equals the request hostname exactly (`login.example.co.uk`) or is a parent
domain at a label boundary (`example.co.uk`), up to but not including the
registrable domain determined by the Public Suffix List — so a `url` of
`co.uk` or `com` never matches. Matching is case-insensitive and
IDNA/punycode-normalized. Only `https:` origins are eligible (plus
`http://localhost` and `http://127.0.0.1` for local development).

The browser host is **strictly read-only**: it never writes the vault. Which
sites may receive an entry is decided by you, from the CLI: the host releases
an entry only to a site that matches the entry's `url`, which is
set only with the master passphrase in a terminal:

```sh
pw add github.com alice --url github.com      # declare the site with --url
pw add work-github alice --url github.com     # name can be anything; the url decides the match
pw update work-github --url gitlab.com --keep-password   # re-point it, password unchanged
```

A compromised browser therefore cannot make the host release an entry for a
site you never associated with it — only you can, with the master passphrase.

Setup:

```sh
pw install-browser          # writes the native-messaging manifest + default config
```

Then load the add-on in `webextension/` (see `webextension/README.md` for
temporary loading during development and signing for permanent installation).
On a login page, click the toolbar button or press `Ctrl+Alt+L`.

Behaviour is configured in `~/.config/pw/browser.json`:

```json
{"file": "~/pw.scrypt", "cache_minutes": 10}
```

- `cache_minutes` — how long a decrypted vault stays in the host's memory
  before it re-prompts (`0` re-prompts every time).

### Security model

| Threat | Mitigation |
|---|---|
| Malicious/XSS'd page harvesting autofill | No fill without a user gesture; no always-on content script; the page cannot trigger the extension. |
| Page spoofing its origin | The origin is taken from the tab URL in the background script, never from page or content-script input. |
| Phishing domain (`github.com.evil.example`) | Suffix matching at label boundaries bounded by the Public Suffix List — only `evil.example`'s own entries can match. |
| Rogue extension talking to the host | `allowed_extensions` in the manifest pins `pw@staldal.nu`; Firefox (and the snap portal) enforces it. |
| Confined snap browser escaping to read the vault | The snap never gains direct access to `~/pw.scrypt`; it can only ask the portal to launch the named host, gated by `allowed_extensions` and a one-time portal prompt. |
| Compromised pw extension / browser process | Cannot read the vault file or passphrase; can only issue `get-logins` per origin, and only entries you associated with that site (by `name` or `url`, set from the CLI) are released. It cannot associate new sites (the host is read-only). |
| Passphrase leakage via process metadata | The passphrase goes from pinentry into a zeroizing buffer and is consumed in-process — never in argv, the environment, or any subprocess. Zeroized after use. |
| Credentials at rest in the host | Never written to disk; held in host memory only, bounded by `cache_minutes`, zeroized on lock or exit. |
| Clipboard sniffers | The clipboard is not used anywhere in this flow. |

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
leave a truncated vault. The temporary file is always `pw.scrypt.tmp` next to
the vault, so a sandbox policy such as AppArmor only needs to allow
`pw.scrypt`, `pw.scrypt.tmp` and `pw.scrypt.bak`.

## Security notes

- On Unix, the vault and its backup are created with mode `0600` from the
  start. **On Windows, file permissions are not restricted** — keep the vault
  in a directory only your user can read.
- A copied password is removed from the clipboard after `--clear-timeout`
  seconds (default 20; `pw` waits in the foreground, or removes it at once when
  you press ENTER), and only if the clipboard still holds it, so anything you
  copy in the meantime is preserved. To reliably evict the password from the
  desktop clipboard manager the slot is overwritten with a single space rather
  than emptied, so the clipboard ends up holding a space, not nothing. **A
  clipboard history manager (GNOME extensions such
  as GPaste or Clipboard Indicator, KDE Klipper, the Windows clipboard
  history, third-party tools) may keep its own copy that `pw` cannot reach** —
  disable history for sensitive copies, or use `--show` and pipe the password
  to a consumer you control. With `--clear-timeout 0` the password stays on
  the clipboard until something else overwrites it.
- Secrets are zeroized in memory when no longer needed, and never appear in
  debug output.
- On startup `pw` disables core dumps, and on Linux marks itself non-dumpable
  (which also blocks `ptrace` attaches from other same-user processes), so a
  crash cannot persist the derived key or decrypted vault to disk. This does
  **not** protect against swap: while a secret is live, the kernel may page it
  out to swap, where zeroize-on-drop cannot reach it. On a machine that may
  swap, use **encrypted swap** (or disable swap with `swapoff`) to close this
  gap — it is an OS-level setting `pw` cannot enforce itself.
- You can use the `apparmor-profile` file as a template for an Apparmor profile, you need to substitute 
  `${PATH_TO_EXECUTABLE}` with absolute paths. This has only been tested on Ubuntu Linux.
  `apparmor-profile-browser-host` is the matching template for the `pw-browser-host`
  binary (see [Firefox integration](#firefox-integration)); it confines the host
  to reading the vault, reading its config, and launching `pinentry`.

## License

Copyright 2024-2026 Mikael Ståldal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
