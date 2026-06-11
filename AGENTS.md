# Coding agent instructions

This file provides guidance to coding agents when working with code in this repository.

## Project

`pw` is a command line password manager written in Rust. It stores passwords in a single encrypted file (`~/pw.scrypt` by default) using the standard Tarsnap scrypt encrypted-data format, so vaults remain recoverable with the common `scrypt` tool (`scrypt dec`).

## Commands

```sh
cargo build                  # build
cargo test                   # all tests (unit + integration)
cargo test --lib             # unit tests only
cargo test --test cli        # CLI integration tests (tests/cli.rs)
cargo test --test interop    # scrypt-format interop tests (tests/interop.rs)
cargo test <test_name>       # single test by name
cargo clippy                 # lint
cargo fmt                    # format
```

Two interop tests shell out to the external `scrypt` binary and silently skip when it is not on `PATH`; `tests/data/known_answer.scrypt` is a fixed known-answer fixture that always runs.

## Architecture

Strict three-layer library (`src/lib.rs` is the crate root) plus a thin binary:

1. **`src/scrypt_format.rs`** — pure byte codec for the scrypt encrypted-data format v0 (scrypt KDF, AES-256-CTR, HMAC-SHA256). Does no I/O and knows nothing about vault contents. Must stay byte-compatible with Tarsnap's `scrypt` tool in both directions — this is the project's central compatibility guarantee (verified by `tests/interop.rs`).
2. **`src/vault.rs`** — encrypted file storage: the JSON envelope (`{"version":1,"entries":[...]}`) inside the scrypt format, atomic writes (write-to-temp, fsync, rename, keep previous as `.bak`), mode `0600` on Unix. Bare JSON arrays written by pw ≤ 0.1.x are still accepted on read.
3. **`src/lib.rs`** — domain operations (init/get/list/add/update/remove/export) and input validation. Each operation takes the vault path and a `Passphrase` parameter.
4. **`src/main.rs`** — the CLI binary (clap). ALL prompting, terminal and clipboard handling lives here; the library never prompts and never assumes a terminal, so it can serve non-interactive hosts.

Error types are layered the same way: `scrypt_format::Error` → `vault::Error` → `PwError`, with `lib.rs` mapping low-level errors to user-meaningful ones (e.g. wrong-passphrase vs corrupt-vault vs I/O are distinct).

## Secret handling conventions

- Passwords are wrapped in `Secret`, the master passphrase in `Passphrase`: both are zeroized on drop and redacted by `Debug`. Decrypted buffers use `Zeroizing`.
- The only way a secret leaves `Secret` is `expose()` — named so every exposure site is greppable. Keep it that way.
- Never print or log decrypted data on error paths.

## Testing conventions

- Default scrypt KDF parameters (`N=2^17`) are deliberately slow; tests always use `log_n = 12`. Unit tests pass small `Params` directly; CLI tests use the hidden global flag `--scrypt-log-n 12` together with `--passphrase-stdin`.
- CLI tests (`tests/cli.rs`) use `assert_cmd`/`assert_fs`/`predicates` against the real binary in a temp dir.

## Other notes

- The vault file format must not change without preserving backward compatibility — see CHANGELOG.md for the 0.2.0 rewrite which kept the format identical.
