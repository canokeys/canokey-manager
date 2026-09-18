# ckman

`ckman` is a command-line manager for [CanoKey](https://www.canokeys.org/)
security keys: configure the device, and manage the OATH, PIV, OpenPGP and
FIDO2 applications.

This is a pure-Rust rewrite of the Python
[yubikey-manager](https://github.com/canokeys/yubikey-manager) fork. The
protocol core is [libcanokey](https://github.com/canokeys/libcanokey); the
CLI owns device connection, prompting, and host-side formats (X.509, PKCS#8,
otpauth://). The Python library and scripting API are **dropped**; a future
PyO3 binding may restore scripting on top of the Rust core.

## Features

| Applet | Commands |
| --- | --- |
| Device | `ckman list`, `ckman info` |
| Configuration | `ckman config info` (incl. flash/applet storage and core commit on 3.1), `config nfc`, `config led`, `config ndef-read-only`, `config webusb-landing`, `config pass` (touch-to-type slots), `config ndef read/write`, `config keyboard` (layout/keymap), `config sm2`, `config reset` |
| OATH | `ckman oath info`, `oath reset`, `oath access change/remember/forget`, `oath accounts add/uri/list/code/rename/delete/set-default` |
| PIV | `ckman piv info`, `piv reset`, `piv access …` (PIN/PUK/management key, retries, unblock), `piv keys generate/import/attest/info/export/move/delete`, `piv certificates import/export/generate/request/delete`, `piv objects export/import/name` |
| OpenPGP | `ckman openpgp info`, `openpgp reset`, `openpgp access …` (PIN/admin PIN/reset code, retries, signature policy), `openpgp keys info/generate/import/set-touch`, `openpgp certificates import/export/delete` |
| FIDO2 | `ckman fido info`, `fido reset`, `fido access set-pin/change-pin/set-min-length/force-change`, `fido credentials list/delete` |

PINs and passwords are prompted without echo (via `rpassword`); the OATH
password can be remembered in the OS keyring per device
(`ckman oath access remember`).

FIDO commands prefer the native USB HID (CTAPHID) transport and fall back to
FIDO over CCID when `--reader` is given or no HID interface is present.

## Build

Requires Rust 1.85.1 (see `rust-toolchain.toml`; rustup installs it
automatically), `pkg-config`, PC/SC (`pcsclite` on Linux, system frameworks
on macOS/Windows) and libusb/hidapi system libraries where required.

```sh
cargo build --release
# The binary is target/release/ckman.
```

Install from a checkout:

```sh
cargo install --path crates/ckman-cli --locked
```

crates.io publishing is blocked until libcanokey publishes (the workspace
depends on it by git revision, which crates.io forbids); 0.1.0 therefore
ships as GitHub-release binaries built by
[cargo-dist](https://opensource.axo.dev/cargo-dist/) (see
`dist-workspace.toml`). cargo-dist is a **release prerequisite**, not
vendored: install it once with `cargo install cargo-dist --locked`, then
validate/refresh the release setup with `cargo dist init` (answer the
prompts to target this workspace; commit the generated workflow).

Man pages are generated with clap and committed under `man/`; regenerate
after CLI changes with:

```sh
mkdir -p man && cargo run -p ckman-mangen -- man
# Install with e.g.: install -Dm644 man/*.1 -t "$PREFIX/share/man/man1"
```

## Usage

```sh
ckman list                       # all attached CanoKeys
ckman info                       # firmware, serial, capabilities
ckman oath accounts list         # OATH accounts
ckman oath accounts code         # TOTP codes (touch prompt on stderr)
ckman piv info                   # PIV slots, retries, certificates
ckman piv keys generate 9a pubkey.pem -a ecc-p256
ckman openpgp info
ckman fido info                  # over USB HID
ckman fido credentials list      # resident credentials
```

Global options: `--device SERIAL` and `--reader NAME` select one of several
attached keys; `-l/--log-level` enables tracing on stderr.

## Security notes

- Secrets entered at prompts are zeroized on drop; secrets supplied as
  command-line arguments (`--password`, `--admin-pin`, `--management-key`,
  OATH base32 secrets) are additionally visible in shell history and the
  process list while the command runs — prefer prompts for those.
- Trace logging (`-l trace`) never logs APDU payloads (VERIFY carries a
  plaintext PIN, OATH PUT the credential secret); full traffic hex requires
  the explicit `CKMAN_LOG_TRAFFIC=1` environment variable.
- `--device` names the 4-byte admin serial. On the FIDO HID path it matches
  the interface whose USB serial string is the uppercase hex of that serial
  (current firmware behavior); otherwise the PC/SC probe resolves it. A
  device that matches neither is an error — another key is never picked
  silently.

## Development

See `AGENTS.md` for the contributor gates. In short:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

## License

Apache License 2.0 (`LICENSE`). The same license covers this rewrite; the
Python original was BSD-2-Clause (Yubico AB) with the CanoKey patch set.
