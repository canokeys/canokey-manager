# ckman

`ckman` is a command-line manager for [CanoKey](https://www.canokeys.org/)
security keys: configure the device, and manage the OATH, PIV, OpenPGP and
FIDO2 applications.

The protocol core is [libcanokey](https://github.com/canokeys/libcanokey)
(from crates.io); the CLI owns device connection, prompting, and host-side
formats (X.509, PKCS#8, otpauth://). Everything is pure Rust.

## Features

| Applet | Commands |
| --- | --- |
| Device | `ckman list`, `ckman info` (incl. vendor chip ID where the firmware reports one) |
| Configuration | `ckman config info` (incl. flash/applet storage and core commit on 3.1), `config nfc`, `config led`, `config ndef-read-only`, `config webusb-landing`, `config admin-pin change/status` (device Admin PIN), `config pass` (touch-to-type slots), `config ndef read/write`, `config keyboard` (layout/keymap), `config sm2` (read and, on 3.1, `sm2 set`), `config reset` |
| OATH | `ckman oath info`, `oath serial`, `oath challenge-response` (KeePassXC-style HMAC-SHA1 via a PASS slot), `oath reset`, `oath access change/remember/forget`, `oath accounts add/uri/list/code/rename/delete/set-default` |
| PIV | `ckman piv info`, `piv reset`, `piv access …` (PIN/PUK/management key, retries, unblock), `piv keys generate/generate-batch/import/attest/info/export/move/delete`, `piv certificates import/export/generate/request/delete`, `piv objects export/import/name`, `piv sign/decrypt/derive/decapsulate/agree-sm2` (raw private-key operations), `piv random` (device RNG), `piv logout` |
| OpenPGP | `ckman openpgp info` (incl. cardholder data), `openpgp reset`, `openpgp access …` (PIN/admin PIN/reset code, retries, signature policy, touch cache time), `openpgp cardholder set-name/set-login/set-language/set-sex/set-url`, `openpgp keys info/generate/import/export/set-touch`, `openpgp certificates import/export/delete` |
| FIDO2 | `ckman fido info`, `fido reset`, `fido touch-test`, `fido access set-pin/change-pin/set-min-length/force-change/verify-pin`, `fido config toggle-always-uv/enable-long-touch-for-reset`, `fido credentials list/update-user/delete`, `fido blobs read/write` |
| Shell | `ckman completions <bash\|zsh\|fish\|powershell>` (stdout) |

PINs and passwords are prompted without echo (via `rpassword`); the OATH
password can be remembered in the OS keyring per device
(`ckman oath access remember`).

FIDO commands prefer the native USB HID (CTAPHID) transport and fall back to
FIDO over CCID when `--reader` is given or no HID interface is present.

## Install

Prebuilt binaries for macOS, Linux and Windows are attached to each
[GitHub release](https://github.com/canokeys/canokey-manager/releases),
with shell/PowerShell installers and checksums. Package-manager options:

| Platform | Command |
| --- | --- |
| macOS (Homebrew) | `brew install canokeys/tap/ckman` |
| Windows (winget) | `winget install Canokeys.Ckman` |
| Arch Linux (AUR) | `yay -S ckman-bin` |
| Rust (crates.io) | `cargo install ckman --locked` (build from source) or `cargo binstall ckman` (prebuilt) |

The one-line installers from the release page work everywhere:

```sh
# macOS / Linux
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/canokeys/canokey-manager/releases/latest/download/ckman-installer.sh | sh
# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -c "irm https://github.com/canokeys/canokey-manager/releases/latest/download/ckman-installer.ps1 | iex"
```

On Linux, `pcscd`/`pcsclite`, `libudev` and a CCID driver package are
required at runtime.

Migrating from the legacy Python ckman: `pipx uninstall canokey-manager`
first, so the old `ckman` shim does not shadow the new binary.

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
cargo install --path crates/ckman --locked
```

Releases ship as GitHub-release binaries built by
[cargo-dist](https://opensource.axo.dev/cargo-dist/) (see
`dist-workspace.toml`), and the CLI is published to crates.io as
[`ckman`](https://crates.io/crates/ckman). cargo-dist is a **release
prerequisite**, not vendored: install it once with
`cargo install cargo-dist --locked`, then validate/refresh the release
setup with `cargo dist init` (answer the prompts to target this workspace;
commit the generated workflow).

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
attached keys; `-l/--log-level` enables tracing (stderr or `--log-file`);
`--diagnose` prints a bug-report environment summary.

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

Apache License 2.0 (`LICENSE`).
