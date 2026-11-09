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
| Configuration | `ckman config info` (incl. flash/applet storage and core commit on 3.1), `config nfc`, `config led`, `config ndef-read-only`, `config webusb-landing`, `config admin-pin change/status` (device Admin PIN), `config pass` (touch-to-type slots), `config ndef read/write`, `config keyboard` (layout/keymap), `config sm2` / `sm2 set` (3.0+), `config reset` |
| OATH | `ckman oath info`, `oath serial`, `oath challenge-response` (KeePassXC-style HMAC-SHA1 via a PASS slot), `oath reset`, `oath access change/remember/forget`, `oath accounts add/uri/list/code/rename/delete/set-default` |
| PIV | `ckman piv info`, `piv reset`, `piv set-chuid/set-ccc`, `piv access …` (PIN/PUK/management key, retries, unblock), `piv keys generate/generate-batch/import/attest/verify-attest/info/export/move/delete`, `piv certificates import/export/generate/request/delete`, `piv objects export/import/name`, `piv sign/decrypt/derive/decapsulate/agree-sm2` (raw private-key operations), `piv random` (device RNG), `piv logout` |
| OpenPGP | `ckman openpgp info` (incl. cardholder data), `openpgp reset`, `openpgp access …` (PIN/admin PIN/reset code, retries, signature policy, touch cache time), `openpgp cardholder set-name/set-login/set-language/set-sex/set-url`, `openpgp keys info/generate/import/export/set-touch`, `openpgp certificates import/export/delete` |
| FIDO2 | `ckman fido info`, `fido reset`, `fido touch-test`, `fido access set-pin/change-pin/set-min-length/force-change/verify-pin`, `fido config toggle-always-uv/enable-long-touch-for-reset`, `fido credentials list/update-user/delete`, `fido blobs read/write` |
| Shell | `ckman completions <bash\|zsh\|fish\|powershell>` (stdout) |

PINs and passwords are prompted without echo (via `rpassword`); a
device-bound OATH access key (derived from the password) can be remembered in
the OS keyring per device (`ckman oath access remember`).

FIDO commands prefer the native USB HID (CTAPHID) transport and fall back to
FIDO over CCID when `--reader` is given or no HID interface is present.
`fido info` recognizes CanoKey's historical SM2 identifiers; see the
[WebAuthn SM2 identifier history](docs/fido-sm2.md) for the -48/-54 mapping
and custom-configuration limitations. Use `fido info --admin-pin PIN` to
read the actual SM2 ID on firmware 3.0+ (requires PC/SC).

`config info` reports physical filesystem allocation in KiB, and applet
logical payloads in bytes (B), using Console's applet names. Optional files
and attributes that do not exist contribute zero. Filesystem overhead/other
is the firmware's physical allocation minus the attributed payloads; it
includes metadata, block slack, copy-on-write overhead and unassigned data.
These figures do not measure how much space deleting an applet would reclaim.
See [the storage accounting audit](docs/storage-accounting.md) for details.

PIV firmware 3.1.x exposes the F9 attestation signer through `piv info` and
`piv keys info f9`. The overview reports key and certificate presence separately;
certificate details alone do not imply trust. Older firmware skips F9 in the
overview and rejects an explicit F9 query.

`piv certificates import`, `export` and `delete` accept `f9` on 3.1.x firmware.
Certificate import checks the public key against slot metadata when available;
changing the F9 certificate affects attestation trust.

The signer supports `piv keys generate f9 --algorithm ecc-p256 PUBLIC-KEY`,
`piv keys import f9 PRIVATE-KEY` and `piv keys export f9 PUBLIC-KEY`.
F9 only supports P-256; replacing its key requires explicit consent and retains
the existing certificate, which may no longer match. Key move/delete, general
private operations, certificate generation and CSR requests remain limited to
ordinary key slots.

PIV key generation/import and certificate import/generation ask for explicit
confirmation before replacing an occupied slot. The prompt defaults to no;
EOF or cancellation aborts without changing PIV data. Key operations also check
for retained certificates, and prompt conservatively when older firmware cannot
report key presence. Batch generation confirms all slots before any write.
Certificate deletion and raw certificate-object imports also require confirmation
when a certificate exists. Read errors abort instead of treating a slot as empty.

```sh
ckman piv keys verify-attest 9a
ckman piv keys verify-attest 9a --ca custom-root.pem
```

`verify-attest` requests a fresh certificate for an ordinary device-generated
key and checks the fixed chain **target -> F9 signer -> trusted root**. It checks
signatures, validity, CA constraints, path length, KeyUsage when present, duplicate
extensions and unsupported critical extensions. It also matches the signed
public key, slot, device serial and PIN/touch policy against observations from
the same exclusive device connection, and matches F9's public key to its issuer
certificate. Only complete verification returns exit code 0. No PIN, management
key or target private-key operation is required; imported keys cannot be attested.

The default trust anchor is the bundled **CanoKey PIV Root CA No. 1** from the
[official certificate publication](https://docs.canokeys.org/attestation/), with
DER SHA-256 fingerprint
`2EB382E5EC235661F926C23D25BA92227BD6B9D5D354131177547368ABEA681C`.
`--ca` replaces it with exactly one independently trusted PEM/DER P-256 root;
PEM bundles, system roots and network retrieval are not used. Both chain signers
must use P-256/SHA-256; the target key can use any firmware-attestable algorithm
whose public key metadata is supported, including ML-DSA-65. Certificate expiry
uses the host's current UTC time. Missing evidence, binding mismatches and
untrusted chains are errors, even if a certificate's signature alone is valid.

This verifies the device-generated-key statement under the selected root's trust
policy. The protocol has no challenge binding; no anti-replay or revocation check
is performed. Offline file verification is not included.

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

`ckman piv set-chuid` and `ckman piv set-ccc` replace the CHUID (5FC102)
and Card Capability Container (5FC107), authenticating with the management key
(including PIN-protected management keys). Each invocation generates a fresh
identifier by default. Use `--guid` with 32 hex characters for a specific CHUID,
or `--card-id` with 28 hex characters for the CCC identifier suffix (the prefix
A000000116FF02 is fixed). CHUID uses a non-federal FASC-N, an empty signature,
and expiration date 2030-01-01, matching ykman. To provision other object contents,
use `piv objects import`.

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
