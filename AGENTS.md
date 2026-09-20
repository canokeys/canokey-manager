# Contributor instructions

## Repository layout

- `crates/ckman-transport` — PC/SC and USB HID (CTAPHID) transports with
  connection-lease semantics.
- `crates/ckman-core` — typed wrappers over libcanokey (admin, OATH, PIV,
  OpenPGP, FIDO2) plus host-side formats (X.509/CSR building, key-file
  parsing: PKCS#8/PKCS#1/SEC1/PKCS#12, otpauth:// URIs).
- `crates/ckman` — the `ckman` binary (clap).
- `crates/ckman-mangen` — the man-page generator, a separate
  `publish = false` crate so `cargo install` never ships it.
- `tests/device/` — hardware/usbip black-box harness (see its README).
- `tests/transcripts/` — scripted-APDU convention (see its README).
- `man/` — generated man pages, regenerated with
  `mkdir -p man && cargo run -p ckman-mangen -- man` and committed;
  `ckman-mangen` writes into an existing directory.

## Gates

All four must pass before committing:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

MSRV is **1.85.1** (pinned in `rust-toolchain.toml`; CI uses the same). When
adding dependencies, check their `rust-version` against it — several recent
crate releases require newer rustc and must be pinned down.

## libcanokey version policy

libcanokey is consumed from crates.io (`canokey = "0.1"`, with the `x509`
and `clientpin` features). Bump the version deliberately and re-run the
transcript tests when upgrading.

## Testing conventions

Unit tests are scripted-transcript tests: recorded command/response APDU
pairs (including SW1/SW2) replayed through a script exchange, with the
firmware version recorded in the profile. See `tests/transcripts/README.md`.
Get APDU bytes from libcanokey's own test fixtures whenever possible.

No device operations that write, reset, change PINs/config, or delete may
run against a real key from tests or CI without explicit operator intent.

## Releases

libcanokey comes from crates.io, so crates.io publishing is unblocked.
Releases ship as GitHub-release binaries via cargo-dist
(`dist-workspace.toml`). Release prerequisite: `cargo install cargo-dist
--locked`, then `cargo dist init` and commit the generated workflow.

## Branch model

The new repository just has `main`.
