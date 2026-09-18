# Contributor instructions

## Repository layout

- `crates/ckman-transport` — PC/SC and USB HID (CTAPHID) transports with
  connection-lease semantics.
- `crates/ckman-core` — typed wrappers over libcanokey (admin, OATH, PIV,
  OpenPGP, FIDO2) plus host-side formats (X.509/CSR building, key-file
  parsing, otpauth:// URIs).
- `crates/ckman-cli` — the `ckman` binary (clap).
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

## libcanokey pin policy

The workspace pins libcanokey to a git revision of the
`codex/oath-admin-migration` branch (the only branch carrying canokey-ctap
and canokey-ndef). Switch the pin to a main-branch tag once that branch
merges; until then, bump the `rev` deliberately and re-run the transcript
tests.

## Testing conventions

Unit tests are scripted-transcript tests: recorded command/response APDU
pairs (including SW1/SW2) replayed through a script exchange, with the
firmware version recorded in the profile. See `tests/transcripts/README.md`.
Get APDU bytes from libcanokey's own test fixtures whenever possible.

No device operations that write, reset, change PINs/config, or delete may
run against a real key from tests or CI without explicit operator intent.

## Releases

crates.io is blocked until libcanokey publishes (git dependency). Releases
ship as GitHub-release binaries via cargo-dist (`dist-workspace.toml`).
Release prerequisite: `cargo install cargo-dist --locked`, then
`cargo dist init` and commit the generated workflow.

## Branch model

- `rust-rewrite` carries the Rust rewrite and becomes the default branch at
  parity.
- `canokey-X.Y.Z` branches keep the Python fork for hotfixes of published
  releases; they are permanent and never deleted. See
  `doc/CanoKey-Fork.md` on those branches for the Python maintenance rules.
