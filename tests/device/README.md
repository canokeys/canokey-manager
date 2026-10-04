# CanoKey device-test harness

Black-box device tests driving the `ckman` binary against the
[canokey-usbip](https://github.com/canokeys/canokey-usbip) virtual (or real)
USB/CCID/PC/SC stack. Environment contract:

| Variable | Meaning |
| --- | --- |
| `CANOKEY_USBIP` | set by the USB/IP harness (guards against accidental hardware runs) |
| `CANOKEY_TEST_PRIVATE_IFD=1` | alternative guard for an isolated Rust PC/SC IFD; does not validate USB/IP transport |
| `CANOKEY_PCSC_READER` | PC/SC reader name to select |
| `CANOKEY_FIRMWARE_VERSION` | firmware under test |
| `CANOKEY_USBIP_WORK_DIR` | scratch dir (smoke.sh creates one) |
| `CKMAN_BIN` | path to the binary (default: `target/debug/ckman`) |
| `CKMAN_DESTRUCTIVE=1` | required for scripts that write/reset/delete |

Run, inside a `canokey-usbip` environment:

```sh
cargo build
tests/device/smoke.sh            # read-only, safe
CKMAN_DESTRUCTIVE=1 tests/device/piv-lifecycle.sh
```

## Layout

- `lib.sh` — shared helpers (section, expect_failure, capture_without_secrets,
  run_versioned_feature).
- `firmware.sh` + `features.tsv` — declarative firmware feature matrix.
  `firmware.sh status <version> <feature>` prints
  `supported` / `unsupported` / `unknown`; unknown is a harness error, so the
  matrix is the auditable record of validated coverage.
- `smoke.sh` — read-only end-to-end: `info` firmware-identity check (incl.
  the `Chip ID:` line, `<unavailable>` where the firmware lacks the command),
  `list` (normal and `--serials`), `config info`, `config admin-pin status`,
  and each applet's `info`.
- `piv-lifecycle.sh` — destructive PIV round trip: reset, PIN/PUK/management
  key changes, unblock after wrong PINs, key generate/import (PEM via
  openssl), `keys generate-batch`, certificate generate/import/export, object
  write/read, `sign` (openssl-verified), `derive` (both-sides ECDH
  comparison), `decrypt` (RSA padded-block round trip), `decapsulate`
  (ML-KEM, 3.1), `agree-sm2` (3.1), `logout`, `random` (PIV 6.0+, currently
  unsupported on catalog firmware), retry reset, and a final
  factory-credential reset.
- `openpgp-lifecycle.sh` — destructive OpenPGP round trip (2.0+): reset, key
  generation, cardholder set-name/login/language/sex/url with `info` readback,
  `access set-touch-cache` set/restore, and `keys export` (openssl-validated
  PEM).
- `oath-lifecycle.sh` — destructive OATH vendor-extension coverage (3.1):
  `oath serial` and `oath challenge-response` against a `config pass set`
  HMAC-SHA1 slot, verified against a host-side python3 HMAC known answer.
- `fido-lifecycle.sh` — destructive FIDO-over-CCID lifecycle (2.0+): `access
  set-pin`/`verify-pin`, `blobs write`/`read` round trip with a minimal valid
  largeBlobs array (3.1), and `credentials update-user` failing cleanly on an
  empty device.

## Rust 4.0.0 functional coverage

`rust-functional.py` supplements the lifecycle scripts with 143 checks on a
dedicated disposable Rust 4.0.0 reader. It changes PINs, imports throwaway
keys, deletes credentials and resets applets. It requires `CKMAN_DESTRUCTIVE=1`,
an explicit reader and a virtual-device guard. Install `requirements.txt` in
a Python virtual environment, then run inside the USB/IP harness:

```sh
CKMAN_DESTRUCTIVE=1 .venv-device/bin/python tests/device/rust-functional.py \
  --output "$CANOKEY_USBIP_WORK_DIR/rust-functional.json"
```

Coverage includes Admin PIN prompts and PASS HMACs; OATH SHA-1/256/512,
HOTP/TOTP, URI import, account lifecycle, touch and password changes; PIV
key-file formats, independent signature/certificate/CSR verification,
attestation, key moves/deletion and protected management keys; OpenPGP
SIG/DEC/AUT imports and generation, independent cryptographic operations,
certificate round trips, PIN authorization and touch policies; FIDO PIN
policies, resident credential creation through python-fido2 followed by ckman
CSV update/deletion, a 4096-byte largeBlob round trip, and ordinary/long-touch
reset. Existing PIV scripts additionally cover RSA decryption, ECDH, ML-KEM
and SM2. The JSON report identifies whether the transport was USB/IP or a
private PC/SC IFD and records failures explicitly.

The Rust host simulates presence through `/tmp/canokey-test-up`; long gestures
use `/tmp/canokey-test-touch-ms`. The suite restores the gesture-duration file.
`CANOKEY_DEVICE_RESTART` may name the harness restart command for the FIDO
power-on reset window; the private IFD uses its test-only restart command.
OATH keyring remember/recall/forget and error cases have mock credential tests;
the platform OS keyring backend is not part of virtual-device acceptance.

NFC/NDEF, HID/keyboard output, WebUSB and fault recovery are deferred.
Legacy firmware retains its existing lifecycle coverage; the deeper suite
currently targets exact version 4.0.0.

The workspace temporarily pins libcanokey commit
`29d021f55ce07202b483cd12e2c8fff17b23c430` for exact 4.0.0 recognition until
that support is published to crates.io. This preserves the reported 4.0.0
identity while using its supported modern applet dialect.

Repeating `piv access change-management-key --protect` without an explicit
current management key can complete PUK blocking when the protection flags
and PIN-protected key were already stored. This requires the correct PIN and
authenticates that stored key before blocking retries. Ordinary stored-key
resolution never blocks the PUK implicitly; incomplete records still require
explicit management credentials.
