# CanoKey device-test harness

Black-box device tests driving the Rust `ckman` binary against the
[canokey-usbip](https://github.com/canokeys/canokey-usbip) virtual (or real)
USB/CCID/PC/SC stack. This is a port of the Python rig that lived in
`tests/integration/usbip/` on the `canokey-5.9.2` branch; the environment
contract is identical:

| Variable | Meaning |
| --- | --- |
| `CANOKEY_USBIP` | must be set (guards against accidental real-hardware runs) |
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
  run_versioned_feature), adapted from the Python rig's `lib.sh`.
- `firmware.sh` + `features.tsv` — declarative firmware feature matrix
  replacing `firmware.py`. `firmware.sh status <version> <feature>` prints
  `supported` / `unsupported` / `unknown`; unknown is a harness error, so the
  matrix is the auditable record of validated coverage.
- `smoke.sh` — read-only end-to-end: `info` firmware-identity check, `list`
  (normal and `--serials`), `config info`, and each applet's `info`.
- `piv-lifecycle.sh` — destructive PIV round trip: reset, PIN/PUK/management
  key changes, unblock after wrong PINs, key generate/import (PEM via
  openssl), certificate generate/import/export, object write/read, retry
  reset, and a final factory-credential reset.

## Gap list (not yet ported)

Compared to the Python rig, still missing — contributions should port these
in this order:

1. **oath-lifecycle.sh / openpgp-lifecycle.sh / fido-lifecycle.sh** — the
   OATH (incl. legacy 1.3 dialect, TOTP/HOTP variants, URI import, touch
   metadata) and OpenPGP (SIG/DEC/AUT provisioning, sign/decrypt/auth round
   trips, certificate round trip, attestation where supported) lifecycles,
   and the FIDO reset/PIN/credential-management lifecycle.
2. **firmware feature seeding** — `features.tsv` covers the features the
   ported scripts query plus the `piv-lifecycle` CI gate, for every catalog
   prefix; extend it as more lifecycle scripts land.
3. **Upstream pytest reuse** (`device-tests.sh`) — the Python rig ran a
   subset of upstream ykman device tests via pytest; no Rust equivalent
   exists. Candidate: port the applicable protocol-level tests as Rust
   integration tests in `crates/ckman-cli/tests/`.
4. **`ckman apdu` and `ckman list --readers`** — the Python CLI commands the
   old smoke script exercised; intentionally dropped from the Rust CLI (see
   NEWS.md). The smoke coverage they provided (raw APDU GET CHALLENGE) has no
   equivalent yet.
5. **Keyring test double** — the Python rig redirected the keyring to a file
   (`keyring_backend.py`); the Rust CLI uses the OS keyring directly, and
   there is no injection point yet.
6. **HID coverage in CI** — the usbip matrix runs
   (`.github/workflows/usbip.yml`) drive FIDO over PC/SC only; the CTAPHID
   transport is covered by loopback tests, not by the virtual-device rig.
