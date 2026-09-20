# CanoKey device-test harness

Black-box device tests driving the `ckman` binary against the
[canokey-usbip](https://github.com/canokeys/canokey-usbip) virtual (or real)
USB/CCID/PC/SC stack. Environment contract:

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
  run_versioned_feature).
- `firmware.sh` + `features.tsv` — declarative firmware feature matrix.
  `firmware.sh status <version> <feature>` prints
  `supported` / `unsupported` / `unknown`; unknown is a harness error, so the
  matrix is the auditable record of validated coverage.
- `smoke.sh` — read-only end-to-end: `info` firmware-identity check, `list`
  (normal and `--serials`), `config info`, and each applet's `info`.
- `piv-lifecycle.sh` — destructive PIV round trip: reset, PIN/PUK/management
  key changes, unblock after wrong PINs, key generate/import (PEM via
  openssl), certificate generate/import/export, object write/read, retry
  reset, and a final factory-credential reset.

## Gap list

Still missing — contributions should add these in this order:

1. **oath-lifecycle.sh / openpgp-lifecycle.sh / fido-lifecycle.sh** — the
   OATH (incl. legacy 1.3 dialect, TOTP/HOTP variants, URI import, touch
   metadata) and OpenPGP (SIG/DEC/AUT provisioning, sign/decrypt/auth round
   trips, certificate round trip, attestation where supported) lifecycles,
   and the FIDO reset/PIN/credential-management lifecycle.
2. **firmware feature seeding** — `features.tsv` covers the features the
   current scripts query plus the `piv-lifecycle` CI gate, for every catalog
   prefix; extend it as more lifecycle scripts land.
3. **Deeper protocol coverage** — candidate: integration tests in
   `crates/ckman/tests/` exercising full command flows over a scripted
   or usbip device.
4. **Keyring test double** — the CLI uses the OS keyring directly, and there
   is no injection point yet.
5. **HID coverage in CI** — the usbip matrix runs
   (`.github/workflows/usbip.yml`) drive FIDO over PC/SC only; the CTAPHID
   transport is covered by loopback tests, not by the virtual-device rig.
