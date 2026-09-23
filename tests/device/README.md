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
  empty device (the CLI has no make-credential path, so no resident
  credential can be provisioned for a rename round trip).

## Gap list

Still missing — contributions should add these in this order:

1. **Deeper lifecycle coverage** — OATH account add/list/code/rename/delete
   (incl. legacy 1.3 dialect, TOTP/HOTP variants, URI import, touch
   metadata); OpenPGP SIG/DEC/AUT provisioning with sign/decrypt/auth round
   trips and certificate round trips; FIDO resident-credential creation (needs
   a make-credential path — the CLI has none, so `credentials update-user`
   can only be exercised against an empty store) and `fido reset` (needs the
   power-up window). Deliberately untested: `fido touch-test` (user presence
   needs the HID path) and `fido config enable-long-touch-for-reset`
   (persistent setting; only a full reset clears it, so it would poison the
   rig for later steps), and `config admin-pin change` (prompt-only by
   design — no argv secret — so it cannot run on a TTY-less runner).
2. **Deeper protocol coverage** — candidate: integration tests in
   `crates/ckman/tests/` exercising full command flows over a scripted
   or usbip device.
3. **Keyring test double** — the CLI uses the OS keyring directly, and there
   is no injection point yet.
4. **HID coverage in CI** — the usbip matrix runs
   (`.github/workflows/usbip.yml`) drive FIDO over PC/SC only; the CTAPHID
   transport is covered by loopback tests, not by the virtual-device rig.
