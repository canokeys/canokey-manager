# NEWS

## ckman 0.1.0 (2026-09-20)

Initial release: a CanoKey manager CLI, written in Rust on top of
[libcanokey](https://crates.io/crates/canokey).

### Features

- Device: `list`, `info`, `--diagnose`, `--log-level`/`--log-file`.
- Configuration: `config info` (with flash usage, applet storage and core
  commit on 3.1), `config nfc`, `config led`, `config ndef-read-only`,
  `config webusb-landing`, `config reset` (factory reset), `config pass`
  (touch-to-type slots), `config ndef read/write` (crash-consistent NDEF
  message replacement), `config keyboard` (HID layout and keymap),
  `config sm2` (CTAP SM2 readout).
- OATH: accounts add (incl. otpauth:// URIs), list, code (with touch
  prompts), rename, delete, set-default (keyboard-emulation default);
  password set/clear with per-device remembering in the OS keyring.
- PIV: full key/certificate lifecycle incl. on-device self-signed
  certificates and CSRs signed by the slot key, the pivman management-key
  model (PIN-derived and PIN-protected stored keys), retry management,
  container names (3.1), and the full algorithm range (RSA 1024–4096,
  P-256/384/521, secp256k1, SM2, Ed25519, X25519, ML-DSA-65, ML-KEM-768).
- OpenPGP: PIN/reset-code/admin-PIN management, touch policies, key
  generate/import (RSA CRT, EC, Ed/X25519), certificates.
- FIDO2: info, reset with the power-up window, ClientPIN set/change/verify,
  resident-credential management, authenticator config (min PIN length,
  force-change, toggle-always-uv). Native USB HID transport with CTAPHID,
  plus FIDO over CCID.

### Validation

Scripted-transcript unit tests (APDU fixtures mirrored from libcanokey)
cover every applet, plus read-only smoke runs on the usbip firmware matrix
(1.3–3.1.0); destructive lifecycle device tests currently exist for PIV
(firmware 2.0+). The FIDO HID path (the default transport) is
loopback-tested and manually verified on real hardware, while CI exercises
FIDO over PC/SC.
