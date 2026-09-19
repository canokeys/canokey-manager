# NEWS

## ckman 0.1.0 (unreleased)

Pure-Rust rewrite of the CanoKey manager, replacing the Python
yubikey-manager fork. The protocol core is
[libcanokey](https://crates.io/crates/canokey) 0.1 from crates.io;
the CLI is new code on top of it.

### Command coverage

Device (`list`, `info`), `config` (NFC toggle, factory reset, configuration
readout), and the OATH, PIV, OpenPGP and FIDO2 applications, mirroring the
CanoKey-relevant surface of the Python CLI, including:

- OATH: accounts add (incl. otpauth:// URIs), list, code (with touch
  prompts), rename, delete; password set/clear with OS-keyring remembering.
- PIV: full key/certificate lifecycle incl. on-device self-signed
  certificates and CSRs signed by the slot key, the pivman management-key
  model (PIN-derived and PIN-protected stored keys), retry management.
- OpenPGP: PIN/reset-code/admin-PIN management, touch policies, key
  generate/import (RSA CRT, EC, Ed/X25519), certificates.
- FIDO2: info, reset with the power-up window, ClientPIN set/change/verify,
  resident-credential management, authenticator config (min PIN length,
  force-change, toggle-always-uv). Native USB HID transport with CTAPHID,
  plus FIDO over CCID.

### Differences from the Python version

Dropped commands and options (mostly YubiKey-only):

- `otp`, `hsmauth`, `securitydomain` and the `--scp*` options (YubiKey
  applets / SCP transport).
- `config mode`, `config usb`/`config nfc` application toggles,
  `config set-lock-code` and other YubiKey interface-configuration commands
  (CanoKey has no equivalent).
- `fido fingerprints` (CanoKey has no fingerprint sensor), `fido config
  enable-ep-attestation` and `fido access change-pin --u2f` (YubiKey FIPS
  only).
- `oath access forget --all` (the OS keyring cannot enumerate entries;
  forget each device individually with `oath access forget`).
- OATH PSKC import/export (`--output`, `--pskc-key/--pskc-passphrase`,
  `accounts import`) — no RFC 6030 implementation is bundled; otpauth://
  URIs cover the common import path.
- `piv objects generate` (CHUID/CCC templates) and PKCS#12 import
  (`piv certificates import` takes PEM/DER).
- `openpgp keys attest` / attestation-key import (libcanokey has no
  OpenPGP attestation request).
- The raw `apdu` command, the `script` command, and `list --readers`.
- The Python library and its scripting API. A future PyO3 binding may
  restore scripting on top of the Rust core.

### New CanoKey-specific surface

- PASS touch-to-type slots: `config pass info` / `config pass set
  <short|long> <off|static|hmac>` (Admin-PIN gated on all firmware; unknown
  slot types stay observable).
- NDEF message read/write with crash-consistent writes (`config ndef`).
- Device configuration patches: `config led`, `config ndef-read-only`,
  `config webusb-landing` (read-modify-write, libcanokey preserves
  unspecified fields and blocks unsafe feature-mask overwrites).
- Keyboard emulation: `config keyboard layout/read-keymap/write-keymap/
  clear-keymap/return`.
- `config info` additionally shows flash usage, applet storage and the core
  commit on 3.1; `config sm2` reads the CTAP SM2 configuration (typed on
  3.1, legacy layout on 3.0.x; read-only — the legacy byte order is
  unvalidated, so no write command is exposed).
- `oath accounts set-default` (keyboard-emulation default for HOTP
  credentials; 3.0+ two-slot dialect) and `piv objects name` (UTF-16
  container names, 3.1+).

### Behavior changes

- OATH remembered passwords moved from the Fernet-encrypted ykman appdata
  store to plain OS-keyring entries keyed by device serial. Remembered
  passwords do **not** migrate; run `oath access remember` again once per
  device.
- `info` output is thinner than the Python version's (no FIPS status, no
  form-factor/USB table).
- `piv access set-retries` accepts 1–15 (the firmware bound); the Python
  CLI allowed up to 255 and let the card clamp.
- FIDO splits the Python `fido access change-pin` into `set-pin` (no PIN
  set) and `change-pin`.
- `--device`/`--reader` are global options (usable after subcommands, which
  the Python CLI achieved by rewriting argv). Their short flags therefore own
  `-d`/`-r` everywhere; the local `-d` (OATH `--digits`) and `-r`
  (`--remember`, `--reset-code`) shorts are long-only now.
- `--reader` matches reader names by case-insensitive substring, as the
  Python CLI did.
- For FIDO, `--device` matches the HID interface whose USB serial string is
  the uppercase hex of the admin serial (current firmware), and otherwise
  falls back to the PC/SC probe; it never silently picks another device.
- The global `--diagnose` report and `--log-file` are ported
  (`--log-file` requires `--log-level`).
- `openpgp keys import` covers the sig/dec/aut slots (not only the
  attestation slot).
- PIV `--protect` management-key storage works (the old fork rejected it on
  CanoKey); libcanokey implements the PIN-protected PRINTED object.
- Credential/PIN prompts never read defaults: no default PINs or management
  keys are ever tried silently.

### Validation

OATH/OpenPGP/FIDO2 are validated by scripted-transcript unit tests (APDU
fixtures mirrored from libcanokey) plus read-only smoke runs on the usbip
firmware matrix (1.3–3.1.0); destructive lifecycle device tests currently
exist for PIV only (firmware 2.0+). The FIDO HID path (the default
transport) is loopback-tested and manually verified on real hardware, while
CI exercises FIDO over PC/SC.
