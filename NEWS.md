# NEWS

## ckman 0.1.0 (unreleased)

Pure-Rust rewrite of the CanoKey manager, replacing the Python
yubikey-manager fork. The protocol core is
[libcanokey](https://github.com/canokeys/libcanokey) (pinned to a git
revision until the `codex/oath-admin-migration` branch merges upstream);
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
- FIDO2: info, reset with the power-up window, ClientPIN set/change,
  resident-credential management, authenticator config (min PIN length,
  force-change). Native USB HID transport with CTAPHID, plus FIDO over CCID.

### Differences from the Python version

Dropped commands and options (mostly YubiKey-only):

- `otp`, `hsmauth`, `securitydomain` and the `--scp*` options (YubiKey
  applets / SCP transport).
- `config mode`, `config set-lock-code`, `config set-flags` and other
  YubiKey interface-configuration commands (CanoKey has no equivalent).
- `fido fingerprints` (CanoKey has no fingerprint sensor).
- OATH PSKC import/export (`--output`, `--pskc-key/--pskc-passphrase`,
  `accounts import`) — no RFC 6030 implementation is bundled; otpauth://
  URIs cover the common import path.
- `piv objects generate` (CHUID/CCC templates) and PKCS#12 import
  (`piv certificates import` takes PEM/DER).
- `openpgp keys attest` / attestation-key import (libcanokey has no
  OpenPGP attestation request) and `openpgp keys delete` (the wire protocol
  cannot delete an OpenPGP key without changing its algorithm attributes).
- The raw `apdu` command and `list --readers`.
- The Python library and its scripting API. A future PyO3 binding may
  restore scripting on top of the Rust core.

Behavior differences worth knowing:

- `openpgp keys import` covers the sig/dec/aut slots (not only the
  attestation slot).
- PIV `--protect` management-key storage works (the old fork rejected it on
  CanoKey); libcanokey implements the PIN-protected PRINTED object.
- Credential/PIN prompts never read defaults: no default PINs or management
  keys are ever tried silently.
