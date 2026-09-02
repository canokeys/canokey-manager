# CanoKey USB/IP integration coverage

The scripts in this directory exercise `ckman` as a black-box CLI against the
real USB, CCID, PC/SC, and CanoKey firmware stack provided by
`canokey-usbip/compat/run`. Every device operation explicitly selects the
reader from `CANOKEY_PCSC_READER`.

## Command coverage

- Top level: `info`, `apdu`
- PIV: `info`, `reset`; every command under `access`, `keys`, `certificates`,
  and `objects`
- OATH: `info`, `reset`; every command under `access` and `accounts`
- OpenPGP: `info`, `reset`; all commands under `access`, `keys`, and
  `certificates`, subject to the CanoKey-specific negative cases below

The PIV and OATH tests provision data, verify round trips, and clean it up. The
OpenPGP test changes and recovers PINs and, when supported, imports an
attestation key and certificate and verifies the certificate round trip. It
resets the applet at the end.

After the executable smoke lifecycle, `device-tests.sh` runs the reusable
upstream CLI and protocol device tests for each applet against the same real
PC/SC reader. The suite covers prompt and error paths, OATH vectors and PSKC,
PIV certificate and cryptographic operations, and OpenPGP signing, decryption,
and key agreement. Pytest reports capability exclusions with their skip
reasons; an ordinary test failure remains fatal.

## Firmware-dependent commands

The test follows the upstream device-test model: known device exclusions are
reported before execution, and discoverable capabilities are probed before a
dependent command runs. The CanoKey admin applet firmware version, rather than
a core ref or an applet protocol version, selects the feature rules. The test
also requires that the admin version matches `CANOKEY_FIRMWARE_VERSION` from
`canokey-usbip`. Unsupported features are reported and do not stop the rest of
the lifecycle. Ordinary command failures remain fatal.

Feature rules have three states. Supported commands must succeed, known
unsupported commands are reported without execution, and unknown newer
firmware is probed at runtime. A runtime rejection is accepted only when it
matches the feature's explicit unsupported error. Hardware provisioning state,
including attestation certificates and preinstalled keys, is always probed at
runtime rather than inferred from firmware.

YubiKey release gates and CanoKey firmware gates are independent. Tests retain
their upstream YubiKey version predicates. On CanoKey, the same test body uses
the admin firmware version and the feature matrix instead; synthetic versions
reported by individual applets are never compared to CanoKey firmware.

- PIV retry counter configuration, metadata-based key info/export, import PIN
  policies, and attestation
- OATH response chaining behavior before and after the 3.0.1 firmware fix
- OpenPGP retry counter configuration
- OpenPGP attestation key, certificate, touch policy, and signing-key
  attestation

## Not covered by the current hosted-runner path

- `fido`: the GitHub-hosted Azure kernel exposes the USB HID interface but does
  not bind it to `usbhid`, so no `hidraw` FIDO transport is available.
- `otp`: CanoKey does not advertise the Yubico OTP capability.
- `hsmauth`: CanoKey does not advertise the YubiHSM Auth capability.
- `securitydomain`: the catalog firmware does not advertise this capability.
- `config`: mutating USB application state can disconnect the sole test device;
  CanoKey configuration behavior needs a lifecycle that can reattach it.
- `list`: this command intentionally rejects the global `--reader` selector and
  therefore is outside this explicitly selected-reader integration path.
- `script`: this executes arbitrary user-provided Python and does not add device
  protocol coverage beyond the commands above.

HID commands must not be marked as integrated until a GitHub-hosted kernel path
provides a real bound HID transport. Help output or mocked transports do not
count as coverage.
