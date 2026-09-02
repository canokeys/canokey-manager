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

## Firmware-dependent commands

The test follows the upstream device-test model: known device exclusions are
reported before execution, and discoverable capabilities are probed before a
dependent command runs. CanoKey core ID/ref, rather than an applet protocol
version, identifies the tested firmware. Unsupported features are reported and
do not stop the rest of the lifecycle. Ordinary command failures remain fatal.

- PIV retry counter configuration and attestation
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
