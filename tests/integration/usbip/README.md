# CanoKey USB/IP integration coverage

The scripts in this directory exercise `ckman` as a black-box CLI against the
real USB, CCID, PC/SC, and CanoKey firmware stack provided by
`canokey-usbip/compat/run`. Every device operation explicitly selects the
reader from `CANOKEY_PCSC_READER`.

## Functionally covered

- Top level: `info`, `apdu`
- PIV: `info`, `reset`; every command under `access`, `keys`, `certificates`,
  and `objects`
- OATH: `info`, `reset`; every command under `access` and `accounts`
- OpenPGP: `info`, `reset`; all commands under `access`, `keys`, and
  `certificates`, subject to the CanoKey-specific negative cases below

The PIV and OATH tests provision data, verify round trips, and clean it up. The
OpenPGP test changes and recovers PINs, imports an attestation key and
certificate, verifies the certificate round trip, and resets the applet at the
end.

## Expected CanoKey rejections

- `piv access set-retries`: the catalog CanoKey core does not implement PIV
  retry counter configuration.
- `openpgp access set-retries`: CanoKey does not implement SET PIN RETRIES.
- `openpgp keys attest`: `ckman` cannot provision a normal OpenPGP signing key,
  and the catalog firmware starts without one. The command is exercised and
  required to reject the missing prerequisite.

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
