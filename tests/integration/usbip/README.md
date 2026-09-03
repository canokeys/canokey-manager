# CanoKey USB/IP integration coverage

The scripts in this directory exercise `ckman` as a black-box CLI against the
real USB, CCID, PC/SC, and CanoKey firmware stack provided by
`canokey-usbip/compat/run`. Every device operation explicitly selects the
reader from `CANOKEY_PCSC_READER`.

The workflow resolves every historical release from the pinned
`canokey-usbip` firmware catalog and runs each one as an independent matrix
job. The catalog is the only source of firmware-to-core mappings; this
repository does not duplicate those commit SHAs.

## Command coverage

- Top level: `list` (normal, serial-only, and reader output), `info`, `apdu`
- FIDO: `info`; `reset` on firmware 1.5.2 through 1.6.2; `access change-pin`,
  `access verify-pin`; from firmware 2.0.0 onward, `credentials list` and
  `credentials delete`; and on 3.1.0, `access force-change`,
  `access set-min-length`, and `config toggle-always-uv`
- PIV: `info`, `reset`; every command under `access`, `keys`, `certificates`,
  and `objects`
- OATH: `info`, `reset`; every command under `access` and `accounts`
- OpenPGP: `info`, `reset`; all commands under `access`, `keys`, and
  `certificates`, subject to the CanoKey-specific negative cases below

The FIDO test resets the application where the command has no power-up window,
sets, verifies, and changes its PIN, then verifies a signed assertion on every
supported PC/SC firmware. From 2.0.0 onward it provisions two resident
credentials, verifies the getNextAssertion path, and checks the CLI's table and
CSV list/delete lifecycle. The PIV and
OATH tests provision data, verify round trips, and clean it up. On firmware
1.3, the OATH lifecycle uses its matrix-selected legacy dialect and still
executes reset, info, TOTP/HOTP with SHA1/SHA256, touch metadata, URI and PSKC
import, generated secrets, list, calculate, and delete. Only the confirmed
missing password, rename, SHA512, and full-HMAC features report `UNSUPPORTED`
or a pytest skip. The OpenPGP test changes and recovers PINs, provisions a
standard SIG, DEC, and AUT keys, verifies signing, decryption and internal
authentication, tests each key's metadata and touch policy, and verifies a
certificate round trip in all three slots. When supported, it also exercises
the separate attestation feature. It resets the applet at the end.

After the executable smoke lifecycle, `device-tests.sh` runs the reusable
upstream CLI and protocol device tests for each applet against the same real
PC/SC reader. The suite covers FIDO U2F version reporting, CTAP2 discovery and
`fido info`, prompt and error paths, OATH vectors and PSKC, PIV certificate and
cryptographic operations, and OpenPGP signing, decryption, and key agreement.
Pytest reports capability exclusions with their skip reasons; an ordinary test
failure remains fatal.

### Upstream ykman reuse

The ykman 5.9.2 baseline contains 24 device-test modules and 472 statically
collected test instances. This runner selects 15 of those upstream modules and
310 instances. The module reuse is therefore 62.5%, and the instance collection
reuse is 65.7%. These are collection metrics, not pass-rate claims: pytest's
pass/skip/fail summary remains the source of truth for a particular firmware
run.

The baseline has four FIDO-related upstream instances, but only one applies to
CanoKey:

- `test_interfaces.py::test_switch_interfaces` runs unchanged in substance and
  repeatedly opens `FidoConnection`; the CanoKey compatibility decorator only
  applies the audited `fido-pcsc` firmware gate.
- The three cases in `test_fips_u2f_commands.py` exercise YubiKey 4 FIPS vendor
  APDUs, not standard U2F or CTAP2 behavior. They are excluded instead of being
  collected only to skip.

Thus FIDO's upstream applicability on CanoKey is 1/4 (25%), and the runner
executes the one applicable upstream instance.

The three fork-added FIDO instances cover gaps with no upstream ykman 5.9.2
equivalent: U2F `VERSION`, CTAP2 `getInfo`, and `ckman fido info`, all over the
real PC/SC connection. Together, the FIDO pytest job executes four applicable
tests without collecting the three YK4 FIPS-only tests. The preceding
black-box lifecycle additionally covers the standard reset and PIN commands
and, where available, credential management.

On firmware 1.3, the `fido-pcsc` matrix entry is explicitly unsupported, so
these four standard PC/SC tests report `UNSUPPORTED` skips. On every cataloged
firmware from 1.5.2 onward, all four tests execute and must pass.

The selected common upstream tests also cover invalid-AID handling and the
general `ykman info` behavior. Tests for OTP, YubiHSM Auth, Security Domain,
SCP, and USB mode mutation remain out of the runner: those applications are not
available on the audited CanoKey firmware, or the test can disconnect the sole
USB/IP device. Collecting them only to skip them would inflate reuse without
increasing exercised behavior.

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
firmware fails the device-test gate until its behavior is validated and the
matrix is updated. Hardware provisioning state, including attestation
certificates and preinstalled keys, is always probed at runtime rather than
inferred from firmware.

All nine cataloged releases from 1.3 through 3.1.0 run this same test
lifecycle. Matrix jobs use `fail-fast: false` so a difference in one release
does not hide results from the others.

YubiKey release gates and CanoKey firmware gates are independent. Tests retain
their upstream YubiKey version predicates. On CanoKey, the same test body uses
the admin firmware version and the feature matrix instead; synthetic versions
reported by individual applets are never compared to CanoKey firmware.

- PIV retry counter configuration, metadata-based key info/export, import PIN
  policies, retired slots, PIN-protected objects, and attestation
- PIV factory object framing before/after 1.6.1 and empty-slot metadata status
  before/after 3.0.0, including Bio probing; audited legacy responses are
  normalized and still tested
- PIV SELECT security-state reset, available from firmware 2.0.0; older
  firmware is explicitly deauthenticated before each standard PIV reset
- OATH response chaining behavior before and after the 3.0.1 firmware fix
- OATH legacy commands and response framing on firmware 1.3; modern commands
  from 1.5.2 onward; touch is independently supported on every cataloged
  firmware, using the 1.3-specific property TLV encoding where required
- OATH full-HMAC responses and duplicate rename rejection, available from 2.0.0;
  ordinary truncated calculations and renames continue to run on older firmware
- OpenPGP retry counter configuration
- OpenPGP 65/6E/7A constructed response framing before/after 2.0.0; legacy
  responses are normalized and the OpenPGP lifecycle still runs
- OpenPGP RSA4096 generation, available from firmware 2.0.0; RSA imports and
  smaller generation sizes remain independently tested
- OpenPGP UIF touch policy, unavailable on 1.3 and available from 1.5.2
- OpenPGP `GET CHALLENGE`, available from firmware 3.0.0
- OpenPGP attestation key and signing-key attestation
- FIDO reset without a power-cycle window from firmware 1.5.2 through 1.6.2;
  PIN management over PC/SC from firmware 1.5.2 onward; credential management
  from firmware 2.0.0 onward
- FIDO authenticator configuration and PIV MOVE KEY from firmware 3.1.0;
  PIV/OpenPGP retry configuration is also enabled only from 3.1.0

## Not covered by the current hosted-runner path

- FIDO over HID: the GitHub-hosted Azure kernel exposes the USB HID interface
  but does not bind it to `usbhid`. FIDO is instead exercised over the audited
  PC/SC path; this does not claim HID coverage.
- FIDO reset on firmware 2.0.0 and newer: the firmware requires reset within
  ten seconds of power-up, before the hosted PC/SC path exposes the card. The
  command remains covered on firmware 1.5.2 through 1.6.2.
- `otp`: CanoKey does not advertise the Yubico OTP capability.
- `hsmauth`: CanoKey does not advertise the YubiHSM Auth capability.
- `securitydomain`: the catalog firmware does not advertise this capability.
- `config`: CanoKey's admin configuration protocol, including the 3.1.0
  extensions, is not wire-compatible with YubiKey management configuration.
  The ckman command is therefore unsupported rather than merely untested.
- `script`: this executes arbitrary user-provided Python and does not add device
  protocol coverage beyond the commands above.

HID commands must not be marked as integrated until a GitHub-hosted kernel path
provides a real bound HID transport. Help output or mocked transports do not
count as coverage.
