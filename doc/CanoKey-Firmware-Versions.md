# CanoKey Firmware Protocol Changelog

Reference for ckman (yubikey-manager fork) development. Only **host-visible protocol changes** are recorded: instructions, APDU/SW behavior, TLV formats, reported version numbers, algorithms, applet additions/removals, and USB enumeration. Internal refactors, build system, and test-only changes are omitted.

The version set matches `canokey-usbip` commit `f7953f70d353316ff8ed29589039c3d23ef99c79`, `compat/config/firmwares.yaml`. Intermediate firmware changes are folded into the next cataloged snapshot.

Device information (firmware version, serial number) must always be read through the **admin applet**. No other channel is reliable across versions; do not add dependencies on any other applet for device identification.

The exact core commit selects a reproducible firmware build, but it is not a
feature-version API. `ckman` feature decisions use the admin applet firmware
version. USB/IP tests assert that the admin version matches the firmware ID
mapped from the exact core commit before executing any lifecycle command.
The integration workflow obtains that mapping from the pinned `canokey-usbip`
catalog and executes every historical release from 1.3 through 3.0.1.

## Milestones (quick reference)

| Firmware | Exact canokey-core commit | Key changes at this snapshot |
|---|---|---|
| 1.3 | `5f1e95f8341856d994abb4566995e2379cc0612d` | CTAP2 Ed25519; FIDO credential ID grows 64 → 68 bytes |
| 1.5.2 | `b16e8c517ed72fe26e5101b450a99df2b3526aa1` | OATH uses the YubiKey instruction set, version TLV, password protection, and SHA512 |
| 1.6.1 | `e022053a87e10d5d1e655f9cc59ecb0207160e09` | OpenPGP algorithm information; PIV 3000-byte certificates and APDU chaining |
| 1.6.2 | `0ac63dfb52805c77af5b19e51b9c5ae19a741c92` | Admin config adds keyboard-return behavior |
| 2.0.0 | `e90f851fe220082a9864136862d3253ab57c96f0` | FIDO 2.1; PIV reports 5.3.0 and gains metadata, retired slots, and extended algorithms |
| 2.0.1 | `be6325b8c4e6d40e86b2943f65083ed6b71f8259` | CTAP authData and getNextAssertion fixes |
| 3.0.0 | `7cb33508a69ce4d281a053e1e53e6d006469076b` | PIV reports 5.7.0; pass applet; admin, OATH, and OpenPGP extensions |
| 3.0.1 | `69e562bcb07eedda015aae6064870c8548571e2b` | PIV Ed25519 and X25519 fixes; OATH and CTAP concurrency fixes |

## Invariants across all versions (safe to rely on)

- APDU layer: a command without Le (case-1) is answered with 61xx chaining; GET RESPONSE without Le never yields data; explicit Le=0x00 means 256 bytes; extended APDU Le is clamped to 1340 bytes; command chaining (CLA=10h) is supported. **ckman must always use short APDUs with an explicit Le.**
- OATH has no reset instruction (INS 04h); OATH reset is only available through the admin applet (INS 05h).
- PIV: no MOVE KEY (INS FFh is SET_MANAGEMENT_KEY); management key is always 3-key TDES, default `0102..08` ×3; PIN/PUK are fixed-length 8 bytes, FF-padded, defaults `123456` / `12345678`.
- PIV slot 9C defaults to PIN policy ONCE whenever metadata is available through 3.0.1, rather than YubiKey's ALWAYS.
- OpenPGP: RSA private key import uses CRT format; VERIFY with a wrong PIN returns 6982 instead of 63Cx.
- Admin applet: default PIN `123456`, 3 retries; READ_SN/READ_CONFIG require an explicit Le.
- Admin PIN handling: use empty-Lc VERIFY to inspect validation state without consuming a retry. Never guess the default PIN; request an explicit PIN when the admin applet is not already verified.
- CCID interface string is "OpenPGP PIV OATH"; the ATR contains "CanoKey".

## Per-version details

### 1.3
- USB VID/PID is `20A0:42D4`; manufacturer is "canokeys.org" and product is "CanoKey"
- Admin READ_VERSION, READ_SN, and READ_CONFIG provide device identification and configuration
- OATH uses the legacy instruction set: PUT 01 / DELETE 02 / LIST 03 / CALCULATE 04 / CALCULATE_ALL 05 / SEND_REMAINING 06 / SET_DEFAULT 55; SELECT returns no version TLV and there is no password protection
- PIV reports 5.0.0 and supports RSA2048, ECCP256, and ECCP384
- OpenPGP GET DATA 65/6E/7A returns the contents without the constructed outer tag
- OpenPGP standard UIF data objects D6/D7/D8 are absent; touch-policy commands
  using those objects are unsupported
- CTAP2 gains Ed25519: makeCredential accepts alg -8; credential ID grows to 68 bytes (U2F key handles likewise)
- Note: getInfo does not advertise Ed25519; hosts must probe. Credentials created by older firmware (64-byte IDs) may not survive the upgrade.

### 1.5.2
- OpenPGP ECDH returns a bare shared secret; UIF data objects and the general-feature-management template are available
- Admin READ_CONFIG is 5 bytes; CONFIG controls NDEF and WebUSB; FACTORY_RESET is rejected over NFC
- **OATH reworked to the YubiKey instruction set**: LIST A1 / CALCULATE A2 / VALIDATE A3 / SEND_REMAINING A5 / SET_CODE 03 / RENAME 05; CALCULATE_ALL moves to SELECT with P1=00; SELECT returns a version TLV (reports 5.5.5) plus a session handle, and a challenge when a password is set; all commands except SELECT/VALIDATE answer 6982 until validated; SHA512 added
- OATH CALCULATE ignores P2 and always returns the five-byte truncated form
  (tag 76h); RENAME does not reject a destination name that already exists
- Admin: EXPORT_OATH (06h) removed
- OpenPGP: terminated state returns 6285; PUT DATA length checks tightened
- PIV: factory CHUID/CCC are now populated (randomized GUID), but their stored
  responses omit the required 0x53 container tag
- CCID: SELECT of the FIDO AID over CCID is no longer rejected
- **FIDO over PC/SC is available**: ckman can select the FIDO AID and issue
  CTAP2 commands through the CCID interface. Firmware 1.3 is explicitly
  unsupported for this transport path.

### 1.6.1
- OpenPGP: GET DATA 0xFA (algorithm information) added, returned as a **bare TLV list without the outer 0xFA tag**; Ed25519 public key read-back off-by-one fixed
- PIV: factory CCC/CHUID are wrapped in the proper 0x53 container tag from this
  release onward
- USB sends gain a ~50 ms timeout instead of blocking forever
- PIV: certificate capacity raised to 3000 bytes; new GET DATA RESPONSE (INS C0h) for chained reads; PUT DATA accepts command chaining (CLA=10h); over-capacity writes return 6700 instead of 6A84

### 1.6.2
- Admin: CONFIG gains P1=06h (keyboard output appends return); READ_CONFIG response grows to 6 bytes

### 2.0.0
- **CTAP upgraded to FIDO 2.1**: getInfo adds FIDO_2_1, pinUvAuthProtocols=[1,2], credMgmt / largeBlobs / credProtect / credBlob / largeBlobKey; authenticatorReset limited to 10 s after power-up
- **PIV**: reported version 5.0.0 → **5.3.0**; GET METADATA (F7h) added; retired key slots 82/83 (certificates 5FC10D/0E); Printed Information object 5FC109 (read requires PIN); Ed25519 (0x22) always available; RSA3072/4096 (custom IDs 0x50/0x51), X25519 (0x52), secp256k1 (0x53), SM2 (0x54) require enabling via admin config (INS 40h, P1=07h); GENERATE accepts PIN/touch policy TLVs; SELECT now clears PIN and management-key security state
- OpenPGP: GET DATA 65/6E/7A responses gain their constructed outer tags (0xFA stays bare); algorithm information gains RSA3072 and SM2
- OpenPGP: RSA4096 key generation becomes functional (1.6.x advertises it
  but its generator only accepts RSA2048)
- OATH: CALCULATE can return the full HMAC digest (P2=0, tag 0x75), and
  RENAME rejects duplicate destination names

### 2.0.1
- CTAP: authData no longer carries the ED flag when no extension output exists; getNextAssertion no longer requires user presence

### 3.0.0
- Admin: Reset CTAP (09h), CTAP SM2 config read/write (11h/12h), Reset Pass (13h), pass slot config (43h/44h), NFC switch (14h) added; CONFIG P1=03/06/07 removed
- **pass applet added** (touch-typing slots; configured through the admin applet, no own AID)
- OATH: SELECT version becomes 6.0.0; SET_DEFAULT (55h) repurposed to configure pass slots
- **PIV**: reported version 5.3.0 → **5.7.0**; extended algorithm IDs switch to standard YubiKey values (Ed25519 0x22→0xE0, RSA3072 0x50→0x05, RSA4096 0x51→0x16, X25519 0x52→0xE1) and are **enabled by default**; GET METADATA on an empty slot returns standard 6A88 instead of the 6900 used by 2.0.x; algorithm extension config INS EEh added
- OpenPGP: GET_CHALLENGE (84h) added; extended capabilities byte 0x34 → 0x74
- PIV fingerprint (5FC103) and facial image (5FC108) objects added (read requires PIN)

### 3.0.1
- Admin NFC (14h) read no longer requires PIN
- PIV: Ed25519 general-authenticate signing fixed; X25519 private key import becomes little-endian; import tags constrained (06 generic / 07 Ed25519 / 08 X25519)
- OATH: SEND_REMAINING chain fixed (no longer returns wrong data when records exactly fill the buffer)
- CTAP: CCID/HID concurrency handling fixed
- OpenPGP: P-384 is advertised and supports key import/generation and ECDH, but ECDSA signing with a SHA-256 digest returns 6700. The later core commit `e3da9ffffdef299defdcb589ed90b08c3b353505` adds the missing digest padding; no cataloged firmware contains it yet.

## ckman implementation notes

- **APDU format**: always short APDUs with an explicit Le. Never rely on case-1 (no Le) commands or Le-less GET RESPONSE — they loop forever on 61xx.
- **Device information**: read firmware version and serial from the admin applet (INS 31h/32h, explicit Le required). PIV/OATH/OpenPGP report synthetic YubiKey-style versions that must not be used for feature decisions.
- **Resets**: OATH reset exists only via the admin applet; PIV and OpenPGP resets work via their own applets (PIV requires PIN+PUK blocked; OpenPGP via TERMINATE+ACTIVATE); CTAP reset via admin 09h needs 3.0.0+.
- **OpenPGP algorithm information**: it is absent in catalog versions 1.3 and 1.5.2, and is a bare TLV list in 1.6.1 through 3.0.1.
- **OpenPGP constructed data objects**: GET DATA 65/6E/7A omits its
  constructed outer tag through 1.6.2. ckman restores only those three tags on
  audited pre-2.0 firmware; 2.0.0 and newer responses remain untouched.
- **OATH dialects**: catalog version 1.3 uses the legacy instruction set (send-remaining 06h, no version TLV, no password protection); 1.5.2 and newer use the YubiKey set (send-remaining A5h). A locked OATH applet answers A5h with 6982, not 6985.
- **OATH data limits**: HOTP counters start at 1; CALCULATE rejects challenges longer than 8 bytes; LIST/CALCULATE_ALL may silently drop records that exactly fill the response buffer.
- **OATH full response**: 1.5.2 through 1.6.2 always return the truncated
  tag-76h response even for P2=0. Its four-byte payload has already undergone
  dynamic truncation; ckman uses it directly for Steam codes, while full-HMAC
  vector tests are explicitly unsupported until 2.0.0.
- **OATH rename collision**: duplicate destination detection is absent through
  1.6.2 and available from 2.0.0. Ordinary rename remains tested on old
  firmware; only the collision-error assertion is gated.
- **PIV algorithms**: RSA1024 never exists. Extended algorithms on 2.0.x need admin config (40h, P1=07h) and use custom IDs; 3.0.0+ enables them by default with standard IDs.
- **PIV object framing**: factory CHUID/CCC data in 1.5.2 omits the 0x53
  container. ckman accepts only the known CHUID (30h) and CCC (F0h) legacy
  forms on audited pre-1.6.1 firmware; other malformed object data remains an
  error.
- **PIV empty metadata**: 2.0.0 and 2.0.1 return 6900 for GET METADATA on an
  empty defined key slot and an empty successful response for key slots not
  implemented by those releases, including the biometric metadata slot. ckman
  maps only those exact GET METADATA results to standard empty-slot or
  unsupported-Bio results. Other APDU errors and malformed non-empty responses
  are preserved.
- **PIV SELECT state**: SELECT does not clear prior PIN/management-key security
  state through 1.6.2; 2.0.0 adds the reset. Tests that specifically assert
  re-selection clears authentication are unsupported on the older releases.
  Before performing a PIV reset on those releases, ckman explicitly logs out a
  verified PIN with standard VERIFY P1=FF so the retry-blocking reset sequence
  cannot loop on the preserved state.
- **PIV management key**: TDES only; SET_MANAGEMENT_KEY requires LC=27 and the `03 9B 18` prefix. The PIN-protected management key feature (pivman objects) is unavailable — hosts must not set a new key before confirming they can store it.
- **PIN retries**: PIV/OpenPGP SET_PIN_RETRIES is unavailable in every cataloged firmware through 3.0.1; map 6D00 to "not supported".
- **OpenPGP attestation**: the YubiKey-specific attestation key, certificate,
  and GET_ATTESTATION command are unavailable in every cataloged firmware
  through 3.0.1. Standard `sig`, `dec`, and `aut` key metadata, UIF, and
  certificate objects remain supported and must be tested independently.
- **OpenPGP UIF**: standard D6/D7/D8 UIF data objects are absent in 1.3 and
  available from 1.5.2. The touch-policy lifecycle is skipped only on 1.3.
- **OpenPGP certificate selection**: CanoKey numbers SELECT DATA certificate
  occurrences as `sig=0`, `dec=1`, `aut=2`; YubiKey uses the reverse order.
  This is consistent across all cataloged CanoKey firmware.
- **OpenPGP RSA generation**: 1.6.x algorithm information advertises RSA4096,
  but GENERATE accepts only RSA2048. RSA4096 generation is available from
  2.0.0; import capability is tested independently.

## ckman feature matrix

The executable matrix is maintained in `yubikit/canokey.py`. Each rule records
supported inclusive firmware ranges and the newest audited catalog firmware.
The resulting states match the upstream device-test model:

- **supported**: the command must succeed; failure is fatal.
- **unsupported**: report the firmware-specific reason and continue.
- **unknown**: do not enable or skip the feature. Device tests fail until the
  firmware/feature combination is validated and the matrix is updated.

`fido-pcsc` is unsupported on 1.3 and supported from 1.5.2 through the latest
audited catalog firmware (3.0.1). The FIDO device and CLI tests exercise this
path through `SmartCardCtapDevice`; transport, permission, and APDU failures are
test failures and are never converted into an unsupported result.

The same matrix records protocol-correct framing/status boundaries for
`openpgp-data-object-wrapping` (2.0.0+), `piv-object-response-wrapping`
(1.6.1+), and `piv-empty-slot-metadata-status` (3.0.0+). Known older forms are
normalized narrowly so their commands still execute; an unknown newer
firmware fails closed instead of inheriting either compatibility path.

It also records the independently confirmed 2.0.0 boundaries for
`oath-full-response`, `oath-rename-collision-check`,
`piv-select-resets-security-state`, and `openpgp-rsa4096-generation`. Tests gate
only the missing semantics; adjacent supported operations continue to execute.

CanoKey CTAP1 responses over PC/SC pass through `SmartCardProtocol`, which
separates the APDU status word from its data. The CanoKey FIDO adapter restores
that status word before returning the frame to `python-fido2`; this is required
by its `CTAPHID.MSG` contract. The CTAP2/CBOR path is unchanged.

Applet-reported PIV, OATH, and OpenPGP protocol versions are synthetic and must
not be used to select these rules. Provisioning-dependent state such as an
attestation certificate or preinstalled key is not a firmware feature and must
always be probed at runtime.
