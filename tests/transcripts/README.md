# Transcript fixtures

Unit tests in this repository use **scripted transcripts**: recorded
command/response APDU pairs replayed through a fake exchange, so libcanokey
operations are verified byte-for-byte without hardware.

## Convention

- A transcript is a list of `(command, response)` byte pairs. The script
  asserts the command matches the next expected entry, then returns the
  recorded response.
- The **response includes SW1/SW2** (`90 00` on success); the exchange
  contract is "one complete command APDU in, one complete response out".
- The **firmware version is part of the fixture**: build the profile with
  `DeviceProfile::from_observations(DeviceObservations::new(b"3.1.0"))` (add
  `serial`/`piv_version`/`algorithm_config` as the applet needs) and name the
  version in the test, since framing rules (explicit Le, DO wrapping, key
  formats) depend on it.
- Record both sides of capability gates: a rejection test asserts the error
  kind **and** that no exchange happened (the gate fires before any I/O).
- Long responses exercise the continuation layer (61xx + GET RESPONSE, or
  CLA-0x10 command chaining) rather than being truncated to fit short APDUs.

## Sources for new recordings

1. **libcanokey's own test fixtures** (`crates/*/tests/` in the pinned
   checkout) — preferred; they are cross-checked against firmware source.
2. APDU traces from real or usbip-virtual hardware, normalized to the
   command/response-pair shape above. Record the exact firmware version with
   the trace.
3. Known-answer vectors (e.g. TDES/AES management-key cryptograms) must be
   cross-checked with an independent tool (OpenSSL) — say so in a comment.

Keep transcripts deterministic: fixed challenges/scalars come from fixtures,
never from the RNG (production randomness is injected via getrandom helpers
that tests bypass by constructing the inner values directly).

Each module carries its own small `Script` helper (see
`crates/ckman-core/src/lib.rs`); this is deliberate duplication — applet
transcripts diverge enough that a shared abstraction obscures them.
