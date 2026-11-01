# CanoKey WebAuthn SM2 algorithm identifiers

`ckman fido info` interprets algorithm identifiers in the CanoKey context.
The global COSE registry alone cannot identify historical CanoKey SM2:

| COSE ID | CanoKey interpretation |
| --- | --- |
| -48 | SM2, legacy default; not ML-DSA-44 |
| -54 | SM2, newer default |
| -49 | ML-DSA-65 |

Firmware history in `canokeys/canokey-core`:

- [0ddb93bc (2023-12-25)](https://github.com/canokeys/canokey-core/commit/0ddb93bcf101fd5b4b54d0c3c6cd3ac39ae174a1)
  introduced configurable WebAuthn SM2, disabled by default, using curve 9
  and algorithm -48 (both then unused). When enabled, getInfo advertises
  the configured algorithm ID. This explains the -48 response on 3.0.x.
- [0d11de44 (2024-01-02)](https://github.com/canokeys/canokey-core/commit/0d11de44958586a032644b96bc49a0f17194bf8a)
  preserved SM2 configuration during FIDO reset.
- [64f54499 (2026-05-06)](https://github.com/canokeys/canokey-core/commit/64f54499216a20c31b426a4cffb9c8b6884f569f)
  enabled SM2 by default and changed the default algorithm to -54. It also
  advertises ML-DSA-65 separately. Existing valid configuration is retained.
- [ffbdb843 (2026-05-07)](https://github.com/canokeys/canokey-core/commit/ffbdb843d694ca9d14fde40cb92f274eb3495c4c)
  allowed custom SM2 IDs except IDs conflicting with the firmware's native
  ES256, EdDSA and ML-DSA-65 algorithms.

The current COSE registry assigns -48 to ML-DSA-44. Consequently, printing
libcanokey's generic `CoseAlgorithm` Debug value incorrectly reports
ML-DSA-44 on historical CanoKeys. Conversely, -54 is unknown to that enum.
The CLI handles both historical defaults locally, for HID and PC/SC,
without changing the library's standards-based mapping or querying another
device for a firmware version. Without authentication, the output includes
a note that these names are inferred and custom IDs may be misidentified.

SM2 IDs are configurable: getInfo contains no curve or other information
that can identify arbitrary custom SM2 IDs unambiguously. The display
recognizes the two known defaults; other IDs retain the library's COSE
interpretation (including `Unknown(id)`).

Use `ckman fido info --admin-pin PIN` for authoritative SM2 identification
on firmware 3.0 and newer. This selects the device once over PC/SC, reads
its SM2 configuration with the supplied Admin PIN, then reads FIDO getInfo
on the same connection. Normal `--reader` and `--device` selection applies.
It requires a working PC/SC interface even when USB HID is available.
The configured algorithm ID takes precedence over every generic COSE
name, and legacy SM2 disabled state is respected. Authentication/read
failures are reported as errors without falling back to inferred names.
The command does not change SM2 configuration.

`ckman config sm2` can also inspect the configuration directly (prompts for
the Admin PIN).
