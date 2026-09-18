//! Typed wrappers around `canokey::admin` operations.
//!
//! Each wrapper owns one complete Admin operation on the caller's exclusive
//! connection: it builds the operation from the immutable probed profile,
//! drives it to completion over the exchange, and returns a typed result.
//! No wrapper holds the connection or retries anything itself.
//!
//! libcanokey never tries default credentials. A protected request built with
//! `pin: None` is rejected before any I/O with a typed
//! [`ErrorKind::SecurityStatusNotSatisfied`] error; callers (e.g. the CLI) may
//! catch that, prompt for the Admin PIN, and retry once with `Some(pin)`.
//! [`factory_reset`] takes no PIN: firmware requires the Admin PIN to already
//! be blocked plus card-enforced physical presence, and libcanokey rejects a
//! supplied PIN to prevent hidden credential attempts.

use crate::{execute, DriveError, Exchange};
use canokey::admin::{self, Request, Value};
use canokey::{DeviceProfile, Error, ErrorKind, OperationOptions, Phase};

pub use canokey::admin::{Applet, Configuration, LegacyConfiguration, Pin, PinStatus};

/// Admin configuration read result, preserving the firmware's own layout.
///
/// The layout is selected from actual firmware evidence, never from the
/// response length; reserved bytes and unknown feature bits stay observable
/// through `raw()` on each variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminConfiguration {
    /// Current six-byte layout (firmware 3.1), including feature bits.
    Modern(Configuration),
    /// Historical layout with optional fields; absent flags are `None`, never
    /// reinterpreted or invented.
    Legacy(LegacyConfiguration),
}

fn unexpected_value<E>() -> DriveError<E> {
    DriveError::Protocol(Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing))
}

fn run<E>(
    profile: &DeviceProfile,
    request: Request,
    pin: Option<Pin>,
    exchange: &mut Exchange<'_, E>,
) -> Result<admin::Outcome, DriveError<E>> {
    let operation = admin::operation(profile, request, pin, OperationOptions::default())?;
    execute(operation, exchange)
}

/// Read the current device configuration in the firmware's own layout.
///
/// On firmware before the pinned 3.1 layout this read sits behind the
/// firmware Admin-PIN gate, so `pin: None` fails preflight with
/// [`ErrorKind::SecurityStatusNotSatisfied`]; prompt and retry with a PIN.
pub fn read_configuration<E>(
    profile: &DeviceProfile,
    pin: Option<Pin>,
    exchange: &mut Exchange<'_, E>,
) -> Result<AdminConfiguration, DriveError<E>> {
    match run(profile, Request::Configuration, pin, exchange)?.value {
        Value::Configuration(config) => Ok(AdminConfiguration::Modern(config)),
        Value::LegacyConfiguration(config) => Ok(AdminConfiguration::Legacy(config)),
        _ => Err(unexpected_value()),
    }
}

/// Read the vendor NFC availability flag.
///
/// Vendor NFC commands are gated by `Capability::AdminNfc` (firmware 3.0+);
/// older known firmware fails with [`ErrorKind::UnsupportedFeature`], and
/// unrecognized firmware with [`ErrorKind::CapabilityUnknown`]. On 3.0.0 the
/// read itself requires the Admin PIN; from 3.0.1 it is public.
pub fn nfc_status<E>(
    profile: &DeviceProfile,
    pin: Option<Pin>,
    exchange: &mut Exchange<'_, E>,
) -> Result<bool, DriveError<E>> {
    match run(profile, Request::NfcStatus, pin, exchange)?.value {
        Value::NfcStatus(on) => Ok(on),
        _ => Err(unexpected_value()),
    }
}

/// Enable or disable NFC and return the new state.
///
/// The returned value is the requested state once firmware has acknowledged
/// the write with 9000; no post-write read is attempted because the NFC write
/// may drop the connection. Same capability gating as [`nfc_status`]; the
/// write always requires the Admin PIN.
pub fn set_nfc<E>(
    profile: &DeviceProfile,
    on: bool,
    pin: Option<Pin>,
    exchange: &mut Exchange<'_, E>,
) -> Result<bool, DriveError<E>> {
    run(profile, Request::SetNfc(on), pin, exchange)?;
    Ok(on)
}

/// Whether the configuration read is public on this firmware.
///
/// Only the pinned 3.1 layout allows reading the device configuration without
/// the Admin PIN; older known firmware answers READ CONFIG with 6982 and
/// libcanokey rejects an unauthenticated read at construction. Callers
/// building read-only status output must check this first instead of
/// prompting for the Admin PIN.
pub fn public_configuration_supported(
    profile: &DeviceProfile,
) -> canokey::compatibility::CapabilityStatus {
    profile.capability(canokey::compatibility::Capability::AdminPublicConfiguration)
}

/// Destroy one applet's data and credentials using Admin authorization.
///
/// This is the shared primitive behind per-applet resets (e.g. `oath reset`):
/// it resets exactly the named applet and nothing else. CTAP and PASS resets
/// are additionally gated by `Capability::AdminCtapPassReset` (firmware 3.0+);
/// older firmware fails with [`ErrorKind::UnsupportedFeature`]. Always
/// requires the Admin PIN.
pub fn reset_applet<E>(
    profile: &DeviceProfile,
    applet: Applet,
    pin: Option<Pin>,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), DriveError<E>> {
    run(profile, Request::ResetApplet(applet), pin, exchange)?;
    Ok(())
}

/// Reset the whole device, erasing all applets and the Admin PIN.
///
/// Firmware only honors this when the Admin PIN is already blocked and
/// physical presence is asserted on-card; libcanokey never submits PIN
/// guesses or retries for it, so no PIN is accepted here either.
pub fn factory_reset<E>(
    profile: &DeviceProfile,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), DriveError<E>> {
    run(profile, Request::FactoryReset, None, exchange)?;
    Ok(())
}

/// Verify the Admin PIN without another target command.
pub fn verify_pin<E>(
    profile: &DeviceProfile,
    pin: Pin,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), DriveError<E>> {
    run(profile, Request::VerifyPin, Some(pin), exchange)?;
    Ok(())
}

/// Replace the Admin PIN. `old` is verified first; `new` must satisfy the
/// applet's six-through-64-byte length rule (enforced by [`Pin::from_bytes`]).
pub fn change_pin<E>(
    profile: &DeviceProfile,
    old: Pin,
    new: Pin,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), DriveError<E>> {
    run(profile, Request::ChangePin(new), Some(old), exchange)?;
    Ok(())
}

/// Query Admin verification state and remaining retries without submitting a
/// PIN (a single empty VERIFY). PIN guesses are never sent; supplying a PIN
/// for this query is rejected by libcanokey, so none is accepted here.
pub fn pin_status<E>(
    profile: &DeviceProfile,
    exchange: &mut Exchange<'_, E>,
) -> Result<PinStatus, DriveError<E>> {
    match run(profile, Request::PinStatus, None, exchange)?.value {
        Value::PinStatus(status) => Ok(status),
        _ => Err(unexpected_value()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use canokey::compatibility::DeviceObservations;
    use std::collections::VecDeque;
    use std::io;

    /// Transcript-driven exchange, mirroring the probe tests in `lib.rs`.
    struct Script {
        transcript: VecDeque<(&'static [u8], &'static [u8])>,
    }

    impl Script {
        fn exchange(&mut self, command: &[u8]) -> io::Result<Vec<u8>> {
            let (expected, response) = self
                .transcript
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "unexpected exchange"))?;
            assert_eq!(command, expected, "command differs from transcript");
            Ok(response.to_vec())
        }
    }

    fn profile(firmware: &[u8]) -> DeviceProfile {
        DeviceProfile::from_observations(DeviceObservations::new(firmware.to_vec())).unwrap()
    }

    fn pin() -> Pin {
        Pin::from_bytes(b"654321").unwrap()
    }

    const SELECT: (&[u8], &[u8]) = (&[0, 0xa4, 4, 0, 5, 0xf0, 0, 0, 0, 0], &[0x90, 0]);
    const VERIFY: (&[u8], &[u8]) = (b"\0\x20\0\0\x06654321", &[0x90, 0]);

    #[test]
    fn nfc_enable_happy_path() {
        let mut script = Script {
            transcript: [SELECT, VERIFY, (&[0, 0x14, 1, 1], &[0x90, 0])]
                .into_iter()
                .collect(),
        };
        let on = set_nfc(&profile(b"3.1.0"), true, Some(pin()), &mut |c| {
            script.exchange(c)
        })
        .unwrap();
        assert!(on);
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn nfc_write_rejected_on_old_firmware_without_io() {
        // The vendor NFC switch exists only from firmware 3.0; the gate must
        // fire at construction so no command ever reaches a 2.0.1 card.
        let mut calls = 0;
        let error = set_nfc(
            &profile(b"2.0.1"),
            true,
            Some(pin()),
            &mut |_| -> io::Result<Vec<u8>> {
                calls += 1;
                unreachable!("capability gate must reject before any exchange")
            },
        )
        .unwrap_err();
        match error {
            DriveError::Protocol(error) => assert_eq!(error.kind, ErrorKind::UnsupportedFeature),
            DriveError::Transport(_) => panic!("no transport exchange should have happened"),
        }
        assert_eq!(calls, 0);
    }

    #[test]
    fn nfc_write_without_pin_is_typed_security_error_before_io() {
        // libcanokey never tries default credentials: a protected request with
        // `pin: None` is rejected preflight, and the CLI catches this exact
        // kind to prompt and retry once.
        let mut calls = 0;
        let error = set_nfc(&profile(b"3.1.0"), true, None, &mut |_| -> io::Result<
            Vec<u8>,
        > {
            calls += 1;
            unreachable!("missing PIN must be rejected before any exchange")
        })
        .unwrap_err();
        match error {
            DriveError::Protocol(error) => {
                assert_eq!(error.kind, ErrorKind::SecurityStatusNotSatisfied)
            }
            DriveError::Transport(_) => panic!("no transport exchange should have happened"),
        }
        assert_eq!(calls, 0);
    }

    #[test]
    fn configuration_read_gate_per_firmware_layout() {
        use canokey::compatibility::Support;
        // Before 3.1 the READ CONFIG command sits behind the firmware's Admin
        // PIN gate, so the unauthenticated read is rejected at construction
        // and nothing reaches the wire; `config info` must check the gate
        // instead of prompting for a PIN (a prompt crashes TTY-less runners).
        for firmware in [
            &b"1.3"[..],
            b"1.5.2",
            b"1.6.1",
            b"1.6.2",
            b"2.0.0",
            b"2.0.1",
            b"3.0.0",
            b"3.0.1",
            b"3.0.3",
        ] {
            let profile = profile(firmware);
            assert_eq!(
                public_configuration_supported(&profile).support,
                Support::Unsupported,
                "{}",
                String::from_utf8_lossy(firmware)
            );
            let mut calls = 0;
            let error = read_configuration(&profile, None, &mut |_| -> io::Result<Vec<u8>> {
                calls += 1;
                unreachable!("the PIN gate must reject before any exchange")
            })
            .unwrap_err();
            match error {
                DriveError::Protocol(error) => {
                    assert_eq!(
                        error.kind,
                        ErrorKind::SecurityStatusNotSatisfied,
                        "{}",
                        String::from_utf8_lossy(firmware)
                    );
                }
                DriveError::Transport(_) => panic!("no transport exchange should have happened"),
            }
            assert_eq!(calls, 0);
        }
        // Unrecognized firmware reports Unknown and is also never read.
        let unknown = profile(b"9.0.0");
        assert_eq!(
            public_configuration_supported(&unknown).support,
            Support::Unknown
        );
        let mut calls = 0;
        assert!(
            read_configuration(&unknown, None, &mut |_| -> io::Result<Vec<u8>> {
                calls += 1;
                unreachable!()
            })
            .is_err()
        );
        assert_eq!(calls, 0);
        // 3.1.0 reads publicly (the happy path is covered by
        // configuration_read_keeps_unknown_feature_bits).
        assert_eq!(
            public_configuration_supported(&profile(b"3.1.0")).support,
            Support::Supported
        );
    }

    #[test]
    fn legacy_configuration_read_with_pin_uses_13_layout() {
        // With an explicit Admin PIN the read still works on legacy firmware;
        // the library parses the 1.3 seven-byte layout (flags plus OpenPGP
        // touch policies/cache). This pins that only the *unauthenticated*
        // path is gated.
        let mut script = Script {
            transcript: {
                // Explicit annotation so each fixed-size array coerces to a slice.
                let transcript: [(&[u8], &[u8]); 3] = [
                    // 1.3 carries an explicit Le even on SELECT and VERIFY.
                    (&[0, 0xa4, 4, 0, 5, 0xf0, 0, 0, 0, 0, 0], &[0x90, 0]),
                    (b"\0\x20\0\0\x06654321\0", &[0x90, 0]),
                    (&[0, 0x42, 0, 0, 0], &[1, 1, 0, 0, 0, 0, 30, 0x90, 0]),
                ];
                transcript.into_iter().collect()
            },
        };
        let config =
            read_configuration(&profile(b"1.3"), Some(pin()), &mut |c| script.exchange(c)).unwrap();
        let AdminConfiguration::Legacy(config) = config else {
            panic!("1.3 firmware uses a legacy layout")
        };
        assert!(config.led_on());
        assert_eq!(config.ndef_enabled(), None, "absent on 1.3");
        assert_eq!(config.openpgp_touch(), Some([0, 0, 0, 30]));
        assert_eq!(config.raw(), &[1, 1, 0, 0, 0, 0, 30]);
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn factory_reset_emits_select_then_reset() {
        let mut script = Script {
            transcript: [SELECT, (b"\0\x50\0\0\x05RESET", &[0x90, 0])]
                .into_iter()
                .collect(),
        };
        factory_reset(&profile(b"3.1.0"), &mut |c| script.exchange(c)).unwrap();
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn applet_reset_uses_admin_authorization() {
        let mut script = Script {
            transcript: [SELECT, VERIFY, (&[0, 5, 0, 0], &[0x90, 0])]
                .into_iter()
                .collect(),
        };
        reset_applet(&profile(b"3.1.0"), Applet::Oath, Some(pin()), &mut |c| {
            script.exchange(c)
        })
        .unwrap();
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn configuration_read_keeps_unknown_feature_bits() {
        let mut script = Script {
            transcript: [
                SELECT,
                (&[0, 0x42, 0, 0, 0], &[1, 0x88, 0, 1, 1, 0xbf, 0x90, 0]),
            ]
            .into_iter()
            .collect(),
        };
        let config =
            read_configuration(&profile(b"3.1.0"), None, &mut |c| script.exchange(c)).unwrap();
        let AdminConfiguration::Modern(config) = config else {
            panic!("3.1 firmware uses the modern layout")
        };
        assert!(config.led_on());
        assert!(config.ndef_enabled());
        assert!(!config.ndef_read_only());
        assert!(config.webusb_landing());
        // 0xbf carries feature bits 6/7, which are unknown to the pinned
        // evidence; they stay observable through the raw bytes.
        assert_eq!(config.features(), 0xbf);
        assert_eq!(config.raw()[1], 0x88, "reserved byte is retained verbatim");
    }

    #[test]
    fn pin_status_reports_retries_without_submitting_a_pin() {
        let mut script = Script {
            transcript: [SELECT, (&[0, 0x20, 0, 0], &[0x63, 0xc3])]
                .into_iter()
                .collect(),
        };
        let status = pin_status(&profile(b"3.1.0"), &mut |c| script.exchange(c)).unwrap();
        assert!(!status.verified);
        assert!(!status.blocked);
        assert_eq!(status.retries_remaining, Some(3));
    }
}
