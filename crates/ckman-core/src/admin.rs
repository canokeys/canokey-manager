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

pub use canokey::admin::{
    Applet, AppletUsage, Configuration, ConfigurationPatch, FlashUsage, KeyboardKeymap,
    LegacyConfiguration, LegacySm2Configuration, PassSlotConfig, PassSlotId, PassSlotState,
    PassSlots, Pin, PinStatus, Sm2Configuration,
};

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

/// Read both PASS touch-slot configurations. PIN-gated on every firmware that
/// implements it (3.0+; `Capability::AdminPassConfig` gates construction).
pub fn pass_slots<E>(
    profile: &DeviceProfile,
    pin: Option<Pin>,
    exchange: &mut Exchange<'_, E>,
) -> Result<PassSlots, DriveError<E>> {
    match run(profile, Request::PassSlots, pin, exchange)?.value {
        Value::PassSlots(slots) => Ok(slots),
        _ => Err(unexpected_value()),
    }
}

/// Replace one PASS slot configuration (Off / static password / HMAC-SHA1).
/// PIN-gated like the read; the slot type is validated before any I/O.
pub fn set_pass_slot<E>(
    profile: &DeviceProfile,
    slot: PassSlotId,
    config: PassSlotConfig,
    pin: Option<Pin>,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), DriveError<E>> {
    run(
        profile,
        Request::SetPassSlot { slot, config },
        pin,
        exchange,
    )?;
    Ok(())
}

/// Apply a configuration patch: libcanokey reads the current state, writes
/// only fields that differ, and preserves every unspecified field; unknown
/// feature bits block feature-mask overwrites. PIN-protected on all firmware.
pub fn configure<E>(
    profile: &DeviceProfile,
    patch: ConfigurationPatch,
    pin: Option<Pin>,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), DriveError<E>> {
    run(profile, Request::Configure(patch), pin, exchange)?;
    Ok(())
}

/// Read the configured keyboard layout identifier. Marked public by the
/// library's request table, but real 3.1 firmware answers 6982, so callers
/// should offer the PIN retry path.
pub fn keyboard_layout<E>(
    profile: &DeviceProfile,
    pin: Option<Pin>,
    exchange: &mut Exchange<'_, E>,
) -> Result<u8, DriveError<E>> {
    match run(profile, Request::KeyboardLayout, pin, exchange)?.value {
        Value::KeyboardLayout(layout) => Ok(layout),
        _ => Err(unexpected_value()),
    }
}

/// Read the 256-byte keyboard HID map. Same firmware PIN gate as
/// [`keyboard_layout`].
pub fn read_keymap<E>(
    profile: &DeviceProfile,
    pin: Option<Pin>,
    exchange: &mut Exchange<'_, E>,
) -> Result<KeyboardKeymap, DriveError<E>> {
    match run(profile, Request::KeyboardKeymap, pin, exchange)?.value {
        Value::KeyboardKeymap(keymap) => Ok(keymap),
        _ => Err(unexpected_value()),
    }
}

/// Replace the keyboard HID map for a layout (PIN-protected).
pub fn set_keymap<E>(
    profile: &DeviceProfile,
    layout_id: u8,
    keymap: KeyboardKeymap,
    pin: Option<Pin>,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), DriveError<E>> {
    run(
        profile,
        Request::SetKeyboardKeymap { layout_id, keymap },
        pin,
        exchange,
    )?;
    Ok(())
}

/// Clear the stored keyboard HID map (PIN-protected).
pub fn clear_keymap<E>(
    profile: &DeviceProfile,
    pin: Option<Pin>,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), DriveError<E>> {
    run(profile, Request::ClearKeyboardKeymap, pin, exchange)?;
    Ok(())
}

/// Set the historical append-return flag (1.6.2–2.x only; gated by
/// `Capability::AdminKeyboardReturn`). PIN-protected.
pub fn set_keyboard_return<E>(
    profile: &DeviceProfile,
    on: bool,
    pin: Option<Pin>,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), DriveError<E>> {
    run(profile, Request::SetKeyboardReturn(on), pin, exchange)?;
    Ok(())
}

/// Read the embedded core commit bytes (3.1 extended configuration).
pub fn core_commit<E>(
    profile: &DeviceProfile,
    exchange: &mut Exchange<'_, E>,
) -> Result<Vec<u8>, DriveError<E>> {
    match run(profile, Request::CoreCommit, None, exchange)?.value {
        Value::Bytes(bytes) => Ok(bytes),
        _ => Err(unexpected_value()),
    }
}

/// Read physical flash usage in KiB. Public on 3.1; PIN-gated before.
pub fn flash_usage<E>(
    profile: &DeviceProfile,
    pin: Option<Pin>,
    exchange: &mut Exchange<'_, E>,
) -> Result<FlashUsage, DriveError<E>> {
    match run(profile, Request::FlashUsage, pin, exchange)?.value {
        Value::FlashUsage(usage) => Ok(usage),
        _ => Err(unexpected_value()),
    }
}

/// Read the eight logical applet usage records (3.1 extended configuration).
pub fn applet_usage<E>(
    profile: &DeviceProfile,
    exchange: &mut Exchange<'_, E>,
) -> Result<Vec<AppletUsage>, DriveError<E>> {
    match run(profile, Request::AppletUsage, None, exchange)?.value {
        Value::AppletUsage(usage) => Ok(usage),
        _ => Err(unexpected_value()),
    }
}

/// CTAP SM2 configuration readout: typed identifiers on 3.1, the legacy
/// nine-byte native layout on 3.0.x.
#[derive(Clone, Debug)]
pub enum Sm2Readout {
    /// 3.1 typed layout: signed COSE curve/algorithm identifiers.
    Typed(Sm2Configuration),
    /// 3.0.x legacy layout: enable flag plus uninterpreted native bytes.
    Legacy(LegacySm2Configuration),
}

/// Read the CTAP SM2 configuration (3.0+; PIN-gated on every firmware).
pub fn sm2_configuration<E>(
    profile: &DeviceProfile,
    pin: Option<Pin>,
    exchange: &mut Exchange<'_, E>,
) -> Result<Sm2Readout, DriveError<E>> {
    match run(profile, Request::Sm2Configuration, pin, exchange)?.value {
        Value::Sm2Configuration(config) => Ok(Sm2Readout::Typed(config)),
        Value::LegacySm2Configuration(config) => Ok(Sm2Readout::Legacy(config)),
        _ => Err(unexpected_value()),
    }
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

#[cfg(test)]
mod feature_tests {
    use super::*;
    use canokey::compatibility::DeviceObservations;
    use canokey::SecretBytes;
    use std::collections::VecDeque;
    use std::io;

    struct Script {
        transcript: VecDeque<(Vec<u8>, Vec<u8>)>,
    }
    impl Script {
        fn new(transcript: &[(&[u8], &[u8])]) -> Self {
            Script {
                transcript: transcript
                    .iter()
                    .map(|(c, r)| (c.to_vec(), r.to_vec()))
                    .collect(),
            }
        }
        fn exchange(&mut self, command: &[u8]) -> io::Result<Vec<u8>> {
            let (expected, response) = self
                .transcript
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "unexpected exchange"))?;
            assert_eq!(command, &expected[..], "command differs from transcript");
            Ok(response)
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
    fn pass_slots_typed_read_preserves_unknown_types() {
        // short = STATIC with enter; long = OATH "abc" (fixture from
        // canokey-admin), then an unknown 0x07 type that stays observable.
        let mut script = Script::new(&[
            SELECT,
            VERIFY,
            (
                &[0, 0x43, 0, 0, 0],
                &[0x02, 0x01, 0x01, 0x03, b'a', b'b', b'c', 0x00, 0x90, 0],
            ),
        ]);
        let slots =
            pass_slots(&profile(b"3.1.0"), Some(pin()), &mut |c| script.exchange(c)).unwrap();
        assert!(matches!(
            slots.short,
            PassSlotState::Static { append_enter: true }
        ));
        assert!(
            matches!(&slots.long, PassSlotState::Oath { name, append_enter: false } if name == b"abc")
        );

        let mut script = Script::new(&[
            SELECT,
            VERIFY,
            (&[0, 0x43, 0, 0, 0], &[0x07, 0x00, 0x90, 0]),
        ]);
        let slots =
            pass_slots(&profile(b"3.1.0"), Some(pin()), &mut |c| script.exchange(c)).unwrap();
        assert!(matches!(slots.short, PassSlotState::Unknown(0x07)));
        assert!(matches!(slots.long, PassSlotState::Off));
    }

    #[test]
    fn set_pass_slot_static_golden() {
        let mut script = Script::new(&[
            SELECT,
            VERIFY,
            (b"\0\x44\x01\0\x09\x02\x06secret\x01", &[0x90, 0]),
        ]);
        set_pass_slot(
            &profile(b"3.1.0"),
            PassSlotId::Short,
            PassSlotConfig::Static {
                password: SecretBytes::new(b"secret".to_vec()),
                append_enter: true,
            },
            Some(pin()),
            &mut |c| script.exchange(c),
        )
        .unwrap();
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn configure_patches_only_changed_fields() {
        // Current config has LED on; the patch turns it off, touching nothing
        // else (fixture from canokey-admin's patch test).
        let mut script = Script::new(&[
            SELECT,
            VERIFY,
            (&[0, 0x42, 0, 0, 0], &[1, 0x88, 0, 1, 1, 0xbf, 0x90, 0]),
            (&[0, 0x40, 1, 0], &[0x90, 0]),
        ]);
        configure(
            &profile(b"3.1.0"),
            ConfigurationPatch {
                led_on: Some(false),
                ..Default::default()
            },
            Some(pin()),
            &mut |c| script.exchange(c),
        )
        .unwrap();
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn keyboard_layout_and_extended_reads() {
        let mut script = Script::new(&[SELECT, (&[0, 0x46, 0, 0, 0], &[1, 0x90, 0])]);
        assert_eq!(
            keyboard_layout(&profile(b"3.1.0"), None, &mut |c| script.exchange(c)).unwrap(),
            1
        );

        let mut script = Script::new(&[SELECT, (&[0, 0x41, 0, 0, 0], &[250, 1, 0x90, 0])]);
        let usage = flash_usage(&profile(b"3.1.0"), None, &mut |c| script.exchange(c)).unwrap();
        assert_eq!((usage.used_kib, usage.total_kib), (250, 1));

        let mut response = [0u8; 50];
        response[..6].copy_from_slice(&[2, 0, 0, 0, 1, 0]); // OpenPGP: 256 bytes
        response[48] = 0x90;
        let mut script = Script::new(&[SELECT, (&[0, 0x41, 1, 0, 0], &[])]);
        script.transcript[1].1 = response.to_vec();
        let usage = applet_usage(&profile(b"3.1.0"), &mut |c| script.exchange(c)).unwrap();
        assert_eq!(usage.len(), 8);
        assert_eq!(usage[0].applet_id, 2);
        assert_eq!(usage[0].logical_bytes, 256);

        let mut script = Script::new(&[SELECT, (&[0, 0x31, 2, 0, 0], &[])]);
        script.transcript[1].1 = b"abcdef\x90\x00".to_vec();
        let commit = core_commit(&profile(b"3.1.0"), &mut |c| script.exchange(c)).unwrap();
        assert_eq!(commit, b"abcdef");
    }

    #[test]
    fn sm2_readout_typed_and_legacy() {
        let mut script = Script::new(&[
            SELECT,
            VERIFY,
            (
                &[0, 0x11, 0, 0, 0],
                &[0, 0, 0, 9, 0xff, 0xff, 0xff, 0xca, 0x90, 0],
            ),
        ]);
        let readout =
            sm2_configuration(&profile(b"3.1.0"), Some(pin()), &mut |c| script.exchange(c))
                .unwrap();
        let Sm2Readout::Typed(config) = readout else {
            panic!("3.1 uses the typed layout")
        };
        assert_eq!(config.curve_id, 9);
        assert_eq!(config.algorithm_id, -54);

        // 3.0.x returns the nine-byte legacy layout (enable + native bytes)
        // and carries the legacy explicit Le even on SELECT/VERIFY.
        let mut script = Script::new(&[
            (&[0, 0xa4, 4, 0, 5, 0xf0, 0, 0, 0, 0, 0], &[0x90, 0]),
            (b"    654321 ", &[0x90, 0]),
            (&[0, 0x11, 0, 0, 0], &[1, 0, 0, 0, 9, 0, 0, 0, 0, 0x90, 0]),
        ]);
        let readout =
            sm2_configuration(&profile(b"3.0.0"), Some(pin()), &mut |c| script.exchange(c))
                .unwrap();
        let Sm2Readout::Legacy(config) = readout else {
            panic!("3.0.x uses the legacy layout")
        };
        assert!(config.enabled());
    }

    #[test]
    fn feature_gates_reject_before_any_io() {
        fn zero_io(
            firmware: &[u8],
            run: impl FnOnce(&DeviceProfile) -> Result<(), DriveError<io::Error>>,
        ) -> ErrorKind {
            let error = run(&profile(firmware)).unwrap_err();
            let DriveError::Protocol(error) = error else {
                panic!("expected construction-time protocol error")
            };
            error.kind
        }
        let kind = zero_io(b"2.0.1", |profile| {
            pass_slots(profile, Some(pin()), &mut |_| -> io::Result<Vec<u8>> {
                unreachable!("gate must reject before any exchange")
            })
            .map(|_| ())
        });
        assert_eq!(kind, ErrorKind::UnsupportedFeature);
        let kind = zero_io(b"2.0.1", |profile| {
            sm2_configuration(profile, Some(pin()), &mut |_| -> io::Result<Vec<u8>> {
                unreachable!()
            })
            .map(|_| ())
        });
        assert_eq!(kind, ErrorKind::UnsupportedFeature);
        let kind = zero_io(b"3.0.0", |profile| {
            set_keyboard_return(
                profile,
                true,
                Some(pin()),
                &mut |_| -> io::Result<Vec<u8>> { unreachable!() },
            )
        });
        assert_eq!(kind, ErrorKind::UnsupportedFeature);
        let kind = zero_io(b"3.0.1", |profile| {
            applet_usage(profile, &mut |_| -> io::Result<Vec<u8>> { unreachable!() }).map(|_| ())
        });
        assert_eq!(kind, ErrorKind::UnsupportedFeature);
    }
}
