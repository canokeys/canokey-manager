//! Typed wrappers around `canokey::openpgp` operations.
//!
//! Every operation re-SELECTs the OpenPGP applet and verifies at most one
//! explicit password reference (PW1-sign/PW1-other/PW3 stay distinct);
//! nothing here caches login state or retries credentials. Data-object reads
//! preserve the firmware's historical framing; use the profile-aware
//! [`read_application_data`] parser rather than interpreting raw bytes.
//!
//! Legacy dialects (bare vs wrapped DO contents, explicit Le, Ed25519
//! trailing-byte quirk) are libcanokey's job via the profile.

use crate::{execute, DriveError, Exchange};
use canokey::openpgp::{self, Outcome, Request};
use canokey::{DeviceProfile, OperationOptions, SecretBytes};

pub use canokey::openpgp::{Access, DataWrite, TouchPolicy};
pub use canokey::openpgp::{
    Algorithm, ApplicationData, CardholderData, Password, PasswordReference, PasswordStatus,
    PinStatus, PrivateKey, PublicKey, Slot,
};

fn run<E>(
    profile: &DeviceProfile,
    request: Request,
    access: Option<Access>,
    exchange: &mut Exchange<'_, E>,
) -> Result<Outcome, DriveError<E>> {
    let operation = openpgp::operation(profile, request, access, OperationOptions::default())
        .map_err(DriveError::from)?;
    execute(operation, exchange)
}

fn unexpected<E>() -> DriveError<E> {
    DriveError::Protocol(
        canokey::Error::new(canokey::ErrorKind::InvalidResponse).at(canokey::Phase::Parsing),
    )
}

/// Read a data object by its complete two-byte tag, preserving the original
/// response framing.
pub fn read_data<E>(
    profile: &DeviceProfile,
    tag: u16,
    exchange: &mut Exchange<'_, E>,
) -> Result<SecretBytes, DriveError<E>> {
    match run(profile, Request::ReadData(tag), None, exchange)? {
        Outcome::Bytes(bytes) => Ok(bytes),
        _ => Err(unexpected()),
    }
}

/// Read and parse the application-related data DO 6E (AID, PW status,
/// fingerprints, generation times, algorithm attributes, UIF) using the
/// profile's framing rule.
pub fn read_application_data<E>(
    profile: &DeviceProfile,
    exchange: &mut Exchange<'_, E>,
) -> Result<ApplicationData, DriveError<E>> {
    let bytes = read_data(profile, 0x6e, exchange)?;
    ApplicationData::parse_with_profile(profile, bytes.as_bytes(), 4096).map_err(DriveError::from)
}

/// Read and parse the cardholder data DO 65.
pub fn read_cardholder_data<E>(
    profile: &DeviceProfile,
    exchange: &mut Exchange<'_, E>,
) -> Result<CardholderData, DriveError<E>> {
    let bytes = read_data(profile, 0x65, exchange)?;
    CardholderData::parse_with_profile(profile, bytes.as_bytes(), 4096).map_err(DriveError::from)
}

/// Empty-VERIFY observations for one reference. Never an authorization token;
/// on pinned firmware this may clear the selected PW1 mode.
pub fn pin_status<E>(
    profile: &DeviceProfile,
    reference: PasswordReference,
    exchange: &mut Exchange<'_, E>,
) -> Result<PinStatus, DriveError<E>> {
    match run(profile, Request::PinStatus(reference), None, exchange)? {
        Outcome::PinStatus(status) => Ok(status),
        _ => Err(unexpected()),
    }
}

/// Perform only an explicit verification of one password reference.
pub fn verify<E>(
    profile: &DeviceProfile,
    reference: PasswordReference,
    password: Password,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), DriveError<E>> {
    run(
        profile,
        Request::Verify,
        Some(Access {
            reference,
            password,
        }),
        exchange,
    )?;
    Ok(())
}

/// Clear authorization for one reference.
pub fn logout<E>(
    profile: &DeviceProfile,
    reference: PasswordReference,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), DriveError<E>> {
    run(profile, Request::Logout(reference), None, exchange)?;
    Ok(())
}

/// Change PW1 (sign reference) or PW3; old and new are sent together without
/// an extra VERIFY.
pub fn change_password<E>(
    profile: &DeviceProfile,
    reference: PasswordReference,
    old: Password,
    new: Password,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), DriveError<E>> {
    run(
        profile,
        Request::ChangePassword {
            reference,
            old,
            new,
        },
        None,
        exchange,
    )?;
    Ok(())
}

/// Reset PW1 with explicit PW3 access (does not change PW3).
pub fn unblock_with_admin<E>(
    profile: &DeviceProfile,
    new_pin: Password,
    admin: Password,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), DriveError<E>> {
    run(
        profile,
        Request::UnblockWithAdmin(new_pin),
        Some(Access {
            reference: PasswordReference::Pw3,
            password: admin,
        }),
        exchange,
    )?;
    Ok(())
}

/// Reset PW1 using the reset code; no password verification is performed.
pub fn unblock_with_code<E>(
    profile: &DeviceProfile,
    code: Password,
    new_pin: Password,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), DriveError<E>> {
    run(
        profile,
        Request::UnblockWithCode { code, new: new_pin },
        None,
        exchange,
    )?;
    Ok(())
}

/// Set or clear the reset code (PW3 access; `None` clears; a present code is
/// 8..64 bytes).
pub fn set_reset_code<E>(
    profile: &DeviceProfile,
    code: Option<Password>,
    admin: Password,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), DriveError<E>> {
    write_data(profile, DataWrite::ResetCode(code), admin, exchange)
}

/// Set PW1/reset-code/PW3 retry limits (1..=15 each), resetting PW1 and PW3
/// to the firmware defaults. Requires 3.1 firmware evidence and PW3 access.
pub fn reset_retries<E>(
    profile: &DeviceProfile,
    retries: [u8; 3],
    admin: Password,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), DriveError<E>> {
    run(
        profile,
        Request::ResetRetries(retries),
        Some(Access {
            reference: PasswordReference::Pw3,
            password: admin,
        }),
        exchange,
    )?;
    Ok(())
}

/// Write one typed data-object field after PW3 verification.
pub fn write_data<E>(
    profile: &DeviceProfile,
    value: DataWrite,
    admin: Password,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), DriveError<E>> {
    run(
        profile,
        Request::WriteData(value),
        Some(Access {
            reference: PasswordReference::Pw3,
            password: admin,
        }),
        exchange,
    )?;
    Ok(())
}

/// Set the signature-PIN policy: `true` allows one PW1-sign verification to
/// authorize multiple signatures.
pub fn set_signature_policy<E>(
    profile: &DeviceProfile,
    reuse: bool,
    admin: Password,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), DriveError<E>> {
    write_data(
        profile,
        DataWrite::ReuseSignaturePin(reuse),
        admin,
        exchange,
    )
}

/// Set a slot's touch policy (UIF; requires 1.5.2+ evidence). `Permanent`
/// cannot be downgraded by ordinary writes.
pub fn set_touch_policy<E>(
    profile: &DeviceProfile,
    slot: Slot,
    policy: TouchPolicy,
    admin: Password,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), DriveError<E>> {
    write_data(
        profile,
        DataWrite::TouchPolicy(slot, policy),
        admin,
        exchange,
    )
}

/// Set the card-wide touch cache duration in seconds (requires 1.5.2+
/// evidence, same capability gate as [`set_touch_policy`]); `0` disables
/// caching.
pub fn set_touch_cache_time<E>(
    profile: &DeviceProfile,
    seconds: u8,
    admin: Password,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), DriveError<E>> {
    write_data(profile, DataWrite::TouchCacheTime(seconds), admin, exchange)
}

/// Read the public key for a slot's currently configured algorithm.
pub fn read_public_key<E>(
    profile: &DeviceProfile,
    slot: Slot,
    exchange: &mut Exchange<'_, E>,
) -> Result<PublicKey, DriveError<E>> {
    match run(profile, Request::ReadPublicKey(slot), None, exchange)? {
        Outcome::PublicKey(key) => Ok(key),
        _ => Err(unexpected()),
    }
}

/// Generate/replace a key using the slot's existing algorithm attributes
/// (PW3 access). Change attributes explicitly with [`set_algorithm`] first;
/// doing so discards the old key.
pub fn generate_key<E>(
    profile: &DeviceProfile,
    slot: Slot,
    admin: Password,
    exchange: &mut Exchange<'_, E>,
) -> Result<PublicKey, DriveError<E>> {
    match run(
        profile,
        Request::GenerateKey(slot),
        Some(Access {
            reference: PasswordReference::Pw3,
            password: admin,
        }),
        exchange,
    )? {
        Outcome::PublicKey(key) => Ok(key),
        _ => Err(unexpected()),
    }
}

/// Replace a slot's algorithm attributes (PW3 access). Firmware discards the
/// slot's key when the attributes change; rewriting identical attributes is a
/// no-op, so this cannot be used to delete a key.
pub fn set_algorithm<E>(
    profile: &DeviceProfile,
    slot: Slot,
    algorithm: Algorithm,
    admin: Password,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), DriveError<E>> {
    write_data(
        profile,
        DataWrite::Algorithm(slot, algorithm),
        admin,
        exchange,
    )
}

/// Import a private key into a slot whose attributes already configure the
/// key's algorithm (PW3 access); a mismatch fails before any mutation.
pub fn import_key<E>(
    profile: &DeviceProfile,
    slot: Slot,
    algorithm: Algorithm,
    key: PrivateKey,
    admin: Password,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), DriveError<E>> {
    run(
        profile,
        Request::ImportKey {
            slot,
            algorithm,
            key,
        },
        Some(Access {
            reference: PasswordReference::Pw3,
            password: admin,
        }),
        exchange,
    )?;
    Ok(())
}

/// Read a slot's certificate (opaque bytes; no X.509 validation).
pub fn read_certificate<E>(
    profile: &DeviceProfile,
    slot: Slot,
    exchange: &mut Exchange<'_, E>,
) -> Result<Vec<u8>, DriveError<E>> {
    match run(profile, Request::ReadCertificate(slot), None, exchange)? {
        Outcome::Bytes(bytes) => Ok(bytes.as_bytes().to_vec()),
        _ => Err(unexpected()),
    }
}

/// Write a slot's certificate (PW3 access; at most 1152 bytes). An empty
/// payload clears it: CanoKey has no separate certificate-deletion command.
pub fn write_certificate<E>(
    profile: &DeviceProfile,
    slot: Slot,
    der: Vec<u8>,
    admin: Password,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), DriveError<E>> {
    run(
        profile,
        Request::WriteCertificate(slot, SecretBytes::new(der)),
        Some(Access {
            reference: PasswordReference::Pw3,
            password: admin,
        }),
        exchange,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use canokey::compatibility::DeviceObservations;
    use canokey::tlv::{Tag, TlvWriter};
    use canokey::{ErrorKind, SecretReference};
    use std::collections::VecDeque;
    use std::io;

    /// Transcript-driven exchange, mirroring the probe tests in `lib.rs`.
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
            assert_eq!(command, expected, "command differs from transcript");
            Ok(response)
        }
    }

    fn wrap(tag: &[u8], value: &[u8]) -> Vec<u8> {
        let mut w = TlvWriter::new(4096);
        w.push(Tag::from_bytes(tag).unwrap(), value).unwrap();
        w.into_bytes().as_bytes().to_vec()
    }

    fn profile(version: &str) -> DeviceProfile {
        DeviceProfile::from_observations(DeviceObservations::new(version.as_bytes().to_vec()))
            .unwrap()
    }

    const SELECT: &[u8] = &[0, 0xa4, 4, 0, 6, 0xd2, 0x76, 0, 1, 0x24, 1];
    const SELECT_LE: &[u8] = &[0, 0xa4, 4, 0, 6, 0xd2, 0x76, 0, 1, 0x24, 1, 0];
    const OK: &[u8] = &[0x90, 0];
    const GET_6E: &[u8] = &[0, 0xca, 0, 0x6e, 0];
    const VERIFY_PW3: &[u8] = b"\0\x20\0\x83\x0887654321";

    fn pw3() -> Password {
        Password::from_bytes(b"87654321").unwrap()
    }

    /// Modern wrapped 6E fixture: AID, discretionary PW status/fingerprints/
    /// times/UIF, and RSA-2048 attributes in C1.
    fn application_data(attrs_c1: &[u8]) -> Vec<u8> {
        let mut discretionary = wrap(&[0xc4], &[1, 64, 64, 64, 3, 2, 1]);
        let mut fingerprints = vec![0x11; 20];
        fingerprints.extend([0x22; 20]);
        fingerprints.extend([0; 20]);
        discretionary.extend(wrap(&[0xc5], &fingerprints));
        discretionary.extend(wrap(&[0xcd], &[0, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0, 0]));
        discretionary.extend(wrap(&[0xd6], &[1, 0x20]));
        discretionary.extend(wrap(&[0xc1], attrs_c1));
        let mut outer = wrap(&[0x4f], &[42; 16]);
        outer.extend(wrap(&[0x73], &discretionary));
        let mut bytes = wrap(&[0x6e], &outer);
        bytes.extend(OK);
        bytes
    }

    #[test]
    fn select_and_application_data_read() {
        let mut script = Script::new(&[
            (SELECT, OK),
            (GET_6E, &[]), // response filled below
        ]);
        let response = application_data(&[1, 8, 0, 0, 32, 2]);
        script.transcript[1].1 = response;
        let app = read_application_data(&profile("3.1.0"), &mut |c| script.exchange(c)).unwrap();
        assert_eq!(app.aid().unwrap(), Some([42; 16]));
        let status = app.password_status().unwrap().unwrap();
        assert_eq!(status.signature_policy, 1);
        assert_eq!(status.retries, [3, 2, 1]);
        assert_eq!(app.fingerprint(Slot::Signature).unwrap(), Some([0x11; 20]));
        assert_eq!(app.fingerprint(Slot::Decryption).unwrap(), Some([0x22; 20]));
        assert_eq!(
            app.fingerprint(Slot::Authentication).unwrap(),
            Some([0; 20])
        );
        assert_eq!(app.generation_time(Slot::Signature).unwrap(), Some(42));
        assert_eq!(app.touch_policy(Slot::Signature).unwrap(), Some([1, 0x20]));
        assert_eq!(
            app.algorithm_attributes(Slot::Signature).unwrap(),
            Some(&[1, 8, 0, 0, 32, 2][..])
        );
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn legacy_13_bare_application_data() {
        // 1.3: no 6E wrapper, explicit Le everywhere (firmware reserves two
        // length bytes even for short constructed values).
        let attrs = &[0x13, 0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7];
        let mut v = vec![
            0x73,
            0x82,
            0,
            (attrs.len() + 2) as u8,
            0xc1,
            attrs.len() as u8,
        ];
        v.extend(attrs);
        v.extend(OK);
        let mut script = Script::new(&[(SELECT_LE, OK), (GET_6E, &[])]);
        script.transcript[1].1 = v;
        let app = read_application_data(&profile("1.3"), &mut |c| script.exchange(c)).unwrap();
        assert_eq!(
            app.algorithm_attributes(Slot::Signature).unwrap(),
            Some(&attrs[..])
        );
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn change_pw3_and_pw1_transcripts() {
        let mut script = Script::new(&[(SELECT, OK), (b"\0\x24\0\x83\x1087654321newadmin", OK)]);
        change_password(
            &profile("3.1.0"),
            PasswordReference::Pw3,
            pw3(),
            Password::from_bytes(b"newadmin").unwrap(),
            &mut |c| script.exchange(c),
        )
        .unwrap();
        let mut script = Script::new(&[(SELECT, OK), (b"\0\x24\0\x81\x0c123456654321", OK)]);
        change_password(
            &profile("3.1.0"),
            PasswordReference::Pw1Sign,
            Password::from_bytes(b"123456").unwrap(),
            Password::from_bytes(b"654321").unwrap(),
            &mut |c| script.exchange(c),
        )
        .unwrap();
    }

    #[test]
    fn pin_status_and_wrong_password_typing() {
        let mut script = Script::new(&[(SELECT, OK), (b"\0\x20\0\x82", &[0x63, 0xc0])]);
        let status = pin_status(&profile("3.1.0"), PasswordReference::Pw1Other, &mut |c| {
            script.exchange(c)
        })
        .unwrap();
        assert!(status.blocked);
        assert_eq!(status.retries_remaining, Some(0));
        // 6982 at VERIFY is authentication failure without retry information.
        let mut script = Script::new(&[(SELECT, OK), (VERIFY_PW3, &[0x69, 0x82])]);
        let error = verify(&profile("3.1.0"), PasswordReference::Pw3, pw3(), &mut |c| {
            script.exchange(c)
        })
        .unwrap_err();
        match error {
            DriveError::Protocol(error) => {
                assert_eq!(error.kind, ErrorKind::AuthenticationFailed);
                assert_eq!(error.reference, Some(SecretReference::Pw3));
                assert_eq!(error.retries_remaining, None);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn ed25519_generate_transcript() {
        let attr = [0x16, 0x2b, 6, 1, 4, 1, 0xda, 0x47, 15, 1];
        let mut public = wrap(&[0x7f, 0x49], &wrap(&[0x86], &[7; 32]));
        public.extend(OK);
        let mut script = Script::new(&[
            (SELECT, OK),
            (GET_6E, &[]),
            (VERIFY_PW3, OK),
            (&[0, 0x47, 0x80, 0, 2, 0xb6, 0], &[]),
        ]);
        let mut attrs = wrap(&[0x6e], &wrap(&[0x73], &wrap(&[0xc1], &attr)));
        attrs.extend(OK);
        script.transcript[1].1 = attrs;
        script.transcript[3].1 = public;
        let key = generate_key(&profile("3.1.0"), Slot::Signature, pw3(), &mut |c| {
            script.exchange(c)
        })
        .unwrap();
        assert_eq!(key.algorithm(), Algorithm::Ed25519);
        assert_eq!(key.to_spki_der().unwrap().len(), 44);
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn rsa_crt_import_canoframing() {
        // The CanoKey framing: 4D { b6 00, 7F48 template, 5F48 data } with
        // 91 exponent / 92 p / 93 q / 94 qInv / 95 dP / 96 dQ, chained.
        let component = |seed: u8| [seed; 128];
        let key = PrivateKey::Rsa {
            exponent: [0, 1, 0, 1],
            p: SecretBytes::new(component(1).to_vec()),
            q: SecretBytes::new(component(2).to_vec()),
            q_inverse: SecretBytes::new(component(3).to_vec()),
            d_p: SecretBytes::new(component(4).to_vec()),
            d_q: SecretBytes::new(component(5).to_vec()),
        };
        // Build the expected import body independently of the library.
        // Template carries tag+length only (91 04, 92..96 81 80); the data
        // starts with the four-byte exponent, then p, q, qInv, dP, dQ.
        let mut template = vec![0x91, 4];
        for tag in 0x92..=0x96 {
            template.extend([tag, 0x81, 128]);
        }
        let mut data = vec![0, 1, 0, 1];
        for seed in 1..=5 {
            data.extend([seed; 128]);
        }
        let mut body = vec![0xb6, 0];
        body.extend(wrap(&[0x7f, 0x48], &template));
        body.extend(wrap(&[0x5f, 0x48], &data));
        let payload = wrap(&[0x4d], &body);
        // Expected chained frames: CLA 10 until the final CLA 00 fragment.
        let mut frames: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (SELECT.to_vec(), OK.to_vec()),
            (GET_6E.to_vec(), application_data(&[1, 8, 0, 0, 32, 2])),
            (VERIFY_PW3.to_vec(), OK.to_vec()),
        ];
        let mut chunks = payload.chunks(255).peekable();
        while let Some(chunk) = chunks.next() {
            let cla = if chunks.peek().is_some() { 0x10 } else { 0x00 };
            let mut frame = vec![cla, 0xdb, 0x3f, 0xff, chunk.len() as u8];
            frame.extend(chunk);
            frames.push((frame, OK.to_vec()));
        }
        let mut script = Script {
            transcript: frames.into(),
        };
        import_key(
            &profile("3.1.0"),
            Slot::Signature,
            Algorithm::Rsa2048,
            key,
            pw3(),
            &mut |c| script.exchange(c),
        )
        .unwrap();
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn fingerprint_and_timestamp_writes() {
        let mut script = Script::new(&[
            (SELECT, OK),
            (VERIFY_PW3, OK),
            (&[0, 0xda, 0, 0xc7, 20], OK),
        ]);
        let mut expected_put = vec![0, 0xda, 0, 0xc7, 20];
        expected_put.extend([0x42; 20]);
        script.transcript[2].0 = expected_put;
        write_data(
            &profile("3.1.0"),
            DataWrite::Fingerprint(Slot::Signature, [0x42; 20]),
            pw3(),
            &mut |c| script.exchange(c),
        )
        .unwrap();
        let mut script = Script::new(&[
            (SELECT, OK),
            (VERIFY_PW3, OK),
            (&[0, 0xda, 0, 0xce, 4, 0x01, 0x02, 0x03, 0x04], OK),
        ]);
        write_data(
            &profile("3.1.0"),
            DataWrite::GenerationTime(Slot::Signature, 0x01020304),
            pw3(),
            &mut |c| script.exchange(c),
        )
        .unwrap();
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn certificate_roundtrip_with_occurrence_selection() {
        let cert = [0x30, 0x03, 0x02, 0x01, 0x42];
        // Write: SELECT, PW3, SELECT DATA (occurrence 2), PUT DATA.
        let mut put = vec![0, 0xda, 0x7f, 0x21, 5];
        put.extend(cert);
        let mut script = Script::new(&[
            (SELECT, OK),
            (VERIFY_PW3, OK),
            (&[0, 0xa5, 2, 4, 6, 0x60, 4, 0x5c, 2, 0x7f, 0x21], OK),
            (&[], OK),
        ]);
        script.transcript[3].0 = put;
        write_certificate(
            &profile("3.1.0"),
            Slot::Authentication,
            cert.to_vec(),
            pw3(),
            &mut |c| script.exchange(c),
        )
        .unwrap();
        // Read: SELECT, SELECT DATA, GET DATA 7F21.
        let mut response = cert.to_vec();
        response.extend(OK);
        let mut script = Script::new(&[
            (SELECT, OK),
            (&[0, 0xa5, 2, 4, 6, 0x60, 4, 0x5c, 2, 0x7f, 0x21], OK),
            (&[0, 0xca, 0x7f, 0x21, 0], &[]),
        ]);
        script.transcript[2].1 = response;
        let read = read_certificate(&profile("3.1.0"), Slot::Authentication, &mut |c| {
            script.exchange(c)
        })
        .unwrap();
        assert_eq!(read, cert);
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn cardholder_and_touch_cache_write_transcripts() {
        // Name (5B), login (5E), language (5F2D), sex (5F35) and URL (5F50)
        // writes each VERIFY PW3 then PUT DATA (fixtures from canokey-openpgp).
        let mut script = Script::new(&[
            (SELECT, OK),
            (VERIFY_PW3, OK),
            (b"\0\xda\0\x5b\x05Alice", OK),
        ]);
        write_data(
            &profile("3.1.0"),
            DataWrite::Name(b"Alice".to_vec()),
            pw3(),
            &mut |c| script.exchange(c),
        )
        .unwrap();
        assert!(script.transcript.is_empty());

        let mut script = Script::new(&[
            (SELECT, OK),
            (VERIFY_PW3, OK),
            (b"\0\xda\0\x5e\x05alice", OK),
        ]);
        write_data(
            &profile("3.1.0"),
            DataWrite::Login(SecretBytes::new(b"alice".to_vec())),
            pw3(),
            &mut |c| script.exchange(c),
        )
        .unwrap();
        assert!(script.transcript.is_empty());

        let mut script = Script::new(&[
            (SELECT, OK),
            (VERIFY_PW3, OK),
            (b"\0\xda\x5f\x2d\x02en", OK),
        ]);
        write_data(
            &profile("3.1.0"),
            DataWrite::Language(b"en".to_vec()),
            pw3(),
            &mut |c| script.exchange(c),
        )
        .unwrap();
        assert!(script.transcript.is_empty());

        let mut script = Script::new(&[
            (SELECT, OK),
            (VERIFY_PW3, OK),
            (&[0, 0xda, 0x5f, 0x35, 1, b'2'], OK),
        ]);
        write_data(&profile("3.1.0"), DataWrite::Sex(b'2'), pw3(), &mut |c| {
            script.exchange(c)
        })
        .unwrap();
        assert!(script.transcript.is_empty());

        let mut script = Script::new(&[
            (SELECT, OK),
            (VERIFY_PW3, OK),
            (b"\0\xda\x5f\x50\x17https://example.invalid", OK),
        ]);
        write_data(
            &profile("3.1.0"),
            DataWrite::Url(b"https://example.invalid".to_vec()),
            pw3(),
            &mut |c| script.exchange(c),
        )
        .unwrap();
        assert!(script.transcript.is_empty());

        // The card-wide touch cache duration lives in DO 0102 (UIF family).
        let mut script = Script::new(&[
            (SELECT, OK),
            (VERIFY_PW3, OK),
            (&[0, 0xda, 0x01, 0x02, 1, 15], OK),
        ]);
        set_touch_cache_time(&profile("3.1.0"), 15, pw3(), &mut |c| script.exchange(c)).unwrap();
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn cardholder_data_read_transcript() {
        // Modern wrapped 65 fixture: name plus language and sex.
        let mut inner = wrap(&[0x5b], b"Alice");
        inner.extend(wrap(&[0x5f, 0x2d], b"en"));
        inner.extend(wrap(&[0x5f, 0x35], b"1"));
        let mut response = wrap(&[0x65], &inner);
        response.extend(OK);
        let mut script = Script::new(&[(SELECT, OK), (&[0, 0xca, 0, 0x65, 0], &[])]);
        script.transcript[1].1 = response;
        let data = read_cardholder_data(&profile("3.1.0"), &mut |c| script.exchange(c)).unwrap();
        assert_eq!(data.name().unwrap(), Some(&b"Alice"[..]));
        assert_eq!(data.language().unwrap(), Some(&b"en"[..]));
        assert_eq!(data.sex().unwrap(), Some(&b"1"[..]));
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn read_public_key_transcript() {
        // Same fixture family as the generate test, with the 0x81 read P1.
        let attr = [0x16, 0x2b, 6, 1, 4, 1, 0xda, 0x47, 15, 1];
        let mut public = wrap(&[0x7f, 0x49], &wrap(&[0x86], &[7; 32]));
        public.extend(OK);
        let mut script = Script::new(&[
            (SELECT, OK),
            (GET_6E, &[]),
            (&[0, 0x47, 0x81, 0, 2, 0xb6, 0], &[]),
        ]);
        let mut attrs = wrap(&[0x6e], &wrap(&[0x73], &wrap(&[0xc1], &attr)));
        attrs.extend(OK);
        script.transcript[1].1 = attrs;
        script.transcript[2].1 = public;
        let key = read_public_key(&profile("3.1.0"), Slot::Signature, &mut |c| {
            script.exchange(c)
        })
        .unwrap();
        assert_eq!(key.algorithm(), Algorithm::Ed25519);
        assert_eq!(key.to_spki_der().unwrap().len(), 44);
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn capability_gates_reject_before_any_io() {
        // Retry reset requires 3.1 evidence; UIF requires 1.5.2.
        for (version, pw3_gated) in [("2.0.0", true), ("1.3", false)] {
            let mut calls = 0;
            let result = if pw3_gated {
                reset_retries(&profile(version), [3, 3, 3], pw3(), &mut |_| -> io::Result<
                    Vec<u8>,
                > {
                    calls += 1;
                    unreachable!("capability gate must reject before any exchange")
                })
            } else {
                set_touch_policy(
                    &profile(version),
                    Slot::Signature,
                    TouchPolicy::On,
                    pw3(),
                    &mut |_| -> io::Result<Vec<u8>> {
                        calls += 1;
                        unreachable!("capability gate must reject before any exchange")
                    },
                )
            };
            match result.unwrap_err() {
                DriveError::Protocol(error) => {
                    assert_eq!(error.kind, ErrorKind::UnsupportedFeature)
                }
                DriveError::Transport(_) => panic!("no transport exchange should have happened"),
            }
            assert_eq!(calls, 0);
        }
    }

    #[test]
    fn openpgp_key_conversion_pads_crt_components() {
        // A 1024-bit RSA key parsed from PKCS#8 converts to OpenPGP material
        // with exact half-modulus component widths.
        let private = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 1024).unwrap();
        let doc = rsa::pkcs8::EncodePrivateKey::to_pkcs8_der(&private).unwrap();
        let imported = crate::keys::parse_private_key(doc.as_bytes(), None).unwrap();
        assert_eq!(imported.algorithm, Algorithm::Rsa1024);
        let key = imported.openpgp_key().unwrap();
        let PrivateKey::Rsa {
            exponent,
            p,
            q,
            q_inverse,
            d_p,
            d_q,
        } = &key
        else {
            panic!("expected RSA")
        };
        assert_eq!(exponent, &[0, 1, 0, 1]);
        for component in [p, q, q_inverse, d_p, d_q] {
            assert_eq!(component.as_bytes().len(), 64);
        }
        let p256 = p256::SecretKey::random(&mut rand_core::OsRng);
        let doc = p256::pkcs8::EncodePrivateKey::to_pkcs8_der(&p256).unwrap();
        let imported = crate::keys::parse_private_key(doc.as_bytes(), None).unwrap();
        let PrivateKey::Ec(scalar) = imported.openpgp_key().unwrap() else {
            panic!("expected EC")
        };
        assert_eq!(scalar.as_bytes(), p256.to_bytes().as_slice());
    }
}
