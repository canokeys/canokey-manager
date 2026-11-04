//! Inspect PIV slot contents and require explicit consent before replacement.
use super::{
    certificate_slot_name, describe_piv, hex_encode, into_metadata_fields, CliResult, KeyReference,
};
use canokey::{DeviceProfile, ErrorKind, Phase};
use ckman_core::piv::{
    self, CertificateReference, KeyOrigin, KnownOrUnknown, MetadataReference, Slot,
};
use ckman_core::x509::HashAlgorithm;
use ckman_core::{DriveError, Exchange};
use std::io;

#[derive(Clone, Copy)]
pub(super) enum CertificateChange {
    Replace,
    Delete,
}

fn missing(error: &piv::PivError<io::Error>) -> bool {
    matches!(error, piv::PivError::Drive(DriveError::Protocol(error))
        if error.kind == ErrorKind::NotFound && error.phase == Phase::Command)
}
fn unavailable(error: &piv::PivError<io::Error>) -> bool {
    matches!(error, piv::PivError::Drive(DriveError::Protocol(error))
        if matches!(error.kind, ErrorKind::UnsupportedFeature | ErrorKind::CapabilityUnknown)
            && matches!(error.phase, Phase::Construction | Phase::Command))
}

fn approve(prompt: &str, ask: &mut impl FnMut(&str) -> CliResult<bool>) -> CliResult<()> {
    if ask(prompt)? {
        Ok(())
    } else {
        Err("Cancelled; no PIV data was changed.".into())
    }
}

fn certificate_summary(bytes: &[u8]) -> String {
    let certificate = piv::Certificate::from_object(bytes, 16 * 1024);
    if let Ok(certificate) = certificate {
        if let Ok(info) = canokey::x509::parse_der(certificate.der(), Default::default()) {
            return format!(
                "Subject: {}\nSHA-256: {}",
                info.subject.display,
                hex_encode(&info.sha256_fingerprint())
            );
        }
    }
    format!(
        "Unparseable certificate object ({} bytes); object SHA-256: {}",
        bytes.len(),
        hex_encode(&HashAlgorithm::Sha256.hash(bytes))
    )
}

pub(super) fn key(
    profile: &DeviceProfile,
    reference: KeyReference,
    exchange: &mut Exchange<'_, io::Error>,
    ask: &mut impl FnMut(&str) -> CliResult<bool>,
) -> CliResult<()> {
    let metadata = match reference {
        KeyReference::Key(slot) => piv::metadata(
            profile,
            MetadataReference::Key(slot),
            piv::Access::None,
            exchange,
        )
        .map(into_metadata_fields),
        KeyReference::Attestation => piv::attestation_metadata(profile, exchange),
    };
    let status = match metadata {
        Ok(fields) => {
            if fields.origin == Some(KnownOrUnknown::Known(KeyOrigin::NotPresent))
                && fields.public_key.is_none()
            {
                None
            } else {
                let fingerprint = fields
                    .public_key
                    .as_ref()
                    .and_then(|key| key.to_spki_der().ok())
                    .map(|spki| {
                        format!(
                            "\nExisting public key SHA-256: {}",
                            hex_encode(&HashAlgorithm::Sha256.hash(&spki))
                        )
                    })
                    .unwrap_or_default();
                Some(format!(
                    "Slot {} already contains a private key.{fingerprint}",
                    reference.name()
                ))
            }
        }
        Err(error) if missing(&error) => None,
        Err(error) if reference != KeyReference::Attestation && unavailable(&error) => {
            Some(format!(
                "Cannot determine whether slot {} contains a private key on this firmware.",
                reference.name()
            ))
        }
        Err(error) => return Err(describe_piv(&error).into()),
    };
    // A certificate-only slot is also occupied: installing a new key can leave
    // the retained certificate inconsistent, so show that content as well.
    let certificate = match piv::read_certificate_object(profile, reference.certificate(), exchange)
    {
        Ok(data) => Some(certificate_summary(data.as_bytes())),
        Err(error) if missing(&error) => None,
        Err(error) => return Err(describe_piv(&error).into()),
    };
    if status.is_none() && certificate.is_none() {
        return Ok(());
    }
    let mut prompt = status
        .unwrap_or_else(|| format!("Slot {} already contains a certificate.", reference.name()));
    if let Some(summary) = certificate {
        prompt.push_str(&format!(
            "\nExisting certificate (retained by this operation):\n{summary}"
        ));
    }
    if reference == KeyReference::Attestation {
        prompt.push_str("\nReplacing the F9 signer changes attestation identity and trust. The existing certificate will be retained and may no longer match.");
    }
    prompt.push_str("\nReplacing a private key is irreversible. A retained certificate may no longer match. Replace this slot's private key?");
    approve(&prompt, ask)
}

/// Complete all preflight checks before the caller authenticates or writes.
pub(super) fn keys(
    profile: &DeviceProfile,
    slots: &[Slot],
    exchange: &mut Exchange<'_, io::Error>,
    ask: &mut impl FnMut(&str) -> CliResult<bool>,
) -> CliResult<()> {
    for slot in slots {
        key(profile, (*slot).into(), exchange, ask)?;
    }
    Ok(())
}

pub(super) fn certificate(
    profile: &DeviceProfile,
    reference: CertificateReference,
    change: CertificateChange,
    exchange: &mut Exchange<'_, io::Error>,
    ask: &mut impl FnMut(&str) -> CliResult<bool>,
) -> CliResult<()> {
    let existing = match piv::read_certificate_object(profile, reference, exchange) {
        Ok(data) => data,
        Err(error) if missing(&error) => return Ok(()),
        Err(error) => return Err(describe_piv(&error).into()),
    };
    let action = match change {
        CertificateChange::Replace => "Replace",
        CertificateChange::Delete => "Delete",
    };
    let mut prompt = format!(
        "Slot {} already contains a certificate.\n{}",
        certificate_slot_name(reference),
        certificate_summary(existing.as_bytes())
    );
    if reference == CertificateReference::Attestation {
        prompt
            .push_str("\nChanging the F9 certificate affects attestation verification and trust.");
    }
    prompt.push_str(&format!("\n{action} this certificate?"));
    approve(&prompt, ask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use canokey::compatibility::{DeviceObservations, PivApplicationVersion};
    use std::collections::VecDeque;

    const SELECT: &[u8] = &[0, 0xa4, 4, 0, 5, 0xa0, 0, 0, 3, 8];
    const OK: &[u8] = &[0x90, 0];
    const METADATA: &[u8] = &[0, 0xf7, 0, 0x9a, 0];
    const CERTIFICATE: &[u8] = &[0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 5, 0];
    const MISSING: &[u8] = &[0x6a, 0x82];
    const MALFORMED_CERT: &[u8] = &[0x53, 3, 0x70, 1, 0xff, 0x90, 0];

    fn profile(version: &str) -> DeviceProfile {
        let mut observations = DeviceObservations::new(version.as_bytes().to_vec());
        observations.piv_version = Some(PivApplicationVersion([5, 7, 0]));
        DeviceProfile::from_observations(observations).unwrap()
    }

    struct Script(VecDeque<(Vec<u8>, Vec<u8>)>);
    impl Script {
        fn new(pairs: &[(&[u8], &[u8])]) -> Self {
            Self(
                pairs
                    .iter()
                    .map(|(c, r)| (c.to_vec(), r.to_vec()))
                    .collect(),
            )
        }
        fn exchange(&mut self, command: &[u8]) -> io::Result<Vec<u8>> {
            let (expected, response) = self
                .0
                .pop_front()
                .expect("unexpected APDU (possibly a write)");
            assert_eq!(command, expected);
            Ok(response)
        }
    }

    #[test]
    fn firmware_310_batch_decline_finishes_preflight_without_any_writes() {
        let mut script = Script::new(&[
            (SELECT, OK),
            (METADATA, &[3, 1, 1, 0x90, 0]),
            (SELECT, OK),
            (CERTIFICATE, MISSING),
            (SELECT, OK),
            (&[0, 0xf7, 0, 0x9c, 0], &[3, 1, 1, 0x90, 0]),
            (SELECT, OK),
            (
                &[0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 0xa, 0],
                MISSING,
            ),
        ]);
        let mut prompts = 0;
        assert!(keys(
            &profile("3.1.0"),
            &[Slot::Authentication, Slot::Signature],
            &mut |c| script.exchange(c),
            &mut |_| {
                prompts += 1;
                Ok(prompts == 1)
            }
        )
        .is_err());
        assert_eq!(prompts, 2);
        assert!(script.0.is_empty());
    }

    #[test]
    fn certificate_summary_displays_subject_and_der_fingerprint() {
        use canokey::tlv::{Tag, TlvWriter};
        let der = include_bytes!("../../../../ckman-core/tests/fixtures/piv-attestation/root.der");
        let mut container = TlvWriter::new(16 * 1024);
        container
            .push(Tag::from_bytes(&[0x70]).unwrap(), der)
            .unwrap();
        let summary = certificate_summary(container.into_bytes().as_bytes());
        let info = canokey::x509::parse_der(der, Default::default()).unwrap();
        assert!(summary.contains(&format!("Subject: {}", info.subject.display)));
        assert!(summary.contains(&hex_encode(&info.sha256_fingerprint())));
    }

    #[test]
    fn firmware_310_f9_existing_key_or_certificate_requires_explicit_consent() {
        let get_metadata = &[0, 0xf7, 0, 0xf9];
        let get_certificate = &[0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xff, 1, 0];
        let mut metadata = vec![1, 1, 0x11, 3, 1, 1, 4, 0x43, 0x86, 0x41];
        metadata.extend(super::super::hex_decode("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5").unwrap());
        metadata.extend(OK);
        for (key_response, certificate_response) in [
            (metadata.as_slice(), MISSING),
            (MISSING, MALFORMED_CERT),
            (metadata.as_slice(), MALFORMED_CERT),
        ] {
            for consent in [false, true] {
                let mut script = Script::new(&[
                    (SELECT, OK),
                    (get_metadata, key_response),
                    (SELECT, OK),
                    (get_certificate, certificate_response),
                ]);
                let mut asked = 0;
                let result = key(
                    &profile("3.1.0"),
                    KeyReference::Attestation,
                    &mut |c| script.exchange(c),
                    &mut |prompt| {
                        asked += 1;
                        assert!(prompt.contains("f9"));
                        assert!(prompt.contains("attestation identity and trust"));
                        if key_response == metadata.as_slice() {
                            assert!(prompt.contains("Existing public key SHA-256:"));
                        }
                        Ok(consent)
                    },
                );
                assert_eq!(result.is_ok(), consent);
                assert_eq!(asked, 1);
                assert!(script.0.is_empty());
            }
        }
    }

    #[test]
    fn firmware_310_empty_f9_does_not_prompt_and_legacy_f9_never_touches_card() {
        let mut script = Script::new(&[
            (SELECT, OK),
            (&[0, 0xf7, 0, 0xf9], MISSING),
            (SELECT, OK),
            (
                &[0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xff, 1, 0],
                MISSING,
            ),
        ]);
        key(
            &profile("3.1.0"),
            KeyReference::Attestation,
            &mut |c| script.exchange(c),
            &mut |_| panic!("empty F9 must not prompt"),
        )
        .unwrap();
        assert!(script.0.is_empty());
        assert!(key(
            &profile("3.0.3"),
            KeyReference::Attestation,
            &mut |_| panic!("unsupported F9 must fail before I/O"),
            &mut |_| panic!("unsupported F9 must not prompt")
        )
        .is_err());
    }

    #[test]
    fn firmware_310_f9_metadata_failure_aborts_without_prompt_or_write() {
        for response in [&[0x69, 0x82][..], &[1, 1, 0x11, 1, 1, 0x11, 0x90, 0][..]] {
            let mut script = Script::new(&[(SELECT, OK), (&[0, 0xf7, 0, 0xf9], response)]);
            assert!(key(
                &profile("3.1.0"),
                KeyReference::Attestation,
                &mut |c| script.exchange(c),
                &mut |_| panic!("failed F9 read must abort")
            )
            .is_err());
            assert!(script.0.is_empty());
        }
    }

    #[test]
    fn firmware_310_empty_key_and_certificate_do_not_prompt() {
        let mut script = Script::new(&[
            (SELECT, OK),
            (METADATA, &[3, 1, 0, 0x90, 0]),
            (SELECT, OK),
            (CERTIFICATE, MISSING),
        ]);
        key(
            &profile("3.1.0"),
            Slot::Authentication.into(),
            &mut |c| script.exchange(c),
            &mut |_| panic!("empty slot must not prompt"),
        )
        .unwrap();
        assert!(script.0.is_empty());
    }

    #[test]
    fn firmware_310_key_or_certificate_requires_consent_before_any_write() {
        for (metadata, certificate) in [
            (&[3, 1, 1, 0x90, 0][..], MISSING),
            (&[3, 1, 0, 0x90, 0][..], MALFORMED_CERT),
            (&[3, 1, 2, 0x90, 0][..], MALFORMED_CERT),
        ] {
            let mut script = Script::new(&[
                (SELECT, OK),
                (METADATA, metadata),
                (SELECT, OK),
                (CERTIFICATE, certificate),
            ]);
            let mut prompts = Vec::new();
            let error = key(
                &profile("3.1.0"),
                Slot::Authentication.into(),
                &mut |c| script.exchange(c),
                &mut |prompt| {
                    prompts.push(prompt.to_string());
                    Ok(false)
                },
            )
            .unwrap_err();
            assert!(error.to_string().contains("Cancelled"));
            assert_eq!(prompts.len(), 1);
            assert!(prompts[0].contains("9a"));
            assert!(prompts[0].contains("irreversible"));
            if certificate == MALFORMED_CERT {
                assert!(prompts[0].contains("object SHA-256"));
            }
            assert!(script.0.is_empty());
        }
    }

    #[test]
    fn firmware_303_unknown_key_presence_requires_consent() {
        let select_le: &[u8] = &[0, 0xa4, 4, 0, 5, 0xa0, 0, 0, 3, 8, 0];
        let mut script = Script::new(&[
            (select_le, OK),
            (METADATA, &[0x6d, 0]),
            (select_le, OK),
            (CERTIFICATE, MISSING),
        ]);
        let mut prompted = false;
        key(
            &profile("3.0.3"),
            Slot::Authentication.into(),
            &mut |c| script.exchange(c),
            &mut |prompt| {
                assert!(prompt.contains("Cannot determine"));
                prompted = true;
                Ok(true)
            },
        )
        .unwrap();
        assert!(prompted);
        assert!(script.0.is_empty());
    }

    #[test]
    fn firmware_310_read_errors_never_authorize_replacement() {
        for response in [&[0x69, 0x82][..], &[3, 2, 0, 0, 0x90, 0][..]] {
            let mut script = Script::new(&[(SELECT, OK), (METADATA, response)]);
            assert!(key(
                &profile("3.1.0"),
                Slot::Authentication.into(),
                &mut |c| script.exchange(c),
                &mut |_| panic!("read error must abort")
            )
            .is_err());
            assert!(script.0.is_empty());
        }
        assert!(key(
            &profile("3.1.0"),
            Slot::Authentication.into(),
            &mut |_| Err(io::Error::new(io::ErrorKind::BrokenPipe, "disconnected")),
            &mut |_| panic!("transport failure must abort")
        )
        .is_err());
        let mut script = Script::new(&[(SELECT, OK), (CERTIFICATE, &[0x69, 0x82])]);
        assert!(certificate(
            &profile("3.1.0"),
            Slot::Authentication.into(),
            CertificateChange::Replace,
            &mut |c| script.exchange(c),
            &mut |_| panic!("GET DATA failure must abort")
        )
        .is_err());
        assert!(script.0.is_empty());
    }

    #[test]
    fn firmware_310_f9_replace_and_delete_warn_about_trust() {
        let get_f9 = &[0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xff, 1, 0];
        for change in [CertificateChange::Replace, CertificateChange::Delete] {
            let mut script = Script::new(&[(SELECT, OK), (get_f9, MALFORMED_CERT)]);
            let error = certificate(
                &profile("3.1.0"),
                CertificateReference::Attestation,
                change,
                &mut |c| script.exchange(c),
                &mut |prompt| {
                    assert!(prompt.contains("f9"));
                    assert!(prompt.contains("attestation verification and trust"));
                    Ok(false)
                },
            )
            .unwrap_err();
            assert!(error.to_string().contains("Cancelled"));
            assert!(script.0.is_empty());
        }
    }

    #[test]
    fn firmware_310_empty_certificate_needs_no_consent() {
        let mut script = Script::new(&[(SELECT, OK), (CERTIFICATE, MISSING)]);
        certificate(
            &profile("3.1.0"),
            Slot::Authentication.into(),
            CertificateChange::Replace,
            &mut |c| script.exchange(c),
            &mut |_| panic!("empty certificate must not prompt"),
        )
        .unwrap();
        assert!(script.0.is_empty());
    }
}
