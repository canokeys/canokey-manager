//! CanoKey 3.1.x attestation policy for a fixed leaf -> F9 issuer -> root chain.
//!
//! This is deliberately not a general-purpose X.509 path builder. Signers must
//! use P-256/SHA-256. Target SPKI bytes are compared without using the target
//! private key, including for key-agreement and post-quantum target algorithms.
//! No revocation, network lookup, challenge binding or anti-replay is provided.
use super::{KeyOrigin, KnownOrUnknown, PinPolicy, Slot, TouchPolicy};
use canokey::piv::MetadataFields;
use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};
use x509_cert::{Certificate, Version};

/// Official CanoKey PIV Root CA No. 1 (PEM), pinned independently of the device.
/// Source: <https://docs.canokeys.org/attestation/> (PIV).
pub const CANOKEY_PIV_ROOT: &[u8] = include_bytes!("canokey-piv-root-ca-1.pem");
/// Maximum DER certificate size accepted by the attestation policy.
pub const MAX_CERTIFICATE_BYTES: usize = 16 * 1024;
const SERIAL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.66602.1.1");
const POLICIES: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.66602.1.2");
const BC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const KU: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// Attestation verification failure. No partial verification is success.
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    /// A certificate is malformed or violates the fixed chain policy.
    #[error("{role} certificate: {reason}")]
    Certificate {
        /// Certificate's role in the chain.
        role: &'static str,
        /// Failed policy check.
        reason: &'static str,
    },
    /// Signed evidence and live device observations disagree or are incomplete.
    #[error("attestation binding failed: {0}")]
    Binding(&'static str),
    /// The caller did not supply exactly one bounded PEM/DER root certificate.
    #[error("invalid trust root: expected one PEM or DER certificate (at most 16 KiB DER)")]
    TrustRoot,
}

fn invalid(role: &'static str, reason: &'static str) -> AttestationError {
    AttestationError::Certificate { role, reason }
}

/// Decode one PEM or DER root certificate, bounded before parsing/allocation.
/// PEM bundles and unrelated PEM blocks are rejected; no system trust is used.
/// This checks syntax only; [`verify`] checks the root's policy and validity.
pub fn decode_root(input: &[u8]) -> Result<Vec<u8>, AttestationError> {
    if input.len() > MAX_CERTIFICATE_BYTES * 2 {
        return Err(AttestationError::TrustRoot);
    }
    if input.first() != Some(&0x30) {
        let text = std::str::from_utf8(input).map_err(|_| AttestationError::TrustRoot)?;
        if text.matches("-----BEGIN ").count() != 1
            || !text.trim_start().starts_with("-----BEGIN CERTIFICATE-----")
            || !text.trim_end().ends_with("-----END CERTIFICATE-----")
        {
            return Err(AttestationError::TrustRoot);
        }
    }
    let (_, der) = crate::keys::pem_decode(input, &["CERTIFICATE"])
        .map_err(|_| AttestationError::TrustRoot)?;
    parse(&der, "root")?;
    Ok(der)
}

/// Observations collected on a single exclusive device connection.
/// Certificate inputs are DER; metadata is asserted by the live device and is
/// checked against the signed evidence rather than treated as a trust anchor.
pub struct Evidence<'a> {
    /// Newly requested target-slot attestation certificate.
    pub certificate: &'a [u8],
    /// F9 signer certificate read from object 5FFF01.
    pub issuer: &'a [u8],
    /// Expected ordinary target slot (never F9).
    pub slot: Slot,
    /// Four device-serial bytes observed on the same connection, in wire order.
    pub serial: [u8; 4],
    /// Target-slot key metadata.
    pub target: &'a MetadataFields,
    /// F9 signer metadata.
    pub signer: &'a MetadataFields,
}

/// All chain and live-device binding checks passed.
#[derive(Debug)]
pub struct VerifiedAttestation {
    /// SHA-256 of the caller-selected trust root's DER, for unambiguous reporting.
    pub root_fingerprint: [u8; 32],
}

/// Verify a fixed three-certificate CanoKey PIV chain and its live bindings.
/// `root` must be independently trusted DER, never taken from the device;
/// `now_unix` is the caller's current nonnegative UTC Unix time in seconds.
/// Signer and root certificates must be P-256 CAs with certificate-signing
/// usage when KeyUsage is present. All validity intervals, path lengths,
/// duplicate extensions, inner/outer signature identifiers and unsupported
/// critical extensions are checked. Signed slot, SPKI, serial and policy bytes
/// must match the observations; the target must report generated origin.
/// No target private operation or target-signature algorithm support is needed.
///
/// # Errors
/// Missing/unknown metadata, malformed certificates, untrusted signatures,
/// expired/not-yet-valid certificates, constraint violations and mismatches
/// fail closed. No revocation or anti-replay check is performed.
pub fn verify(
    evidence: Evidence<'_>,
    root: &[u8],
    now_unix: u64,
) -> Result<VerifiedAttestation, AttestationError> {
    let leaf = parse(evidence.certificate, "attestation")?;
    let issuer = parse(evidence.issuer, "F9 issuer")?;
    let root_cert = parse(root, "root")?;
    check_profile(&leaf, "attestation", now_unix, None)?;
    check_profile(&issuer, "F9 issuer", now_unix, Some(0))?;
    // One non-self-issued intermediate CA is below the root.
    let intermediate_count =
        u8::from(issuer.tbs_certificate.subject != issuer.tbs_certificate.issuer);
    check_profile(&root_cert, "root", now_unix, Some(intermediate_count))?;
    if root_cert.tbs_certificate.issuer != root_cert.tbs_certificate.subject {
        return Err(invalid("root", "trust root must be self-issued"));
    }
    verify_signature(&root_cert, &root_cert, "root")?;
    verify_signature(&issuer, &root_cert, "F9 issuer")?;
    verify_signature(&leaf, &issuer, "attestation")?;
    let binding = AttestationError::Binding;
    if evidence.target.origin != Some(KnownOrUnknown::Known(KeyOrigin::Generated)) {
        return Err(binding("target key is not reported as generated on device"));
    }
    let target_spki = metadata_spki(evidence.target)?;
    let signer_spki = metadata_spki(evidence.signer)?;
    if leaf
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .ok()
        .as_deref()
        != Some(&target_spki)
    {
        return Err(binding("target public key mismatch"));
    }
    if issuer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .ok()
        .as_deref()
        != Some(&signer_spki)
    {
        return Err(binding("F9 public key does not match issuer certificate"));
    }
    let expected_subject = crate::x509::parse_rfc4514(&format!(
        "CN=CanoKey PIV Attestation {:02x}",
        evidence.slot.reference()
    ))
    .map_err(|_| binding("invalid target slot"))?;
    if leaf.tbs_certificate.subject != expected_subject {
        return Err(binding("target slot subject mismatch"));
    }
    if extension(&leaf, SERIAL) != Some(evidence.serial.as_slice()) {
        return Err(binding("device serial extension missing or mismatched"));
    }
    let policies = [
        pin_wire(evidence.target.pin_policy)?,
        touch_wire(evidence.target.touch_policy)?,
    ];
    if extension(&leaf, POLICIES) != Some(policies.as_slice()) {
        return Err(binding("PIN/touch policy extension missing or mismatched"));
    }
    Ok(VerifiedAttestation {
        root_fingerprint: Sha256::digest(root).into(),
    })
}

fn parse(bytes: &[u8], role: &'static str) -> Result<Certificate, AttestationError> {
    if bytes.len() > MAX_CERTIFICATE_BYTES {
        return Err(invalid(role, "certificate exceeds size limit"));
    }
    Certificate::from_der(bytes).map_err(|_| invalid(role, "malformed DER"))
}

fn extension(cert: &Certificate, oid: ObjectIdentifier) -> Option<&[u8]> {
    cert.tbs_certificate
        .extensions
        .as_ref()?
        .iter()
        .find(|ext| ext.extn_id == oid)
        .map(|ext| ext.extn_value.as_bytes())
}

fn check_profile(
    cert: &Certificate,
    role: &'static str,
    now: u64,
    ca_depth: Option<u8>,
) -> Result<(), AttestationError> {
    let tbs = &cert.tbs_certificate;
    if tbs.version != Version::V3
        || tbs.issuer_unique_id.is_some()
        || tbs.subject_unique_id.is_some()
    {
        return Err(invalid(
            role,
            "unsupported certificate version or unique identifiers",
        ));
    }
    if cert.signature_algorithm != tbs.signature
        || cert.signature_algorithm.oid != ECDSA_SHA256
        || cert.signature_algorithm.parameters.is_some()
    {
        return Err(invalid(
            role,
            "expected matching ECDSA/SHA-256 signature identifiers without parameters",
        ));
    }
    let validity = &tbs.validity;
    let before = validity.not_before.to_unix_duration().as_secs();
    let after = validity.not_after.to_unix_duration().as_secs();
    if before > after || now < before || now > after {
        return Err(invalid(role, "certificate is expired or not yet valid"));
    }
    if let Some(extensions) = &tbs.extensions {
        for (i, ext) in extensions.iter().enumerate() {
            if extensions[..i]
                .iter()
                .any(|other| other.extn_id == ext.extn_id)
            {
                return Err(invalid(role, "duplicate extension"));
            }
            // These are the only critical constraints this fixed profile implements.
            if ext.critical && ext.extn_id != BC && ext.extn_id != KU {
                return Err(invalid(role, "unsupported critical extension"));
            }
        }
    }
    let bc = extension(cert, BC)
        .map(BasicConstraints::from_der)
        .transpose()
        .map_err(|_| invalid(role, "malformed BasicConstraints"))?;
    let ku = extension(cert, KU)
        .map(KeyUsage::from_der)
        .transpose()
        .map_err(|_| invalid(role, "malformed KeyUsage"))?;
    if let Some(depth) = ca_depth {
        let bc = bc
            .filter(|bc| bc.ca)
            .ok_or_else(|| invalid(role, "signer must be a CA"))?;
        if bc.path_len_constraint.is_some_and(|limit| depth > limit) {
            return Err(invalid(role, "CA path length exceeded"));
        }
        if ku.is_some_and(|ku| !ku.key_cert_sign()) {
            return Err(invalid(
                role,
                "signer KeyUsage does not allow certificate signing",
            ));
        }
    } else if bc.is_some_and(|bc| bc.ca || bc.path_len_constraint.is_some())
        || ku.is_some_and(|ku| ku.key_cert_sign() || ku.crl_sign())
    {
        return Err(invalid(
            role,
            "target attestation must be an end-entity certificate",
        ));
    }
    Ok(())
}

fn verify_signature(
    cert: &Certificate,
    issuer: &Certificate,
    role: &'static str,
) -> Result<(), AttestationError> {
    if cert.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        return Err(invalid(role, "issuer name does not match signer subject"));
    }
    let spki = issuer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| invalid(role, "invalid signer SPKI"))?;
    let key = VerifyingKey::from_public_key_der(&spki)
        .map_err(|_| invalid(role, "signer must use P-256"))?;
    let signature = cert
        .signature
        .as_bytes()
        .and_then(|bytes| Signature::from_der(bytes).ok())
        .ok_or_else(|| invalid(role, "invalid ECDSA signature encoding"))?;
    let tbs = cert
        .tbs_certificate
        .to_der()
        .map_err(|_| invalid(role, "invalid TBS certificate"))?;
    key.verify(&tbs, &signature)
        .map_err(|_| invalid(role, "signature verification failed"))
}

fn metadata_spki(fields: &MetadataFields) -> Result<Vec<u8>, AttestationError> {
    fields
        .public_key
        .as_ref()
        .ok_or(AttestationError::Binding(
            "public key metadata missing or unsupported",
        ))?
        .to_spki_der()
        .map_err(|_| AttestationError::Binding("invalid public key metadata"))
}
fn pin_wire(policy: Option<KnownOrUnknown<PinPolicy>>) -> Result<u8, AttestationError> {
    match policy {
        Some(KnownOrUnknown::Known(PinPolicy::Never)) => Ok(1),
        Some(KnownOrUnknown::Known(PinPolicy::Once)) => Ok(2),
        Some(KnownOrUnknown::Known(PinPolicy::Always)) => Ok(3),
        _ => Err(AttestationError::Binding("PIN policy missing or unknown")),
    }
}
fn touch_wire(policy: Option<KnownOrUnknown<TouchPolicy>>) -> Result<u8, AttestationError> {
    match policy {
        Some(KnownOrUnknown::Known(TouchPolicy::Never)) => Ok(1),
        Some(KnownOrUnknown::Known(TouchPolicy::Always)) => Ok(2),
        Some(KnownOrUnknown::Known(TouchPolicy::Cached)) => Ok(3),
        _ => Err(AttestationError::Binding("touch policy missing or unknown")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::piv::{Algorithm, PublicKey};
    use canokey::SecretBytes;
    use der::asn1::OctetString;
    use p256::ecdsa::{signature::Signer, SigningKey};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use x509_cert::ext::Extension;

    const ROOT: &[u8] = include_bytes!("../../tests/fixtures/piv-attestation/root.der");
    const ISSUER: &[u8] = include_bytes!("../../tests/fixtures/piv-attestation/issuer.der");
    const LEAF: &[u8] = include_bytes!("../../tests/fixtures/piv-attestation/leaf.der");
    const NOW: u64 = 1893456000;

    fn scalar(n: u8) -> [u8; 32] {
        let mut scalar = [0; 32];
        scalar[31] = n;
        scalar
    }
    fn public(n: u8) -> PublicKey {
        PublicKey::Ec {
            algorithm: Algorithm::EccP256,
            point: SigningKey::from_slice(&scalar(n))
                .unwrap()
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
        }
    }
    fn metadata(public_key: PublicKey) -> MetadataFields {
        MetadataFields {
            raw: SecretBytes::default(),
            algorithm_id: Some(0x11),
            pin_policy: Some(KnownOrUnknown::Known(PinPolicy::Once)),
            touch_policy: Some(KnownOrUnknown::Known(TouchPolicy::Never)),
            origin: Some(KnownOrUnknown::Known(KeyOrigin::Generated)),
            is_default: None,
            retries: None,
            public_key_tlv: None,
            public_key: Some(public_key),
            unknown_fields: vec![],
        }
    }
    fn resign(mut cert: Certificate, signer: u8) -> Vec<u8> {
        let key = SigningKey::from_slice(&scalar(signer)).unwrap();
        let signature: Signature = key.sign(&cert.tbs_certificate.to_der().unwrap());
        cert.signature = der::asn1::BitString::from_bytes(signature.to_der().as_bytes()).unwrap();
        cert.to_der().unwrap()
    }
    #[allow(clippy::too_many_arguments)]
    fn check(
        leaf: &[u8],
        issuer: &[u8],
        root: &[u8],
        target: &MetadataFields,
        signer: &MetadataFields,
        slot: Slot,
        serial: [u8; 4],
        now: u64,
    ) -> Result<VerifiedAttestation, AttestationError> {
        verify(
            Evidence {
                certificate: leaf,
                issuer,
                slot,
                serial,
                target,
                signer,
            },
            root,
            now,
        )
    }
    fn base(
        leaf: &[u8],
        issuer: &[u8],
        root: &[u8],
    ) -> Result<VerifiedAttestation, AttestationError> {
        check(
            leaf,
            issuer,
            root,
            &metadata(public(3)),
            &metadata(public(2)),
            Slot::Authentication,
            [0x11, 0x22, 0x33, 0x44],
            NOW,
        )
    }
    fn assert_certificate_error(
        result: Result<VerifiedAttestation, AttestationError>,
        role: &'static str,
        reason: &'static str,
    ) {
        assert!(
            matches!(result, Err(AttestationError::Certificate { role: r, reason: e })
            if r == role && e == reason)
        );
    }
    fn ext(oid: ObjectIdentifier, bytes: &[u8], critical: bool) -> Extension {
        Extension {
            extn_id: oid,
            critical,
            extn_value: OctetString::new(bytes).unwrap(),
        }
    }

    #[test]
    fn independent_chain_and_pinned_official_root() {
        let report = base(LEAF, ISSUER, ROOT).unwrap();
        assert_eq!(
            report.root_fingerprint.as_slice(),
            Sha256::digest(ROOT).as_slice()
        );
        let official = decode_root(CANOKEY_PIV_ROOT).unwrap();
        assert_eq!(
            Sha256::digest(&official).as_slice(),
            &[
                0x2e, 0xb3, 0x82, 0xe5, 0xec, 0x23, 0x56, 0x61, 0xf9, 0x26, 0xc2, 0x3d, 0x25, 0xba,
                0x92, 0x22, 0x7b, 0xd6, 0xb9, 0xd5, 0xd3, 0x54, 0x13, 0x11, 0x77, 0x54, 0x73, 0x68,
                0xab, 0xea, 0x68, 0x1c,
            ]
        );
        let cert = parse(&official, "root").unwrap();
        check_profile(&cert, "root", 1793700000, Some(1)).unwrap();
        verify_signature(&cert, &cert, "root").unwrap();
        assert!(base(LEAF, ISSUER, &official).is_err());
    }

    #[test]
    fn tampering_and_wrong_root_do_not_verify() {
        let mut leaf = LEAF.to_vec();
        *leaf.last_mut().unwrap() ^= 1;
        assert_certificate_error(
            base(&leaf, ISSUER, ROOT),
            "attestation",
            "signature verification failed",
        );
        let mut root = parse(ROOT, "root").unwrap();
        root.tbs_certificate.subject_public_key_info =
            spki::SubjectPublicKeyInfoOwned::from_der(&public(3).to_spki_der().unwrap()).unwrap();
        assert_certificate_error(
            base(LEAF, ISSUER, &resign(root, 3)),
            "F9 issuer",
            "signature verification failed",
        );
    }

    #[test]
    fn slot_serial_keys_policies_and_origin_must_match() {
        let target = metadata(public(3));
        let signer = metadata(public(2));
        for (slot, serial) in [
            (Slot::Signature, [0x11, 0x22, 0x33, 0x44]),
            (Slot::Authentication, [0; 4]),
        ] {
            assert!(matches!(
                check(LEAF, ISSUER, ROOT, &target, &signer, slot, serial, NOW),
                Err(AttestationError::Binding(_))
            ));
        }
        for change in 0..6 {
            let mut target = metadata(public(3));
            let mut signer = metadata(public(2));
            match change {
                0 => target.public_key = Some(public(4)),
                1 => signer.public_key = Some(public(4)),
                2 => target.origin = Some(KnownOrUnknown::Known(KeyOrigin::Imported)),
                3 => target.pin_policy = Some(KnownOrUnknown::Unknown(0xff)),
                4 => target.touch_policy = Some(KnownOrUnknown::Known(TouchPolicy::Always)),
                _ => target.public_key = None,
            }
            assert!(matches!(
                check(
                    LEAF,
                    ISSUER,
                    ROOT,
                    &target,
                    &signer,
                    Slot::Authentication,
                    [0x11, 0x22, 0x33, 0x44],
                    NOW
                ),
                Err(AttestationError::Binding(_))
            ));
        }
        let mut leaf = parse(LEAF, "attestation").unwrap();
        leaf.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .retain(|e| e.extn_id != SERIAL);
        assert!(matches!(
            base(&resign(leaf, 2), ISSUER, ROOT),
            Err(AttestationError::Binding(_))
        ));
    }

    #[test]
    fn all_certificate_validity_intervals_are_enforced() {
        for now in [0, 4102444800] {
            assert!(check(
                LEAF,
                ISSUER,
                ROOT,
                &metadata(public(3)),
                &metadata(public(2)),
                Slot::Authentication,
                [0x11, 0x22, 0x33, 0x44],
                now
            )
            .is_err());
        }
        // Narrow the issuer/root alone, leaving the other certificates valid.
        for role in ["F9 issuer", "root"] {
            let mut cert = parse(if role == "root" { ROOT } else { ISSUER }, role).unwrap();
            cert.tbs_certificate.validity.not_after = x509_cert::time::Time::UtcTime(
                der::asn1::UtcTime::from_unix_duration(std::time::Duration::from_secs(NOW - 1))
                    .unwrap(),
            );
            let der = resign(cert, 1);
            assert_certificate_error(
                base(
                    LEAF,
                    if role == "root" { ISSUER } else { &der },
                    if role == "root" { &der } else { ROOT },
                ),
                role,
                "certificate is expired or not yet valid",
            );
        }
    }

    #[test]
    fn constraints_critical_extensions_and_signature_identifiers_fail_closed() {
        for (oid, bytes, reason) in [
            (BC, vec![0x30, 0], "signer must be a CA"),
            (
                KU,
                vec![3, 2, 7, 0x80],
                "signer KeyUsage does not allow certificate signing",
            ),
        ] {
            let mut cert = parse(ISSUER, "F9 issuer").unwrap();
            let extensions = cert.tbs_certificate.extensions.as_mut().unwrap();
            extensions.retain(|e| e.extn_id != oid);
            extensions.push(ext(oid, &bytes, true));
            assert_certificate_error(base(LEAF, &resign(cert, 1), ROOT), "F9 issuer", reason);
        }
        let mut root = parse(ROOT, "root").unwrap();
        let extensions = root.tbs_certificate.extensions.as_mut().unwrap();
        extensions.retain(|e| e.extn_id != BC);
        extensions.push(ext(BC, &[0x30, 6, 1, 1, 0xff, 2, 1, 0], true));
        assert_certificate_error(
            base(LEAF, ISSUER, &resign(root, 1)),
            "root",
            "CA path length exceeded",
        );
        for (duplicate, reason) in [
            (true, "duplicate extension"),
            (false, "unsupported critical extension"),
        ] {
            let mut cert = parse(LEAF, "attestation").unwrap();
            cert.tbs_certificate.extensions.as_mut().unwrap().push(ext(
                if duplicate {
                    SERIAL
                } else {
                    ObjectIdentifier::new_unwrap("1.2.3.4")
                },
                &[0; 4],
                !duplicate,
            ));
            assert_certificate_error(base(&resign(cert, 2), ISSUER, ROOT), "attestation", reason);
        }
        let mut cert = parse(LEAF, "attestation").unwrap();
        cert.signature_algorithm.oid = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
        assert_certificate_error(
            base(&cert.to_der().unwrap(), ISSUER, ROOT),
            "attestation",
            "expected matching ECDSA/SHA-256 signature identifiers without parameters",
        );
    }

    #[test]
    fn bounded_strict_root_and_certificate_decoding() {
        assert_eq!(decode_root(ROOT).unwrap(), ROOT);
        let pem = include_bytes!("../../tests/fixtures/piv-attestation/root.pem");
        assert_eq!(decode_root(pem).unwrap(), ROOT);
        let mut bundle = pem.to_vec();
        bundle.extend(pem);
        assert!(decode_root(&bundle).is_err());
        assert!(decode_root(&vec![0; MAX_CERTIFICATE_BYTES * 2 + 1]).is_err());
        assert!(base(&[0x30, 0], ISSUER, ROOT).is_err());
        assert!(base(&vec![0; MAX_CERTIFICATE_BYTES + 1], ISSUER, ROOT).is_err());
        let mut trailing = ROOT.to_vec();
        trailing.push(0);
        assert!(decode_root(&trailing).is_err());
    }

    #[test]
    fn target_algorithm_is_independent_of_p256_attestation_signature() {
        use rsa::traits::PublicKeyParts;
        let rsa = rsa::RsaPublicKey::from_public_key_der(include_bytes!(
            "../../tests/fixtures/rsa-export-verify-openssl-pub.der"
        ))
        .unwrap();
        let mut keys = vec![
            public(3),
            PublicKey::Rsa {
                algorithm: Algorithm::Rsa2048,
                modulus: rsa.n().to_bytes_be(),
                exponent: rsa.e().to_bytes_be(),
            },
        ];
        // Actual public points on each supported curve; no target signature is made.
        keys.push(PublicKey::Ec {
            algorithm: Algorithm::EccP384,
            point: p384::SecretKey::from_slice(&[1; 48])
                .unwrap()
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
        });
        keys.push(PublicKey::Ec {
            algorithm: Algorithm::EccP521,
            point: p521::SecretKey::from_slice(&[1; 66])
                .unwrap()
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
        });
        keys.push(PublicKey::Ec {
            algorithm: Algorithm::Secp256k1,
            point: k256::SecretKey::from_slice(&[1; 32])
                .unwrap()
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
        });
        keys.push(PublicKey::Ec {
            algorithm: Algorithm::Sm2,
            point: sm2::SecretKey::from_slice(&[1; 32])
                .unwrap()
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
        });
        for (algorithm, size) in [
            (Algorithm::Ed25519, 32),
            (Algorithm::X25519, 32),
            (Algorithm::MlDsa65, 1952),
        ] {
            keys.push(PublicKey::Raw {
                algorithm,
                bytes: vec![0x42; size],
            });
        }
        for key in keys {
            let mut cert = parse(LEAF, "attestation").unwrap();
            cert.tbs_certificate.subject_public_key_info =
                spki::SubjectPublicKeyInfoOwned::from_der(&key.to_spki_der().unwrap()).unwrap();
            check(
                &resign(cert, 2),
                ISSUER,
                ROOT,
                &metadata(key),
                &metadata(public(2)),
                Slot::Authentication,
                [0x11, 0x22, 0x33, 0x44],
                NOW,
            )
            .unwrap();
        }
    }
}
