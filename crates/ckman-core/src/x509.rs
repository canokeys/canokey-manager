//! Host-side X.509 building: RFC 4514 subject parsing, self-signed
//! certificate and CSR assembly, hashing and RSA PKCS#1 v1.5 padding.
//!
//! The private-key operation itself runs on the CanoKey; this module only
//! prepares the to-be-signed bytes and assembles the final object, mirroring
//! ykman's `sign_certificate_builder`/`sign_csr_builder` without the
//! dummy-key detour (the TBS is built directly and signed once).

use canokey::piv::Algorithm;
use der::asn1::{Any, BitString, ObjectIdentifier, SetOfVec, UtcTime};
use der::{Decode, Encode};
use sha2::Digest as _;
use spki::{AlgorithmIdentifierOwned as AlgorithmIdentifier, SubjectPublicKeyInfo};
use std::time::Duration;
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};
use x509_cert::request::{CertReq, CertReqInfo};
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};
use x509_cert::{Certificate, TbsCertificate, Version};

/// X.509/host-encoding failure.
#[derive(Debug, thiserror::Error)]
pub enum X509Error {
    /// Malformed RFC 4514 subject string.
    #[error("invalid RFC 4514 string: {0}")]
    Rfc4514(String),
    /// The key algorithm cannot sign certificates/CSRs (e.g. X25519).
    #[error("algorithm cannot sign certificates")]
    UnsupportedAlgorithm,
    /// The hash is not defined for this key algorithm.
    #[error("hash not supported for this algorithm")]
    UnsupportedHash,
    /// DER encoding/decoding failed.
    #[error("ASN.1 encoding failed: {0}")]
    Der(String),
    /// A timestamp does not fit UTCTime (1950-2049).
    #[error("timestamp out of UTCTime range")]
    TimeRange,
    /// The Ed25519 message exceeds the firmware's classic scratch buffer.
    #[error("Ed25519 message too large")]
    MessageTooLarge,
    /// The key algorithm cannot sign (key-agreement/encapsulation only).
    #[error("algorithm {0} cannot sign certificates or CSRs")]
    NotSigning(&'static str),
}

fn der<E: std::fmt::Display>(error: E) -> X509Error {
    X509Error::Der(error.to_string())
}

/// Hash algorithms offered for certificate/CSR signing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl HashAlgorithm {
    /// Digest the message.
    pub fn hash(self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => sha2::Sha256::digest(message).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(message).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(message).to_vec(),
        }
    }

    fn digest_info_prefix(self) -> &'static [u8] {
        match self {
            // DER SEQUENCE { SEQUENCE { OID, NULL }, OCTET STRING } headers.
            Self::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            Self::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            Self::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }
}

/// EMSA-PKCS1-v1_5 encoded message for an RSA private operation: hash the
/// message, wrap in DigestInfo, pad to the modulus width.
pub fn rsa_pkcs1v15_encode(
    hash: HashAlgorithm,
    message: &[u8],
    modulus_bytes: usize,
) -> Result<Vec<u8>, X509Error> {
    let mut info = hash.digest_info_prefix().to_vec();
    info.extend(hash.hash(message));
    if modulus_bytes < info.len() + 11 {
        return Err(X509Error::UnsupportedHash);
    }
    let mut encoded = vec![0, 1];
    encoded.resize(modulus_bytes - info.len() - 1, 0xff);
    encoded.push(0);
    encoded.extend(info);
    Ok(encoded)
}

/// Signature algorithm identifier for a key algorithm and hash, matching the
/// identifiers ykman writes. Ed25519 takes no hash (PureEdDSA).
pub fn signature_algorithm(
    key: Algorithm,
    hash: Option<HashAlgorithm>,
) -> Result<AlgorithmIdentifier, X509Error> {
    let oid = match (key, hash) {
        (Algorithm::Ed25519, None) => "1.3.101.112",
        // SM2 signs SM3(ZA || M); no hash parameter.
        (Algorithm::Sm2, None) => "1.2.156.10197.1.501",
        // ML-DSA-65, empty context; parameters are absent by definition.
        (Algorithm::MlDsa65, None) => "2.16.840.1.101.3.4.18",
        (Algorithm::X25519 | Algorithm::MlKem768, _) => {
            return Err(X509Error::NotSigning(if key == Algorithm::X25519 {
                "X25519"
            } else {
                "ML-KEM-768"
            }))
        }
        (Algorithm::EccP521 | Algorithm::Secp256k1, h) => {
            match h.ok_or(X509Error::UnsupportedHash)? {
                HashAlgorithm::Sha256 => "1.2.840.10045.4.3.2",
                HashAlgorithm::Sha384 => "1.2.840.10045.4.3.3",
                HashAlgorithm::Sha512 => "1.2.840.10045.4.3.4",
            }
        }
        (Algorithm::Rsa1024 | Algorithm::Rsa2048 | Algorithm::Rsa3072 | Algorithm::Rsa4096, h) => {
            match h.ok_or(X509Error::UnsupportedHash)? {
                HashAlgorithm::Sha256 => "1.2.840.113549.1.1.11",
                HashAlgorithm::Sha384 => "1.2.840.113549.1.1.12",
                HashAlgorithm::Sha512 => "1.2.840.113549.1.1.13",
            }
        }
        (Algorithm::EccP256 | Algorithm::EccP384, h) => {
            match h.ok_or(X509Error::UnsupportedHash)? {
                HashAlgorithm::Sha256 => "1.2.840.10045.4.3.2",
                HashAlgorithm::Sha384 => "1.2.840.10045.4.3.3",
                HashAlgorithm::Sha512 => "1.2.840.10045.4.3.4",
            }
        }
        _ => return Err(X509Error::UnsupportedAlgorithm),
    };
    let oid = ObjectIdentifier::new(oid).map_err(der)?;
    Ok(match key {
        Algorithm::Rsa1024 | Algorithm::Rsa2048 | Algorithm::Rsa3072 | Algorithm::Rsa4096 => {
            AlgorithmIdentifier {
                oid,
                parameters: Some(Any::null()),
            }
        }
        _ => AlgorithmIdentifier {
            oid,
            parameters: None,
        },
    })
}

const NAME_ATTRIBUTES: [(&str, &str); 9] = [
    ("CN", "2.5.4.3"),
    ("L", "2.5.4.7"),
    ("ST", "2.5.4.8"),
    ("O", "2.5.4.10"),
    ("OU", "2.5.4.11"),
    ("C", "2.5.4.6"),
    ("STREET", "2.5.4.9"),
    ("DC", "0.9.2342.19200300.100.1.25"),
    ("UID", "0.9.2342.19200300.100.1.1"),
];

/// Parse an RFC 4514 string into an X.501 Name, ported from ykman's
/// `_parse_rfc4514_string`: `,` separates RDNs, `+` separates multi-valued
/// RDN attributes, `\` escapes the special characters `"+"',<> #=` and
/// introduces `\XX` UTF-8 hex bytes. RDNs are reversed into DER order.
pub fn parse_rfc4514(value: &str) -> Result<Name, X509Error> {
    let invalid = |msg: &str| X509Error::Rfc4514(msg.to_string());
    // Split into RDNs of attributes, handling escapes.
    let mut name: Vec<Vec<String>> = Vec::new();
    let mut entry: Vec<String> = Vec::new();
    let mut buf = String::new();
    let mut hexbuf: Vec<u8> = Vec::new();
    let mut chars = value.chars();
    while let Some(mut c) = chars.next() {
        if c == '\\' {
            let c1 = chars.next().ok_or_else(|| invalid("trailing backslash"))?;
            if "\\\"+,'<> #=".contains(c1) {
                c = c1;
            } else {
                let c2 = chars
                    .next()
                    .ok_or_else(|| invalid("truncated hex escape"))?;
                hexbuf.push(
                    u8::from_str_radix(&format!("{c1}{c2}"), 16)
                        .map_err(|_| invalid("invalid hex escape"))?,
                );
                if let Ok(text) = std::str::from_utf8(&hexbuf) {
                    buf.push_str(text);
                    hexbuf.clear();
                }
                continue; // Possibly multi-byte; expect more hex.
            }
        } else if c == ',' || c == '+' {
            entry.push(std::mem::take(&mut buf));
            if c == ',' {
                name.push(std::mem::take(&mut entry));
            }
            continue;
        }
        if !hexbuf.is_empty() {
            return Err(invalid("invalid UTF-8 data"));
        }
        buf.push(c);
    }
    if !hexbuf.is_empty() {
        return Err(invalid("invalid UTF-8 data"));
    }
    entry.push(buf);
    name.push(entry);
    let mut rdns = Vec::new();
    for entry in name {
        let mut attributes = SetOfVec::new();
        for part in entry {
            let (key, value) = part
                .split_once('=')
                .ok_or_else(|| invalid("missing '=' in attribute"))?;
            let dotted = key.chars().all(|c| c.is_ascii_digit() || c == '.')
                && key.split('.').all(|n| !n.is_empty())
                && key.contains('.');
            let oid = NAME_ATTRIBUTES
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, oid)| *oid)
                .or(if dotted { Some(key) } else { None })
                .ok_or_else(|| invalid("unsupported attribute"))?;
            let oid = ObjectIdentifier::new(oid).map_err(der)?;
            let value = Any::encode_from(&der::asn1::Utf8StringRef::new(value).map_err(der)?)
                .map_err(der)?;
            attributes
                .insert(AttributeTypeAndValue { oid, value })
                .map_err(der)?;
        }
        rdns.insert(0, RelativeDistinguishedName(attributes));
    }
    Ok(Name::from(RdnSequence::from(rdns)))
}

fn time(unix_seconds: i64) -> Result<Time, X509Error> {
    let duration =
        Duration::from_secs(u64::try_from(unix_seconds).map_err(|_| X509Error::TimeRange)?);
    Ok(Time::UtcTime(
        UtcTime::from_unix_duration(duration).map_err(|_| X509Error::TimeRange)?,
    ))
}

fn spki(
    der_bytes: &[u8],
) -> Result<SubjectPublicKeyInfo<der::Any, der::asn1::BitString>, X509Error> {
    SubjectPublicKeyInfo::from_der(der_bytes).map_err(der)
}

/// Build the to-be-signed certificate bytes for a self-signed certificate.
/// `serial` is the INTEGER content without sign padding; the caller supplies
/// positive randomness. Returns the TBS DER and the signature algorithm.
pub fn tbs_self_signed(
    spki_der: &[u8],
    subject: &Name,
    serial: &[u8],
    not_before: i64,
    not_after: i64,
    signature: AlgorithmIdentifier,
) -> Result<Vec<u8>, X509Error> {
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(serial).map_err(der)?,
        signature: signature.clone(),
        issuer: subject.clone(),
        validity: Validity {
            not_before: time(not_before)?,
            not_after: time(not_after)?,
        },
        subject: subject.clone(),
        subject_public_key_info: spki(spki_der)?,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: None,
    };
    tbs.to_der().map_err(der)
}

/// Assemble a certificate from signed TBS bytes.
pub fn assemble_certificate(
    tbs_der: &[u8],
    signature_algorithm: AlgorithmIdentifier,
    signature: &[u8],
) -> Result<Vec<u8>, X509Error> {
    let certificate = Certificate {
        tbs_certificate: TbsCertificate::from_der(tbs_der).map_err(der)?,
        signature_algorithm,
        signature: BitString::new(0, signature).map_err(der)?,
    };
    certificate.to_der().map_err(der)
}

/// Build the CertificationRequestInfo bytes to sign for a CSR.
pub fn certification_request_info(spki_der: &[u8], subject: &Name) -> Result<Vec<u8>, X509Error> {
    let info = CertReqInfo {
        version: Default::default(),
        subject: subject.clone(),
        public_key: spki(spki_der)?,
        attributes: Default::default(),
    };
    info.to_der().map_err(der)
}

/// Assemble a CSR from signed request-info bytes.
pub fn assemble_csr(
    cri_der: &[u8],
    signature_algorithm: AlgorithmIdentifier,
    signature: &[u8],
) -> Result<Vec<u8>, X509Error> {
    let csr = CertReq {
        info: CertReqInfo::from_der(cri_der).map_err(der)?,
        algorithm: signature_algorithm,
        signature: BitString::new(0, signature).map_err(der)?,
    };
    csr.to_der().map_err(der)
}

/// Wrap DER bytes in a PEM armor block.
pub fn pem_encode(label: &str, der_bytes: &[u8]) -> Vec<u8> {
    use base64ct::{Base64, Encoding as _};
    let mut out = format!("-----BEGIN {label}-----\n");
    let encoded = Base64::encode_string(der_bytes);
    for line in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rfc4514_text(name: &Name) -> String {
        // Render back in RFC 4514 order for comparison.
        let mut parts = Vec::new();
        for rdn in name.0.iter().rev() {
            let mut attrs = Vec::new();
            for attr in rdn.0.iter() {
                let oid = attr.oid.to_string();
                let label = NAME_ATTRIBUTES
                    .iter()
                    .find(|(_, o)| *o == oid)
                    .map(|(l, _)| *l)
                    .unwrap_or(&oid);
                let value = attr.value.decode_as::<der::asn1::Utf8StringRef>().unwrap();
                attrs.push(format!("{label}={value}"));
            }
            parts.push(attrs.join("+"));
        }
        parts.join(",")
    }

    #[test]
    fn rfc4514_parsing() {
        let name = parse_rfc4514("CN=foo,O=Example,C=SE").unwrap();
        assert_eq!(rfc4514_text(&name), "CN=foo,O=Example,C=SE");
        let name = parse_rfc4514("OU=a+OU=b,CN=x").unwrap();
        assert_eq!(name.0.len(), 2);
        assert_eq!(
            name.0[1].0.iter().count(),
            2,
            "multi-valued RDN kept together"
        );
        let name = parse_rfc4514("CN=a\\,b\\\\c").unwrap();
        assert_eq!(rfc4514_text(&name), "CN=a,b\\c");
        let name = parse_rfc4514("CN=\\c3\\a5tana").unwrap();
        assert_eq!(rfc4514_text(&name), "CN=åtana");
        let name = parse_rfc4514("1.2.3.4=x").unwrap();
        assert_eq!(
            name.0[0].0.iter().next().unwrap().oid.to_string(),
            "1.2.3.4"
        );
        for bad in ["CN", "CN=a,BAD=x", "CN=a\\", "CN=\\zz41"] {
            assert!(parse_rfc4514(bad).is_err(), "{bad}");
        }
    }
}

#[cfg(test)]
mod signing_tests {
    use super::*;
    use der::Decode;

    /// Sign a TBS as the card would (RSA PKCS#1 v1.5 over SHA-256), then
    /// verify the assembled certificate end to end.
    #[test]
    fn self_signed_certificate_roundtrip_rsa() {
        let mut rng = rand_core::OsRng;
        let private = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let public = private.to_public_key();
        let spki = rsa::pkcs8::EncodePublicKey::to_public_key_der(&public).unwrap();
        let subject = parse_rfc4514("CN=test,O=Example").unwrap();
        let algorithm =
            signature_algorithm(Algorithm::Rsa1024, Some(HashAlgorithm::Sha256)).unwrap();
        let tbs = tbs_self_signed(
            spki.as_bytes(),
            &subject,
            &[7; 16],
            1_700_000_000,
            1_800_000_000,
            algorithm.clone(),
        )
        .unwrap();
        let signing_key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private.clone());
        let signature: rsa::pkcs1v15::Signature = {
            use rsa::signature::Signer;
            signing_key.sign(&tbs)
        };
        let signature_bytes: Box<[u8]> = signature.clone().into();
        let signature_bytes: &[u8] = &signature_bytes;
        let cert_der = assemble_certificate(&tbs, algorithm, signature_bytes).unwrap();
        let cert = Certificate::from_der(&cert_der).unwrap();
        assert!(cert.tbs_certificate.subject.to_string().contains("CN=test"));
        assert_eq!(
            cert.tbs_certificate.subject.to_string(),
            cert.tbs_certificate.issuer.to_string(),
            "self-signed"
        );
        // Our padding matches what the rsa crate produced for the card.
        use rsa::signature::Verifier;
        let verifying = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(public.clone());
        verifying
            .verify(&tbs, &signature)
            .expect("signature verifies");
        // The raw public operation on the signature equals our encoded block.
        use rsa::traits::PublicKeyParts;
        let em = rsa::BigUint::from_bytes_be(signature_bytes)
            .modpow(public.e(), public.n())
            .to_bytes_be();
        let mut padded = vec![0; 128 - em.len()];
        padded.extend(em);
        assert_eq!(
            padded,
            rsa_pkcs1v15_encode(HashAlgorithm::Sha256, &tbs, 128).unwrap()
        );
    }

    #[test]
    fn csr_roundtrip_p256() {
        let secret = p256::SecretKey::random(&mut rand_core::OsRng);
        let public = secret.public_key();
        let spki = p256::pkcs8::EncodePublicKey::to_public_key_der(&public).unwrap();
        let subject = parse_rfc4514("CN=csr,O=Example").unwrap();
        let cri = certification_request_info(spki.as_bytes(), &subject).unwrap();
        let signing = p256::ecdsa::SigningKey::from(&secret);
        let digest = HashAlgorithm::Sha256.hash(&cri);
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let signature: p256::ecdsa::Signature = signing.sign_prehash(&digest).unwrap();
        let algorithm =
            signature_algorithm(Algorithm::EccP256, Some(HashAlgorithm::Sha256)).unwrap();
        let csr_der = assemble_csr(&cri, algorithm, signature.to_der().as_bytes()).unwrap();
        let csr = CertReq::from_der(&csr_der).unwrap();
        assert!(csr.info.subject.to_string().contains("CN=csr"));
        assert_eq!(csr.info.public_key.to_der().unwrap(), spki.as_bytes());
        // The signature verifies against the request contents.
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        let verifying = p256::ecdsa::VerifyingKey::from(&public);
        verifying
            .verify_prehash(&digest, &signature)
            .expect("verifies");
    }
}
