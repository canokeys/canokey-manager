//! Host-side X.509 building: RFC 4514 subject parsing, self-signed
//! certificate and CSR assembly, hashing and RSA PKCS#1 v1.5 padding.
//!
//! The private-key operation itself runs on the CanoKey; this module only
//! prepares the to-be-signed bytes and assembles the final object (the TBS is
//! built directly and signed exactly once).

use canokey::piv::Algorithm;
use der::asn1::{Any, BitString, GeneralizedTime, ObjectIdentifier, SetOfVec, UtcTime};
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
    /// A timestamp is outside the supported ASN.1 time range (1970-9999).
    #[error("timestamp out of ASN.1 time range")]
    TimeRange,
    /// The certificate expires before it becomes valid.
    #[error("certificate validity ends before it starts")]
    InvalidValidity,
    /// The certificate's inner and outer signature identifiers differ.
    #[error("certificate signature algorithm does not match its TBS identifier")]
    SignatureAlgorithmMismatch,
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

/// Signature algorithm identifier for a key algorithm and hash.
/// Ed25519 takes no hash (PureEdDSA).
pub fn signature_algorithm(
    key: Algorithm,
    hash: Option<HashAlgorithm>,
) -> Result<AlgorithmIdentifier, X509Error> {
    let oid = match (key, hash) {
        (Algorithm::Ed25519, None) => "1.3.101.112",
        // SM2 signs SM3(ZA || M); no hash parameter.
        (Algorithm::Sm2, None) => "1.2.156.10197.1.501",
        // ML-DSA-65, empty context; parameters are absent by definition.
        (Algorithm::MlDsa65, None) => "2.16.840.1.101.3.4.3.18",
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

const NAME_ATTRIBUTES: [(&str, &str); 11] = [
    ("CN", "2.5.4.3"),
    ("L", "2.5.4.7"),
    ("ST", "2.5.4.8"),
    ("O", "2.5.4.10"),
    ("OU", "2.5.4.11"),
    ("C", "2.5.4.6"),
    ("STREET", "2.5.4.9"),
    ("DC", "0.9.2342.19200300.100.1.25"),
    ("UID", "0.9.2342.19200300.100.1.1"),
    ("serialNumber", "2.5.4.5"),
    ("emailAddress", "1.2.840.113549.1.9.1"),
];

/// Parse an RFC 4514 string into an X.501 Name: `,` separates RDNs, `+`
/// separates multi-valued RDN attributes, and `\` escapes special characters
/// or introduces `\XX` UTF-8 bytes. A leading unescaped `#` carries a complete
/// DER attribute value in hexadecimal. RDNs are reversed into DER order.
pub fn parse_rfc4514(value: &str) -> Result<Name, X509Error> {
    let invalid = |msg: &str| X509Error::Rfc4514(msg.to_string());
    let mut rdns = Vec::new();
    let mut attributes = SetOfVec::new();
    let mut start = 0;
    let mut escaped = false;
    // Keep escapes intact until the attribute type and value are separated.
    // Tracking every backslash also handles any number of consecutive escapes.
    for (index, c) in value.char_indices().chain([(value.len(), ',')]) {
        if escaped {
            escaped = false;
            if index != value.len() {
                continue;
            }
            return Err(invalid("trailing backslash"));
        }
        match c {
            '\\' => escaped = true,
            ',' | '+' => {
                let part = &value[start..index];
                let (key, value) = part
                    .split_once('=')
                    .ok_or_else(|| invalid("missing '=' in attribute"))?;
                let oid = NAME_ATTRIBUTES
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case(key))
                    .map(|(_, oid)| *oid)
                    .unwrap_or(key);
                let oid =
                    ObjectIdentifier::new(oid).map_err(|_| invalid("unsupported attribute"))?;
                let value = subject_value(oid, value)?;
                attributes
                    .insert(AttributeTypeAndValue { oid, value })
                    .map_err(der)?;
                start = index + 1;
                if c == ',' {
                    rdns.push(RelativeDistinguishedName(std::mem::take(&mut attributes)));
                }
            }
            _ => {}
        }
    }
    rdns.reverse();
    Ok(Name::from(RdnSequence::from(rdns)))
}

fn subject_value(oid: ObjectIdentifier, value: &str) -> Result<Any, X509Error> {
    use der::asn1::{Ia5StringRef, PrintableStringRef, Utf8StringRef};
    let invalid = |msg: &str| X509Error::Rfc4514(msg.to_string());
    let encoded = if let Some(hex) = value.strip_prefix('#') {
        if hex.is_empty() || hex.len() % 2 != 0 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(invalid("invalid hexadecimal DER attribute value"));
        }
        let bytes = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("hex is ASCII"), 16)
                    .expect("hex digits checked")
            })
            .collect::<Vec<_>>();
        Any::from_der(&bytes).map_err(|_| invalid("invalid DER attribute value"))?
    } else {
        let bytes = value.as_bytes();
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            let byte = bytes[index];
            if byte == b'\\' {
                index += 1;
                let escaped = *bytes
                    .get(index)
                    .ok_or_else(|| invalid("trailing backslash"))?;
                if b"\\\"#+,;<> =".contains(&escaped) {
                    decoded.push(escaped);
                } else {
                    let pair = bytes
                        .get(index..index + 2)
                        .ok_or_else(|| invalid("truncated hex escape"))?;
                    if !pair.iter().all(u8::is_ascii_hexdigit) {
                        return Err(invalid("invalid hex escape"));
                    }
                    decoded.push(
                        u8::from_str_radix(std::str::from_utf8(pair).expect("hex is ASCII"), 16)
                            .expect("hex digits checked"),
                    );
                    index += 1;
                }
            } else {
                if b"\";<>\0".contains(&byte)
                    || (byte == b' ' && (index == 0 || index + 1 == bytes.len()))
                {
                    return Err(invalid("special or boundary character must be escaped"));
                }
                decoded.push(byte);
            }
            index += 1;
        }
        let text = std::str::from_utf8(&decoded).map_err(|_| invalid("invalid UTF-8 data"))?;
        match oid.to_string().as_str() {
            "2.5.4.6" | "2.5.4.5" => Any::encode_from(&PrintableStringRef::new(text).map_err(der)?),
            "0.9.2342.19200300.100.1.25" | "1.2.840.113549.1.9.1" => {
                Any::encode_from(&Ia5StringRef::new(text).map_err(der)?)
            }
            _ => Any::encode_from(&Utf8StringRef::new(text).map_err(der)?),
        }
        .map_err(der)?
    };
    // ANY preserves the tag; validate the contents of supported string types.
    use der::Tagged;
    match encoded.tag() {
        der::Tag::Utf8String => {
            encoded.decode_as::<Utf8StringRef>().map_err(der)?;
        }
        der::Tag::PrintableString => {
            encoded.decode_as::<PrintableStringRef>().map_err(der)?;
        }
        der::Tag::Ia5String => {
            encoded.decode_as::<Ia5StringRef>().map_err(der)?;
        }
        _ => {}
    }
    // Hexadecimal input must obey the same fixed attribute types as text.
    match oid.to_string().as_str() {
        "2.5.4.6" => {
            let country = encoded.decode_as::<PrintableStringRef>().map_err(der)?;
            if country.as_str().len() != 2 {
                return Err(invalid("country must contain two characters"));
            }
        }
        "2.5.4.5" => {
            encoded.decode_as::<PrintableStringRef>().map_err(der)?;
        }
        "0.9.2342.19200300.100.1.25" | "1.2.840.113549.1.9.1" => {
            encoded.decode_as::<Ia5StringRef>().map_err(der)?;
        }
        _ => {}
    }
    Ok(encoded)
}

fn time(unix_seconds: i64) -> Result<Time, X509Error> {
    let duration =
        Duration::from_secs(u64::try_from(unix_seconds).map_err(|_| X509Error::TimeRange)?);
    let generalized =
        GeneralizedTime::from_unix_duration(duration).map_err(|_| X509Error::TimeRange)?;
    if generalized.to_date_time().year() < 2050 {
        Ok(Time::UtcTime(
            UtcTime::from_unix_duration(duration).map_err(|_| X509Error::TimeRange)?,
        ))
    } else {
        Ok(Time::GeneralTime(generalized))
    }
}

/// Validate and encode a certificate validity interval, in Unix seconds.
/// Both endpoints must be in 1970-9999 and the end must not precede the start.
pub fn validity(not_before: i64, not_after: i64) -> Result<Validity, X509Error> {
    if not_after < not_before {
        return Err(X509Error::InvalidValidity);
    }
    Ok(Validity {
        not_before: time(not_before)?,
        not_after: time(not_after)?,
    })
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
        validity: validity(not_before, not_after)?,
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
    let tbs_certificate = TbsCertificate::from_der(tbs_der).map_err(der)?;
    if tbs_certificate.signature != signature_algorithm {
        return Err(X509Error::SignatureAlgorithmMismatch);
    }
    let certificate = Certificate {
        tbs_certificate,
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
    use der::Tagged;

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
                let value = std::str::from_utf8(attr.value.value()).unwrap();
                attrs.push(format!("{label}={value}"));
            }
            parts.push(attrs.join("+"));
        }
        parts.join(",")
    }

    #[test]
    fn validity_accepts_inclusive_endpoints_and_enforces_time_range() {
        assert!(validity(0, 0).is_ok());
        assert!(validity(0, 253_402_300_799).is_ok()); // 9999-12-31 23:59:59 UTC
        assert!(matches!(validity(-1, 0), Err(X509Error::TimeRange)));
        assert!(matches!(
            validity(0, 253_402_300_800),
            Err(X509Error::TimeRange)
        ));
        assert!(matches!(validity(1, 0), Err(X509Error::InvalidValidity)));
    }

    #[test]
    fn certificate_time_switches_encoding_at_2050() {
        let last_utc = time(2_524_607_999).unwrap(); // 2049-12-31 23:59:59 UTC
        let first_general = time(2_524_608_000).unwrap();
        assert!(matches!(last_utc, Time::UtcTime(_)));
        assert!(matches!(first_general, Time::GeneralTime(_)));
        assert_eq!(last_utc.to_der().unwrap()[0], 0x17);
        assert_eq!(first_general.to_der().unwrap()[0], 0x18);
        assert_eq!(
            Time::from_der(&first_general.to_der().unwrap()).unwrap(),
            first_general
        );
        assert!(time(-1).is_err());
        assert!(time(i64::MAX).is_err());
    }

    #[test]
    fn subject_attributes_use_their_asn1_types() {
        for (subject, tag) in [
            ("c=SG", der::Tag::PrintableString),
            ("2.5.4.6=US", der::Tag::PrintableString),
            ("dc=example", der::Tag::Ia5String),
            ("cn=示例", der::Tag::Utf8String),
        ] {
            let name = parse_rfc4514(subject).unwrap();
            let attr = name.0[0].0.iter().next().unwrap();
            assert_eq!(attr.value.tag(), tag, "{subject}");
        }
        for bad in ["C=Singapore", "C=é", "DC=示例"] {
            assert!(parse_rfc4514(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn subject_encoding_matches_openssl() {
        // Independent OpenSSL 3.5.9 subject with mixed ASN.1 string types,
        // a multi-valued RDN, and escaped punctuation/backslashes.
        let text = include_str!("../tests/fixtures/subject-openssl.txt").trim_end();
        let expected = include_bytes!("../tests/fixtures/subject-openssl.der");
        assert_eq!(parse_rfc4514(text).unwrap().to_der().unwrap(), expected);
    }

    #[test]
    fn rfc4514_hex_values_preserve_their_der_meaning() {
        let decoded = parse_rfc4514("CN=#0c03666f6f,O=Example,C=#13025347").unwrap();
        assert_eq!(decoded, parse_rfc4514("CN=foo,O=Example,C=SG").unwrap());
        assert_eq!(
            rfc4514_text(&parse_rfc4514(r"CN=\#0c03666f6f").unwrap()),
            "CN=#0c03666f6f"
        );
        let name = parse_rfc4514("1.2.3.4=#0403ff0001").unwrap();
        assert_eq!(
            name.0[0].0.iter().next().unwrap().value.to_der().unwrap(),
            [0x04, 0x03, 0xff, 0, 1]
        );
        for bad in [
            "CN=#",
            "CN=#0",
            "CN=#zz",
            "CN=#0c0366",
            "CN=#0c016100",
            "CN=#0c01ff",
            "C=#0c025347",
        ] {
            assert!(parse_rfc4514(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn rfc4514_escapes_are_decoded_after_splitting() {
        for (encoded, text) in [
            (r"CN=a\;b", "CN=a;b"),
            (r"CN=a\=b", "CN=a=b"),
            (r"CN=\ leading\ ", "CN= leading "),
            (r"CN=\20leading\20", "CN= leading "),
            (r"CN=a\\\,b,O=Example", "CN=a\\,b,O=Example"),
            (r"CN=a\\,O=Example", "CN=a\\,O=Example"),
            (r"CN=\c3\a5\e4\b8\ad", "CN=å中"),
        ] {
            assert_eq!(
                rfc4514_text(&parse_rfc4514(encoded).unwrap()),
                text,
                "{encoded}"
            );
        }
        for bad in [
            r"CN=a\",
            r"CN=\c3,OU=\a5",
            r"CN=\ff",
            r"CN=\0",
            r"CN=\qz",
            "CN= leading",
            "CN=trailing ",
            "CN=a;b",
            "CN=a\0b",
            r"CN=a\'b",
        ] {
            assert!(parse_rfc4514(bad).is_err(), "{bad:?}");
        }
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

    #[test]
    fn certificate_builder_rejects_reversed_validity() {
        let public = include_bytes!("../tests/fixtures/rsa-export-verify-openssl-pub.der");
        let subject = parse_rfc4514("CN=audit").unwrap();
        let algorithm =
            signature_algorithm(Algorithm::Rsa2048, Some(HashAlgorithm::Sha256)).unwrap();
        assert!(tbs_self_signed(
            public,
            &subject,
            &[1],
            1_800_000_000,
            1_700_000_000,
            algorithm
        )
        .is_err());
    }

    #[test]
    fn certificate_builder_rejects_inconsistent_signature_identifiers() {
        let public = include_bytes!("../tests/fixtures/rsa-export-verify-openssl-pub.der");
        let subject = parse_rfc4514("CN=audit").unwrap();
        let inner = signature_algorithm(Algorithm::Rsa2048, Some(HashAlgorithm::Sha256)).unwrap();
        let outer = signature_algorithm(Algorithm::Rsa2048, Some(HashAlgorithm::Sha384)).unwrap();
        let tbs = tbs_self_signed(
            public,
            &subject,
            &[1],
            1_700_000_000,
            1_800_000_000,
            inner.clone(),
        )
        .unwrap();
        assert!(assemble_certificate(&tbs, outer, &[0; 256]).is_err());
        let mut different_parameters = inner;
        different_parameters.parameters = None;
        assert!(assemble_certificate(&tbs, different_parameters, &[0; 256]).is_err());
    }

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
