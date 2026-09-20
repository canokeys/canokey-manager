//! PKCS#12 (PFX, RFC 7292) bundle parsing for key/certificate import.
//!
//! Supports the interoperable subset modern OpenSSL emits: plaintext or
//! PBES2-encrypted SafeContents, PKCS#8 key bags, shrouded key bags and
//! X.509 cert bags, with password-integrity MAC verification. Legacy
//! PKCS#12 PBE (`pbeWithSHA1And*`, e.g. LibreSSL `pkcs12 -export` output)
//! is rejected as unsupported rather than decrypted with obsolete ciphers.

use der::asn1::{ObjectIdentifier, OctetStringRef};
use der::{Decode, Encode, Sequence};
use hmac::{Hmac, Mac};
use zeroize::Zeroizing;

use super::{from_pkcs8, ImportedKey, KeyError};

const OID_DATA: &str = "1.2.840.113549.1.7.1";
const OID_ENCRYPTED_DATA: &str = "1.2.840.113549.1.7.6";
const OID_KEY_BAG: &str = "1.2.840.113549.1.12.10.1.1";
const OID_SHROUDED_KEY_BAG: &str = "1.2.840.113549.1.12.10.1.2";
const OID_CERT_BAG: &str = "1.2.840.113549.1.12.10.1.3";
const OID_X509_CERT: &str = "1.2.840.113549.1.9.22.1";

/// Bound on password-stretching work accepted from a file.
const MAX_ITERATIONS: u32 = 10_000_000;

#[derive(Sequence)]
struct Pfx<'a> {
    version: u8,
    auth_safe: ContentInfo<'a>,
    mac_data: Option<MacData<'a>>,
}

#[derive(Sequence)]
struct ContentInfo<'a> {
    content_type: ObjectIdentifier,
    #[asn1(context_specific = "0")]
    content: der::AnyRef<'a>,
}

#[derive(Sequence)]
struct MacData<'a> {
    mac: DigestInfo<'a>,
    mac_salt: OctetStringRef<'a>,
    iterations: Option<u32>,
}

#[derive(Sequence)]
struct DigestInfo<'a> {
    algorithm: spki::AlgorithmIdentifierRef<'a>,
    digest: OctetStringRef<'a>,
}

#[derive(Sequence)]
struct SafeBag<'a> {
    bag_id: ObjectIdentifier,
    #[asn1(context_specific = "0")]
    bag_value: der::AnyRef<'a>,
    attributes: Option<der::AnyRef<'a>>,
}

#[derive(Sequence)]
struct CertBag<'a> {
    cert_id: ObjectIdentifier,
    #[asn1(context_specific = "0")]
    cert_value: der::AnyRef<'a>,
}

#[derive(Sequence)]
struct EncryptedData<'a> {
    version: u8,
    content: EncryptedContentInfo<'a>,
}

#[derive(Sequence)]
struct EncryptedContentInfo<'a> {
    content_type: ObjectIdentifier,
    encryption: spki::AlgorithmIdentifierRef<'a>,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    encrypted_content: Option<OctetStringRef<'a>>,
}

/// A parsed PKCS#12 bundle: the first private key and every X.509
/// certificate found, in file order.
#[derive(Debug)]
pub struct PfxData {
    /// First key/pkcs8-shrouded key bag, when present.
    pub key: Option<ImportedKey>,
    /// DER of every X.509 cert bag, in file order.
    pub certificates: Vec<Vec<u8>>,
}

/// Digest algorithms accepted for the PFX MAC (RFC 7292 B.2 KDF).
#[derive(Clone, Copy)]
enum MacDigest {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl MacDigest {
    fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        match oid.to_string().as_str() {
            "1.3.14.3.2.26" => Some(Self::Sha1),
            "2.16.840.1.101.3.4.2.1" => Some(Self::Sha256),
            "2.16.840.1.101.3.4.2.2" => Some(Self::Sha384),
            "2.16.840.1.101.3.4.2.3" => Some(Self::Sha512),
            _ => None,
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        use sha2::Digest as _;
        match self {
            Self::Sha1 => sha1::Sha1::digest(data).to_vec(),
            Self::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(data).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }

    fn hmac_verify(self, key: &[u8], data: &[u8], expected: &[u8]) -> bool {
        use hmac::Mac as _;
        macro_rules! verify {
            ($digest:ty) => {{
                let mut mac = <Hmac<$digest> as Mac>::new_from_slice(key)
                    .expect("HMAC accepts any key length");
                mac.update(data);
                mac.verify_slice(expected).is_ok()
            }};
        }
        match self {
            Self::Sha1 => verify!(sha1::Sha1),
            Self::Sha256 => verify!(sha2::Sha256),
            Self::Sha384 => verify!(sha2::Sha384),
            Self::Sha512 => verify!(sha2::Sha512),
        }
    }

    fn out_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    fn block_len(self) -> usize {
        match self {
            Self::Sha1 | Self::Sha256 => 64,
            Self::Sha384 | Self::Sha512 => 128,
        }
    }

    /// The RFC 7292 B.2 password-based KDF over an already-BMPString'd
    /// password: diversifier `id`, blockwise I update after each round.
    fn kdf(self, id: u8, bmp: &[u8], salt: &[u8], iterations: u32, out_len: usize) -> Vec<u8> {
        let v = self.block_len();
        // Repeat material to a multiple of v; empty material stays empty.
        let fill = |material: &[u8]| -> Vec<u8> {
            if material.is_empty() {
                return Vec::new();
            }
            material
                .iter()
                .copied()
                .cycle()
                .take(v * material.len().div_ceil(v))
                .collect()
        };
        let d = vec![id; v];
        let s = fill(salt);
        let p = fill(bmp);
        let mut i = [s, p].concat();
        let mut out = Vec::new();
        while out.len() < out_len {
            let mut a = self.digest(&[d.as_slice(), i.as_slice()].concat());
            for _ in 1..iterations {
                a = self.digest(&a);
            }
            out.extend_from_slice(&a);
            // I_j = (I_j + B + 1) mod 2^(8v) with B = A repeated to v.
            let b: Vec<u8> = a.iter().copied().cycle().take(v).collect();
            for block in i.chunks_mut(v) {
                let mut carry = 1u16;
                for (byte, add) in block.iter_mut().rev().zip(b.iter().rev()) {
                    let sum = u16::from(*byte) + u16::from(*add) + carry;
                    *byte = sum as u8;
                    carry = sum >> 8;
                }
            }
        }
        out.truncate(out_len);
        out
    }
}

fn verify_mac(
    mac_data: &MacData<'_>,
    auth_safe_der: &[u8],
    password: Option<&[u8]>,
) -> Result<(), KeyError> {
    let digest = MacDigest::from_oid(&mac_data.mac.algorithm.oid).ok_or(KeyError::Unsupported)?;
    let iterations = mac_data.iterations.unwrap_or(1);
    if iterations == 0 || iterations > MAX_ITERATIONS {
        return Err(KeyError::Encoding);
    }
    let password_bytes = password.unwrap_or(b"");
    let mut bmp = Zeroizing::new(Vec::new());
    for unit in String::from_utf8_lossy(password_bytes).encode_utf16() {
        bmp.extend_from_slice(&unit.to_be_bytes());
    }
    bmp.extend_from_slice(&[0, 0]);
    let verifies = |material: &[u8]| {
        let key = Zeroizing::new(digest.kdf(
            3,
            material,
            mac_data.mac_salt.as_bytes(),
            iterations,
            digest.out_len(),
        ));
        digest.hmac_verify(&key, auth_safe_der, mac_data.mac.digest.as_bytes())
    };
    if verifies(&bmp) {
        return Ok(());
    }
    // Empty-password quirk: OpenSSL derives the MAC key from zero-length
    // material rather than the two-byte BMPString terminator, and accepts
    // both on parse; do the same.
    if password_bytes.is_empty() && verifies(b"") {
        return Ok(());
    }
    // With no password the caller may still supply one; with one, the file
    // fails integrity and retrying the same password cannot help.
    if password.is_none() {
        Err(KeyError::Password)
    } else {
        Err(KeyError::MacMismatch)
    }
}

fn safe_contents(
    info: &ContentInfo<'_>,
    password: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    match info.content_type.to_string().as_str() {
        OID_DATA => {
            let octets = info
                .content
                .decode_as::<OctetStringRef>()
                .map_err(|_| KeyError::Encoding)?;
            Ok(Zeroizing::new(octets.as_bytes().to_vec()))
        }
        OID_ENCRYPTED_DATA => {
            let data = info
                .content
                .decode_as::<EncryptedData>()
                .map_err(|_| KeyError::Encoding)?;
            if data.version != 0 || data.content.content_type.to_string() != OID_DATA {
                return Err(KeyError::Encoding);
            }
            // Empty password is legitimate in PKCS#12: attempt it, and let a
            // decryption failure surface as a password request.
            let password = password.unwrap_or(b"");
            // pkcs5 handles PBES2; legacy PKCS#12 PBE schemes fail here.
            let scheme = pkcs5::EncryptionScheme::try_from(data.content.encryption)
                .map_err(|_| KeyError::Unsupported)?;
            let ciphertext = data.content.encrypted_content.ok_or(KeyError::Encoding)?;
            let plaintext = scheme
                .decrypt(password, ciphertext.as_bytes())
                .map_err(|_| KeyError::Password)?;
            Ok(Zeroizing::new(plaintext))
        }
        _ => Err(KeyError::Unsupported),
    }
}

fn collect_bags(
    contents: &[u8],
    password: Option<&[u8]>,
    data: &mut PfxData,
) -> Result<(), KeyError> {
    let bags = Vec::<SafeBag<'_>>::from_der(contents).map_err(|_| KeyError::Encoding)?;
    for bag in bags {
        let _ = bag.attributes;
        match bag.bag_id.to_string().as_str() {
            OID_KEY_BAG if data.key.is_none() => {
                let der = bag.bag_value.to_der().map_err(|_| KeyError::Encoding)?;
                data.key = Some(from_pkcs8(&der)?);
            }
            OID_SHROUDED_KEY_BAG if data.key.is_none() => {
                // Empty password is legitimate in PKCS#12 (see safe_contents).
                let encrypted = bag
                    .bag_value
                    .decode_as::<pkcs8::EncryptedPrivateKeyInfo<'_>>()
                    .map_err(|_| KeyError::Encoding)?;
                let decrypted = encrypted
                    .decrypt(password.unwrap_or(b""))
                    .map_err(|_| KeyError::Password)?;
                data.key = Some(from_pkcs8(decrypted.as_bytes())?);
            }
            OID_CERT_BAG => {
                let cert: CertBag<'_> =
                    bag.bag_value.decode_as().map_err(|_| KeyError::Encoding)?;
                if cert.cert_id.to_string() != OID_X509_CERT {
                    continue;
                }
                let octets = cert
                    .cert_value
                    .decode_as::<OctetStringRef>()
                    .map_err(|_| KeyError::Encoding)?;
                data.certificates.push(octets.as_bytes().to_vec());
            }
            // Extra keys and CRL/secret bags carry nothing importable here.
            _ => {}
        }
    }
    Ok(())
}

/// Parse a PKCS#12 bundle, verifying the MAC when present and decrypting
/// password-protected content. `Encoding` means the input is not a PFX at
/// all (callers may fall through to other formats).
pub fn parse_pfx(input: &[u8], password: Option<&[u8]>) -> Result<PfxData, KeyError> {
    let pfx = Pfx::from_der(input).map_err(|_| KeyError::Encoding)?;
    if pfx.version != 3 || pfx.auth_safe.content_type.to_string() != OID_DATA {
        return Err(KeyError::Encoding);
    }
    let auth_safe = pfx
        .auth_safe
        .content
        .decode_as::<OctetStringRef>()
        .map_err(|_| KeyError::Encoding)?;
    if let Some(mac_data) = &pfx.mac_data {
        verify_mac(mac_data, auth_safe.as_bytes(), password)?;
    }
    let infos =
        Vec::<ContentInfo<'_>>::from_der(auth_safe.as_bytes()).map_err(|_| KeyError::Encoding)?;
    let mut data = PfxData {
        key: None,
        certificates: Vec::new(),
    };
    for info in &infos {
        let contents = safe_contents(info, password)?;
        collect_bags(&contents, password, &mut data)?;
    }
    if data.key.is_none() && data.certificates.is_empty() {
        return Err(KeyError::Encoding);
    }
    Ok(data)
}

/// The private key of a PKCS#12 bundle; `Encoding` when the input is not a
/// PFX or holds no key.
pub(super) fn key_from_pfx(input: &[u8], password: Option<&[u8]>) -> Result<ImportedKey, KeyError> {
    parse_pfx(input, password)?.key.ok_or(KeyError::Encoding)
}

/// Every X.509 certificate of a PKCS#12 bundle, in file order.
pub fn certificates_from_pfx(
    input: &[u8],
    password: Option<&[u8]>,
) -> Result<Vec<Vec<u8>>, KeyError> {
    let data = parse_pfx(input, password)?;
    if data.certificates.is_empty() {
        return Err(KeyError::Encoding);
    }
    Ok(data.certificates)
}

/// The index of the leaf certificate in a bundle: the one whose subject no
/// other certificate in the set issues. `AmbiguousCertificates` when the
/// leaf cannot be determined (callers should ask for an extracted file).
pub fn leaf_certificate(certificates: &[Vec<u8>]) -> Result<usize, KeyError> {
    if certificates.len() == 1 {
        return Ok(0);
    }
    let names: Vec<(Vec<u8>, Vec<u8>)> = certificates
        .iter()
        .map(|der| {
            let cert = x509_cert::Certificate::from_der(der).map_err(|_| KeyError::Encoding)?;
            let subject = cert.tbs_certificate.subject.to_der();
            let issuer = cert.tbs_certificate.issuer.to_der();
            Ok((
                subject.map_err(|_| KeyError::Encoding)?,
                issuer.map_err(|_| KeyError::Encoding)?,
            ))
        })
        .collect::<Result<_, KeyError>>()?;
    let mut leafs = names
        .iter()
        .enumerate()
        .filter(|(i, (subject, _))| {
            !names
                .iter()
                .enumerate()
                .any(|(j, (_, issuer))| i != &j && issuer == subject)
        })
        .map(|(i, _)| i);
    match (leafs.next(), leafs.next()) {
        (Some(leaf), None) => Ok(leaf),
        _ => Err(KeyError::AmbiguousCertificates),
    }
}
