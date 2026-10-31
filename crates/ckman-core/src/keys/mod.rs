//! Host-side key file parsing for PIV import/export: PEM armor, PKCS#8
//! (plain and encrypted), PKCS#1 RSA, SEC1 EC and PKCS#12 bundles, and SPKI
//! or PKCS#1 public keys. Output is libcanokey's typed private-key material;
//! no key bytes are retained beyond it.

use canokey::piv::{Algorithm, PrivateKeyMaterial};
use canokey::SecretBytes;
use der::asn1::{ObjectIdentifier, OctetStringRef};
use der::{Decode, Encode};
use zeroize::Zeroizing;

mod pfx;
mod pq;

pub use pfx::{certificates_from_pfx, leaf_certificate, parse_pfx, PfxData};

/// Key-file parsing failure.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// The PEM armor is malformed or carries an unexpected label.
    #[error("invalid or unsupported PEM block")]
    Pem,
    /// The key encoding or its fields are invalid or not recognized.
    #[error("invalid or unrecognized key encoding")]
    Encoding,
    /// The key type or curve is not usable in a PIV slot.
    #[error("unsupported key type")]
    Unsupported,
    /// The file uses a password-based encryption scheme we cannot decrypt.
    #[error("unsupported private key encryption scheme; re-export using PBES2")]
    UnsupportedEncryption,
    /// The key needs a password, or the supplied password is wrong.
    #[error("cannot decrypt the private key (wrong or missing password?)")]
    Password,
    /// The RSA key does not use the firmware-implied public exponent 65537.
    #[error("only RSA keys with public exponent 65537 are supported")]
    RsaExponent,
    /// The PKCS#12 password-integrity MAC does not match.
    #[error("PKCS#12 integrity check failed (wrong password or corrupted file?)")]
    MacMismatch,
    /// A PKCS#12 bundle holds several certificates and the leaf is ambiguous.
    #[error("several certificates in the bundle; extract the one to import")]
    AmbiguousCertificates,
}

/// Parsed key material in a neutral form; convert to the applet-specific
/// import shape with [`ImportedKey::piv_material`] or
/// [`ImportedKey::openpgp_key`].
enum Material {
    /// RSA CRT components; OpenPGP also wants the four-byte public exponent.
    Rsa {
        exponent: [u8; 4],
        p: Zeroizing<Vec<u8>>,
        q: Zeroizing<Vec<u8>>,
        dp: Zeroizing<Vec<u8>>,
        dq: Zeroizing<Vec<u8>>,
        qinv: Zeroizing<Vec<u8>>,
    },
    /// EC scalar, Ed25519 seed or X25519 private bytes (algorithm implied by
    /// the surrounding [`ImportedKey`]).
    Ec(Zeroizing<Vec<u8>>),
}

/// A parsed private key: its algorithm and neutral material.
/// Debug output redacts the private material.
pub struct ImportedKey {
    /// Detected algorithm.
    pub algorithm: Algorithm,
    material: Material,
}

impl std::fmt::Debug for ImportedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportedKey")
            .field("algorithm", &self.algorithm)
            .field("material", &"[REDACTED]")
            .finish()
    }
}

impl ImportedKey {
    /// PIV import material. The PIV applet implies public exponent 65537;
    /// other exponents are rejected here rather than silently mismatched.
    pub fn piv_material(&self) -> Result<PrivateKeyMaterial, KeyError> {
        match &self.material {
            Material::Rsa {
                exponent,
                p,
                q,
                dp,
                dq,
                qinv,
            } => {
                if exponent != &[0, 1, 0, 1] {
                    return Err(KeyError::RsaExponent);
                }
                PrivateKeyMaterial::rsa_crt(
                    self.algorithm,
                    [p, q, dp, dq, qinv].map(|v| v.as_slice()),
                )
                .map_err(|_| KeyError::Encoding)
            }
            Material::Ec(bytes) => match self.algorithm {
                Algorithm::Ed25519 => PrivateKeyMaterial::ed25519_seed(bytes),
                Algorithm::X25519 => PrivateKeyMaterial::x25519_key(bytes),
                Algorithm::MlDsa65 => PrivateKeyMaterial::mldsa65_seed(bytes),
                Algorithm::MlKem768 => PrivateKeyMaterial::mlkem768_seed(bytes),
                _ => PrivateKeyMaterial::ec_scalar(self.algorithm, bytes),
            }
            .map_err(|_| KeyError::Encoding),
        }
    }

    /// OpenPGP import material (4D/7F48/5F48 CRT framing is libcanokey's).
    /// Components are left-padded to the half-modulus width the card expects.
    /// X25519 PKCS#8 bytes are decoded to a clamped big-endian card scalar.
    pub fn openpgp_key(&self) -> Result<canokey::openpgp::PrivateKey, KeyError> {
        let pad = |bytes: &Zeroizing<Vec<u8>>, width: usize| -> Result<SecretBytes, KeyError> {
            if bytes.len() > width {
                return Err(KeyError::Encoding);
            }
            let mut padded = SecretBytes::new(vec![0; width - bytes.len()]);
            padded.extend(bytes);
            Ok(padded)
        };
        match &self.material {
            Material::Rsa {
                exponent,
                p,
                q,
                dp,
                dq,
                qinv,
            } => {
                let width = match self.algorithm {
                    Algorithm::Rsa1024 => 128,
                    Algorithm::Rsa2048 => 256,
                    Algorithm::Rsa3072 => 384,
                    Algorithm::Rsa4096 => 512,
                    _ => return Err(KeyError::Unsupported),
                } / 2;
                Ok(canokey::openpgp::PrivateKey::Rsa {
                    exponent: *exponent,
                    p: pad(p, width)?,
                    q: pad(q, width)?,
                    q_inverse: pad(qinv, width)?,
                    d_p: pad(dp, width)?,
                    d_q: pad(dq, width)?,
                })
            }
            Material::Ec(bytes) => {
                let mut scalar = Zeroizing::new(bytes.to_vec());
                if self.algorithm == Algorithm::X25519 {
                    if scalar.len() != 32 {
                        return Err(KeyError::Encoding);
                    }
                    // RFC 7748 decoding precedes the card's big-endian MPI ABI.
                    scalar[0] &= 0xf8;
                    scalar[31] = (scalar[31] & 0x7f) | 0x40;
                    scalar.reverse();
                }
                Ok(canokey::openpgp::PrivateKey::Ec(SecretBytes::new(
                    scalar.to_vec(),
                )))
            }
        }
    }
}

/// A parsed public key: its PIV algorithm and SPKI DER.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedPublicKey {
    /// Detected algorithm.
    pub algorithm: Algorithm,
    /// Complete SubjectPublicKeyInfo DER.
    pub spki_der: Vec<u8>,
}

/// Extract the first PEM block whose label is in `labels`, or pass DER
/// through unchanged. Blocks with other labels (a certificate bundled with
/// a key, a key bundled with a certificate) are skipped, so block order in
/// a combined file does not matter.
pub fn pem_decode(input: &[u8], labels: &[&str]) -> Result<(String, Vec<u8>), KeyError> {
    use base64ct::{Base64, Encoding as _};
    let text = match std::str::from_utf8(input) {
        Ok(text) if text.contains("-----BEGIN") => text,
        _ => return Ok((String::new(), input.to_vec())),
    };
    let mut cursor = 0;
    while let Some(at) = text[cursor..].find("-----BEGIN ") {
        let begin = cursor + at + "-----BEGIN ".len();
        let label_end = text[begin..].find("-----").ok_or(KeyError::Pem)?;
        let label = &text[begin..begin + label_end];
        let end_marker = format!("-----END {label}-----");
        let block_end = text[begin + label_end..]
            .find(&end_marker)
            .map(|i| begin + label_end + i + end_marker.len())
            .ok_or(KeyError::Pem)?;
        if !labels.contains(&label) {
            cursor = block_end;
            continue;
        }
        let body_start = text[begin + label_end..]
            .find('\n')
            .map(|i| begin + label_end + i + 1)
            .ok_or(KeyError::Pem)?;
        let end = text[body_start..].find(&end_marker).ok_or(KeyError::Pem)?;
        let mut body = Zeroizing::new(String::with_capacity(end));
        body.extend(
            text[body_start..body_start + end]
                .chars()
                .filter(|c| !c.is_whitespace()),
        );
        let mut decoded = Zeroizing::new(vec![0; body.len()]);
        let length = Base64::decode(body.as_bytes(), &mut decoded)
            .map_err(|_| KeyError::Pem)?
            .len();
        decoded.truncate(length);
        return Ok((label.to_string(), std::mem::take(&mut *decoded)));
    }
    Err(KeyError::Pem)
}

fn rsa_material(key: &rsa::RsaPrivateKey) -> Result<Material, KeyError> {
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    use rsa::BigUint;
    let primes = key.primes();
    if primes.len() != 2 {
        return Err(KeyError::Unsupported);
    }
    let one = BigUint::from(1u32);
    let (p, q) = (&primes[0], &primes[1]);
    // Both PIV and OpenPGP want p, q, dP, dQ, qInv (q^{-1} mod p).
    let d = key.d();
    let dp = Zeroizing::new(d % (p - &one));
    let dq = Zeroizing::new(d % (q - &one));
    let qinv = Zeroizing::new(key.crt_coefficient().ok_or(KeyError::Encoding)?);
    let bytes = |v: &BigUint| Zeroizing::new(v.to_bytes_be());
    let exponent_bytes = key.e().to_bytes_be();
    if exponent_bytes.len() > 4 {
        return Err(KeyError::Unsupported);
    }
    let mut exponent = [0; 4];
    exponent[4 - exponent_bytes.len()..].copy_from_slice(&exponent_bytes);
    Ok(Material::Rsa {
        exponent,
        p: bytes(p),
        q: bytes(q),
        dp: bytes(&dp),
        dq: bytes(&dq),
        qinv: bytes(&qinv),
    })
}

/// SEC1 ECPrivateKey, including its optional curve and public point.
#[derive(der::Sequence)]
struct EcPrivateKey<'a> {
    version: u8,
    private_key: OctetStringRef<'a>,
    #[asn1(context_specific = "0", optional = "true")]
    parameters: Option<ObjectIdentifier>,
    #[asn1(context_specific = "1", optional = "true")]
    public_key: Option<der::asn1::BitStringRef<'a>>,
}

fn from_sec1(der_bytes: &[u8]) -> Result<ImportedKey, KeyError> {
    from_ec_private(der_bytes, None)
}

fn from_ec_private(
    der_bytes: &[u8],
    outer_curve: Option<ObjectIdentifier>,
) -> Result<ImportedKey, KeyError> {
    let key = EcPrivateKey::from_der(der_bytes).map_err(|_| KeyError::Encoding)?;
    if key.version != 1 {
        return Err(KeyError::Encoding);
    }
    if outer_curve.is_some() && key.parameters.is_some() && outer_curve != key.parameters {
        return Err(KeyError::Encoding);
    }
    let curve = outer_curve.or(key.parameters).ok_or(KeyError::Encoding)?;
    let bytes = key.private_key.as_bytes();
    let algorithm = match curve.to_string().as_str() {
        "1.2.840.10045.3.1.7" => Algorithm::EccP256,
        "1.3.132.0.34" => Algorithm::EccP384,
        "1.3.132.0.35" => Algorithm::EccP521,
        "1.3.132.0.10" => Algorithm::Secp256k1,
        "1.2.156.10197.1.301" => Algorithm::Sm2,
        _ => return Err(KeyError::Unsupported),
    };
    let imported = ec_imported(algorithm, bytes)?;
    if let Some(public) = key.public_key {
        validate_ec_public_key(
            algorithm,
            bytes,
            public.as_bytes().ok_or(KeyError::Encoding)?,
        )?;
    }
    Ok(imported)
}

/// Seed-based PKCS#8: RFC 8410 Curve25519 keys and ML-DSA/ML-KEM
/// seed-only or seed-and-expanded-key forms. Legacy raw/wrapped seeds are
/// also accepted. Expanded-only PQ keys cannot be imported as card seeds.
fn from_seed_oid(
    oid: &str,
    private_key: &[u8],
    public_key: Option<&[u8]>,
) -> Result<ImportedKey, KeyError> {
    let (algorithm, width) = match oid {
        "1.3.101.112" => (Algorithm::Ed25519, 32),
        "1.3.101.110" => (Algorithm::X25519, 32),
        "2.16.840.1.101.3.4.3.18" => (Algorithm::MlDsa65, 32),
        "2.16.840.1.101.3.4.4.2" => (Algorithm::MlKem768, 64),
        _ => return Err(KeyError::Unsupported),
    };
    let seed = if matches!(algorithm, Algorithm::MlDsa65 | Algorithm::MlKem768) {
        pq::seed(algorithm, private_key, public_key)?
    } else {
        // Preserve every legacy raw seed, including ones that happen to
        // look like a complete shorter DER OCTET STRING.
        if private_key.len() == width {
            private_key
        } else {
            OctetStringRef::from_der(private_key)
                .map_err(|_| KeyError::Encoding)?
                .as_bytes()
        }
    };
    if seed.len() != width {
        return Err(KeyError::Encoding);
    }
    if matches!(algorithm, Algorithm::Ed25519 | Algorithm::X25519) {
        if let Some(public) = public_key {
            if public != seed_public_key(algorithm, seed)? {
                return Err(KeyError::Encoding);
            }
        }
    }
    Ok(ImportedKey {
        algorithm,
        material: Material::Ec(Zeroizing::new(seed.to_vec())),
    })
}

fn from_pkcs8(der_bytes: &[u8]) -> Result<ImportedKey, KeyError> {
    let info = pkcs8::PrivateKeyInfo::from_der(der_bytes).map_err(|_| KeyError::Encoding)?;
    let oid = info.algorithm.oid.to_string();
    match oid.as_str() {
        "1.2.840.113549.1.1.1" => {
            if info
                .algorithm
                .parameters
                .is_some_and(|value| value != der::AnyRef::NULL)
            {
                return Err(KeyError::Encoding);
            }
            let key = decode_rsa_private(info.private_key)?;
            if let Some(public) = info.public_key {
                use rsa::traits::PublicKeyParts;
                let supplied =
                    pkcs1::RsaPublicKey::from_der(public).map_err(|_| KeyError::Encoding)?;
                if key.n().to_bytes_be() != supplied.modulus.as_bytes()
                    || key.e().to_bytes_be() != supplied.public_exponent.as_bytes()
                {
                    return Err(KeyError::Encoding);
                }
            }
            rsa_imported(&key)
        }
        "1.2.840.10045.2.1" => {
            let curve = info
                .algorithm
                .parameters
                .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
                .ok_or(KeyError::Encoding)?;
            let imported = from_ec_private(info.private_key, Some(curve))?;
            if let Some(public) = info.public_key {
                let Material::Ec(scalar) = &imported.material else {
                    return Err(KeyError::Encoding);
                };
                validate_ec_public_key(imported.algorithm, scalar, public)?;
            }
            Ok(imported)
        }
        _ => {
            // RFC 8410 and the ML-DSA/ML-KEM key formats require absent
            // AlgorithmIdentifier parameters (even NULL is forbidden).
            if info.algorithm.parameters.is_some() {
                return Err(KeyError::Encoding);
            }
            from_seed_oid(&oid, info.private_key, info.public_key)
        }
    }
}

fn seed_public_key(algorithm: Algorithm, seed: &[u8]) -> Result<[u8; 32], KeyError> {
    use sha2::Digest;
    let scalar: Zeroizing<[u8; 32]> =
        Zeroizing::new(seed.try_into().map_err(|_| KeyError::Encoding)?);
    match algorithm {
        Algorithm::X25519 => {
            Ok(curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(*scalar).to_bytes())
        }
        Algorithm::Ed25519 => {
            // RFC 8032 section 5.1.5: hash the seed, then use the clamped
            // lower half as the base-point scalar. Dalek performs clamping.
            let mut digest = Zeroizing::new([0u8; 64]);
            sha2::Sha512::new_with_prefix(scalar.as_slice()).finalize_into((&mut *digest).into());
            let mut lower = Zeroizing::new([0u8; 32]);
            lower.copy_from_slice(&digest[..32]);
            Ok(
                curve25519_dalek::edwards::EdwardsPoint::mul_base_clamped(*lower)
                    .compress()
                    .to_bytes(),
            )
        }
        _ => Err(KeyError::Unsupported),
    }
}

/// Parse a PEM or DER private key (PKCS#8 plain/encrypted, PKCS#1 RSA, SEC1
/// EC) or a PKCS#12 bundle into PIV import material.
pub fn parse_private_key(input: &[u8], password: Option<&[u8]>) -> Result<ImportedKey, KeyError> {
    let (label, der_bytes) = pem_decode(
        input,
        &[
            "PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY",
            "RSA PRIVATE KEY",
            "EC PRIVATE KEY",
        ],
    )?;
    let der_bytes = Zeroizing::new(der_bytes);
    if label == "ENCRYPTED PRIVATE KEY" {
        return decrypt_pkcs8(&der_bytes, password);
    }
    if label == "RSA PRIVATE KEY" {
        return from_pkcs1(&der_bytes);
    }
    if label == "EC PRIVATE KEY" {
        return from_sec1(&der_bytes);
    }
    // "PRIVATE KEY" or bare DER: try PKCS#8, then encrypted PKCS#8 (a
    // recognized-but-undecryptable blob keeps its Password error), then
    // PKCS#1 RSA, then SEC1 EC, then PKCS#12. A recognized-but-unsupported
    // key keeps its Unsupported error; PKCS#12 is tried only when no other
    // encoding matched at all.
    match from_pkcs8(&der_bytes) {
        Err(KeyError::Encoding) => match decrypt_pkcs8(&der_bytes, password) {
            Err(KeyError::Encoding) => {
                let parsed = match from_pkcs1(&der_bytes) {
                    Err(KeyError::Encoding) => from_sec1(&der_bytes),
                    other => other,
                };
                match parsed {
                    Err(KeyError::Encoding) => pfx::key_from_pfx(&der_bytes, password),
                    other => other,
                }
            }
            other => other,
        },
        other => other,
    }
}

fn decode_rsa_private(der_bytes: &[u8]) -> Result<rsa::RsaPrivateKey, KeyError> {
    let key: rsa::RsaPrivateKey = rsa::pkcs1::DecodeRsaPrivateKey::from_pkcs1_der(der_bytes)
        .map_err(|_| KeyError::Encoding)?;
    // rsa validates n/e/d/p/q but ignores the encoded dP, dQ and qInv.
    // Its encoder recomputes those values, so a canonical DER comparison
    // rejects inconsistent CRT fields instead of silently repairing them.
    // SecretDocument clears the reconstructed private encoding on drop.
    let canonical =
        rsa::pkcs1::EncodeRsaPrivateKey::to_pkcs1_der(&key).map_err(|_| KeyError::Encoding)?;
    if canonical.as_bytes() != der_bytes {
        return Err(KeyError::Encoding);
    }
    Ok(key)
}

fn from_pkcs1(der_bytes: &[u8]) -> Result<ImportedKey, KeyError> {
    let key = decode_rsa_private(der_bytes)?;
    rsa_imported(&key)
}

fn rsa_imported(key: &rsa::RsaPrivateKey) -> Result<ImportedKey, KeyError> {
    use rsa::traits::PublicKeyParts;
    let algorithm = match key.n().bits() {
        1024 => Algorithm::Rsa1024,
        2048 => Algorithm::Rsa2048,
        3072 => Algorithm::Rsa3072,
        4096 => Algorithm::Rsa4096,
        _ => return Err(KeyError::Unsupported),
    };
    Ok(ImportedKey {
        algorithm,
        material: rsa_material(key)?,
    })
}

fn ec_imported(algorithm: Algorithm, bytes: &[u8]) -> Result<ImportedKey, KeyError> {
    // Use the same fixed-width and scalar-range checks as card import for
    // every supported curve, before credential resolution or slot changes.
    PrivateKeyMaterial::ec_scalar(algorithm, bytes).map_err(|_| KeyError::Encoding)?;
    Ok(ImportedKey {
        algorithm,
        material: Material::Ec(Zeroizing::new(bytes.to_vec())),
    })
}

fn validate_ec_public_key(
    algorithm: Algorithm,
    scalar: &[u8],
    public: &[u8],
) -> Result<(), KeyError> {
    macro_rules! matches_scalar {
        ($curve:ident) => {{
            let secret = $curve::SecretKey::from_slice(scalar).map_err(|_| KeyError::Encoding)?;
            let supplied =
                $curve::PublicKey::from_sec1_bytes(public).map_err(|_| KeyError::Encoding)?;
            secret.public_key() == supplied
        }};
    }
    let matches = match algorithm {
        Algorithm::EccP256 => matches_scalar!(p256),
        Algorithm::EccP384 => matches_scalar!(p384),
        Algorithm::EccP521 => matches_scalar!(p521),
        Algorithm::Secp256k1 => matches_scalar!(k256),
        Algorithm::Sm2 => matches_scalar!(sm2),
        _ => return Err(KeyError::Unsupported),
    };
    if !matches {
        return Err(KeyError::Encoding);
    }
    Ok(())
}

fn decrypt_pkcs8(der_bytes: &[u8], password: Option<&[u8]>) -> Result<ImportedKey, KeyError> {
    let encrypted =
        pkcs8::EncryptedPrivateKeyInfo::from_der(der_bytes).map_err(|_| KeyError::Encoding)?;
    check_encryption_scheme(&encrypted.encryption_algorithm)?;
    let password = password.ok_or(KeyError::Password)?;
    let decrypted = encrypted
        .decrypt(password)
        .map_err(|_| KeyError::Password)?;
    from_pkcs8(decrypted.as_bytes())
}

fn check_encryption_scheme(scheme: &pkcs5::EncryptionScheme<'_>) -> Result<(), KeyError> {
    // pkcs5 can parse PBES1 parameters but cannot decrypt PBES1. Check
    // before requesting a password: another password cannot make it work.
    let params = scheme.pbes2().ok_or(KeyError::UnsupportedEncryption)?;
    // The optional KDF keyLength is in bytes and must match the cipher.
    // This is a file parameter error, independent of the password.
    if params
        .kdf
        .key_length()
        .is_some_and(|length| usize::from(length) != params.encryption.key_size())
    {
        return Err(KeyError::Encoding);
    }
    // RFC 8018 defines iterationCount as a positive integer. The KDF
    // implementation treats zero as one, so reject it before decryption.
    if params
        .kdf
        .pbkdf2()
        .is_some_and(|pbkdf2| pbkdf2.iteration_count == 0)
    {
        return Err(KeyError::Encoding);
    }
    if let Some(scrypt) = params.kdf.scrypt() {
        // RFC 7914 requires N > 1 and a power of two. In particular, the
        // upstream conversion computes log2(N) and panics for N = 0.
        if scrypt.cost_parameter < 2 || !scrypt.cost_parameter.is_power_of_two() {
            return Err(KeyError::Encoding);
        }
        pkcs5::scrypt::Params::try_from(scrypt).map_err(|_| KeyError::Encoding)?;
    }
    Ok(())
}

/// Parse a PEM or DER public key (SPKI, or PKCS#1 RSA) and report its PIV
/// algorithm. RSA size comes from the modulus bit length.
pub fn parse_public_key(input: &[u8]) -> Result<ImportedPublicKey, KeyError> {
    let parsed = parse_public_key_encoding(input)?;
    canonical_spki_fields(parsed.algorithm, &parsed.spki_der)?;
    Ok(parsed)
}

fn parse_public_key_encoding(input: &[u8]) -> Result<ImportedPublicKey, KeyError> {
    let (label, der_bytes) = pem_decode(input, &["PUBLIC KEY", "RSA PUBLIC KEY"])?;
    if label == "RSA PUBLIC KEY"
        || (label.is_empty() && pkcs1::RsaPublicKey::from_der(&der_bytes).is_ok())
    {
        let key = pkcs1::RsaPublicKey::from_der(&der_bytes).map_err(|_| KeyError::Encoding)?;
        let spki_der = spki::SubjectPublicKeyInfo::<der::Any, der::asn1::BitString> {
            algorithm: spki::AlgorithmIdentifier {
                oid: ObjectIdentifier::new("1.2.840.113549.1.1.1")
                    .map_err(|_| KeyError::Encoding)?,
                parameters: Some(der::Any::null()),
            },
            subject_public_key: der::asn1::BitString::new(0, der_bytes.clone())
                .map_err(|_| KeyError::Encoding)?,
        }
        .to_der()
        .map_err(|_| KeyError::Encoding)?;
        let algorithm = match key.modulus.as_bytes().len() * 8
            - key
                .modulus
                .as_bytes()
                .first()
                .map_or(8, |b| b.leading_zeros() as usize)
        {
            1024 => Algorithm::Rsa1024,
            2048 => Algorithm::Rsa2048,
            3072 => Algorithm::Rsa3072,
            4096 => Algorithm::Rsa4096,
            _ => return Err(KeyError::Unsupported),
        };
        return Ok(ImportedPublicKey {
            algorithm,
            spki_der,
        });
    }
    let spki_parsed =
        spki::SubjectPublicKeyInfo::<der::Any, der::asn1::BitString>::from_der(&der_bytes)
            .map_err(|_| KeyError::Encoding)?;
    let oid = spki_parsed.algorithm.oid.to_string();
    let algorithm = match oid.as_str() {
        "1.2.840.113549.1.1.1" => {
            let key = pkcs1::RsaPublicKey::from_der(
                spki_parsed
                    .subject_public_key
                    .as_bytes()
                    .ok_or(KeyError::Encoding)?,
            )
            .map_err(|_| KeyError::Encoding)?;
            let modulus = key.modulus.as_bytes();
            match modulus.len() * 8 - modulus.first().map_or(8, |b| b.leading_zeros() as usize) {
                1024 => Algorithm::Rsa1024,
                2048 => Algorithm::Rsa2048,
                3072 => Algorithm::Rsa3072,
                4096 => Algorithm::Rsa4096,
                _ => return Err(KeyError::Unsupported),
            }
        }
        "1.2.840.10045.2.1" => {
            let curve = spki_parsed
                .algorithm
                .parameters
                .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
                .ok_or(KeyError::Encoding)?;
            match curve.to_string().as_str() {
                "1.2.840.10045.3.1.7" => Algorithm::EccP256,
                "1.3.132.0.34" => Algorithm::EccP384,
                "1.3.132.0.35" => Algorithm::EccP521,
                "1.3.132.0.10" => Algorithm::Secp256k1,
                "1.2.156.10197.1.301" => Algorithm::Sm2,
                _ => return Err(KeyError::Unsupported),
            }
        }
        "1.3.101.112" => Algorithm::Ed25519,
        "1.3.101.110" => Algorithm::X25519,
        "2.16.840.1.101.3.4.3.18" => Algorithm::MlDsa65,
        "2.16.840.1.101.3.4.4.2" => Algorithm::MlKem768,
        _ => return Err(KeyError::Unsupported),
    };
    Ok(ImportedPublicKey {
        algorithm,
        spki_der: der_bytes,
    })
}

/// Compare public keys by their mathematical fields rather than their SPKI
/// encoding. In particular, compressed and uncompressed EC points compare
/// equal. Malformed points, bit strings and algorithm parameters are rejected.
/// This compares identity; it does not verify key provenance or ownership.
pub fn public_keys_equal(left: &[u8], right: &[u8]) -> Result<bool, KeyError> {
    Ok(canonical_public_key(left)? == canonical_public_key(right)?)
}

fn canonical_public_key(input: &[u8]) -> Result<canokey::piv::PublicKey, KeyError> {
    let parsed = parse_public_key_encoding(input)?;
    canonical_spki_fields(parsed.algorithm, &parsed.spki_der)
}

fn canonical_spki_fields(
    algorithm: Algorithm,
    spki_der: &[u8],
) -> Result<canokey::piv::PublicKey, KeyError> {
    use canokey::piv::PublicKey;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let info = spki::SubjectPublicKeyInfoRef::from_der(spki_der).map_err(|_| KeyError::Encoding)?;
    let bytes = info
        .subject_public_key
        .as_bytes()
        .ok_or(KeyError::Encoding)?;
    match algorithm {
        Algorithm::Rsa1024 | Algorithm::Rsa2048 | Algorithm::Rsa3072 | Algorithm::Rsa4096 => {
            if info
                .algorithm
                .parameters
                .is_some_and(|value| value != der::AnyRef::NULL)
            {
                return Err(KeyError::Encoding);
            }
            let rsa = pkcs1::RsaPublicKey::from_der(bytes).map_err(|_| KeyError::Encoding)?;
            let modulus = rsa.modulus.as_bytes();
            let exponent = rsa.public_exponent.as_bytes();
            // DER INTEGER validity alone does not make a usable RSA key:
            // the modulus and exponent must be odd, with e >= 3. Do not
            // impose the card's private-import exponent (65537) here.
            if modulus.last().is_none_or(|byte| byte & 1 == 0)
                || exponent.last().is_none_or(|byte| byte & 1 == 0)
                || (exponent.len() == 1 && exponent[0] < 3)
            {
                return Err(KeyError::Encoding);
            }
            Ok(PublicKey::Rsa {
                algorithm,
                modulus: modulus.to_vec(),
                exponent: exponent.to_vec(),
            })
        }
        Algorithm::EccP256
        | Algorithm::EccP384
        | Algorithm::EccP521
        | Algorithm::Secp256k1
        | Algorithm::Sm2 => {
            let point = match algorithm {
                Algorithm::EccP256 => p256::PublicKey::from_sec1_bytes(bytes)
                    .map(|key| key.to_encoded_point(false).as_bytes().to_vec()),
                Algorithm::EccP384 => p384::PublicKey::from_sec1_bytes(bytes)
                    .map(|key| key.to_encoded_point(false).as_bytes().to_vec()),
                Algorithm::EccP521 => p521::PublicKey::from_sec1_bytes(bytes)
                    .map(|key| key.to_encoded_point(false).as_bytes().to_vec()),
                Algorithm::Secp256k1 => k256::PublicKey::from_sec1_bytes(bytes)
                    .map(|key| key.to_encoded_point(false).as_bytes().to_vec()),
                Algorithm::Sm2 => sm2::PublicKey::from_sec1_bytes(bytes)
                    .map(|key| key.to_encoded_point(false).as_bytes().to_vec()),
                _ => unreachable!(),
            }
            .map_err(|_| KeyError::Encoding)?;
            Ok(PublicKey::Ec { algorithm, point })
        }
        _ => {
            let width = match algorithm {
                Algorithm::Ed25519 | Algorithm::X25519 => 32,
                Algorithm::MlDsa65 => 1952,
                Algorithm::MlKem768 => 1184,
                _ => return Err(KeyError::Unsupported),
            };
            if info.algorithm.parameters.is_some() || bytes.len() != width {
                return Err(KeyError::Encoding);
            }
            Ok(PublicKey::Raw {
                algorithm,
                bytes: bytes.to_vec(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressed_public_points_match_for_every_supported_curve() {
        use canokey::piv::PublicKey;
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        macro_rules! check_curve {
            ($curve:ident, $algorithm:expr, $width:expr) => {{
                let mut scalar = [0; $width];
                scalar[$width - 1] = 1;
                let key = $curve::SecretKey::from_slice(&scalar).unwrap().public_key();
                let uncompressed = PublicKey::Ec {
                    algorithm: $algorithm,
                    point: key.to_encoded_point(false).as_bytes().to_vec(),
                }
                .to_spki_der()
                .unwrap();
                let mut info = spki::SubjectPublicKeyInfoOwned::from_der(&uncompressed).unwrap();
                info.subject_public_key =
                    der::asn1::BitString::new(0, key.to_encoded_point(true).as_bytes()).unwrap();
                let compressed = info.to_der().unwrap();
                assert_ne!(uncompressed, compressed);
                assert!(public_keys_equal(&uncompressed, &compressed).unwrap());
                assert!(public_keys_equal(&compressed, &uncompressed).unwrap());
                scalar[$width - 1] = 2;
                let other = $curve::SecretKey::from_slice(&scalar).unwrap().public_key();
                info.subject_public_key =
                    der::asn1::BitString::new(0, other.to_encoded_point(true).as_bytes()).unwrap();
                assert!(!public_keys_equal(&uncompressed, &info.to_der().unwrap()).unwrap());
                // The correctly sized encoding of (0, 0) is not a curve point.
                let mut invalid = vec![0; 1 + 2 * $width];
                invalid[0] = 4;
                info.subject_public_key = der::asn1::BitString::new(0, invalid).unwrap();
                assert!(public_keys_equal(&uncompressed, &info.to_der().unwrap()).is_err());
                assert!(parse_public_key(&info.to_der().unwrap()).is_err());
            }};
        }
        check_curve!(p256, Algorithm::EccP256, 32);
        check_curve!(p384, Algorithm::EccP384, 48);
        check_curve!(p521, Algorithm::EccP521, 66);
        check_curve!(k256, Algorithm::Secp256k1, 32);
        check_curve!(sm2, Algorithm::Sm2, 32);
    }

    #[test]
    fn pkcs1_public_keys_accept_both_der_and_pem() {
        let modulus = [0x81; 128];
        let key = pkcs1::RsaPublicKey {
            modulus: der::asn1::UintRef::new(&modulus).unwrap(),
            public_exponent: der::asn1::UintRef::new(&[1, 0, 1]).unwrap(),
        }
        .to_der()
        .unwrap();
        let der = parse_public_key(&key).unwrap();
        let pem = parse_public_key(&crate::x509::pem_encode("RSA PUBLIC KEY", &key)).unwrap();
        assert_eq!(der, pem);
        assert_eq!(der.algorithm, Algorithm::Rsa1024);
        assert!(public_keys_equal(&key, &der.spki_der).unwrap());
        assert!(parse_public_key(&crate::x509::pem_encode("PUBLIC KEY", &key)).is_err());
    }

    #[test]
    fn rsa_public_keys_reject_invalid_modulus_and_exponent() {
        for (even_modulus, exponent, valid) in [
            (false, &[0][..], false),
            (false, &[1][..], false),
            (false, &[2][..], false),
            (false, &[4][..], false),
            (true, &[1, 0, 1][..], false),
            (false, &[3][..], true),
            (false, &[1, 0, 1][..], true),
        ] {
            let mut modulus = [0x81; 128];
            if even_modulus {
                modulus[127] = 0x80;
            }
            let raw = pkcs1::RsaPublicKey {
                modulus: der::asn1::UintRef::new(&modulus).unwrap(),
                public_exponent: der::asn1::UintRef::new(exponent).unwrap(),
            }
            .to_der()
            .unwrap();
            let spki = spki::SubjectPublicKeyInfoOwned {
                algorithm: spki::AlgorithmIdentifierOwned {
                    oid: ObjectIdentifier::new("1.2.840.113549.1.1.1").unwrap(),
                    parameters: Some(der::Any::null()),
                },
                subject_public_key: der::asn1::BitString::new(0, raw.clone()).unwrap(),
            }
            .to_der()
            .unwrap();
            for (der, label) in [(&raw, "RSA PUBLIC KEY"), (&spki, "PUBLIC KEY")] {
                let pem = crate::x509::pem_encode(label, der);
                for input in [der.as_slice(), pem.as_slice()] {
                    assert_eq!(parse_public_key(input).is_ok(), valid);
                    assert_eq!(public_keys_equal(input, input).is_ok(), valid);
                }
            }
        }
    }

    #[test]
    fn rsa_comparison_uses_modulus_and_exponent() {
        let key = canokey::piv::PublicKey::Rsa {
            algorithm: Algorithm::Rsa1024,
            modulus: vec![0x81; 128],
            exponent: vec![1, 0, 1],
        };
        let encoded = key.to_spki_der().unwrap();
        let mut info = spki::SubjectPublicKeyInfoOwned::from_der(&encoded).unwrap();
        info.algorithm.parameters = None;
        assert!(public_keys_equal(&encoded, &info.to_der().unwrap()).unwrap());
        let mut other = key;
        let canokey::piv::PublicKey::Rsa { exponent, .. } = &mut other else {
            unreachable!()
        };
        *exponent = vec![3];
        assert!(!public_keys_equal(&encoded, &other.to_spki_der().unwrap()).unwrap());
        info.algorithm.parameters = Some(der::Any::encode_from(&true).unwrap());
        assert!(public_keys_equal(&encoded, &info.to_der().unwrap()).is_err());
    }

    #[test]
    fn public_key_comparison_rejects_malformed_raw_encodings() {
        for (algorithm, width) in [
            (Algorithm::Ed25519, 32),
            (Algorithm::X25519, 32),
            (Algorithm::MlDsa65, 1952),
            (Algorithm::MlKem768, 1184),
        ] {
            let encoded = canokey::piv::PublicKey::Raw {
                algorithm,
                bytes: vec![0x42; width],
            }
            .to_spki_der()
            .unwrap();
            assert!(public_keys_equal(&encoded, &encoded).unwrap());
            let mut info = spki::SubjectPublicKeyInfoOwned::from_der(&encoded).unwrap();
            info.subject_public_key = der::asn1::BitString::new(0, vec![0x42; width - 1]).unwrap();
            assert!(public_keys_equal(&encoded, &info.to_der().unwrap()).is_err());
            info.subject_public_key = der::asn1::BitString::new(1, vec![0x42; width]).unwrap();
            assert!(public_keys_equal(&encoded, &info.to_der().unwrap()).is_err());
            info.subject_public_key = der::asn1::BitString::new(0, vec![0x42; width]).unwrap();
            info.algorithm.parameters = Some(der::Any::null());
            assert!(public_keys_equal(&encoded, &info.to_der().unwrap()).is_err());
        }
    }

    #[test]
    fn ec_private_import_matches_openssl_on_all_curves() {
        for (algorithm, fixture) in EC_PRIVATE_FIXTURES {
            let info = pkcs8::PrivateKeyInfo::from_der(fixture).unwrap();
            let inner = EcPrivateKey::from_der(info.private_key).unwrap();
            assert!(
                inner.public_key.is_some(),
                "fixture must independently bind the public key"
            );
            let imported = parse_private_key(fixture, None).unwrap();
            assert_eq!(imported.algorithm, algorithm);
            assert_eq!(imported.piv_material().unwrap().algorithm(), algorithm);
            let Material::Ec(scalar) = imported.material else {
                panic!("expected EC scalar")
            };
            assert_eq!(&*scalar, inner.private_key.as_bytes());
            assert_eq!(scalar[scalar.len() - 1], 1);
            assert!(scalar[..scalar.len() - 1].iter().all(|byte| *byte == 0));

            // Standalone SEC1 needs its own curve identifier.
            let curve = info.algorithm.parameters.unwrap().decode_as().unwrap();
            let standalone = EcPrivateKey {
                parameters: Some(curve),
                ..inner
            }
            .to_der()
            .unwrap();
            assert_eq!(
                parse_private_key(&standalone, None).unwrap().algorithm,
                algorithm
            );
        }
    }

    #[test]
    fn ec_private_import_rejects_invalid_scalar_ranges_and_widths() {
        for (_, fixture) in EC_PRIVATE_FIXTURES {
            let info = pkcs8::PrivateKeyInfo::from_der(fixture).unwrap();
            let original = EcPrivateKey::from_der(info.private_key).unwrap();
            let width = original.private_key.as_bytes().len();
            for scalar in [
                vec![0; width],
                vec![0xff; width],
                vec![1; width - 1],
                vec![1; width + 1],
            ] {
                let inner = EcPrivateKey {
                    version: 1,
                    private_key: OctetStringRef::new(&scalar).unwrap(),
                    parameters: None,
                    public_key: None,
                }
                .to_der()
                .unwrap();
                let malformed = pkcs8::PrivateKeyInfo::new(info.algorithm, &inner)
                    .to_der()
                    .unwrap();
                assert!(parse_private_key(&malformed, None).is_err());
            }
        }
    }

    #[test]
    fn ec_private_import_rejects_conflicting_curves_and_public_keys() {
        for (_, fixture) in EC_PRIVATE_FIXTURES {
            let info = pkcs8::PrivateKeyInfo::from_der(fixture).unwrap();
            let mut inner = EcPrivateKey::from_der(info.private_key).unwrap();
            let curve = info
                .algorithm
                .parameters
                .unwrap()
                .decode_as::<ObjectIdentifier>()
                .unwrap();
            let other_curve = ObjectIdentifier::new(if curve.to_string() == "1.3.132.0.10" {
                "1.2.840.10045.3.1.7"
            } else {
                "1.3.132.0.10"
            })
            .unwrap();
            inner.parameters = Some(other_curve);
            let encoded = inner.to_der().unwrap();
            let malformed = pkcs8::PrivateKeyInfo::new(info.algorithm, &encoded)
                .to_der()
                .unwrap();
            assert!(parse_private_key(&malformed, None).is_err());

            // Both scalar one and scalar two are valid, but the fixture's
            // public point belongs only to scalar one.
            let mut scalar = inner.private_key.as_bytes().to_vec();
            *scalar.last_mut().unwrap() = 2;
            inner.parameters = None;
            inner.private_key = OctetStringRef::new(&scalar).unwrap();
            let encoded = inner.to_der().unwrap();
            let malformed = pkcs8::PrivateKeyInfo::new(info.algorithm, &encoded)
                .to_der()
                .unwrap();
            assert!(parse_private_key(&malformed, None).is_err());

            // RFC 5958 may also bind a public point in the outer structure.
            let public = inner.public_key.take().unwrap();
            let encoded = inner.to_der().unwrap();
            let mut outer = pkcs8::PrivateKeyInfo::new(info.algorithm, &encoded);
            outer.public_key = public.as_bytes();
            assert!(parse_private_key(&outer.to_der().unwrap(), None).is_err());
        }
    }

    #[test]
    fn ec_private_import_accepts_compressed_matching_public_points() {
        for (_, fixture) in EC_PRIVATE_FIXTURES {
            let info = pkcs8::PrivateKeyInfo::from_der(fixture).unwrap();
            let mut inner = EcPrivateKey::from_der(info.private_key).unwrap();
            let point = inner.public_key.unwrap().as_bytes().unwrap();
            let width = inner.private_key.as_bytes().len();
            let mut compressed = vec![2 | (point.last().unwrap() & 1)];
            compressed.extend_from_slice(&point[1..=width]);
            inner.public_key = Some(der::asn1::BitStringRef::new(0, &compressed).unwrap());
            let encoded = inner.to_der().unwrap();
            let mut outer = pkcs8::PrivateKeyInfo::new(info.algorithm, &encoded);
            outer.public_key = Some(&compressed);
            assert!(parse_private_key(&outer.to_der().unwrap(), None).is_ok());
        }
    }

    const EC_PRIVATE_FIXTURES: [(Algorithm, &[u8]); 5] = [
        (
            Algorithm::EccP256,
            include_bytes!("../../tests/fixtures/p256-scalar-one-openssl.der"),
        ),
        (
            Algorithm::EccP384,
            include_bytes!("../../tests/fixtures/p384-scalar-one-openssl.der"),
        ),
        (
            Algorithm::EccP521,
            include_bytes!("../../tests/fixtures/p521-scalar-one-openssl.der"),
        ),
        (
            Algorithm::Secp256k1,
            include_bytes!("../../tests/fixtures/k256-scalar-one-openssl.der"),
        ),
        (
            Algorithm::Sm2,
            include_bytes!("../../tests/fixtures/sm2-scalar-one-openssl.der"),
        ),
    ];

    #[test]
    fn pem_bundle_selects_block_by_label() {
        // A key+certificate bundle parses regardless of block order: the
        // CERTIFICATE block (dummy bytes) is skipped for the key, and
        // selected when a certificate is asked for.
        let secret = p256::SecretKey::random(&mut rand_core::OsRng);
        let doc = p256::pkcs8::EncodePrivateKey::to_pkcs8_der(&secret).unwrap();
        let mut bundle = crate::x509::pem_encode("CERTIFICATE", b"not a real cert");
        bundle.extend_from_slice(&crate::x509::pem_encode("PRIVATE KEY", doc.as_bytes()));
        let key = parse_private_key(&bundle, None).unwrap();
        assert_eq!(key.algorithm, Algorithm::EccP256);
        let (label, der) = pem_decode(&bundle, &["CERTIFICATE"]).unwrap();
        assert_eq!(label, "CERTIFICATE");
        assert_eq!(der, b"not a real cert");
    }

    #[test]
    fn pkcs8_rsa1024_roundtrip() {
        // Host-side parsing only; RSA-1024 keeps the test fast.
        let private = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 1024).unwrap();
        let doc = rsa::pkcs8::EncodePrivateKey::to_pkcs8_der(&private).unwrap();
        let key = parse_private_key(doc.as_bytes(), None).unwrap();
        assert_eq!(key.algorithm, Algorithm::Rsa1024);
        // PKCS#1 as well.
        let doc = rsa::pkcs1::EncodeRsaPrivateKey::to_pkcs1_der(&private).unwrap();
        let key = parse_private_key(doc.as_bytes(), None).unwrap();
        assert_eq!(key.algorithm, Algorithm::Rsa1024);
        let pem = crate::x509::pem_encode("RSA PRIVATE KEY", doc.as_bytes());
        let key = parse_private_key(&pem, None).unwrap();
        assert_eq!(key.algorithm, Algorithm::Rsa1024);
    }

    #[test]
    fn pkcs8_ed25519_and_x25519_seeds() {
        // PrivateKeyInfo: version 0, OID 1.3.101.112 (Ed25519), OCTET STRING
        // wrapping the 32-byte seed OCTET STRING.
        let mut der = vec![
            0x30, 0x2e, 2, 1, 0, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 4, 0x22, 4, 0x20,
        ];
        der.extend([7; 32]);
        let key = parse_private_key(&der, None).unwrap();
        assert_eq!(key.algorithm, Algorithm::Ed25519);
        // X25519: OID 1.3.101.110.
        let mut der = vec![
            0x30, 0x2e, 2, 1, 0, 0x30, 5, 6, 3, 0x2b, 0x65, 0x6e, 4, 0x22, 4, 0x20,
        ];
        der.extend([9; 32]);
        let key = parse_private_key(&der, None).unwrap();
        assert_eq!(key.algorithm, Algorithm::X25519);
        let canokey::openpgp::PrivateKey::Ec(scalar) = key.openpgp_key().unwrap() else {
            panic!("X25519 import must contain a scalar");
        };
        assert_eq!(scalar.as_bytes()[0], 0x49);
        assert_eq!(scalar.as_bytes()[31], 0x08);
        assert_eq!(&scalar.as_bytes()[1..31], &[9; 30]);
    }

    #[test]
    fn encrypted_pkcs8_needs_password() {
        let secret = p256::SecretKey::random(&mut rand_core::OsRng);
        let doc = p256::pkcs8::EncodePrivateKey::to_pkcs8_der(&secret).unwrap();
        let info = pkcs8::PrivateKeyInfo::from_der(doc.as_bytes()).unwrap();
        let encrypted = info.encrypt(&mut rand_core::OsRng, b"pw").unwrap();
        let der_bytes = encrypted.as_bytes();
        assert!(matches!(
            parse_private_key(der_bytes, None),
            Err(KeyError::Password)
        ));
        assert!(matches!(
            parse_private_key(der_bytes, Some(b"wrong")),
            Err(KeyError::Password)
        ));
        let key = parse_private_key(der_bytes, Some(b"pw")).unwrap();
        assert_eq!(key.algorithm, Algorithm::EccP256);
    }

    #[test]
    fn openssl_encrypted_keys_with_default_hmac_sha1_prf() {
        for encoded in [
            include_bytes!("../../tests/fixtures/pbkdf2-sha1-openssl.der").as_slice(),
            include_bytes!("../../tests/fixtures/pbkdf2-sha1-safe-openssl.p12").as_slice(),
        ] {
            for password in [None, Some(b"wrong".as_slice())] {
                assert!(matches!(
                    parse_private_key(encoded, password),
                    Err(KeyError::Password)
                ));
            }
            let imported = parse_private_key(encoded, Some(b"audit")).unwrap();
            assert_eq!(imported.algorithm, Algorithm::EccP256);
            let Material::Ec(scalar) = imported.material else {
                panic!("expected an EC scalar")
            };
            let mut expected = [0; 32];
            expected[31] = 1;
            assert_eq!(scalar.as_slice(), expected);
        }
    }

    #[test]
    fn encrypted_pkcs8_rejects_zero_pbkdf2_iterations() {
        let secret = p256::SecretKey::from_slice(&[1; 32]).unwrap();
        let doc = p256::pkcs8::EncodePrivateKey::to_pkcs8_der(&secret).unwrap();
        let params =
            pkcs5::pbes2::Parameters::pbkdf2_sha256_aes256cbc(1, &[2; 16], &[3; 16]).unwrap();
        let ciphertext = params.encrypt(b"pw", doc.as_bytes()).unwrap();
        for iterations in [1, 0] {
            let mut params = params.clone();
            let pkcs5::pbes2::Kdf::Pbkdf2(pbkdf2) = &mut params.kdf else {
                unreachable!()
            };
            pbkdf2.iteration_count = iterations;
            let encoded = pkcs8::EncryptedPrivateKeyInfo {
                encryption_algorithm: params.into(),
                encrypted_data: &ciphertext,
            }
            .to_der()
            .unwrap();
            if iterations == 1 {
                assert!(parse_private_key(&encoded, Some(b"pw")).is_ok());
            } else {
                // Its ciphertext is valid for one iteration, which the
                // underlying library also uses for the invalid zero value.
                for password in [None, Some(b"pw".as_slice())] {
                    assert!(matches!(
                        parse_private_key(&encoded, password),
                        Err(KeyError::Encoding)
                    ));
                }
            }
        }
    }

    #[test]
    fn public_key_spki_roundtrip() {
        let secret = p256::SecretKey::random(&mut rand_core::OsRng);
        let spki = p256::pkcs8::EncodePublicKey::to_public_key_der(&secret.public_key()).unwrap();
        let parsed = parse_public_key(spki.as_bytes()).unwrap();
        assert_eq!(parsed.algorithm, Algorithm::EccP256);
        assert_eq!(parsed.spki_der, spki.as_bytes());
        let pem = crate::x509::pem_encode("PUBLIC KEY", spki.as_bytes());
        assert_eq!(
            parse_public_key(&pem).unwrap().algorithm,
            Algorithm::EccP256
        );

        let private = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 1024).unwrap();
        let spki =
            rsa::pkcs8::EncodePublicKey::to_public_key_der(&private.to_public_key()).unwrap();
        assert_eq!(
            parse_public_key(spki.as_bytes()).unwrap().algorithm,
            Algorithm::Rsa1024
        );
    }
}

#[cfg(test)]
mod extended_tests {
    use super::*;

    #[test]
    fn private_key_debug_redacts_material_including_bundles() {
        for input in [
            include_bytes!("../../tests/fixtures/p256-scalar-one-openssl.der").as_slice(),
            include_bytes!("../../tests/fixtures/mldsa65-openssl.der").as_slice(),
            include_bytes!("../../tests/fixtures/p12_nopw.p12").as_slice(),
        ] {
            let key = parse_private_key(input, None).unwrap();
            for debug in [format!("{key:?}"), format!("{key:#?}")] {
                assert!(
                    debug.contains("REDACTED"),
                    "private material must be redacted"
                );
                assert!(
                    !debug.contains("Zeroizing"),
                    "private buffers must not be formatted"
                );
            }
        }
        let bundle = parse_pfx(include_bytes!("../../tests/fixtures/p12_nopw.p12"), None).unwrap();
        assert!(format!("{bundle:?}").contains("REDACTED"));
    }

    /// Hand-built PKCS#8: version 0, algorithm OID (+ optional curve OID
    /// parameter), privateKey = OCTET STRING (inner OCTET STRING seed).
    fn pkcs8_with_params(oid_bytes: &[u8], params: Option<&[u8]>, seed: &[u8]) -> Vec<u8> {
        let mut alg = vec![0x06, oid_bytes.len() as u8];
        alg.extend(oid_bytes);
        if let Some(params) = params {
            alg.extend([0x06, params.len() as u8]);
            alg.extend(params);
        }
        let mut wrapped = vec![0x30, alg.len() as u8];
        wrapped.extend(alg);
        let alg = wrapped;
        let mut inner = vec![4, seed.len() as u8];
        inner.extend(seed);
        let mut key = vec![4, inner.len() as u8];
        key.extend(inner);
        let mut body = vec![2, 1, 0];
        body.extend(alg);
        body.extend(key);
        let mut der = vec![0x30, body.len() as u8];
        der.extend(body);
        der
    }

    fn pkcs8(oid_bytes: &[u8], seed: &[u8]) -> Vec<u8> {
        pkcs8_with_params(oid_bytes, None, seed)
    }

    #[test]
    fn rfc8410_public_keys_match_rfc_vectors() {
        fn hex(value: &str) -> Vec<u8> {
            value
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect()
        }
        for (algorithm, oid, seed, public) in [
            (
                Algorithm::Ed25519,
                "1.3.101.112",
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            ),
            (
                Algorithm::X25519,
                "1.3.101.110",
                "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
                "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            ),
        ] {
            let seed = hex(seed);
            let public = hex(public);
            assert_eq!(
                seed_public_key(algorithm, &seed).unwrap().as_slice(),
                public
            );
            let wrapped = OctetStringRef::new(&seed).unwrap().to_der().unwrap();
            let alg = spki::AlgorithmIdentifierRef {
                oid: ObjectIdentifier::new(oid).unwrap(),
                parameters: None,
            };
            let mut info = pkcs8::PrivateKeyInfo::new(alg, &wrapped);
            info.public_key = Some(&public);
            assert_eq!(
                parse_private_key(&info.to_der().unwrap(), None)
                    .unwrap()
                    .algorithm,
                algorithm
            );
            let mut wrong_public = public.clone();
            wrong_public[0] ^= 1;
            info.public_key = Some(&wrong_public);
            assert!(parse_private_key(&info.to_der().unwrap(), None).is_err());
            info.public_key = Some(&public[..31]);
            assert!(parse_private_key(&info.to_der().unwrap(), None).is_err());
        }
    }

    #[test]
    fn seed_algorithms_reject_parameters_and_preserve_raw_seeds() {
        for (oid, width) in [
            ("1.3.101.112", 32),
            ("1.3.101.110", 32),
            ("2.16.840.1.101.3.4.3.18", 32),
            ("2.16.840.1.101.3.4.4.2", 64),
        ] {
            let mut seed = vec![0x42; width];
            seed[..2].copy_from_slice(&[4, (width - 2) as u8]);
            let wrapped = OctetStringRef::new(&seed).unwrap().to_der().unwrap();
            for bytes in [seed.as_slice(), wrapped.as_slice()] {
                let alg = spki::AlgorithmIdentifierRef {
                    oid: ObjectIdentifier::new(oid).unwrap(),
                    parameters: None,
                };
                let mut info = pkcs8::PrivateKeyInfo::new(alg, bytes);
                let imported = parse_private_key(&info.to_der().unwrap(), None).unwrap();
                let Material::Ec(actual) = imported.material else {
                    panic!("expected seed")
                };
                assert_eq!(*actual, seed);
                for params in [der::AnyRef::NULL, der::AnyRef::from_der(&[4, 0]).unwrap()] {
                    info.algorithm.parameters = Some(params);
                    assert!(parse_private_key(&info.to_der().unwrap(), None).is_err());
                }
            }
        }
    }

    #[test]
    fn rsa_pkcs8_checks_parameters_and_public_binding() {
        use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
        let private = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 1024).unwrap();
        let private_der = private.to_pkcs1_der().unwrap();
        let public_der = private.to_public_key().to_pkcs1_der().unwrap();
        let alg = spki::AlgorithmIdentifierRef {
            oid: ObjectIdentifier::new("1.2.840.113549.1.1.1").unwrap(),
            parameters: None,
        };
        let mut info = pkcs8::PrivateKeyInfo::new(alg, private_der.as_bytes());
        info.public_key = Some(public_der.as_bytes());
        for parameters in [None, Some(der::AnyRef::NULL)] {
            info.algorithm.parameters = parameters;
            assert!(parse_private_key(&info.to_der().unwrap(), None).is_ok());
        }
        info.algorithm.parameters = Some(der::AnyRef::from_der(&[4, 0]).unwrap());
        assert!(parse_private_key(&info.to_der().unwrap(), None).is_err());
        info.algorithm.parameters = None;
        let public = pkcs1::RsaPublicKey::from_der(public_der.as_bytes()).unwrap();
        let wrong_exponent = [3];
        let wrong = pkcs1::RsaPublicKey {
            modulus: public.modulus,
            public_exponent: der::asn1::UintRef::new(&wrong_exponent).unwrap(),
        }
        .to_der()
        .unwrap();
        info.public_key = Some(&wrong);
        assert!(parse_private_key(&info.to_der().unwrap(), None).is_err());
        info.public_key = Some(&[0x30, 0]);
        assert!(parse_private_key(&info.to_der().unwrap(), None).is_err());
    }

    #[test]
    fn rsa_rejects_inconsistent_crt_fields_in_pkcs1_and_pkcs8() {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        let private = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 1024).unwrap();
        let private_der = private.to_pkcs1_der().unwrap();
        let alg = spki::AlgorithmIdentifierRef {
            oid: ObjectIdentifier::new("1.2.840.113549.1.1.1").unwrap(),
            parameters: Some(der::AnyRef::NULL),
        };
        assert!(parse_private_key(private_der.as_bytes(), None).is_ok());
        let valid = Zeroizing::new(
            pkcs8::PrivateKeyInfo::new(alg, private_der.as_bytes())
                .to_der()
                .unwrap(),
        );
        assert!(parse_private_key(&valid, None).is_ok());
        for field in 0..3 {
            let mut encoded = pkcs1::RsaPrivateKey::from_der(private_der.as_bytes()).unwrap();
            let component = match field {
                0 => &mut encoded.exponent1,
                1 => &mut encoded.exponent2,
                _ => &mut encoded.coefficient,
            };
            let mut corrupted = Zeroizing::new(component.as_bytes().to_vec());
            *corrupted.last_mut().unwrap() ^= 1;
            *component = der::asn1::UintRef::new(&corrupted).unwrap();
            let bad_pkcs1 = Zeroizing::new(encoded.to_der().unwrap());
            let bad_pkcs8 = Zeroizing::new(
                pkcs8::PrivateKeyInfo::new(alg, &bad_pkcs1)
                    .to_der()
                    .unwrap(),
            );
            for input in [&*bad_pkcs1, &*bad_pkcs8] {
                assert!(matches!(
                    parse_private_key(input, None),
                    Err(KeyError::Encoding)
                ));
            }
        }
    }

    const PQ_FIXTURES: [(Algorithm, &[u8], &[u8], usize); 2] = [
        (
            Algorithm::MlDsa65,
            include_bytes!("../../tests/fixtures/mldsa65-openssl.der"),
            include_bytes!("../../tests/fixtures/mldsa65-openssl-pub.der"),
            32,
        ),
        (
            Algorithm::MlKem768,
            include_bytes!("../../tests/fixtures/mlkem768-openssl.der"),
            include_bytes!("../../tests/fixtures/mlkem768-openssl-pub.der"),
            64,
        ),
    ];

    fn assert_seed(key: ImportedKey, algorithm: Algorithm, width: usize) {
        assert_eq!(key.algorithm, algorithm);
        assert_eq!(key.piv_material().unwrap().algorithm(), algorithm);
        let Material::Ec(seed) = key.material else {
            panic!("expected seed")
        };
        assert_eq!(*seed, (0..width as u8).collect::<Vec<_>>());
    }

    #[test]
    fn openssl_pq_seed_and_expanded_private_keys() {
        // OpenSSL 3.5.9, deterministic seeds 00..1f and 00..3f.
        for (algorithm, private, _, width) in PQ_FIXTURES {
            assert_seed(parse_private_key(private, None).unwrap(), algorithm, width);
        }
    }

    #[test]
    fn pq_seed_only_and_expanded_only_choices() {
        for (algorithm, private, _, width) in PQ_FIXTURES {
            let mut info = pkcs8::PrivateKeyInfo::from_der(private).unwrap();
            let seed: Vec<_> = (0..width as u8).collect();
            let mut choice = vec![0x80, width as u8]; // [0] IMPLICIT seed
            choice.extend(&seed);
            info.private_key = &choice;
            assert_seed(
                parse_private_key(&info.to_der().unwrap(), None).unwrap(),
                algorithm,
                width,
            );
            let expanded = vec![0; if width == 32 { 4032 } else { 2400 }];
            let encoded = OctetStringRef::new(&expanded).unwrap().to_der().unwrap();
            info.private_key = &encoded;
            assert!(matches!(
                parse_private_key(&info.to_der().unwrap(), None),
                Err(KeyError::Unsupported)
            ));
            let bad_seed = [0x80, 1, 0];
            info.private_key = &bad_seed;
            assert!(parse_private_key(&info.to_der().unwrap(), None).is_err());
        }
    }

    #[test]
    fn pq_public_keys_interoperate_with_openssl_and_libcanokey() {
        for (algorithm, _, public, _) in PQ_FIXTURES {
            assert_eq!(parse_public_key(public).unwrap().algorithm, algorithm);
            let info = spki::SubjectPublicKeyInfoRef::from_der(public).unwrap();
            let key = canokey::piv::PublicKey::Raw {
                algorithm,
                bytes: info.subject_public_key.as_bytes().unwrap().to_vec(),
            };
            let exported = key.to_spki_der().unwrap();
            assert_eq!(exported, public);
            assert_eq!(parse_public_key(&exported).unwrap().algorithm, algorithm);
            if algorithm == Algorithm::MlDsa65 {
                let signature = crate::x509::signature_algorithm(algorithm, None).unwrap();
                assert_eq!(signature.oid, info.algorithm.oid);
                assert!(signature.parameters.is_none());
            }
        }
    }

    #[test]
    fn incorrect_pq_oids_are_not_aliases() {
        for oid in ["2.16.840.1.101.3.4.17", "2.16.840.1.101.3.4.21"] {
            let oid = ObjectIdentifier::new(oid).unwrap();
            let encoded = pkcs8(oid.as_bytes(), &[0; 32]);
            assert!(matches!(
                parse_private_key(&encoded, None),
                Err(KeyError::Unsupported)
            ));
        }
    }

    #[test]
    fn recognized_unsupported_keys_keep_their_error() {
        let oid = ObjectIdentifier::new("1.2.3.4").unwrap();
        let encoded = pkcs8(oid.as_bytes(), &[1; 32]);
        for input in [
            encoded.clone(),
            crate::x509::pem_encode("PRIVATE KEY", &encoded),
        ] {
            assert!(matches!(
                parse_private_key(&input, None),
                Err(KeyError::Unsupported)
            ));
        }
        // SEC1 with a named curve unknown to the importer.
        let mut sec1 = vec![0x30, 44, 0x02, 0x01, 0x01, 0x04, 32];
        sec1.extend([1; 32]);
        sec1.extend([0xa0, 5, 0x06, 3]);
        sec1.extend(oid.as_bytes());
        for input in [
            sec1.clone(),
            crate::x509::pem_encode("EC PRIVATE KEY", &sec1),
        ] {
            assert!(matches!(
                parse_private_key(&input, None),
                Err(KeyError::Unsupported)
            ));
        }
    }
}
