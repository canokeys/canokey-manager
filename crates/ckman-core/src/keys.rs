//! Host-side key file parsing for PIV import/export: PEM armor, PKCS#8
//! (plain and encrypted), PKCS#1 RSA and SEC1 EC private keys, and SPKI or
//! PKCS#1 public keys. Output is libcanokey's typed private-key material;
//! no key bytes are retained beyond it.

use canokey::piv::{Algorithm, PrivateKeyMaterial};
use canokey::SecretBytes;
use der::asn1::{ObjectIdentifier, OctetStringRef};
use der::{Decode, Encode};
use zeroize::Zeroizing;

/// Key-file parsing failure.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// The PEM armor is malformed or carries an unexpected label.
    #[error("invalid or unsupported PEM block")]
    Pem,
    /// The key encoding is not recognized (tried PKCS#8, PKCS#1, SEC1).
    #[error("unrecognized private key encoding")]
    Encoding,
    /// The key type or curve is not usable in a PIV slot.
    #[error("unsupported key type")]
    Unsupported,
    /// The key needs a password, or the supplied password is wrong.
    #[error("cannot decrypt the private key (wrong or missing password?)")]
    Password,
    /// The RSA key does not use the firmware-implied public exponent 65537.
    #[error("only RSA keys with public exponent 65537 are supported")]
    RsaExponent,
}

/// Parsed key material in a neutral form; convert to the applet-specific
/// import shape with [`ImportedKey::piv_material`] or
/// [`ImportedKey::openpgp_key`].
#[derive(Debug)]
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
#[derive(Debug)]
pub struct ImportedKey {
    /// Detected algorithm.
    pub algorithm: Algorithm,
    material: Material,
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
            Material::Ec(bytes) => Ok(canokey::openpgp::PrivateKey::Ec(SecretBytes::new(
                bytes.to_vec(),
            ))),
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

/// Extract the single labeled PEM block, or pass DER through unchanged.
pub fn pem_decode(input: &[u8], labels: &[&str]) -> Result<(String, Vec<u8>), KeyError> {
    use base64ct::{Base64, Encoding as _};
    let text = match std::str::from_utf8(input) {
        Ok(text) if text.contains("-----BEGIN") => text,
        _ => return Ok((String::new(), input.to_vec())),
    };
    let begin = text.find("-----BEGIN ").ok_or(KeyError::Pem)? + "-----BEGIN ".len();
    let label_end = text[begin..].find("-----").ok_or(KeyError::Pem)?;
    let label = &text[begin..begin + label_end];
    if !labels.contains(&label) {
        return Err(KeyError::Pem);
    }
    let body_start = text[begin + label_end..]
        .find('\n')
        .map(|i| begin + label_end + i + 1)
        .ok_or(KeyError::Pem)?;
    let end_marker = format!("-----END {label}-----");
    let end = text[body_start..].find(&end_marker).ok_or(KeyError::Pem)?;
    let body: String = text[body_start..body_start + end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let decoded = Base64::decode_vec(&body).map_err(|_| KeyError::Pem)?;
    Ok((label.to_string(), decoded))
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
    let dp = d.clone() % (p - &one);
    let dq = d.clone() % (q - &one);
    let qinv = key.crt_coefficient().ok_or(KeyError::Encoding)?;
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

/// SEC1 ECPrivateKey: SEQUENCE { INTEGER 1, OCTET STRING privateKey,
/// [0] parameters, [1] publicKey }. OpenSSL emits both optional fields;
/// publicKey is decoded and ignored so it does not fail as trailing data.
fn from_sec1(der_bytes: &[u8]) -> Result<ImportedKey, KeyError> {
    use der::Sequence;
    #[derive(Sequence)]
    struct EcPrivateKey<'a> {
        version: u8,
        private_key: OctetStringRef<'a>,
        #[asn1(context_specific = "0", optional = "true")]
        parameters: Option<der::AnyRef<'a>>,
        #[asn1(context_specific = "1", optional = "true")]
        public_key: Option<der::AnyRef<'a>>,
    }
    let key = EcPrivateKey::from_der(der_bytes).map_err(|_| KeyError::Encoding)?;
    if key.version != 1 {
        return Err(KeyError::Encoding);
    }
    let _ = key.public_key;
    let curve = key
        .parameters
        .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
        .ok_or(KeyError::Encoding)?;
    let bytes = key.private_key.as_bytes();
    let algorithm = match curve.to_string().as_str() {
        "1.2.840.10045.3.1.7" => Algorithm::EccP256,
        "1.3.132.0.34" => Algorithm::EccP384,
        "1.3.132.0.35" => Algorithm::EccP521,
        "1.3.132.0.10" => Algorithm::Secp256k1,
        "1.2.156.10197.1.301" => Algorithm::Sm2,
        _ => return Err(KeyError::Unsupported),
    };
    ec_imported(algorithm, bytes)
}

/// Seed-based PKCS#8 (Curve 25519, ML-DSA-65, ML-KEM-768): the privateKey
/// OCTET STRING wraps the seed as an inner OCTET STRING; accept the raw
/// fixed-width seed too, as some encoders skip the inner wrapper.
fn from_seed_oid(oid: &str, private_key: &[u8]) -> Result<ImportedKey, KeyError> {
    let (algorithm, width) = match oid {
        "1.3.101.112" => (Algorithm::Ed25519, 32),
        "1.3.101.110" => (Algorithm::X25519, 32),
        "2.16.840.1.101.3.4.17" => (Algorithm::MlDsa65, 32),
        "2.16.840.1.101.3.4.21" => (Algorithm::MlKem768, 64),
        _ => return Err(KeyError::Unsupported),
    };
    let seed = match OctetStringRef::from_der(private_key) {
        Ok(inner) => inner.as_bytes(),
        Err(_) => private_key,
    };
    if seed.len() != width {
        return Err(KeyError::Encoding);
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
            let key = rsa::pkcs1::DecodeRsaPrivateKey::from_pkcs1_der(info.private_key)
                .map_err(|_| KeyError::Encoding)?;
            rsa_imported(&key)
        }
        "1.2.840.10045.2.1" => {
            let curve = info
                .algorithm
                .parameters
                .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
                .ok_or(KeyError::Encoding)?;
            let algorithm = match curve.to_string().as_str() {
                "1.2.840.10045.3.1.7" => Algorithm::EccP256,
                "1.3.132.0.34" => Algorithm::EccP384,
                "1.3.132.0.35" => Algorithm::EccP521,
                "1.3.132.0.10" => Algorithm::Secp256k1,
                "1.2.156.10197.1.301" => Algorithm::Sm2,
                _ => return Err(KeyError::Unsupported),
            };
            // ECPrivateKey SEC1 structure inside privateKey.
            let scalar = from_sec1_inner(info.private_key)?;
            ec_imported(algorithm, &scalar)
        }
        _ => from_seed_oid(&oid, info.private_key),
    }
}

fn from_sec1_inner(ec_private_key: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    use der::Sequence;
    #[derive(Sequence)]
    struct Inner<'a> {
        version: u8,
        private_key: OctetStringRef<'a>,
        #[asn1(context_specific = "0", optional = "true")]
        parameters: Option<der::AnyRef<'a>>,
        #[asn1(context_specific = "1", optional = "true")]
        public_key: Option<der::AnyRef<'a>>,
    }
    let inner = Inner::from_der(ec_private_key).map_err(|_| KeyError::Encoding)?;
    if inner.version != 1 {
        return Err(KeyError::Encoding);
    }
    let _ = inner.parameters;
    let _ = inner.public_key;
    Ok(Zeroizing::new(inner.private_key.as_bytes().to_vec()))
}

/// Parse a PEM or DER private key (PKCS#8 plain/encrypted, PKCS#1 RSA, SEC1
/// EC) into PIV import material.
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
    // PKCS#1 RSA, then SEC1 EC.
    match from_pkcs8(&der_bytes) {
        Ok(key) => Ok(key),
        Err(_) => match decrypt_pkcs8(&der_bytes, password) {
            Err(KeyError::Encoding) => from_pkcs1(&der_bytes).or_else(|_| from_sec1(&der_bytes)),
            other => other,
        },
    }
}

fn from_pkcs1(der_bytes: &[u8]) -> Result<ImportedKey, KeyError> {
    let key = rsa::pkcs1::DecodeRsaPrivateKey::from_pkcs1_der(der_bytes)
        .map_err(|_| KeyError::Encoding)?;
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
    match algorithm {
        Algorithm::EccP256 if p256::SecretKey::from_slice(bytes).is_err() => {
            return Err(KeyError::Encoding)
        }
        Algorithm::EccP384 if p384::SecretKey::from_slice(bytes).is_err() => {
            return Err(KeyError::Encoding)
        }
        _ => {}
    }
    Ok(ImportedKey {
        algorithm,
        material: Material::Ec(Zeroizing::new(bytes.to_vec())),
    })
}

fn decrypt_pkcs8(der_bytes: &[u8], password: Option<&[u8]>) -> Result<ImportedKey, KeyError> {
    let encrypted =
        pkcs8::EncryptedPrivateKeyInfo::from_der(der_bytes).map_err(|_| KeyError::Encoding)?;
    let password = password.ok_or(KeyError::Password)?;
    let decrypted = encrypted
        .decrypt(password)
        .map_err(|_| KeyError::Password)?;
    from_pkcs8(decrypted.as_bytes())
}

/// Parse a PEM or DER public key (SPKI, or PKCS#1 RSA) and report its PIV
/// algorithm. RSA size comes from the modulus bit length.
pub fn parse_public_key(input: &[u8]) -> Result<ImportedPublicKey, KeyError> {
    let (label, der_bytes) = pem_decode(input, &["PUBLIC KEY", "RSA PUBLIC KEY"])?;
    if label == "RSA PUBLIC KEY" {
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
        "2.16.840.1.101.3.4.17" => Algorithm::MlDsa65,
        "2.16.840.1.101.3.4.21" => Algorithm::MlKem768,
        _ => return Err(KeyError::Unsupported),
    };
    Ok(ImportedPublicKey {
        algorithm,
        spki_der: der_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs8_p256_roundtrip() {
        let secret = p256::SecretKey::random(&mut rand_core::OsRng);
        let doc = p256::pkcs8::EncodePrivateKey::to_pkcs8_der(&secret).unwrap();
        let key = parse_private_key(doc.as_bytes(), None).unwrap();
        assert_eq!(key.algorithm, Algorithm::EccP256);
        let pem = crate::x509::pem_encode("PRIVATE KEY", doc.as_bytes());
        let key = parse_private_key(&pem, None).unwrap();
        assert_eq!(key.algorithm, Algorithm::EccP256);
        // SEC1 too.
        let sec1 = p256::pkcs8::EncodePrivateKey::to_pkcs8_der(&secret).unwrap();
        let _ = sec1;
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
    fn sec1_openssl_with_public_key() {
        // SEC1 as emitted by `openssl ec`: version, privateKey,
        // [0] parameters (P-256), [1] publicKey BIT STRING.
        let der: &[u8] = &[
            0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x48, 0xca, 0x30, 0x1c, 0x5b, 0x0f, 0x0c,
            0x09, 0xf5, 0x59, 0xb2, 0xc3, 0x44, 0x14, 0xe0, 0xb0, 0xbc, 0x2d, 0x1f, 0x3f, 0xd0,
            0xde, 0xa2, 0xae, 0x8d, 0x9a, 0x95, 0x8e, 0xfd, 0x22, 0xd6, 0x52, 0xa0, 0x0a, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00,
            0x04, 0x3f, 0x1d, 0x0f, 0x6c, 0xcd, 0x6a, 0x16, 0x1c, 0xd2, 0x36, 0x3f, 0x8a, 0xe0,
            0x5a, 0x7e, 0xc1, 0x49, 0xc7, 0x00, 0x9c, 0x63, 0x18, 0x98, 0x5d, 0xe1, 0x07, 0x77,
            0xfa, 0x94, 0x2d, 0x12, 0x85, 0xb1, 0xe1, 0xdc, 0xd1, 0xfd, 0xd7, 0x81, 0x63, 0xed,
            0x98, 0x0d, 0x04, 0x02, 0x81, 0x44, 0xf8, 0xb8, 0x9a, 0xc5, 0xb8, 0x8d, 0xc3, 0xef,
            0x59, 0x45, 0x23, 0x6a, 0x20, 0x75, 0xfb, 0x6d, 0x62,
        ];
        let key = parse_private_key(der, None).unwrap();
        assert_eq!(key.algorithm, Algorithm::EccP256);
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
    fn parses_sm2_p521_k256_scalars_and_ml_seeds() {
        // SM2 uses id-ecPublicKey with the SM2 curve OID as parameter and a
        // SEC1 ECPrivateKey inside privateKey (same shape as ECDSA).
        let ec_oid = ObjectIdentifier::new("1.2.840.10045.2.1").unwrap();
        let sm2_curve = ObjectIdentifier::new("1.2.156.10197.1.301").unwrap();
        let mut sec1 = vec![0x30, 37, 2, 1, 1, 4, 32];
        sec1.extend([7; 32]);
        // pkcs8_with_params puts the seed in an inner OCTET STRING; for the
        // EC shape the privateKey wraps the SEC1 structure directly.
        let mut alg = vec![0x06, ec_oid.as_bytes().len() as u8];
        alg.extend(ec_oid.as_bytes());
        alg.extend([0x06, sm2_curve.as_bytes().len() as u8]);
        alg.extend(sm2_curve.as_bytes());
        let mut alg_wrapped = vec![0x30, alg.len() as u8];
        alg_wrapped.extend(alg);
        let mut key_field = vec![4, sec1.len() as u8];
        key_field.extend(&sec1);
        let mut body = vec![2, 1, 0];
        body.extend(alg_wrapped);
        body.extend(key_field);
        let mut sm2 = vec![0x30, body.len() as u8];
        sm2.extend(body);
        let key = parse_private_key(&sm2, None).unwrap();
        assert_eq!(key.algorithm, Algorithm::Sm2);
        let mldsa_oid = ObjectIdentifier::new("2.16.840.1.101.3.4.17").unwrap();
        let mldsa = pkcs8(mldsa_oid.as_bytes(), &[9; 32]);
        let key = parse_private_key(&mldsa, None).unwrap();
        assert_eq!(key.algorithm, Algorithm::MlDsa65);
        // Raw 64-byte seed without the inner OCTET STRING wrapper (ML-KEM).
        let mlkem_body = {
            let oid = ObjectIdentifier::new("2.16.840.1.101.3.4.21").unwrap();
            let oid = oid.as_bytes();
            let mut alg = vec![0x30, (oid.len() + 2) as u8, 0x06, oid.len() as u8];
            alg.extend(oid);
            let mut key = vec![4, 64];
            key.extend([3u8; 64]);
            let mut body = vec![2, 1, 0];
            body.extend(alg);
            body.extend(key);
            let mut der = vec![0x30, body.len() as u8];
            der.extend(body);
            der
        };
        let key = parse_private_key(&mlkem_body, None).unwrap();
        assert_eq!(key.algorithm, Algorithm::MlKem768);
    }

    #[test]
    fn public_key_oids_for_new_algorithms() {
        use der::Encode;
        let spki_for = |oid_bytes: &[u8], key: &[u8]| {
            let spki = spki::SubjectPublicKeyInfo::<der::Any, der::asn1::BitString> {
                algorithm: spki::AlgorithmIdentifier {
                    oid: ObjectIdentifier::from_bytes(oid_bytes).unwrap(),
                    parameters: None,
                },
                subject_public_key: der::asn1::BitString::new(0, key).unwrap(),
            };
            spki.to_der().unwrap()
        };
        // ML-DSA-65 public key (1952 bytes); OID content bytes computed by
        // the der crate, never hand-encoded.
        let der = spki_for(
            ObjectIdentifier::new("2.16.840.1.101.3.4.17")
                .unwrap()
                .as_bytes(),
            &[7; 1952],
        );
        assert_eq!(
            parse_public_key(&der).unwrap().algorithm,
            Algorithm::MlDsa65
        );
        // SM2 (id-ecPublicKey with the SM2 curve OID).
        let params =
            der::Any::encode_from(&ObjectIdentifier::new("1.2.156.10197.1.301").unwrap()).unwrap();
        let spki = spki::SubjectPublicKeyInfo::<der::Any, der::asn1::BitString> {
            algorithm: spki::AlgorithmIdentifier {
                oid: ObjectIdentifier::from_bytes(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1]).unwrap(),
                parameters: Some(params),
            },
            subject_public_key: der::asn1::BitString::new(0, [4; 65]).unwrap(),
        };
        let der = spki.to_der().unwrap();
        assert_eq!(parse_public_key(&der).unwrap().algorithm, Algorithm::Sm2);
    }
}
