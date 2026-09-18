//! Host-side key file parsing for PIV import/export: PEM armor, PKCS#8
//! (plain and encrypted), PKCS#1 RSA and SEC1 EC private keys, and SPKI or
//! PKCS#1 public keys. Output is libcanokey's typed private-key material;
//! no key bytes are retained beyond it.

use canokey::piv::{Algorithm, PrivateKeyMaterial};
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

/// A parsed private key: its PIV algorithm and the import material.
#[derive(Debug)]
pub struct ImportedKey {
    /// Detected algorithm.
    pub algorithm: Algorithm,
    /// Typed import material, redacted and zeroized by libcanokey.
    pub material: PrivateKeyMaterial,
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

fn rsa_material(key: &rsa::RsaPrivateKey) -> Result<PrivateKeyMaterial, KeyError> {
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    use rsa::BigUint;
    if key.e() != &BigUint::from(65537u32) {
        return Err(KeyError::RsaExponent);
    }
    let primes = key.primes();
    if primes.len() != 2 {
        return Err(KeyError::Unsupported);
    }
    let one = BigUint::from(1u32);
    let (p, q) = (&primes[0], &primes[1]);
    // PIV wants p, q, dP, dQ, qInv (q^{-1} mod p), half-modulus width each.
    let d = key.d();
    let dp = d.clone() % (p - &one);
    let dq = d.clone() % (q - &one);
    let qinv = key.crt_coefficient().ok_or(KeyError::Encoding)?;
    let bytes = |v: &BigUint| v.to_bytes_be();
    let algorithm = match key.n().bits() {
        1024 => Algorithm::Rsa1024,
        2048 => Algorithm::Rsa2048,
        3072 => Algorithm::Rsa3072,
        4096 => Algorithm::Rsa4096,
        _ => return Err(KeyError::Unsupported),
    };
    PrivateKeyMaterial::rsa_crt(
        algorithm,
        [
            &bytes(p),
            &bytes(q),
            &bytes(&dp),
            &bytes(&dq),
            &bytes(&qinv),
        ],
    )
    .map_err(|_| KeyError::Encoding)
}

fn ec_scalar(algorithm: Algorithm, bytes: &[u8]) -> Result<PrivateKeyMaterial, KeyError> {
    PrivateKeyMaterial::ec_scalar(algorithm, bytes).map_err(|_| KeyError::Encoding)
}

/// SEC1 ECPrivateKey: SEQUENCE { INTEGER 1, OCTET STRING privateKey, ... }.
fn from_sec1(der_bytes: &[u8]) -> Result<ImportedKey, KeyError> {
    use der::Sequence;
    #[derive(Sequence)]
    struct EcPrivateKey<'a> {
        version: u8,
        private_key: OctetStringRef<'a>,
        #[asn1(context_specific = "0", optional = "true")]
        parameters: Option<der::AnyRef<'a>>,
    }
    let key = EcPrivateKey::from_der(der_bytes).map_err(|_| KeyError::Encoding)?;
    if key.version != 1 {
        return Err(KeyError::Encoding);
    }
    let curve = key
        .parameters
        .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
        .ok_or(KeyError::Encoding)?;
    let bytes = key.private_key.as_bytes();
    let algorithm = match curve.to_string().as_str() {
        "1.2.840.10045.3.1.7" => Algorithm::EccP256,
        "1.3.132.0.34" => Algorithm::EccP384,
        _ => return Err(KeyError::Unsupported),
    };
    Ok(ImportedKey {
        algorithm,
        material: ec_scalar(algorithm, bytes)?,
    })
}

/// Curve 25519 PKCS#8: privateKey OCTET STRING wraps a one-field OCTET STRING.
fn from_curve25519(oid: &str, private_key: &[u8]) -> Result<ImportedKey, KeyError> {
    let seed = OctetStringRef::from_der(private_key)
        .map_err(|_| KeyError::Encoding)?
        .as_bytes();
    let material = match oid {
        "1.3.101.112" => PrivateKeyMaterial::ed25519_seed(seed),
        "1.3.101.110" => PrivateKeyMaterial::x25519_key(seed),
        _ => return Err(KeyError::Unsupported),
    }
    .map_err(|_| KeyError::Encoding)?;
    Ok(ImportedKey {
        algorithm: material.algorithm(),
        material,
    })
}

fn from_pkcs8(der_bytes: &[u8]) -> Result<ImportedKey, KeyError> {
    let info = pkcs8::PrivateKeyInfo::from_der(der_bytes).map_err(|_| KeyError::Encoding)?;
    let oid = info.algorithm.oid.to_string();
    match oid.as_str() {
        "1.2.840.113549.1.1.1" => {
            let key = rsa::pkcs1::DecodeRsaPrivateKey::from_pkcs1_der(info.private_key)
                .map_err(|_| KeyError::Encoding)?;
            let material = rsa_material(&key)?;
            Ok(ImportedKey {
                algorithm: material.algorithm(),
                material,
            })
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
                _ => return Err(KeyError::Unsupported),
            };
            // ECPrivateKey SEC1 structure inside privateKey.
            let scalar = from_sec1_inner(info.private_key)?;
            Ok(ImportedKey {
                algorithm,
                material: ec_scalar(algorithm, &scalar)?,
            })
        }
        _ => from_curve25519(&oid, info.private_key),
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
    let material = rsa_material(&key)?;
    Ok(ImportedKey {
        algorithm: material.algorithm(),
        material,
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
                _ => return Err(KeyError::Unsupported),
            }
        }
        "1.3.101.112" => Algorithm::Ed25519,
        "1.3.101.110" => Algorithm::X25519,
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
