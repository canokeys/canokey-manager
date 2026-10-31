//! Validate redundant PQ key fields before reducing an import to its seed.

use super::{Algorithm, KeyError};
use der::asn1::OctetStringRef;
use der::{Decode, Sequence, Tagged};
use zeroize::Zeroizing;

#[derive(Sequence)]
struct Both<'a> {
    seed: OctetStringRef<'a>,
    expanded_key: OctetStringRef<'a>,
}

pub(super) fn seed<'a>(
    algorithm: Algorithm,
    private_key: &'a [u8],
    public_key: Option<&[u8]>,
) -> Result<&'a [u8], KeyError> {
    let (width, expanded_width) = match algorithm {
        Algorithm::MlDsa65 => (32, 4032),
        Algorithm::MlKem768 => (64, 2400),
        _ => return Err(KeyError::Unsupported),
    };
    let (seed, expanded) = if private_key.len() == width {
        // Preserve every previously supported raw seed.
        (private_key, None)
    } else {
        let value = der::AnyRef::from_der(private_key).map_err(|_| KeyError::Encoding)?;
        match value.tag() {
            der::Tag::ContextSpecific {
                constructed: false,
                number: der::TagNumber::N0,
            } => (value.value(), None),
            der::Tag::Sequence => {
                let both = Both::from_der(private_key).map_err(|_| KeyError::Encoding)?;
                if both.expanded_key.as_bytes().len() != expanded_width {
                    return Err(KeyError::Encoding);
                }
                (both.seed.as_bytes(), Some(both.expanded_key.as_bytes()))
            }
            der::Tag::OctetString if value.value().len() == width => (value.value(), None),
            der::Tag::OctetString if value.value().len() == expanded_width => {
                return Err(KeyError::Unsupported);
            }
            _ => return Err(KeyError::Encoding),
        }
    };
    if seed.len() != width {
        return Err(KeyError::Encoding);
    }
    if expanded.is_some() || public_key.is_some() {
        let derived = derive(algorithm, seed)?;
        if expanded.is_some_and(|supplied| supplied != derived.expanded.as_slice())
            || public_key.is_some_and(|supplied| supplied != derived.public)
        {
            return Err(KeyError::Encoding);
        }
    }
    Ok(seed)
}

struct Derived {
    public: Vec<u8>,
    expanded: Zeroizing<Vec<u8>>,
}

fn derive(algorithm: Algorithm, seed: &[u8]) -> Result<Derived, KeyError> {
    match algorithm {
        Algorithm::MlDsa65 => {
            use fips204::traits::{KeyGen, SerDes};
            let seed = seed.try_into().map_err(|_| KeyError::Encoding)?;
            let (public, private) = fips204::ml_dsa_65::KG::keygen_from_seed(seed);
            let expanded = Zeroizing::new(private.into_bytes());
            Ok(Derived {
                public: public.into_bytes().to_vec(),
                expanded: Zeroizing::new(expanded.to_vec()),
            })
        }
        Algorithm::MlKem768 => {
            use fips203::traits::{KeyGen, SerDes};
            if seed.len() != 64 {
                return Err(KeyError::Encoding);
            }
            let d = Zeroizing::new(seed[..32].try_into().map_err(|_| KeyError::Encoding)?);
            let z = Zeroizing::new(seed[32..].try_into().map_err(|_| KeyError::Encoding)?);
            let (public, private) = fips203::ml_kem_768::KG::keygen_from_seed(*d, *z);
            let expanded = Zeroizing::new(private.into_bytes());
            Ok(Derived {
                public: public.into_bytes().to_vec(),
                expanded: Zeroizing::new(expanded.to_vec()),
            })
        }
        _ => Err(KeyError::Unsupported),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::parse_private_key;
    use der::Encode;

    const FIXTURES: [(Algorithm, &[u8], &[u8]); 2] = [
        (
            Algorithm::MlDsa65,
            include_bytes!("../../tests/fixtures/mldsa65-openssl.der"),
            include_bytes!("../../tests/fixtures/mldsa65-openssl-pub.der"),
        ),
        (
            Algorithm::MlKem768,
            include_bytes!("../../tests/fixtures/mlkem768-openssl.der"),
            include_bytes!("../../tests/fixtures/mlkem768-openssl-pub.der"),
        ),
    ];

    #[test]
    fn derived_keys_match_openssl_byte_for_byte() {
        // Independent OpenSSL 3.5.9 fixtures, deterministic seeds 00..1f/00..3f.
        for (algorithm, private, public) in FIXTURES {
            let info = pkcs8::PrivateKeyInfo::from_der(private).unwrap();
            let both = Both::from_der(info.private_key).unwrap();
            let public = spki::SubjectPublicKeyInfoRef::from_der(public).unwrap();
            let derived = derive(algorithm, both.seed.as_bytes()).unwrap();
            assert_eq!(derived.expanded.as_slice(), both.expanded_key.as_bytes());
            assert_eq!(
                derived.public,
                public.subject_public_key.as_bytes().unwrap()
            );
        }
    }

    #[test]
    fn inconsistent_seed_and_expanded_key_are_rejected() {
        for (_, private, _) in FIXTURES {
            let original = pkcs8::PrivateKeyInfo::from_der(private).unwrap();
            let both = Both::from_der(original.private_key).unwrap();
            let expanded = both.expanded_key.as_bytes();
            // Exercise the start, middle and end, including ML-KEM's final z.
            for offset in [0, expanded.len() / 2, expanded.len() - 1] {
                let mut wrong = expanded.to_vec();
                wrong[offset] ^= 1;
                let encoded = Both {
                    seed: both.seed,
                    expanded_key: OctetStringRef::new(&wrong).unwrap(),
                }
                .to_der()
                .unwrap();
                let mut info = original.clone();
                info.private_key = &encoded;
                assert!(parse_private_key(&info.to_der().unwrap(), None).is_err());
            }
            let mut wrong_seed = both.seed.as_bytes().to_vec();
            wrong_seed[0] ^= 1;
            let encoded = Both {
                seed: OctetStringRef::new(&wrong_seed).unwrap(),
                expanded_key: both.expanded_key,
            }
            .to_der()
            .unwrap();
            let mut info = original.clone();
            info.private_key = &encoded;
            assert!(parse_private_key(&info.to_der().unwrap(), None).is_err());
        }
    }

    #[test]
    fn outer_public_key_is_checked_for_every_seed_encoding() {
        for (algorithm, private, public) in FIXTURES {
            let original = pkcs8::PrivateKeyInfo::from_der(private).unwrap();
            let both = Both::from_der(original.private_key).unwrap();
            let raw_seed = both.seed.as_bytes();
            let wrapped = both.seed.to_der().unwrap();
            let mut implicit = vec![0x80, raw_seed.len() as u8];
            implicit.extend(raw_seed);
            let public = spki::SubjectPublicKeyInfoRef::from_der(public).unwrap();
            let public = public.subject_public_key.as_bytes().unwrap();
            for encoded in [raw_seed, &wrapped, &implicit, original.private_key] {
                let mut info = original.clone();
                info.private_key = encoded;
                info.public_key = Some(public);
                assert_eq!(
                    parse_private_key(&info.to_der().unwrap(), None)
                        .unwrap()
                        .algorithm,
                    algorithm
                );
                for offset in [0, public.len() - 1] {
                    let mut wrong = public.to_vec();
                    wrong[offset] ^= 1;
                    let mut invalid = info.clone();
                    invalid.public_key = Some(&wrong);
                    assert!(parse_private_key(&invalid.to_der().unwrap(), None).is_err());
                }
                for wrong in [&[][..], &public[..public.len() - 1]] {
                    let mut invalid = info.clone();
                    invalid.public_key = Some(wrong);
                    assert!(parse_private_key(&invalid.to_der().unwrap(), None).is_err());
                }
            }
        }
    }
}
