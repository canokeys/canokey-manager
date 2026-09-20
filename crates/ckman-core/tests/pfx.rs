//! PKCS#12 bundle tests. Fixtures were generated once with OpenSSL 3.6
//! (PBES2 + PBKDF2 + AES-256-CBC, SHA-256 MAC):
//!
//! ```sh
//! openssl pkcs12 -export -inkey key.pem -in leaf.pem -out p12_pw.p12 -passout pass:pw
//! openssl pkcs12 -export -inkey key.pem -in leaf.pem -out p12_nopw.p12 -passout pass:
//! openssl pkcs12 -export -inkey key.pem -in leaf.pem -certfile ca.pem -out p12_chain.p12 -passout pass:pw
//! ```
//!
//! `leaf.pem` is signed by `ca.pem`; both are throwaway test keys.

use ckman_core::keys::{
    self, KeyError,
    KeyError::{AmbiguousCertificates, Password},
};

const PW: &[u8] = include_bytes!("fixtures/p12_pw.p12");
const NO_PW: &[u8] = include_bytes!("fixtures/p12_nopw.p12");
const CHAIN: &[u8] = include_bytes!("fixtures/p12_chain.p12");

#[test]
fn password_protected_bundle_yields_key_and_certificate() {
    let data = keys::parse_pfx(PW, Some(b"pw")).unwrap();
    assert_eq!(
        data.key.as_ref().unwrap().algorithm,
        canokey::piv::Algorithm::EccP256
    );
    assert_eq!(data.certificates.len(), 1);
    canokey::x509::parse_der(&data.certificates[0], Default::default()).unwrap();
    // The same bytes parse through the generic private-key entry point.
    let key = keys::parse_private_key(PW, Some(b"pw")).unwrap();
    assert_eq!(key.algorithm, canokey::piv::Algorithm::EccP256);
}

#[test]
fn wrong_or_missing_password_is_a_password_error() {
    assert!(matches!(
        keys::parse_pfx(PW, Some(b"wrong")),
        Err(Password) | Err(KeyError::MacMismatch)
    ));
    assert!(matches!(keys::parse_pfx(PW, None), Err(Password)));
    assert!(matches!(keys::parse_private_key(PW, None), Err(Password)));
}

#[test]
fn empty_password_bundle_needs_no_password() {
    let data = keys::parse_pfx(NO_PW, None).unwrap();
    assert!(data.key.is_some());
    assert_eq!(data.certificates.len(), 1);
}

#[test]
fn chain_bundle_picks_the_leaf_certificate() {
    let certs = keys::certificates_from_pfx(CHAIN, Some(b"pw")).unwrap();
    assert_eq!(certs.len(), 2);
    let leaf = keys::leaf_certificate(&certs).unwrap();
    let leaf = canokey::x509::parse_der(&certs[leaf], Default::default()).unwrap();
    assert_eq!(leaf.subject.display, "CN=ckman-test-leaf");
    // A single-certificate bundle is its own leaf.
    let certs = keys::certificates_from_pfx(PW, Some(b"pw")).unwrap();
    assert_eq!(keys::leaf_certificate(&certs).unwrap(), 0);
}

#[test]
fn unrelated_certificates_are_an_ambiguous_leaf() {
    // Both bundles hold the same leaf certificate and no issuer; neither
    // copy can be told apart as "the" leaf.
    let fixtures: [(&[u8], &[u8]); 2] = [(PW, b"pw"), (NO_PW, b"")];
    let certs: Vec<Vec<u8>> = fixtures
        .iter()
        .flat_map(|(bytes, password)| keys::certificates_from_pfx(bytes, Some(password)).unwrap())
        .collect();
    assert_eq!(certs.len(), 2);
    assert!(matches!(
        keys::leaf_certificate(&certs),
        Err(AmbiguousCertificates)
    ));
}
