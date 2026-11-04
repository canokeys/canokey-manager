//! Read-only firmware 3.1.0 transcripts, including chained certificate replies.
use canokey::compatibility::{DeviceObservations, PivApplicationVersion};
use canokey::{DeviceProfile, ErrorKind};
use ckman_core::{piv, DriveError};
use der::Decode;
use std::collections::VecDeque;

const ROOT: &[u8] = include_bytes!("fixtures/piv-attestation/root.der");
const ISSUER: &[u8] = include_bytes!("fixtures/piv-attestation/issuer.der");
const LEAF: &[u8] = include_bytes!("fixtures/piv-attestation/leaf.der");
const SELECT: &[u8] = &[0, 0xa4, 4, 0, 5, 0xa0, 0, 0, 3, 8];
const NOW: u64 = 1893456000;

fn profile(version: &str) -> DeviceProfile {
    let mut observed = DeviceObservations::new(version.as_bytes().to_vec());
    observed.piv_version = Some(PivApplicationVersion([6, 0, 0]));
    observed.serial = Some(vec![0x11, 0x22, 0x33, 0x44]);
    DeviceProfile::from_observations(observed).unwrap()
}
fn tlv(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if bytes.len() < 128 {
        out.push(bytes.len() as u8);
    } else {
        out.extend([0x82, (bytes.len() >> 8) as u8, bytes.len() as u8]);
    }
    out.extend(bytes);
    out
}
fn metadata(certificate: &[u8], origin: u8, pin: u8) -> Vec<u8> {
    let cert = x509_cert::Certificate::from_der(certificate).unwrap();
    let point = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .unwrap();
    let mut bytes = vec![1, 1, 0x11, 2, 2, pin, 1, 3, 1, origin];
    bytes.extend(tlv(4, &tlv(0x86, point)));
    bytes
}
struct Script(VecDeque<(Vec<u8>, Vec<u8>)>);
impl Script {
    fn new() -> Self {
        Self(VecDeque::new())
    }
    fn reply(&mut self, command: &[u8], response: &[u8]) {
        self.0.push_back((command.to_vec(), response.to_vec()));
    }
    fn operation(&mut self, command: &[u8], response: &[u8]) {
        self.reply(SELECT, &[0x90, 0]);
        let mut command = command.to_vec();
        for (i, chunk) in response.chunks(256).enumerate() {
            let remaining = response.len() - i * 256 - chunk.len();
            let mut response = chunk.to_vec();
            if remaining == 0 {
                response.extend([0x90, 0]);
            } else {
                response.extend([0x61, remaining.min(256) as u8]);
            }
            self.reply(&command, &response);
            command = vec![0, 0xc0, 0, 0, remaining.min(256) as u8];
        }
    }
    fn exchange(&mut self, command: &[u8]) -> Result<Vec<u8>, &'static str> {
        let (expected, response) = self.0.pop_front().expect("unexpected device operation");
        assert_eq!(command, expected);
        Ok(response)
    }
}
fn script() -> Script {
    let mut script = Script::new();
    script.operation(&[0, 0xf7, 0, 0x9a, 0], &metadata(LEAF, 1, 2));
    script.operation(&[0, 0xf9, 0x9a, 0, 0], LEAF);
    let mut container = tlv(0x70, ISSUER);
    container.extend([0x71, 1, 0, 0xfe, 0]);
    script.operation(
        &[0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xff, 1, 0],
        &tlv(0x53, &container),
    );
    script.operation(&[0, 0xf7, 0, 0xf9], &metadata(ISSUER, 2, 1));
    script
}

#[test]
fn firmware_310_verifies_without_credentials_or_target_private_operations() {
    let mut script = script();
    piv::verify_attestation(
        &profile("3.1.0"),
        piv::Slot::Authentication,
        ROOT,
        NOW,
        &mut |c| script.exchange(c),
    )
    .unwrap();
    assert!(script.0.is_empty());
}

#[test]
fn firmware_303_rejects_attestation_before_io() {
    let error = piv::verify_attestation(
        &profile("3.0.3"),
        piv::Slot::Authentication,
        ROOT,
        NOW,
        &mut |_| -> Result<Vec<u8>, ()> { panic!("unsupported firmware must not send APDUs") },
    )
    .unwrap_err();
    assert!(
        matches!(error, piv::PivError::Drive(DriveError::Protocol(e)) if e.kind == ErrorKind::UnsupportedFeature)
    );
}

#[test]
fn firmware_310_missing_issuer_is_not_empty_success() {
    let mut script = script();
    // Stop immediately when GET DATA reports no issuer; do not query F9 or retry.
    let first_get_data = script
        .0
        .iter()
        .position(|(c, _)| c.get(1) == Some(&0xcb))
        .unwrap();
    script.0[first_get_data].1 = vec![0x6a, 0x82];
    script.0.truncate(first_get_data + 1);
    let result = piv::verify_attestation(
        &profile("3.1.0"),
        piv::Slot::Authentication,
        ROOT,
        NOW,
        &mut |c| script.exchange(c),
    );
    assert!(
        matches!(result, Err(piv::PivError::Drive(DriveError::Protocol(e))) if e.kind == ErrorKind::NotFound)
    );
    assert!(script.0.is_empty());
}

#[test]
fn firmware_310_transport_failure_is_propagated_without_retry() {
    let mut calls = 0;
    let result = piv::verify_attestation(
        &profile("3.1.0"),
        piv::Slot::Authentication,
        ROOT,
        NOW,
        &mut |_| {
            calls += 1;
            Err("disconnected")
        },
    );
    assert!(matches!(
        result,
        Err(piv::PivError::Drive(DriveError::Transport("disconnected")))
    ));
    assert_eq!(calls, 1);
}
