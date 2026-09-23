//! FIDO2/CTAP operations over PC/SC (the ISO 7816 envelope, driven with a
//! plain [`crate::execute`]) or over USB HID (CTAPHID CBOR, through
//! [`CtapHidAdapter`]). The canokey-ctap factories are profile-free; every
//! operation re-SELECTs and re-authenticates from caller-owned inputs.
//!
//! ClientPIN protocol selection: prefer V2 when the authenticator offers it
//! (`AuthenticatorInfo::pin_uv_auth_protocols`), else V1. All randomness
//! (ephemeral P-256 scalars, V2 IVs) comes from the host CSPRNG here.

use crate::{execute, DriveError, Exchange};
use canokey::ctap::credmgmt::{self, CredentialEntry, CredsMetadata, RpEntry};
use canokey::ctap::pin::{self, Permissions, PinRetries, PinSession, PinToken};
use canokey::ctap::UserEntity;
use canokey::ctap::{self, AuthenticatorInfo, PinUvAuthProtocol, PublicKeyCredentialDescriptor};
use canokey::{Error, ErrorKind, Operation, OperationOptions};
use ckman_transport::ctaphid::{Command, CtapHidChannel, Keepalive, ReportIo};
use std::io;
use std::time::Duration;

/// Failure preparing or driving a FIDO operation. CTAP-level failures carry
/// their raw status byte in `Error::application_status` of the Drive variant.
#[derive(Debug, thiserror::Error)]
pub enum FidoError<E> {
    /// Transport or protocol failure while driving the operation.
    #[error(transparent)]
    Drive(#[from] DriveError<E>),
    /// The host CSPRNG failed before any I/O; nothing was sent.
    #[error("failed to generate randomness: {0}")]
    Random(#[from] getrandom::Error),
}

fn run<T, E>(
    operation: Result<Operation<T>, Error>,
    exchange: &mut Exchange<'_, E>,
) -> Result<T, FidoError<E>> {
    Ok(execute(operation.map_err(DriveError::from)?, exchange)?)
}

/// CTAPHID frames carry up to 7609 bytes, and over PC/SC the envelope's own
/// 61xx continuation covers larger replies; the default 258-byte physical
/// budget would reject a full getInfo.
fn options() -> OperationOptions {
    OperationOptions {
        exchange: canokey::ExchangeOptions {
            max_response_bytes: 7609,
            ..Default::default()
        },
        ..Default::default()
    }
}

/// FIDO2 AID selected by every envelope operation.
const FIDO2_SELECT: &[u8] = &[
    0x00, 0xa4, 0x04, 0x00, 0x08, 0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01,
];

/// Adapts the ISO 7816 envelope that canokey-ctap speaks onto a CTAPHID
/// channel: SELECT is answered locally (HID has no applet selection), and
/// `80 10` CTAP messages (chained or extended-Lc) are unwrapped and sent as
/// one CTAPHID CBOR request. Keepalive statuses are forwarded to the
/// caller's callback (touch prompts live there).
pub struct CtapHidAdapter<T: ReportIo> {
    channel: CtapHidChannel<T>,
    pending: Vec<u8>,
    timeout: Duration,
    on_keepalive: Box<dyn FnMut(Keepalive) + Send>,
}

impl<T: ReportIo> CtapHidAdapter<T> {
    /// Wrap an allocated channel. `timeout` bounds each complete CBOR
    /// exchange, including the wait for user presence.
    pub fn new(
        channel: CtapHidChannel<T>,
        timeout: Duration,
        on_keepalive: impl FnMut(Keepalive) + Send + 'static,
    ) -> Self {
        Self {
            channel,
            pending: Vec::new(),
            timeout,
            on_keepalive: Box::new(on_keepalive),
        }
    }

    /// Borrow the channel (e.g. to send CTAPHID CANCEL on Ctrl-C).
    pub fn channel_mut(&mut self) -> &mut CtapHidChannel<T> {
        &mut self.channel
    }

    /// Unwrap into the channel.
    pub fn into_inner(self) -> CtapHidChannel<T> {
        self.channel
    }

    fn hid_err(error: impl std::fmt::Display) -> io::Error {
        io::Error::new(io::ErrorKind::Other, error.to_string())
    }

    /// One logical APDU of the envelope in, one full response out; satisfies
    /// the [`crate::Exchange`] contract.
    pub fn exchange(&mut self, command: &[u8]) -> io::Result<Vec<u8>> {
        if command == FIDO2_SELECT {
            return Ok(vec![0x90, 0x00]);
        }
        if command.len() < 5 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "short APDU"));
        }
        let (cla, ins) = (command[0], command[1]);
        if ins != 0x10 || cla & !0x10 != 0x80 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a CTAP message command",
            ));
        }
        // Short Lc, or extended 3-byte Lc when the first Lc byte is zero.
        let (data, rest) = if command[4] == 0 {
            if command.len() < 7 {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "short Lc"));
            }
            let len = u16::from_be_bytes([command[5], command[6]]) as usize;
            (&command[7..], len)
        } else {
            (&command[5..], command[4] as usize)
        };
        if data.len() != rest {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Lc does not match the APDU length",
            ));
        }
        self.pending.extend_from_slice(data);
        if cla & 0x10 != 0 {
            return Ok(vec![0x90, 0x00]); // more fragments follow
        }
        let message = std::mem::take(&mut self.pending);
        let response = self
            .channel
            .request(
                Command::Cbor,
                &message,
                self.timeout,
                &mut self.on_keepalive,
            )
            .map_err(Self::hid_err)?;
        let mut out = response;
        out.extend([0x90, 0x00]);
        Ok(out)
    }
}

/// The authenticatorGetInfo typed result.
pub fn get_info<E>(exchange: &mut Exchange<'_, E>) -> Result<AuthenticatorInfo, FidoError<E>> {
    run(ctap::get_info(options()), exchange)
}

/// Ask the authenticator to identify itself (blink); no state change.
pub fn selection<E>(exchange: &mut Exchange<'_, E>) -> Result<(), FidoError<E>> {
    run(ctap::selection(options()), exchange)
}

/// authenticatorReset: wipes all FIDO state and the PIN. Firmware requires
/// the command within seconds of power-up plus a touch; on CanoKey 2.0+ a
/// re-plug is mandatory. The CLI re-establishes the connection first.
pub fn reset<E>(exchange: &mut Exchange<'_, E>) -> Result<(), FidoError<E>> {
    run(ctap::reset(options()), exchange)
}

/// Preferred ClientPIN protocol: V2 when offered, else V1.
pub fn preferred_protocol(info: &AuthenticatorInfo) -> PinUvAuthProtocol {
    match info.pin_uv_auth_protocols() {
        Some(protocols) if protocols.contains(&2) => PinUvAuthProtocol::V2,
        _ => PinUvAuthProtocol::V1,
    }
}

/// The PIN retry counter (clientPIN subcommand 0x01, read-only).
pub fn pin_retries<E>(
    protocol: PinUvAuthProtocol,
    exchange: &mut Exchange<'_, E>,
) -> Result<PinRetries, FidoError<E>> {
    run(pin::get_pin_retries(protocol, options()), exchange)
}

/// ClientPIN key agreement with a fresh ephemeral P-256 scalar (regenerated
/// in the astronomically unlikely case the CSPRNG yields an invalid scalar).
pub fn key_agreement<E>(
    protocol: PinUvAuthProtocol,
    exchange: &mut Exchange<'_, E>,
) -> Result<PinSession, FidoError<E>> {
    for _ in 0..8 {
        let mut scalar = zeroize::Zeroizing::new([0; 32]);
        getrandom::fill(&mut scalar[..])?;
        match pin::get_key_agreement(protocol, &scalar, options()) {
            Ok(operation) => return run(Ok(operation), exchange),
            Err(error) if error.kind == ErrorKind::InvalidArgument => continue,
            Err(error) => return Err(FidoError::Drive(DriveError::Protocol(error))),
        }
    }
    Err(FidoError::Drive(DriveError::Protocol(Error::new(
        ErrorKind::InvalidArgument,
    ))))
}

fn fresh_iv(protocol: PinUvAuthProtocol) -> Result<Option<[u8; 16]>, getrandom::Error> {
    if protocol == PinUvAuthProtocol::V2 {
        let mut iv = [0; 16];
        getrandom::fill(&mut iv)?;
        Ok(Some(iv))
    } else {
        Ok(None)
    }
}

/// Set the initial FIDO2 PIN (the authenticator must have none set).
pub fn set_pin<E>(
    session: &PinSession,
    new_pin: &[u8],
    exchange: &mut Exchange<'_, E>,
) -> Result<(), FidoError<E>> {
    let iv = fresh_iv(session.protocol())?;
    run(
        pin::set_pin(session, new_pin, iv.as_ref(), options()),
        exchange,
    )
}

/// Change the FIDO2 PIN.
pub fn change_pin<E>(
    session: &PinSession,
    old_pin: &[u8],
    new_pin: &[u8],
    exchange: &mut Exchange<'_, E>,
) -> Result<(), FidoError<E>> {
    let iv = fresh_iv(session.protocol())?;
    run(
        pin::change_pin(session, old_pin, new_pin, iv.as_ref(), options()),
        exchange,
    )
}

/// Obtain a pinUvAuthToken with explicit permissions.
pub fn pin_token<E>(
    session: &PinSession,
    pin: &[u8],
    permissions: Permissions,
    rp_id: Option<&str>,
    exchange: &mut Exchange<'_, E>,
) -> Result<PinToken, FidoError<E>> {
    let iv = fresh_iv(session.protocol())?;
    run(
        pin::get_pin_token_with_permissions(
            session,
            pin,
            permissions,
            rp_id,
            iv.as_ref(),
            options(),
        ),
        exchange,
    )
}

/// Resident-credential counters.
pub fn creds_metadata<E>(
    token: &PinToken,
    protocol: PinUvAuthProtocol,
    exchange: &mut Exchange<'_, E>,
) -> Result<CredsMetadata, FidoError<E>> {
    run(
        credmgmt::get_creds_metadata(token, protocol, options()),
        exchange,
    )
}

/// Enumerate relying parties with resident credentials (in-operation GetNext
/// loop; a NO_CREDENTIALS status yields an empty vector).
pub fn enumerate_rps<E>(
    token: &PinToken,
    protocol: PinUvAuthProtocol,
    exchange: &mut Exchange<'_, E>,
) -> Result<Vec<RpEntry>, FidoError<E>> {
    run(
        credmgmt::enumerate_rps(token, protocol, options()),
        exchange,
    )
}

/// Enumerate one RP's resident credentials. `metadata_only` selects the
/// CanoKey vendor extension that omits public keys (needed for ML-DSA-sized
/// responses).
pub fn enumerate_credentials<E>(
    token: &PinToken,
    protocol: PinUvAuthProtocol,
    rp_id_hash: [u8; 32],
    metadata_only: bool,
    exchange: &mut Exchange<'_, E>,
) -> Result<Vec<CredentialEntry>, FidoError<E>> {
    run(
        credmgmt::enumerate_credentials(token, protocol, rp_id_hash, metadata_only, options()),
        exchange,
    )
}

/// Delete one resident credential.
pub fn delete_credential<E>(
    token: &PinToken,
    protocol: PinUvAuthProtocol,
    credential_id: &PublicKeyCredentialDescriptor,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), FidoError<E>> {
    run(
        credmgmt::delete_credential(token, protocol, credential_id, options()),
        exchange,
    )
}

/// Replace the user name/display name on one resident credential, keeping its
/// user handle. Unset `UserEntity` fields are cleared by the authenticator;
/// callers preserving a field must pass its current value.
pub fn update_user_information<E>(
    token: &PinToken,
    protocol: PinUvAuthProtocol,
    credential_id: &PublicKeyCredentialDescriptor,
    user: &UserEntity,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), FidoError<E>> {
    run(
        credmgmt::update_user_information(token, protocol, credential_id, user, options()),
        exchange,
    )
}

/// Toggle the persistent always-UV authenticator setting.
pub fn toggle_always_uv<E>(
    token: &PinToken,
    protocol: PinUvAuthProtocol,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), FidoError<E>> {
    run(
        ctap::config::toggle_always_uv(token, protocol, options()),
        exchange,
    )
}

/// Enable the persistent long-touch-for-reset setting. There is no way back
/// short of a full authenticator reset: once enabled, a reset requires
/// holding the touch for up to 30 seconds and never succeeds over NFC.
pub fn enable_long_touch_for_reset<E>(
    token: &PinToken,
    protocol: PinUvAuthProtocol,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), FidoError<E>> {
    run(
        ctap::config::enable_long_touch_for_reset(token, protocol, options()),
        exchange,
    )
}

/// Read the whole CTAP largeBlobs array (16-byte truncated SHA-256 prefix
/// plus the CBOR array), fragmenting at the channel's capacity.
pub fn large_blobs_read<E>(exchange: &mut Exchange<'_, E>) -> Result<Vec<u8>, FidoError<E>> {
    run(ctap::largeblob::read_array(options()), exchange)
}

/// Replace the whole CTAP largeBlobs array. `token` is required when the
/// authenticator has a PIN set (largeBlobWrite permission); the write is
/// length-checked before any I/O (17..=4096 bytes on CanoKey).
pub fn large_blobs_write<E>(
    data: &[u8],
    token: Option<(&PinToken, PinUvAuthProtocol)>,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), FidoError<E>> {
    run(
        ctap::largeblob::write_array(data, token, options()),
        exchange,
    )
}

/// Set the minimum PIN length, optionally forcing a PIN change and binding
/// the policy to relying parties.
pub fn set_min_pin_length<E>(
    token: &PinToken,
    protocol: PinUvAuthProtocol,
    new_min_pin_length: u8,
    force_pin_change: Option<bool>,
    rp_ids: Vec<String>,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), FidoError<E>> {
    run(
        ctap::config::set_min_pin_length(
            token,
            protocol,
            new_min_pin_length,
            force_pin_change,
            rp_ids,
            options(),
        ),
        exchange,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ckman_transport::ctaphid::CtapHidChannel;
    use std::collections::VecDeque;
    use std::time::Duration;

    // Reuse the loopback device-side CTAPHID from the transport tests.
    use ckman_transport::ctaphid::loopback;

    /// Transcript-driven envelope exchange, mirroring the other applet tests:
    /// one complete command APDU in, one complete response (with SW1/SW2) out.
    struct Script {
        transcript: VecDeque<(Vec<u8>, Vec<u8>)>,
    }

    impl Script {
        fn new(transcript: &[(&[u8], &[u8])]) -> Self {
            Script {
                transcript: transcript
                    .iter()
                    .map(|(c, r)| (c.to_vec(), r.to_vec()))
                    .collect(),
            }
        }
        fn exchange(&mut self, command: &[u8]) -> io::Result<Vec<u8>> {
            let (expected, response) = self
                .transcript
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "unexpected exchange"))?;
            assert_eq!(command, expected, "command differs from transcript");
            Ok(response)
        }
    }

    const SELECT_OK: (&[u8], &[u8]) = (FIDO2_SELECT, &[0x90, 0x00]);

    #[test]
    fn selection_transcript_and_timeout() {
        // authenticatorSelection (0x0B): success, and the 0x2f user-action
        // timeout the CLI reports as "timed out waiting for user presence".
        let mut script = Script::new(&[
            SELECT_OK,
            (&[0x80, 0x10, 0, 0, 1, 0x0b], &[0x00, 0x90, 0x00]),
        ]);
        selection(&mut |c| script.exchange(c)).unwrap();
        assert!(script.transcript.is_empty());

        let mut script = Script::new(&[
            SELECT_OK,
            (&[0x80, 0x10, 0, 0, 1, 0x0b], &[0x2f, 0x90, 0x00]),
        ]);
        let error = selection(&mut |c| script.exchange(c)).unwrap_err();
        match error {
            FidoError::Drive(DriveError::Protocol(error)) => {
                assert_eq!(error.application_status, Some(0x2f))
            }
            other => panic!("unexpected error: {other}"),
        }
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn large_blobs_read_array_transcript() {
        // With this module's 7609-byte response budget the fragment size is
        // the 1024-byte default: {1: 1024, 3: 0}. A short fragment terminates
        // the read (fixture shape mirrored from canokey-ctap's largeblob.rs).
        let mut script = Script::new(&[
            SELECT_OK,
            (
                &[
                    0x80, 0x10, 0, 0, 8, 0x0c, 0xa2, 0x01, 0x19, 0x04, 0x00, 0x03, 0x00,
                ],
                &[0x00, 0xa1, 0x01, 0x43, 1, 2, 3, 0x90, 0x00],
            ),
        ]);
        let array = large_blobs_read(&mut |c| script.exchange(c)).unwrap();
        assert_eq!(array, [1, 2, 3]);
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn large_blobs_write_array_without_pin_transcript() {
        // 17 bytes (16-byte prefix + empty CBOR array 0x80), no PIN set:
        // {2: h'..', 3: 0, 4: 17} and no pinUvAuthParam.
        let data: Vec<u8> = (0..16).chain([0x80]).collect();
        let mut message = vec![0x0c, 0xa3, 0x02, 0x51];
        message.extend(&data);
        message.extend([0x03, 0x00, 0x04, 0x11]);
        let mut command = vec![0x80, 0x10, 0, 0, message.len() as u8];
        command.extend(&message);
        let mut script = Script::new(&[SELECT_OK, (&[], &[0x00, 0x90, 0x00])]);
        script.transcript[1].0 = command;
        large_blobs_write(&data, None, &mut |c| script.exchange(c)).unwrap();
        assert!(script.transcript.is_empty());
    }

    /// Fixed ClientPIN V1 fixture (platform scalar 0x01..=0x20, PIN "1234",
    /// token plaintext 0x10..=0x2F), mirrored from canokey-ctap's
    /// tests/support; cross-checked there against an independent Python
    /// implementation. Makes every pinUvAuthParam deterministic.
    const EPHEMERAL_SCALAR: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    const PEER_KEY_AGREEMENT_PAYLOAD: &str = "a101a5010203381820012158200d0918a04198474605615b6df90fdcb34791fb3ecb822f4b26eb6e4fc4511b9d22582019b90c1b83c0c35cfbbb31ead32bb52ae33622f57e3cc1638097ce97f430baba";
    const TOKEN_CT_V1: &str = "b98cc635132fa3ea8c191b7a4aa3e093ce926c35488221b4684fce766f3b14b0";

    fn hex(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn authenticated_config_and_credmgmt_goldens_over_loopback() {
        // Golden messages from canokey-ctap's config.rs / credmgmt.rs tests
        // (V1 token; HMACs cross-checked with Python stdlib hmac there).
        const MSG_ENABLE_LONG_TOUCH: &str = "0da3010403010450967369eaf14c745bb57c5340d0cc9416";
        const MSG_UPDATE: &str =
            "0aa4010702a202a2626964440102030464747970656a7075626c69632d6b657903a36269644405060708646e616d6565616c6963656b646973706c61794e616d6565416c696365030104503f101861670b03d4287bc78e520e9a21";
        let mut token_payload = vec![0x00, 0xa1, 0x02, 0x58, 0x20];
        token_payload.extend(hex(TOKEN_CT_V1));
        let mut peer_payload = vec![0x00];
        peer_payload.extend(hex(PEER_KEY_AGREEMENT_PAYLOAD));
        let device = loopback::Loopback::new(loopback::CborBehavior::Scripted(vec![
            peer_payload,
            token_payload,
            vec![0x00],
            vec![0x00],
        ]));
        let mut adapter = CtapHidAdapter::new(
            CtapHidChannel::allocate(device, *b"nonce123", Duration::from_secs(1))
                .unwrap()
                .0,
            Duration::from_secs(1),
            |_| {},
        );
        let operation =
            pin::get_key_agreement(PinUvAuthProtocol::V1, &EPHEMERAL_SCALAR, options()).unwrap();
        let session = execute::<_, io::Error>(operation, &mut |c| adapter.exchange(c)).unwrap();
        let operation = pin::get_pin_token(&session, b"1234", None, options()).unwrap();
        let token = execute::<_, io::Error>(operation, &mut |c| adapter.exchange(c)).unwrap();

        enable_long_touch_for_reset(&token, PinUvAuthProtocol::V1, &mut |c| adapter.exchange(c))
            .unwrap();
        let descriptor = PublicKeyCredentialDescriptor::new("public-key", vec![1, 2, 3, 4]);
        let user = UserEntity {
            id: vec![5, 6, 7, 8],
            name: Some("alice".to_string()),
            display_name: Some("Alice".to_string()),
        };
        update_user_information(
            &token,
            PinUvAuthProtocol::V1,
            &descriptor,
            &user,
            &mut |c| adapter.exchange(c),
        )
        .unwrap();

        let device = adapter.into_inner().into_inner();
        assert_eq!(device.cbor_payloads().len(), 4);
        assert_eq!(device.cbor_payloads()[2], hex(MSG_ENABLE_LONG_TOUCH));
        assert_eq!(device.cbor_payloads()[3], hex(MSG_UPDATE));
    }

    /// CanoKey 3.1.0-shaped getInfo response payload, mirrored in full from
    /// the canokey-ctap ctap2_commands fixture (17 map entries).
    fn get_info_payload() -> Vec<u8> {
        fn hex(s: &str) -> Vec<u8> {
            s.split_ascii_whitespace()
                .flat_map(|s| {
                    (0..s.len())
                        .step_by(2)
                        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                })
                .collect()
        }
        let mut payload = vec![0x00]; // CTAP1_ERR_SUCCESS
        payload.extend(hex("b1"));
        payload.extend(hex(
            "01 84 665532465f5632 684649444f5f325f30 684649444f5f325f31 684649444f5f325f33",
        ));
        payload.extend(hex(
            "02 87 6863726564426c6f62 6b6372656450726f74656374 6b686d61632d736563726574
         6e686d61632d7365637265742d6d63 6c6c61726765426c6f624b6579 6c6d696e50696e4c656e677468
         71746869726450617274795061796d656e74",
        ));
        payload.extend(hex("03 50 244eb29ee0904e4981fe1f20f8d3b8f4"));
        payload.extend(hex(
            "04 a9 62726bf5 68616c776179735576f4 68637265644d676d74f5 69617574686e72436667f5
         69636c69656e7450696ef4 6a6c61726765426c6f6273f5 6e70696e557641757468546f6b656ef5
         6f7365744d696e50494e4c656e677468f5 706d616b654372656455764e6f74527164f5",
        ));
        payload.extend(hex("05 1904b0"));
        payload.extend(hex("06 82 01 02"));
        payload.extend(hex("07 10"));
        payload.extend(hex("08 1880"));
        payload.extend(hex("09 82 636e6663 63757362"));
        payload.extend(hex("0a 84
         a263616c672664747970656a7075626c69632d6b6579
         a263616c672764747970656a7075626c69632d6b6579
         a263616c67383064747970656a7075626c69632d6b6579
         a263616c67383564747970656a7075626c69632d6b6579"));
        payload.extend(hex("0b 191000"));
        payload.extend(hex("0d 04"));
        payload.extend(hex("0e 1a00030100"));
        payload.extend(hex("0f 1820"));
        payload.extend(hex("10 04"));
        payload.extend(hex("14 1864"));
        payload.extend(hex("15 81 1840"));
        payload
    }

    #[test]
    fn hid_adapter_drives_get_info_over_loopback() {
        let channel = CtapHidChannel::allocate(
            loopback::Loopback::new(loopback::CborBehavior::Respond(get_info_payload())),
            *b"nonce123",
            Duration::from_secs(1),
        )
        .unwrap()
        .0;
        let mut adapter = CtapHidAdapter::new(channel, Duration::from_secs(1), |_| {});
        let info = get_info::<io::Error>(&mut |command| adapter.exchange(command)).unwrap();
        assert_eq!(
            info.versions(),
            &["U2F_V2", "FIDO_2_0", "FIDO_2_1", "FIDO_2_3"]
        );
        assert_eq!(info.aaguid()[..4], hex_bytes("244eb29e")[..]);
        assert_eq!(info.min_pin_length(), Some(4));
        assert_eq!(preferred_protocol(&info), PinUvAuthProtocol::V2);
        // The adapter answered SELECT locally and sent exactly one CBOR
        // request carrying the bare getInfo command byte.
        let device = adapter.into_inner().into_inner();
        assert_eq!(device.cbor_payloads().len(), 1);
        assert_eq!(device.cbor_payloads()[0], &[0x04]);
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn clientpin_set_pin_v2_golden_message_over_loopback() {
        // Fixed scalar and IV from canokey-ctap's client_pin fixtures: the
        // scripted CBOR reply checks the deterministic golden message.
        fn hex(s: &str) -> Vec<u8> {
            s.split_ascii_whitespace()
                .flat_map(|s| {
                    (0..s.len())
                        .step_by(2)
                        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                })
                .collect()
        }
        let scalar: [u8; 32] = (1..=32).collect::<Vec<u8>>().try_into().unwrap();
        let iv: [u8; 16] = hex("0f0e0d0c0b0a09080706050403020100").try_into().unwrap();
        let peer = hex("a101a5010203381820012158200d0918a04198474605615b6df90fdcb34791fb3ecb822f4b26eb6e4fc4511b9d22582019b90c1b83c0c35cfbbb31ead32bb52ae33622f57e3cc1638097ce97f430baba");
        let device = loopback::Loopback::new(loopback::CborBehavior::Scripted(vec![
            {
                let mut payload = vec![0x00];
                payload.extend(&peer);
                payload
            },
            vec![0x00],
        ]));
        let mut expected = vec![0x06]; // clientPIN command byte
        expected.extend(hex("a50102020303a501020338182001215820515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f2258204536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f9354045820431e258245363cec539cc0cf5ba429e4d122155741c81b7c55473fbe19c9b2650558500f0e0d0c0b0a09080706050403020100eb721e5129c4f3b3d780de13bdc001328e7c9eead4e15735a93382ae65f2b23ed020dbaea27fea48b44cad1597d65906de97d6f4444c221e1da73c2edcf7d511"));
        let mut adapter = CtapHidAdapter::new(
            CtapHidChannel::allocate(device, *b"nonce123", Duration::from_secs(1))
                .unwrap()
                .0,
            Duration::from_secs(1),
            |_| {},
        );
        let operation = pin::get_key_agreement(PinUvAuthProtocol::V2, &scalar, options()).unwrap();
        let session = execute::<_, io::Error>(operation, &mut |c| adapter.exchange(c)).unwrap();
        let operation = pin::set_pin(&session, b"1234", Some(&iv), options()).unwrap();
        execute::<_, io::Error>(operation, &mut |c| adapter.exchange(c)).unwrap();
        // The device saw the golden setPIN message as its second CBOR payload.
        let device = adapter.into_inner().into_inner();
        assert_eq!(device.cbor_payloads().len(), 2);
        assert_eq!(device.cbor_payloads()[1], expected);
    }
}
