//! CTAPHID framing: packet fragmentation/reassembly and channel management.
//!
//! This module is deliberately device-agnostic. Real USB HID I/O is plugged
//! in through [`ReportIo`]; tests use an in-memory loopback authenticator.
//! The framing layer never retries or reorders reports on its own — a
//! failure aborts the in-flight message and is reported to the caller, which
//! owns the connection-lease discipline required by libcanokey.

use std::io;
use std::time::{Duration, Instant};

use thiserror::Error;

/// USB full-speed HID report size used by CTAPHID.
pub const REPORT_LEN: usize = 64;
const INIT_HEADER: usize = 7; // CID(4) + CMD(1) + BCNT(2)
const CONT_HEADER: usize = 5; // CID(4) + SEQ(1)
const INIT_PAYLOAD: usize = REPORT_LEN - INIT_HEADER; // 57
const CONT_PAYLOAD: usize = REPORT_LEN - CONT_HEADER; // 59
const MAX_SEQ: u8 = 0x7f;
/// Largest message that fits the continuation-sequence space.
pub const MAX_MESSAGE_LEN: usize = INIT_PAYLOAD + (MAX_SEQ as usize + 1) * CONT_PAYLOAD;

/// Channel identifier reserved for channel-allocation traffic.
pub const BROADCAST_CID: u32 = 0xffff_ffff;

/// CTAPHID command byte, including the 0x80 command flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Ping,
    Msg,
    Lock,
    Init,
    Wink,
    Cbor,
    Cancel,
    Error,
    Keepalive,
}

impl Command {
    pub const fn byte(self) -> u8 {
        match self {
            Command::Ping => 0x81,
            Command::Msg => 0x83,
            Command::Lock => 0x84,
            Command::Init => 0x86,
            Command::Wink => 0x88,
            Command::Cbor => 0x90,
            Command::Cancel => 0x91,
            Command::Error => 0xbf,
            Command::Keepalive => 0xbb,
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0x81 => Command::Ping,
            0x83 => Command::Msg,
            0x84 => Command::Lock,
            0x86 => Command::Init,
            0x88 => Command::Wink,
            0x90 => Command::Cbor,
            0x91 => Command::Cancel,
            0xbf => Command::Error,
            0xbb => Command::Keepalive,
            _ => return None,
        })
    }
}

/// Error code carried by a CTAPHID ERROR packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceError {
    InvalidCmd,
    InvalidParam,
    InvalidLen,
    InvalidSeq,
    MsgTimeout,
    ChannelBusy,
    LockRequired,
    InvalidChannel,
    Other,
    Unknown(u8),
}

impl DeviceError {
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x01 => DeviceError::InvalidCmd,
            0x02 => DeviceError::InvalidParam,
            0x03 => DeviceError::InvalidLen,
            0x04 => DeviceError::InvalidSeq,
            0x05 => DeviceError::MsgTimeout,
            0x06 => DeviceError::ChannelBusy,
            0x0a => DeviceError::LockRequired,
            0x0b => DeviceError::InvalidChannel,
            0x7f => DeviceError::Other,
            other => DeviceError::Unknown(other),
        }
    }
}

/// Status carried by a CTAPHID KEEPALIVE packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keepalive {
    Processing,
    UserPresenceNeeded,
    Unknown(u8),
}

impl Keepalive {
    fn from_byte(byte: u8) -> Self {
        match byte {
            0x01 => Keepalive::Processing,
            0x02 => Keepalive::UserPresenceNeeded,
            other => Keepalive::Unknown(other),
        }
    }
}

#[derive(Debug, Error)]
pub enum CtapHidError {
    #[error("HID I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("timed out waiting for the authenticator")]
    Timeout,
    #[error("message of {0} bytes exceeds the CTAPHID limit of {MAX_MESSAGE_LEN}")]
    PayloadTooLarge(usize),
    #[error("malformed report from the authenticator: {0}")]
    Malformed(&'static str),
    #[error("authenticator reported an error: {0:?}")]
    Device(DeviceError),
    #[error("authenticator answered on an unexpected channel")]
    WrongChannel,
}

/// Raw HID report access. Implementations must deliver exactly one 64-byte
/// report per call and must not retry or reorder reports themselves.
pub trait ReportIo {
    fn write_report(&mut self, report: &[u8; REPORT_LEN]) -> io::Result<()>;
    /// Returns `Ok(None)` when `timeout` expires without a report.
    fn read_report(&mut self, timeout: Duration) -> io::Result<Option<[u8; REPORT_LEN]>>;
}

/// Split `payload` into one initialization packet plus continuation packets.
pub fn frame_message(
    cid: u32,
    cmd: Command,
    payload: &[u8],
) -> Result<Vec<[u8; REPORT_LEN]>, CtapHidError> {
    if payload.len() > MAX_MESSAGE_LEN {
        return Err(CtapHidError::PayloadTooLarge(payload.len()));
    }
    let mut packets = Vec::new();
    let mut init = [0u8; REPORT_LEN];
    init[..4].copy_from_slice(&cid.to_be_bytes());
    init[4] = cmd.byte();
    init[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    let head = payload.len().min(INIT_PAYLOAD);
    init[INIT_HEADER..INIT_HEADER + head].copy_from_slice(&payload[..head]);
    packets.push(init);

    let mut offset = head;
    let mut seq = 0u8;
    while offset < payload.len() {
        let mut cont = [0u8; REPORT_LEN];
        cont[..4].copy_from_slice(&cid.to_be_bytes());
        cont[4] = seq;
        let take = (payload.len() - offset).min(CONT_PAYLOAD);
        cont[CONT_HEADER..CONT_HEADER + take].copy_from_slice(&payload[offset..offset + take]);
        packets.push(cont);
        offset += take;
        seq += 1;
    }
    Ok(packets)
}

/// Reassembles fragmented messages for one channel. Report-level protocol
/// violations abort the in-flight message and surface an error; the decoder
/// is then back in idle state and usable again.
#[derive(Default)]
pub struct MessageDecoder {
    active: Option<Partial>,
}

struct Partial {
    cmd: u8,
    expected: usize,
    buf: Vec<u8>,
    next_seq: u8,
}

impl MessageDecoder {
    pub fn new() -> Self {
        MessageDecoder::default()
    }

    /// Feed one report belonging to the channel's CID. Returns the command
    /// byte and full payload once a message completes.
    pub fn push(
        &mut self,
        report: &[u8; REPORT_LEN],
    ) -> Result<Option<(Command, Vec<u8>)>, CtapHidError> {
        let tag = report[4];
        if tag & 0x80 != 0 {
            // Initialization packet: aborts any partial message.
            let expected = u16::from_be_bytes([report[5], report[6]]) as usize;
            let cmd =
                Command::from_byte(tag).ok_or(CtapHidError::Malformed("unknown command byte"))?;
            if expected > MAX_MESSAGE_LEN {
                self.active = None;
                return Err(CtapHidError::Malformed("declared length out of range"));
            }
            let head = expected.min(INIT_PAYLOAD);
            let mut buf = Vec::with_capacity(expected);
            buf.extend_from_slice(&report[INIT_HEADER..INIT_HEADER + head]);
            if buf.len() == expected {
                self.active = None;
                return Ok(Some((cmd, buf)));
            }
            self.active = Some(Partial {
                cmd: tag,
                expected,
                buf,
                next_seq: 0,
            });
            return Ok(None);
        }

        // Continuation packet.
        let mut partial = self
            .active
            .take()
            .ok_or(CtapHidError::Malformed("unexpected continuation packet"))?;
        if tag != partial.next_seq {
            return Err(CtapHidError::Device(DeviceError::InvalidSeq));
        }
        let remaining = partial.expected - partial.buf.len();
        let take = remaining.min(CONT_PAYLOAD);
        partial
            .buf
            .extend_from_slice(&report[CONT_HEADER..CONT_HEADER + take]);
        partial.next_seq += 1;
        if partial.buf.len() == partial.expected {
            let cmd = Command::from_byte(partial.cmd)
                .ok_or(CtapHidError::Malformed("unknown command byte"))?;
            return Ok(Some((cmd, partial.buf)));
        }
        self.active = Some(partial);
        Ok(None)
    }
}

/// One allocated CTAPHID channel over a [`ReportIo`] device.
pub struct CtapHidChannel<T> {
    io: T,
    cid: u32,
}

/// Capabilities reported by the device in the INIT response.
#[derive(Debug, Clone, Copy, Default)]
pub struct Capabilities {
    pub wink: bool,
    pub cbor: bool,
    pub nmsg: bool,
}

impl<T: ReportIo> CtapHidChannel<T> {
    /// Allocate a channel via broadcast INIT. Also serves as resync: the
    /// device aborts any half-finished message when it sees a broadcast INIT.
    pub fn allocate(
        mut io: T,
        nonce: [u8; 8],
        timeout: Duration,
    ) -> Result<(Self, Capabilities), CtapHidError> {
        let packets = frame_message(BROADCAST_CID, Command::Init, &nonce)?;
        for packet in &packets {
            io.write_report(packet)?;
        }
        let deadline = Instant::now() + timeout;
        let mut decoder = MessageDecoder::new();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(CtapHidError::Timeout);
            }
            let report = match io.read_report(remaining)? {
                Some(report) => report,
                None => return Err(CtapHidError::Timeout),
            };
            if u32::from_be_bytes(report[..4].try_into().unwrap()) != BROADCAST_CID {
                continue; // stale traffic on another channel
            }
            if let Some((cmd, payload)) = decoder.push(&report)? {
                if cmd != Command::Init {
                    continue;
                }
                if payload.len() < 17 || payload[..8] != nonce {
                    return Err(CtapHidError::Malformed(
                        "INIT response does not match nonce",
                    ));
                }
                let cid = u32::from_be_bytes(payload[8..12].try_into().unwrap());
                let caps = payload[16];
                let capabilities = Capabilities {
                    wink: caps & 0x01 != 0,
                    cbor: caps & 0x04 != 0,
                    nmsg: caps & 0x08 != 0,
                };
                return Ok((CtapHidChannel { io, cid }, capabilities));
            }
        }
    }

    pub fn cid(&self) -> u32 {
        self.cid
    }

    /// Send one command and wait for its response, forwarding KEEPALIVE
    /// statuses to `on_keepalive`. The deadline applies to the whole exchange.
    pub fn request(
        &mut self,
        cmd: Command,
        payload: &[u8],
        timeout: Duration,
        on_keepalive: &mut dyn FnMut(Keepalive),
    ) -> Result<Vec<u8>, CtapHidError> {
        let packets = frame_message(self.cid, cmd, payload)?;
        for packet in &packets {
            self.io.write_report(packet)?;
        }
        let deadline = Instant::now() + timeout;
        let mut decoder = MessageDecoder::new();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(CtapHidError::Timeout);
            }
            let report = match self.io.read_report(remaining)? {
                Some(report) => report,
                None => return Err(CtapHidError::Timeout),
            };
            if u32::from_be_bytes(report[..4].try_into().unwrap()) != self.cid {
                continue; // interleaved traffic from another channel
            }
            match decoder.push(&report)? {
                None => continue,
                Some((Command::Keepalive, body)) => {
                    let status = body.first().copied().unwrap_or(0);
                    on_keepalive(Keepalive::from_byte(status));
                }
                Some((Command::Error, body)) => {
                    let code = body.first().copied().unwrap_or(0x7f);
                    return Err(CtapHidError::Device(DeviceError::from_byte(code)));
                }
                Some((response, body)) if response == cmd => return Ok(body),
                Some((_, _)) => {
                    return Err(CtapHidError::Malformed("unexpected response command"));
                }
            }
        }
    }

    /// Abort an in-flight CBOR command. The CTAP-level cancellation shows up
    /// as the pending command's response, not as a CANCEL response.
    pub fn cancel(&mut self) -> Result<(), CtapHidError> {
        for packet in &frame_message(self.cid, Command::Cancel, &[])? {
            self.io.write_report(packet)?;
        }
        Ok(())
    }

    pub fn into_inner(self) -> T {
        self.io
    }
}

/// In-memory loopback authenticator for tests. Implements the device side of
/// CTAPHID: INIT channel allocation, PING echo, and scripted CBOR behavior.
#[cfg(test)]
pub mod loopback {
    use super::*;
    use std::collections::VecDeque;

    pub enum CborBehavior {
        /// Respond immediately with this payload.
        Respond(Vec<u8>),
        /// Emit these keepalive statuses, then respond with the payload.
        KeepaliveThen(Vec<Keepalive>, Vec<u8>),
        /// Emit a HID-level error instead of a response.
        Fail(DeviceError),
    }

    pub struct Loopback {
        /// Reports written by the host, for inspection by tests.
        pub inbox: VecDeque<[u8; REPORT_LEN]>,
        /// Reports queued by the device, for preloading by tests.
        pub outbox: VecDeque<[u8; REPORT_LEN]>,
        decoder: MessageDecoder,
        next_cid: u32,
        pub cbor: CborBehavior,
    }

    impl Loopback {
        pub fn new(cbor: CborBehavior) -> Self {
            Loopback {
                inbox: VecDeque::new(),
                outbox: VecDeque::new(),
                decoder: MessageDecoder::new(),
                next_cid: 1,
                cbor,
            }
        }

        fn respond(&mut self, cid: u32, cmd: Command, payload: &[u8]) {
            for packet in frame_message(cid, cmd, payload).expect("loopback frame") {
                self.outbox.push_back(packet);
            }
        }

        fn handle(&mut self, cid: u32, cmd: Command, payload: &[u8]) {
            match cmd {
                Command::Init => {
                    let cid = self.next_cid;
                    self.next_cid += 1;
                    let mut response = Vec::with_capacity(17);
                    response.extend_from_slice(payload); // nonce
                    response.extend_from_slice(&cid.to_be_bytes());
                    response.extend_from_slice(&[2, 1, 0, 0]); // version
                    response.push(0x01 | 0x04); // wink + cbor
                    self.respond(BROADCAST_CID, Command::Init, &response);
                }
                Command::Ping => self.respond(cid, Command::Ping, payload),
                Command::Wink => self.respond(cid, Command::Wink, &[]),
                Command::Cbor => {
                    // Snapshot the scripted behavior first so `respond` can
                    // take &mut self.
                    enum Act {
                        Respond(Vec<u8>),
                        KeepaliveThen(Vec<u8>, Vec<u8>),
                        Fail(u8),
                    }
                    let act = match &self.cbor {
                        CborBehavior::Respond(payload) => Act::Respond(payload.clone()),
                        CborBehavior::KeepaliveThen(statuses, payload) => {
                            let statuses = statuses
                                .iter()
                                .map(|status| match status {
                                    Keepalive::Processing => 0x01,
                                    Keepalive::UserPresenceNeeded => 0x02,
                                    Keepalive::Unknown(other) => *other,
                                })
                                .collect();
                            Act::KeepaliveThen(statuses, payload.clone())
                        }
                        CborBehavior::Fail(error) => Act::Fail(match error {
                            DeviceError::InvalidCmd => 0x01,
                            DeviceError::InvalidParam => 0x02,
                            DeviceError::InvalidLen => 0x03,
                            DeviceError::InvalidSeq => 0x04,
                            DeviceError::MsgTimeout => 0x05,
                            DeviceError::ChannelBusy => 0x06,
                            DeviceError::LockRequired => 0x0a,
                            DeviceError::InvalidChannel => 0x0b,
                            DeviceError::Other => 0x7f,
                            DeviceError::Unknown(other) => *other,
                        }),
                    };
                    match act {
                        Act::Respond(payload) => self.respond(cid, Command::Cbor, &payload),
                        Act::KeepaliveThen(statuses, payload) => {
                            for status in statuses {
                                self.respond(cid, Command::Keepalive, &[status]);
                            }
                            self.respond(cid, Command::Cbor, &payload);
                        }
                        Act::Fail(byte) => self.respond(cid, Command::Error, &[byte]),
                    }
                }
                _ => self.respond(cid, Command::Error, &[0x01]), // INVALID_CMD
            }
        }
    }

    impl ReportIo for Loopback {
        fn write_report(&mut self, report: &[u8; REPORT_LEN]) -> io::Result<()> {
            let cid = u32::from_be_bytes(report[..4].try_into().unwrap());
            self.inbox.push_back(*report);
            if let Some((cmd, payload)) = self.decoder.push(report).map_err(io_other)? {
                self.handle(cid, cmd, &payload);
            }
            Ok(())
        }

        fn read_report(&mut self, _timeout: Duration) -> io::Result<Option<[u8; REPORT_LEN]>> {
            Ok(self.outbox.pop_front())
        }
    }

    fn io_other(error: CtapHidError) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::loopback::{CborBehavior, Loopback};
    use super::*;

    const CID: u32 = 0x0102_0304;

    fn decode_all(packets: &[[u8; REPORT_LEN]]) -> (Command, Vec<u8>) {
        let mut decoder = MessageDecoder::new();
        let mut result = None;
        for packet in packets {
            result = decoder.push(packet).unwrap();
        }
        result.expect("complete message")
    }

    #[test]
    fn frame_roundtrip_boundaries() {
        for len in [0, 1, 57, 58, 57 + 59, 116, 117, MAX_MESSAGE_LEN] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let packets = frame_message(CID, Command::Cbor, &payload).unwrap();
            let (cmd, decoded) = decode_all(&packets);
            assert_eq!(cmd, Command::Cbor);
            assert_eq!(decoded, payload, "length {len}");
        }
    }

    #[test]
    fn frame_rejects_oversized_payload() {
        let payload = vec![0u8; MAX_MESSAGE_LEN + 1];
        assert!(matches!(
            frame_message(CID, Command::Cbor, &payload),
            Err(CtapHidError::PayloadTooLarge(n)) if n == MAX_MESSAGE_LEN + 1
        ));
    }

    #[test]
    fn decoder_rejects_bad_sequence() {
        let payload = vec![7u8; 100];
        let mut packets = frame_message(CID, Command::Ping, &payload).unwrap();
        packets[1][4] = 5; // corrupt the sequence number
        let mut decoder = MessageDecoder::new();
        assert!(decoder.push(&packets[0]).unwrap().is_none());
        assert!(matches!(
            decoder.push(&packets[1]),
            Err(CtapHidError::Device(DeviceError::InvalidSeq))
        ));
    }

    #[test]
    fn decoder_rejects_orphan_continuation() {
        let mut report = [0u8; REPORT_LEN];
        report[..4].copy_from_slice(&CID.to_be_bytes());
        report[4] = 0; // continuation, seq 0
        let mut decoder = MessageDecoder::new();
        assert!(matches!(
            decoder.push(&report),
            Err(CtapHidError::Malformed(_))
        ));
    }

    fn channel(cbor: CborBehavior) -> CtapHidChannel<Loopback> {
        let (channel, caps) =
            CtapHidChannel::allocate(Loopback::new(cbor), *b"nonce123", Duration::from_secs(1))
                .unwrap();
        assert!(caps.cbor && caps.wink && !caps.nmsg);
        channel
    }

    #[test]
    fn allocate_assigns_channel() {
        let channel = channel(CborBehavior::Respond(vec![]));
        assert_eq!(channel.cid(), 1);
    }

    #[test]
    fn allocate_rejects_wrong_nonce() {
        let mut device = Loopback::new(CborBehavior::Respond(vec![]));
        // Preload a response to a different nonce.
        let mut response = Vec::new();
        response.extend_from_slice(b"nonceXXX");
        response.extend_from_slice(&1u32.to_be_bytes());
        response.extend_from_slice(&[2, 1, 0, 0, 0x04]);
        let packets = frame_message(BROADCAST_CID, Command::Init, &response).unwrap();
        device.outbox.extend(packets);
        let result = CtapHidChannel::allocate(device, *b"nonce123", Duration::from_secs(1));
        assert!(matches!(result, Err(CtapHidError::Malformed(_))));
    }

    #[test]
    fn ping_echoes_payload() {
        let mut channel = channel(CborBehavior::Respond(vec![]));
        let payload = b"hello ctaphid";
        let response = channel
            .request(Command::Ping, payload, Duration::from_secs(1), &mut |_| {
                panic!("no keepalive expected")
            })
            .unwrap();
        assert_eq!(response, payload);
    }

    #[test]
    fn cbor_large_payload_roundtrip() {
        let payload: Vec<u8> = (0..1200).map(|i| (i % 253) as u8).collect();
        let mut channel = channel(CborBehavior::Respond(payload.clone()));
        let response = channel
            .request(Command::Cbor, &payload, Duration::from_secs(1), &mut |_| {})
            .unwrap();
        assert_eq!(response, payload);
    }

    #[test]
    fn keepalives_are_forwarded() {
        let mut channel = channel(CborBehavior::KeepaliveThen(
            vec![Keepalive::Processing, Keepalive::UserPresenceNeeded],
            vec![0x00],
        ));
        let mut seen = Vec::new();
        let response = channel
            .request(
                Command::Cbor,
                &[0x04],
                Duration::from_secs(1),
                &mut |status| seen.push(status),
            )
            .unwrap();
        assert_eq!(response, vec![0x00]);
        assert_eq!(
            seen,
            vec![Keepalive::Processing, Keepalive::UserPresenceNeeded]
        );
    }

    #[test]
    fn device_error_surfaces() {
        let mut channel = channel(CborBehavior::Fail(DeviceError::ChannelBusy));
        let result = channel.request(Command::Cbor, &[0x04], Duration::from_secs(1), &mut |_| {});
        assert!(matches!(
            result,
            Err(CtapHidError::Device(DeviceError::ChannelBusy))
        ));
    }

    #[test]
    fn cancel_sends_empty_cancel_packet() {
        let mut channel = channel(CborBehavior::Respond(vec![]));
        channel.cancel().unwrap();
        let device = channel.into_inner();
        let last = device.inbox.back().unwrap();
        assert_eq!(&last[..4], &1u32.to_be_bytes());
        assert_eq!(last[4], Command::Cancel.byte());
        assert_eq!(&last[5..7], &[0, 0]); // BCNT = 0
    }
}
