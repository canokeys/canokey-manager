//! Typed wrappers around `canokey::ndef` (the Type 4 Tag NDEF applet).
//!
//! The NDEF applet stores one message; the CC file declares the data file.
//! Writes are crash-consistent: libcanokey zeroes the message length first
//! and writes it last, so a crash or connection loss mid-write leaves an
//! empty message instead of a stale length pointing at partial data. These
//! factories are profile-free; a failed applet SELECT reports
//! `ErrorKind::UnsupportedDevice` (NDEF disabled or absent).

use crate::{execute, DriveError, Exchange};
use canokey::{ndef, OperationOptions};

pub use canokey::ndef::NdefCapability;

/// Read the stored NDEF message (empty when none is stored).
pub fn read_message<E>(exchange: &mut Exchange<'_, E>) -> Result<Vec<u8>, DriveError<E>> {
    Ok(
        execute(ndef::read_message(OperationOptions::default())?, exchange)?
            .as_bytes()
            .to_vec(),
    )
}

/// Read the capability container observations (file id, size limit, and the
/// read-only flag).
pub fn read_capability<E>(exchange: &mut Exchange<'_, E>) -> Result<NdefCapability, DriveError<E>> {
    execute(
        ndef::read_capability(OperationOptions::default())?,
        exchange,
    )
}

/// Replace the stored NDEF message. Fails before any write when the CC marks
/// the file read-only or too small.
pub fn write_message<E>(
    message: &[u8],
    exchange: &mut Exchange<'_, E>,
) -> Result<(), DriveError<E>> {
    execute(
        ndef::write_message(message, OperationOptions::default())?,
        exchange,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io;

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
            assert_eq!(command, &expected[..], "command differs from transcript");
            Ok(response)
        }
    }

    const SELECT_APPLET: &[u8] = &[0, 0xa4, 4, 0, 7, 0xd2, 0x76, 0, 0, 0x85, 1, 1];
    const SELECT_CC: &[u8] = &[0, 0xa4, 0, 0x0c, 2, 0xe1, 0x03];
    const READ_CC: &[u8] = &[0, 0xb0, 0, 0, 15];
    // CC: NDEF file 0x0001, writable, max 1024 bytes.
    const CC: &[u8] = &[
        0x00, 0x0f, 0x20, 0x00, 0xff, 0x00, 0xff, 0x04, 0x06, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00,
        0x90, 0x00,
    ];
    const SELECT_NDEF: &[u8] = &[0, 0xa4, 0, 0x0c, 2, 0x00, 0x01];

    #[test]
    fn read_empty_message() {
        // Mirrors canokey-ndef's doctest transcript.
        let mut script = Script::new(&[
            (SELECT_APPLET, &[0x90, 0]),
            (SELECT_CC, &[0x90, 0]),
            (READ_CC, CC),
            (SELECT_NDEF, &[0x90, 0]),
            (&[0, 0xb0, 0, 0, 2], &[0, 0, 0x90, 0]),
        ]);
        let message = read_message(&mut |c| script.exchange(c)).unwrap();
        assert!(message.is_empty());
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn write_is_crash_consistent() {
        // The write clears NLEN first and writes the real NLEN last.
        let mut script = Script::new(&[
            (SELECT_APPLET, &[0x90, 0]),
            (SELECT_CC, &[0x90, 0]),
            (READ_CC, CC),
            (SELECT_NDEF, &[0x90, 0]),
            (&[0, 0xd6, 0, 0, 2, 0, 0], &[0x90, 0]), // NLEN := 0 first
            (&[0, 0xd6, 0, 2, 3, 0xd1, 2, 5], &[0x90, 0]), // message at offset 2
            (&[0, 0xd6, 0, 0, 2, 0, 3], &[0x90, 0]), // NLEN := 3 last
        ]);
        write_message(&[0xd1, 2, 5], &mut |c| script.exchange(c)).unwrap();
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn read_only_cc_rejects_before_any_update() {
        // CC with write-access byte set (last byte before SW) → the write
        // fails after the CC read, before any UPDATE.
        let mut cc = CC.to_vec();
        cc[14] = 1; // write-access byte (last content byte)
        let mut script = Script::new(&[
            (SELECT_APPLET, &[0x90, 0]),
            (SELECT_CC, &[0x90, 0]),
            (READ_CC, &[]),
        ]);
        script.transcript[2].1 = cc;
        let error = write_message(&[0xd1, 2, 5], &mut |c| script.exchange(c)).unwrap_err();
        let DriveError::Protocol(error) = error else {
            panic!("expected protocol error")
        };
        assert_eq!(error.kind, canokey::ErrorKind::SecurityStatusNotSatisfied);
        assert!(script.transcript.is_empty(), "no UPDATE may be sent");
    }
}
