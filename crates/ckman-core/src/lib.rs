//! Session layer over libcanokey: operation driving, probing, and per-applet
//! sessions.
//!
//! The application drives every libcanokey operation itself: it holds the
//! exclusive connection lease for the whole operation, exchanges each command
//! exactly once, and feeds back the complete response including SW1/SW2.

use canokey::{DeviceProfile, Operation, ProbeOptions, Step};

pub mod admin;
pub mod keys;
pub mod oath;
pub mod piv;
pub mod uri;
pub mod x509;

/// The caller's raw transport: one complete command APDU in, one complete
/// response (data + SW1/SW2) out. Exactly one round trip per call.
pub type Exchange<'a, E> = dyn FnMut(&[u8]) -> Result<Vec<u8>, E> + 'a;

/// Failure while driving one operation to completion.
#[derive(Debug, thiserror::Error)]
pub enum DriveError<E> {
    /// The caller's transport failed; drop the operation and isolate or
    /// drain the connection before reuse.
    #[error("transport exchange failed: {0}")]
    Transport(E),
    /// libcanokey reported a protocol-level failure.
    #[error("protocol error: {0}")]
    Protocol(#[from] canokey::Error),
}

/// Drive one operation over `exchange` and return its typed result.
///
/// `exchange` must perform exactly one raw transport round trip per call,
/// returning the complete response including SW1/SW2. A transport failure
/// aborts the operation; never feed a late response into a new operation.
pub fn execute<T, E>(mut op: Operation<T>, exchange: &mut Exchange<E>) -> Result<T, DriveError<E>> {
    let mut step = op.start()?;
    while step == Step::Exchange {
        let response = exchange(op.command()?.as_bytes()).map_err(DriveError::Transport)?;
        step = op.advance(&response)?;
    }
    Ok(op.take_result()?)
}

/// Probe the device, selecting Admin and PIV applets in the process.
///
/// Probe switches applets, so it must never run between another operation's
/// authentication and its target command. The returned profile is immutable;
/// it becomes stale after configuration writes or reconnects.
pub fn probe<E>(exchange: &mut Exchange<E>) -> Result<DeviceProfile, DriveError<E>> {
    execute(canokey::probe_device(ProbeOptions::default())?, exchange)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io;

    /// Transcript-driven exchange, mirroring the libcanokey examples.
    struct Script {
        transcript: VecDeque<(&'static [u8], &'static [u8])>,
    }

    impl Script {
        fn exchange(&mut self, command: &[u8]) -> io::Result<Vec<u8>> {
            let (expected, response) = self
                .transcript
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "unexpected exchange"))?;
            assert_eq!(command, expected, "command differs from transcript");
            Ok(response.to_vec())
        }
    }

    const PROBE_TRANSCRIPT: &[(&[u8], &[u8])] = &[
        (&[0, 0xa4, 4, 0, 5, 0xf0, 0, 0, 0, 0, 0], &[0x90, 0]),
        (&[0, 0x31, 0, 0, 0], b"9.0.0\x90\x00"),
        (&[0, 0x31, 1, 0, 0], b"CanoKey\x90\x00"),
        (&[0, 0x32, 0, 0, 0], &[1, 2, 3, 4, 0x90, 0]),
        (&[0, 0xa4, 4, 0, 5, 0xa0, 0, 0, 3, 8, 0], &[0x90, 0]),
        (&[0, 0xfd, 0, 0, 0], &[5, 7, 0, 0x90, 0]),
    ];

    #[test]
    fn probe_over_scripted_exchange() {
        let mut script = Script {
            transcript: PROBE_TRANSCRIPT.iter().copied().collect(),
        };
        let profile = probe(&mut |command| script.exchange(command)).unwrap();
        // Unknown firmware stays observable and never enables mutations.
        assert_eq!(profile.info().firmware_text(), b"9.0.0");
        assert_eq!(profile.info().model(), Some("CanoKey"));
        assert_eq!(profile.info().serial(), Some(&[1, 2, 3, 4][..]));
        assert!(profile.info().piv_version().is_some());
    }

    #[test]
    fn transport_failure_aborts_operation() {
        let mut calls = 0;
        let result: Result<DeviceProfile, DriveError<io::Error>> = probe(&mut |_command| {
            calls += 1;
            Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "card removed",
            ))
        });
        assert!(matches!(result, Err(DriveError::Transport(_))));
        assert_eq!(calls, 1, "a failed exchange is never retried");
    }
}
