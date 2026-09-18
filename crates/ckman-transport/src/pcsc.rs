//! PC/SC (CCID / contactless) transport.
//!
//! Exchanges here are raw: `transmit` passes the command APDU through
//! untouched and returns the complete response including SW1/SW2. No
//! transport-level GET RESPONSE, retry, or chaining is performed, as the
//! libcanokey contract requires. Cards are connected in exclusive share mode
//! so the caller's connection lease holds for the whole operation.

use std::ffi::CString;
use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PcscError {
    #[error("PC/SC error: {0}")]
    Pcsc(#[from] ::pcsc::Error),
}

/// A PC/SC context. Keep it alive for as long as its cards are in use.
pub struct Pcsc {
    context: ::pcsc::Context,
}

/// One PC/SC reader.
#[derive(Debug, Clone)]
pub struct Reader {
    name: CString,
}

impl Reader {
    pub fn name(&self) -> &str {
        // Reader names from PC/SC are printable on every supported platform.
        self.name.to_str().unwrap_or("<invalid reader name>")
    }

    pub(crate) fn as_cstr(&self) -> &CString {
        &self.name
    }

    /// USB CCID readers of a CanoKey carry the product string in the reader
    /// name; contactless readers are identified by ATR after connect. The
    /// CCID driver renders the name as "Canokeys Canokey ...", so the match
    /// is case-insensitive.
    pub fn looks_like_canokey(&self) -> bool {
        self.name().to_ascii_lowercase().contains("canokey")
    }
}

impl Pcsc {
    pub fn establish() -> Result<Self, PcscError> {
        Ok(Pcsc {
            context: ::pcsc::Context::establish(::pcsc::Scope::User)?,
        })
    }

    pub fn readers(&self) -> Result<Vec<Reader>, PcscError> {
        match self.context.list_readers_owned() {
            Ok(names) => Ok(names.into_iter().map(|name| Reader { name }).collect()),
            // No readers attached: report an empty list instead.
            Err(::pcsc::Error::NoReadersAvailable) => Ok(Vec::new()),
            Err(error) => Err(error.into()),
        }
    }

    /// Connect to a card in exclusive mode, honoring the connection lease.
    pub fn connect(&self, reader: &Reader) -> Result<PcscConnection, PcscError> {
        let card = self.context.connect(
            reader.as_cstr(),
            ::pcsc::ShareMode::Exclusive,
            ::pcsc::Protocols::ANY,
        )?;
        let atr = card.status2_owned()?.atr().to_owned();
        tracing::debug!(reader = reader.name(), atr = %hex(&atr), "connected");
        Ok(PcscConnection {
            card,
            reader: reader.name().to_owned(),
            atr,
        })
    }
}

/// An exclusive PC/SC card connection.
pub struct PcscConnection {
    card: ::pcsc::Card,
    reader: String,
    atr: Vec<u8>,
}

impl PcscConnection {
    pub fn reader_name(&self) -> &str {
        &self.reader
    }

    pub fn atr(&self) -> &[u8] {
        &self.atr
    }

    /// Contactless readers have no USB PID; CanoKey puts its name in the ATR
    /// historical bytes (matching the Python fork's `is_canokey` check). The
    /// CCID driver renders the reader name as "Canokeys Canokey ...", so both
    /// matches are case-insensitive.
    pub fn is_canokey(&self) -> bool {
        self.reader.to_ascii_lowercase().contains("canokey")
            || contains(&self.atr.to_ascii_lowercase(), b"canokey")
    }

    /// One raw exchange: complete command APDU in, complete response
    /// (data + SW1/SW2) out. No continuation, no retry.
    pub fn exchange(&mut self, command: &[u8]) -> io::Result<Vec<u8>> {
        tracing::trace!(command = %hex(command), ">>");
        let mut buf = vec![0u8; 64 * 1024 + 2];
        let response = self
            .card
            .transmit(command, &mut buf)
            .map_err(io::Error::other)?;
        tracing::trace!(response = %hex(response), "<<");
        Ok(response.to_vec())
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn hex(data: &[u8]) -> String {
    use std::fmt::Write;
    data.iter()
        .fold(String::with_capacity(2 * data.len()), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

#[cfg(test)]
mod tests {
    use super::contains;

    #[test]
    fn atr_substring_detection() {
        assert!(contains(b"\x00\x14CanoKey\x90", b"CanoKey"));
        assert!(!contains(b"\x00\x14YubiKey\x90", b"CanoKey"));
        assert!(!contains(b"Can", b"CanoKey"));
    }

    #[test]
    fn detection_is_case_insensitive() {
        // libccid renders the reader name "Canokeys Canokey [OpenPGP PIV
        // OATH] ..." — a case-sensitive "CanoKey" match misses it, which
        // failed the usbip CI smoke on every firmware.
        let atr = b"\x00\x14Canokey\x90".to_ascii_lowercase();
        assert!(contains(&atr, b"canokey"));
    }
}
