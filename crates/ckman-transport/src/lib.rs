//! Transports for talking to a CanoKey, honoring the libcanokey
//! connection-lease contract: one operation holds exclusive access to its
//! connection, frames are exchanged verbatim, and the transport never
//! retries, continues, or reorders on its own.

pub mod ctaphid;
pub mod hid;
pub mod pcsc;
