//! USB HID enumeration and I/O for CTAPHID, over the `hidapi` crate.
//!
//! This module is only device plumbing: protocol framing lives in
//! [`crate::ctaphid`]. Enumeration matches the FIDO usage page and the
//! CanoKey USB identity (VID 0x20A0, PID 0x42D4 for the FIDO+CCID composite,
//! or a "CanoKey" product string for firmware variants).

use crate::ctaphid::{Capabilities, CtapHidChannel, CtapHidError, ReportIo, REPORT_LEN};
use hidapi::{DeviceInfo, HidApi, HidDevice};
use std::ffi::CString;
use std::io;
use std::time::Duration;

fn hid_err(error: hidapi::HidError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error.to_string())
}

/// CanoKey USB vendor ID.
pub const CANOKEY_VID: u16 = 0x20a0;
/// CanoKey FIDO+CCID composite USB product ID.
pub const CANOKEY_FIDO_CCID_PID: u16 = 0x42d4;
/// USB HID usage page for FIDO (CTAPHID) interfaces.
pub const FIDO_USAGE_PAGE: u16 = 0xf1d0;
/// USB HID usage for a FIDO interface.
pub const FIDO_USAGE: u16 = 1;

/// One enumerated CanoKey FIDO interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FidoInterface {
    /// Platform device path for `hidapi` open.
    pub path: CString,
    /// USB product string, when reported.
    pub product: Option<String>,
    /// USB serial string, when reported.
    pub serial: Option<String>,
}

/// Pure matching predicate, split out for testability.
fn matches(vid: u16, pid: u16, usage_page: u16, usage: u16, product: Option<&str>) -> bool {
    if usage_page != FIDO_USAGE_PAGE || usage != FIDO_USAGE {
        return false;
    }
    (vid == CANOKEY_VID && pid == CANOKEY_FIDO_CCID_PID)
        || product.is_some_and(|p| p.contains("CanoKey"))
}

fn interface_of(info: &DeviceInfo) -> Option<FidoInterface> {
    matches(
        info.vendor_id(),
        info.product_id(),
        info.usage_page(),
        info.usage(),
        info.product_string(),
    )
    .then(|| FidoInterface {
        path: info.path().to_owned(),
        product: info.product_string().map(str::to_string),
        serial: info.serial_number().map(str::to_string),
    })
}

/// Enumerate CanoKey FIDO interfaces.
pub fn list_fido_interfaces(api: &HidApi) -> Vec<FidoInterface> {
    api.device_list().filter_map(interface_of).collect()
}

/// [`ReportIo`] over one open HID device.
pub struct HidReportIo {
    device: HidDevice,
}

impl ReportIo for HidReportIo {
    fn write_report(&mut self, report: &[u8; REPORT_LEN]) -> io::Result<()> {
        // hidapi wants the report ID prefix; CTAPHID uses report ID 0.
        let mut framed = [0u8; REPORT_LEN + 1];
        framed[1..].copy_from_slice(report);
        let written = self.device.write(&framed).map_err(hid_err)?;
        if written != framed.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short HID report write",
            ));
        }
        Ok(())
    }

    fn read_report(&mut self, timeout: Duration) -> io::Result<Option<[u8; REPORT_LEN]>> {
        let mut buf = [0u8; REPORT_LEN];
        let millis = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        match self
            .device
            .read_timeout(&mut buf, millis)
            .map_err(hid_err)?
        {
            0 => Ok(None),
            _ => Ok(Some(buf)),
        }
    }
}

/// Open one enumerated interface and allocate a CTAPHID channel on it.
pub fn connect(
    api: &HidApi,
    interface: &FidoInterface,
    nonce: [u8; 8],
    timeout: Duration,
) -> Result<(CtapHidChannel<HidReportIo>, Capabilities), CtapHidError> {
    let device = api.open_path(&interface.path).map_err(hid_err)?;
    CtapHidChannel::allocate(HidReportIo { device }, nonce, timeout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_requires_fido_usage_and_canokey_identity() {
        assert!(matches(0x20a0, 0x42d4, 0xf1d0, 1, None));
        assert!(matches(0x1234, 0x5678, 0xf1d0, 1, Some("CanoKey Pigeon")));
        // FIDO usage on an unrelated device is not claimed.
        assert!(!matches(0x1050, 0x0407, 0xf1d0, 1, Some("OtherKey")));
        // CanoKey VID/PID without the FIDO usage page is the CCID interface.
        assert!(!matches(0x20a0, 0x42d4, 0x0001, 1, None));
        assert!(!matches(0x20a0, 0x42d4, 0xf1d0, 2, None));
        // A conflicting product string does not override a VID/PID match.
        assert!(matches(0x20a0, 0x42d4, 0xf1d0, 1, Some("Other")));
    }
}
