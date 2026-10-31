use super::{describe_drive_error, single_target, CliResult};
use canokey::{DeviceProfile, ErrorKind, Phase};
use ckman_core::{admin, DriveError, Exchange};
use ckman_transport::pcsc::Pcsc;
use std::io;

// Older vendor implementations may omit this optional command or P1.
// Only those explicit command-level rejections mean "unavailable".
fn read_chip_id(
    profile: &DeviceProfile,
    exchange: &mut Exchange<'_, io::Error>,
) -> CliResult<Option<Vec<u8>>> {
    match admin::chip_id(profile, exchange) {
        Ok(bytes) => Ok((!bytes.is_empty()).then_some(bytes)),
        Err(DriveError::Protocol(error))
            if error.phase == Phase::Command
                && (matches!(
                    error.kind,
                    ErrorKind::NotFound | ErrorKind::UnsupportedFeature
                ) || error
                    .status_word
                    .is_some_and(|status| status.raw() == 0x6a86)) =>
        {
            Ok(None)
        }
        Err(error) => Err(describe_drive_error(&error).into()),
    }
}

pub fn run(device: Option<u32>, reader: Option<&str>) -> CliResult<()> {
    let pcsc = Pcsc::establish()?;
    let mut target = single_target(&pcsc, device, reader)?;
    let info = target.profile.info();

    let model = info.model().unwrap_or("CanoKey");
    println!("Device type:        {model}");
    match target.serial() {
        Some(serial) => println!("Serial number:      {serial}"),
        None => println!("Serial number:      <unavailable>"),
    }
    match read_chip_id(&target.profile, &mut |command| {
        target.connection.exchange(command)
    })? {
        Some(bytes) => {
            use std::fmt::Write as _;
            let hex = bytes.iter().fold(String::new(), |mut out, byte| {
                let _ = write!(out, "{byte:02x}");
                out
            });
            println!("Chip ID:            {hex}");
        }
        None => println!("Chip ID:            <unavailable>"),
    }
    let firmware = String::from_utf8_lossy(info.firmware_text());
    println!("Firmware version:   {firmware}");
    if info.firmware().is_none() {
        println!("                    (unrecognized firmware; mutating operations are disabled)");
    }
    if let Some(piv) = info.piv_version() {
        println!("PIV version:        {}.{}.{}", piv.0[0], piv.0[1], piv.0[2]);
    }
    for warning in target.profile.warnings() {
        println!("Warning:            {warning:?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use canokey::compatibility::DeviceObservations;

    #[test]
    fn chip_id_3_1_0_preserves_failures_and_accepts_absence() {
        let profile =
            DeviceProfile::from_observations(DeviceObservations::new(b"3.1.0".to_vec())).unwrap();
        // SELECT and vendor Chip ID command from ckman-core's libcanokey
        // transcript fixture. Substitute failures only at the specified step.
        let select = [0, 0xa4, 4, 0, 5, 0xf0, 0, 0, 0, 0];
        let command = [0, 0x32, 1, 0, 0];
        for (response, expected) in [
            (Some(&[0xde, 0xad, 0x90, 0][..]), Ok(Some(vec![0xde, 0xad]))),
            (Some(&[0x90, 0][..]), Ok(None)),
            (Some(&[0x6a, 0x88][..]), Ok(None)),
            (Some(&[0x6a, 0x82][..]), Ok(None)),
            (Some(&[0x6a, 0x86][..]), Ok(None)),
            (Some(&[0x6d, 0][..]), Ok(None)),
            (Some(&[0x6e, 0][..]), Ok(None)),
            (Some(&[0x90][..]), Err("InvalidResponse")),
            (Some(&[0x69, 0x82][..]), Err("requires authentication")),
            (Some(&[0x69, 0x85][..]), Err("ConditionsNotSatisfied")),
            (Some(&[0x6f, 0][..]), Err("UnexpectedStatusWord")),
            (None, Err("transport")),
        ] {
            let mut calls = 0;
            let result = read_chip_id(&profile, &mut |actual| {
                calls += 1;
                if calls == 1 {
                    assert_eq!(actual, select);
                    return Ok(vec![0x90, 0]);
                }
                assert_eq!(calls, 2);
                assert_eq!(actual, command);
                response
                    .map(Vec::from)
                    .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))
            });
            assert_eq!(calls, 2);
            match expected {
                Ok(value) => assert_eq!(result.unwrap(), value),
                Err(message) => assert!(result.unwrap_err().to_string().contains(message)),
            }
        }
        // An unsupported SELECT is an applet failure, not an absent Chip ID.
        for response in [[0x6d, 0], [0x6a, 0x82], [0x6a, 0x86]] {
            let mut calls = 0;
            assert!(read_chip_id(&profile, &mut |actual| {
                calls += 1;
                assert_eq!(actual, select);
                Ok(response.to_vec())
            })
            .is_err());
            assert_eq!(calls, 1);
        }
    }
}
