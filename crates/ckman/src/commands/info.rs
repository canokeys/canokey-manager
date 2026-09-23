use super::{describe_drive_error, single_target, CliResult};
use ckman_core::{admin, DriveError};
use ckman_transport::pcsc::Pcsc;

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
    // The vendor chip-ID command is not capability-gated; firmware that lacks
    // it answers with a protocol error, which is reported as "unavailable"
    // rather than failing the read-only info output.
    match admin::chip_id(&target.profile, &mut |command| {
        target.connection.exchange(command)
    }) {
        Ok(bytes) if !bytes.is_empty() => {
            use std::fmt::Write as _;
            let hex = bytes.iter().fold(String::new(), |mut out, byte| {
                let _ = write!(out, "{byte:02x}");
                out
            });
            println!("Chip ID:            {hex}");
        }
        Ok(_) => println!("Chip ID:            <unavailable>"),
        Err(error @ DriveError::Transport(_)) => return Err(describe_drive_error(&error).into()),
        Err(DriveError::Protocol(_)) => println!("Chip ID:            <unavailable>"),
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
