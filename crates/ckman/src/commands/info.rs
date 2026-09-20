use super::{single_target, CliResult};
use ckman_transport::pcsc::Pcsc;

pub fn run(device: Option<u32>, reader: Option<&str>) -> CliResult<()> {
    let pcsc = Pcsc::establish()?;
    let target = single_target(&pcsc, device, reader)?;
    let info = target.profile.info();

    let model = info.model().unwrap_or("CanoKey");
    println!("Device type:        {model}");
    match target.serial() {
        Some(serial) => println!("Serial number:      {serial}"),
        None => println!("Serial number:      <unavailable>"),
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
