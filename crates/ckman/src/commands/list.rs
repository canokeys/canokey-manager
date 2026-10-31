use super::{targets_matching_reader, CliResult};
use ckman_transport::pcsc::Pcsc;

pub fn run(serials_only: bool, device: Option<u32>, reader: Option<&str>) -> CliResult<()> {
    let pcsc = Pcsc::establish()?;
    let targets = targets_matching_reader(&pcsc, reader)?;
    for target in &targets {
        if device.is_some_and(|serial| target.serial() != Some(serial)) {
            continue;
        }
        let info = target.profile.info();
        let serial = target.serial();
        if serials_only {
            if let Some(serial) = serial {
                println!("{serial}");
            }
            continue;
        }
        let model = info.model().unwrap_or("CanoKey");
        let firmware = String::from_utf8_lossy(info.firmware_text());
        match serial {
            Some(serial) => println!("{model} (firmware {firmware}) Serial: {serial}"),
            None => println!("{model} (firmware {firmware})"),
        }
    }
    Ok(())
}
