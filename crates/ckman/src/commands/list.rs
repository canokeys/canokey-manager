use super::{all_targets, CliResult};
use ckman_transport::pcsc::Pcsc;

pub fn run(serials_only: bool, reader: Option<&str>) -> CliResult<()> {
    let pcsc = Pcsc::establish()?;
    let mut targets = all_targets(&pcsc)?;
    if let Some(name) = reader {
        targets.retain(|target| target.connection.reader_name() == name);
    }
    for target in &targets {
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
