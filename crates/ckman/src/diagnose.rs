//! `--diagnose`: a bug-report-friendly, read-only environment report.
//! Prints device serials (public identifiers) but never secrets; trace
//! traffic redaction rules apply (`CKMAN_LOG_TRAFFIC` is not consulted here).

use crate::commands::{all_targets, CliResult};
use ckman_transport::hid;
use ckman_transport::pcsc::Pcsc;

pub fn run() -> CliResult<()> {
    println!("ckman {}", env!("CARGO_PKG_VERSION"));
    println!(
        "Platform: {} {} ({})",
        std::env::consts::OS,
        std::env::consts::ARCH,
        std::env::consts::FAMILY
    );

    println!("\nPC/SC:");
    match Pcsc::establish() {
        Ok(pcsc) => match pcsc.readers() {
            Ok(readers) => {
                if readers.is_empty() {
                    println!("  (no readers)");
                }
                for reader in &readers {
                    println!("  reader: {}", reader.name());
                }
                let targets = all_targets(&pcsc)?;
                if targets.is_empty() {
                    println!("  (no CanoKey found)");
                }
                for target in &targets {
                    let info = target.profile.info();
                    let model = info.model().unwrap_or("CanoKey");
                    let firmware = String::from_utf8_lossy(info.firmware_text());
                    match target.serial() {
                        Some(serial) => {
                            println!("  {model} (firmware {firmware}) Serial: {serial}")
                        }
                        None => println!("  {model} (firmware {firmware})"),
                    }
                }
            }
            Err(error) => println!("  cannot list readers: {error}"),
        },
        Err(error) => println!("  PC/SC unavailable: {error}"),
    }

    println!("\nUSB HID (FIDO):");
    match hidapi::HidApi::new() {
        Ok(api) => {
            let interfaces = hid::list_fido_interfaces(&api);
            if interfaces.is_empty() {
                println!("  (no CanoKey FIDO interface found)");
            }
            for interface in interfaces {
                println!(
                    "  {} (serial {}, path {:?})",
                    interface.product.as_deref().unwrap_or("CanoKey"),
                    interface.serial.as_deref().unwrap_or("unknown"),
                    interface.path
                );
            }
        }
        Err(error) => println!("  HID unavailable: {error}"),
    }
    Ok(())
}
