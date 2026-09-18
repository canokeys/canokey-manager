use super::{describe_drive_error, single_target, with_admin_pin_retry, CliResult};
use ckman_core::admin::{self, AdminConfiguration};
use ckman_transport::pcsc::Pcsc;

use clap::{Subcommand, ValueEnum};
use std::io;
use std::io::Write as _;

#[derive(Subcommand)]
pub enum ConfigCommand {
    /// Turn NFC on or off.
    Nfc {
        /// Desired NFC state.
        state: NfcState,
    },
    /// Reset the device to factory defaults, erasing all applets and PINs.
    Reset {
        /// Do not ask for confirmation.
        #[arg(long)]
        force: bool,
    },
    /// Show the current device configuration.
    Info,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum NfcState {
    On,
    Off,
}

pub fn run(device: Option<u32>, reader: Option<&str>, command: &ConfigCommand) -> CliResult<()> {
    match command {
        ConfigCommand::Nfc { state } => nfc(device, reader, matches!(state, NfcState::On)),
        ConfigCommand::Reset { force } => reset(device, reader, *force),
        ConfigCommand::Info => info(device, reader),
    }
}

fn nfc(device: Option<u32>, reader: Option<&str>, on: bool) -> CliResult<()> {
    let pcsc = Pcsc::establish()?;
    let mut target = single_target(&pcsc, device, reader)?;
    let new_state = with_admin_pin_retry(None, |pin| {
        admin::set_nfc(&target.profile, on, pin, &mut |command| {
            target.connection.exchange(command)
        })
    })?;
    println!("NFC is now {}.", if new_state { "on" } else { "off" });
    Ok(())
}

fn reset(device: Option<u32>, reader: Option<&str>, force: bool) -> CliResult<()> {
    let pcsc = Pcsc::establish()?;
    let mut target = single_target(&pcsc, device, reader)?;
    if !force {
        eprintln!("This erases ALL data and credentials on the device and cannot be undone.");
        eprintln!("Factory reset only succeeds while the Admin PIN is blocked.");
        print!("Type 'yes' to confirm: ");
        io::stdout().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        if answer.trim() != "yes" {
            return Err("factory reset aborted".into());
        }
    }
    admin::factory_reset(&target.profile, &mut |command| {
        target.connection.exchange(command)
    })
    .map_err(|error| describe_drive_error(&error))?;
    println!("Factory reset complete.");
    Ok(())
}

fn info(device: Option<u32>, reader: Option<&str>) -> CliResult<()> {
    let pcsc = Pcsc::establish()?;
    let mut target = single_target(&pcsc, device, reader)?;
    let configuration = with_admin_pin_retry(None, |pin| {
        admin::read_configuration(&target.profile, pin, &mut |command| {
            target.connection.exchange(command)
        })
    })?;
    match &configuration {
        AdminConfiguration::Modern(config) => {
            println!("LED:                  {}", on_off(config.led_on()));
            println!("NDEF:                 {}", enabled(config.ndef_enabled()));
            println!("NDEF read-only:       {}", yes_no(config.ndef_read_only()));
            println!("WebUSB landing page:  {}", on_off(config.webusb_landing()));
            let features = config.features();
            println!("Applet features (raw 0x{features:02x}):");
            for (bit, name) in [
                (0, "PASS"),
                (1, "OpenPGP over CCID"),
                (2, "OpenPGP over NFC"),
                (3, "PIV over CCID"),
                (4, "PIV over NFC"),
                (5, "WebAuthn"),
            ] {
                println!("  {name:<18}{}", on_off(features & (1 << bit) != 0));
            }
            if features & !0x3f != 0 {
                println!("  (unknown feature bits set: 0x{:02x})", features & !0x3f);
            }
        }
        AdminConfiguration::Legacy(config) => {
            println!("LED:                  {}", on_off(config.led_on()));
            println!("NDEF read-only:       {}", yes_no(config.ndef_read_only()));
            if let Some(value) = config.ndef_enabled() {
                println!("NDEF:                 {}", enabled(value));
            }
            if let Some(value) = config.webusb_landing() {
                println!("WebUSB landing page:  {}", on_off(value));
            }
            if let Some(value) = config.keyboard_interface() {
                println!("Keyboard interface:   {}", on_off(value));
            }
            if let Some(value) = config.keyboard_return() {
                println!("Keyboard return:      {}", on_off(value));
            }
            if let Some(touch) = config.openpgp_touch() {
                println!(
                    "OpenPGP touch:        sig={} dec={} aut={} cache={}s",
                    on_off(touch[0] != 0),
                    on_off(touch[1] != 0),
                    on_off(touch[2] != 0),
                    touch[3]
                );
            }
        }
    }
    Ok(())
}

fn on_off(value: bool) -> &'static str {
    if value {
        "on"
    } else {
        "off"
    }
}

fn enabled(value: bool) -> &'static str {
    if value {
        "enabled"
    } else {
        "disabled"
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}
