use super::{single_target, CliResult};
use ckman_core::admin::{self, AdminConfiguration, Pin};
use ckman_core::DriveError;
use ckman_transport::pcsc::Pcsc;

use canokey::{ErrorKind, SecretReference};
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

fn prompt_admin_pin() -> CliResult<Pin> {
    let entered = rpassword::prompt_password("Admin PIN: ")?;
    Pin::from_bytes(entered.as_bytes()).map_err(|error| format!("{error}").into())
}

/// True when libcanokey reports that the request needs Admin PIN verification
/// (a protected request built without a PIN, or a card-side 6982), so the CLI
/// should prompt and retry once. libcanokey never tries default credentials.
fn needs_pin<E>(error: &DriveError<E>) -> bool {
    matches!(
        error,
        DriveError::Protocol(error)
            if error.kind == ErrorKind::SecurityStatusNotSatisfied
                || (error.kind == ErrorKind::AuthenticationFailed
                    && error.reference == Some(SecretReference::AdminPin))
    )
}

/// Human-facing message for a protocol failure, decoding the firmware
/// capability gates that libcanokey surfaces as typed errors.
fn describe(error: &DriveError<io::Error>) -> String {
    match error {
        DriveError::Transport(error) => format!("transport exchange failed: {error}"),
        DriveError::Protocol(error) => match error.kind {
            ErrorKind::CapabilityUnknown => {
                "unrecognized firmware; refusing to attempt the operation".to_string()
            }
            ErrorKind::UnsupportedFeature => {
                "this firmware does not support the operation".to_string()
            }
            ErrorKind::AuthenticationFailed => match error.retries_remaining {
                Some(retries) => {
                    format!("incorrect Admin PIN ({retries} attempts remaining)")
                }
                None => "incorrect Admin PIN".to_string(),
            },
            ErrorKind::PinBlocked => "the Admin PIN is blocked".to_string(),
            _ => format!("protocol error: {error}"),
        },
    }
}

/// Run an Admin operation that may be PIN-protected: try without a PIN first,
/// and when the card or the library demands verification, prompt once and
/// retry with the entered PIN.
fn with_pin_retry<T>(
    mut operation: impl FnMut(Option<Pin>) -> Result<T, DriveError<io::Error>>,
) -> CliResult<T> {
    match operation(None) {
        Ok(result) => Ok(result),
        Err(error) if needs_pin(&error) => {
            let pin = prompt_admin_pin()?;
            operation(Some(pin)).map_err(|error| describe(&error).into())
        }
        Err(error) => Err(describe(&error).into()),
    }
}

fn nfc(device: Option<u32>, reader: Option<&str>, on: bool) -> CliResult<()> {
    let pcsc = Pcsc::establish()?;
    let mut target = single_target(&pcsc, device, reader)?;
    let new_state = with_pin_retry(|pin| {
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
    .map_err(|error| describe(&error))?;
    println!("Factory reset complete.");
    Ok(())
}

fn info(device: Option<u32>, reader: Option<&str>) -> CliResult<()> {
    let pcsc = Pcsc::establish()?;
    let mut target = single_target(&pcsc, device, reader)?;
    let configuration = with_pin_retry(|pin| {
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
