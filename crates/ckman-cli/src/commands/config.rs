use super::{describe_drive_error, single_target, with_admin_pin_retry, CliResult};
use canokey::compatibility::{Capability, Support};
use ckman_core::admin::{self, AdminConfiguration, PassSlotState, Sm2Readout};
use ckman_transport::pcsc::Pcsc;

use canokey::SecretBytes;
use clap::{Subcommand, ValueEnum};
use std::io;
use std::io::{Read as _, Write as _};

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
    /// Turn the LED on or off (device configuration patch).
    Led {
        /// Desired LED state.
        state: NfcState,
    },
    /// Allow or forbid NDEF writes (device configuration patch).
    NdefReadOnly {
        /// Desired read-only state.
        state: NfcState,
    },
    /// Enable or disable the WebUSB landing page (device configuration patch).
    WebusbLanding {
        /// Desired landing-page state.
        state: NfcState,
    },
    /// Manage the PASS touch-to-type slots.
    Pass {
        #[command(subcommand)]
        command: PassCommand,
    },
    /// Read or replace the NDEF message.
    ///
    /// Writes are crash-consistent: a crash or unplug mid-write leaves an
    /// empty message instead of a partially written one.
    Ndef {
        #[command(subcommand)]
        command: NdefCommand,
    },
    /// Manage the keyboard (HID) emulation layout.
    Keyboard {
        #[command(subcommand)]
        command: KeyboardCommand,
    },
    /// Show the CTAP SM2 configuration (3.0+; read-only).
    Sm2,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum NfcState {
    On,
    Off,
}

#[derive(Subcommand)]
pub enum PassCommand {
    /// Show both PASS slot configurations.
    Info,
    /// Configure a PASS slot.
    Set {
        /// Slot: short-touch or long-touch.
        #[arg(value_enum)]
        slot: PassSlotArg,
        /// Slot type to set.
        #[arg(value_enum)]
        kind: PassKindArg,
        /// HMAC-SHA1 key as 40 hex characters (prompted when omitted).
        #[arg(long)]
        key: Option<String>,
        /// Append Return after typing (static passwords only).
        #[arg(long)]
        enter: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum PassSlotArg {
    Short,
    Long,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum PassKindArg {
    Off,
    Static,
    Hmac,
}

#[derive(Subcommand)]
pub enum NdefCommand {
    /// Read the stored NDEF message.
    Read,
    /// Replace the NDEF message with the file contents ('-' for stdin).
    ///
    /// The write is crash-consistent: a crash or unplug mid-write leaves an
    /// empty message rather than a partially written one.
    Write {
        /// File containing the NDEF message ('-' for stdin, empty to clear).
        file: String,
    },
}

#[derive(Subcommand)]
pub enum KeyboardCommand {
    /// Show the configured keyboard layout identifier.
    Layout,
    /// Read the 256-byte keyboard HID map into a file ('-' for stdout).
    ReadKeymap {
        /// File to write the keymap to ('-' for stdout).
        output: String,
    },
    /// Replace the keyboard HID map from a 256-byte file ('-' for stdin).
    WriteKeymap {
        /// Layout identifier this map belongs to.
        #[arg(long)]
        layout: u8,
        /// File containing exactly 256 keymap bytes ('-' for stdin).
        file: String,
    },
    /// Clear the stored keyboard HID map.
    ClearKeymap,
    /// Set the append-return flag (firmware 1.6.2 through 2.x only).
    Return {
        /// Desired append-return state.
        state: NfcState,
    },
}

pub fn run(device: Option<u32>, reader: Option<&str>, command: &ConfigCommand) -> CliResult<()> {
    match command {
        ConfigCommand::Nfc { state } => nfc(device, reader, matches!(state, NfcState::On)),
        ConfigCommand::Reset { force } => reset(device, reader, *force),
        ConfigCommand::Info => info(device, reader),
        ConfigCommand::Led { state } => patch(device, reader, "LED", |p| {
            p.led_on = Some(matches!(state, NfcState::On));
        }),
        ConfigCommand::NdefReadOnly { state } => patch(device, reader, "NDEF read-only", |p| {
            p.ndef_read_only = Some(matches!(state, NfcState::On));
        }),
        ConfigCommand::WebusbLanding { state } => {
            patch(device, reader, "WebUSB landing page", |p| {
                p.webusb_landing = Some(matches!(state, NfcState::On));
            })
        }
        ConfigCommand::Pass { command } => pass(device, reader, command),
        ConfigCommand::Ndef { command } => ndef(device, reader, command),
        ConfigCommand::Keyboard { command } => keyboard(device, reader, command),
        ConfigCommand::Sm2 => sm2(device, reader),
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
    // READ CONFIG sits behind the firmware's Admin-PIN gate on every layout
    // before 3.1. Do not prompt for the Admin PIN from a read-only status
    // command: the old CLI refused to configure legacy CanoKey firmware at
    // all, and prompting from a non-interactive runner fails on /dev/tty
    // (ENXIO), which looks like a dropped card.
    match admin::public_configuration_supported(&target.profile).support {
        Support::Unsupported => {
            println!(
                "Configuration read is not supported by this firmware (requires 3.1 or newer)."
            );
            return Ok(());
        }
        Support::Unknown => {
            println!("Unrecognized firmware; configuration not read.");
            return Ok(());
        }
        Support::Supported => {}
    }
    let configuration = admin::read_configuration(&target.profile, None, &mut |command| {
        target.connection.exchange(command)
    })
    .map_err(|error| describe_drive_error(&error))?;
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
            // (only reachable if the public-read gate semantics loosen)
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

    // Extended reads (3.1 evidence). Flash usage is public together with the
    // configuration read; core commit and applet usage are gated on the
    // extended-configuration capability.
    let usage = admin::flash_usage(&target.profile, None, &mut |command| {
        target.connection.exchange(command)
    })
    .map_err(|error| describe_drive_error(&error))?;
    println!(
        "Flash usage:          {} / {} KiB",
        usage.used_kib, usage.total_kib
    );
    if target
        .profile
        .capability(Capability::AdminExtendedConfiguration)
        .support
        == Support::Supported
    {
        let commit = admin::core_commit(&target.profile, &mut |command| {
            target.connection.exchange(command)
        })
        .map_err(|error| describe_drive_error(&error))?;
        println!("Core commit:          {}", String::from_utf8_lossy(&commit));
        let usage = admin::applet_usage(&target.profile, &mut |command| {
            target.connection.exchange(command)
        })
        .map_err(|error| describe_drive_error(&error))?;
        const APPLETS: [&str; 8] = [
            "system", "Admin", "OpenPGP", "PIV", "OATH", "CTAP", "NDEF", "PASS",
        ];
        println!("Applet storage:");
        for record in &usage {
            let name = APPLETS
                .get(record.applet_id as usize)
                .copied()
                .unwrap_or("unknown");
            let flagged = if record.flags & 1 != 0 {
                " (missing paths/attributes)"
            } else {
                ""
            };
            println!("  {name:<10}{} byte(s){flagged}", record.logical_bytes);
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

/// A device configuration patch with the shared Admin-PIN retry: libcanokey
/// reads the current state, writes only fields that differ, and refuses
/// unsafe overwrites when unknown feature bits are present.
fn patch(
    device: Option<u32>,
    reader: Option<&str>,
    name: &str,
    edit: impl FnOnce(&mut admin::ConfigurationPatch),
) -> CliResult<()> {
    let pcsc = Pcsc::establish()?;
    let mut target = single_target(&pcsc, device, reader)?;
    let mut patch = admin::ConfigurationPatch::default();
    edit(&mut patch);
    with_admin_pin_retry(None, |pin| {
        admin::configure(&target.profile, patch, pin, &mut |command| {
            target.connection.exchange(command)
        })
    })?;
    println!("{name} updated.");
    Ok(())
}

fn pass_slot_state(state: &PassSlotState) -> String {
    match state {
        PassSlotState::Off => "off".to_string(),
        PassSlotState::Static { append_enter } => {
            format!("static password (append Return: {})", yes_no(*append_enter))
        }
        PassSlotState::HmacSha1 => "HMAC-SHA1 challenge-response".to_string(),
        PassSlotState::Oath { name, append_enter } => {
            format!(
                "OATH credential '{}' (append Return: {})",
                String::from_utf8_lossy(name),
                yes_no(*append_enter)
            )
        }
        // Unknown slot types stay faithfully observable, never collapsed.
        PassSlotState::Unknown(kind) => format!("unknown slot type 0x{kind:02x}"),
    }
}

fn pass(device: Option<u32>, reader: Option<&str>, command: &PassCommand) -> CliResult<()> {
    let pcsc = Pcsc::establish()?;
    let mut target = single_target(&pcsc, device, reader)?;
    match command {
        PassCommand::Info => {
            let slots = with_admin_pin_retry(None, |pin| {
                admin::pass_slots(&target.profile, pin, &mut |command| {
                    target.connection.exchange(command)
                })
            })?;
            println!("Short touch: {}", pass_slot_state(&slots.short));
            println!("Long touch:  {}", pass_slot_state(&slots.long));
            Ok(())
        }
        PassCommand::Set {
            slot,
            kind,
            key,
            enter,
        } => {
            // Prompt for secrets once; the config is rebuilt per attempt
            // because the operation consumes it (it is not Clone).
            let secret = match kind {
                PassKindArg::Off => None,
                PassKindArg::Static => Some(zeroize::Zeroizing::new(
                    super::prompt_password("Enter the static password: ")?
                        .as_bytes()
                        .to_vec(),
                )),
                PassKindArg::Hmac => {
                    let hex = match key {
                        Some(key) => key.clone(),
                        None => {
                            super::prompt_password("Enter the HMAC-SHA1 key (hex): ")?.to_string()
                        }
                    };
                    let bytes = (0..hex.len())
                        .step_by(2)
                        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
                        .collect::<Result<Vec<u8>, _>>()
                        .map_err(|_| "the HMAC-SHA1 key must be hex-encoded")?;
                    if bytes.len() != 20 {
                        return Err("the HMAC-SHA1 key must be 20 bytes (40 hex characters)".into());
                    }
                    Some(zeroize::Zeroizing::new(bytes))
                }
            };
            let build = |secret: &Option<zeroize::Zeroizing<Vec<u8>>>| match kind {
                PassKindArg::Off => admin::PassSlotConfig::Off,
                PassKindArg::Static => admin::PassSlotConfig::Static {
                    password: SecretBytes::new(
                        secret.as_ref().expect("static has a password").to_vec(),
                    ),
                    append_enter: *enter,
                },
                PassKindArg::Hmac => admin::PassSlotConfig::HmacSha1 {
                    key: SecretBytes::new(secret.as_ref().expect("hmac has a key").to_vec()),
                },
            };
            let slot = match slot {
                PassSlotArg::Short => admin::PassSlotId::Short,
                PassSlotArg::Long => admin::PassSlotId::Long,
            };
            with_admin_pin_retry(None, |pin| {
                admin::set_pass_slot(&target.profile, slot, build(&secret), pin, &mut |command| {
                    target.connection.exchange(command)
                })
            })?;
            println!("PASS slot updated.");
            Ok(())
        }
    }
}

fn ndef(device: Option<u32>, reader: Option<&str>, command: &NdefCommand) -> CliResult<()> {
    use ckman_core::ndef;
    let pcsc = Pcsc::establish()?;
    let mut target = single_target(&pcsc, device, reader)?;
    match command {
        NdefCommand::Read => {
            let capability =
                ndef::read_capability(&mut |command| target.connection.exchange(command))
                    .map_err(|error| describe_drive_error(&error))?;
            let message = ndef::read_message(&mut |command| target.connection.exchange(command))
                .map_err(|error| describe_drive_error(&error))?;
            println!("NDEF message: {} byte(s)", message.len());
            println!("  max message length: {}", capability.max_message_length);
            println!("  read-only:          {}", yes_no(capability.read_only));
            if !message.is_empty() {
                match std::str::from_utf8(&message) {
                    Ok(text) => println!("  content (text):     {text}"),
                    Err(_) => {
                        use std::fmt::Write as _;
                        let hex = message.iter().fold(String::new(), |mut out, byte| {
                            let _ = write!(out, "{byte:02x}");
                            out
                        });
                        println!("  content (hex):      {hex}");
                    }
                }
            }
            Ok(())
        }
        NdefCommand::Write { file } => {
            let message = if file == "-" {
                let mut data = Vec::new();
                io::stdin().read_to_end(&mut data)?;
                data
            } else {
                std::fs::read(file)?
            };
            ndef::write_message(&message, &mut |command| target.connection.exchange(command))
                .map_err(|error| describe_drive_error(&error))?;
            println!("NDEF message written ({} byte(s)).", message.len());
            Ok(())
        }
    }
}

fn keyboard(device: Option<u32>, reader: Option<&str>, command: &KeyboardCommand) -> CliResult<()> {
    let pcsc = Pcsc::establish()?;
    let mut target = single_target(&pcsc, device, reader)?;
    match command {
        KeyboardCommand::Layout => {
            let layout = with_admin_pin_retry(None, |pin| {
                admin::keyboard_layout(&target.profile, pin, &mut |command| {
                    target.connection.exchange(command)
                })
            })?;
            println!("Keyboard layout: {layout}");
            Ok(())
        }
        KeyboardCommand::ReadKeymap { output } => {
            let keymap = with_admin_pin_retry(None, |pin| {
                admin::read_keymap(&target.profile, pin, &mut |command| {
                    target.connection.exchange(command)
                })
            })?;
            if output == "-" {
                io::stdout().write_all(keymap.as_bytes())?;
            } else {
                std::fs::write(output, keymap.as_bytes())?;
            }
            println!("Keymap written to {output}.");
            Ok(())
        }
        KeyboardCommand::WriteKeymap { layout, file } => {
            let bytes = if file == "-" {
                let mut data = Vec::new();
                io::stdin().read_to_end(&mut data)?;
                data
            } else {
                std::fs::read(file)?
            };
            let keymap = admin::KeyboardKeymap::from_bytes(&bytes)
                .map_err(|_| "the keymap file must contain exactly 256 bytes")?;
            with_admin_pin_retry(None, |pin| {
                admin::set_keymap(
                    &target.profile,
                    *layout,
                    keymap.clone(),
                    pin,
                    &mut |command| target.connection.exchange(command),
                )
            })?;
            println!("Keymap written for layout {layout}.");
            Ok(())
        }
        KeyboardCommand::ClearKeymap => {
            with_admin_pin_retry(None, |pin| {
                admin::clear_keymap(&target.profile, pin, &mut |command| {
                    target.connection.exchange(command)
                })
            })?;
            println!("Keymap cleared.");
            Ok(())
        }
        KeyboardCommand::Return { state } => {
            let on = matches!(state, NfcState::On);
            with_admin_pin_retry(None, |pin| {
                admin::set_keyboard_return(&target.profile, on, pin, &mut |command| {
                    target.connection.exchange(command)
                })
            })?;
            println!(
                "Keyboard append-return is now {}.",
                if on { "on" } else { "off" }
            );
            Ok(())
        }
    }
}

fn sm2(device: Option<u32>, reader: Option<&str>) -> CliResult<()> {
    let pcsc = Pcsc::establish()?;
    let mut target = single_target(&pcsc, device, reader)?;
    let readout = with_admin_pin_retry(None, |pin| {
        admin::sm2_configuration(&target.profile, pin, &mut |command| {
            target.connection.exchange(command)
        })
    })?;
    match readout {
        Sm2Readout::Typed(config) => {
            println!("SM2 curve:      {}", config.curve_id);
            println!("SM2 algorithm:  {}", config.algorithm_id);
        }
        Sm2Readout::Legacy(config) => {
            println!("SM2 enabled:    {}", yes_no(config.enabled()));
            use std::fmt::Write as _;
            let raw = config.raw()[1..]
                .iter()
                .fold(String::new(), |mut out, byte| {
                    let _ = write!(out, "{byte:02x}");
                    out
                });
            println!("SM2 identifiers (legacy layout, raw): {raw}");
        }
    }
    Ok(())
}
