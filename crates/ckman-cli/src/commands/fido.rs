use super::{confirm, single_target, CliResult};
use ckman_core::fido::{self, FidoError};
use ckman_core::{DriveError, Exchange};
use ckman_transport::ctaphid::Keepalive;
use ckman_transport::hid::{self, HidReportIo};
use ckman_transport::pcsc::Pcsc;

use canokey::ctap::pin::Permissions;
use canokey::ctap::{PinUvAuthProtocol, PublicKeyCredentialDescriptor};
use canokey::ErrorKind;
use clap::Subcommand;
use std::io;
use std::time::Duration;

#[derive(Subcommand)]
pub enum FidoCommand {
    /// Display general status of the FIDO application.
    Info,
    /// Reset the FIDO application, deleting all credentials and the PIN.
    ///
    /// The reset must be triggered immediately after the CanoKey is
    /// (re-)inserted, and requires a touch to confirm.
    Reset {
        /// Do not ask for confirmation; assume a freshly inserted key.
        #[arg(long)]
        force: bool,
    },
    /// Manage the FIDO2 PIN.
    Access {
        #[command(subcommand)]
        command: AccessCommand,
    },
    /// Manage persistent FIDO authenticator configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Manage discoverable (resident) credentials.
    Credentials {
        #[command(subcommand)]
        command: CredentialsCommand,
    },
}

#[derive(Subcommand)]
pub enum AccessCommand {
    /// Set the FIDO2 PIN (when none is set).
    SetPin {
        /// New PIN (prompted when omitted).
        #[arg(short = 'n', long, value_parser = crate::commands::secret_arg)]
        new_pin: Option<crate::commands::SecretString>,
    },
    /// Change the FIDO2 PIN.
    ChangePin {
        /// Current PIN (prompted when omitted).
        #[arg(short = 'P', long, value_parser = crate::commands::secret_arg)]
        pin: Option<crate::commands::SecretString>,
        /// New PIN (prompted when omitted).
        #[arg(short = 'n', long, value_parser = crate::commands::secret_arg)]
        new_pin: Option<crate::commands::SecretString>,
    },
    /// Set the minimum PIN length (persistent authenticator configuration).
    SetMinLength {
        /// Minimum PIN length (4-63).
        #[arg(value_parser = clap::value_parser!(u8).range(4..=63))]
        length: u8,
        /// Restrict the policy to these relying parties.
        #[arg(short = 'R', long = "rp-id")]
        rp_ids: Vec<String>,
        /// Force the user to change the PIN on next use.
        #[arg(short, long)]
        force_change: bool,
        /// Current PIN (prompted when omitted).
        #[arg(short = 'P', long, value_parser = crate::commands::secret_arg)]
        pin: Option<crate::commands::SecretString>,
    },
    /// Force the user to change the PIN on next use.
    ForceChange {
        /// Current PIN (prompted when omitted).
        #[arg(short = 'P', long, value_parser = crate::commands::secret_arg)]
        pin: Option<crate::commands::SecretString>,
    },
    /// Verify the FIDO2 PIN against the CanoKey (resets the retry counter).
    VerifyPin {
        /// Current PIN (prompted when omitted).
        #[arg(short = 'P', long, value_parser = crate::commands::secret_arg)]
        pin: Option<crate::commands::SecretString>,
    },
}

#[derive(Subcommand)]
pub enum ConfigCommand {
    /// Toggle the "always require user verification" setting.
    ToggleAlwaysUv {
        /// Current PIN (prompted when omitted).
        #[arg(short = 'P', long, value_parser = crate::commands::secret_arg)]
        pin: Option<crate::commands::SecretString>,
    },
}

#[derive(Subcommand)]
pub enum CredentialsCommand {
    /// List resident credentials.
    List {
        /// FIDO2 PIN (prompted when omitted).
        #[arg(short = 'P', long, value_parser = crate::commands::secret_arg)]
        pin: Option<crate::commands::SecretString>,
        /// Output full credential information as CSV.
        #[arg(short, long)]
        csv: bool,
    },
    /// Delete a resident credential.
    Delete {
        /// A unique substring of the credential ID (as shown by "list").
        credential_id: String,
        /// FIDO2 PIN (prompted when omitted).
        #[arg(short = 'P', long, value_parser = crate::commands::secret_arg)]
        pin: Option<crate::commands::SecretString>,
        /// Confirm deletion without prompting.
        #[arg(short, long)]
        force: bool,
    },
}

pub fn run(device: Option<u32>, reader: Option<&str>, command: &FidoCommand) -> CliResult<()> {
    match command {
        FidoCommand::Info => info(device, reader),
        FidoCommand::Reset { force } => reset(device, reader, *force),
        FidoCommand::Access { command } => access(device, reader, command),
        FidoCommand::Config { command } => config(device, reader, command),
        FidoCommand::Credentials { command } => credentials(device, reader, command),
    }
}

/// CTAP status bytes mapped to user-facing messages.
fn describe(error: &FidoError<io::Error>) -> String {
    match error {
        FidoError::Random(error) => format!("failed to generate randomness: {error}"),
        FidoError::Drive(DriveError::Transport(error)) => {
            format!("transport exchange failed: {error}")
        }
        FidoError::Drive(DriveError::Protocol(error)) => match error.application_status {
            Some(0x31) => "wrong PIN".to_string(),
            Some(0x32) => "the FIDO2 PIN is blocked".to_string(),
            Some(0x34) => {
                "PIN authentication is currently blocked; remove and re-insert the CanoKey"
                    .to_string()
            }
            Some(0x36) => "the new PIN does not meet the device's requirements".to_string(),
            Some(0x30) => "operation not allowed (a FIDO reset must be confirmed within a few \
                               seconds of inserting the key)"
                .to_string(),
            Some(0x2f) => "timed out waiting for user presence".to_string(),
            Some(0x2e) => "no credentials".to_string(),
            Some(status) => format!("CTAP error 0x{status:02x}"),
            None => match error.kind {
                ErrorKind::InvalidPin => "invalid PIN".to_string(),
                _ => format!("protocol error: {error}"),
            },
        },
    }
}

/// A connected FIDO link: USB HID (native CTAPHID) or FIDO-over-CCID.
enum FidoLink {
    Hid(fido::CtapHidAdapter<HidReportIo>),
    Pcsc(super::Target),
}

impl FidoLink {
    /// HID is preferred (native FIDO transport); PC/SC is used when --reader
    /// or --device is given or no HID interface exists. FIDO over CCID
    /// requires firmware 1.5.2+; older known firmware is rejected with a
    /// clear message.
    fn connect(device: Option<u32>, reader: Option<&str>) -> CliResult<Self> {
        if let Some(serial) = device {
            // Current CanoKey firmware sets the USB HID serial string to the
            // uppercase hex of the 4-byte admin serial (verified on a DevKit:
            // HID "FFFFFFFF" == admin serial 4294967295). Match on that when
            // it is unambiguous; older firmware may not, so fall back to the
            // PC/SC probe and
            // never silently pick another device.
            if let Ok(api) = hidapi::HidApi::new() {
                let matches: Vec<_> = hid::list_fido_interfaces(&api)
                    .into_iter()
                    .filter(|interface| {
                        interface
                            .serial
                            .as_deref()
                            .and_then(|s| u32::from_str_radix(s, 16).ok())
                            == Some(serial)
                    })
                    .collect();
                if matches.len() == 1 {
                    let mut nonce = [0; 8];
                    getrandom::fill(&mut nonce)?;
                    let (channel, capabilities) =
                        hid::connect(&api, &matches[0], nonce, Duration::from_secs(5))?;
                    if !capabilities.cbor {
                        return Err("the HID interface does not speak CTAP2 (CBOR)".into());
                    }
                    return Ok(FidoLink::Hid(fido::CtapHidAdapter::new(
                        channel,
                        Duration::from_secs(60),
                        |_| {},
                    )));
                }
            }
            let pcsc = Pcsc::establish()?;
            let target = single_target(&pcsc, Some(serial), reader).map_err(|_| {
                format!(
                    "cannot resolve --device {serial}: no CanoKey with that serial over PC/SC, \
                     and no HID interface carries the matching serial"
                )
            })?;
            return Self::pcsc(target);
        }
        if reader.is_none() {
            if let Ok(api) = hidapi::HidApi::new() {
                let interfaces = hid::list_fido_interfaces(&api);
                if interfaces.len() > 1 {
                    let mut message =
                        "multiple CanoKey FIDO interfaces found; select one with --device or --reader:"
                        .to_string();
                    for interface in &interfaces {
                        message.push_str(&format!(
                            "
  {} (serial {}, path {:?})",
                            interface.product.as_deref().unwrap_or("CanoKey"),
                            interface.serial.as_deref().unwrap_or("unknown"),
                            interface.path
                        ));
                    }
                    return Err(message.into());
                }
                if let Some(interface) = interfaces.into_iter().next() {
                    let mut nonce = [0; 8];
                    getrandom::fill(&mut nonce)?;
                    match hid::connect(&api, &interface, nonce, Duration::from_secs(5)) {
                        Ok((channel, capabilities)) if capabilities.cbor => {
                            let mut prompted = false;
                            let adapter = fido::CtapHidAdapter::new(
                                channel,
                                Duration::from_secs(60),
                                move |keepalive| {
                                    if keepalive == Keepalive::UserPresenceNeeded && !prompted {
                                        eprintln!("Touch your CanoKey...");
                                        prompted = true;
                                    }
                                    if keepalive == Keepalive::Processing {
                                        prompted = false;
                                    }
                                },
                            );
                            return Ok(FidoLink::Hid(adapter));
                        }
                        Ok(_) => eprintln!("note: the HID interface does not speak CTAP2 (CBOR); falling back to PC/SC"),
                        Err(error) => {
                            // e.g. the hidraw device is busy in another process.
                            eprintln!("note: cannot open the HID interface ({error}); falling back to PC/SC");
                        }
                    }
                }
            }
        }
        let pcsc = Pcsc::establish()?;
        let target = single_target(&pcsc, device, reader)?;
        Self::pcsc(target)
    }

    fn pcsc(target: super::Target) -> CliResult<Self> {
        if let Some(firmware) = target.profile.info().firmware() {
            if (firmware.major, firmware.minor) < (1, 5) {
                return Err("FIDO over CCID requires firmware 1.5.2 or newer".into());
            }
        }
        Ok(FidoLink::Pcsc(target))
    }

    fn run<T>(
        &mut self,
        operation: impl FnOnce(&mut Exchange<'_, io::Error>) -> Result<T, FidoError<io::Error>>,
    ) -> CliResult<T> {
        match self {
            FidoLink::Hid(adapter) => operation(&mut |command| adapter.exchange(command)),
            FidoLink::Pcsc(target) => operation(&mut |command| target.connection.exchange(command)),
        }
        .map_err(|error| describe(&error).into())
    }
}

fn read_line() -> CliResult<String> {
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn prompt_new_pin(minimum: u64) -> CliResult<super::SecretString> {
    let pin = super::prompt_password("Enter the new PIN: ")?;
    if (pin.len() as u64) < minimum || pin.len() > 63 {
        return Err(format!("the PIN must be {minimum}-63 characters").into());
    }
    let repeated = super::prompt_password("Repeat the new PIN: ")?;
    if pin.as_str() != repeated.as_str() {
        return Err("the PINs do not match".into());
    }
    Ok(pin)
}

fn info(device: Option<u32>, reader: Option<&str>) -> CliResult<()> {
    let mut link = FidoLink::connect(device, reader)?;
    let info = link.run(|exchange| fido::get_info(exchange))?;
    println!("FIDO2 version:          {}", info.versions().join(", "));
    println!("AAGUID:                 {}", hex_encode(info.aaguid()));
    if let Some(extensions) = info.extensions() {
        println!("Extensions:             {}", extensions.join(", "));
    }
    if let Some(options) = info.options() {
        let rendered: Vec<String> = options
            .iter()
            .map(|(name, value)| {
                if *value {
                    name.clone()
                } else {
                    format!("not {name}")
                }
            })
            .collect();
        println!("Options:                {}", rendered.join(", "));
    }
    if let Some(algorithms) = info.algorithms() {
        let rendered: Vec<String> = algorithms
            .iter()
            .map(|algorithm| format!("{:?}", algorithm.algorithm()))
            .collect();
        println!("Algorithms:             {}", rendered.join(", "));
    }
    if let Some(transports) = info.transports() {
        println!("Transports:             {}", transports.join(", "));
    }
    if let Some(min) = info.min_pin_length() {
        println!("Min PIN length:         {min}");
    }
    if let Some(remaining) = info.remaining_discoverable_credentials() {
        println!("Remaining discoverable credentials: {remaining}");
    }
    let protocol = fido::preferred_protocol(&info);
    if let Ok(retries) = link.run(|exchange| fido::pin_retries(protocol, exchange)) {
        println!("PIN retries:            {}", retries.pin_retries);
    }
    Ok(())
}

fn reset(device: Option<u32>, reader: Option<&str>, force: bool) -> CliResult<()> {
    if !force {
        if !confirm(
            "This will delete all FIDO credentials, including FIDO U2F credentials, and the FIDO2 PIN. Proceed?",
        )? {
            return Err("FIDO reset aborted".into());
        }
        println!("Remove and re-insert your CanoKey, then press Enter.");
        println!("(The reset command is only accepted for a few seconds after insertion.)");
        read_line()?;
    }
    let mut link = FidoLink::connect(device, reader)?;
    link.run(|exchange| fido::reset(exchange))?;
    println!("FIDO application data reset.");
    Ok(())
}

fn access(device: Option<u32>, reader: Option<&str>, command: &AccessCommand) -> CliResult<()> {
    let mut link = FidoLink::connect(device, reader)?;
    let info = link.run(|exchange| fido::get_info(exchange))?;
    let client_pin_set = info
        .options()
        .and_then(|options| options.iter().find(|(name, _)| name == "clientPin"))
        .map(|(_, value)| *value)
        .unwrap_or(false);
    let protocol = fido::preferred_protocol(&info);
    let minimum = info.min_pin_length().unwrap_or(4);
    match command {
        AccessCommand::SetPin { new_pin } => {
            if client_pin_set {
                return Err("a PIN is already set; use change-pin".into());
            }
            let new_pin = match new_pin {
                Some(pin) => pin.clone(),
                None => prompt_new_pin(minimum)?,
            };
            let session = link.run(|exchange| fido::key_agreement(protocol, exchange))?;
            link.run(|exchange| fido::set_pin(&session, new_pin.as_bytes(), exchange))?;
            println!("FIDO2 PIN set.");
            Ok(())
        }
        AccessCommand::ChangePin { pin, new_pin } => {
            if !client_pin_set {
                return Err("there is no current PIN set; use set-pin".into());
            }
            let pin = match pin {
                Some(pin) => pin.clone(),
                None => super::prompt_password("Enter the current PIN: ")?,
            };
            let new_pin = match new_pin {
                Some(pin) => pin.clone(),
                None => prompt_new_pin(minimum)?,
            };
            let session = link.run(|exchange| fido::key_agreement(protocol, exchange))?;
            link.run(|exchange| {
                fido::change_pin(&session, pin.as_bytes(), new_pin.as_bytes(), exchange)
            })?;
            println!("FIDO2 PIN changed.");
            Ok(())
        }
        AccessCommand::SetMinLength {
            length,
            rp_ids,
            force_change,
            pin,
        } => {
            if !client_pin_set {
                return Err("a FIDO2 PIN must be set first".into());
            }
            let token = config_token(&mut link, protocol, super::secret_str(pin))?;
            link.run(|exchange| {
                fido::set_min_pin_length(
                    &token,
                    protocol,
                    *length,
                    force_change.then_some(true),
                    rp_ids.clone(),
                    exchange,
                )
            })?;
            println!("Minimum PIN length set to {length}.");
            Ok(())
        }
        AccessCommand::VerifyPin { pin } => {
            if !client_pin_set {
                return Err("this CanoKey does not have a FIDO2 PIN set".into());
            }
            let pin = match pin {
                Some(pin) => zeroize::Zeroizing::new(pin.to_string()),
                None => super::prompt_password("Enter the FIDO2 PIN: ")?,
            };
            // A pinUvAuthToken request with an RP binding verifies the PIN,
            // A pinUvAuthToken request with an RP binding verifies the PIN.
            let session = link.run(|exchange| fido::key_agreement(protocol, exchange))?;
            link.run(|exchange| {
                fido::pin_token(
                    &session,
                    pin.as_bytes(),
                    Permissions::GET_ASSERTION,
                    Some("ckman.example.com"),
                    exchange,
                )
            })?;
            println!("PIN verified.");
            Ok(())
        }
        AccessCommand::ForceChange { pin } => {
            if !client_pin_set {
                return Err("a FIDO2 PIN must be set first".into());
            }
            let token = config_token(&mut link, protocol, super::secret_str(pin))?;
            link.run(|exchange| {
                fido::set_min_pin_length(
                    &token,
                    protocol,
                    minimum as u8,
                    Some(true),
                    vec![],
                    exchange,
                )
            })?;
            println!("The user will be required to change the PIN.");
            Ok(())
        }
    }
}

fn config(device: Option<u32>, reader: Option<&str>, command: &ConfigCommand) -> CliResult<()> {
    match command {
        ConfigCommand::ToggleAlwaysUv { pin } => {
            let mut link = FidoLink::connect(device, reader)?;
            let info = link.run(|exchange| fido::get_info(exchange))?;
            let options = info.options();
            let always_uv = options
                .and_then(|options| options.iter().find(|(name, _)| name == "alwaysUv"))
                .map(|(_, value)| *value);
            let Some(always_uv) = always_uv else {
                return Err("Always Require UV is not supported on this CanoKey".into());
            };
            if options
                .and_then(|options| options.iter().find(|(name, _)| name == "authnrCfg"))
                .map(|(_, value)| *value)
                != Some(true)
            {
                return Err("authenticator configuration is not supported on this CanoKey".into());
            }
            let protocol = fido::preferred_protocol(&info);
            let token = config_token(&mut link, protocol, super::secret_str(pin))?;
            link.run(|exchange| fido::toggle_always_uv(&token, protocol, exchange))?;
            println!(
                "Always Require UV is {}.",
                if always_uv { "off" } else { "on" }
            );
            Ok(())
        }
    }
}

fn config_token(
    link: &mut FidoLink,
    protocol: PinUvAuthProtocol,
    pin: Option<&str>,
) -> CliResult<canokey::ctap::pin::PinToken> {
    let pin = match pin {
        Some(pin) => zeroize::Zeroizing::new(pin.to_string()),
        None => super::prompt_password("Enter the FIDO2 PIN: ")?,
    };
    let session = link.run(|exchange| fido::key_agreement(protocol, exchange))?;
    link.run(|exchange| {
        fido::pin_token(
            &session,
            pin.as_bytes(),
            Permissions::AUTHENTICATOR_CONFIG,
            None,
            exchange,
        )
    })
}

fn credman_token(
    link: &mut FidoLink,
    protocol: PinUvAuthProtocol,
    pin: Option<&str>,
) -> CliResult<canokey::ctap::pin::PinToken> {
    let pin = match pin {
        Some(pin) => zeroize::Zeroizing::new(pin.to_string()),
        None => super::prompt_password("Enter the FIDO2 PIN: ")?,
    };
    let session = link.run(|exchange| fido::key_agreement(protocol, exchange))?;
    link.run(|exchange| {
        fido::pin_token(
            &session,
            pin.as_bytes(),
            Permissions::CREDENTIAL_MANAGEMENT,
            None,
            exchange,
        )
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

struct CredRow {
    rp_id: String,
    credential_id: Vec<u8>,
    user_id: Vec<u8>,
    user_name: String,
    display_name: String,
}

fn enumerate(
    link: &mut FidoLink,
    protocol: PinUvAuthProtocol,
    token: &canokey::ctap::pin::PinToken,
) -> CliResult<Vec<CredRow>> {
    let metadata = link.run(|exchange| fido::creds_metadata(token, protocol, exchange))?;
    if metadata.existing_resident_credentials_count == 0 {
        return Ok(Vec::new());
    }
    let rps = link.run(|exchange| fido::enumerate_rps(token, protocol, exchange))?;
    let mut rows = Vec::new();
    for rp in rps {
        let credentials = link.run(|exchange| {
            fido::enumerate_credentials(token, protocol, rp.rp_id_hash, false, exchange)
        })?;
        for credential in credentials {
            let (user_id, user_name, display_name) = match &credential.user {
                Some(user) => (
                    user.id.clone(),
                    user.name.clone().unwrap_or_default(),
                    user.display_name.clone().unwrap_or_default(),
                ),
                None => (Vec::new(), String::new(), String::new()),
            };
            rows.push(CredRow {
                rp_id: rp.rp.id.clone(),
                credential_id: credential.credential_id.id.clone(),
                user_id,
                user_name,
                display_name,
            });
        }
    }
    Ok(rows)
}

fn credentials(
    device: Option<u32>,
    reader: Option<&str>,
    command: &CredentialsCommand,
) -> CliResult<()> {
    match command {
        CredentialsCommand::List { pin, csv } => {
            let mut link = FidoLink::connect(device, reader)?;
            let protocol = {
                let info = link.run(|exchange| fido::get_info(exchange))?;
                fido::preferred_protocol(&info)
            };
            let token = credman_token(&mut link, protocol, super::secret_str(pin))?;
            let rows = enumerate(&mut link, protocol, &token)?;
            if *csv {
                println!("credential_id,rp_id,user_name,user_display_name,user_id");
                for row in &rows {
                    println!(
                        "{},{},{},{},{}",
                        hex_encode(&row.credential_id),
                        row.rp_id,
                        row.user_name,
                        row.display_name,
                        hex_encode(&row.user_id)
                    );
                }
                return Ok(());
            }
            // Unique-shorten the displayed credential ID prefixes.
            let mut len = 4;
            while len < 64
                && rows
                    .iter()
                    .map(|row| row.credential_id.get(..len).unwrap_or(&row.credential_id))
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    < rows.len()
            {
                len += 1;
            }
            let width_id = (len + 3).max(13);
            let width_rp = rows.iter().map(|r| r.rp_id.len()).max().unwrap_or(0).max(5);
            println!(
                "{:<width_id$}  {:<width_rp$}  Username  Display name",
                "Credential ID", "RP ID"
            );
            for row in &rows {
                let prefix = hex_encode(row.credential_id.get(..len).unwrap_or(&row.credential_id));
                println!(
                    "{prefix}...  {:<width_rp$}  {}  {}",
                    row.rp_id, row.user_name, row.display_name
                );
            }
            Ok(())
        }
        CredentialsCommand::Delete {
            credential_id,
            pin,
            force,
        } => {
            let query = credential_id.trim_end_matches('.').to_lowercase();
            let mut link = FidoLink::connect(device, reader)?;
            let protocol = {
                let info = link.run(|exchange| fido::get_info(exchange))?;
                fido::preferred_protocol(&info)
            };
            let token = credman_token(&mut link, protocol, super::secret_str(pin))?;
            let rows = enumerate(&mut link, protocol, &token)?;
            let hits: Vec<&CredRow> = rows
                .iter()
                .filter(|row| hex_encode(&row.credential_id).starts_with(&query))
                .collect();
            let [row] = hits.as_slice() else {
                return Err(if hits.is_empty() {
                    "no matching credential".into()
                } else {
                    "multiple matches; be more specific".into()
                });
            };
            if !force
                && !confirm(&format!(
                    "Delete credential for {} ({})?",
                    row.rp_id, row.user_name
                ))?
            {
                return Err("deletion aborted".into());
            }
            // Same token as the enumeration: one PIN prompt covers both.
            let descriptor =
                PublicKeyCredentialDescriptor::new("public-key", row.credential_id.clone());
            link.run(|exchange| fido::delete_credential(&token, protocol, &descriptor, exchange))?;
            println!("Credential deleted.");
            Ok(())
        }
    }
}
