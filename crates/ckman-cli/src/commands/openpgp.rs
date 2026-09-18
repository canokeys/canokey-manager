use super::{confirm, single_target, CliResult, Target};
use ckman_core::admin::{self, Applet};
use ckman_core::openpgp::{self, Password, PasswordReference, Slot};
use ckman_core::{DriveError, Exchange};
use ckman_transport::pcsc::Pcsc;

use canokey::{DeviceProfile, ErrorKind, SecretReference};
use clap::{Subcommand, ValueEnum};
use std::io::{self, Read, Write as _};

#[derive(Subcommand)]
pub enum OpenPgpCommand {
    /// Display general status of the OpenPGP application.
    Info,
    /// Reset the OpenPGP application, deleting all keys and data.
    Reset {
        /// Do not ask for confirmation.
        #[arg(long)]
        force: bool,
        /// CanoKey Admin PIN (prompted when omitted).
        #[arg(long, value_name = "PIN")]
        admin_pin: Option<String>,
    },
    /// Manage PIN, Reset Code and Admin PIN.
    Access {
        #[command(subcommand)]
        command: AccessCommand,
    },
    /// Manage private keys.
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },
    /// Manage certificates.
    Certificates {
        #[command(subcommand)]
        command: CertificatesCommand,
    },
}

#[derive(Subcommand)]
pub enum AccessCommand {
    /// Set retry counters for PIN, Reset Code and Admin PIN.
    ///
    /// Note: this resets the PIN and Admin PIN to their factory defaults.
    SetRetries {
        /// PIN retry count (1-15).
        #[arg(value_parser = clap::value_parser!(u8).range(1..=15))]
        pin_retries: u8,
        /// Reset Code retry count (1-15).
        #[arg(value_parser = clap::value_parser!(u8).range(1..=15))]
        reset_code_retries: u8,
        /// Admin PIN retry count (1-15).
        #[arg(value_parser = clap::value_parser!(u8).range(1..=15))]
        admin_pin_retries: u8,
        /// Admin PIN (prompted when omitted).
        #[arg(short, long)]
        admin_pin: Option<String>,
        /// Do not ask for confirmation.
        #[arg(long)]
        force: bool,
    },
    /// Change the User PIN.
    ChangePin {
        /// Current PIN (prompted when omitted).
        #[arg(short = 'P', long)]
        pin: Option<String>,
        /// New PIN (prompted when omitted).
        #[arg(short, long)]
        new_pin: Option<String>,
    },
    /// Change the Admin PIN.
    ChangeAdminPin {
        /// Current Admin PIN (prompted when omitted).
        #[arg(short, long)]
        admin_pin: Option<String>,
        /// New Admin PIN (prompted when omitted).
        #[arg(short = 'n', long)]
        new_admin_pin: Option<String>,
    },
    /// Set (or, with --clear, remove) the Reset Code.
    ChangeResetCode {
        /// Admin PIN (prompted when omitted).
        #[arg(short, long)]
        admin_pin: Option<String>,
        /// New Reset Code (prompted when omitted).
        #[arg(short, long)]
        reset_code: Option<String>,
        /// Remove the Reset Code instead of setting one.
        #[arg(short, long)]
        clear: bool,
    },
    /// Unblock and set a new PIN using the Reset Code or the Admin PIN.
    UnblockPin {
        /// Admin PIN (use "-" to prompt).
        #[arg(short, long)]
        admin_pin: Option<String>,
        /// Reset Code.
        #[arg(short, long)]
        reset_code: Option<String>,
        /// New PIN (prompted when omitted).
        #[arg(short = 'n', long)]
        new_pin: Option<String>,
    },
    /// Set the signature PIN policy.
    SetSignaturePolicy {
        /// Whether the PIN is required for every signature or once per session.
        #[arg(value_enum)]
        policy: SignaturePolicyArg,
        /// Admin PIN (prompted when omitted).
        #[arg(short, long)]
        admin_pin: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum KeysCommand {
    /// Show metadata about a private key.
    Info {
        /// Key slot.
        #[arg(value_enum)]
        key: KeySlotArg,
    },
    /// Generate a key pair on the device (replacing any key in the slot).
    Generate {
        /// Key slot.
        #[arg(value_enum)]
        key: KeySlotArg,
        /// Set the slot's algorithm attributes first (discards any existing key).
        #[arg(short, long, value_enum)]
        algorithm: Option<KeyAlgorithmArg>,
        /// Admin PIN (prompted when omitted).
        #[arg(short = 'a', long)]
        admin_pin: Option<String>,
    },
    /// Import a private key (PEM/DER: PKCS#8, PKCS#1, SEC1).
    Import {
        /// Key slot.
        #[arg(value_enum)]
        key: KeySlotArg,
        /// File containing the private key ('-' for stdin).
        private_key: String,
        /// Set the slot's algorithm attributes first (discards any existing key).
        #[arg(long, value_enum)]
        algorithm: Option<KeyAlgorithmArg>,
        /// Password used to decrypt the private key.
        #[arg(short, long)]
        password: Option<String>,
        /// Admin PIN (prompted when omitted).
        #[arg(short = 'a', long)]
        admin_pin: Option<String>,
    },
    /// Set the touch policy for a key slot.
    SetTouch {
        /// Key slot.
        #[arg(value_enum)]
        key: KeySlotArg,
        /// Touch policy to set.
        #[arg(value_enum)]
        policy: TouchPolicyArg,
        /// Admin PIN (prompted when omitted).
        #[arg(short = 'a', long)]
        admin_pin: Option<String>,
        /// Do not ask for confirmation.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
pub enum CertificatesCommand {
    /// Import a certificate (PEM/DER) for a key slot.
    Import {
        /// Key slot.
        #[arg(value_enum)]
        key: KeySlotArg,
        /// File containing the certificate ('-' for stdin).
        certificate: String,
        /// Admin PIN (prompted when omitted).
        #[arg(short = 'a', long)]
        admin_pin: Option<String>,
    },
    /// Export the certificate of a key slot.
    Export {
        /// Key slot.
        #[arg(value_enum)]
        key: KeySlotArg,
        /// File to write the certificate to ('-' for stdout).
        certificate: String,
        /// Output format.
        #[arg(long, value_enum, default_value_t = EncodingArg::Pem)]
        format: EncodingArg,
    },
    /// Delete the certificate of a key slot (the key is retained).
    Delete {
        /// Key slot.
        #[arg(value_enum)]
        key: KeySlotArg,
        /// Admin PIN (prompted when omitted).
        #[arg(short = 'a', long)]
        admin_pin: Option<String>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum KeySlotArg {
    Sig,
    Dec,
    Aut,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum KeyAlgorithmArg {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EccP256,
    EccP384,
    EccP521,
    Secp256k1,
    Ed25519,
    X25519,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum TouchPolicyArg {
    Off,
    On,
    Fixed,
    Cached,
    CachedFixed,
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum SignaturePolicyArg {
    Always,
    Once,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum EncodingArg {
    Pem,
    Der,
}

pub fn run(device: Option<u32>, reader: Option<&str>, command: &OpenPgpCommand) -> CliResult<()> {
    match command {
        OpenPgpCommand::Info => info(device, reader),
        OpenPgpCommand::Reset { force, admin_pin } => {
            reset(device, reader, *force, admin_pin.as_deref())
        }
        OpenPgpCommand::Access { command } => access(device, reader, command),
        OpenPgpCommand::Keys { command } => keys(device, reader, command),
        OpenPgpCommand::Certificates { command } => certificates(device, reader, command),
    }
}

fn slot_of(arg: KeySlotArg) -> Slot {
    match arg {
        KeySlotArg::Sig => Slot::Signature,
        KeySlotArg::Dec => Slot::Decryption,
        KeySlotArg::Aut => Slot::Authentication,
    }
}

fn slot_name(slot: Slot) -> &'static str {
    match slot {
        Slot::Signature => "Signature",
        Slot::Decryption => "Decryption",
        Slot::Authentication => "Authentication",
    }
}

fn algorithm_of(arg: KeyAlgorithmArg) -> openpgp::Algorithm {
    use openpgp::Algorithm;
    match arg {
        KeyAlgorithmArg::Rsa2048 => Algorithm::Rsa2048,
        KeyAlgorithmArg::Rsa3072 => Algorithm::Rsa3072,
        KeyAlgorithmArg::Rsa4096 => Algorithm::Rsa4096,
        KeyAlgorithmArg::EccP256 => Algorithm::EccP256,
        KeyAlgorithmArg::EccP384 => Algorithm::EccP384,
        KeyAlgorithmArg::EccP521 => Algorithm::EccP521,
        KeyAlgorithmArg::Secp256k1 => Algorithm::Secp256k1,
        KeyAlgorithmArg::Ed25519 => Algorithm::Ed25519,
        KeyAlgorithmArg::X25519 => Algorithm::X25519,
    }
}

fn describe(error: &DriveError<io::Error>) -> String {
    match error {
        DriveError::Transport(error) => format!("transport exchange failed: {error}"),
        DriveError::Protocol(error) => match error.kind {
            ErrorKind::AuthenticationFailed => match error.reference {
                Some(SecretReference::Pw3) => "incorrect Admin PIN".to_string(),
                Some(SecretReference::ResetCode) => "incorrect Reset Code".to_string(),
                _ => match error.retries_remaining {
                    Some(retries) => format!("incorrect PIN ({retries} attempts remaining)"),
                    None => "incorrect PIN".to_string(),
                },
            },
            ErrorKind::PinBlocked => match error.reference {
                Some(SecretReference::Pw3) => "the Admin PIN is blocked".to_string(),
                Some(SecretReference::ResetCode) => "the Reset Code is blocked".to_string(),
                _ => "the PIN is blocked".to_string(),
            },
            ErrorKind::NotFound => "not found on the device".to_string(),
            ErrorKind::UnsupportedAlgorithm => {
                "algorithm does not match the slot's configured attributes (use --algorithm \
                 to change them, which discards the existing key)"
                    .to_string()
            }
            ErrorKind::CapabilityUnknown => {
                "unrecognized firmware; refusing to attempt the operation".to_string()
            }
            ErrorKind::UnsupportedFeature => {
                "this firmware does not support the operation".to_string()
            }
            ErrorKind::SecurityStatusNotSatisfied => {
                "the operation requires authentication".to_string()
            }
            ErrorKind::ConditionsNotSatisfied => {
                "the card refused the operation (conditions not satisfied)".to_string()
            }
            _ => format!("protocol error: {error}"),
        },
    }
}

struct OpenPgpSession {
    target: Target,
}

impl OpenPgpSession {
    fn connect(device: Option<u32>, reader: Option<&str>) -> CliResult<Self> {
        let pcsc = Pcsc::establish()?;
        let target = single_target(&pcsc, device, reader)?;
        Ok(Self { target })
    }

    fn profile(&self) -> &DeviceProfile {
        &self.target.profile
    }

    fn run<T>(
        &mut self,
        operation: impl FnOnce(
            &DeviceProfile,
            &mut Exchange<'_, io::Error>,
        ) -> Result<T, DriveError<io::Error>>,
    ) -> CliResult<T> {
        operation(&self.target.profile, &mut |command| {
            self.target.connection.exchange(command)
        })
        .map_err(|error| describe(&error).into())
    }

    fn password(
        value: Option<&str>,
        prompt: &str,
        minimum: usize,
        name: &str,
    ) -> CliResult<String> {
        let value = match value {
            Some(value) => value.to_string(),
            None => rpassword::prompt_password(format!("{prompt}: "))?,
        };
        if value.len() < minimum || value.len() > 64 {
            return Err(format!("{name} must be {minimum}-64 characters").into());
        }
        Ok(value)
    }

    fn pin(value: Option<&str>, prompt: &str) -> CliResult<Password> {
        let pin = Self::password(value, prompt, 6, "PIN")?;
        Ok(Password::from_bytes(pin.as_bytes()).expect("length checked"))
    }

    fn admin_string(value: Option<&str>, prompt: &str) -> CliResult<String> {
        Self::password(value, prompt, 8, "Admin PIN")
    }

    fn admin(value: Option<&str>, prompt: &str) -> CliResult<Password> {
        let pin = Self::admin_string(value, prompt)?;
        Ok(Password::from_bytes(pin.as_bytes()).expect("length checked"))
    }

    fn new_password(prompt: &str, minimum: usize, name: &str) -> CliResult<Password> {
        let entered = Self::password(None, prompt, minimum, name)?;
        let repeated = rpassword::prompt_password(format!("Repeat the {name}: "))?;
        if entered != repeated {
            return Err(format!("the {name}s do not match").into());
        }
        Ok(Password::from_bytes(entered.as_bytes()).expect("length checked"))
    }
}

fn fingerprint_hex(fingerprint: Option<[u8; 20]>) -> Option<String> {
    use std::fmt::Write as _;
    let fingerprint = fingerprint?;
    if fingerprint.iter().all(|b| *b == 0) {
        return None;
    }
    Some(fingerprint.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02X}");
        out
    }))
}

/// The UIF two-byte value rendered like the Python CLI's policy names.
fn touch_policy_name(uif: Option<[u8; 2]>) -> &'static str {
    match uif.map(|[policy, flags]| (policy, flags & 0x20 != 0)) {
        Some((0, _)) => "off",
        Some((1, false)) => "on",
        Some((1, true)) => "cached",
        Some((2, false)) => "fixed",
        Some((2, true)) => "cached-fixed",
        _ => "unknown",
    }
}

/// Algorithm attributes rendered like the Python CLI (`RSA2048`, curve names).
fn attributes_name(attributes: Option<&[u8]>) -> String {
    let Some(attributes) = attributes else {
        return "unknown".to_string();
    };
    match attributes[0] {
        1 if attributes.len() >= 2 => {
            format!("RSA{}", u16::from_be_bytes([attributes[1], attributes[2]]))
        }
        0x12 | 0x13 | 0x16 => {
            // Match the known curve OID bytes.
            match &attributes[1..] {
                [0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7] => "ECCP256".to_string(),
                [0x2b, 0x81, 4, 0, 0x22] => "ECCP384".to_string(),
                [0x2b, 0x81, 4, 0, 0x23] => "ECCP521".to_string(),
                [0x2b, 0x81, 4, 0, 10] => "SECP256K1".to_string(),
                [0x2b, 6, 1, 4, 1, 0xda, 0x47, 15, 1] => "ED25519".to_string(),
                [0x2b, 6, 1, 4, 1, 0x97, 0x55, 1, 5, 1] => "X25519".to_string(),
                other => format!("unknown ({})", super_hex(other)),
            }
        }
        other => format!("unknown (0x{other:02x})"),
    }
}

fn super_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn key_information(data: &openpgp::ApplicationData, slot: Slot) -> Option<u8> {
    let field = data.discretionary.iter().find(|field| field.tag == 0xde)?;
    let bytes = field.value.as_bytes();
    if bytes.len() != 3 {
        return None;
    }
    Some(bytes[slot.occurrence() as usize])
}

fn info(device: Option<u32>, reader: Option<&str>) -> CliResult<()> {
    let mut session = OpenPgpSession::connect(device, reader)?;
    let data =
        session.run(|profile, exchange| openpgp::read_application_data(profile, exchange))?;
    if let Some(aid) = data.aid()? {
        println!("OpenPGP version:          {}.{}", aid[6], aid[7]);
    }
    println!(
        "Application version:      {}",
        String::from_utf8_lossy(session.profile().info().firmware_text())
    );
    if let Some(status) = data.password_status()? {
        println!("PIN tries remaining:      {}", status.retries[0]);
        println!("Reset code tries remaining: {}", status.retries[1]);
        println!("Admin PIN tries remaining: {}", status.retries[2]);
        println!(
            "Require PIN for signature: {}",
            if status.signature_policy == 0 {
                "always"
            } else {
                "once"
            }
        );
    }
    // The pinned firmware evidence has no KDF data object at all.
    println!("KDF enabled:              no");
    for slot in [Slot::Signature, Slot::Decryption, Slot::Authentication] {
        let Some(fingerprint) = fingerprint_hex(data.fingerprint(slot)?) else {
            continue;
        };
        println!("{} key:", slot_name(slot));
        println!("  Fingerprint:   {fingerprint}");
        println!(
            "  Touch policy:  {}",
            touch_policy_name(data.touch_policy(slot)?)
        );
    }
    Ok(())
}

fn reset(
    device: Option<u32>,
    reader: Option<&str>,
    force: bool,
    admin_pin: Option<&str>,
) -> CliResult<()> {
    let pcsc = Pcsc::establish()?;
    let mut target = single_target(&pcsc, device, reader)?;
    if !force
        && !confirm(
            "This will delete all stored OpenPGP keys and data and restore factory settings. Proceed?",
        )?
    {
        return Err("OpenPGP reset aborted".into());
    }
    println!("Resetting OpenPGP data, don't remove the CanoKey...");
    let pin = admin_pin
        .map(|pin| admin::Pin::from_bytes(pin.as_bytes()).map_err(|error| format!("{error}")))
        .transpose()?;
    super::with_admin_pin_retry(pin, |pin| {
        admin::reset_applet(&target.profile, Applet::OpenPgp, pin, &mut |command| {
            target.connection.exchange(command)
        })
    })?;
    println!("Reset complete. OpenPGP data has been cleared and default PINs are set.");
    println!("PIN:         123456");
    println!("Reset code:  not set");
    println!("Admin PIN:   12345678");
    Ok(())
}

fn access(device: Option<u32>, reader: Option<&str>, command: &AccessCommand) -> CliResult<()> {
    match command {
        AccessCommand::SetRetries {
            pin_retries,
            reset_code_retries,
            admin_pin_retries,
            admin_pin,
            force,
        } => {
            let mut session = OpenPgpSession::connect(device, reader)?;
            let admin = OpenPgpSession::admin(admin_pin.as_deref(), "Enter Admin PIN")?;
            println!("WARNING: Setting PIN retries will reset the values for all 3 PINs!");
            if !force
                && !confirm(&format!(
                    "Set PIN retry counters to: {pin_retries} {reset_code_retries} {admin_pin_retries}?"
                ))?
            {
                return Err("aborted".into());
            }
            session.run(|profile, exchange| {
                openpgp::reset_retries(
                    profile,
                    [*pin_retries, *reset_code_retries, *admin_pin_retries],
                    admin,
                    exchange,
                )
            })?;
            println!("Number of PIN/Reset Code/Admin PIN retries set.");
            println!("Default values have been restored:");
            println!("PIN:         123456");
            println!("Admin PIN:   12345678");
            Ok(())
        }
        AccessCommand::ChangePin { pin, new_pin } => {
            let mut session = OpenPgpSession::connect(device, reader)?;
            let old = OpenPgpSession::pin(pin.as_deref(), "Enter PIN")?;
            let new = match new_pin {
                Some(pin) => OpenPgpSession::pin(Some(pin.as_str()), "Enter PIN")?,
                None => OpenPgpSession::new_password("New PIN", 6, "PIN")?,
            };
            session.run(|profile, exchange| {
                openpgp::change_password(profile, PasswordReference::Pw1Sign, old, new, exchange)
            })?;
            println!("User PIN has been changed.");
            Ok(())
        }
        AccessCommand::ChangeAdminPin {
            admin_pin,
            new_admin_pin,
        } => {
            let mut session = OpenPgpSession::connect(device, reader)?;
            let old = OpenPgpSession::admin(admin_pin.as_deref(), "Enter Admin PIN")?;
            let new = match new_admin_pin {
                Some(pin) => OpenPgpSession::admin(Some(pin.as_str()), "Enter Admin PIN")?,
                None => OpenPgpSession::new_password("New Admin PIN", 8, "Admin PIN")?,
            };
            session.run(|profile, exchange| {
                openpgp::change_password(profile, PasswordReference::Pw3, old, new, exchange)
            })?;
            println!("Admin PIN has been changed.");
            Ok(())
        }
        AccessCommand::ChangeResetCode {
            admin_pin,
            reset_code,
            clear,
        } => {
            if *clear && reset_code.is_some() {
                return Err("--clear cannot be combined with --reset-code".into());
            }
            let mut session = OpenPgpSession::connect(device, reader)?;
            let admin = OpenPgpSession::admin(admin_pin.as_deref(), "Enter Admin PIN")?;
            let code = if *clear {
                None
            } else {
                Some(match reset_code {
                    Some(code) => OpenPgpSession::admin(Some(code.as_str()), "Enter Reset Code")?,
                    None => OpenPgpSession::new_password("New Reset Code", 8, "Reset Code")?,
                })
            };
            session
                .run(|profile, exchange| openpgp::set_reset_code(profile, code, admin, exchange))?;
            if *clear {
                println!("Reset Code has been removed.");
            } else {
                println!("Reset Code has been changed.");
            }
            Ok(())
        }
        AccessCommand::UnblockPin {
            admin_pin,
            reset_code,
            new_pin,
        } => {
            if reset_code.is_some() && admin_pin.is_some() {
                return Err("only one of --reset-code and --admin-pin may be used".into());
            }
            let mut session = OpenPgpSession::connect(device, reader)?;
            let new = match new_pin {
                Some(pin) => OpenPgpSession::pin(Some(pin.as_str()), "Enter PIN")?,
                None => OpenPgpSession::new_password("New PIN", 6, "PIN")?,
            };
            match (admin_pin, reset_code) {
                (Some(admin), None) => {
                    let admin = if admin == "-" {
                        OpenPgpSession::admin(None, "Enter Admin PIN")?
                    } else {
                        OpenPgpSession::admin(Some(admin.as_str()), "Enter Admin PIN")?
                    };
                    session.run(|profile, exchange| {
                        openpgp::unblock_with_admin(profile, new, admin, exchange)
                    })?;
                }
                (None, code) => {
                    let code = match code {
                        Some(code) => {
                            OpenPgpSession::admin(Some(code.as_str()), "Enter Reset Code")?
                        }
                        None => OpenPgpSession::admin(None, "Enter Reset Code")?,
                    };
                    session.run(|profile, exchange| {
                        openpgp::unblock_with_code(profile, code, new, exchange)
                    })?;
                }
                (Some(_), Some(_)) => unreachable!("rejected above"),
            }
            println!("User PIN has been changed.");
            Ok(())
        }
        AccessCommand::SetSignaturePolicy { policy, admin_pin } => {
            let mut session = OpenPgpSession::connect(device, reader)?;
            let admin = OpenPgpSession::admin(admin_pin.as_deref(), "Enter Admin PIN")?;
            let reuse = *policy == SignaturePolicyArg::Once;
            session.run(|profile, exchange| {
                openpgp::set_signature_policy(profile, reuse, admin, exchange)
            })?;
            println!("Signature PIN policy has been set.");
            Ok(())
        }
    }
}

fn keys(device: Option<u32>, reader: Option<&str>, command: &KeysCommand) -> CliResult<()> {
    match command {
        KeysCommand::Info { key } => {
            let mut session = OpenPgpSession::connect(device, reader)?;
            let slot = slot_of(*key);
            let data = session
                .run(|profile, exchange| openpgp::read_application_data(profile, exchange))?;
            if key_information(&data, slot) == Some(0) {
                return Err(format!("no key stored in slot {:?}", slot_name(slot)).into());
            }
            println!("Key slot:      {}", slot_name(slot));
            println!(
                "Fingerprint:   {}",
                fingerprint_hex(data.fingerprint(slot)?).unwrap_or_default()
            );
            println!(
                "Algorithm:     {}",
                attributes_name(data.algorithm_attributes(slot)?)
            );
            println!(
                "Origin:        {}",
                match key_information(&data, slot) {
                    Some(1) => "generated on device",
                    Some(2) => "imported",
                    _ => "unknown",
                }
            );
            if let Some(time) = data.generation_time(slot)? {
                if time != 0 {
                    println!("Created:       {time}");
                }
            }
            println!(
                "Touch policy:  {}",
                touch_policy_name(data.touch_policy(slot)?)
            );
            Ok(())
        }
        KeysCommand::Generate {
            key,
            algorithm,
            admin_pin,
        } => {
            let mut session = OpenPgpSession::connect(device, reader)?;
            let slot = slot_of(*key);
            let admin = OpenPgpSession::admin_string(admin_pin.as_deref(), "Enter Admin PIN")?;
            if let Some(algorithm) = algorithm {
                println!(
                    "Setting the slot algorithm discards any existing key in the slot; generating a new key."
                );
                let pw3 = Password::from_bytes(admin.as_bytes()).expect("length checked");
                session.run(|profile, exchange| {
                    openpgp::set_algorithm(profile, slot, algorithm_of(*algorithm), pw3, exchange)
                })?;
            }
            let pw3 = Password::from_bytes(admin.as_bytes()).expect("length checked");
            let public = session
                .run(|profile, exchange| openpgp::generate_key(profile, slot, pw3, exchange))?;
            let _ = public;
            println!("Key generated in slot {}.", slot_name(slot));
            Ok(())
        }
        KeysCommand::Import {
            key,
            private_key,
            algorithm,
            password,
            admin_pin,
        } => {
            let data = read_input(private_key)?;
            let password = match password {
                Some(password) => Some(password.clone()),
                None if data.starts_with(b"-----BEGIN ENCRYPTED") => Some(
                    rpassword::prompt_password("Enter the private key password: ")?,
                ),
                None => None,
            };
            let imported =
                ckman_core::keys::parse_private_key(&data, password.as_deref().map(str::as_bytes))
                    .map_err(|error| format!("{error}"))?;
            let mut session = OpenPgpSession::connect(device, reader)?;
            let slot = slot_of(*key);
            let admin = OpenPgpSession::admin_string(admin_pin.as_deref(), "Enter Admin PIN")?;
            if let Some(algorithm) = algorithm {
                println!(
                    "Setting the slot algorithm discards any existing key in the slot; importing over it."
                );
                let pw3 = Password::from_bytes(admin.as_bytes()).expect("length checked");
                session.run(|profile, exchange| {
                    openpgp::set_algorithm(profile, slot, algorithm_of(*algorithm), pw3, exchange)
                })?;
            }
            let material = imported.openpgp_key().map_err(|error| format!("{error}"))?;
            let pw3 = Password::from_bytes(admin.as_bytes()).expect("length checked");
            session.run(|profile, exchange| {
                openpgp::import_key(profile, slot, imported.algorithm, material, pw3, exchange)
            })?;
            println!("Private key imported for slot {}.", slot_name(slot));
            Ok(())
        }
        KeysCommand::SetTouch {
            key,
            policy,
            admin_pin,
            force,
        } => {
            let mut session = OpenPgpSession::connect(device, reader)?;
            let slot = slot_of(*key);
            let admin = OpenPgpSession::admin(admin_pin.as_deref(), "Enter Admin PIN")?;
            let policy_name = format!("{policy:?}").to_lowercase();
            let prompt = format!(
                "Set touch policy of {:?} key to {policy_name}?",
                slot_name(slot)
            );
            let fixed = matches!(policy, TouchPolicyArg::Fixed | TouchPolicyArg::CachedFixed);
            if fixed {
                println!(
                    "WARNING: This touch policy cannot be changed without deleting the corresponding key slot!"
                );
            }
            if !force && !confirm(&prompt)? {
                return Err("aborted".into());
            }
            let policy = match policy {
                TouchPolicyArg::Off => openpgp::TouchPolicy::Off,
                TouchPolicyArg::On | TouchPolicyArg::Cached => openpgp::TouchPolicy::On,
                TouchPolicyArg::Fixed | TouchPolicyArg::CachedFixed => {
                    openpgp::TouchPolicy::Permanent
                }
            };
            session.run(|profile, exchange| {
                openpgp::set_touch_policy(profile, slot, policy, admin, exchange)
            })?;
            println!("Touch policy for slot {} set.", slot_name(slot));
            Ok(())
        }
    }
}

fn read_input(path: &str) -> CliResult<Vec<u8>> {
    if path == "-" {
        let mut data = Vec::new();
        io::stdin().read_to_end(&mut data)?;
        Ok(data)
    } else {
        Ok(std::fs::read(path)?)
    }
}

fn certificates(
    device: Option<u32>,
    reader: Option<&str>,
    command: &CertificatesCommand,
) -> CliResult<()> {
    match command {
        CertificatesCommand::Import {
            key,
            certificate,
            admin_pin,
        } => {
            let data = read_input(certificate)?;
            let der = if data.starts_with(b"-----BEGIN") {
                canokey::x509::parse_pem(&data, Default::default())
                    .map_err(|error| format!("invalid certificate: {error}"))?
                    .der
            } else {
                canokey::x509::parse_der(&data, Default::default())
                    .map_err(|error| format!("invalid certificate: {error}"))?
                    .der
            };
            let mut session = OpenPgpSession::connect(device, reader)?;
            let admin = OpenPgpSession::admin(admin_pin.as_deref(), "Enter Admin PIN")?;
            session.run(|profile, exchange| {
                openpgp::write_certificate(profile, slot_of(*key), der, admin, exchange)
            })?;
            println!(
                "Certificate imported for slot {}.",
                slot_name(slot_of(*key))
            );
            Ok(())
        }
        CertificatesCommand::Export {
            key,
            certificate,
            format,
        } => {
            let mut session = OpenPgpSession::connect(device, reader)?;
            let der = session.run(|profile, exchange| {
                openpgp::read_certificate(profile, slot_of(*key), exchange)
            })?;
            let data = match format {
                EncodingArg::Pem => ckman_core::x509::pem_encode("CERTIFICATE", &der),
                EncodingArg::Der => der,
            };
            if certificate == "-" {
                io::stdout().write_all(&data)?;
            } else {
                std::fs::write(certificate, data)?;
            }
            println!("Certificate written to {certificate}.");
            Ok(())
        }
        CertificatesCommand::Delete { key, admin_pin } => {
            let mut session = OpenPgpSession::connect(device, reader)?;
            let admin = OpenPgpSession::admin(admin_pin.as_deref(), "Enter Admin PIN")?;
            // CanoKey has no certificate-deletion command; an empty PUT clears it.
            session.run(|profile, exchange| {
                openpgp::write_certificate(profile, slot_of(*key), Vec::new(), admin, exchange)
            })?;
            println!("Certificate deleted for slot {}.", slot_name(slot_of(*key)));
            Ok(())
        }
    }
}
