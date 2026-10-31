use super::{
    confirm, describe_drive_error, single_target, with_admin_pin_retry, CliResult, Target,
};
use ckman_core::admin::{self, Applet, Pin};
use ckman_core::oath::{self, Access, Algorithm, Entry, Format, Kind, Name};
use ckman_core::oath::{OathError, Selected};
use ckman_core::uri;
use ckman_core::{DriveError, Exchange};
use ckman_transport::pcsc::Pcsc;

use canokey::{DeviceProfile, ErrorKind, Phase, SecretBytes, SecretReference};
use clap::{Args, Subcommand, ValueEnum};
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

fn store_remembered_key(entry: &keyring::Entry, key: &[u8; 16]) -> keyring::Result<()> {
    let encoded = Zeroizing::new(hex_encode(key));
    entry.set_password(&encoded)
}

fn recall_remembered_key(entry: &keyring::Entry) -> Option<Zeroizing<[u8; 16]>> {
    let stored = Zeroizing::new(entry.get_password().ok()?);
    let bytes = Zeroizing::new(hex_decode(stored.trim())?);
    Some(Zeroizing::new(bytes.as_slice().try_into().ok()?))
}

#[cfg(test)]
mod keyring_tests {
    use super::*;
    use keyring::mock::MockCredential;

    #[test]
    fn remember_recall_forget_and_unavailable_keyring() {
        let entry = keyring::Entry::new_with_credential(Box::new(MockCredential::default()));
        assert!(recall_remembered_key(&entry).is_none());
        let key = [0x5a; 16];
        store_remembered_key(&entry, &key).unwrap();
        assert_eq!(*recall_remembered_key(&entry).unwrap(), key);
        let mock = entry
            .get_credential()
            .downcast_ref::<MockCredential>()
            .unwrap();
        mock.set_error(keyring::Error::NoEntry);
        assert!(recall_remembered_key(&entry).is_none());
        assert_eq!(*recall_remembered_key(&entry).unwrap(), key);
        mock.set_error(keyring::Error::NoEntry);
        assert!(store_remembered_key(&entry, &[0; 16]).is_err());
        assert_eq!(*recall_remembered_key(&entry).unwrap(), key);
        entry.delete_credential().unwrap();
        assert!(recall_remembered_key(&entry).is_none());
        assert!(entry.delete_credential().is_err());
    }

    #[test]
    fn malformed_remembered_keys_are_rejected() {
        let entry = keyring::Entry::new_with_credential(Box::new(MockCredential::default()));
        for value in ["not hex", "00", &"ab".repeat(17)] {
            entry.set_password(value).unwrap();
            assert!(recall_remembered_key(&entry).is_none());
        }
    }
}

#[derive(Subcommand)]
pub enum OathCommand {
    /// Display general status of the OATH application.
    Info,
    /// Delete all OATH accounts and the OATH password.
    Reset {
        /// Do not ask for confirmation.
        #[arg(long)]
        force: bool,
        /// CanoKey Admin PIN (prompted when omitted).
        #[arg(long, value_name = "PIN", value_parser = crate::commands::secret_arg)]
        admin_pin: Option<crate::commands::SecretString>,
    },
    /// Print the device serial as answered by the OATH applet.
    Serial,
    /// Compute an HMAC-SHA1 challenge-response from a PASS slot.
    ///
    /// The slot must be configured as HMAC-SHA1 (see `config pass set`).
    ChallengeResponse {
        /// PASS HMAC-SHA1 slot to answer from.
        #[arg(value_enum)]
        slot: DefaultSlotArg,
        /// The challenge, hex-encoded (a plain string with --text).
        challenge: String,
        /// Treat the challenge as a plain UTF-8 string instead of hex.
        #[arg(short, long)]
        text: bool,
    },
    /// Manage password protection for OATH.
    Access {
        #[command(subcommand)]
        command: AccessCommand,
    },
    /// Manage and use OATH accounts.
    Accounts {
        #[command(subcommand)]
        command: AccountsCommand,
    },
}

#[derive(Subcommand)]
pub enum AccessCommand {
    /// Set or change the OATH password.
    Change {
        /// The current password.
        #[arg(short, long, value_parser = crate::commands::secret_arg)]
        password: Option<crate::commands::SecretString>,
        /// Remove the current password instead of setting a new one.
        #[arg(short, long)]
        clear: bool,
        /// Provide the new password as an argument.
        #[arg(short = 'n', long, value_parser = crate::commands::secret_arg)]
        new_password: Option<crate::commands::SecretString>,
        /// Remember the password on this machine (long-only: the global
        /// -r/--reader owns the short flag).
        #[arg(long)]
        remember: bool,
    },
    /// Store the OATH password in the OS keyring to avoid entering it on each use.
    Remember {
        /// The current password.
        #[arg(short, long, value_parser = crate::commands::secret_arg)]
        password: Option<crate::commands::SecretString>,
    },
    /// Remove this device's stored password from the OS keyring.
    Forget,
}

#[derive(Subcommand)]
pub enum AccountsCommand {
    /// Add a new account.
    Add {
        /// Human-readable name of the account, such as a username or e-mail address.
        name: String,
        /// Base32-encoded secret key provided by the server (prompted when omitted).
        #[arg(value_parser = super::secret_arg)]
        secret: Option<super::SecretString>,
        /// Time-based (TOTP) or counter-based (HOTP) account.
        #[arg(short = 'o', long, value_enum, default_value_t = KindArg::Totp)]
        oath_type: KindArg,
        /// Number of digits in generated codes (long-only: the global
        /// -d/--device owns the short flag).
        #[arg(long, default_value_t = 6, value_parser = clap::value_parser!(u8).range(4..=8))]
        digits: u8,
        /// Algorithm used for code generation.
        #[arg(short, long, value_enum, default_value_t = AlgorithmArg::Sha1)]
        algorithm: AlgorithmArg,
        /// Stored HOTP counter; the first calculation uses COUNTER + 1.
        #[arg(short, long, default_value_t = 0)]
        counter: u32,
        /// Issuer of the account (optional).
        #[arg(short, long)]
        issuer: Option<String>,
        /// Number of seconds a TOTP code is valid.
        #[arg(short = 'P', long, default_value_t = 30, value_parser = clap::value_parser!(u32).range(1..))]
        period: u32,
        /// Generate a random credential key (cannot be used with SECRET).
        #[arg(short, long)]
        generate: bool,
        /// Require touch on the CanoKey to generate a code.
        #[arg(short, long)]
        touch: bool,
        /// Skip the existing-account check.
        #[arg(short, long)]
        force: bool,
        #[command(flatten)]
        access: AccessArgs,
    },
    /// Add a new account from an otpauth:// URI (prompted when omitted).
    ///
    /// HOTP counter specifies the next code's counter. CanoKey cannot start
    /// at counter zero; such URIs are rejected. Query parameter names and
    /// values accept percent-encoding; repeated recognized parameters are
    /// rejected before connecting to the key.
    Uri {
        /// The otpauth:// URI.
        #[arg(value_parser = super::secret_arg)]
        uri: Option<super::SecretString>,
        /// Require touch on the CanoKey to generate a code.
        #[arg(short, long)]
        touch: bool,
        /// Skip the existing-account check.
        #[arg(short, long)]
        force: bool,
        #[command(flatten)]
        access: AccessArgs,
    },
    /// List all accounts.
    List {
        /// Include hidden accounts.
        #[arg(short = 'H', long)]
        show_hidden: bool,
        /// Display the OATH type.
        #[arg(short = 'o', long)]
        oath_type: bool,
        /// Display the period.
        #[arg(short = 'P', long)]
        period: bool,
        #[command(flatten)]
        access: AccessArgs,
    },
    /// Generate codes from matching accounts using each account's own period.
    /// Touch-protected TOTP accounts request touch individually. HOTP accounts
    /// are calculated only when exactly one account matches.
    /// Results are printed as each account completes.
    Code {
        /// Query string to match specific accounts.
        query: Option<String>,
        /// Ensure only a single match, and output only the code.
        #[arg(short, long)]
        single: bool,
        /// Include hidden accounts.
        #[arg(short = 'H', long)]
        show_hidden: bool,
        #[command(flatten)]
        access: AccessArgs,
    },
    /// Rename an account.
    Rename {
        /// A query to match a single account (as shown in "list").
        query: String,
        /// The new name of the account (use "issuer:name" to specify an issuer).
        name: String,
        /// Confirm the rename without prompting.
        #[arg(short, long)]
        force: bool,
        #[command(flatten)]
        access: AccessArgs,
    },
    /// Mark an existing HOTP account as the touch keyboard-emulation default.
    SetDefault {
        /// A query to match a single account (as shown in "list").
        query: String,
        /// Touch slot (firmware 3.0+ for long).
        #[arg(long, value_enum, default_value_t = DefaultSlotArg::Short)]
        slot: DefaultSlotArg,
        /// Append a Return keystroke after the emitted code (firmware 3.0+).
        #[arg(long)]
        enter: bool,
        #[command(flatten)]
        access: AccessArgs,
    },
    /// Delete an account.
    Delete {
        /// A query to match a single account (as shown in "list").
        query: String,
        /// Confirm the deletion without prompting.
        #[arg(short, long)]
        force: bool,
        #[command(flatten)]
        access: AccessArgs,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum KindArg {
    Totp,
    Hotp,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum AlgorithmArg {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum DefaultSlotArg {
    Short,
    Long,
}

#[derive(Args)]
pub struct AccessArgs {
    /// The password to unlock the OATH application.
    #[arg(short, long, value_parser = crate::commands::secret_arg)]
    password: Option<crate::commands::SecretString>,
    /// Remember the password on this machine (long-only: the global
    /// -r/--reader owns the short flag).
    #[arg(long)]
    remember: bool,
}

const KEYRING_SERVICE: &str = "ckman";

pub fn run(device: Option<u32>, reader: Option<&str>, command: &OathCommand) -> CliResult<()> {
    match command {
        OathCommand::Info => info(device, reader),
        OathCommand::Serial => serial(device, reader),
        OathCommand::ChallengeResponse {
            slot,
            challenge,
            text,
        } => challenge_response(device, reader, *slot, challenge, *text),
        OathCommand::Reset { force, admin_pin } => {
            reset(device, reader, *force, super::secret_str(admin_pin))
        }
        OathCommand::Access { command } => match command {
            AccessCommand::Change {
                password,
                clear,
                new_password,
                remember,
            } => access_change(
                device,
                reader,
                super::secret_str(password),
                *clear,
                super::secret_str(new_password),
                *remember,
            ),
            AccessCommand::Remember { password } => {
                access_remember(device, reader, super::secret_str(password))
            }
            AccessCommand::Forget => access_forget(device, reader),
        },
        OathCommand::Accounts { command } => match command {
            AccountsCommand::Add {
                name,
                secret,
                oath_type,
                digits,
                algorithm,
                counter,
                issuer,
                period,
                generate,
                touch,
                force,
                access,
            } => accounts_add(
                device,
                reader,
                AddInput {
                    name: name.clone(),
                    secret: secret.clone(),
                    kind: match oath_type {
                        KindArg::Totp => Kind::Totp,
                        KindArg::Hotp => Kind::Hotp,
                    },
                    digits: *digits,
                    algorithm: match algorithm {
                        AlgorithmArg::Sha1 => Algorithm::Sha1,
                        AlgorithmArg::Sha256 => Algorithm::Sha256,
                        AlgorithmArg::Sha512 => Algorithm::Sha512,
                    },
                    counter: *counter,
                    issuer: issuer.clone(),
                    period: *period,
                    generate: *generate,
                },
                *touch,
                *force,
                access,
            ),
            AccountsCommand::Uri {
                uri: uri_arg,
                touch,
                force,
                access,
            } => accounts_uri(device, reader, uri_arg.clone(), *touch, *force, access),
            AccountsCommand::List {
                show_hidden,
                oath_type,
                period,
                access,
            } => accounts_list(device, reader, *show_hidden, *oath_type, *period, access),
            AccountsCommand::Code {
                query,
                single,
                show_hidden,
                access,
            } => accounts_code(
                device,
                reader,
                query.as_deref().unwrap_or(""),
                *single,
                *show_hidden,
                access,
            ),
            AccountsCommand::Rename {
                query,
                name,
                force,
                access,
            } => accounts_rename(device, reader, query, name, *force, access),
            AccountsCommand::SetDefault {
                query,
                slot,
                enter,
                access,
            } => accounts_set_default(device, reader, query, *slot, *enter, access),
            AccountsCommand::Delete {
                query,
                force,
                access,
            } => accounts_delete(device, reader, query, *force, access),
        },
    }
}

/// A connected OATH applet with its resolved access key, when protected.
struct OathSession {
    target: Target,
    handle: Option<[u8; 8]>,
    key: Option<Zeroizing<[u8; 16]>>,
}

impl OathSession {
    /// Connect, select the OATH applet, and resolve access: an explicit
    /// password is used first, then a remembered key, then a prompt. A stale
    /// remembered key is forgotten and falls through to the prompt.
    fn connect(
        device: Option<u32>,
        reader: Option<&str>,
        password: Option<&str>,
        remember: bool,
    ) -> CliResult<Self> {
        let pcsc = Pcsc::establish()?;
        let mut target = single_target(&pcsc, device, reader)?;
        let selected = oath::select(&target.profile, &mut |command| {
            target.connection.exchange(command)
        })
        .map_err(|error| describe_oath(&error))?;
        let (locked, handle) = match &selected {
            Selected::Modern(selection) => (selection.challenge.is_some(), Some(selection.handle)),
            Selected::Legacy { .. } => (false, None),
        };
        let mut session = OathSession {
            target,
            handle,
            key: None,
        };
        if !locked {
            if password.is_some() {
                return Err("password provided, but no password is set".into());
            }
            return Ok(session);
        }
        let handle = handle.expect("a locked applet is modern and carries a handle");
        if let Some(password) = password {
            let key = oath::derive_key_bytes(password.as_bytes(), handle);
            session
                .validate_key(&key)
                .map_err(|error| wrong_password(&error))?;
            if remember {
                session.remember_key(&key);
            }
            session.key = Some(key);
            return Ok(session);
        }
        if let Some(key) = session.recall_key() {
            match session.validate_key(&key) {
                Ok(()) => {
                    session.key = Some(key);
                    return Ok(session);
                }
                Err(error) if is_wrong_password(&error) => {
                    // The device-bound key no longer matches (password changed
                    // on another host); forget it and fall through to a prompt.
                    session.forget_key();
                }
                Err(error) => return Err(describe_oath(&error).into()),
            }
        }
        let password = super::prompt_password("Enter the OATH password: ")?;
        let key = oath::derive_key_bytes(password.as_bytes(), handle);
        session
            .validate_key(&key)
            .map_err(|error| wrong_password(&error))?;
        if remember {
            session.remember_key(&key);
        }
        session.key = Some(key);
        Ok(session)
    }

    fn validate_key(&mut self, key: &[u8; 16]) -> Result<(), OathError<io::Error>> {
        let access = oath::access_from_key(oath::access_key(key))?;
        oath::validate(&self.target.profile, access, &mut |command| {
            self.target.connection.exchange(command)
        })
    }

    /// Run one OATH operation with the resolved access, if any. A fresh
    /// CSPRNG challenge is built per operation; every operation re-SELECTs
    /// and re-validates.
    fn run<T>(
        &mut self,
        operation: impl FnOnce(
            &DeviceProfile,
            Option<Access>,
            &mut Exchange<'_, io::Error>,
        ) -> Result<T, OathError<io::Error>>,
    ) -> CliResult<T> {
        self.run_typed(operation)
            .map_err(|error| describe_oath(&error).into())
    }

    fn run_typed<T>(
        &mut self,
        operation: impl FnOnce(
            &DeviceProfile,
            Option<Access>,
            &mut Exchange<'_, io::Error>,
        ) -> Result<T, OathError<io::Error>>,
    ) -> Result<T, OathError<io::Error>> {
        let access = match &self.key {
            Some(key) => Some(oath::access_from_key(oath::access_key(key))?),
            None => None,
        };
        operation(&self.target.profile, access, &mut |command| {
            self.target.connection.exchange(command)
        })
    }

    fn keyring_entry(&self) -> Option<keyring::Entry> {
        let serial = self.target.serial()?;
        keyring::Entry::new(KEYRING_SERVICE, &format!("oath:{serial}"))
            .map_err(|error| {
                eprintln!("Warning: system keyring unavailable: {error}");
                error
            })
            .ok()
    }

    /// Store the device-bound derived key (never the password) in the OS
    /// keyring, keyed by device serial. Keyring failure is non-fatal.
    fn remember_key(&self, key: &[u8; 16]) {
        let Some(entry) = self.keyring_entry() else {
            eprintln!("Warning: no readable serial number; password not remembered");
            return;
        };
        match store_remembered_key(&entry, key) {
            Ok(()) => eprintln!("Password remembered."),
            Err(error) => eprintln!("Warning: could not store password in the keyring: {error}"),
        }
    }

    fn recall_key(&self) -> Option<Zeroizing<[u8; 16]>> {
        let entry = self.keyring_entry()?;
        recall_remembered_key(&entry)
    }

    /// Delete the remembered key; returns whether one was stored.
    fn forget_key(&self) -> bool {
        let Some(entry) = self.keyring_entry() else {
            return false;
        };
        entry.delete_credential().is_ok()
    }
}

fn is_wrong_password(error: &OathError<io::Error>) -> bool {
    matches!(
        error,
        OathError::Drive(DriveError::Protocol(error))
            if error.kind == ErrorKind::AuthenticationFailed
                && error.reference == Some(SecretReference::OathAccess)
    )
}

fn wrong_password(error: &OathError<io::Error>) -> Box<dyn std::error::Error> {
    if is_wrong_password(error) {
        "authentication to the CanoKey failed; wrong password?".into()
    } else {
        describe_oath(error).into()
    }
}

fn describe_oath(error: &OathError<io::Error>) -> String {
    match error {
        OathError::Random(error) => {
            format!("failed to generate authentication randomness: {error}")
        }
        OathError::Drive(DriveError::Protocol(error)) => match error.kind {
            ErrorKind::AuthenticationFailed => {
                "authentication to the CanoKey failed; wrong password?".to_string()
            }
            ErrorKind::DeviceAuthenticationFailed => {
                "the CanoKey failed mutual authentication; refusing to continue".to_string()
            }
            ErrorKind::NotFound => "no such account".to_string(),
            ErrorKind::ConditionsNotSatisfied
                if error.phase == Phase::Authentication && error.status_word.is_none() =>
            {
                "an OATH access key was supplied, but the applet has no password set".to_string()
            }
            ErrorKind::ConditionsNotSatisfied => {
                "the OATH command's execution conditions were not satisfied".to_string()
            }
            _ => describe_drive_error(&DriveError::Protocol(error.clone())),
        },
        OathError::Drive(drive) => describe_drive_error(drive),
    }
}

fn describe_calculation(error: &OathError<io::Error>, kind: Kind) -> String {
    if let OathError::Drive(DriveError::Protocol(protocol)) = error {
        if protocol.phase == Phase::Command {
            match protocol.kind {
                ErrorKind::SecurityStatusNotSatisfied => {
                    return if kind == Kind::Totp {
                        "TOTP calculation rejected: touch may have timed out or been cancelled, or the time step is older than the credential's stored value; check the system clock".to_string()
                    } else {
                        "HOTP calculation rejected by a security condition; touch may have timed out or been cancelled".to_string()
                    };
                }
                ErrorKind::ConditionsNotSatisfied => {
                    return if kind == Kind::Hotp {
                        "HOTP calculation conditions not satisfied: touch may have timed out or the counter may be exhausted".to_string()
                    } else {
                        "TOTP calculation conditions not satisfied; touch may have timed out"
                            .to_string()
                    };
                }
                _ => {}
            }
        }
    }
    describe_oath(error)
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(text.get(index..index + 2)?, 16).ok())
        .collect()
}

/// Vendor extension commands the OATH applet answers before its
/// access-validation gate (KeePassXC-style challenge-response); they need no
/// password even when one is set, and are gated to the pinned 3.1 evidence by
/// libcanokey.
fn serial(device: Option<u32>, reader: Option<&str>) -> CliResult<()> {
    let pcsc = Pcsc::establish()?;
    let mut target = single_target(&pcsc, device, reader)?;
    let serial = oath::get_serial(&target.profile, &mut |command| {
        target.connection.exchange(command)
    })
    .map_err(|error| describe_oath(&error))?;
    println!("{}", u32::from_be_bytes(serial));
    Ok(())
}

fn challenge_response(
    device: Option<u32>,
    reader: Option<&str>,
    slot: DefaultSlotArg,
    challenge: &str,
    text: bool,
) -> CliResult<()> {
    let challenge = if text {
        challenge.as_bytes().to_vec()
    } else {
        hex_decode(challenge).ok_or("the challenge must be hex-encoded (or use --text)")?
    };
    if challenge.len() > 64 {
        return Err("the challenge must be at most 64 bytes".into());
    }
    let slot = match slot {
        DefaultSlotArg::Short => oath::HmacSlot::Short,
        DefaultSlotArg::Long => oath::HmacSlot::Long,
    };
    let pcsc = Pcsc::establish()?;
    let mut target = single_target(&pcsc, device, reader)?;
    let response =
        oath::challenge_response_hmac(&target.profile, slot, challenge, &mut |command| {
            target.connection.exchange(command)
        })
        .map_err(|error| describe_oath(&error))?;
    println!("{}", hex_encode(response.as_bytes()));
    Ok(())
}

fn info(device: Option<u32>, reader: Option<&str>) -> CliResult<()> {
    let pcsc = Pcsc::establish()?;
    let mut target = single_target(&pcsc, device, reader)?;
    let selected = oath::select(&target.profile, &mut |command| {
        target.connection.exchange(command)
    })
    .map_err(|error| describe_oath(&error))?;
    match &selected {
        Selected::Modern(selection) => {
            let [major, minor, patch] = selection.version;
            println!("OATH version:         {major}.{minor}.{patch}");
            println!(
                "Password protection:  {}",
                if selection.challenge.is_some() {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            if selection.challenge.is_some() {
                if let Some(entry) = target.serial().and_then(|serial| {
                    keyring::Entry::new(KEYRING_SERVICE, &format!("oath:{serial}")).ok()
                }) {
                    if entry.get_password().is_ok() {
                        println!("The password for this CanoKey is remembered by ckman.");
                    }
                }
            }
        }
        Selected::Legacy { .. } => {
            println!("OATH version:         unknown (legacy firmware)");
            println!("Password protection:  disabled (not supported by this firmware)");
        }
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
        && !confirm("This will delete all stored OATH accounts and the OATH password. Proceed?")?
    {
        return Err("OATH reset aborted".into());
    }
    let pin = admin_pin
        .map(|pin| Pin::from_bytes(pin.as_bytes()).map_err(|error| format!("{error}")))
        .transpose()?;
    with_admin_pin_retry(pin, |pin| {
        admin::reset_applet(&target.profile, Applet::Oath, pin, &mut |command| {
            target.connection.exchange(command)
        })
    })?;
    // The device-bound remembered key no longer matches after a reset.
    let serial = target.serial();
    if let Some(serial) = serial {
        if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, &format!("oath:{serial}")) {
            let _ = entry.delete_credential();
        }
    }
    println!("Reset complete. All OATH accounts have been deleted from the CanoKey.");
    Ok(())
}

fn access_change(
    device: Option<u32>,
    reader: Option<&str>,
    password: Option<&str>,
    clear: bool,
    new_password: Option<&str>,
    remember: bool,
) -> CliResult<()> {
    if clear && new_password.is_some() {
        return Err("--clear cannot be combined with --new-password".into());
    }
    let mut session = OathSession::connect(device, reader, password, false)?;
    if clear {
        session.run(|profile, access, exchange| oath::clear_password(profile, access, exchange))?;
        session.forget_key();
        println!("Password cleared from the CanoKey.");
        return Ok(());
    }
    let new_password = match new_password {
        Some(password) => super::SecretString::new(password.to_string()),
        None => {
            let entered = super::prompt_password("Enter the new OATH password: ")?;
            let repeated = super::prompt_password("Repeat the new OATH password: ")?;
            if entered.as_str() != repeated.as_str() {
                return Err("the passwords do not match".into());
            }
            entered
        }
    };
    let handle = session
        .handle
        .ok_or("this firmware does not support OATH password protection")?;
    let new_key = oath::derive_key_bytes(new_password.as_bytes(), handle);
    session.run(|profile, access, exchange| {
        oath::set_password(profile, access, oath::access_key(&new_key), exchange)
    })?;
    if remember {
        session.remember_key(&new_key);
    } else {
        session.forget_key();
    }
    println!("Password updated.");
    Ok(())
}

fn access_remember(
    device: Option<u32>,
    reader: Option<&str>,
    password: Option<&str>,
) -> CliResult<()> {
    let pcsc = Pcsc::establish()?;
    let mut target = single_target(&pcsc, device, reader)?;
    let selected = oath::select(&target.profile, &mut |command| {
        target.connection.exchange(command)
    })
    .map_err(|error| describe_oath(&error))?;
    let Selected::Modern(selection) = &selected else {
        println!("This CanoKey is not password protected.");
        return Ok(());
    };
    if selection.challenge.is_none() {
        println!("This CanoKey is not password protected.");
        return Ok(());
    }
    let password = match password {
        Some(password) => super::SecretString::new(password.to_string()),
        None => super::prompt_password("Enter the OATH password: ")?,
    };
    let key = oath::derive_key_bytes(password.as_bytes(), selection.handle);
    let access = oath::access_from_key(oath::access_key(&key))?;
    oath::validate(&target.profile, access, &mut |command| {
        target.connection.exchange(command)
    })
    .map_err(|error| wrong_password(&error))?;
    let session = OathSession {
        target,
        handle: Some(selection.handle),
        key: None,
    };
    session.remember_key(&key);
    Ok(())
}

fn access_forget(device: Option<u32>, reader: Option<&str>) -> CliResult<()> {
    let pcsc = Pcsc::establish()?;
    let target = single_target(&pcsc, device, reader)?;
    let session = OathSession {
        target,
        handle: None,
        key: None,
    };
    if session.forget_key() {
        println!("Password forgotten.");
    } else {
        println!("No password stored for this CanoKey.");
    }
    Ok(())
}

/// Inputs shared by `accounts add` and `accounts uri`.
struct AddInput {
    name: String,
    secret: Option<super::SecretString>,
    kind: Kind,
    digits: u8,
    algorithm: Algorithm,
    counter: u32,
    issuer: Option<String>,
    period: u32,
    generate: bool,
}

fn accounts_add(
    device: Option<u32>,
    reader: Option<&str>,
    input: AddInput,
    touch: bool,
    force: bool,
    access: &AccessArgs,
) -> CliResult<()> {
    if input.counter != 0 && input.kind != Kind::Hotp {
        return Err("counter is only supported for HOTP accounts".into());
    }
    if input.generate && input.secret.is_some() {
        return Err("cannot use --generate together with a provided SECRET".into());
    }
    let mut generated = false;
    let secret = zeroize::Zeroizing::new(match (&input.secret, input.generate) {
        (Some(secret), false) => {
            uri::base32_decode(secret).map_err(|error| format!("invalid base32 secret: {error}"))?
        }
        (None, true) => {
            let mut secret = vec![0; 20];
            getrandom::fill(&mut secret)?;
            generated = true;
            secret
        }
        (None, false) => loop {
            let Some(entered) = super::prompt_line("Enter a secret key (base32): ")? else {
                return Err("no secret key entered (end of input)".into());
            };
            let entered = super::SecretString::new(entered);
            match uri::base32_decode(&entered) {
                Ok(secret) => break secret,
                Err(error) => println!("invalid base32 secret: {error}"),
            }
        },
        (Some(_), true) => unreachable!("--generate with SECRET rejected above"),
    });
    add_credential(
        device,
        reader,
        input.issuer.as_deref(),
        &input.name,
        input.kind,
        input.algorithm,
        input.digits,
        input.period,
        input.counter,
        secret,
        generated,
        touch,
        force,
        access,
    )
}

fn accounts_uri(
    device: Option<u32>,
    reader: Option<&str>,
    uri_arg: Option<super::SecretString>,
    touch: bool,
    force: bool,
    access: &AccessArgs,
) -> CliResult<()> {
    let mut parsed = match uri_arg {
        Some(text) => uri::parse(&text).map_err(|error| format!("{error}"))?,
        None => loop {
            let Some(entered) = super::prompt_line("Enter an OATH URI (otpauth://): ")? else {
                return Err("no URI entered (end of input)".into());
            };
            let entered = super::SecretString::new(entered);
            match uri::parse(&entered) {
                Ok(parsed) => break parsed,
                Err(error) => println!("{error}"),
            }
        },
    };
    let counter = uri_initial_counter(parsed.kind, parsed.counter)?;
    // Steam issues 5-digit URIs for what is a 6-digit computation; the
    // steam_code formatter maps the result to the five-character alphabet.
    if parsed.digits == 5 && parsed.issuer.as_deref() == Some("Steam") {
        parsed.digits = 6;
    }
    add_credential(
        device,
        reader,
        parsed.issuer.as_deref(),
        &parsed.account,
        parsed.kind,
        parsed.algorithm,
        parsed.digits,
        parsed.period,
        counter,
        parsed.secret,
        false,
        touch,
        force,
        access,
    )
}

// The URI counter is the next RFC 4226 moving factor. CanoKey stores the
// previous factor and increments it before calculating; its PUT ABI accepts
// only a 32-bit nonnegative value, so a first factor of zero is unavailable.
fn uri_initial_counter(kind: Kind, counter: u32) -> CliResult<u32> {
    match kind {
        Kind::Hotp => counter.checked_sub(1).ok_or_else(||
            "HOTP URI counter=0 is unsupported: CanoKey increments before calculating; a nonzero next counter is required".into()),
        Kind::Totp if counter != 0 => Err("counter is only supported for HOTP accounts".into()),
        Kind::Totp => Ok(0),
    }
}

#[allow(clippy::too_many_arguments)]
fn add_credential(
    device: Option<u32>,
    reader: Option<&str>,
    issuer: Option<&str>,
    name: &str,
    kind: Kind,
    algorithm: Algorithm,
    digits: u8,
    period: u32,
    counter: u32,
    secret: zeroize::Zeroizing<Vec<u8>>,
    generated: bool,
    touch: bool,
    force: bool,
    access: &AccessArgs,
) -> CliResult<()> {
    if kind == Kind::Totp && period == 0 {
        return Err("TOTP period must be at least one second".into());
    }
    if kind == Kind::Totp && counter != 0 {
        return Err("counter is only supported for HOTP accounts".into());
    }
    if !(4..=8).contains(&digits) {
        return Err("digits must be between 4 and 8".into());
    }
    if !(1..=64).contains(&secret.len()) {
        return Err("secret must be between 1 and 64 bytes".into());
    }
    let id = oath::format_id(issuer, name, kind, period);
    let credential = oath::Credential {
        name: Name::from_bytes(id.as_bytes()).map_err(|_| "name must be between 1 and 64 bytes")?,
        kind,
        algorithm,
        digits,
        secret: SecretBytes::new(secret.to_vec()),
        require_touch: touch,
        increasing: false,
        initial_counter: counter,
    };
    let mut session = OathSession::connect(
        device,
        reader,
        super::secret_str(&access.password),
        access.remember,
    )?;
    if !force {
        let entries =
            session.run(|profile, access, exchange| oath::list(profile, access, exchange))?;
        // CanoKey firmware does not silently replace an existing name; fail
        // before the write instead of surfacing the card's duplicate error.
        if entries
            .iter()
            .any(|entry| entry.name.as_bytes() == id.as_bytes())
        {
            return Err(format!("an account called '{id}' already exists; delete it first").into());
        }
    }
    session.run(|profile, access, exchange| oath::add(profile, access, credential, exchange))?;
    println!("Account added.");
    if generated {
        println!(
            "Generated credential secret (base32): {}",
            uri::base32_encode(&secret)
        );
    }
    Ok(())
}

/// Credential type decoded from the high nibble of the algorithm/type octet.
fn kind_of(entry: &Entry) -> Option<Kind> {
    match entry.algorithm_type >> 4 {
        1 => Some(Kind::Hotp),
        2 => Some(Kind::Totp),
        _ => None,
    }
}

/// HMAC algorithm decoded from the low nibble of the algorithm/type octet.
fn algorithm_of(entry: &Entry) -> CliResult<Algorithm> {
    match entry.algorithm_type & 0x0f {
        1 => Ok(Algorithm::Sha1),
        2 => Ok(Algorithm::Sha256),
        3 => Ok(Algorithm::Sha512),
        other => Err(format!("unsupported algorithm octet 0x{other:x}").into()),
    }
}

fn display_name(entry: &Entry) -> String {
    String::from_utf8_lossy(entry.name.as_bytes()).into_owned()
}

/// Search accounts: an exact match wins; otherwise a case-insensitive
/// substring match. Hidden accounts are skipped unless asked.
fn search<'e>(entries: &'e [Entry], query: &str, show_hidden: bool) -> Vec<&'e Entry> {
    let mut hits = Vec::new();
    for entry in entries {
        let parsed = oath::parse_name(entry.name.as_bytes(), kind_of(entry).unwrap_or(Kind::Totp));
        if !show_hidden && parsed.issuer.as_deref() == Some("_hidden") {
            continue;
        }
        let id = display_name(entry);
        // Lossy display strings can collide for distinct raw names. Only raw
        // byte equality may override the other substring matches.
        if entry.name.as_bytes() == query.as_bytes() {
            return vec![entry];
        }
        if id.to_lowercase().contains(&query.to_lowercase()) {
            hits.push(entry);
        }
    }
    hits
}

fn multiple_hits(hits: &[&Entry]) -> Box<dyn std::error::Error> {
    let mut message = "multiple matches, make the query more specific:".to_string();
    for hit in hits {
        message.push_str("\n  ");
        message.push_str(&display_name(hit));
    }
    message.into()
}

fn accounts_list(
    device: Option<u32>,
    reader: Option<&str>,
    show_hidden: bool,
    show_type: bool,
    show_period: bool,
    access: &AccessArgs,
) -> CliResult<()> {
    let mut session = OathSession::connect(
        device,
        reader,
        super::secret_str(&access.password),
        access.remember,
    )?;
    let entries = session.run(|profile, access, exchange| oath::list(profile, access, exchange))?;
    let mut rows: Vec<String> = entries
        .iter()
        .filter(|entry| {
            let parsed =
                oath::parse_name(entry.name.as_bytes(), kind_of(entry).unwrap_or(Kind::Totp));
            show_hidden || parsed.issuer.as_deref() != Some("_hidden")
        })
        .map(|entry| {
            let mut row = display_name(entry);
            if show_type {
                row.push_str(match kind_of(entry) {
                    Some(Kind::Hotp) => ", HOTP",
                    Some(Kind::Totp) => ", TOTP",
                    None => ", unknown",
                });
            }
            if show_period {
                let parsed =
                    oath::parse_name(entry.name.as_bytes(), kind_of(entry).unwrap_or(Kind::Totp));
                if kind_of(entry) == Some(Kind::Totp) {
                    row.push_str(&format!(", {}", parsed.period));
                }
            }
            row
        })
        .collect();
    rows.sort_by_key(|row| row.to_lowercase());
    for row in rows {
        println!("{row}");
    }
    Ok(())
}

fn accounts_code(
    device: Option<u32>,
    reader: Option<&str>,
    query: &str,
    single: bool,
    show_hidden: bool,
    access: &AccessArgs,
) -> CliResult<()> {
    let mut session = OathSession::connect(
        device,
        reader,
        super::secret_str(&access.password),
        access.remember,
    )?;
    let entries = session.run(|profile, access, exchange| oath::list(profile, access, exchange))?;
    let hits = search(&entries, query, show_hidden);
    if single && hits.len() != 1 {
        return Err(if hits.is_empty() {
            "no matching account found".into()
        } else {
            multiple_hits(&hits)
        });
    }
    if hits.is_empty() {
        return Ok(());
    }
    let one_match = hits.len() == 1;
    write_account_codes(&hits, single, &mut io::stdout().lock(), |entry| {
        account_code(entry, one_match, |kind, period| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "system clock is before the Unix epoch")?
                .as_secs();
            calculate_one(&mut session, entry, kind, period, now, false)
        })
    })
}

/// Publish and flush each result before the next calculation can wait for
/// touch or persist state. A later failure must not hide completed codes.
fn write_account_codes(
    entries: &[&Entry],
    single: bool,
    output: &mut impl io::Write,
    mut calculate: impl FnMut(&Entry) -> CliResult<String>,
) -> CliResult<()> {
    let mut rows: Vec<_> = entries
        .iter()
        .map(|entry| (display_name(entry), *entry))
        .collect();
    rows.sort_by_key(|(name, _)| name.to_lowercase());
    let longest_name = rows
        .iter()
        .map(|(name, _)| name.chars().count())
        .max()
        .unwrap_or(0);
    for (name, entry) in rows {
        let code = calculate(entry).map_err(|error| format!("{name}: {error}"))?;
        if single {
            writeln!(output, "{code}")?;
        } else {
            writeln!(output, "{name:<longest_name$}  {code}")?;
        }
        output.flush()?;
    }
    Ok(())
}

/// Calculate only this matched credential. CALCULATE ALL cannot safely
/// discover touch flags: its shared challenge can advance an increasing TOTP
/// credential past its proper time step, even when that account is not matched.
fn account_code(
    entry: &Entry,
    one_match: bool,
    mut calculate: impl FnMut(Kind, u32) -> CliResult<oath::Calculation>,
) -> CliResult<String> {
    let kind = kind_of(entry).ok_or("unsupported credential type octet")?;
    if kind == Kind::Hotp && !one_match {
        return Ok("[HOTP Account]".to_string());
    }
    let parsed = oath::parse_name(entry.name.as_bytes(), kind);
    if kind == Kind::Totp && parsed.period == 0 {
        return Err("the credential has an invalid zero TOTP period".into());
    }
    eprintln!(
        "{}: touch your CanoKey if it flashes...",
        display_name(entry)
    );
    let calculation = calculate(kind, parsed.period)?;
    if kind == Kind::Totp && parsed.issuer.as_deref() == Some("Steam") {
        oath::steam_code(&calculation)
            .ok_or_else(|| "the credential did not produce a Steam code".into())
    } else {
        decimal(&calculation)
    }
}

/// Individually calculate one credential (HOTP, touch-protected, or Steam),
/// using the credential's own TOTP period for the time step.
fn calculate_one(
    session: &mut OathSession,
    entry: &Entry,
    kind: Kind,
    period: u32,
    now: u64,
    full: bool,
) -> CliResult<oath::Calculation> {
    let credential = oath::CredentialRef {
        name: Name::from_bytes(entry.name.as_bytes())?,
        kind,
        algorithm: algorithm_of(entry)?,
    };
    let challenge = (kind == Kind::Totp).then(|| oath::totp_challenge(now, period));
    let format = if full {
        Format::Full
    } else {
        Format::Truncated
    };
    session
        .run_typed(|profile, access, exchange| {
            oath::calculate(profile, access, credential, challenge, format, exchange)
        })
        .map_err(|error| describe_calculation(&error, kind).into())
}

fn decimal(calculation: &oath::Calculation) -> CliResult<String> {
    let decimal = calculation
        .decimal()
        .ok_or("the credential did not produce a truncated code")?;
    String::from_utf8(decimal.as_bytes().to_vec()).map_err(|_| "invalid code bytes".into())
}

fn accounts_rename(
    device: Option<u32>,
    reader: Option<&str>,
    query: &str,
    name: &str,
    force: bool,
    access: &AccessArgs,
) -> CliResult<()> {
    let mut session = OathSession::connect(
        device,
        reader,
        super::secret_str(&access.password),
        access.remember,
    )?;
    let entries = session.run(|profile, access, exchange| oath::list(profile, access, exchange))?;
    let hits = search(&entries, query, true);
    let [entry] = hits.as_slice() else {
        return Err(if hits.is_empty() {
            "no matches, nothing to be done".into()
        } else {
            multiple_hits(&hits)
        });
    };
    let kind = kind_of(entry).ok_or("unsupported credential type octet")?;
    let parsed = oath::parse_name(entry.name.as_bytes(), kind);
    let (issuer, account) = match name.split_once(':') {
        Some((issuer, account)) => (Some(issuer), account),
        None => (None, name),
    };
    let new_id = oath::format_id(issuer, account, kind, parsed.period);
    if entries
        .iter()
        .any(|other| other.name.as_bytes() == new_id.as_bytes())
    {
        return Err(
            format!("another account with ID {new_id} already exists on this CanoKey").into(),
        );
    }
    if !force && !confirm(&format!("Rename account: {}?", display_name(entry)))? {
        return Err("rename aborted".into());
    }
    let old = Name::from_bytes(entry.name.as_bytes())?;
    let new =
        Name::from_bytes(new_id.as_bytes()).map_err(|_| "name must be between 1 and 64 bytes")?;
    session.run(|profile, access, exchange| oath::rename(profile, access, old, new, exchange))?;
    println!("Renamed {} to {new_id}.", display_name(entry));
    Ok(())
}

/// Mark an HOTP credential as the keyboard-emulation default (PASS slot).
fn accounts_set_default(
    device: Option<u32>,
    reader: Option<&str>,
    query: &str,
    slot: DefaultSlotArg,
    enter: bool,
    access: &AccessArgs,
) -> CliResult<()> {
    let mut session = OathSession::connect(
        device,
        reader,
        super::secret_str(&access.password),
        access.remember,
    )?;
    let entries = session.run(|profile, access, exchange| oath::list(profile, access, exchange))?;
    let hits = search(&entries, query, true);
    let [entry] = hits.as_slice() else {
        return Err(if hits.is_empty() {
            "no matches, nothing to be done".into()
        } else {
            multiple_hits(&hits)
        });
    };
    if kind_of(entry) != Some(Kind::Hotp) {
        return Err("only HOTP accounts can be the keyboard-emulation default".into());
    }
    let name = Name::from_bytes(entry.name.as_bytes())?;
    let slot = match slot {
        DefaultSlotArg::Short => oath::DefaultSlot::Short,
        DefaultSlotArg::Long => oath::DefaultSlot::Long,
    };
    session.run(|profile, access, exchange| {
        oath::set_default(profile, slot, enter, name, access, exchange)
    })?;
    println!(
        "Default credential set ({} touch slot).",
        match slot {
            oath::DefaultSlot::Short => "short",
            oath::DefaultSlot::Long => "long",
        }
    );
    Ok(())
}

fn accounts_delete(
    device: Option<u32>,
    reader: Option<&str>,
    query: &str,
    force: bool,
    access: &AccessArgs,
) -> CliResult<()> {
    let mut session = OathSession::connect(
        device,
        reader,
        super::secret_str(&access.password),
        access.remember,
    )?;
    let entries = session.run(|profile, access, exchange| oath::list(profile, access, exchange))?;
    let hits = search(&entries, query, true);
    let [entry] = hits.as_slice() else {
        return Err(if hits.is_empty() {
            "no matches, nothing to be done".into()
        } else {
            multiple_hits(&hits)
        });
    };
    if !force && !confirm(&format!("Delete account: {}?", display_name(entry)))? {
        return Err("deletion aborted".into());
    }
    let name = Name::from_bytes(entry.name.as_bytes())?;
    session.run(|profile, access, exchange| oath::delete(profile, access, name, exchange))?;
    println!("Deleted {}.", display_name(entry));
    Ok(())
}

#[cfg(test)]
mod import_tests {
    use super::*;

    #[test]
    fn uri_counter_conversion_preserves_the_next_rfc_counter() {
        assert!(uri_initial_counter(Kind::Hotp, 0)
            .unwrap_err()
            .to_string()
            .contains("counter=0"));
        for next in [1, 42, u32::MAX] {
            let stored = uri_initial_counter(Kind::Hotp, next).unwrap();
            assert_eq!(u64::from(stored) + 1, u64::from(next));
        }
        assert_eq!(uri_initial_counter(Kind::Totp, 0).unwrap(), 0);
        assert!(uri_initial_counter(Kind::Totp, 1).is_err());
    }

    #[test]
    fn invalid_import_fields_fail_before_device_access() {
        let access = AccessArgs {
            password: None,
            remember: false,
        };
        for (digits, counter, length, expected) in [
            (0, 0, 20, "digits"),
            (9, 0, 20, "digits"),
            (6, 1, 20, "counter"),
            (6, 0, 0, "secret"),
            (6, 0, 65, "secret"),
        ] {
            let error = add_credential(
                None,
                Some("nonexistent-audit-reader"),
                None,
                "audit",
                Kind::Totp,
                Algorithm::Sha1,
                digits,
                30,
                counter,
                Zeroizing::new(vec![1; length]),
                false,
                false,
                false,
                &access,
            )
            .unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
        }
    }
}

#[cfg(test)]
mod code_tests {
    use super::*;
    use canokey::compatibility::DeviceObservations;
    use oath::Code;

    fn entry(name: &[u8]) -> Entry {
        Entry {
            name: Name::from_bytes(name).unwrap(),
            algorithm_type: 0x21,
            digits: None,
        }
    }
    fn truncated(value: u32) -> oath::Calculation {
        oath::Calculation {
            name: None,
            digits: 6,
            code: Code::Truncated(SecretBytes::new(value.to_be_bytes().to_vec())),
        }
    }

    #[test]
    fn calculation_statuses_do_not_claim_a_wrong_password_or_a_definite_timeout() {
        let profile =
            DeviceProfile::from_observations(DeviceObservations::new(b"3.1.2".to_vec())).unwrap();
        for kind in [Kind::Totp, Kind::Hotp] {
            for status in [0x82, 0x85] {
                let mut command = vec![0, 0xa2, 0, 1, 6, 0x71, 4];
                command.extend(b"test");
                if kind == Kind::Totp {
                    command[4] = 16;
                    command.extend([0x74, 8, 0, 0, 0, 0, 0, 0, 0, 1]);
                }
                let mut script = [
                    (
                        vec![0, 0xa4, 4, 0, 7, 0xa0, 0, 0, 5, 0x27, 0x21, 1],
                        b"\x79\x03\x06\x00\x00\x71\x0812345678\x90\x00".to_vec(),
                    ),
                    (command, vec![0x69, status]),
                ]
                .into_iter();
                let error = oath::calculate(
                    &profile,
                    None,
                    oath::CredentialRef {
                        name: Name::from_bytes(b"test").unwrap(),
                        kind,
                        algorithm: Algorithm::Sha1,
                    },
                    (kind == Kind::Totp).then(|| 1u64.to_be_bytes()),
                    Format::Truncated,
                    &mut |command| {
                        let (expected, response) = script.next().expect("unexpected exchange");
                        assert_eq!(command, expected);
                        Ok::<_, io::Error>(response)
                    },
                )
                .unwrap_err();
                assert!(script.next().is_none());
                let message = describe_calculation(&error, kind);
                assert!(!message.contains("wrong password"), "{message}");
                assert!(!message.contains("requires authentication"), "{message}");
                assert!(message.contains("may have timed out"), "{message}");
                if kind == Kind::Totp && status == 0x82 {
                    assert!(message.contains("system clock"), "{message}");
                }
                if kind == Kind::Hotp && status == 0x85 {
                    assert!(message.contains("counter may be exhausted"), "{message}");
                }
                // Generic OATH operations must not label every 6985 as touch.
                if status == 0x85 {
                    assert!(!describe_oath(&error).contains("touch"));
                }
            }
        }
    }

    #[test]
    fn supplied_key_on_unprotected_applet_is_not_a_touch_timeout() {
        let profile =
            DeviceProfile::from_observations(DeviceObservations::new(b"3.1.2".to_vec())).unwrap();
        let access = Access {
            key: oath::access_key(&[0; 16]),
            challenge: [0; 8],
        };
        let mut exchanges = 0;
        let error = oath::validate(&profile, access, &mut |command| {
            exchanges += 1;
            assert_eq!(command, [0, 0xa4, 4, 0, 7, 0xa0, 0, 0, 5, 0x27, 0x21, 1]);
            Ok::<_, io::Error>(b"\x79\x03\x06\x00\x00\x71\x0812345678\x90\x00".to_vec())
        })
        .unwrap_err();
        assert_eq!(exchanges, 1, "no VALIDATE is sent to an unprotected applet");
        for message in [
            describe_oath(&error),
            describe_calculation(&error, Kind::Totp),
        ] {
            assert!(message.contains("no password set"), "{message}");
            assert!(!message.contains("touch"));
        }
    }

    #[test]
    fn completed_codes_are_flushed_before_later_calculations_and_survive_failure() {
        use std::cell::RefCell;
        use std::rc::Rc;

        struct SharedWriter(Rc<RefCell<Vec<u8>>>);
        impl io::Write for SharedWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.borrow_mut().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let bytes = Rc::new(RefCell::new(Vec::new()));
        // Buffering makes the test fail if results are written but not flushed
        // before the next operation waits for touch or fails.
        let mut output = io::BufWriter::with_capacity(4096, SharedWriter(bytes.clone()));
        let entries = [entry(b"beta"), entry(b"alpha")];
        let mut calls = 0;
        let error = write_account_codes(&[&entries[0], &entries[1]], false, &mut output, |entry| {
            calls += 1;
            if calls == 1 {
                assert_eq!(entry.name.as_bytes(), b"alpha");
                assert!(bytes.borrow().is_empty());
                Ok("123456".to_string())
            } else {
                assert_eq!(entry.name.as_bytes(), b"beta");
                assert_eq!(&*bytes.borrow(), b"alpha  123456\n");
                Err("device disconnected".into())
            }
        })
        .unwrap_err();
        assert_eq!(calls, 2);
        assert_eq!(&*bytes.borrow(), b"alpha  123456\n");
        assert!(error.to_string().contains("beta: device disconnected"));
    }

    #[test]
    fn output_failure_stops_before_the_next_device_operation() {
        struct FailedOutput {
            fail_write: bool,
        }
        impl io::Write for FailedOutput {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.fail_write {
                    Err(io::ErrorKind::BrokenPipe.into())
                } else {
                    Ok(bytes.len())
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
        }
        let entries = [entry(b"alpha"), entry(b"beta")];
        for fail_write in [true, false] {
            let mut output = FailedOutput { fail_write };
            let mut calculations = 0;
            let error =
                write_account_codes(&[&entries[0], &entries[1]], false, &mut output, |_| {
                    calculations += 1;
                    Ok("123456".to_string())
                })
                .unwrap_err();
            assert_eq!(
                calculations, 1,
                "do not calculate after write/flush failure"
            );
            assert_eq!(
                error.downcast_ref::<io::Error>().unwrap().kind(),
                io::ErrorKind::BrokenPipe
            );
        }
    }

    #[test]
    fn lossy_names_do_not_override_ambiguous_matches() {
        let entries = [entry(b"account\xff"), entry(b"account\xfe")];
        assert_eq!(search(&entries, "account\u{fffd}", true).len(), 2);
        assert_eq!(search(&entries, "account", true).len(), 2);

        // A real UTF-8 exact match still wins, even when an earlier invalid
        // name has the same display text.
        let entries = [entry(b"account\xff"), entry("account\u{fffd}".as_bytes())];
        let hits = search(&entries, "account\u{fffd}", true);
        assert_eq!(hits.len(), 1);
        assert!(std::ptr::eq(hits[0], &entries[1]));
    }

    #[test]
    fn single_account_needs_no_batch_result() {
        for name in ["test", "60/test", "Steam:alice"] {
            let mut calls = 0;
            let code = account_code(&entry(name.as_bytes()), true, |kind, period| {
                assert_eq!(kind, Kind::Totp);
                assert_eq!(period, if name.starts_with("60/") { 60 } else { 30 });
                calls += 1;
                Ok(truncated(1284755224))
            })
            .unwrap();
            assert_eq!(calls, 1);
            assert_eq!(
                code,
                if name.starts_with("Steam:") {
                    oath::steam_code(&truncated(1284755224)).unwrap()
                } else {
                    "755224".to_string()
                }
            );
        }
        let mut hotp = entry(b"counter");
        hotp.algorithm_type = 0x11;
        let mut calls = 0;
        assert_eq!(
            account_code(&hotp, true, |kind, period| {
                assert_eq!(kind, Kind::Hotp);
                assert_eq!(period, 0);
                calls += 1;
                Ok(truncated(1284755224))
            })
            .unwrap(),
            "755224"
        );
        assert_eq!(calls, 1);
        assert!(account_code(&entry(b"0/test"), true, |_, _| {
            panic!("invalid periods must fail before calculation")
        })
        .is_err());
    }

    #[test]
    fn sixty_second_totp_sends_its_own_time_step() {
        // RFC 4226 key "12345678901234567890": counter 0 => 755224,
        // counter 1 => 287082. At t=59, a 60-second account needs counter 0.
        let profile =
            DeviceProfile::from_observations(DeviceObservations::new(b"3.1.2".to_vec())).unwrap();
        let entry = entry(b"60/test");
        let mut command = vec![0, 0xa2, 0, 1, 19, 0x71, 7];
        command.extend(b"60/test");
        command.extend([0x74, 8, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut response = vec![0x76, 5, 6];
        response.extend(1284755224u32.to_be_bytes());
        response.extend([0x90, 0]);
        let mut script = [
            (
                vec![0, 0xa4, 4, 0, 7, 0xa0, 0, 0, 5, 0x27, 0x21, 1],
                b"\x79\x03\x06\x00\x00\x71\x0812345678\x90\x00".to_vec(),
            ),
            (command, response),
        ]
        .into_iter();
        let code = account_code(&entry, false, |kind, period| {
            oath::calculate(
                &profile,
                None,
                oath::CredentialRef {
                    name: Name::from_bytes(entry.name.as_bytes()).unwrap(),
                    kind,
                    algorithm: Algorithm::Sha1,
                },
                Some(oath::totp_challenge(59, period)),
                Format::Truncated,
                &mut |command| {
                    let (expected, response) = script.next().expect("unexpected exchange");
                    assert_eq!(command, expected);
                    Ok::<_, io::Error>(response)
                },
            )
            .map_err(|error| describe_oath(&error).into())
        })
        .unwrap();
        assert_eq!(code, "755224");
        assert!(script.next().is_none());
    }

    #[test]
    fn multiple_matches_calculate_each_totp_but_never_consume_hotp() {
        let mut hotp = entry(b"counter");
        hotp.algorithm_type = 0x11;
        assert_eq!(
            account_code(&hotp, false, |_, _| panic!("must not advance HOTP")).unwrap(),
            "[HOTP Account]"
        );
        for (name, period) in [("alice", 30), ("60/bob", 60), ("15/Steam:charlie", 15)] {
            let mut calls = 0;
            let result = truncated(1284755224);
            let code = account_code(&entry(name.as_bytes()), false, |kind, actual_period| {
                assert_eq!(kind, Kind::Totp);
                assert_eq!(actual_period, period);
                calls += 1;
                Ok(truncated(1284755224))
            })
            .unwrap();
            assert_eq!(calls, 1);
            assert_eq!(
                code,
                if name.contains("Steam:") {
                    oath::steam_code(&result).unwrap()
                } else {
                    "755224".to_string()
                }
            );
        }
        assert!(account_code(&entry(b"60/test"), false, |_, _| Err(
            "device disconnected".into()
        ))
        .unwrap_err()
        .to_string()
        .contains("disconnected"));
    }
}
