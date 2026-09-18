use super::{
    confirm, describe_drive_error, single_target, with_admin_pin_retry, CliResult, Target,
};
use ckman_core::admin::{self, Applet, Pin};
use ckman_core::oath::{self, Access, Algorithm, Code, Entry, Format, Kind, Name};
use ckman_core::oath::{OathError, Selected};
use ckman_core::uri;
use ckman_core::{DriveError, Exchange};
use ckman_transport::pcsc::Pcsc;

use canokey::{DeviceProfile, ErrorKind, SecretBytes, SecretReference};
use clap::{Args, Subcommand, ValueEnum};
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

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
        secret: Option<String>,
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
        /// Initial counter value for HOTP accounts.
        #[arg(short, long, default_value_t = 0)]
        counter: u32,
        /// Issuer of the account (optional).
        #[arg(short, long)]
        issuer: Option<String>,
        /// Number of seconds a TOTP code is valid.
        #[arg(short = 'P', long, default_value_t = 30)]
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
    Uri {
        /// The otpauth:// URI.
        uri: Option<String>,
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
    /// Generate codes from accounts, optionally filtered by a query.
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
    /// password is used first, then a remembered key, then a prompt. Mirrors
    /// the Python CLI's `_init_session`: a stale remembered key is forgotten
    /// and falls through to the prompt.
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
        let access = match &self.key {
            Some(key) => Some(oath::access_from_key(oath::access_key(key))?),
            None => None,
        };
        operation(&self.target.profile, access, &mut |command| {
            self.target.connection.exchange(command)
        })
        .map_err(|error| describe_oath(&error).into())
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
        match entry.set_password(&hex_encode(key)) {
            Ok(()) => println!("Password remembered."),
            Err(error) => eprintln!("Warning: could not store password in the keyring: {error}"),
        }
    }

    fn recall_key(&self) -> Option<Zeroizing<[u8; 16]>> {
        let entry = self.keyring_entry()?;
        let stored = entry.get_password().ok()?;
        let bytes = hex_decode(stored.trim())?;
        Some(Zeroizing::new(bytes.as_slice().try_into().ok()?))
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
            ErrorKind::ConditionsNotSatisfied => "touch timed out".to_string(),
            _ => describe_drive_error(&DriveError::Protocol(error.clone())),
        },
        OathError::Drive(drive) => describe_drive_error(drive),
    }
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
        Some(password) => zeroize::Zeroizing::new(password.to_string()),
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
        Some(password) => zeroize::Zeroizing::new(password.to_string()),
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
    secret: Option<String>,
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
            match uri::base32_decode(&entered) {
                Ok(secret) => break secret,
                Err(error) => println!("invalid base32 secret: {error}"),
            }
        },
        (Some(_), true) => unreachable!("--generate with SECRET rejected above"),
    });
    if secret.len() < 2 {
        return Err("secret must be at least 2 bytes".into());
    }
    if secret.len() > 64 {
        return Err("secret must be at most 64 bytes".into());
    }
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
    uri_arg: Option<String>,
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
            match uri::parse(&entered) {
                Ok(parsed) => break parsed,
                Err(error) => println!("{error}"),
            }
        },
    };
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
        parsed.counter,
        parsed.secret,
        false,
        touch,
        force,
        access,
    )
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

/// Search accounts like the Python CLI: an exact match wins; otherwise a
/// case-insensitive substring match. Hidden accounts are skipped unless asked.
fn search<'e>(entries: &'e [Entry], query: &str, show_hidden: bool) -> Vec<&'e Entry> {
    let mut hits = Vec::new();
    for entry in entries {
        let parsed = oath::parse_name(entry.name.as_bytes(), kind_of(entry).unwrap_or(Kind::Totp));
        if !show_hidden && parsed.issuer.as_deref() == Some("_hidden") {
            continue;
        }
        let id = display_name(entry);
        if id == query {
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
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch")?
        .as_secs();
    let calculations = session.run(|profile, access, exchange| {
        oath::calculate_all(
            profile,
            access,
            oath::totp_challenge(now, oath::DEFAULT_PERIOD),
            Format::Truncated,
            exchange,
        )
    })?;
    let entries = session.run(|profile, access, exchange| oath::list(profile, access, exchange))?;
    let hits = search(&entries, query, show_hidden);
    if hits.len() == 1 {
        let entry = hits[0];
        let kind = kind_of(entry).ok_or("unsupported credential type octet")?;
        let parsed = oath::parse_name(entry.name.as_bytes(), kind);
        let calculation = calculations.iter().find(|calculation| {
            calculation.name.as_ref().map(Name::as_bytes) == Some(entry.name.as_bytes())
        });
        let is_steam = kind == Kind::Totp && parsed.issuer.as_deref() == Some("Steam");
        let code: String = if is_steam {
            let calculation = calculate_one(&mut session, entry, kind, parsed.period, now, false)?;
            oath::steam_code(&calculation).ok_or("the credential did not produce a code")?
        } else {
            match calculation.map(|calculation| &calculation.code) {
                Some(Code::Truncated(_)) => decimal(calculation.unwrap())?,
                Some(Code::TouchRequired) => {
                    eprintln!("Touch your CanoKey...");
                    decimal(&calculate_one(
                        &mut session,
                        entry,
                        kind,
                        parsed.period,
                        now,
                        false,
                    )?)?
                }
                Some(Code::Hotp) => {
                    eprintln!("Touch your CanoKey if it flashes...");
                    decimal(&calculate_one(
                        &mut session,
                        entry,
                        kind,
                        parsed.period,
                        now,
                        false,
                    )?)?
                }
                Some(Code::Full(_)) => return Err("unexpected full-HMAC response".into()),
                None => return Err("the credential did not produce a code".into()),
            }
        };
        if single {
            println!("{code}");
        } else {
            println!("{}  {code}", display_name(entry));
        }
        return Ok(());
    }
    if single {
        return Err(if hits.is_empty() {
            "no matching account found".into()
        } else {
            multiple_hits(&hits)
        });
    }
    let mut rows: Vec<(String, String)> = Vec::new();
    for entry in hits {
        let kind = kind_of(entry);
        let parsed = oath::parse_name(entry.name.as_bytes(), kind.unwrap_or(Kind::Totp));
        let calculation = calculations.iter().find(|calculation| {
            calculation.name.as_ref().map(Name::as_bytes) == Some(entry.name.as_bytes())
        });
        let is_steam = kind == Some(Kind::Totp) && parsed.issuer.as_deref() == Some("Steam");
        let code = if is_steam {
            match calculate_one(&mut session, entry, Kind::Totp, parsed.period, now, false) {
                Ok(calculation) => oath::steam_code(&calculation).unwrap_or_default(),
                Err(_) => String::new(),
            }
        } else {
            match calculation.map(|calculation| &calculation.code) {
                Some(Code::Truncated(_)) => decimal(calculation.unwrap())?,
                Some(Code::TouchRequired) => "[Requires Touch]".to_string(),
                Some(Code::Hotp) => "[HOTP Account]".to_string(),
                _ => String::new(),
            }
        };
        rows.push((display_name(entry), code));
    }
    rows.sort_by_key(|(name, _)| name.to_lowercase());
    let longest_name = rows.iter().map(|(name, _)| name.len()).max().unwrap_or(0);
    let longest_code = rows.iter().map(|(_, code)| code.len()).max().unwrap_or(0);
    for (name, code) in rows {
        println!("{name:<longest_name$}  {code:>longest_code$}");
    }
    Ok(())
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
    let challenge = (kind == Kind::Totp).then(|| oath::totp_challenge(now, period.max(1)));
    let format = if full {
        Format::Full
    } else {
        Format::Truncated
    };
    session.run(|profile, access, exchange| {
        oath::calculate(profile, access, credential, challenge, format, exchange)
    })
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
