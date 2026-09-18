use super::{confirm, single_target, CliResult, Target};
use ckman_core::admin::{self, Applet};
use ckman_core::piv::{self, PivError};
use ckman_core::{keys, piv::Pin, piv::Puk};
use ckman_core::{x509, DriveError, Exchange};
use ckman_transport::pcsc::Pcsc;

use canokey::piv::{
    Algorithm, KeyParameters, ManagementKey, ManagementKeyAlgorithm, Metadata, MetadataReference,
    PinPolicy, PublicKey, Slot, TouchPolicy,
};
use canokey::{DeviceProfile, ErrorKind, SecretBytes, SecretReference};
use clap::{Args, Subcommand, ValueEnum};
use std::io::{self, Read, Write as _};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Subcommand)]
pub enum PivCommand {
    /// Display general status of the PIV application.
    Info,
    /// Reset the PIV application, deleting all keys, certificates and PINs.
    Reset {
        /// Do not ask for confirmation.
        #[arg(long)]
        force: bool,
        /// CanoKey Admin PIN (prompted when omitted).
        #[arg(long, value_name = "PIN", value_parser = crate::commands::secret_arg)]
        admin_pin: Option<crate::commands::SecretString>,
    },
    /// Manage PIV PIN, PUK and management key.
    Access {
        #[command(subcommand)]
        command: AccessCommand,
    },
    /// Manage PIV keys.
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },
    /// Manage PIV certificates.
    Certificates {
        #[command(subcommand)]
        command: CertificatesCommand,
    },
    /// Read and write arbitrary PIV data objects.
    Objects {
        #[command(subcommand)]
        command: ObjectsCommand,
    },
}

#[derive(Subcommand)]
pub enum AccessCommand {
    /// Set PIN/PUK retry limits, resetting both to the factory defaults.
    SetRetries {
        /// PIN retry count (1-15).
        #[arg(value_parser = clap::value_parser!(u8).range(1..=15))]
        pin_retries: u8,
        /// PUK retry count (1-15).
        #[arg(value_parser = clap::value_parser!(u8).range(1..=15))]
        puk_retries: u8,
        #[command(flatten)]
        mgmt: MgmtArgs,
        #[command(flatten)]
        pin: PinArgs,
        /// Do not ask for confirmation.
        #[arg(long)]
        force: bool,
    },
    /// Change the PIV PIN.
    ChangePin {
        /// Current PIN (prompted when omitted).
        #[arg(short = 'P', long, value_parser = crate::commands::secret_arg)]
        pin: Option<crate::commands::SecretString>,
        /// New PIN (prompted when omitted).
        #[arg(short, long, value_parser = crate::commands::secret_arg)]
        new_pin: Option<crate::commands::SecretString>,
    },
    /// Change the PUK.
    ChangePuk {
        /// Current PUK (prompted when omitted).
        #[arg(short, long, value_parser = crate::commands::secret_arg)]
        puk: Option<crate::commands::SecretString>,
        /// New PUK (prompted when omitted).
        #[arg(short = 'n', long, value_parser = crate::commands::secret_arg)]
        new_puk: Option<crate::commands::SecretString>,
    },
    /// Change the management key.
    ChangeManagementKey {
        /// Require touch when authenticating with the management key (AES-192 only).
        #[arg(short, long)]
        touch: bool,
        /// New management key as 48 hex characters (prompted when omitted).
        #[arg(short = 'n', long, value_parser = crate::commands::secret_arg)]
        new_management_key: Option<crate::commands::SecretString>,
        /// Management key algorithm (default: the card's current algorithm).
        #[arg(short, long, value_enum)]
        algorithm: Option<MgmtAlgorithmArg>,
        /// Store the new management key on the CanoKey, protected by PIN.
        #[arg(short = 'p', long)]
        protect: bool,
        /// Generate a random management key.
        #[arg(short, long)]
        generate: bool,
        /// Do not prompt; requires --generate or --new-management-key.
        #[arg(long)]
        force: bool,
        #[command(flatten)]
        mgmt: MgmtArgs,
        #[command(flatten)]
        pin: PinArgs,
    },
    /// Unblock and set a new PIN using the PUK.
    UnblockPin {
        /// Current PUK (prompted when omitted).
        #[arg(short, long, value_parser = crate::commands::secret_arg)]
        puk: Option<crate::commands::SecretString>,
        /// New PIN (prompted when omitted).
        #[arg(short = 'n', long, value_parser = crate::commands::secret_arg)]
        new_pin: Option<crate::commands::SecretString>,
    },
}

#[derive(Subcommand)]
pub enum KeysCommand {
    /// Generate an asymmetric key pair on the device.
    Generate {
        /// PIV slot (9a, 9c, 9d, 9e, or retired 82-95).
        #[arg(value_parser = parse_slot)]
        slot: Slot,
        /// File to write the public key to ('-' for stdout).
        public_key_output: String,
        /// Algorithm to use in key generation.
        #[arg(short, long, value_enum, default_value_t = KeyAlgorithmArg::Rsa2048)]
        algorithm: KeyAlgorithmArg,
        /// PIN policy for the key.
        #[arg(long, value_enum)]
        pin_policy: Option<PinPolicyArg>,
        /// Touch policy for the key.
        #[arg(long, value_enum)]
        touch_policy: Option<TouchPolicyArg>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = EncodingArg::Pem)]
        format: EncodingArg,
        #[command(flatten)]
        mgmt: MgmtArgs,
    },
    /// Import a private key from a PEM/DER file (PKCS#8, PKCS#1, SEC1).
    Import {
        /// PIV slot.
        #[arg(value_parser = parse_slot)]
        slot: Slot,
        /// File containing the private key ('-' for stdin).
        private_key: String,
        /// Password used to decrypt the private key.
        #[arg(short, long, value_parser = crate::commands::secret_arg)]
        password: Option<crate::commands::SecretString>,
        /// PIN policy for the key.
        #[arg(long, value_enum)]
        pin_policy: Option<PinPolicyArg>,
        /// Touch policy for the key.
        #[arg(long, value_enum)]
        touch_policy: Option<TouchPolicyArg>,
        #[command(flatten)]
        mgmt: MgmtArgs,
    },
    /// Write a device-generated attestation certificate for a slot.
    Attest {
        /// PIV slot.
        #[arg(value_parser = parse_slot)]
        slot: Slot,
        /// File to write the certificate to ('-' for stdout).
        certificate: String,
        /// Output format.
        #[arg(long, value_enum, default_value_t = EncodingArg::Pem)]
        format: EncodingArg,
    },
    /// Show metadata about the key in a slot.
    Info {
        /// PIV slot.
        #[arg(value_parser = parse_slot)]
        slot: Slot,
    },
    /// Export the public key of a slot.
    Export {
        /// PIV slot.
        #[arg(value_parser = parse_slot)]
        slot: Slot,
        /// File to write the public key to ('-' for stdout).
        public_key_output: String,
        /// Output format.
        #[arg(long, value_enum, default_value_t = EncodingArg::Pem)]
        format: EncodingArg,
        /// Verify that the private key matches by a test signature (needs PIN).
        #[arg(long)]
        verify: bool,
        #[command(flatten)]
        pin: PinArgs,
    },
    /// Move a key from one slot to another (certificate stays in place).
    Move {
        /// Source slot.
        #[arg(value_parser = parse_slot)]
        source: Slot,
        /// Destination slot.
        #[arg(value_parser = parse_slot)]
        dest: Slot,
        #[command(flatten)]
        mgmt: MgmtArgs,
    },
    /// Delete the key in a slot (the certificate is retained).
    Delete {
        /// PIV slot.
        #[arg(value_parser = parse_slot)]
        slot: Slot,
        #[command(flatten)]
        mgmt: MgmtArgs,
    },
}

#[derive(Subcommand)]
pub enum CertificatesCommand {
    /// Import a certificate (PEM/DER) into a slot.
    Import {
        /// PIV slot.
        #[arg(value_parser = parse_slot)]
        slot: Slot,
        /// File containing the certificate ('-' for stdin).
        certificate: String,
        #[command(flatten)]
        mgmt: MgmtArgs,
    },
    /// Export the certificate stored in a slot.
    Export {
        /// PIV slot.
        #[arg(value_parser = parse_slot)]
        slot: Slot,
        /// File to write the certificate to ('-' for stdout).
        certificate: String,
        /// Output format.
        #[arg(long, value_enum, default_value_t = EncodingArg::Pem)]
        format: EncodingArg,
    },
    /// Generate a self-signed certificate, signed by the key in the slot.
    Generate {
        /// PIV slot.
        #[arg(value_parser = parse_slot)]
        slot: Slot,
        /// File containing the public key (PEM/DER); defaults to the slot's own key.
        public_key: Option<String>,
        /// Subject for the certificate, as an RFC 4514 string.
        #[arg(short, long)]
        subject: String,
        /// Number of days until the certificate expires.
        #[arg(short, long, default_value_t = 365)]
        valid_days: u32,
        /// Hash algorithm used for the signature.
        #[arg(long, value_enum, default_value_t = HashArg::Sha256)]
        hash: HashArg,
        #[command(flatten)]
        mgmt: MgmtArgs,
        #[command(flatten)]
        pin: PinArgs,
    },
    /// Generate a Certificate Signing Request (CSR).
    Request {
        /// PIV slot.
        #[arg(value_parser = parse_slot)]
        slot: Slot,
        /// File containing the public key (PEM/DER, '-' for stdin).
        public_key: String,
        /// File to write the CSR to ('-' for stdout).
        csr_output: String,
        /// Subject for the requested certificate, as an RFC 4514 string.
        #[arg(short, long)]
        subject: String,
        /// Hash algorithm used for the signature.
        #[arg(long, value_enum, default_value_t = HashArg::Sha256)]
        hash: HashArg,
        #[command(flatten)]
        pin: PinArgs,
    },
    /// Delete the certificate in a slot (the key is retained).
    Delete {
        /// PIV slot.
        #[arg(value_parser = parse_slot)]
        slot: Slot,
        #[command(flatten)]
        mgmt: MgmtArgs,
    },
}

#[derive(Subcommand)]
pub enum ObjectsCommand {
    /// Read an arbitrary PIV object.
    Export {
        /// Object ID as hex (e.g. 5f0000 or 5fc105).
        #[arg(value_parser = parse_object_id)]
        object_id: canokey::piv::ObjectId,
        /// File to write the object value to ('-' for stdout).
        output: String,
        #[command(flatten)]
        pin: PinArgs,
    },
    /// Write an arbitrary PIV object value (without the outer 53 container).
    Import {
        /// Object ID as hex (e.g. 5f0000 or 5fc105).
        #[arg(value_parser = parse_object_id)]
        object_id: canokey::piv::ObjectId,
        /// File containing the object value ('-' for stdin).
        data: String,
        #[command(flatten)]
        mgmt: MgmtArgs,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum MgmtAlgorithmArg {
    Tdes,
    Aes192,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum KeyAlgorithmArg {
    Rsa1024,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EccP256,
    EccP384,
    EccP521,
    Secp256k1,
    Sm2,
    Ed25519,
    X25519,
    MlDsa65,
    MlKem768,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum PinPolicyArg {
    Never,
    Once,
    Always,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum TouchPolicyArg {
    Never,
    Always,
    Cached,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum EncodingArg {
    Pem,
    Der,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum HashArg {
    Sha256,
    Sha384,
    Sha512,
}

/// Current-management-key argument.
#[derive(Args)]
pub struct MgmtArgs {
    /// Current management key as 48 hex characters (prompted when needed).
    #[arg(short, long, value_parser = crate::commands::secret_arg)]
    management_key: Option<crate::commands::SecretString>,
}

/// PIN argument for commands that verify the PIN.
#[derive(Args)]
pub struct PinArgs {
    /// PIN code (prompted when needed).
    #[arg(short = 'P', long, value_parser = crate::commands::secret_arg)]
    pin: Option<crate::commands::SecretString>,
}

pub fn run(device: Option<u32>, reader: Option<&str>, command: &PivCommand) -> CliResult<()> {
    match command {
        PivCommand::Info => info(device, reader),
        PivCommand::Reset { force, admin_pin } => {
            reset(device, reader, *force, super::secret_str(admin_pin))
        }
        PivCommand::Access { command } => access(device, reader, command),
        PivCommand::Keys { command } => keys(device, reader, command),
        PivCommand::Certificates { command } => certificates(device, reader, command),
        PivCommand::Objects { command } => objects(device, reader, command),
    }
}

// --- shared plumbing ---------------------------------------------------------

fn parse_slot(text: &str) -> Result<Slot, String> {
    match text.to_ascii_lowercase().as_str() {
        "9a" => Ok(Slot::Authentication),
        "9c" => Ok(Slot::Signature),
        "9d" => Ok(Slot::KeyManagement),
        "9e" => Ok(Slot::CardAuthentication),
        other => {
            let reference =
                u8::from_str_radix(other, 16).map_err(|_| "invalid slot".to_string())?;
            if (0x82..=0x95).contains(&reference) {
                piv::RetiredSlot::new(reference - 0x81)
                    .map(Slot::Retired)
                    .map_err(|_| "invalid slot".to_string())
            } else {
                Err("invalid slot (expected 9a, 9c, 9d, 9e, or 82-95)".to_string())
            }
        }
    }
}

fn parse_object_id(text: &str) -> Result<canokey::piv::ObjectId, String> {
    let bytes = hex_decode(text).ok_or_else(|| "invalid hex object id".to_string())?;
    canokey::piv::ObjectId::from_bytes(&bytes).map_err(|_| "invalid object id".to_string())
}

fn slot_name(slot: Slot) -> String {
    format!("{:02x}", slot.reference())
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

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn read_input(path: &str) -> CliResult<Vec<u8>> {
    if path == "-" {
        let mut data = Vec::new();
        std::io::stdin().read_to_end(&mut data)?;
        Ok(data)
    } else {
        Ok(std::fs::read(path)?)
    }
}

fn write_output(path: &str, data: &[u8]) -> CliResult<()> {
    if path == "-" {
        std::io::stdout().write_all(data)?;
    } else {
        std::fs::write(path, data)?;
    }
    Ok(())
}

fn describe_piv(error: &PivError<io::Error>) -> String {
    match error {
        PivError::Random(error) => format!("failed to generate randomness: {error}"),
        PivError::X509(error) => format!("{error}"),
        PivError::Key(error) => format!("{error}"),
        PivError::Drive(DriveError::Transport(error)) => {
            format!("transport exchange failed: {error}")
        }
        PivError::Drive(DriveError::Protocol(error)) => match error.kind {
            ErrorKind::AuthenticationFailed => match error.reference {
                Some(SecretReference::Pin) => match error.retries_remaining {
                    Some(retries) => format!("incorrect PIN ({retries} attempts remaining)"),
                    None => "incorrect PIN".to_string(),
                },
                Some(SecretReference::Puk) => match error.retries_remaining {
                    Some(retries) => format!("incorrect PUK ({retries} attempts remaining)"),
                    None => "incorrect PUK".to_string(),
                },
                Some(SecretReference::ManagementKey) => "incorrect management key".to_string(),
                _ => "authentication failed".to_string(),
            },
            ErrorKind::PinBlocked => match error.reference {
                Some(SecretReference::Puk) => "the PUK is blocked".to_string(),
                _ => "the PIN is blocked".to_string(),
            },
            ErrorKind::NotFound => "not found on the device".to_string(),
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

/// The resolved management key (and the PIN when it unlocked the key).
/// Every operation builds a fresh mutual authentication from the key:
/// libcanokey forbids reusing a cloned mutual request across executions,
/// because it would replay the same challenge.
struct ResolvedManagement {
    key: ManagementKey,
    pin: Option<Pin>,
}

impl ResolvedManagement {
    /// A fresh mutual authentication; the getrandom failure converts into
    /// the caller's `PivError::Random` inside operation closures.
    fn access(&self) -> Result<piv::Access, getrandom::Error> {
        Ok(piv::Access::Management(piv::mutual_auth(self.key.clone())?))
    }

    fn pin_and_management(&self, pin: Pin) -> Result<piv::Access, getrandom::Error> {
        Ok(piv::Access::PinAndManagement {
            pin,
            management: piv::mutual_auth(self.key.clone())?,
        })
    }
}

/// True for the typed "this firmware cannot answer" errors that license a
/// legacy fallback; transport and protocol failures are not gates.
fn is_capability_gate(error: &PivError<io::Error>) -> bool {
    matches!(
        error,
        PivError::Drive(DriveError::Protocol(error))
            if matches!(
                error.kind,
                ErrorKind::UnsupportedFeature | ErrorKind::CapabilityUnknown
            )
    )
}

/// A connected PIV target with credential resolution helpers.
struct PivSession {
    target: Target,
}

impl PivSession {
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
        ) -> Result<T, PivError<io::Error>>,
    ) -> CliResult<T> {
        self.run_typed(operation)
            .map_err(|error| describe_piv(&error).into())
    }

    /// Run an operation, keeping the typed error for capability inspection.
    fn run_typed<T>(
        &mut self,
        operation: impl FnOnce(
            &DeviceProfile,
            &mut Exchange<'_, io::Error>,
        ) -> Result<T, PivError<io::Error>>,
    ) -> Result<T, PivError<io::Error>> {
        operation(&self.target.profile, &mut |command| {
            self.target.connection.exchange(command)
        })
    }

    /// Resolve the management-key authentication like the Python CLI's
    /// `_authenticate`: an explicit `-m` hex key wins; then a PIN-protected
    /// stored key; then a PIN-derived key; otherwise prompt, with a blank
    /// answer meaning the factory default. Warns when the default key is in
    /// use. Yields the key (and the PIN when it was needed); each operation
    /// builds a fresh mutual authentication from it — libcanokey forbids
    /// reusing a cloned mutual request, since it would replay the challenge.
    fn resolve_management(
        &mut self,
        management_key: Option<&str>,
        pin: Option<&str>,
    ) -> CliResult<ResolvedManagement> {
        if let Some(hex) = management_key {
            let bytes = hex_decode(hex).ok_or("management key must be hex-encoded")?;
            let algorithm = self.management_algorithm()?;
            let key = ManagementKey::from_bytes(algorithm, &bytes)
                .map_err(|_| "management key must be 24 bytes (48 hex characters)")?;
            return Ok(ResolvedManagement { key, pin: None });
        }
        let pivman = self.run(|profile, exchange| piv::read_pivman_data(profile, exchange))?;
        if pivman.has_stored_key() {
            let pin = self.resolve_pin(pin, "Enter PIN (to unlock the stored management key)")?;
            let key_bytes =
                self.run(|profile, exchange| piv::pin_managed_key(profile, pin.clone(), exchange))?;
            let algorithm = self.management_algorithm()?;
            let key = ManagementKey::from_bytes(algorithm, key_bytes.as_bytes())
                .map_err(|_| "stored management key has an unexpected length")?;
            return Ok(ResolvedManagement {
                key,
                pin: Some(pin),
            });
        }
        if pivman.has_derived_key() {
            let pin =
                self.resolve_pin_string(pin, "Enter PIN (the management key is derived from it)")?;
            let salt = pivman.salt.expect("derived key has a salt");
            let key = ManagementKey::from_bytes(
                ManagementKeyAlgorithm::Tdes,
                piv::derive_management_key(pin.as_bytes(), &salt).as_slice(),
            )
            .map_err(|_| "derived management key is invalid")?;
            let pin = Pin::from_bytes(pin.as_bytes()).map_err(|_| "PIN must be 6-8 characters")?;
            return Ok(ResolvedManagement {
                key,
                pin: Some(pin),
            });
        }
        let entered =
            super::prompt_password("Enter the management key [blank to use default key]: ")?;
        let (key, default) = if entered.is_empty() {
            (piv::default_management_key(), true)
        } else {
            let bytes = hex_decode(&entered).ok_or("management key must be hex-encoded")?;
            let algorithm = self.management_algorithm()?;
            (
                ManagementKey::from_bytes(algorithm, &bytes)
                    .map_err(|_| "management key must be 24 bytes (48 hex characters)")?,
                false,
            )
        };
        if default || self.management_is_default()?.unwrap_or(false) {
            eprintln!("WARNING: Using default Management key!");
        }
        Ok(ResolvedManagement { key, pin: None })
    }

    /// The card's management-key algorithm from metadata, defaulting to TDES
    /// only when the metadata command is missing (legacy firmware); transport
    /// and protocol failures propagate.
    fn management_algorithm(&mut self) -> CliResult<ManagementKeyAlgorithm> {
        match self.run_typed(|profile, exchange| {
            piv::metadata(
                profile,
                MetadataReference::Management,
                canokey::piv::Access::None,
                exchange,
            )
        }) {
            Ok(metadata) => match metadata.fields().algorithm_id {
                Some(3) => Ok(ManagementKeyAlgorithm::Tdes),
                Some(10) => Ok(ManagementKeyAlgorithm::Aes192),
                _ => Err("unknown management key algorithm on the card".into()),
            },
            Err(error) if is_capability_gate(&error) => Ok(ManagementKeyAlgorithm::Tdes),
            Err(error) => Err(describe_piv(&error).into()),
        }
    }

    /// Ok(None) when the metadata command is unavailable (legacy firmware);
    /// transport and protocol failures propagate so the default-key warning
    /// is never suppressed by a flaky read.
    fn management_is_default(&mut self) -> CliResult<Option<bool>> {
        match self.run_typed(|profile, exchange| {
            piv::metadata(
                profile,
                MetadataReference::Management,
                canokey::piv::Access::None,
                exchange,
            )
        }) {
            Ok(metadata) => Ok(match metadata.fields().is_default {
                Some(piv::KnownOrUnknown::Known(value)) => Some(value),
                _ => None,
            }),
            Err(error) if is_capability_gate(&error) => Ok(None),
            Err(error) => Err(describe_piv(&error).into()),
        }
    }

    fn resolve_pin_string(
        &mut self,
        pin: Option<&str>,
        prompt: &str,
    ) -> CliResult<super::SecretString> {
        match pin {
            Some(pin) => Ok(zeroize::Zeroizing::new(pin.to_string())),
            None => Ok(super::prompt_password(&format!("{prompt}: "))?),
        }
    }

    fn resolve_pin(&mut self, pin: Option<&str>, prompt: &str) -> CliResult<Pin> {
        let pin = self.resolve_pin_string(pin, prompt)?;
        Pin::from_bytes(pin.as_bytes()).map_err(|_| "PIN must be 6-8 characters".into())
    }

    fn resolve_puk(&mut self, puk: Option<&str>) -> CliResult<Puk> {
        let puk = match puk {
            Some(puk) => zeroize::Zeroizing::new(puk.to_string()),
            None => super::prompt_password("Enter PUK: ")?,
        };
        Puk::from_bytes(puk.as_bytes()).map_err(|_| "PUK must be 6-8 characters".into())
    }
}

fn pin_policy_of(arg: Option<PinPolicyArg>) -> PinPolicy {
    match arg {
        None => PinPolicy::Default,
        Some(PinPolicyArg::Never) => PinPolicy::Never,
        Some(PinPolicyArg::Once) => PinPolicy::Once,
        Some(PinPolicyArg::Always) => PinPolicy::Always,
    }
}

fn touch_policy_of(arg: Option<TouchPolicyArg>) -> TouchPolicy {
    match arg {
        None => TouchPolicy::Default,
        Some(TouchPolicyArg::Never) => TouchPolicy::Never,
        Some(TouchPolicyArg::Always) => TouchPolicy::Always,
        Some(TouchPolicyArg::Cached) => TouchPolicy::Cached,
    }
}

fn key_algorithm(arg: KeyAlgorithmArg) -> Algorithm {
    match arg {
        KeyAlgorithmArg::Rsa1024 => Algorithm::Rsa1024,
        KeyAlgorithmArg::Rsa2048 => Algorithm::Rsa2048,
        KeyAlgorithmArg::Rsa3072 => Algorithm::Rsa3072,
        KeyAlgorithmArg::Rsa4096 => Algorithm::Rsa4096,
        KeyAlgorithmArg::EccP256 => Algorithm::EccP256,
        KeyAlgorithmArg::EccP384 => Algorithm::EccP384,
        KeyAlgorithmArg::EccP521 => Algorithm::EccP521,
        KeyAlgorithmArg::Secp256k1 => Algorithm::Secp256k1,
        KeyAlgorithmArg::Sm2 => Algorithm::Sm2,
        KeyAlgorithmArg::Ed25519 => Algorithm::Ed25519,
        KeyAlgorithmArg::X25519 => Algorithm::X25519,
        KeyAlgorithmArg::MlDsa65 => Algorithm::MlDsa65,
        KeyAlgorithmArg::MlKem768 => Algorithm::MlKem768,
    }
}

fn hash_algorithm(arg: HashArg) -> x509::HashAlgorithm {
    match arg {
        HashArg::Sha256 => x509::HashAlgorithm::Sha256,
        HashArg::Sha384 => x509::HashAlgorithm::Sha384,
        HashArg::Sha512 => x509::HashAlgorithm::Sha512,
    }
}

// --- commands ------------------------------------------------------------------

fn info(device: Option<u32>, reader: Option<&str>) -> CliResult<()> {
    let mut session = PivSession::connect(device, reader)?;
    let version = session
        .profile()
        .info()
        .piv_version()
        .map(|v| format!("{}.{}.{}", v.0[0], v.0[1], v.0[2]))
        .unwrap_or_else(|| "unknown".to_string());
    println!("PIV version:            {version}");

    // GET METADATA exists only on 2.0+; on legacy firmware fall back to the
    // baseline empty-VERIFY for the PIN counter (like the Python CLI) and
    // skip the PUK/management records.
    let pin_meta = session.run(|profile, exchange| {
        piv::metadata(
            profile,
            MetadataReference::Pin,
            canokey::piv::Access::None,
            exchange,
        )
    });
    match pin_meta {
        Ok(metadata) => {
            let fields = metadata.fields();
            if fields.is_default == Some(piv::KnownOrUnknown::Known(true)) {
                println!("WARNING: Using default PIN!");
            }
            if let Some((total, remaining)) = fields.retries {
                println!("PIN tries remaining:    {remaining}/{total}");
            }
        }
        Err(_) => {
            let status = session.run(|profile, exchange| piv::pin_status(profile, exchange))?;
            if let Some(remaining) = status.retries_remaining {
                let text = if remaining == 15 {
                    "15 or more".to_string()
                } else {
                    remaining.to_string()
                };
                println!("PIN tries remaining:    {text}");
            }
        }
    }
    let puk_meta = session.run(|profile, exchange| {
        piv::metadata(
            profile,
            MetadataReference::Puk,
            canokey::piv::Access::None,
            exchange,
        )
    });
    if let Ok(puk_meta) = &puk_meta {
        let fields = puk_meta.fields();
        if let Some((total, remaining)) = fields.retries {
            if remaining == 0 {
                println!("PUK is blocked");
            } else if fields.is_default == Some(piv::KnownOrUnknown::Known(true)) {
                println!("WARNING: Using default PUK!");
            }
            println!("PUK tries remaining:    {remaining}/{total}");
        }
    }
    let mgmt_meta = session.run(|profile, exchange| {
        piv::metadata(
            profile,
            MetadataReference::Management,
            canokey::piv::Access::None,
            exchange,
        )
    });
    let algorithm = match &mgmt_meta {
        Ok(metadata) => {
            let fields = metadata.fields();
            if fields.is_default == Some(piv::KnownOrUnknown::Known(true)) {
                println!("WARNING: Using default Management key!");
            }
            match fields.algorithm_id {
                Some(3) => "TDES",
                Some(10) => "AES192",
                other => return Err(format!("unknown management key algorithm {other:?}").into()),
            }
        }
        // No metadata on legacy firmware: the management key is 3DES there.
        Err(_) => "TDES",
    };
    println!("Management key algorithm: {algorithm}");

    let pivman = session.run(|profile, exchange| piv::read_pivman_data(profile, exchange))?;
    if puk_meta.is_err() && pivman.puk_blocked() {
        println!("PUK is blocked");
    }
    if pivman.has_derived_key() {
        println!("Management key is derived from PIN.");
    }
    if pivman.has_stored_key() {
        println!("Management key is stored on the CanoKey, protected by PIN.");
    }

    // CHUID/CCC objects.
    for (name, id) in [("CHUID", [0x5f, 0xc1, 2]), ("CCC", [0x5f, 0xc1, 7])] {
        let id = canokey::piv::ObjectId::from_bytes(&id)?;
        match session.run(|profile, exchange| {
            piv::read_object(profile, id, canokey::piv::Access::None, exchange)
        }) {
            Ok(data) => println!("{name}:                   {} bytes", data.as_bytes().len()),
            Err(_) => println!("{name}:                   No data available."),
        }
    }

    // Per-slot key and certificate state.
    let mut slots = vec![
        Slot::Authentication,
        Slot::Signature,
        Slot::KeyManagement,
        Slot::CardAuthentication,
    ];
    slots.extend((1..=20).map(|i| Slot::Retired(piv::RetiredSlot::new(i).unwrap())));
    for slot in slots {
        let key = session
            .run(|profile, exchange| {
                piv::metadata(
                    profile,
                    MetadataReference::Key(slot),
                    canokey::piv::Access::None,
                    exchange,
                )
            })
            .ok();
        let certificate = session
            .run(|profile, exchange| {
                piv::read_certificate(profile, slot, canokey::piv::Access::None, exchange)
            })
            .ok();
        if key.is_none() && certificate.is_none() {
            continue;
        }
        println!("Slot {:>4}:", slot_name(slot));
        match &key {
            Some(Metadata::Key { fields, .. }) => {
                let algorithm = fields
                    .algorithm_id
                    .and_then(|id| session_algorithm_name(session.profile(), id))
                    .unwrap_or("unknown");
                println!("  Private key type: {algorithm}");
                if let Some(origin) = &fields.origin {
                    let origin = match origin {
                        piv::KnownOrUnknown::Known(piv::KeyOrigin::Generated) => {
                            "generated on device".to_string()
                        }
                        piv::KnownOrUnknown::Known(piv::KeyOrigin::Imported) => {
                            "imported".to_string()
                        }
                        piv::KnownOrUnknown::Known(piv::KeyOrigin::NotPresent) => {
                            "none".to_string()
                        }
                        piv::KnownOrUnknown::Unknown(value) => format!("unknown ({value})"),
                    };
                    println!("  Origin:             {origin}");
                }
                if let Some(piv::KnownOrUnknown::Known(policy)) = fields.pin_policy {
                    println!("  PIN policy:         {policy:?}");
                }
                if let Some(piv::KnownOrUnknown::Known(policy)) = fields.touch_policy {
                    println!("  Touch policy:       {policy:?}");
                }
            }
            _ => println!("  Private key type: EMPTY"),
        }
        if let Some(certificate) = &certificate {
            match canokey::x509::parse_der(certificate.der(), Default::default()) {
                Ok(info) => {
                    println!("  Subject DN:         {}", info.subject.display);
                    println!("  Issuer DN:          {}", info.issuer.display);
                    println!("  Serial:             {}", hex_encode(&info.serial_number));
                    println!(
                        "  Fingerprint (SHA-256): {}",
                        hex_encode(&info.sha256_fingerprint())
                    );
                    println!("  Not before:         {}", info.validity.not_before_unix);
                    println!("  Not after:          {}", info.validity.not_after_unix);
                }
                Err(_) => println!("  Error: failed to parse certificate"),
            }
        }
    }
    Ok(())
}

fn session_algorithm_name(profile: &DeviceProfile, id: u8) -> Option<&'static str> {
    let algorithm = profile.algorithm_from_wire_id(id)?;
    Some(match algorithm {
        Algorithm::Rsa1024 => "RSA1024",
        Algorithm::Rsa2048 => "RSA2048",
        Algorithm::Rsa3072 => "RSA3072",
        Algorithm::Rsa4096 => "RSA4096",
        Algorithm::EccP256 => "ECCP256",
        Algorithm::EccP384 => "ECCP384",
        Algorithm::EccP521 => "ECCP521",
        Algorithm::Secp256k1 => "SECP256K1",
        Algorithm::Sm2 => "SM2",
        Algorithm::Ed25519 => "ED25519",
        Algorithm::X25519 => "X25519",
        Algorithm::MlDsa65 => "ML-DSA-65",
        Algorithm::MlKem768 => "ML-KEM-768",
    })
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
        && !confirm("This will delete all stored PIV data and restore factory settings. Proceed?")?
    {
        return Err("PIV reset aborted".into());
    }
    let pin = admin_pin
        .map(|pin| admin::Pin::from_bytes(pin.as_bytes()).map_err(|error| format!("{error}")))
        .transpose()?;
    super::with_admin_pin_retry(pin, |pin| {
        admin::reset_applet(&target.profile, Applet::Piv, pin, &mut |command| {
            target.connection.exchange(command)
        })
    })?;
    println!("Reset complete. All PIV data has been cleared from the CanoKey.");
    println!("Your CanoKey now has the default PIN, PUK and Management Key:");
    println!("\tPIN:\t123456");
    println!("\tPUK:\t12345678");
    println!(
        "\tManagement Key:\t{}",
        hex_encode(&piv::DEFAULT_MANAGEMENT_KEY)
    );
    Ok(())
}

fn access(device: Option<u32>, reader: Option<&str>, command: &AccessCommand) -> CliResult<()> {
    match command {
        AccessCommand::SetRetries {
            pin_retries,
            puk_retries,
            mgmt,
            pin,
            force,
        } => {
            let mut session = PivSession::connect(device, reader)?;
            if !force
                && !confirm(
                    "This sets the retry counters and resets PIN and PUK to the factory defaults (123456 / 12345678). Proceed?",
                )?
            {
                return Err("aborted".into());
            }
            let management = session.resolve_management(
                super::secret_str(&mgmt.management_key),
                super::secret_str(&pin.pin),
            )?;
            let pin = match &management.pin {
                Some(pin) => pin.clone(),
                None => {
                    session.resolve_pin(super::secret_str(&pin.pin), "Enter the current PIN")?
                }
            };
            session.run(|profile, exchange| {
                piv::set_retries(
                    profile,
                    *pin_retries,
                    *puk_retries,
                    management.pin_and_management(pin)?,
                    exchange,
                )
            })?;
            // pivman: clear the PUK-blocked claim.
            let mut pivman =
                session.run(|profile, exchange| piv::read_pivman_data(profile, exchange))?;
            if pivman.puk_blocked() {
                pivman.set_puk_blocked(false);
                let management =
                    session.resolve_management(super::secret_str(&mgmt.management_key), None)?;
                session.run(|profile, exchange| {
                    piv::write_object(
                        profile,
                        piv::pivman_object_id(),
                        SecretBytes::new(pivman.to_value()),
                        management.access()?,
                        exchange,
                    )
                })?;
            }
            println!("PIN and PUK retry counters reset; both are now at factory defaults.");
            Ok(())
        }
        AccessCommand::ChangePin { pin, new_pin } => {
            let mut session = PivSession::connect(device, reader)?;
            let old = match pin {
                Some(pin) => pin.clone(),
                None => super::prompt_password("Enter current PIN: ")?,
            };
            let new = match new_pin {
                Some(pin) => pin.clone(),
                None => {
                    let entered = super::prompt_password("Enter new PIN: ")?;
                    let repeated = super::prompt_password("Repeat new PIN: ")?;
                    if entered != repeated {
                        return Err("the PINs do not match".into());
                    }
                    entered
                }
            };
            session.run(|profile, exchange| {
                piv::change_pin_synced(profile, old.as_bytes(), new.as_bytes(), exchange)
            })?;
            println!("PIN changed.");
            Ok(())
        }
        AccessCommand::ChangePuk { puk, new_puk } => {
            let mut session = PivSession::connect(device, reader)?;
            let old = session.resolve_puk(super::secret_str(puk))?;
            let new = match new_puk {
                Some(puk) => {
                    Puk::from_bytes(puk.as_bytes()).map_err(|_| "PUK must be 6-8 characters")?
                }
                None => {
                    let entered = super::prompt_password("Enter new PUK: ")?;
                    let repeated = super::prompt_password("Repeat new PUK: ")?;
                    if entered != repeated {
                        return Err("the PUKs do not match".into());
                    }
                    Puk::from_bytes(entered.as_bytes()).map_err(|_| "PUK must be 6-8 characters")?
                }
            };
            session.run(|profile, exchange| piv::change_puk(profile, old, new, exchange))?;
            println!("PUK changed.");
            Ok(())
        }
        AccessCommand::ChangeManagementKey {
            touch,
            new_management_key,
            algorithm,
            protect,
            generate,
            force,
            mgmt,
            pin,
        } => {
            if new_management_key.is_some() && *generate {
                return Err("--new-management-key conflicts with --generate".into());
            }
            let mut session = PivSession::connect(device, reader)?;
            let algorithm = match algorithm {
                Some(MgmtAlgorithmArg::Tdes) => ManagementKeyAlgorithm::Tdes,
                Some(MgmtAlgorithmArg::Aes192) => ManagementKeyAlgorithm::Aes192,
                None => session.management_algorithm()?,
            };
            // The current key is needed first; --protect also needs the PIN.
            let management = session.resolve_management(
                super::secret_str(&mgmt.management_key),
                super::secret_str(&pin.pin),
            )?;
            let pin = if *protect {
                Some(match management.pin.clone() {
                    Some(pin) => pin,
                    None => session.resolve_pin(super::secret_str(&pin.pin), "Enter PIN")?,
                })
            } else {
                management.pin.clone()
            };
            let new_bytes: [u8; 24] = if let Some(hex) = new_management_key {
                hex_decode(hex)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or("management key must be 24 bytes (48 hex characters)")?
            } else if *generate || *protect {
                let mut bytes = [0; 24];
                getrandom::fill(&mut bytes)?;
                if !protect {
                    println!("Generated management key: {}", hex_encode(&bytes));
                }
                bytes
            } else if *force {
                return Err(
                    "new management key not given; drop --force or use --generate/--new-management-key"
                        .into(),
                );
            } else {
                let entered = super::prompt_password("Enter the new management key: ")?;
                let repeated = super::prompt_password("Repeat the new management key: ")?;
                if entered != repeated {
                    return Err("the management keys do not match".into());
                }
                hex_decode(&entered)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or("management key must be 24 bytes (48 hex characters)")?
            };
            let touch = if *touch {
                piv::ManagementTouchPolicy::Always
            } else {
                piv::ManagementTouchPolicy::Never
            };
            session.run(|profile, exchange| {
                piv::set_management_key_synced(
                    profile,
                    piv::ManagementKeyUpdate {
                        new_key_bytes: new_bytes,
                        algorithm,
                        touch,
                        protect: *protect,
                        pin,
                        access: management.access()?,
                    },
                    exchange,
                )
            })?;
            println!("New management key set.");
            Ok(())
        }
        AccessCommand::UnblockPin { puk, new_pin } => {
            let mut session = PivSession::connect(device, reader)?;
            let puk = session.resolve_puk(super::secret_str(puk))?;
            let new = match new_pin {
                Some(pin) => pin.clone(),
                None => {
                    let entered = super::prompt_password("Enter new PIN: ")?;
                    let repeated = super::prompt_password("Repeat new PIN: ")?;
                    if entered != repeated {
                        return Err("the PINs do not match".into());
                    }
                    entered
                }
            };
            let new = Pin::from_bytes(new.as_bytes()).map_err(|_| "PIN must be 6-8 characters")?;
            session.run(|profile, exchange| piv::unblock_pin(profile, puk, new, exchange))?;
            println!("PIN unblocked and set.");
            Ok(())
        }
    }
}

fn keys(device: Option<u32>, reader: Option<&str>, command: &KeysCommand) -> CliResult<()> {
    match command {
        KeysCommand::Generate {
            slot,
            public_key_output,
            algorithm,
            pin_policy,
            touch_policy,
            format,
            mgmt,
        } => {
            let mut session = PivSession::connect(device, reader)?;
            let management =
                session.resolve_management(super::secret_str(&mgmt.management_key), None)?;
            let mut parameters = KeyParameters::new(*slot, key_algorithm(*algorithm));
            parameters.pin_policy = pin_policy_of(*pin_policy);
            parameters.touch_policy = touch_policy_of(*touch_policy);
            let public = session.run(|profile, exchange| {
                piv::generate_key(profile, parameters, management.access()?, exchange)
            })?;
            let der = public
                .to_spki_der()
                .map_err(|error| format!("cannot encode the public key: {error}"))?;
            let data = match format {
                EncodingArg::Pem => x509::pem_encode("PUBLIC KEY", &der),
                EncodingArg::Der => der,
            };
            write_output(public_key_output, &data)?;
            println!(
                "Private key generated in slot {}, public key written to {public_key_output}.",
                slot_name(*slot)
            );
            Ok(())
        }
        KeysCommand::Import {
            slot,
            private_key,
            password,
            pin_policy,
            touch_policy,
            mgmt,
        } => {
            let data = read_input(private_key)?;
            let password = match password {
                Some(password) => Some(password.clone()),
                None if data.starts_with(b"-----BEGIN ENCRYPTED") => {
                    Some(super::prompt_password("Enter the private key password: ")?)
                }
                None => None,
            };
            let imported =
                keys::parse_private_key(&data, super::secret_str(&password).map(str::as_bytes))
                    .map_err(|error| format!("{error}"))?;
            let mut session = PivSession::connect(device, reader)?;
            let management =
                session.resolve_management(super::secret_str(&mgmt.management_key), None)?;
            let mut parameters = KeyParameters::new(*slot, imported.algorithm);
            parameters.pin_policy = pin_policy_of(*pin_policy);
            parameters.touch_policy = touch_policy_of(*touch_policy);
            let material = imported
                .piv_material()
                .map_err(|error| format!("{error}"))?;
            session.run(|profile, exchange| {
                piv::import_key(
                    profile,
                    parameters,
                    material,
                    management.access()?,
                    exchange,
                )
            })?;
            println!("Private key imported in slot {}.", slot_name(*slot));
            Ok(())
        }
        KeysCommand::Attest {
            slot,
            certificate,
            format,
        } => {
            let mut session = PivSession::connect(device, reader)?;
            let der = session.run(|profile, exchange| piv::attest(profile, *slot, exchange))?;
            let data = match format {
                EncodingArg::Pem => x509::pem_encode("CERTIFICATE", &der),
                EncodingArg::Der => der,
            };
            write_output(certificate, &data)?;
            println!("Attestation certificate written to {certificate}.");
            Ok(())
        }
        KeysCommand::Info { slot } => {
            let mut session = PivSession::connect(device, reader)?;
            let metadata = session.run(|profile, exchange| {
                piv::metadata(
                    profile,
                    MetadataReference::Key(*slot),
                    canokey::piv::Access::None,
                    exchange,
                )
            })?;
            let fields = metadata.fields();
            if let Some(id) = fields.algorithm_id {
                let name = session_algorithm_name(session.profile(), id).unwrap_or("unknown");
                println!("Algorithm:    {name} (wire id 0x{id:02x})");
            }
            if let Some(origin) = &fields.origin {
                println!("Origin:       {origin:?}");
            }
            if let Some(policy) = fields.pin_policy {
                println!("PIN policy:   {policy:?}");
            }
            if let Some(policy) = fields.touch_policy {
                println!("Touch policy: {policy:?}");
            }
            for field in &fields.unknown_fields {
                println!(
                    "Unknown field 0x{:x}: {}",
                    field.tag.value(),
                    hex_encode(field.value.as_bytes())
                );
            }
            Ok(())
        }
        KeysCommand::Export {
            slot,
            public_key_output,
            format,
            verify,
            pin,
        } => {
            let mut session = PivSession::connect(device, reader)?;
            let metadata = session.run(|profile, exchange| {
                piv::metadata(
                    profile,
                    MetadataReference::Key(*slot),
                    canokey::piv::Access::None,
                    exchange,
                )
            })?;
            let fields = metadata.fields();
            let public = fields
                .public_key
                .clone()
                .ok_or("no public key metadata for this slot")?;
            let der = public
                .to_spki_der()
                .map_err(|error| format!("cannot encode the public key: {error}"))?;
            let data = match format {
                EncodingArg::Pem => x509::pem_encode("PUBLIC KEY", &der),
                EncodingArg::Der => der,
            };
            write_output(public_key_output, &data)?;
            if *verify {
                let pin = session.resolve_pin(super::secret_str(&pin.pin), "Enter PIN")?;
                let algorithm = public.algorithm();
                let message = b"test";
                let signature = session.run(|profile, exchange| {
                    piv::sign_message(
                        profile,
                        *slot,
                        algorithm,
                        Some(x509::HashAlgorithm::Sha256),
                        message,
                        canokey::piv::Access::Pin(pin),
                        exchange,
                    )
                })?;
                let ok = verify_signature(&public, message, &signature);
                if !ok {
                    return Err("private key in slot does NOT match the exported public key".into());
                }
                println!("Private key verified against the public key.");
            }
            println!("Public key written to {public_key_output}.");
            Ok(())
        }
        KeysCommand::Move { source, dest, mgmt } => {
            let mut session = PivSession::connect(device, reader)?;
            let management =
                session.resolve_management(super::secret_str(&mgmt.management_key), None)?;
            session.run(|profile, exchange| {
                piv::move_key(profile, *source, *dest, management.access()?, exchange)
            })?;
            println!(
                "Key moved from {} to {}.",
                slot_name(*source),
                slot_name(*dest)
            );
            Ok(())
        }
        KeysCommand::Delete { slot, mgmt } => {
            let mut session = PivSession::connect(device, reader)?;
            let management =
                session.resolve_management(super::secret_str(&mgmt.management_key), None)?;
            session.run(|profile, exchange| {
                piv::delete_key(profile, *slot, management.access()?, exchange)
            })?;
            println!("Key deleted from slot {}.", slot_name(*slot));
            Ok(())
        }
    }
}

/// Host-side signature verification for `keys export --verify`.
fn verify_signature(public: &PublicKey, message: &[u8], signature: &[u8]) -> bool {
    match public {
        PublicKey::Rsa {
            modulus, exponent, ..
        } => {
            // The device signed our DigestInfo-padded block; verify by
            // comparing the raw public operation against the expected block.
            let Ok(key) = rsa::RsaPublicKey::new(
                rsa::BigUint::from_bytes_be(modulus),
                rsa::BigUint::from_bytes_be(exponent),
            ) else {
                return false;
            };
            rsa_pkcs1v15_verify(&key, message, signature).unwrap_or(false)
        }
        PublicKey::Ec { algorithm, point } => match algorithm {
            Algorithm::EccP256 => {
                use p256::ecdsa::signature::hazmat::PrehashVerifier;
                use p256::ecdsa::{Signature, VerifyingKey};
                let Ok(key) = VerifyingKey::from_sec1_bytes(point) else {
                    return false;
                };
                let Ok(signature) = Signature::from_der(signature) else {
                    return false;
                };
                let digest = x509::HashAlgorithm::Sha256.hash(message);
                key.verify_prehash(&digest, &signature).is_ok()
            }
            Algorithm::EccP384 => {
                use p384::ecdsa::signature::hazmat::PrehashVerifier;
                use p384::ecdsa::{Signature, VerifyingKey};
                let Ok(key) = VerifyingKey::from_sec1_bytes(point) else {
                    return false;
                };
                let Ok(signature) = Signature::from_der(signature) else {
                    return false;
                };
                let digest = x509::HashAlgorithm::Sha256.hash(message);
                key.verify_prehash(&digest, &signature).is_ok()
            }
            _ => false,
        },
        PublicKey::Raw { .. } => false,
    }
}

fn rsa_pkcs1v15_verify(
    key: &rsa::RsaPublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, rsa::Error> {
    use rsa::traits::PublicKeyParts;
    // Re-encode the expected block and compare against the raw signature
    // raised to the public exponent.
    let modulus_bytes = key.size();
    let expected = x509::rsa_pkcs1v15_encode(x509::HashAlgorithm::Sha256, message, modulus_bytes)
        .map_err(|_| rsa::Error::Verification)?;
    let signature_int = rsa::BigUint::from_bytes_be(signature);
    let em = signature_int.modpow(key.e(), key.n()).to_bytes_be();
    let mut padded = vec![0; modulus_bytes.saturating_sub(em.len())];
    padded.extend(em);
    Ok(padded == expected)
}

fn certificates(
    device: Option<u32>,
    reader: Option<&str>,
    command: &CertificatesCommand,
) -> CliResult<()> {
    match command {
        CertificatesCommand::Import {
            slot,
            certificate,
            mgmt,
        } => {
            let data = read_input(certificate)?;
            let parsed = if data.starts_with(b"-----BEGIN") {
                canokey::x509::parse_pem(&data, Default::default())
            } else {
                canokey::x509::parse_der(&data, Default::default())
            }
            .map_err(|error| format!("invalid certificate: {error}"))?;
            let mut session = PivSession::connect(device, reader)?;
            // When a key occupies the slot, the certificate must match it.
            if let Ok(metadata) = session.run(|profile, exchange| {
                piv::metadata(
                    profile,
                    MetadataReference::Key(*slot),
                    canokey::piv::Access::None,
                    exchange,
                )
            }) {
                if let Some(public) = &metadata.fields().public_key {
                    let slot_spki = public
                        .to_spki_der()
                        .map_err(|error| format!("cannot encode the slot public key: {error}"))?;
                    if slot_spki != parsed.public_key.spki_der {
                        return Err(
                            "the certificate does not match the private key in the slot".into()
                        );
                    }
                }
            }
            let management =
                session.resolve_management(super::secret_str(&mgmt.management_key), None)?;
            session.run(|profile, exchange| {
                piv::write_certificate(
                    profile,
                    *slot,
                    SecretBytes::new(parsed.der.clone()),
                    management.access()?,
                    exchange,
                )
            })?;
            println!("Certificate imported in slot {}.", slot_name(*slot));
            Ok(())
        }
        CertificatesCommand::Export {
            slot,
            certificate,
            format,
        } => {
            let mut session = PivSession::connect(device, reader)?;
            let cert = session.run(|profile, exchange| {
                piv::read_certificate(profile, *slot, canokey::piv::Access::None, exchange)
            })?;
            let data = match format {
                EncodingArg::Pem => x509::pem_encode("CERTIFICATE", cert.der()),
                EncodingArg::Der => cert.der().to_vec(),
            };
            write_output(certificate, &data)?;
            println!("Certificate written to {certificate}.");
            Ok(())
        }
        CertificatesCommand::Generate {
            slot,
            public_key,
            subject,
            valid_days,
            hash,
            mgmt,
            pin,
        } => {
            let mut session = PivSession::connect(device, reader)?;
            let metadata = session
                .run(|profile, exchange| {
                    piv::metadata(
                        profile,
                        MetadataReference::Key(*slot),
                        canokey::piv::Access::None,
                        exchange,
                    )
                })
                .map_err(|_| format!("no private key in slot {}", slot_name(*slot)))?;
            let fields = metadata.fields();
            if fields.touch_policy == Some(piv::KnownOrUnknown::Known(TouchPolicy::Always))
                || fields.touch_policy == Some(piv::KnownOrUnknown::Known(TouchPolicy::Cached))
            {
                eprintln!("Touch your CanoKey...");
            }
            let (spki_der, algorithm) = match public_key {
                Some(path) => {
                    let parsed = keys::parse_public_key(&read_input(path)?)
                        .map_err(|error| format!("{error}"))?;
                    (parsed.spki_der, parsed.algorithm)
                }
                None => {
                    let public = fields
                        .public_key
                        .clone()
                        .ok_or("no public key metadata for this slot; supply PUBLIC-KEY")?;
                    (
                        public
                            .to_spki_der()
                            .map_err(|error| format!("cannot encode the public key: {error}"))?,
                        public.algorithm(),
                    )
                }
            };
            if !subject.contains('=') {
                return Err("subject must be an RFC 4514 string (e.g. \"CN=name\")".into());
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "system clock is before the Unix epoch")?
                .as_secs() as i64;
            let not_after = now + i64::from(*valid_days) * 86400;
            let management = session.resolve_management(
                super::secret_str(&mgmt.management_key),
                super::secret_str(&pin.pin),
            )?;
            let pin = match &management.pin {
                Some(pin) => pin.clone(),
                None => session.resolve_pin(super::secret_str(&pin.pin), "Enter PIN")?,
            };
            // Each operation gets a fresh mutual authentication; a cloned
            // challenge must never be replayed (libcanokey contract).
            let der = session.run(|profile, exchange| {
                piv::generate_self_signed_certificate(
                    profile,
                    &piv::SignRequest {
                        slot: *slot,
                        algorithm,
                        spki_der: &spki_der,
                        subject,
                        hash: Some(hash_algorithm(*hash)),
                        access: management.pin_and_management(pin)?,
                    },
                    now,
                    not_after,
                    exchange,
                )
            })?;
            session.run(|profile, exchange| {
                piv::write_certificate(
                    profile,
                    *slot,
                    SecretBytes::new(der),
                    management.access()?,
                    exchange,
                )
            })?;
            println!("Certificate generated in slot {}.", slot_name(*slot));
            Ok(())
        }
        CertificatesCommand::Request {
            slot,
            public_key,
            csr_output,
            subject,
            hash,
            pin,
        } => {
            let parsed = keys::parse_public_key(&read_input(public_key)?)
                .map_err(|error| format!("{error}"))?;
            let mut session = PivSession::connect(device, reader)?;
            let metadata = session
                .run(|profile, exchange| {
                    piv::metadata(
                        profile,
                        MetadataReference::Key(*slot),
                        canokey::piv::Access::None,
                        exchange,
                    )
                })
                .map_err(|_| format!("no private key in slot {}", slot_name(*slot)))?;
            if metadata.fields().touch_policy
                == Some(piv::KnownOrUnknown::Known(TouchPolicy::Always))
                || metadata.fields().touch_policy
                    == Some(piv::KnownOrUnknown::Known(TouchPolicy::Cached))
            {
                eprintln!("Touch your CanoKey...");
            }
            if !subject.contains('=') {
                return Err("subject must be an RFC 4514 string (e.g. \"CN=name\")".into());
            }
            let pin = session.resolve_pin(super::secret_str(&pin.pin), "Enter PIN")?;
            let der = session.run(|profile, exchange| {
                piv::generate_csr(
                    profile,
                    &piv::SignRequest {
                        slot: *slot,
                        algorithm: parsed.algorithm,
                        spki_der: &parsed.spki_der,
                        subject,
                        hash: Some(hash_algorithm(*hash)),
                        access: canokey::piv::Access::Pin(pin),
                    },
                    exchange,
                )
            })?;
            write_output(csr_output, &x509::pem_encode("CERTIFICATE REQUEST", &der))?;
            println!("CSR for slot {} written to {csr_output}.", slot_name(*slot));
            Ok(())
        }
        CertificatesCommand::Delete { slot, mgmt } => {
            let mut session = PivSession::connect(device, reader)?;
            let management =
                session.resolve_management(super::secret_str(&mgmt.management_key), None)?;
            session.run(|profile, exchange| {
                piv::delete_certificate(profile, *slot, management.access()?, exchange)
            })?;
            println!("Certificate in slot {} deleted.", slot_name(*slot));
            Ok(())
        }
    }
}

fn objects(device: Option<u32>, reader: Option<&str>, command: &ObjectsCommand) -> CliResult<()> {
    match command {
        ObjectsCommand::Export {
            object_id,
            output,
            pin,
        } => {
            let mut session = PivSession::connect(device, reader)?;
            let access = match &pin.pin {
                Some(pin) => canokey::piv::Access::Pin(
                    Pin::from_bytes(pin.as_bytes()).map_err(|_| "PIN must be 6-8 characters")?,
                ),
                None => canokey::piv::Access::None,
            };
            let data = session
                .run(|profile, exchange| piv::read_object(profile, *object_id, access, exchange))?;
            write_output(output, data.as_bytes())?;
            println!("Object written to {output}.");
            Ok(())
        }
        ObjectsCommand::Import {
            object_id,
            data,
            mgmt,
        } => {
            let data = read_input(data)?;
            let mut session = PivSession::connect(device, reader)?;
            let management =
                session.resolve_management(super::secret_str(&mgmt.management_key), None)?;
            session.run(|profile, exchange| {
                piv::write_object(
                    profile,
                    *object_id,
                    SecretBytes::new(data),
                    management.access()?,
                    exchange,
                )
            })?;
            println!("Object written.");
            Ok(())
        }
    }
}
