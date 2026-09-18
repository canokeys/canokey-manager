pub mod config;
pub mod info;
pub mod list;
pub mod oath;

use ckman_core::admin::Pin;
use ckman_core::{probe, DriveError};
use ckman_transport::pcsc::{Pcsc, PcscConnection, Reader};

use canokey::{DeviceProfile, ErrorKind, SecretReference};
use std::io;

pub type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

/// A probed CanoKey: exclusive connection plus its immutable profile.
pub struct Target {
    pub connection: PcscConnection,
    pub profile: DeviceProfile,
}

impl Target {
    pub fn serial(&self) -> Option<u32> {
        let bytes: [u8; 4] = self.profile.info().serial()?.try_into().ok()?;
        Some(u32::from_be_bytes(bytes))
    }
}

/// Connect to and probe one reader; returns `None` when the card is not a
/// CanoKey or probing fails (foreign cards must not break listing).
fn try_probe(pcsc: &Pcsc, reader: &Reader) -> Option<Target> {
    let mut connection = pcsc.connect(reader).ok()?;
    if !connection.is_canokey() {
        return None;
    }
    let profile = probe(&mut |command| connection.exchange(command)).ok()?;
    Some(Target {
        connection,
        profile,
    })
}

/// All reachable CanoKeys, in reader order.
pub fn all_targets(pcsc: &Pcsc) -> CliResult<Vec<Target>> {
    let mut targets = Vec::new();
    for reader in pcsc.readers()? {
        if let Some(target) = try_probe(pcsc, &reader) {
            targets.push(target);
        }
    }
    Ok(targets)
}

/// The single CanoKey selected by `--reader` / `--device`, or the only one
/// attached when no filter is given.
pub fn single_target(
    pcsc: &Pcsc,
    device: Option<u32>,
    reader_name: Option<&str>,
) -> CliResult<Target> {
    if let Some(name) = reader_name {
        let reader = pcsc
            .readers()?
            .into_iter()
            .find(|reader| reader.name() == name)
            .ok_or_else(|| format!("no such reader: {name}"))?;
        return try_probe(pcsc, &reader)
            .ok_or_else(|| format!("no CanoKey found in reader {name}").into());
    }
    let targets = all_targets(pcsc)?;
    if let Some(serial) = device {
        return targets
            .into_iter()
            .find(|target| target.serial() == Some(serial))
            .ok_or_else(|| format!("no CanoKey with serial number {serial} found").into());
    }
    match targets.len() {
        0 => Err("no CanoKey found".into()),
        1 => Ok(targets.into_iter().next().unwrap()),
        _ => Err("multiple CanoKeys found; use --device or --reader to select one".into()),
    }
}

/// Prompt for the Admin PIN without echoing.
pub fn prompt_admin_pin() -> CliResult<Pin> {
    let entered = rpassword::prompt_password("Admin PIN: ")?;
    Pin::from_bytes(entered.as_bytes()).map_err(|error| format!("{error}").into())
}

/// True when libcanokey reports that the request needs Admin PIN verification
/// (a protected request built without a PIN, or a card-side 6982), so the CLI
/// should prompt and retry once. libcanokey never tries default credentials.
pub fn needs_admin_pin<E>(error: &DriveError<E>) -> bool {
    matches!(
        error,
        DriveError::Protocol(error)
            if error.kind == ErrorKind::SecurityStatusNotSatisfied
                || (error.kind == ErrorKind::AuthenticationFailed
                    && error.reference == Some(SecretReference::AdminPin))
    )
}

/// Human-facing message for a transport/protocol failure, decoding the
/// firmware capability gates that libcanokey surfaces as typed errors.
pub fn describe_drive_error(error: &DriveError<io::Error>) -> String {
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
                Some(retries) => format!("incorrect PIN ({retries} attempts remaining)"),
                None => "incorrect PIN".to_string(),
            },
            ErrorKind::PinBlocked => "the PIN is blocked".to_string(),
            _ => format!("protocol error: {error}"),
        },
    }
}

/// Run an Admin operation that may be PIN-protected. An explicit `pin` is used
/// directly; otherwise the operation is tried without a PIN first, and when
/// the library or the card demands verification the user is prompted once and
/// the operation retried with the entered PIN.
pub fn with_admin_pin_retry<T>(
    pin: Option<Pin>,
    mut operation: impl FnMut(Option<Pin>) -> Result<T, DriveError<io::Error>>,
) -> CliResult<T> {
    match pin {
        Some(pin) => operation(Some(pin)).map_err(|error| describe_drive_error(&error).into()),
        None => match operation(None) {
            Ok(result) => Ok(result),
            Err(error) if needs_admin_pin(&error) => {
                let pin = prompt_admin_pin()?;
                operation(Some(pin)).map_err(|error| describe_drive_error(&error).into())
            }
            Err(error) => Err(describe_drive_error(&error).into()),
        },
    }
}

/// Ask a y/N question on the terminal; defaults to "no".
pub fn confirm(prompt: &str) -> CliResult<bool> {
    use std::io::Write as _;
    eprint!("{prompt} [y/N]: ");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}
