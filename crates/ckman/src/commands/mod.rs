pub mod config;
pub mod fido;
pub mod info;
mod input;
pub mod list;
pub mod oath;
pub mod openpgp;
mod output;
pub mod piv;
mod piv_recovery;

use ckman_core::admin::Pin;
use ckman_core::{probe, DriveError};
use ckman_transport::pcsc::{Pcsc, PcscConnection, Reader};

use canokey::{DeviceProfile, ErrorKind, SecretReference};
use std::io;
use zeroize::Zeroizing;

pub type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Reader selection matching: case-insensitive substring.
pub fn reader_matches(reader_name: &str, filter: &str) -> bool {
    reader_name.to_lowercase().contains(&filter.to_lowercase())
}

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

/// Probe an explicitly selected reader without hiding connection failures.
fn probe_reader(pcsc: &Pcsc, reader: &Reader) -> CliResult<Target> {
    let mut connection = pcsc
        .connect(reader)
        .map_err(|error| format!("cannot connect to reader {}: {error}", reader.name()))?;
    if !connection.is_canokey() {
        return Err(format!("no CanoKey found in reader {}", reader.name()).into());
    }
    let profile = probe(&mut |command| connection.exchange(command)).map_err(|error| {
        format!(
            "cannot probe CanoKey in reader {}: {}",
            reader.name(),
            describe_drive_error(&error)
        )
    })?;
    Ok(Target {
        connection,
        profile,
    })
}

/// All reachable CanoKeys, in reader order.
pub fn all_targets(pcsc: &Pcsc) -> CliResult<Vec<Target>> {
    targets_matching_reader(pcsc, None)
}

/// Probe only readers matching the optional case-insensitive substring.
pub fn targets_matching_reader(pcsc: &Pcsc, reader_name: Option<&str>) -> CliResult<Vec<Target>> {
    let mut targets = Vec::new();
    for reader in pcsc.readers()? {
        if reader_name.is_some_and(|name| !reader_matches(reader.name(), name)) {
            continue;
        }
        // Enumeration reports reachable CanoKeys; an unrelated or unavailable
        // card must not prevent listing the other readers.
        if let Ok(target) = probe_reader(pcsc, &reader) {
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
        let reader = only_match(
            pcsc.readers()?
                .into_iter()
                .filter(|reader| reader_matches(reader.name(), name)),
            &format!("no such reader: {name}"),
            &format!("multiple readers match {name}; use a more specific --reader"),
        )?;
        return probe_reader(pcsc, &reader);
    }
    let targets = selection_targets(pcsc.readers()?, |reader| {
        let mut connection = match pcsc.connect(&reader) {
            Ok(connection) => connection,
            Err(error) if error.is_no_smartcard() => return Ok(None),
            Err(error) => return Err(format!(
                "cannot determine whether reader {} contains another CanoKey: {error}; select a reader explicitly with --reader",
                reader.name()
            ).into()),
        };
        if !connection.is_canokey() {
            return Ok(None);
        }
        let profile = probe(&mut |command| connection.exchange(command)).map_err(|error| {
            format!(
                "cannot probe CanoKey in reader {}: {}; select a reader explicitly with --reader",
                reader.name(),
                describe_drive_error(&error)
            )
        })?;
        Ok(Some(Target {
            connection,
            profile,
        }))
    })?;
    if let Some(serial) = device {
        return only_match(
            targets
                .into_iter()
                .filter(|target| target.serial() == Some(serial)),
            &format!("no CanoKey with serial number {serial} found"),
            &format!("multiple CanoKeys have serial number {serial}; select one with --reader"),
        );
    }
    match targets.len() {
        0 => Err("no CanoKey found".into()),
        1 => Ok(targets.into_iter().next().unwrap()),
        _ => Err("multiple CanoKeys found; use --device or --reader to select one".into()),
    }
}

// Selection must account for every candidate, unlike best-effort listing.
fn selection_targets<R, T>(
    readers: impl IntoIterator<Item = R>,
    mut probe: impl FnMut(R) -> CliResult<Option<T>>,
) -> CliResult<Vec<T>> {
    let mut targets = Vec::new();
    for reader in readers {
        if let Some(target) = probe(reader)? {
            targets.push(target);
        }
    }
    Ok(targets)
}

fn only_match<T>(
    mut matches: impl Iterator<Item = T>,
    missing: &str,
    ambiguous: &str,
) -> CliResult<T> {
    let first = matches.next().ok_or_else(|| missing.to_string())?;
    if matches.next().is_some() {
        return Err(ambiguous.to_string().into());
    }
    Ok(first)
}

/// A secret string (PIN, password, key) with redacted Debug output, zeroized
/// on drop. Used for
/// every prompted secret and for argv-supplied secrets (which additionally
/// remain visible in shell history and `ps` — see README).
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Take ownership of a secret, clearing it when dropped.
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Borrow the secret for an operation that needs its plaintext value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for SecretString {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

/// clap value parser for `Option<SecretString>` arguments.
pub fn secret_arg(value: &str) -> Result<SecretString, std::convert::Infallible> {
    Ok(SecretString::new(value.to_string()))
}

/// Borrow an optional secret argument as `&str`.
pub fn secret_str(value: &Option<SecretString>) -> Option<&str> {
    value.as_ref().map(|s| s.as_str())
}

/// Prompt for a secret without echo, with actionable context when no
/// terminal is attached (rpassword opens /dev/tty, which fails with ENXIO on
/// non-interactive runners). The returned secret is zeroized on drop.
pub fn prompt_password(prompt: &str) -> CliResult<SecretString> {
    rpassword::prompt_password(prompt)
        .map(SecretString::new)
        .map_err(|error| {
            format!("cannot prompt for input ({prompt:?}): {error}; is a terminal attached?").into()
        })
}

/// Prompt for the Admin PIN without echoing.
pub fn prompt_admin_pin() -> CliResult<Pin> {
    let entered = prompt_password("Admin PIN: ")?;
    Pin::from_bytes(entered.as_bytes()).map_err(|error| format!("{error}").into())
}

/// Parse a private key file (PEM/DER/PKCS#12), prompting once for a password
/// when the file needs one and none was supplied on the command line.
pub fn parse_private_key_input(
    data: &[u8],
    password: &Option<SecretString>,
) -> CliResult<ckman_core::keys::ImportedKey> {
    let parsed = ckman_core::keys::parse_private_key(data, secret_str(password).map(str::as_bytes));
    match parsed {
        Err(ckman_core::keys::KeyError::Password) if password.is_none() => {
            let entered = prompt_password("Enter the private key password: ")?;
            ckman_core::keys::parse_private_key(data, Some(entered.as_bytes()))
                .map_err(|error| format!("{error}").into())
        }
        other => other.map_err(|error| format!("{error}").into()),
    }
}

/// Parse a certificate file: a PEM bundle contributes its first CERTIFICATE
/// block; DER is a lone X.509 certificate or a PKCS#12 bundle (importing
/// its leaf certificate, prompting for the bundle password when needed).
pub fn parse_certificate_input(data: &[u8]) -> CliResult<canokey::x509::CertificateInfo> {
    let (label, decoded) = ckman_core::keys::pem_decode(data, &["CERTIFICATE"])
        .map_err(|error| format!("invalid certificate: {error}"))?;
    let decoded = Zeroizing::new(decoded);
    if !label.is_empty() {
        return canokey::x509::parse_der(&decoded, Default::default())
            .map_err(|error| format!("invalid certificate: {error}").into());
    }
    if let Ok(cert) = canokey::x509::parse_der(data, Default::default()) {
        return Ok(cert);
    }
    let certs = match ckman_core::keys::certificates_from_pfx(data, None) {
        Err(ckman_core::keys::KeyError::Password) => {
            let entered = prompt_password("Enter the PKCS#12 password: ")?;
            ckman_core::keys::certificates_from_pfx(data, Some(entered.as_bytes()))
        }
        other => other,
    }
    .map_err(|error| format!("invalid certificate: {error}"))?;
    let leaf = ckman_core::keys::leaf_certificate(&certs)
        .map_err(|error| format!("invalid certificate: {error}"))?;
    canokey::x509::parse_der(&certs[leaf], Default::default())
        .map_err(|error| format!("invalid certificate: {error}").into())
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
            ErrorKind::SecurityStatusNotSatisfied => {
                "the operation requires authentication".to_string()
            }
            ErrorKind::UnsupportedDevice => {
                "the applet is disabled or absent on this device".to_string()
            }
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

/// Read one line after writing `prompt`; `None` at EOF so prompt loops can
/// never spin on a closed stdin.
pub fn prompt_line(prompt: &str) -> CliResult<Option<String>> {
    let mut input = io::stdin().lock();
    prompt_line_from(&mut input, prompt, &mut io::stdout())
}

/// [`prompt_line`] over explicit streams (testable).
pub fn prompt_line_from(
    reader: &mut impl io::BufRead,
    prompt: &str,
    writer: &mut impl io::Write,
) -> CliResult<Option<String>> {
    write!(writer, "{prompt}")?;
    writer.flush()?;
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    Ok(Some(line.trim().to_string()))
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

#[cfg(test)]
mod tests {

    #[test]
    fn selection_does_not_turn_failed_candidates_into_a_unique_device() {
        for failed_reader in [0, 1] {
            let mut visited = Vec::new();
            let result = selection_targets([0, 1, 2], |reader| {
                visited.push(reader);
                if reader == failed_reader {
                    Err("candidate is busy or its probe failed".into())
                } else {
                    Ok(Some(reader))
                }
            });
            assert!(result.unwrap_err().to_string().contains("candidate"));
            assert_eq!(visited, (0..=failed_reader).collect::<Vec<_>>());
        }
        assert_eq!(
            selection_targets([0, 1, 2], |reader| Ok((reader == 1).then_some(reader))).unwrap(),
            vec![1]
        );
        assert_eq!(
            selection_targets([0, 1], |reader| Ok(Some(reader))).unwrap(),
            vec![0, 1]
        );
    }

    #[test]
    fn secret_arguments_are_redacted_without_changing_their_value() {
        let secret = super::secret_arg("audit-only-secret-1234").unwrap();
        assert_eq!(secret.as_str(), "audit-only-secret-1234");
        assert_eq!(secret.clone().as_str(), secret.as_str());
        assert!(format!("{secret:?}").contains("REDACTED"));
        assert!(!format!("{secret:#?}").contains("audit-only-secret-1234"));
    }

    use super::*;
    use std::io::BufReader;

    #[test]
    fn certificate_pem_accepts_preambles_and_bundles() {
        let pfx = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../ckman-core/tests/fixtures/p12_nopw.p12"
        ));
        let certs = ckman_core::keys::certificates_from_pfx(pfx, None).unwrap();
        let pem = ckman_core::x509::pem_encode("CERTIFICATE", &certs[0]);
        for prefix in [
            "",
            "\n \n",
            "\u{feff}",
            "Bag Attributes\n    friendlyName: leaf\n",
            "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n",
        ] {
            let mut input = prefix.as_bytes().to_vec();
            input.extend(&pem);
            let parsed = parse_certificate_input(&input).unwrap();
            assert_eq!(parsed.der, certs[0], "{prefix:?}");
        }
        assert_eq!(parse_certificate_input(&certs[0]).unwrap().der, certs[0]);
        assert_eq!(parse_certificate_input(pfx).unwrap().der, certs[0]);
        assert!(parse_certificate_input(
            b"\n-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----"
        )
        .is_err());
    }

    #[test]
    fn device_selection_rejects_ambiguous_readers_and_duplicate_serials() {
        let readers = ["CanoKey A", "CanoKey B"];
        assert!(only_match(
            readers
                .iter()
                .filter(|name| reader_matches(name, "canokey")),
            "missing",
            "ambiguous"
        )
        .unwrap_err()
        .to_string()
        .contains("ambiguous"));
        assert_eq!(
            *only_match(
                readers.iter().filter(|name| reader_matches(name, "key b")),
                "missing",
                "ambiguous"
            )
            .unwrap(),
            "CanoKey B"
        );
        let serials = [u32::MAX, u32::MAX];
        assert!(only_match(
            serials.into_iter().filter(|serial| *serial == u32::MAX),
            "missing",
            "duplicate serial"
        )
        .is_err());
        assert!(only_match(
            serials.into_iter().filter(|serial| *serial == 1),
            "missing",
            "ambiguous"
        )
        .is_err());
    }

    #[test]
    fn reader_matching_is_case_insensitive_substring() {
        assert!(reader_matches("Canokeys Canokey [CCID] 00 00", "canokey"));
        assert!(reader_matches("Canokeys Canokey [CCID] 00 00", "CANOKEY"));
        assert!(reader_matches("Canokeys Canokey [CCID] 00 00", "ccid] 00"));
        assert!(!reader_matches("Canokeys Canokey [CCID] 00 00", "otherkey"));
        // An empty filter matches everything (substring semantics).
        assert!(reader_matches("Some Reader", ""));
    }

    #[test]
    fn prompt_line_from_handles_eof() {
        let mut out = Vec::new();
        let mut input = BufReader::new(&b""[..]);
        assert_eq!(
            prompt_line_from(&mut input, "Prompt: ", &mut out).unwrap(),
            None,
            "EOF must end the loop, not spin"
        );
        assert_eq!(out, b"Prompt: ");
        let mut input = BufReader::new(&b"  hello world \nrest"[..]);
        assert_eq!(
            prompt_line_from(&mut input, "Prompt: ", &mut out).unwrap(),
            Some("hello world".to_string())
        );
    }
}
