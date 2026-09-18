//! Typed wrappers around `canokey::oath` operations.
//!
//! Each wrapper owns one complete OATH operation on the caller's exclusive
//! connection: every operation re-SELECTs the applet and, when an access key
//! is supplied, re-validates it against the card's fresh challenge (mutual
//! authentication; a wrong key fails with `AuthenticationFailed`). libcanokey
//! reads no clock and no RNG: TOTP time steps come from [`totp_challenge`]
//! with a caller timestamp, and authentication randomness comes from the host
//! CSPRNG via [`access_from_key`].
//!
//! Password protection is signalled by the SELECT response: a modern
//! [`Selected::Modern`] with a challenge means the applet is locked. The
//! device-bound access key derives from the password and the SELECT handle
//! ([`derive_key_bytes`], the same PBKDF2 convention libcanokey applies in
//! `AccessKey::from_password`), so callers can store the derived key instead
//! of the password.
//!
//! Touch is signalled in-band: `CalculateAll` returns [`Code::TouchRequired`]
//! or [`Code::Hotp`] markers for credentials it did not calculate; the
//! individual [`calculate`] then blocks in the transport until the user
//! touches the key or the card times out (6985, surfaced as
//! `ConditionsNotSatisfied`). No polling loop is needed.
//!
//! Legacy (1.3-era) dialects are libcanokey's job: the wrappers pass the
//! profile through and never special-case firmware.

use crate::{execute, DriveError, Exchange};
use canokey::oath::{self, Outcome, Request};
use canokey::{DeviceProfile, Error, ErrorKind, OperationOptions, Phase, SecretBytes};
use zeroize::Zeroizing;

pub use canokey::oath::{
    Access, AccessKey, Algorithm, Calculation, Code, Credential, Entry, Format, Kind, Name,
};

/// The conventional TOTP time step, seconds.
pub const DEFAULT_PERIOD: u32 = 30;

/// Failure preparing or driving an OATH operation.
#[derive(Debug, thiserror::Error)]
pub enum OathError<E> {
    /// Transport or protocol failure while driving the operation.
    #[error(transparent)]
    Drive(#[from] DriveError<E>),
    /// The host CSPRNG failed before any I/O; nothing was sent to the card.
    #[error("failed to generate authentication randomness: {0}")]
    Random(#[from] getrandom::Error),
}

/// Result of selecting the OATH applet.
#[derive(Debug)]
pub enum Selected {
    /// Modern selection: applet version, derivation handle, and the access
    /// challenge whose presence signals password protection.
    Modern(oath::Selection),
    /// Legacy 1.3 selection carries no version, salt or challenge; the Admin
    /// serial is copied from the profile when available.
    Legacy {
        /// Independently observed Admin serial, when available.
        serial: Option<[u8; 4]>,
    },
}

impl Selected {
    /// Applet version bytes on modern firmware; absent on 1.3.
    pub fn version(&self) -> Option<[u8; 3]> {
        match self {
            Self::Modern(selection) => Some(selection.version),
            Self::Legacy { .. } => None,
        }
    }

    /// Password-derivation handle; absent on 1.3 (no access codes there).
    pub fn handle(&self) -> Option<[u8; 8]> {
        match self {
            Self::Modern(selection) => Some(selection.handle),
            Self::Legacy { .. } => None,
        }
    }

    /// Whether the applet requires access validation (a password is set).
    pub fn locked(&self) -> bool {
        match self {
            Self::Modern(selection) => selection.challenge.is_some(),
            Self::Legacy { .. } => false,
        }
    }
}

fn unexpected<E>() -> OathError<E> {
    DriveError::Protocol(Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing)).into()
}

fn run<E>(
    profile: &DeviceProfile,
    request: Request,
    access: Option<Access>,
    exchange: &mut Exchange<'_, E>,
) -> Result<Outcome, OathError<E>> {
    let operation = oath::operation(profile, request, access, OperationOptions::default())
        .map_err(DriveError::from)?;
    Ok(execute(operation, exchange)?)
}

/// Select the OATH applet and report version, handle and protection state.
/// Performs no validation even when an access code is installed.
pub fn select<E>(
    profile: &DeviceProfile,
    exchange: &mut Exchange<'_, E>,
) -> Result<Selected, OathError<E>> {
    match run(profile, Request::Select, None, exchange)? {
        Outcome::Selection(selection) => Ok(Selected::Modern(selection)),
        Outcome::LegacySelection { serial } => Ok(Selected::Legacy { serial }),
        _ => Err(unexpected()),
    }
}

/// Validate an access key against the card's challenge without another
/// target command. This is mutual: the card must also prove it holds the key,
/// or the operation fails with `DeviceAuthenticationFailed`.
pub fn validate<E>(
    profile: &DeviceProfile,
    access: Access,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), OathError<E>> {
    match run(profile, Request::Validate, Some(access), exchange)? {
        Outcome::Unit => Ok(()),
        _ => Err(unexpected()),
    }
}

/// List credential names and algorithm/type octets, paging until the card
/// reports no further records.
pub fn list<E>(
    profile: &DeviceProfile,
    access: Option<Access>,
    exchange: &mut Exchange<'_, E>,
) -> Result<Vec<Entry>, OathError<E>> {
    match run(profile, Request::List, access, exchange)? {
        Outcome::Entries(entries) => Ok(entries),
        _ => Err(unexpected()),
    }
}

/// Insert a credential. Firmware does not silently replace an existing name;
/// a duplicate fails with the card's error status.
pub fn add<E>(
    profile: &DeviceProfile,
    access: Option<Access>,
    credential: Credential,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), OathError<E>> {
    match run(profile, Request::Put(credential), access, exchange)? {
        Outcome::Unit => Ok(()),
        _ => Err(unexpected()),
    }
}

/// Rename a credential without changing its key or counter. Before firmware
/// 2.0 the card does not reject an existing destination.
pub fn rename<E>(
    profile: &DeviceProfile,
    access: Option<Access>,
    old: Name,
    new: Name,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), OathError<E>> {
    match run(profile, Request::Rename { old, new }, access, exchange)? {
        Outcome::Unit => Ok(()),
        _ => Err(unexpected()),
    }
}

/// Delete one credential.
pub fn delete<E>(
    profile: &DeviceProfile,
    access: Option<Access>,
    name: Name,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), OathError<E>> {
    match run(profile, Request::Delete(name), access, exchange)? {
        Outcome::Unit => Ok(()),
        _ => Err(unexpected()),
    }
}

/// Caller record of a credential for an individual calculation; the card is
/// not re-queried, so `kind` and `algorithm` must match the stored credential
/// (from a prior [`list`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialRef {
    /// Credential name.
    pub name: Name,
    /// Counter-based or time-based credential.
    pub kind: Kind,
    /// HMAC algorithm, used to validate full-response length.
    pub algorithm: Algorithm,
}

/// Calculate one credential. `challenge` is the TOTP time step and must be
/// `None` for HOTP. For a touch-protected credential the exchange blocks
/// until the user touches the key.
pub fn calculate<E>(
    profile: &DeviceProfile,
    access: Option<Access>,
    credential: CredentialRef,
    challenge: Option<[u8; 8]>,
    format: Format,
    exchange: &mut Exchange<'_, E>,
) -> Result<Calculation, OathError<E>> {
    match run(
        profile,
        Request::Calculate {
            name: credential.name,
            kind: credential.kind,
            algorithm: credential.algorithm,
            challenge,
            format,
        },
        access,
        exchange,
    )? {
        Outcome::Calculations(mut calculations) if calculations.len() == 1 => {
            Ok(calculations.remove(0))
        }
        _ => Err(unexpected()),
    }
}

/// Calculate all eligible TOTP entries at the given time step. HOTP and
/// touch-protected entries come back as [`Code::Hotp`]/[`Code::TouchRequired`]
/// markers; calculate those individually with [`calculate`].
pub fn calculate_all<E>(
    profile: &DeviceProfile,
    access: Option<Access>,
    challenge: [u8; 8],
    format: Format,
    exchange: &mut Exchange<'_, E>,
) -> Result<Vec<Calculation>, OathError<E>> {
    match run(
        profile,
        Request::CalculateAll { challenge, format },
        access,
        exchange,
    )? {
        Outcome::Calculations(calculations) => Ok(calculations),
        _ => Err(unexpected()),
    }
}

/// Set or replace the OATH access code. When the applet is already protected,
/// `access` must carry the current key, which is validated first.
pub fn set_password<E>(
    profile: &DeviceProfile,
    access: Option<Access>,
    new_key: AccessKey,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), OathError<E>> {
    let mut challenge = [0; 8];
    getrandom::fill(&mut challenge)?;
    match run(
        profile,
        Request::SetCode {
            key: new_key,
            challenge,
        },
        access,
        exchange,
    )? {
        Outcome::Unit => Ok(()),
        _ => Err(unexpected()),
    }
}

/// Remove the OATH access code, validating the current key when the applet is
/// protected.
pub fn clear_password<E>(
    profile: &DeviceProfile,
    access: Option<Access>,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), OathError<E>> {
    match run(profile, Request::ClearCode, access, exchange)? {
        Outcome::Unit => Ok(()),
        _ => Err(unexpected()),
    }
}

/// Derive the 16-byte OATH access key from a password and the SELECT handle:
/// PBKDF2-HMAC-SHA1, 1000 iterations, the handle as salt. This is the frozen
/// protocol convention libcanokey implements in `AccessKey::from_password`;
/// it is exposed byte-wise so callers can persist the device-bound key (e.g.
/// in an OS keyring) instead of the password.
pub fn derive_key_bytes(password: &[u8], handle: [u8; 8]) -> Zeroizing<[u8; 16]> {
    let mut output = Zeroizing::new([0; 16]);
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, &handle, 1000, output.as_mut());
    output
}

/// Build an [`AccessKey`] from derived key bytes.
pub fn access_key(key: &[u8; 16]) -> AccessKey {
    AccessKey::from_bytes(key).expect("a 16-byte key always satisfies the access-key bounds")
}

/// Build an [`AccessKey`] directly from a password and handle.
pub fn access_key_from_password(password: &[u8], handle: [u8; 8]) -> AccessKey {
    AccessKey::from_password(SecretBytes::new(password.to_vec()), handle)
}

/// Wrap an access key with a fresh CSPRNG challenge for one validation.
pub fn access_from_key(key: AccessKey) -> Result<Access, getrandom::Error> {
    let mut challenge = [0; 8];
    getrandom::fill(&mut challenge)?;
    Ok(Access { key, challenge })
}

/// The big-endian TOTP time-step challenge for a timestamp; `period` is in
/// seconds and must be at least 1.
pub fn totp_challenge(timestamp: u64, period: u32) -> [u8; 8] {
    assert!(period > 0, "TOTP period must be at least one second");
    (timestamp / u64::from(period)).to_be_bytes()
}

const STEAM_CHARS: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";

/// Format a calculation as a five-character Steam code. Accepts both the
/// truncated response and a full HMAC (dynamic truncation is applied). Marker
/// results return `None`.
pub fn steam_code(calculation: &Calculation) -> Option<String> {
    let mut code = match &calculation.code {
        Code::Truncated(bytes) => u32::from_be_bytes(bytes.as_bytes().try_into().ok()?),
        Code::Full(bytes) => {
            let bytes = bytes.as_bytes();
            let offset = usize::from(bytes.last()? & 0x0f);
            u32::from_be_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?) & 0x7fff_ffff
        }
        _ => return None,
    };
    let mut output = String::with_capacity(5);
    for _ in 0..5 {
        output.push(STEAM_CHARS[code as usize % STEAM_CHARS.len()] as char);
        code /= STEAM_CHARS.len() as u32;
    }
    Some(output)
}

/// Display form of a credential name following the yubikit convention:
/// `[period/][issuer:]account`, where the `period/` prefix appears only on
/// TOTP credentials with a non-default period.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedName {
    /// Issuer prefix, when present.
    pub issuer: Option<String>,
    /// Account part of the name.
    pub account: String,
    /// TOTP period in seconds; [`DEFAULT_PERIOD`] when the prefix is absent,
    /// zero for HOTP.
    pub period: u32,
}

/// Parse the display convention from raw credential name bytes. Invalid UTF-8
/// is lossily replaced; the raw bytes remain authoritative for all operations.
pub fn parse_name(raw: &[u8], kind: Kind) -> ParsedName {
    let text = String::from_utf8_lossy(raw);
    let mut rest = text.as_ref();
    let mut issuer = None;
    let mut period = 0;
    if kind == Kind::Totp {
        period = DEFAULT_PERIOD;
        if let Some((head, tail)) = rest.split_once('/') {
            if !head.is_empty() && head.bytes().all(|b| b.is_ascii_digit()) {
                if let Ok(parsed) = head.parse() {
                    period = parsed;
                    rest = tail;
                }
            }
        }
    }
    if !rest.starts_with(':') {
        if let Some((head, tail)) = rest.split_once(':') {
            issuer = Some(head.to_string());
            rest = tail;
        }
    }
    ParsedName {
        issuer,
        account: rest.to_string(),
        period,
    }
}

/// Format the on-device credential name for the yubikit convention.
pub fn format_id(issuer: Option<&str>, account: &str, kind: Kind, period: u32) -> String {
    let mut id = String::new();
    if kind == Kind::Totp && period != DEFAULT_PERIOD {
        id.push_str(&period.to_string());
        id.push('/');
    }
    if let Some(issuer) = issuer {
        id.push_str(issuer);
        id.push(':');
    }
    id.push_str(account);
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use canokey::compatibility::DeviceObservations;
    use std::collections::VecDeque;
    use std::io;

    /// Transcript-driven exchange, mirroring the probe tests in `lib.rs`.
    struct Script {
        transcript: VecDeque<(&'static [u8], &'static [u8])>,
    }

    impl Script {
        fn new(transcript: &[(&'static [u8], &'static [u8])]) -> Self {
            Script {
                transcript: transcript.iter().copied().collect(),
            }
        }
    }

    impl Script {
        fn exchange(&mut self, command: &[u8]) -> io::Result<Vec<u8>> {
            let (expected, response) = self
                .transcript
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "unexpected exchange"))?;
            assert_eq!(command, expected, "command differs from transcript");
            Ok(response.to_vec())
        }
    }

    fn profile(firmware: &[u8]) -> DeviceProfile {
        let mut observations = DeviceObservations::new(firmware.to_vec());
        observations.serial = Some(vec![1, 2, 3, 4]);
        DeviceProfile::from_observations(observations).unwrap()
    }

    const SELECT: &[u8] = &[0, 0xa4, 4, 0, 7, 0xa0, 0, 0, 5, 0x27, 0x21, 1];
    const SELECT_LEGACY: &[u8] = &[0, 0xa4, 4, 0, 7, 0xa0, 0, 0, 5, 0x27, 0x21, 1, 0];

    /// Modern SELECT response without an access challenge.
    const SELECTION_OPEN: &[u8] = &[
        0x79, 3, 6, 0, 0, 0x71, 8, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', 0x90, 0,
    ];
    /// Modern SELECT response with an access challenge (password set).
    const SELECTION_LOCKED: &[u8] = &[
        0x79, 3, 6, 0, 0, 0x71, 8, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', 0x74, 8, b'C',
        b'C', b'C', b'C', b'C', b'C', b'C', b'C', 0x7b, 1, 1, 0x90, 0,
    ];

    #[test]
    fn list_on_modern_firmware_pages_until_exhausted() {
        let mut script = Script::new(&[
            (SELECT, SELECTION_OPEN),
            (&[0, 0xa1, 0, 0, 255], &[0x72, 2, 0x21, b'a', 0x90, 0]),
            // A terminal empty 6985 is only accepted after a 9000 page,
            // never directly after a 61xx more-data page.
            (&[0, 0xa5, 0, 0, 255], &[0x72, 2, 0x12, b'b', 0x90, 0]),
            (&[0, 0xa5, 0, 0, 255], &[0x69, 0x85]),
        ]);
        let entries = list(&profile(b"3.1.0"), None, &mut |c| script.exchange(c)).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name.as_bytes(), b"a");
        assert_eq!(entries[0].algorithm_type, 0x21);
        assert_eq!(entries[1].algorithm_type, 0x12);
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn list_on_legacy_13_uses_legacy_dialect() {
        // 1.3: explicit Le on SELECT, empty selection response, INS 03 LIST
        // paged with INS 06 SEND REMAINING, name/digits metadata preserved.
        let mut script = Script::new(&[
            (SELECT_LEGACY, &[0x90, 0]),
            (
                &[0, 3, 0, 0, 255],
                &[0x71, 1, b'a', 0x75, 2, 0x21, 6, 0x61, 0xff],
            ),
            (
                &[0, 6, 0, 0, 255],
                &[0x71, 1, b'b', 0x75, 2, 0x12, 8, 0x90, 0],
            ),
            (&[0, 6, 0, 0, 255], &[0x69, 0x85]),
        ]);
        let entries = list(&profile(b"1.3"), None, &mut |c| script.exchange(c)).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].name.as_bytes(), b"b");
        assert_eq!(entries[1].algorithm_type, 0x12);
        assert_eq!(entries[1].digits, Some(8));
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn add_totp_credential_transcript() {
        let credential = Credential {
            name: Name::from_bytes(b"test").unwrap(),
            kind: Kind::Totp,
            algorithm: Algorithm::Sha1,
            digits: 6,
            secret: SecretBytes::new(vec![1, 2, 3]),
            require_touch: false,
            increasing: false,
            initial_counter: 0,
        };
        let mut script = Script::new(&[
            (SELECT, SELECTION_OPEN),
            (
                &[
                    0, 1, 0, 0, 13, 0x71, 4, b't', b'e', b's', b't', 0x73, 5, 0x21, 6, 1, 2, 3,
                ],
                &[0x90, 0],
            ),
        ]);
        add(&profile(b"3.1.0"), None, credential, &mut |c| {
            script.exchange(c)
        })
        .unwrap();
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn calculate_all_reports_touch_and_hotp_markers() {
        let mut script = Script::new(&[
            (SELECT, SELECTION_OPEN),
            (
                &[0, 0xa4, 0, 1, 10, 0x74, 8, 0, 0, 0, 0, 0, 0, 0, 1, 255],
                &[0x71, 1, b'a', 0x77, 1, 6, 0x61, 255],
            ),
            (&[0, 0xa5, 0, 0, 255], &[0x71, 1, b'b', 0x7c, 1, 8, 0x90, 0]),
            (&[0, 0xa5, 0, 0, 255], &[0x90, 0]),
        ]);
        let calculations = calculate_all(
            &profile(b"3.1.0"),
            None,
            totp_challenge(30, DEFAULT_PERIOD),
            Format::Truncated,
            &mut |c| script.exchange(c),
        )
        .unwrap();
        assert_eq!(calculations.len(), 2);
        assert!(matches!(calculations[0].code, Code::Hotp));
        assert!(matches!(calculations[1].code, Code::TouchRequired));
        assert_eq!(calculations[1].name.as_ref().unwrap().as_bytes(), b"b");
        assert!(script.transcript.is_empty());
    }

    /// Fixed-challenge access for deterministic transcripts; production code
    /// uses [`access_from_key`]'s CSPRNG challenge.
    fn fixed_access() -> Access {
        Access {
            key: AccessKey::from_bytes(b"KKKKKKKKKKKKKKKK").unwrap(),
            challenge: *b"HHHHHHHH",
        }
    }

    /// The VALIDATE command for [`fixed_access`] against card challenge "CCCCCCCC".
    const VALIDATE: &[u8] = &[
        0, 0xa3, 0, 0, 32, 0x75, 20, 0x0d, 0xe0, 0xba, 0xe2, 0x81, 0xba, 0x21, 0x98, 0x0e, 0x76,
        0x92, 0xc9, 0x34, 0x52, 0x9f, 0x0f, 0x61, 0x11, 0x16, 0x51, 0x74, 8, b'H', b'H', b'H',
        b'H', b'H', b'H', b'H', b'H',
    ];
    /// The card's proof for [`fixed_access`].
    const VALIDATE_RESPONSE: &[u8] = &[
        0x75, 20, 0xca, 0xa1, 0x34, 0x6e, 0x39, 0x05, 0x8d, 0xd3, 0x6e, 0xd7, 0x6f, 0xb4, 0x90,
        0x53, 0xe1, 0x4f, 0x66, 0xce, 0x42, 0x8b, 0x90, 0,
    ];

    #[test]
    fn validate_performs_mutual_authentication() {
        let mut script = Script::new(&[(SELECT, SELECTION_LOCKED), (VALIDATE, VALIDATE_RESPONSE)]);
        validate(&profile(b"3.1.0"), fixed_access(), &mut |c| {
            script.exchange(c)
        })
        .unwrap();
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn calculate_authenticated_truncated_decimal() {
        let mut script = Script::new(&[
            (SELECT, SELECTION_LOCKED),
            (VALIDATE, VALIDATE_RESPONSE),
            (
                b"\0\xa2\0\x01\x06\x71\x04test",
                &[0x76, 5, 6, 0, 0, 0, 42, 0x90, 0],
            ),
        ]);
        let calculation = calculate(
            &profile(b"3.1.0"),
            Some(fixed_access()),
            CredentialRef {
                name: Name::from_bytes(b"test").unwrap(),
                kind: Kind::Hotp,
                algorithm: Algorithm::Sha1,
            },
            None,
            Format::Truncated,
            &mut |c| script.exchange(c),
        )
        .unwrap();
        assert_eq!(calculation.decimal().unwrap().as_bytes(), b"000042");
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn set_password_carries_derived_key_and_proof() {
        // Mirrors the canokey-oath fixture: PBKDF2("password", "12345678").
        let key_bytes = derive_key_bytes(b"password", *b"12345678");
        assert_eq!(
            &key_bytes[..],
            &[
                0xf5, 0x31, 0x15, 0x4d, 0x46, 0xd1, 0xbd, 0xbb, 0xcc, 0x1f, 0xcc, 0xe0, 0x2d, 0x6b,
                0x4c, 0x93,
            ]
        );
        let key = access_key(&key_bytes);
        let mut step = 0;
        set_password::<io::Error>(&profile(b"3.1.0"), None, key, &mut |command| {
            step += 1;
            match step {
                1 => {
                    assert_eq!(command, SELECT);
                    Ok(SELECTION_OPEN.to_vec())
                }
                2 => {
                    // 73 11 01 <16 key> 74 08 <8 challenge> 75 14 <20 proof>;
                    // challenge and proof are fresh randomness, so only the
                    // structure and the derived key bytes are checked here.
                    assert_eq!(&command[..5], &[0, 3, 0, 0, 51]);
                    assert_eq!(&command[5..8], &[0x73, 17, 1]);
                    assert_eq!(&command[8..24], &key_bytes[..]);
                    Ok(vec![0x90, 0])
                }
                _ => panic!("unexpected exchange"),
            }
        })
        .unwrap();
        assert_eq!(step, 2);
    }

    #[test]
    fn name_convention_roundtrip() {
        let parsed = parse_name(b"60/Example:alice", Kind::Totp);
        assert_eq!(parsed.issuer.as_deref(), Some("Example"));
        assert_eq!(parsed.account, "alice");
        assert_eq!(parsed.period, 60);
        assert_eq!(
            format_id(
                parsed.issuer.as_deref(),
                &parsed.account,
                Kind::Totp,
                parsed.period
            ),
            "60/Example:alice"
        );
        let parsed = parse_name(b"Example:bob", Kind::Totp);
        assert_eq!(parsed.period, DEFAULT_PERIOD);
        assert_eq!(
            format_id(
                parsed.issuer.as_deref(),
                &parsed.account,
                Kind::Totp,
                parsed.period
            ),
            "Example:bob"
        );
        let parsed = parse_name(b"issuer:counter", Kind::Hotp);
        assert_eq!(parsed.issuer.as_deref(), Some("issuer"));
        assert_eq!(parsed.account, "counter");
        assert_eq!(parsed.period, 0);
    }
}
