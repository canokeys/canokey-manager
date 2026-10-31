//! Minimal `otpauth://` URI parsing for credential import, plus the RFC 4648
//! base32 codec that account secrets are conventionally encoded with.

use canokey::oath::{Algorithm, Kind};
use zeroize::Zeroizing;

/// Credential data parsed from an `otpauth://` URI.
/// Debug output redacts the credential secret.
#[derive(Clone, PartialEq, Eq)]
pub struct OtpAuth {
    /// Counter-based or time-based credential.
    pub kind: Kind,
    /// Issuer; the query parameter wins over the label prefix.
    pub issuer: Option<String>,
    /// Account name from the label.
    pub account: String,
    /// Decoded base32 secret; zeroized on drop.
    pub secret: Zeroizing<Vec<u8>>,
    /// HMAC algorithm, SHA-1 when unspecified.
    pub algorithm: Algorithm,
    /// Decimal digit count, six when unspecified.
    pub digits: u8,
    /// TOTP period in seconds, 30 when unspecified.
    pub period: u32,
    /// Initial HOTP counter, zero when unspecified.
    pub counter: u32,
}

impl std::fmt::Debug for OtpAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtpAuth")
            .field("kind", &self.kind)
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .field("secret", &"[REDACTED]")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("counter", &self.counter)
            .finish()
    }
}

/// URI parsing failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UriError {
    /// The URI does not start with `otpauth://`.
    #[error("not an otpauth:// URI")]
    Scheme,
    /// Missing or unsupported OATH type; expected `totp` or `hotp`.
    #[error("missing or unsupported OATH type (expected totp or hotp)")]
    Kind,
    /// The label carries no account name.
    #[error("missing account name in the URI label")]
    MissingName,
    /// The mandatory `secret` parameter is absent or empty.
    #[error("missing or empty secret parameter")]
    MissingSecret,
    /// The `secret` parameter is not valid base32.
    #[error("invalid base32 secret: {0}")]
    Secret(#[from] Base32Error),
    /// Malformed percent-encoding or non-UTF-8 decoded text.
    #[error("invalid percent-encoding")]
    PercentEncoding,
    /// Unsupported `algorithm` parameter; expected SHA1, SHA256 or SHA512.
    #[error("unsupported algorithm (expected SHA1, SHA256 or SHA512)")]
    Algorithm,
    /// Malformed `digits` parameter.
    #[error("invalid digits parameter")]
    Digits,
    /// Malformed `period` parameter.
    #[error("invalid period parameter")]
    Period,
    /// A recognized query parameter occurs more than once after decoding.
    #[error("duplicate {0} parameter")]
    DuplicateParameter(&'static str),
    /// Malformed `counter` parameter, or missing for HOTP.
    #[error("missing or invalid counter parameter")]
    Counter,
}

/// Base32 decoding failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid base32 encoding")]
pub struct Base32Error;

/// Decode RFC 4648 base32, accepting lowercase and ignoring spaces and `=`
/// padding (the leniency OATH secrets are conventionally shared with).
/// Incomplete final groups and nonzero unused padding bits are rejected.
pub fn base32_decode(input: &str) -> Result<Vec<u8>, Base32Error> {
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    let mut output = Zeroizing::new(Vec::with_capacity(input.len() * 5 / 8));
    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            b'=' | b' ' => continue,
            _ => return Err(Base32Error),
        };
        accumulator = (accumulator << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
        }
    }
    // Valid unpadded lengths leave fewer than five bits, all zero padding.
    // Otherwise a truncated/mistyped secret would silently lose data.
    if bits >= 5 || accumulator & ((1 << bits) - 1) != 0 {
        return Err(Base32Error);
    }
    Ok(std::mem::take(&mut *output))
}

/// Encode as RFC 4648 base32 without padding.
pub fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut output = String::with_capacity(data.len().div_ceil(5) * 8);
    for chunk in data.chunks(5) {
        let mut accumulator = 0u64;
        for &byte in chunk {
            accumulator = (accumulator << 8) | u64::from(byte);
        }
        let digits = (chunk.len() * 8).div_ceil(5);
        accumulator <<= digits * 5 - chunk.len() * 8;
        for index in (0..digits).rev() {
            output.push(ALPHABET[(accumulator >> (index * 5)) as usize & 31] as char);
        }
    }
    output
}

fn percent_decode(input: &str) -> Result<String, UriError> {
    fn hex(byte: u8) -> Result<u8, UriError> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            b'A'..=b'F' => Ok(byte - b'A' + 10),
            _ => Err(UriError::PercentEncoding),
        }
    }
    let bytes = input.as_bytes();
    let mut output = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(UriError::PercentEncoding);
            }
            output.push((hex(bytes[index + 1])? << 4) | hex(bytes[index + 2])?);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    std::str::from_utf8(&output)
        .map(str::to_owned)
        .map_err(|_| UriError::PercentEncoding)
}

/// Parse an `otpauth://totp/...` or `otpauth://hotp/...` URI: the label is
/// `[issuer:]account`, and the `issuer` query parameter overrides the label
/// prefix. Query parameter names and values are percent-decoded; repeated
/// recognized parameters are rejected rather than silently choosing a value.
pub fn parse(uri: &str) -> Result<OtpAuth, UriError> {
    let rest = uri
        .trim()
        .strip_prefix("otpauth://")
        .ok_or(UriError::Scheme)?;
    let (kind, rest) = rest.split_once('/').ok_or(UriError::Kind)?;
    let kind = match kind {
        "totp" => Kind::Totp,
        "hotp" => Kind::Hotp,
        _ => return Err(UriError::Kind),
    };
    let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
    let label = percent_decode(label)?;
    let (label_issuer, account) = match label.split_once(':') {
        Some((issuer, account)) => (Some(issuer.to_string()), account.to_string()),
        None => (None, label),
    };
    if account.is_empty() {
        return Err(UriError::MissingName);
    }
    let mut secret = None;
    let mut issuer = label_issuer;
    let mut algorithm = Algorithm::Sha1;
    let mut digits = 6;
    let mut period = 30;
    let mut counter = None;
    const PARAMETERS: [&str; 6] = [
        "secret",
        "issuer",
        "algorithm",
        "digits",
        "period",
        "counter",
    ];
    let mut seen = [false; 6];
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = Zeroizing::new(percent_decode(key)?);
        let value = Zeroizing::new(percent_decode(value)?);
        if let Some(index) = PARAMETERS
            .iter()
            .position(|parameter| *parameter == key.as_str())
        {
            if std::mem::replace(&mut seen[index], true) {
                return Err(UriError::DuplicateParameter(PARAMETERS[index]));
            }
        }
        match key.as_str() {
            "secret" => secret = Some(Zeroizing::new(base32_decode(&value)?)),
            "issuer" => issuer = Some(value.to_string()),
            "algorithm" => {
                algorithm = match value.to_ascii_uppercase().as_str() {
                    "SHA1" => Algorithm::Sha1,
                    "SHA256" => Algorithm::Sha256,
                    "SHA512" => Algorithm::Sha512,
                    _ => return Err(UriError::Algorithm),
                }
            }
            "digits" => {
                digits = value.parse().map_err(|_| UriError::Digits)?;
                if !(4..=8).contains(&digits) {
                    return Err(UriError::Digits);
                }
            }
            "period" => {
                period = value.parse().map_err(|_| UriError::Period)?;
                if period == 0 {
                    return Err(UriError::Period);
                }
            }
            "counter" => counter = Some(value.parse().map_err(|_| UriError::Counter)?),
            _ => {}
        }
    }
    Ok(OtpAuth {
        kind,
        issuer,
        account,
        secret: secret
            .filter(|bytes| !bytes.is_empty())
            .ok_or(UriError::MissingSecret)?,
        algorithm,
        digits,
        period,
        counter: match counter {
            Some(value) => value,
            None if kind == Kind::Hotp => return Err(UriError::Counter),
            None => 0,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_parameter_names_are_percent_decoded() {
        // RFC 3986 section 6.2.2.2: percent-encoded unreserved characters
        // are equivalent to their literal form. Cross-checked with Python
        // urllib.parse.parse_qsl; '+' is deliberately not form-decoded.
        let plain = "otpauth://hotp/Issuer:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA256&digits=8&period=45&counter=17";
        let encoded = "otpauth://hotp/Issuer:alice?%73ecret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&%69ssuer=Example&%61lgorithm=SHA256&%64igits=8&%70eriod=45&%63ounter=17";
        assert_eq!(parse(encoded).unwrap(), parse(plain).unwrap());
        for key in ["%", "%7", "%ZZ", "%ff"] {
            assert_eq!(
                parse(&format!("otpauth://totp/alice?secret=MFRGGZDF&{key}=x")),
                Err(UriError::PercentEncoding)
            );
        }
    }

    #[test]
    fn duplicate_recognized_parameters_are_rejected_after_decoding() {
        for (key, value) in [
            ("secret", "MFRGGZDF"),
            ("issuer", "Example"),
            ("algorithm", "SHA1"),
            ("digits", "6"),
            ("period", "30"),
            ("counter", "1"),
        ] {
            let first = if key == "secret" {
                format!("secret={value}&")
            } else {
                format!("secret=MFRGGZDF&{key}={value}&")
            };
            for repeated in [
                key.to_string(),
                format!("%{:02x}{}", key.as_bytes()[0], &key[1..]),
            ] {
                let uri = format!("otpauth://totp/alice?{first}{repeated}={value}");
                assert_eq!(parse(&uri), Err(UriError::DuplicateParameter(key)));
            }
        }
        // Unrecognized extensions may repeat without changing a credential.
        assert!(parse("otpauth://totp/alice?secret=MFRGGZDF&x=1&x=2").is_ok());
    }

    #[test]
    fn credential_debug_redacts_secret() {
        let parsed = parse("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP").unwrap();
        let decimal_secret = format!("{:?}", parsed.secret.as_slice());
        for debug in [format!("{parsed:?}"), format!("{parsed:#?}")] {
            assert!(
                debug.contains("REDACTED"),
                "credential secret must be redacted"
            );
            assert!(!debug.contains(&decimal_secret));
            assert!(debug.contains("alice"));
            assert!(debug.contains("Example"));
        }
    }

    #[test]
    fn parses_totp_uri_with_label_issuer() {
        let parsed =
            parse("otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(parsed.kind, Kind::Totp);
        assert_eq!(parsed.issuer.as_deref(), Some("Example"));
        assert_eq!(parsed.account, "alice@example.com");
        assert_eq!(&*parsed.secret, b"Hello!\xde\xad\xbe\xef");
        assert_eq!(parsed.algorithm, Algorithm::Sha1);
        assert_eq!(parsed.digits, 6);
        assert_eq!(parsed.period, 30);
    }

    #[test]
    fn query_issuer_overrides_label_and_parameters_parse() {
        let parsed = parse(
            "otpauth://hotp/Label:bob?secret=JBSWY3DP&issuer=Query&algorithm=SHA256&digits=8&counter=42",
        )
        .unwrap();
        assert_eq!(parsed.kind, Kind::Hotp);
        assert_eq!(parsed.issuer.as_deref(), Some("Query"));
        assert_eq!(parsed.algorithm, Algorithm::Sha256);
        assert_eq!(parsed.digits, 8);
        assert_eq!(parsed.counter, 42);
    }

    #[test]
    fn percent_decoding_applies_to_label_and_params() {
        let parsed =
            parse("otpauth://totp/Issuer%20A:alice?secret=MFRGGZDF&issuer=Issuer%20B").unwrap();
        assert_eq!(parsed.issuer.as_deref(), Some("Issuer B"));
        assert_eq!(parsed.account, "alice");
    }

    #[test]
    fn base32_rejects_incomplete_groups_and_nonzero_padding_bits() {
        for bad in ["M", "MZX", "MZXW6Y", "MZ", "MZXR", "MZXW7", "MZXW6YR"] {
            assert!(base32_decode(bad).is_err(), "{bad}");
        }
        for len in 0..80 {
            let bytes: Vec<u8> = (0..len).map(|index| (index * 37) as u8).collect();
            assert_eq!(base32_decode(&base32_encode(&bytes)).unwrap(), bytes);
        }
    }

    #[test]
    fn uri_requires_a_hotp_counter_and_valid_credential_fields() {
        assert_eq!(
            parse("otpauth://hotp/x?secret=MY").unwrap_err(),
            UriError::Counter
        );
        // Zero is a valid URI value; hardware representability is a CLI check.
        assert_eq!(
            parse("otpauth://hotp/x?secret=MY&counter=0")
                .unwrap()
                .counter,
            0
        );
        for digits in [0, 3, 9, 255] {
            assert_eq!(
                parse(&format!("otpauth://totp/x?secret=MY&digits={digits}")).unwrap_err(),
                UriError::Digits
            );
        }
        for secret in ["", "==", "   "] {
            assert_eq!(
                parse(&format!("otpauth://totp/x?secret={secret}")).unwrap_err(),
                UriError::MissingSecret
            );
        }
    }

    #[test]
    fn base32_vectors_and_leniency() {
        assert_eq!(base32_decode("MY").unwrap(), b"f");
        assert_eq!(base32_decode("MZXW6===").unwrap(), b"foo");
        assert_eq!(base32_decode("mzxw 6ytb").unwrap(), b"fooba");
        assert!(base32_decode("MZX1").is_err());
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
        assert_eq!(base32_encode(b"Hello!\xde\xad\xbe\xef"), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn base32_rfc4648_vectors_cover_partial_groups() {
        for (raw, encoded) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32_encode(raw.as_bytes()), encoded);
            assert_eq!(base32_decode(encoded).unwrap(), raw.as_bytes());
        }
    }

    #[test]
    fn rejects_malformed_uris() {
        assert_eq!(
            parse("otpauth://totp/x?secret=MY&period=0").unwrap_err(),
            UriError::Period
        );

        assert_eq!(
            parse("https://totp/x?secret=MY").unwrap_err(),
            UriError::Scheme
        );
        assert_eq!(
            parse("otpauth://x/y?secret=MY").unwrap_err(),
            UriError::Kind
        );
        assert_eq!(
            parse("otpauth://totp/x").unwrap_err(),
            UriError::MissingSecret
        );
        assert_eq!(
            parse("otpauth://totp/x?secret=M1").unwrap_err(),
            UriError::Secret(Base32Error)
        );
    }
}
