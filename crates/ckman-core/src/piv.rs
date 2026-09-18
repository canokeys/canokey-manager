//! Typed wrappers around `canokey::piv` operations, plus the ykman "pivman"
//! management-key model (PIN-derived keys and PIN-protected on-device key
//! storage) and host-side certificate/CSR generation whose private-key
//! signature runs on the device.
//!
//! As in the OATH wrappers, every operation re-SELECTs the PIV applet and
//! re-authenticates from owned credentials; nothing here caches login state.
//! PINs/PUKs are 6-8 byte credentials enforced by [`Pin`]/[`Puk`]; the
//! management key is 24 bytes of 3DES or AES-192.
//!
//! The pivman metadata lives in two PIV objects: ADMIN DATA (5FFF00) carries
//! the protection flags and the derivation salt, PRINTED (5FC109) stores the
//! PIN-protected management key itself.

use crate::{execute, DriveError, Exchange};
use canokey::piv::{self, SelectionInfo};
use canokey::tlv::{Tag, TlvReader, TlvWriter};
use canokey::{DeviceProfile, Error, ErrorKind, OperationOptions, Phase, SecretBytes};
use zeroize::Zeroizing;

pub use crate::x509::HashAlgorithm;
pub use canokey::piv::{sign_streaming, StreamingSignInput};
pub use canokey::piv::{
    Access, Algorithm, Certificate, KeyOrigin, KeyParameters, KnownOrUnknown,
    ManagementAuthentication, ManagementKey, ManagementKeyAlgorithm, ManagementTouchPolicy,
    Metadata, MetadataReference, MutationResult, ObjectId, Pin, PinPolicy, PinStatus,
    PrivateKeyMaterial, PublicKey, Puk, RetiredSlot, SignInput, Signature, Slot, TouchPolicy,
};

/// Failure preparing or driving a PIV operation.
#[derive(Debug, thiserror::Error)]
pub enum PivError<E> {
    /// Transport or protocol failure while driving the operation.
    #[error(transparent)]
    Drive(#[from] DriveError<E>),
    /// The host CSPRNG failed before any I/O; nothing was sent to the card.
    #[error("failed to generate randomness: {0}")]
    Random(#[from] getrandom::Error),
    /// Host-side X.509 building failed.
    #[error(transparent)]
    X509(#[from] crate::x509::X509Error),
    /// Host-side key-file parsing failed.
    #[error(transparent)]
    Key(#[from] crate::keys::KeyError),
}

impl<E> PivError<E> {
    pub(crate) fn protocol(kind: ErrorKind) -> Self {
        Self::Drive(DriveError::Protocol(Error::new(kind)))
    }
}

fn run<T, E>(
    operation: Result<canokey::Operation<T>, Error>,
    exchange: &mut Exchange<'_, E>,
) -> Result<T, PivError<E>> {
    Ok(execute(operation.map_err(DriveError::from)?, exchange)?)
}

fn options() -> OperationOptions {
    OperationOptions::default()
}

/// The factory-default 3DES management key, documented for the user after a
/// reset. It is never submitted implicitly.
pub const DEFAULT_MANAGEMENT_KEY: [u8; 24] = [
    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
];

/// The default management key as a typed 3DES key.
pub fn default_management_key() -> ManagementKey {
    ManagementKey::from_bytes(ManagementKeyAlgorithm::Tdes, &DEFAULT_MANAGEMENT_KEY)
        .expect("the default management key is 24 bytes")
}

/// Generate a fresh random management key for the algorithm.
pub fn random_management_key(
    algorithm: ManagementKeyAlgorithm,
) -> Result<ManagementKey, getrandom::Error> {
    let mut bytes = Zeroizing::new([0; 24]);
    getrandom::fill(&mut bytes[..])?;
    ManagementKey::from_bytes(algorithm, &bytes[..]).map_err(|_| getrandom::Error::new_custom(0))
}

/// Mutual management authentication with a fresh CSPRNG challenge; prefer
/// this over [`external_auth`] so the card is authenticated too.
pub fn mutual_auth(key: ManagementKey) -> Result<ManagementAuthentication, getrandom::Error> {
    let mut challenge = Zeroizing::new(vec![0; key.algorithm().block_len()]);
    getrandom::fill(&mut challenge[..])?;
    ManagementAuthentication::mutual(key, &challenge[..])
        .map_err(|_| getrandom::Error::new_custom(0))
}

/// External management authentication; does not authenticate the card.
pub fn external_auth(key: ManagementKey) -> ManagementAuthentication {
    ManagementAuthentication::external(key)
}

// --- PIN/PUK -------------------------------------------------------------

/// Empty-VERIFY status query: verified flag and remaining retries.
pub fn pin_status<E>(
    profile: &DeviceProfile,
    exchange: &mut Exchange<'_, E>,
) -> Result<PinStatus, PivError<E>> {
    run(piv::get_pin_status(profile, options()), exchange)
}

/// Verify the PIN explicitly; no persistent authorization token results.
pub fn verify_pin<E>(
    profile: &DeviceProfile,
    pin: Pin,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), PivError<E>> {
    run(piv::verify_pin(profile, pin, options()), exchange)
}

/// Clear PIN verification state on the card.
pub fn logout<E>(
    profile: &DeviceProfile,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), PivError<E>> {
    run(piv::logout(profile, options()), exchange)
}

/// Change the user PIN. Use [`change_pin_synced`] to keep a PIN-derived
/// management key working afterwards.
pub fn change_pin<E>(
    profile: &DeviceProfile,
    old: Pin,
    new: Pin,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), PivError<E>> {
    run(piv::change_pin(profile, old, new, options()), exchange)?;
    Ok(())
}

/// Change the PUK.
pub fn change_puk<E>(
    profile: &DeviceProfile,
    old: Puk,
    new: Puk,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), PivError<E>> {
    run(piv::change_puk(profile, old, new, options()), exchange)?;
    Ok(())
}

/// Unblock and replace the PIN using the PUK.
pub fn unblock_pin<E>(
    profile: &DeviceProfile,
    puk: Puk,
    new_pin: Pin,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), PivError<E>> {
    run(piv::unblock_pin(profile, puk, new_pin, options()), exchange)?;
    Ok(())
}

/// Set PIN/PUK retry limits, resetting both to the firmware defaults
/// (123456 / 12345678). Firmware limits each to 1..=15. Requires management
/// and PIN access; the caller's PIN must be the current one.
pub fn set_retries<E>(
    profile: &DeviceProfile,
    pin_retries: u8,
    puk_retries: u8,
    access: piv::Access,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), PivError<E>> {
    run(
        piv::reset_pin_puk_retries(profile, pin_retries, puk_retries, access, options()),
        exchange,
    )?;
    Ok(())
}

// --- Management key --------------------------------------------------------

/// Recover the PIN-protected management key stored in PRINTED, mirroring
/// ykman's protected-key authentication: requires PIN access and ADMIN DATA
/// claiming both PIN protection and a blocked PUK. Returns the verified
/// 24-byte key.
pub fn pin_managed_key<E>(
    profile: &DeviceProfile,
    pin: Pin,
    exchange: &mut Exchange<'_, E>,
) -> Result<SecretBytes, PivError<E>> {
    run(
        piv::protection::pin_managed(profile, None, piv::Access::Pin(pin), options()),
        exchange,
    )
}

/// Perform one standalone management-key authentication (selects PIV first).
pub fn authenticate<E>(
    profile: &DeviceProfile,
    auth: ManagementAuthentication,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), PivError<E>> {
    run(
        piv::authenticate_management_key(profile, auth, true, options()),
        exchange,
    )
}

/// Replace the management key, without touching pivman metadata. Use
/// [`set_management_key_synced`] to keep ADMIN DATA / PRINTED in sync.
pub fn set_management_key<E>(
    profile: &DeviceProfile,
    key: ManagementKey,
    touch: ManagementTouchPolicy,
    access: piv::Access,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), PivError<E>> {
    run(
        piv::set_management_key(profile, key, touch, false, access, options()),
        exchange,
    )?;
    Ok(())
}

// --- Objects and certificates ----------------------------------------------

/// Read a PIV object (the value inside its 53 container).
pub fn read_object<E>(
    profile: &DeviceProfile,
    id: ObjectId,
    access: piv::Access,
    exchange: &mut Exchange<'_, E>,
) -> Result<SecretBytes, PivError<E>> {
    run(piv::read_object(profile, id, access, options()), exchange)
}

/// Write a PIV object value (without the outer 53 container); requires
/// management access.
pub fn write_object<E>(
    profile: &DeviceProfile,
    id: ObjectId,
    data: SecretBytes,
    access: piv::Access,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), PivError<E>> {
    run(
        piv::write_object(profile, id, data, access, options()),
        exchange,
    )?;
    Ok(())
}

/// Read and unwrap a certificate (gzip handled by libcanokey); no X.509
/// validation is performed.
pub fn read_certificate<E>(
    profile: &DeviceProfile,
    slot: Slot,
    access: piv::Access,
    exchange: &mut Exchange<'_, E>,
) -> Result<Certificate, PivError<E>> {
    run(
        piv::read_certificate(profile, slot, access, options()),
        exchange,
    )
}

/// Store an uncompressed certificate payload.
pub fn write_certificate<E>(
    profile: &DeviceProfile,
    slot: Slot,
    der: SecretBytes,
    access: piv::Access,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), PivError<E>> {
    run(
        piv::write_certificate(profile, slot, der, access, options()),
        exchange,
    )?;
    Ok(())
}

/// Delete a certificate, retaining its key (requires 3.1.0 certificate
/// deletion support).
pub fn delete_certificate<E>(
    profile: &DeviceProfile,
    slot: Slot,
    access: piv::Access,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), PivError<E>> {
    run(
        piv::delete_certificate(profile, slot, access, options()),
        exchange,
    )?;
    Ok(())
}

// --- Keys ------------------------------------------------------------------

/// Read one key/PIN/PUK/management metadata record.
pub fn metadata<E>(
    profile: &DeviceProfile,
    reference: MetadataReference,
    access: piv::Access,
    exchange: &mut Exchange<'_, E>,
) -> Result<Metadata, PivError<E>> {
    run(
        piv::get_metadata(profile, reference, access, options()),
        exchange,
    )
}

/// Generate a key pair on-device; returns the public key (SPKI-encodable).
pub fn generate_key<E>(
    profile: &DeviceProfile,
    parameters: KeyParameters,
    access: piv::Access,
    exchange: &mut Exchange<'_, E>,
) -> Result<PublicKey, PivError<E>> {
    run(
        piv::generate_key(profile, parameters, access, options()),
        exchange,
    )
}

/// Import caller-owned private key material.
pub fn import_key<E>(
    profile: &DeviceProfile,
    parameters: KeyParameters,
    material: PrivateKeyMaterial,
    access: piv::Access,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), PivError<E>> {
    run(
        piv::import_key(profile, parameters, material, access, options()),
        exchange,
    )?;
    Ok(())
}

/// Delete a key (certificate and name handling per firmware); capability-gated.
pub fn delete_key<E>(
    profile: &DeviceProfile,
    slot: Slot,
    access: piv::Access,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), PivError<E>> {
    run(piv::delete_key(profile, slot, access, options()), exchange)?;
    Ok(())
}

/// Move a key to an empty slot; capability-gated.
pub fn move_key<E>(
    profile: &DeviceProfile,
    source: Slot,
    target: Slot,
    access: piv::Access,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), PivError<E>> {
    run(
        piv::move_key(profile, source, target, access, options()),
        exchange,
    )?;
    Ok(())
}

/// Request a device-generated attestation certificate (opaque DER).
pub fn attest<E>(
    profile: &DeviceProfile,
    slot: Slot,
    exchange: &mut Exchange<'_, E>,
) -> Result<Vec<u8>, PivError<E>> {
    Ok(run(piv::attest(profile, slot, true, options()), exchange)?
        .as_bytes()
        .to_vec())
}

/// Select PIV without further commands (raw selection data).
pub fn select<E>(
    profile: &DeviceProfile,
    exchange: &mut Exchange<'_, E>,
) -> Result<SelectionInfo, PivError<E>> {
    run(piv::select(profile, options()), exchange)
}

/// Sign one explicitly prepared input; hashing/padding is the caller's job
/// (see [`sign_message`] for the certificate-oriented form).
pub fn sign<E>(
    profile: &DeviceProfile,
    slot: Slot,
    algorithm: Algorithm,
    input: SignInput,
    access: piv::Access,
    exchange: &mut Exchange<'_, E>,
) -> Result<Signature, PivError<E>> {
    run(
        piv::sign(profile, slot, algorithm, input, access, options()),
        exchange,
    )
}

// --- Host-side signing for certificates/CSRs ---------------------------------

/// Hash and (for RSA) pad `message`, sign it with the slot key, and return
/// the signature in certificate encoding (raw RSA / DER ECDSA / raw Ed25519).
pub fn sign_message<E>(
    profile: &DeviceProfile,
    slot: Slot,
    algorithm: Algorithm,
    hash: Option<HashAlgorithm>,
    message: &[u8],
    access: piv::Access,
    exchange: &mut Exchange<'_, E>,
) -> Result<Vec<u8>, PivError<E>> {
    let signature = match algorithm {
        Algorithm::Rsa1024 | Algorithm::Rsa2048 | Algorithm::Rsa3072 | Algorithm::Rsa4096 => {
            let width = match algorithm {
                Algorithm::Rsa1024 => 128,
                Algorithm::Rsa2048 => 256,
                Algorithm::Rsa3072 => 384,
                _ => 512,
            };
            let encoded = crate::x509::rsa_pkcs1v15_encode(
                hash.ok_or(crate::x509::X509Error::UnsupportedHash)?,
                message,
                width,
            )?;
            sign(
                profile,
                slot,
                algorithm,
                SignInput::RsaEncodedBlock(SecretBytes::new(encoded)),
                access,
                exchange,
            )?
        }
        Algorithm::EccP256 | Algorithm::EccP384 | Algorithm::EccP521 | Algorithm::Secp256k1 => {
            let digest = hash
                .ok_or(crate::x509::X509Error::UnsupportedHash)?
                .hash(message);
            sign(
                profile,
                slot,
                algorithm,
                SignInput::Digest(SecretBytes::new(digest)),
                access,
                exchange,
            )?
        }
        Algorithm::Ed25519 => sign(
            profile,
            slot,
            algorithm,
            SignInput::Message(SecretBytes::new(message.to_vec())),
            access,
            exchange,
        )?,
        // Firmware computes SM3(ZA || M) itself; the default user ID applies.
        Algorithm::Sm2 => run(
            sign_streaming(
                profile,
                slot,
                StreamingSignInput::Sm2 {
                    message: SecretBytes::new(message.to_vec()),
                    user_id: None,
                },
                access,
                options(),
            ),
            exchange,
        )?,
        // Pure ML-DSA-65 with the firmware's hardcoded empty context.
        Algorithm::MlDsa65 => run(
            sign_streaming(
                profile,
                slot,
                StreamingSignInput::MlDsa65(SecretBytes::new(message.to_vec())),
                access,
                options(),
            ),
            exchange,
        )?,
        Algorithm::X25519 => {
            return Err(PivError::X509(crate::x509::X509Error::NotSigning("X25519")))
        }
        Algorithm::MlKem768 => {
            return Err(PivError::X509(crate::x509::X509Error::NotSigning(
                "ML-KEM-768",
            )))
        }
    };
    // EC signatures arrive as DER already; RSA/Ed25519 are raw.
    Ok(signature.as_bytes().to_vec())
}

/// Inputs for on-device certificate/CSR signing.
#[derive(Debug)]
pub struct SignRequest<'a> {
    /// Slot holding the signing key.
    pub slot: Slot,
    /// Key algorithm; must match the slot key.
    pub algorithm: Algorithm,
    /// SubjectPublicKeyInfo DER of the slot's public key.
    pub spki_der: &'a [u8],
    /// Subject as an RFC 4514 string.
    pub subject: &'a str,
    /// Hash for RSA/ECDSA; `None` selects PureEdDSA for Ed25519.
    pub hash: Option<HashAlgorithm>,
    /// PIN access (management too when the certificate is written after).
    pub access: piv::Access,
}

/// Generate a self-signed certificate, signing with the slot key on-device.
/// The serial is 16 fresh random bytes with the sign bit cleared. Returns
/// certificate DER.
pub fn generate_self_signed_certificate<E>(
    profile: &DeviceProfile,
    request: &SignRequest<'_>,
    not_before: i64,
    not_after: i64,
    exchange: &mut Exchange<'_, E>,
) -> Result<Vec<u8>, PivError<E>> {
    let subject = crate::x509::parse_rfc4514(request.subject)?;
    let signature_algorithm = crate::x509::signature_algorithm(request.algorithm, request.hash)?;
    let mut serial = [0; 16];
    getrandom::fill(&mut serial)?;
    serial[0] &= 0x7f; // Keep the serial INTEGER positive.
    let tbs = crate::x509::tbs_self_signed(
        request.spki_der,
        &subject,
        &serial,
        not_before,
        not_after,
        signature_algorithm.clone(),
    )?;
    // The signing access is borrowed per call; clone for the owned request.
    let signature = sign_message(
        profile,
        request.slot,
        request.algorithm,
        request.hash,
        &tbs,
        request.access.clone(),
        exchange,
    )?;
    Ok(crate::x509::assemble_certificate(
        &tbs,
        signature_algorithm,
        &signature,
    )?)
}

/// Generate a CSR, signing with the slot key on-device. Returns CSR DER.
pub fn generate_csr<E>(
    profile: &DeviceProfile,
    request: &SignRequest<'_>,
    exchange: &mut Exchange<'_, E>,
) -> Result<Vec<u8>, PivError<E>> {
    let subject = crate::x509::parse_rfc4514(request.subject)?;
    let signature_algorithm = crate::x509::signature_algorithm(request.algorithm, request.hash)?;
    let cri = crate::x509::certification_request_info(request.spki_der, &subject)?;
    let signature = sign_message(
        profile,
        request.slot,
        request.algorithm,
        request.hash,
        &cri,
        request.access.clone(),
        exchange,
    )?;
    Ok(crate::x509::assemble_csr(
        &cri,
        signature_algorithm,
        &signature,
    )?)
}

// --- pivman: the ykman management-key data model ------------------------------

/// ADMIN DATA object identifier (5FFF00), holding pivman flags and the
/// PIN-derivation salt.
pub fn pivman_object_id() -> ObjectId {
    ObjectId::from_bytes(&[0x5f, 0xff, 0]).expect("fixed object id")
}

/// PRINTED object identifier (5FC109), holding the PIN-protected management key.
pub fn pivman_protected_object_id() -> ObjectId {
    ObjectId::from_bytes(&[0x5f, 0xc1, 9]).expect("fixed object id")
}

/// Derive a 24-byte 3DES management key from the user PIN and a salt:
/// PBKDF2-HMAC-SHA1, 10000 iterations. Deprecated by ykman in favor of the
/// PIN-protected stored key; kept for compatibility with existing devices.
pub fn derive_management_key(pin: &[u8], salt: &[u8]) -> Zeroizing<[u8; 24]> {
    let mut output = Zeroizing::new([0; 24]);
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(pin, salt, 10000, output.as_mut());
    output
}

/// The parsed ADMIN DATA (pivman) value, mirroring ykman's `PivmanData`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PivmanData {
    /// Flag byte: bit 0 = PUK blocked, bit 1 = management key stored on device.
    pub flags: Option<u8>,
    /// Salt for the (deprecated) PIN-derived management key.
    pub salt: Option<Vec<u8>>,
    /// Last PIN-change timestamp.
    pub pin_timestamp: Option<u32>,
}

impl PivmanData {
    /// Parse the object value (the content of the outer 53 tag): `80 { 81
    /// flags, 82 salt, 83 timestamp }`. Empty input is valid unconfigured data.
    pub fn from_value(value: &[u8]) -> Result<Self, Error> {
        let invalid = || Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing);
        if value.is_empty() {
            return Ok(Self::default());
        }
        let mut reader = TlvReader::new_ber(value, Default::default());
        let outer = reader.next()?.ok_or_else(invalid)?;
        if outer.tag.value() != 0x80 || reader.next()?.is_some() {
            return Err(invalid());
        }
        let mut data = Self::default();
        if outer.value.is_empty() {
            return Ok(data);
        }
        let mut inner = TlvReader::new_ber(outer.value, Default::default());
        while let Some(field) = inner.next()? {
            match field.tag.value() {
                0x81 if data.flags.is_none() && field.value.len() == 1 => {
                    data.flags = Some(field.value[0])
                }
                0x82 if data.salt.is_none() => data.salt = Some(field.value.to_vec()),
                0x83 if data.pin_timestamp.is_none() && field.value.len() == 4 => {
                    data.pin_timestamp = Some(u32::from_be_bytes(field.value.try_into().unwrap()))
                }
                _ => return Err(invalid()),
            }
        }
        Ok(data)
    }

    /// Encode the object value; empty when nothing is configured (writing an
    /// empty value deletes the object firmware-side).
    pub fn to_value(&self) -> Vec<u8> {
        let mut inner = TlvWriter::default();
        if let Some(flags) = self.flags {
            inner
                .push(Tag::from_bytes(&[0x81]).unwrap(), &[flags])
                .unwrap();
        }
        if let Some(salt) = &self.salt {
            inner.push(Tag::from_bytes(&[0x82]).unwrap(), salt).unwrap();
        }
        if let Some(timestamp) = self.pin_timestamp {
            inner
                .push(Tag::from_bytes(&[0x83]).unwrap(), &timestamp.to_be_bytes())
                .unwrap();
        }
        let inner = inner.into_bytes();
        if inner.as_bytes().is_empty() {
            return Vec::new();
        }
        let mut outer = TlvWriter::default();
        outer
            .push(Tag::from_bytes(&[0x80]).unwrap(), inner.as_bytes())
            .unwrap();
        outer.into_bytes().as_bytes().to_vec()
    }

    /// Whether the flags claim a blocked PUK (verify live retries separately).
    pub fn puk_blocked(&self) -> bool {
        self.flags.unwrap_or(0) & 1 != 0
    }

    /// Whether a management key is stored on-device, protected by PIN.
    pub fn has_stored_key(&self) -> bool {
        self.flags.unwrap_or(0) & 2 != 0
    }

    /// Whether a PIN-derived management key is in use.
    pub fn has_derived_key(&self) -> bool {
        self.salt.is_some()
    }

    fn set_flag(&mut self, mask: u8, value: bool) {
        if value {
            self.flags = Some(self.flags.unwrap_or(0) | mask);
        } else if let Some(flags) = &mut self.flags {
            *flags &= !mask;
        }
    }

    /// Set the stored-key flag.
    pub fn set_stored_key(&mut self, value: bool) {
        self.set_flag(2, value);
    }

    /// Set the PUK-blocked flag.
    pub fn set_puk_blocked(&mut self, value: bool) {
        self.set_flag(1, value);
    }
}

/// The parsed PRINTED object value, mirroring ykman's `PivmanProtectedData`.
#[derive(Clone, Debug, Default)]
pub struct PivmanProtectedData {
    /// The stored 24-byte management key, when present.
    pub key: Option<SecretBytes>,
}

impl PivmanProtectedData {
    /// Parse the object value: `88 { 89 key }`.
    pub fn from_value(value: &[u8]) -> Result<Self, Error> {
        let invalid = || Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing);
        if value.is_empty() {
            return Ok(Self::default());
        }
        let mut reader = TlvReader::new_ber(value, Default::default());
        let outer = reader.next()?.ok_or_else(invalid)?;
        if outer.tag.value() != 0x88 || reader.next()?.is_some() {
            return Err(invalid());
        }
        if outer.value.is_empty() {
            return Ok(Self::default());
        }
        let mut inner = TlvReader::new_ber(outer.value, Default::default());
        let field = inner.next()?.ok_or_else(invalid)?;
        if field.tag.value() != 0x89 || field.value.len() != 24 || inner.next()?.is_some() {
            return Err(invalid());
        }
        Ok(Self {
            key: Some(SecretBytes::new(field.value.to_vec())),
        })
    }

    /// Encode the object value (`88 {}` when the key is cleared).
    pub fn to_value(&self) -> Vec<u8> {
        let mut inner = TlvWriter::default();
        if let Some(key) = &self.key {
            inner
                .push(Tag::from_bytes(&[0x89]).unwrap(), key.as_bytes())
                .unwrap();
        }
        let mut outer = TlvWriter::default();
        outer
            .push(
                Tag::from_bytes(&[0x88]).unwrap(),
                inner.into_bytes().as_bytes(),
            )
            .unwrap();
        outer.into_bytes().as_bytes().to_vec()
    }
}

/// Read ADMIN DATA, tolerating a missing object as unconfigured.
pub fn read_pivman_data<E>(
    profile: &DeviceProfile,
    exchange: &mut Exchange<'_, E>,
) -> Result<PivmanData, PivError<E>> {
    match read_object(profile, pivman_object_id(), piv::Access::None, exchange) {
        Ok(value) => PivmanData::from_value(value.as_bytes())
            .map_err(|e| PivError::Drive(DriveError::Protocol(e))),
        Err(PivError::Drive(DriveError::Protocol(error))) if error.kind == ErrorKind::NotFound => {
            Ok(PivmanData::default())
        }
        Err(error) => Err(error),
    }
}

/// Read the PIN-protected PRINTED object. The caller must supply PIN access.
pub fn read_pivman_protected<E>(
    profile: &DeviceProfile,
    access: piv::Access,
    exchange: &mut Exchange<'_, E>,
) -> Result<PivmanProtectedData, PivError<E>> {
    match read_object(profile, pivman_protected_object_id(), access, exchange) {
        Ok(value) => PivmanProtectedData::from_value(value.as_bytes())
            .map_err(|e| PivError::Drive(DriveError::Protocol(e))),
        Err(PivError::Drive(DriveError::Protocol(error))) if error.kind == ErrorKind::NotFound => {
            Ok(PivmanProtectedData::default())
        }
        Err(error) => Err(error),
    }
}

/// A management-key replacement, keeping pivman metadata in sync.
#[derive(Debug)]
pub struct ManagementKeyUpdate {
    /// The new 24-byte management key.
    pub new_key_bytes: [u8; 24],
    /// Its algorithm.
    pub algorithm: ManagementKeyAlgorithm,
    /// Touch requirement (AES-192 only).
    pub touch: ManagementTouchPolicy,
    /// Store the key on-device, protected by PIN.
    pub protect: bool,
    /// PIN, required when `protect` is set or an old stored key is cleared.
    pub pin: Option<Pin>,
    /// Authentication with the current management key.
    pub access: piv::Access,
}

/// Replace the management key while keeping pivman metadata in sync,
/// mirroring ykman's `pivman_set_mgm_key`: clears the derivation salt, tracks
/// the stored-key flag in ADMIN DATA, and stores/clears the key in PRINTED.
/// Follow-up writes authenticate externally with the new key within the same
/// connection. The PIN is verified adjacent to the protected-object writes.
pub fn set_management_key_synced<E>(
    profile: &DeviceProfile,
    update: ManagementKeyUpdate,
    exchange: &mut Exchange<'_, E>,
) -> Result<(), PivError<E>> {
    let ManagementKeyUpdate {
        new_key_bytes,
        algorithm,
        touch,
        protect,
        pin,
        access,
    } = update;
    let new_key_bytes = &new_key_bytes;
    let new_key = ManagementKey::from_bytes(algorithm, new_key_bytes).map_err(DriveError::from)?;
    let pivman = read_pivman_data(profile, exchange)?;
    // Ensure protected-data access before committing the key replacement.
    let protected = if protect || pivman.has_stored_key() {
        let pin = pin
            .clone()
            .ok_or_else(|| PivError::protocol(ErrorKind::SecurityStatusNotSatisfied))?;
        Some(read_pivman_protected(
            profile,
            piv::Access::Pin(pin),
            exchange,
        )?)
    } else {
        None
    };
    let old_value = pivman.to_value();
    set_management_key(profile, new_key.clone(), touch, access, exchange)?;
    let mut updated = pivman.clone();
    if updated.has_derived_key() {
        updated.salt = None;
    }
    updated.set_stored_key(protect);
    if updated.to_value() != old_value {
        let auth = external_auth(new_key.clone());
        write_object(
            profile,
            pivman_object_id(),
            SecretBytes::new(updated.to_value()),
            piv::Access::Management(auth),
            exchange,
        )?;
    }
    if let Some(mut protected) = protected {
        if protect {
            protected.key = Some(SecretBytes::new(new_key_bytes.to_vec()));
        } else if protected.key.is_some() {
            protected.key = None;
        } else {
            return Ok(());
        }
        let pin = pin.expect("PIN presence checked above");
        let auth = external_auth(new_key);
        write_object(
            profile,
            pivman_protected_object_id(),
            SecretBytes::new(protected.to_value()),
            piv::Access::PinAndManagement {
                pin,
                management: auth,
            },
            exchange,
        )?;
    }
    Ok(())
}

/// Change the PIN while keeping a PIN-derived management key working,
/// mirroring ykman's `pivman_change_pin`: after the change, re-derive with a
/// fresh salt and rotate the management key. Raw PIN bytes are required for
/// the derivation.
pub fn change_pin_synced<E>(
    profile: &DeviceProfile,
    old_pin: &[u8],
    new_pin: &[u8],
    exchange: &mut Exchange<'_, E>,
) -> Result<(), PivError<E>> {
    change_pin(
        profile,
        Pin::from_bytes(old_pin).map_err(DriveError::from)?,
        Pin::from_bytes(new_pin).map_err(DriveError::from)?,
        exchange,
    )?;
    let pivman = read_pivman_data(profile, exchange)?;
    if !pivman.has_derived_key() {
        return Ok(());
    }
    let salt = pivman.salt.as_ref().expect("derived key has a salt");
    let old_key = ManagementKey::from_bytes(
        ManagementKeyAlgorithm::Tdes,
        derive_management_key(old_pin, salt).as_slice(),
    )
    .map_err(DriveError::from)?;
    // Prove the old key before rotating, then verify the new PIN.
    authenticate(profile, external_auth(old_key.clone()), exchange)?;
    verify_pin(
        profile,
        Pin::from_bytes(new_pin).map_err(DriveError::from)?,
        exchange,
    )?;
    let mut new_salt = [0; 16];
    getrandom::fill(&mut new_salt)?;
    let new_key = ManagementKey::from_bytes(
        ManagementKeyAlgorithm::Tdes,
        derive_management_key(new_pin, &new_salt).as_slice(),
    )
    .map_err(DriveError::from)?;
    set_management_key(
        profile,
        new_key.clone(),
        ManagementTouchPolicy::Never,
        piv::Access::Management(external_auth(old_key)),
        exchange,
    )?;
    let mut updated = pivman;
    updated.salt = Some(new_salt.to_vec());
    write_object(
        profile,
        pivman_object_id(),
        SecretBytes::new(updated.to_value()),
        piv::Access::Management(external_auth(new_key)),
        exchange,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use canokey::compatibility::{AlgorithmConfig, DeviceObservations, PivApplicationVersion};
    use std::collections::VecDeque;
    use std::io;

    /// Transcript-driven exchange, mirroring the probe tests in `lib.rs`.
    struct Script {
        transcript: VecDeque<(Vec<u8>, Vec<u8>)>,
    }

    impl Script {
        fn new(transcript: &[(&[u8], &[u8])]) -> Self {
            Script {
                transcript: transcript
                    .iter()
                    .map(|(c, r)| (c.to_vec(), r.to_vec()))
                    .collect(),
            }
        }
        fn exchange(&mut self, command: &[u8]) -> io::Result<Vec<u8>> {
            let (expected, response) = self
                .transcript
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "unexpected exchange"))?;
            assert_eq!(command, expected, "command differs from transcript");
            Ok(response)
        }
    }

    fn profile(version: &str) -> DeviceProfile {
        let mut o = DeviceObservations::new(version.as_bytes().to_vec());
        o.piv_version = Some(PivApplicationVersion([5, 7, 0]));
        o.algorithm_config = Some(
            AlgorithmConfig::parse(&[1, 0xe0, 5, 0x16, 0xe1, 0x53, 0x54, 0x55, 0x56, 0x57])
                .unwrap(),
        );
        DeviceProfile::from_observations(o).unwrap()
    }

    const SELECT: &[u8] = &[0, 0xa4, 4, 0, 5, 0xa0, 0, 0, 3, 8];
    const SELECT_LE: &[u8] = &[0, 0xa4, 4, 0, 5, 0xa0, 0, 0, 3, 8, 0];
    const OK: &[u8] = &[0x90, 0];
    const VERIFY_123456: &[u8] = b"\0\x20\0\x80\x08123456\xff\xff";

    /// AES-192 external authentication with key 00..17 (libcanokey fixture).
    const AES_AUTH: &[(&[u8], &[u8])] = &[
        (SELECT, OK),
        (
            &[0, 0x87, 0x0a, 0x9b, 4, 0x7c, 2, 0x81, 0],
            &[
                0x7c, 0x12, 0x81, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x90, 0,
            ],
        ),
        (
            &[
                0, 0x87, 0x0a, 0x9b, 0x14, 0x7c, 0x12, 0x82, 0x10, 0xdd, 0xa9, 0x7c, 0xa4, 0x86,
                0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
            ],
            OK,
        ),
    ];

    fn aes_access() -> piv::Access {
        piv::Access::Management(ManagementAuthentication::external(
            ManagementKey::from_bytes(
                ManagementKeyAlgorithm::Aes192,
                &(0u8..24).collect::<Vec<_>>(),
            )
            .unwrap(),
        ))
    }

    #[test]
    fn pin_verify_reports_retries_and_never_retries() {
        let mut script = Script::new(&[(SELECT, OK), (VERIFY_123456, &[0x63, 0xc2])]);
        let error = verify_pin(
            &profile("3.1.0"),
            Pin::from_bytes(b"123456").unwrap(),
            &mut |c| script.exchange(c),
        )
        .unwrap_err();
        match error {
            PivError::Drive(DriveError::Protocol(error)) => {
                assert_eq!(error.kind, ErrorKind::AuthenticationFailed);
                assert_eq!(error.retries_remaining, Some(2));
                assert_eq!(error.reference, Some(canokey::SecretReference::Pin));
            }
            other => panic!("unexpected error: {other}"),
        }
        assert!(
            script.transcript.is_empty(),
            "a failed VERIFY is never retried"
        );
    }

    #[test]
    fn change_pin_pads_both_credentials() {
        let mut script = Script::new(&[
            (SELECT, OK),
            (b"\0\x24\0\x80\x10123456\xff\xff654321\xff\xff", OK),
        ]);
        change_pin(
            &profile("3.1.0"),
            Pin::from_bytes(b"123456").unwrap(),
            Pin::from_bytes(b"654321").unwrap(),
            &mut |c| script.exchange(c),
        )
        .unwrap();
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn unblock_pin_uses_puk_reference() {
        let mut script = Script::new(&[
            (SELECT, OK),
            (b"\0\x2c\0\x80\x1012345678654321\xff\xff", OK),
        ]);
        unblock_pin(
            &profile("3.1.0"),
            Puk::from_bytes(b"12345678").unwrap(),
            Pin::from_bytes(b"654321").unwrap(),
            &mut |c| script.exchange(c),
        )
        .unwrap();
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn management_external_auth_known_answer_tdes() {
        // Cross-checked 3DES vector from libcanokey's management tests.
        let mut script = Script::new(&[
            (SELECT_LE, OK),
            (
                &[0, 0x87, 3, 0x9b, 4, 0x7c, 2, 0x81, 0, 0],
                &[
                    0x7c, 0x0a, 0x81, 8, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x90, 0,
                ],
            ),
            (
                &[
                    0, 0x87, 3, 0x9b, 0x0c, 0x7c, 0x0a, 0x82, 8, 0x07, 0x37, 0xf6, 0xc5, 0x37,
                    0x50, 0xd4, 0xa4, 0,
                ],
                OK,
            ),
        ]);
        let key = ManagementKey::from_bytes(
            ManagementKeyAlgorithm::Tdes,
            &[
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
                0xef, 0x01, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23,
            ],
        )
        .unwrap();
        authenticate(
            &profile("3.0.3"),
            ManagementAuthentication::external(key),
            &mut |c| script.exchange(c),
        )
        .unwrap();
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn management_mutual_auth_known_answer_aes() {
        // AES-192 mutual authentication with an all-zero host challenge
        // (deterministic test input; production uses mutual_auth's CSPRNG).
        let key = ManagementKey::from_bytes(
            ManagementKeyAlgorithm::Aes192,
            &(0u8..24).collect::<Vec<_>>(),
        )
        .unwrap();
        let auth = ManagementAuthentication::mutual(key, &[0; 16]).unwrap();
        let mut script = Script::new(&[
            (SELECT, OK),
            (
                &[0, 0x87, 0x0a, 0x9b, 4, 0x7c, 2, 0x80, 0],
                &[
                    0x7c, 0x12, 0x80, 0x10, 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e,
                    0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91, 0x90, 0,
                ],
            ),
            (
                &[
                    0, 0x87, 0x0a, 0x9b, 0x26, 0x7c, 0x24, 0x80, 0x10, 0x00, 0x11, 0x22, 0x33,
                    0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x81,
                    0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
                &[
                    0x7c, 0x12, 0x82, 0x10, 0x91, 0x62, 0x51, 0x82, 0x1c, 0x73, 0xa5, 0x22, 0xc3,
                    0x96, 0xd6, 0x27, 0x38, 0x01, 0x96, 0x07, 0x90, 0,
                ],
            ),
        ]);
        authenticate(&profile("3.1.0"), auth, &mut |c| script.exchange(c)).unwrap();
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn generate_rsa2048_and_p256() {
        // RSA-2048 into slot 9A with default policies.
        let mut modulus = vec![0x42; 256];
        modulus[0] = 0x80;
        let mut public = vec![0x7f, 0x49, 0x82, 1, 9, 0x81, 0x82, 1, 0];
        public.extend(&modulus);
        public.extend([0x82, 3, 1, 0, 1]);
        // The 269-byte reply exceeds a short-APDU frame: the card signals
        // 61xx and libcanokey drives GET RESPONSE through the exchange.
        let mut first = public[..256].to_vec();
        first.extend([0x61, (public.len() - 256) as u8]);
        let mut rest = public[256..].to_vec();
        rest.extend(OK);
        let mut transcript = AES_AUTH.to_vec();
        let get_response = [0, 0xc0, 0, 0, (public.len() - 256) as u8];
        transcript.push((&[0, 0x47, 0, 0x9a, 5, 0xac, 3, 0x80, 1, 7], &[]));
        transcript.push((&get_response, &[]));
        let mut script = Script {
            transcript: transcript
                .into_iter()
                .map(|(c, r)| (c.to_vec(), r.to_vec()))
                .collect(),
        };
        script.transcript[3].1 = first;
        script.transcript[4].1 = rest;
        let key = generate_key(
            &profile("3.1.0"),
            KeyParameters::new(Slot::Authentication, Algorithm::Rsa2048),
            aes_access(),
            &mut |c| script.exchange(c),
        )
        .unwrap();
        assert_eq!(key.algorithm(), Algorithm::Rsa2048);
        let PublicKey::Rsa {
            modulus: n,
            exponent,
            ..
        } = &key
        else {
            panic!("expected RSA key")
        };
        assert_eq!(n, &modulus[..]);
        assert_eq!(exponent, &[1, 0, 1]);

        // P-256 into slot 9C with explicit PIN/touch policies.
        let mut params = KeyParameters::new(Slot::Signature, Algorithm::EccP256);
        params.pin_policy = PinPolicy::Always;
        params.touch_policy = TouchPolicy::Always;
        let point = hex(P256_POINT);
        let mut public = vec![0x7f, 0x49, 0x43, 0x86, 0x41];
        public.extend(&point);
        public.extend(OK);
        let mut transcript = AES_AUTH.to_vec();
        transcript.push((
            &[
                0, 0x47, 0, 0x9c, 0x0b, 0xac, 9, 0x80, 1, 0x11, 0xaa, 1, 3, 0xab, 1, 2,
            ],
            &[],
        ));
        let mut script = Script {
            transcript: transcript
                .into_iter()
                .map(|(c, r)| (c.to_vec(), r.to_vec()))
                .collect(),
        };
        script.transcript.back_mut().unwrap().1 = public;
        let key = generate_key(&profile("3.1.0"), params, aes_access(), &mut |c| {
            script.exchange(c)
        })
        .unwrap();
        let PublicKey::Ec { point: p, .. } = &key else {
            panic!("expected EC key")
        };
        assert_eq!(p, &point[..]);
    }

    const P256_POINT: &str = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn import_rsa_crt_components() {
        let component = |seed: u8| [seed; 128];
        let material = PrivateKeyMaterial::rsa_crt(
            Algorithm::Rsa2048,
            [
                &component(1),
                &component(2),
                &component(3),
                &component(4),
                &component(5),
            ],
        )
        .unwrap();
        // The 650-byte payload is chained: 255-byte fragments with CLA 10
        // (more coming) and a final CLA 00 fragment (RSA-1024 is no longer
        // offered by the pinned 3.1 evidence, hence RSA-2048 here).
        let mut data = Vec::new();
        for tag in 1u8..=5 {
            data.extend([tag, 0x81, 128]);
            data.extend([tag; 128]);
        }
        let mut transcript: Vec<(Vec<u8>, Vec<u8>)> = AES_AUTH
            .iter()
            .map(|(c, r)| (c.to_vec(), r.to_vec()))
            .collect();
        let mut chunks = data.chunks(255).peekable();
        while let Some(chunk) = chunks.next() {
            let cla = if chunks.peek().is_some() { 0x10 } else { 0x00 };
            let mut frame = vec![cla, 0xfe, 7, 0x9a, chunk.len() as u8];
            frame.extend(chunk);
            transcript.push((frame, OK.to_vec()));
        }
        let mut script = Script {
            transcript: transcript.into(),
        };
        import_key(
            &profile("3.1.0"),
            KeyParameters::new(Slot::Authentication, Algorithm::Rsa2048),
            material,
            aes_access(),
            &mut |c| script.exchange(c),
        )
        .unwrap();
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn certificate_write_and_read_roundtrip() {
        // Write (management-authenticated), then public read of the container.
        let mut transcript = AES_AUTH.to_vec();
        transcript.push((
            &[
                0, 0xdb, 0x3f, 0xff, 0x10, 0x5c, 3, 0x5f, 0xc1, 5, 0x53, 9, 0x70, 2, 0x30, 0, 0x71,
                1, 0, 0xfe, 0,
            ],
            OK,
        ));
        let mut script = Script {
            transcript: transcript
                .into_iter()
                .map(|(c, r)| (c.to_vec(), r.to_vec()))
                .collect(),
        };
        write_certificate(
            &profile("3.1.0"),
            Slot::Authentication,
            SecretBytes::new(vec![0x30, 0]),
            aes_access(),
            &mut |c| script.exchange(c),
        )
        .unwrap();
        assert!(script.transcript.is_empty());

        let mut script = Script::new(&[
            (SELECT, OK),
            (
                &[0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 5, 0],
                &[0x53, 9, 0x70, 2, 0x30, 0, 0x71, 1, 0, 0xfe, 0, 0x90, 0],
            ),
        ]);
        let certificate = read_certificate(
            &profile("3.1.0"),
            Slot::Authentication,
            piv::Access::None,
            &mut |c| script.exchange(c),
        )
        .unwrap();
        assert_eq!(certificate.der(), &[0x30, 0]);
        assert!(!certificate.was_compressed());
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn metadata_retains_unknown_values_and_retries() {
        let mut script = Script::new(&[
            (SELECT, OK),
            (
                &[0, 0xf7, 0, 0x80, 0],
                &[
                    1, 1, 0xff, 5, 1, 2, 6, 2, 3, 9, 0x88, 1, 0xaa, 0x88, 1, 0xbb, 0x90, 0,
                ],
            ),
        ]);
        let metadata = metadata(
            &profile("3.1.0"),
            MetadataReference::Pin,
            piv::Access::None,
            &mut |c| script.exchange(c),
        )
        .unwrap();
        let fields = metadata.fields();
        assert_eq!(fields.retries, Some((3, 9)));
        assert_eq!(fields.is_default, Some(KnownOrUnknown::Unknown(2)));
        assert_eq!(fields.unknown_fields.len(), 2);
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn legacy_gated_operations_fail_before_any_io() {
        // Certificate deletion requires 3.1.0 evidence; 3.0.3 is rejected at
        // construction without touching the card.
        let mut calls = 0;
        let error = delete_certificate(
            &profile("3.0.3"),
            Slot::Authentication,
            aes_access(),
            &mut |_| -> io::Result<Vec<u8>> {
                calls += 1;
                unreachable!("capability gate must reject before any exchange")
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            PivError::Drive(DriveError::Protocol(error))
                if error.kind == ErrorKind::UnsupportedFeature
        ));
        assert_eq!(calls, 0);
    }

    #[test]
    fn pivman_data_roundtrip_and_flags() {
        let mut data = PivmanData::default();
        assert!(!data.puk_blocked());
        assert!(!data.has_stored_key());
        assert!(!data.has_derived_key());
        assert!(data.to_value().is_empty());
        data.set_stored_key(true);
        data.set_puk_blocked(true);
        data.salt = Some(vec![0x42; 16]);
        let parsed = PivmanData::from_value(&data.to_value()).unwrap();
        assert_eq!(parsed, data);
        assert!(parsed.puk_blocked());
        assert!(parsed.has_stored_key());
        assert!(parsed.has_derived_key());
        // ykman fixture shape: 80 { 81 flags }.
        let parsed = PivmanData::from_value(&[0x80, 3, 0x81, 1, 3]).unwrap();
        assert!(parsed.puk_blocked());
        assert!(parsed.has_stored_key());
        assert!(PivmanData::from_value(&[0x81, 3, 0x81, 1, 3]).is_err());
        assert!(PivmanData::from_value(&[0x80, 3, 0x81, 1, 3, 0]).is_err());
    }

    #[test]
    fn derive_management_key_matches_pykman_vector() {
        // PBKDF2-HMAC-SHA1(pin="123456", salt=0^16, 10000 rounds, 24 bytes),
        // computed with Python's hashlib.pbkdf2_hmac.
        let key = derive_management_key(b"123456", &[0; 16]);
        assert_eq!(
            &key[..],
            &hex("145c883db7eed2a867efebede8c45bbb9a2d4e45a135c6c5")
        );
    }

    #[test]
    #[allow(clippy::vec_init_then_push)]
    fn set_management_key_synced_protect_full_transcript() {
        // Blank device (both pivman objects missing), protect=true:
        // read ADMIN (6A82), read PRINTED with PIN (6A82), replace the key
        // (external AES auth with key 00..17), write ADMIN DATA flags and
        // PRINTED with the new key (external auth; witness 0^16 → the
        // OpenSSL-computed AES-192 ciphertext 5e9c...).
        let new_key = [0x42; 24];
        let new_auth: &[(&[u8], &[u8])] = &[
            (
                &[0, 0x87, 0x0a, 0x9b, 4, 0x7c, 2, 0x81, 0],
                &[
                    0x7c, 0x12, 0x81, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x90, 0,
                ],
            ),
            (
                &[
                    0, 0x87, 0x0a, 0x9b, 0x14, 0x7c, 0x12, 0x82, 0x10, 0x5e, 0x9c, 0x17, 0x37,
                    0x10, 0xc6, 0x46, 0x3a, 0x98, 0x2b, 0xac, 0x20, 0x48, 0xc1, 0xbd, 0x0d,
                ],
                OK,
            ),
        ];
        let not_found: &[u8] = &[0x6a, 0x82];
        let mut transcript: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        // 1. read ADMIN DATA.
        transcript.push((SELECT.to_vec(), OK.to_vec()));
        transcript.push((hex("00cb3fff055c035fff0000"), not_found.to_vec()));
        // 2. read PRINTED with PIN.
        transcript.push((SELECT.to_vec(), OK.to_vec()));
        transcript.push((VERIFY_123456.to_vec(), OK.to_vec()));
        transcript.push((hex("00cb3fff055c035fc10900"), not_found.to_vec()));
        // 3. replace the management key under the current key (00..17).
        transcript.extend(AES_AUTH.iter().map(|(c, r)| (c.to_vec(), r.to_vec())));
        let mut set_key = hex("00ffffff1b0a9b18");
        set_key.extend(new_key);
        transcript.push((set_key, OK.to_vec()));
        // 4. write ADMIN DATA (flags: stored key) under the new key.
        transcript.push((SELECT.to_vec(), OK.to_vec()));
        transcript.extend(new_auth.iter().map(|(c, r)| (c.to_vec(), r.to_vec())));
        transcript.push((hex("00db3fff0c5c035fff0053058003810102"), OK.to_vec()));
        // 5. write PRINTED under the new key, PIN verified adjacent.
        transcript.push((SELECT.to_vec(), OK.to_vec()));
        transcript.extend(new_auth.iter().map(|(c, r)| (c.to_vec(), r.to_vec())));
        transcript.push((VERIFY_123456.to_vec(), OK.to_vec()));
        let mut printed = hex("00db3fff235c035fc109531c881a8918");
        printed.extend(new_key);
        transcript.push((printed, OK.to_vec()));
        let mut script = Script {
            transcript: transcript.into(),
        };
        set_management_key_synced(
            &profile("3.1.0"),
            ManagementKeyUpdate {
                new_key_bytes: new_key,
                algorithm: ManagementKeyAlgorithm::Aes192,
                touch: ManagementTouchPolicy::Never,
                protect: true,
                pin: Some(Pin::from_bytes(b"123456").unwrap()),
                access: aes_access(),
            },
            &mut |c| script.exchange(c),
        )
        .unwrap();
        assert!(script.transcript.is_empty());
    }
}

#[cfg(test)]
mod extended_algorithm_tests {
    use super::*;
    use canokey::compatibility::{AlgorithmConfig, DeviceObservations, PivApplicationVersion};
    use std::collections::VecDeque;
    use std::io;

    struct Script {
        transcript: VecDeque<(Vec<u8>, Vec<u8>)>,
    }
    impl Script {
        fn new(transcript: Vec<(Vec<u8>, Vec<u8>)>) -> Self {
            Script {
                transcript: transcript.into(),
            }
        }
        fn exchange(&mut self, command: &[u8]) -> io::Result<Vec<u8>> {
            let (expected, response) = self
                .transcript
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "unexpected exchange"))?;
            assert_eq!(command, &expected[..], "command differs from transcript");
            Ok(response)
        }
    }

    /// 3.1.0 profile with the ML-DSA/ML-KEM extension IDs observed enabled.
    fn profile() -> DeviceProfile {
        let mut o = DeviceObservations::new(b"3.1.0".to_vec());
        o.piv_version = Some(PivApplicationVersion([5, 7, 0]));
        o.algorithm_config = Some(
            AlgorithmConfig::parse(&[1, 0xe0, 5, 0x16, 0xe1, 0x53, 0x54, 0x55, 0x56, 0x57])
                .unwrap(),
        );
        DeviceProfile::from_observations(o).unwrap()
    }

    /// 3.1.0 profile without the ML extension IDs (disabled mapping).
    fn profile_without_ml() -> DeviceProfile {
        let mut o = DeviceObservations::new(b"3.1.0".to_vec());
        o.piv_version = Some(PivApplicationVersion([5, 7, 0]));
        o.algorithm_config =
            Some(AlgorithmConfig::parse(&[1, 0xe0, 5, 0x16, 0xe1, 0x53, 0x54, 0x55]).unwrap());
        DeviceProfile::from_observations(o).unwrap()
    }

    const SELECT: &[u8] = &[0, 0xa4, 4, 0, 5, 0xa0, 0, 0, 3, 8];
    const OK: &[u8] = &[0x90, 0];
    const AES_AUTH: &[(&[u8], &[u8])] = &[
        (SELECT, OK),
        (
            &[0, 0x87, 0x0a, 0x9b, 4, 0x7c, 2, 0x81, 0],
            &[
                0x7c, 0x12, 0x81, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x90, 0,
            ],
        ),
        (
            &[
                0, 0x87, 0x0a, 0x9b, 0x14, 0x7c, 0x12, 0x82, 0x10, 0xdd, 0xa9, 0x7c, 0xa4, 0x86,
                0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
            ],
            OK,
        ),
    ];

    fn aes_access() -> Access {
        Access::Management(ManagementAuthentication::external(
            ManagementKey::from_bytes(
                ManagementKeyAlgorithm::Aes192,
                &(0u8..24).collect::<Vec<_>>(),
            )
            .unwrap(),
        ))
    }

    #[test]
    fn mldsa65_seed_import_fixture() {
        // Mirrors canokey-piv's mldsa65_seed_import_writes_seed_and_policy_tlvs.
        let seed: Vec<u8> = (0..32).collect();
        let material = PrivateKeyMaterial::mldsa65_seed(&seed).unwrap();
        let mut expected = vec![0, 0xfe, 0x56, 0x9c, 34, 9, 0x20];
        expected.extend(0..32);
        let mut transcript: Vec<(Vec<u8>, Vec<u8>)> = AES_AUTH
            .iter()
            .map(|(c, r)| (c.to_vec(), r.to_vec()))
            .collect();
        transcript.push((expected, OK.to_vec()));
        let mut script = Script::new(transcript);
        import_key(
            &profile(),
            KeyParameters::new(Slot::Signature, Algorithm::MlDsa65),
            material,
            aes_access(),
            &mut |c| script.exchange(c),
        )
        .unwrap();
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn mlkem768_seed_import_fixture() {
        // Mirrors canokey-piv's mlkem768_seed_import_writes_seed_tlv.
        let seed: Vec<u8> = (0..64).collect();
        let material = PrivateKeyMaterial::mlkem768_seed(&seed).unwrap();
        let mut expected = vec![0, 0xfe, 0x57, 0x9d, 0x42, 0x0a, 0x40];
        expected.extend(0..64);
        let mut transcript: Vec<(Vec<u8>, Vec<u8>)> = AES_AUTH
            .iter()
            .map(|(c, r)| (c.to_vec(), r.to_vec()))
            .collect();
        transcript.push((expected, OK.to_vec()));
        let mut script = Script::new(transcript);
        import_key(
            &profile(),
            KeyParameters::new(Slot::KeyManagement, Algorithm::MlKem768),
            material,
            aes_access(),
            &mut |c| script.exchange(c),
        )
        .unwrap();
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn sm2_generate_fixture() {
        // SM2 key generation in slot 9A; the public point comes back in 7F49.
        let mut point = vec![4];
        point.extend([7; 64]);
        let mut public = vec![0x7f, 0x49, 0x43, 0x86, 0x41];
        public.extend(&point);
        public.extend(OK);
        let mut transcript: Vec<(Vec<u8>, Vec<u8>)> = AES_AUTH
            .iter()
            .map(|(c, r)| (c.to_vec(), r.to_vec()))
            .collect();
        transcript.push((vec![0, 0x47, 0, 0x9a, 5, 0xac, 3, 0x80, 1, 0x55], public));
        let mut script = Script::new(transcript);
        let key = generate_key(
            &profile(),
            KeyParameters::new(Slot::Authentication, Algorithm::Sm2),
            aes_access(),
            &mut |c| script.exchange(c),
        )
        .unwrap();
        assert_eq!(key.algorithm(), Algorithm::Sm2);
        assert!(script.transcript.is_empty());
    }

    #[test]
    fn ml_import_gate_fails_before_any_io_without_observed_ids() {
        // Mirrors canokey-piv's ml_seed_import_requires_observed_wire_ids.
        let mut calls = 0;
        let error = import_key(
            &profile_without_ml(),
            KeyParameters::new(Slot::Signature, Algorithm::MlDsa65),
            PrivateKeyMaterial::mldsa65_seed(&[0; 32]).unwrap(),
            aes_access(),
            &mut |_| -> io::Result<Vec<u8>> {
                calls += 1;
                unreachable!("the wire-id gate must reject before any exchange")
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            PivError::Drive(DriveError::Protocol(error))
                if error.kind == ErrorKind::CapabilityUnknown
        ));
        assert_eq!(calls, 0);
    }

    #[test]
    fn kem_and_key_agreement_cannot_sign_certificates() {
        assert!(matches!(
            crate::x509::signature_algorithm(Algorithm::MlKem768, None),
            Err(crate::x509::X509Error::NotSigning("ML-KEM-768"))
        ));
        assert!(matches!(
            crate::x509::signature_algorithm(Algorithm::X25519, None),
            Err(crate::x509::X509Error::NotSigning("X25519"))
        ));
        assert_eq!(
            crate::x509::signature_algorithm(Algorithm::Sm2, None)
                .unwrap()
                .oid
                .to_string(),
            "1.2.156.10197.1.501"
        );
        assert_eq!(
            crate::x509::signature_algorithm(Algorithm::MlDsa65, None)
                .unwrap()
                .oid
                .to_string(),
            "2.16.840.1.101.3.4.18"
        );
    }
}
