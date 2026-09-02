"""CanoKey-specific support.

This module is fork-only: it centralizes the CanoKey admin applet protocol
and device detection so that hooks in upstream files stay minimal (each
marked with a "# CanoKey:" comment).

Admin applet protocol: canokey-documentation, development/protocols/admin.
The admin applet (AID F000000000) is present in all supported firmware
versions (1.3 - 3.0.3) and provides applet reset (OpenPGP/PIV/OATH/NDEF in
all versions, CTAP from 3.0.0) behind its own PIN (default "123456").
"""

import logging
import re
from dataclasses import dataclass
from enum import Enum

from .core import PID, BadResponseError, CommandError, NotSupportedError, Version
from .core.smartcard import SW, ApduError, SmartCardProtocol

logger = logging.getLogger(__name__)

ADMIN_AID = b"\xf0\x00\x00\x00\x00"

# Admin applet instructions
INS_WRITE_FIDO_KEY = 0x01
INS_WRITE_FIDO_CERT = 0x02
INS_RESET_OPENPGP = 0x03
INS_RESET_PIV = 0x04
INS_RESET_OATH = 0x05
INS_RESET_NDEF = 0x07
INS_RESET_CTAP = 0x09  # firmware 3.0.0+
INS_NFC_ENABLE = 0x14  # firmware 3.0.0+
INS_VERIFY = 0x20
INS_CHANGE_PIN = 0x21
INS_WRITE_SN = 0x30
INS_READ_VERSION = 0x31
INS_READ_SN = 0x32
INS_CONFIG = 0x40
INS_FLASH_USAGE = 0x41
INS_READ_CONFIG = 0x42
INS_FACTORY_RESET = 0x50

DEFAULT_ADMIN_PIN = "123456"

_FIRMWARE_VERSION_PATTERN = re.compile(
    r"^v?(?P<major>\d+)\.(?P<minor>\d+)"
    r"(?:\.(?P<patch>\d+))?"
    r"(?:[-+][0-9A-Za-z][0-9A-Za-z.+-]*)?$"
)


class CanoKeyFeature(str, Enum):
    """Host-visible features whose support depends on CanoKey firmware."""

    OATH_MODERN_COMMANDS = "oath-modern-commands"
    OPENPGP_ALGORITHM_INFORMATION = "openpgp-algorithm-information"
    PIV_METADATA = "piv-metadata"
    PIV_ECCP384 = "piv-eccp384"
    PIV_EXTENDED_ALGORITHMS = "piv-extended-algorithms"
    PIV_GENERATE_POLICIES = "piv-generate-policies"
    CTAP_RESET = "ctap-reset"
    PIV_STANDARD_ALGORITHM_IDS = "piv-standard-algorithm-ids"
    NFC_STATUS_WITHOUT_PIN = "nfc-status-without-pin"
    PIV_ED25519_X25519_FIXES = "piv-ed25519-x25519-fixes"
    OATH_RESPONSE_CHAINING_FIX = "oath-response-chaining-fix"
    PIV_SET_RETRIES = "piv-set-retries"
    PIV_SIGNATURE_DEFAULT_ALWAYS = "piv-signature-default-always"
    OPENPGP_SET_RETRIES = "openpgp-set-retries"
    OPENPGP_GET_CHALLENGE = "openpgp-get-challenge"
    OPENPGP_ECDSA_P384_SIGNING = "openpgp-ecdsa-p384-signing"
    OPENPGP_ATTESTATION = "openpgp-attestation"


class FeatureStatus(str, Enum):
    """Support state for a feature at a particular firmware version."""

    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class FirmwareRange:
    """Inclusive firmware interval where a feature is supported."""

    minimum: Version
    maximum: Version | None = None

    def contains(self, version: Version) -> bool:
        return version >= self.minimum and (
            self.maximum is None or version <= self.maximum
        )


@dataclass(frozen=True)
class FeatureRule:
    """Known support ranges and the newest firmware audited for a feature."""

    supported: tuple[FirmwareRange, ...]
    known_through: Version


CATALOG_VERSIONS = (
    Version(1, 3, 0),
    Version(1, 5, 2),
    Version(1, 6, 1),
    Version(1, 6, 2),
    Version(2, 0, 0),
    Version(2, 0, 1),
    Version(3, 0, 0),
    Version(3, 0, 1),
)
CATALOG_LATEST_VERSION = CATALOG_VERSIONS[-1]

# This is the single source of truth for firmware-dependent CanoKey behavior.
# Hardware provisioning state, such as the presence of attestation material, is
# intentionally not listed here and must be detected with a runtime probe.
FEATURE_MATRIX: dict[CanoKeyFeature, FeatureRule] = {
    CanoKeyFeature.OATH_MODERN_COMMANDS: FeatureRule(
        (FirmwareRange(Version(1, 5, 2)),), CATALOG_LATEST_VERSION
    ),
    CanoKeyFeature.OPENPGP_ALGORITHM_INFORMATION: FeatureRule(
        (FirmwareRange(Version(1, 6, 1)),), CATALOG_LATEST_VERSION
    ),
    CanoKeyFeature.PIV_METADATA: FeatureRule(
        (FirmwareRange(Version(2, 0, 0)),), CATALOG_LATEST_VERSION
    ),
    CanoKeyFeature.PIV_ECCP384: FeatureRule(
        (FirmwareRange(Version(1, 3, 0)),), CATALOG_LATEST_VERSION
    ),
    CanoKeyFeature.PIV_EXTENDED_ALGORITHMS: FeatureRule(
        (FirmwareRange(Version(2, 0, 0)),), CATALOG_LATEST_VERSION
    ),
    CanoKeyFeature.PIV_GENERATE_POLICIES: FeatureRule(
        (FirmwareRange(Version(2, 0, 0)),), CATALOG_LATEST_VERSION
    ),
    CanoKeyFeature.CTAP_RESET: FeatureRule(
        (FirmwareRange(Version(3, 0, 0)),), CATALOG_LATEST_VERSION
    ),
    CanoKeyFeature.PIV_STANDARD_ALGORITHM_IDS: FeatureRule(
        (FirmwareRange(Version(3, 0, 0)),), CATALOG_LATEST_VERSION
    ),
    CanoKeyFeature.NFC_STATUS_WITHOUT_PIN: FeatureRule(
        (FirmwareRange(Version(3, 0, 1)),), CATALOG_LATEST_VERSION
    ),
    CanoKeyFeature.PIV_ED25519_X25519_FIXES: FeatureRule(
        (FirmwareRange(Version(3, 0, 1)),), CATALOG_LATEST_VERSION
    ),
    CanoKeyFeature.OATH_RESPONSE_CHAINING_FIX: FeatureRule(
        (FirmwareRange(Version(3, 0, 1)),), CATALOG_LATEST_VERSION
    ),
    CanoKeyFeature.PIV_SET_RETRIES: FeatureRule((), CATALOG_LATEST_VERSION),
    CanoKeyFeature.PIV_SIGNATURE_DEFAULT_ALWAYS: FeatureRule(
        (), CATALOG_LATEST_VERSION
    ),
    CanoKeyFeature.OPENPGP_SET_RETRIES: FeatureRule((), CATALOG_LATEST_VERSION),
    CanoKeyFeature.OPENPGP_GET_CHALLENGE: FeatureRule(
        (FirmwareRange(Version(3, 0, 0)),), CATALOG_LATEST_VERSION
    ),
    CanoKeyFeature.OPENPGP_ECDSA_P384_SIGNING: FeatureRule((), CATALOG_LATEST_VERSION),
    CanoKeyFeature.OPENPGP_ATTESTATION: FeatureRule((), CATALOG_LATEST_VERSION),
}


def parse_firmware_version(value: str) -> Version:
    """Parse a CanoKey admin firmware version without accepting arbitrary text."""
    match = _FIRMWARE_VERSION_PATTERN.fullmatch(value.strip())
    if not match:
        raise ValueError(f"Invalid CanoKey firmware version: {value!r}")
    return Version(
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch") or 0),
    )


def get_feature_status(version: Version, feature: CanoKeyFeature) -> FeatureStatus:
    """Return the audited support status for a firmware-dependent feature."""
    rule = FEATURE_MATRIX[feature]
    if version > rule.known_through:
        return FeatureStatus.UNKNOWN
    if any(version_range.contains(version) for version_range in rule.supported):
        return FeatureStatus.SUPPORTED
    return FeatureStatus.UNSUPPORTED


def require_feature(version: Version, feature: CanoKeyFeature) -> None:
    """Reject a feature known to be unavailable on the given firmware.

    Unknown newer firmware is allowed to continue so the protocol operation can
    probe support at runtime.
    """
    if get_feature_status(version, feature) == FeatureStatus.UNSUPPORTED:
        raise NotSupportedError(
            f"{feature.value} is not supported by CanoKey firmware {version}"
        )


def is_canokey(connection) -> bool:
    """Check if a connection is to a CanoKey device.

    USB connections are recognized by PID; NFC connections (no PID) by the
    "CanoKey" string in the ATR historical bytes.
    """
    if getattr(connection, "is_cano", False):
        return True
    if getattr(connection, "pid", None) == PID.CK_FIDO_CCID:
        return True
    atr = getattr(connection, "atr", None)
    return atr is not None and b"CanoKey" in bytes(atr)


class AdminPinError(CommandError):
    """CanoKey admin PIN verification failed.

    :param retries: Remaining PIN retries, or None if the applet is blocked.
    """

    def __init__(self, message: str, retries: int | None = None):
        super().__init__(message)
        self.retries = retries


class AdminPinRequired(AdminPinError):
    """The admin applet is not verified; an explicit PIN is required."""

    def __init__(self):
        super().__init__("CanoKey admin PIN required")


class CanoKeyAdminSession:
    """Session with the CanoKey admin applet.

    Selecting the admin applet deselects any previously selected applet;
    callers must re-select the applet they were working with afterwards.
    """

    def __init__(self, connection, pin: str | None = None):
        self.protocol = SmartCardProtocol(connection)
        self.protocol.select(ADMIN_AID)
        self._verified = False
        if pin is not None:
            self.verify_pin(pin)

    def read_version(self) -> Version:
        """Read the CanoKey firmware version."""
        raw_version = self.protocol.send_apdu(0, INS_READ_VERSION, 0, 0, le=0x20)
        try:
            return parse_firmware_version(raw_version.decode("ascii"))
        except (UnicodeDecodeError, ValueError) as e:
            raise BadResponseError(
                f"Invalid CanoKey admin firmware version: {raw_version.hex()}"
            ) from e

    def read_product_string(self) -> str:
        """Read the hardware variant string."""
        return self.protocol.send_apdu(0, INS_READ_VERSION, 1, 0, le=0x20).decode()

    def read_serial(self) -> int:
        """Read the 4-byte serial number."""
        data = self.protocol.send_apdu(0, INS_READ_SN, 0, 0, le=4)
        return int.from_bytes(data, "big")

    def read_nfc_enable(self) -> bool:
        """Read whether NFC is enabled (firmware 3.0.0+)."""
        require_feature(self.read_version(), CanoKeyFeature.NFC_STATUS_WITHOUT_PIN)
        data = self.protocol.send_apdu(0, INS_NFC_ENABLE, 0, 0, le=1)
        return data != b"\0"

    def verify_pin(self, pin: str) -> None:
        """Verify the admin applet PIN."""
        try:
            self.protocol.send_apdu(0, INS_VERIFY, 0, 0, pin.encode())
            self._verified = True
        except ApduError as e:
            if e.sw == SW.AUTH_METHOD_BLOCKED:
                raise AdminPinError("Admin PIN is blocked") from e
            if e.sw >> 8 == 0x63 and e.sw & 0xF0 == 0xC0:
                retries = e.sw & 0x0F
                raise AdminPinError(
                    f"Wrong admin PIN, {retries} retries remaining", retries
                ) from e
            raise

    def _ensure_verified(self) -> None:
        """Verify the default PIN, unless a PIN was already verified."""
        if self._verified:
            return

        try:
            self.protocol.send_apdu(0, INS_VERIFY, 0, 0)
            self._verified = True
            return
        except ApduError as e:
            if e.sw == SW.AUTH_METHOD_BLOCKED:
                raise AdminPinError("Admin PIN is blocked") from e
            if e.sw >> 8 == 0x63 and e.sw & 0xF0 == 0xC0:
                raise AdminPinRequired() from e
            raise

    def _reset_applet(self, ins: int, name: str) -> None:
        self._ensure_verified()
        self.protocol.send_apdu(0, ins, 0, 0)
        logger.info(f"{name} applet reset via CanoKey admin")

    def reset_openpgp(self) -> None:
        """Factory reset the OpenPGP applet."""
        self._reset_applet(INS_RESET_OPENPGP, "OpenPGP")

    def reset_piv(self) -> None:
        """Factory reset the PIV applet."""
        self._reset_applet(INS_RESET_PIV, "PIV")

    def reset_oath(self) -> None:
        """Factory reset the OATH applet."""
        self._reset_applet(INS_RESET_OATH, "OATH")

    def reset_ctap(self) -> None:
        """Factory reset the CTAP (FIDO) applet. Requires firmware 3.0.0+."""
        require_feature(self.read_version(), CanoKeyFeature.CTAP_RESET)
        self._reset_applet(INS_RESET_CTAP, "CTAP")
