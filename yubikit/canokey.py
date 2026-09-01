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

from .core import PID, CommandError, NotSupportedError, Version
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

# Firmware 3.0.0 added Reset CTAP and NFC enable
_VERSION_CTAP_RESET = (3, 0, 0)


def is_canokey(connection) -> bool:
    """Check if a connection is to a CanoKey device.

    USB connections are recognized by PID; NFC connections (no PID) by the
    "CanoKey" string in the ATR historical bytes.
    """
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
    """The default admin PIN did not verify; an explicit PIN is required."""

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
        return Version.from_string(
            self.protocol.send_apdu(0, INS_READ_VERSION, 0, 0, le=0x20).decode()
        )

    def read_product_string(self) -> str:
        """Read the hardware variant string."""
        return self.protocol.send_apdu(0, INS_READ_VERSION, 1, 0, le=0x20).decode()

    def read_serial(self) -> int:
        """Read the 4-byte serial number."""
        data = self.protocol.send_apdu(0, INS_READ_SN, 0, 0, le=4)
        return int.from_bytes(data, "big")

    def read_nfc_enable(self) -> bool:
        """Read whether NFC is enabled (firmware 3.0.0+)."""
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
            self.verify_pin(DEFAULT_ADMIN_PIN)
        except AdminPinError as e:
            if e.retries is None:  # Blocked
                raise
            raise AdminPinRequired() from e

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
        if self.read_version() < _VERSION_CTAP_RESET:
            raise NotSupportedError("CTAP reset requires CanoKey firmware 3.0.0+")
        self._reset_applet(INS_RESET_CTAP, "CTAP")
