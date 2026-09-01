"""Unit tests for yubikit.canokey (fork-only module)."""

import pytest
from yubikit import canokey
from yubikit.canokey import (
    ADMIN_AID,
    INS_READ_VERSION,
    INS_RESET_CTAP,
    INS_RESET_OATH,
    INS_VERIFY,
    AdminPinError,
    AdminPinRequired,
    CanoKeyAdminSession,
)
from yubikit.core import PID, TRANSPORT, NotSupportedError, Version
from yubikit.core.smartcard import SmartCardConnection


class FakeConnection(SmartCardConnection):
    """A scripted smartcard connection.

    Each entry in `script` is (expected_apdu_prefix, (response, sw)).
    """

    def __init__(self, script=(), pid=None, atr=None):
        self._script = list(script)
        self.pid = pid
        self.atr = atr
        self.sent = []

    @property
    def transport(self):
        return TRANSPORT.USB

    def send_and_receive(self, apdu):
        self.sent.append(bytes(apdu))
        if not self._script:
            raise AssertionError(f"Unexpected APDU: {bytes(apdu).hex()}")
        prefix, (data, sw) = self._script.pop(0)
        assert bytes(apdu).startswith(prefix), (
            f"APDU {bytes(apdu).hex()} does not match {prefix.hex()}"
        )
        return data, sw

    def close(self):
        pass


def select_apdu():
    return bytes([0, 0xA4, 0x04, 0, len(ADMIN_AID)]) + ADMIN_AID


def test_is_canokey_by_pid():
    conn = FakeConnection(pid=PID.CK_FIDO_CCID)
    assert canokey.is_canokey(conn)


def test_is_canokey_by_atr():
    atr = bytes.fromhex("3bf71100008131fe6543616e6f4b657999")
    assert b"CanoKey" in atr
    conn = FakeConnection(pid=None, atr=atr)
    assert canokey.is_canokey(conn)


def test_is_canokey_negative():
    assert not canokey.is_canokey(FakeConnection())
    assert not canokey.is_canokey(FakeConnection(pid=None, atr=b"\x3b\x00"))


def test_read_version():
    conn = FakeConnection(
        [
            (select_apdu(), (b"", 0x9000)),
            (bytes([0, INS_READ_VERSION, 0, 0]), (b"2.0.1", 0x9000)),
        ],
        pid=PID.CK_FIDO_CCID,
    )
    session = CanoKeyAdminSession(conn)
    assert session.read_version() == Version(2, 0, 1)


def test_reset_oath_verifies_default_pin():
    conn = FakeConnection(
        [
            (select_apdu(), (b"", 0x9000)),
            (bytes([0, INS_VERIFY, 0, 0]), (b"", 0x9000)),
            (bytes([0, INS_RESET_OATH, 0, 0]), (b"", 0x9000)),
        ],
        pid=PID.CK_FIDO_CCID,
    )
    CanoKeyAdminSession(conn).reset_oath()
    verify_apdu = conn.sent[1]
    assert verify_apdu[5:] == b"123456"


def test_reset_oath_custom_pin():
    conn = FakeConnection(
        [
            (select_apdu(), (b"", 0x9000)),
            (bytes([0, INS_VERIFY, 0, 0]), (b"", 0x9000)),
            (bytes([0, INS_RESET_OATH, 0, 0]), (b"", 0x9000)),
        ],
        pid=PID.CK_FIDO_CCID,
    )
    CanoKeyAdminSession(conn, pin="654321").reset_oath()
    assert conn.sent[1][5:] == b"654321"


def test_reset_oath_requires_pin_when_default_fails():
    conn = FakeConnection(
        [
            (select_apdu(), (b"", 0x9000)),
            (bytes([0, INS_VERIFY, 0, 0]), (b"", 0x63C2)),
        ],
        pid=PID.CK_FIDO_CCID,
    )
    with pytest.raises(AdminPinRequired):
        CanoKeyAdminSession(conn).reset_oath()


def test_wrong_pin_reports_retries():
    conn = FakeConnection(
        [
            (select_apdu(), (b"", 0x9000)),
            (bytes([0, INS_VERIFY, 0, 0]), (b"", 0x63C1)),
        ],
        pid=PID.CK_FIDO_CCID,
    )
    with pytest.raises(AdminPinError) as exc_info:
        CanoKeyAdminSession(conn, pin="000000")
    assert exc_info.value.retries == 1


def test_blocked_pin():
    conn = FakeConnection(
        [
            (select_apdu(), (b"", 0x9000)),
            (bytes([0, INS_VERIFY, 0, 0]), (b"", 0x6983)),
        ],
        pid=PID.CK_FIDO_CCID,
    )
    with pytest.raises(AdminPinError) as exc_info:
        CanoKeyAdminSession(conn, pin="000000")
    assert exc_info.value.retries is None


def test_reset_ctap_version_gate():
    conn = FakeConnection(
        [
            (select_apdu(), (b"", 0x9000)),
            (bytes([0, INS_READ_VERSION, 0, 0]), (b"1.6.2", 0x9000)),
        ],
        pid=PID.CK_FIDO_CCID,
    )
    with pytest.raises(NotSupportedError):
        CanoKeyAdminSession(conn).reset_ctap()


def test_reset_ctap_supported():
    conn = FakeConnection(
        [
            (select_apdu(), (b"", 0x9000)),
            (bytes([0, INS_READ_VERSION, 0, 0]), (b"3.0.3", 0x9000)),
            (bytes([0, INS_VERIFY, 0, 0]), (b"", 0x9000)),
            (bytes([0, INS_RESET_CTAP, 0, 0]), (b"", 0x9000)),
        ],
        pid=PID.CK_FIDO_CCID,
    )
    CanoKeyAdminSession(conn).reset_ctap()


def test_oath_reset_falls_back_to_admin():
    from yubikit.oath import OathSession

    select_oath = bytes([0, 0xA4, 0x04, 0, 7]) + bytes.fromhex("A0000005272101")
    oath_select_resp = bytes.fromhex("7903") + b"\x05\x05\x05" + bytes.fromhex(
        "7108"
    ) + b"12345678"
    # The fork's OATH chaining workaround sends INS_SEND_REMAINING (0xA5)
    # after every successful APDU; the card answers 6985 when done.
    a5_done = (bytes([0, 0xA5, 0, 0]), (b"", 0x6985))
    conn = FakeConnection(
        [
            (select_oath, (oath_select_resp, 0x9000)),  # OathSession init
            a5_done,
            (select_apdu(), (b"", 0x9000)),  # select admin applet
            (bytes([0, INS_VERIFY, 0, 0]), (b"", 0x9000)),  # default admin PIN
            (bytes([0, INS_RESET_OATH, 0, 0]), (b"", 0x9000)),
            (select_oath, (oath_select_resp, 0x9000)),  # re-select OATH
            a5_done,
        ],
        pid=PID.CK_FIDO_CCID,
    )
    OathSession(conn).reset()
    assert not conn._script  # All scripted APDUs consumed


def test_oath_select_when_locked():
    """A5 workaround must not fail when OATH is password-protected (6982)."""
    from yubikit.oath import OathSession

    select_oath = bytes([0, 0xA4, 0x04, 0, 7]) + bytes.fromhex("A0000005272101")
    # Locked: response includes a challenge (tag 0x74) and algorithm (0x7B)
    locked_resp = (
        bytes.fromhex("7903")
        + b"\x05\x05\x05"
        + bytes.fromhex("7108")
        + b"12345678"
        + bytes.fromhex("7408")
        + b"87654321"
        + bytes.fromhex("7B0101")
    )
    conn = FakeConnection(
        [
            (select_oath, (locked_resp, 0x9000)),
            (bytes([0, 0xA5, 0, 0]), (b"", 0x6982)),  # locked: no more data
        ],
        pid=PID.CK_FIDO_CCID,
    )
    session = OathSession(conn)
    assert session.locked
