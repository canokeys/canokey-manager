"""Unit tests for yubikit.canokey (fork-only module)."""

from typing import Any, cast

import pytest
from yubikit import canokey
from yubikit.canokey import (
    ADMIN_AID,
    CATALOG_LATEST_VERSION,
    CATALOG_VERSIONS,
    FEATURE_MATRIX,
    INS_READ_SN,
    INS_READ_VERSION,
    INS_RESET_CTAP,
    INS_RESET_OATH,
    INS_VERIFY,
    AdminPinError,
    AdminPinRequired,
    CanoKeyFeature,
    CanoKeyAdminSession,
    FeatureStatus,
    UnknownFeatureError,
    get_feature_status,
    parse_firmware_version,
)
from yubikit.core import PID, TRANSPORT, BadResponseError, NotSupportedError, Version
from yubikit.core.smartcard import SW, ApduError, SmartCardConnection
from yubikit.management import ManagementSession
from yubikit.openpgp import KEY_REF, OpenPgpSession


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


@pytest.mark.parametrize(
    ("connection", "sw", "expected"),
    [
        (FakeConnection(), SW.CONDITIONS_NOT_SATISFIED, Version(1, 0, 0)),
        (
            FakeConnection(pid=PID.CK_FIDO_CCID),
            SW.INVALID_INSTRUCTION,
            Version(5, 5, 5),
        ),
    ],
)
def test_openpgp_expected_version_fallbacks(connection, sw, expected):
    class Protocol:
        def __init__(self):
            self.connection = connection

        def send_apdu(self, *args):
            raise ApduError(b"", sw)

    session = object.__new__(OpenPgpSession)
    session.protocol = cast(Any, Protocol())
    assert session._read_version() == expected


def test_openpgp_version_read_propagates_unexpected_error():
    class Protocol:
        connection = FakeConnection(pid=PID.CK_FIDO_CCID)

        def send_apdu(self, *args):
            raise ApduError(b"", SW.SECURITY_CONDITION_NOT_SATISFIED)

    session = object.__new__(OpenPgpSession)
    session.protocol = cast(Any, Protocol())
    with pytest.raises(ApduError):
        session._read_version()


@pytest.mark.parametrize(
    ("connection", "key_ref", "expected_occurrence"),
    [
        (FakeConnection(pid=PID.CK_FIDO_CCID), KEY_REF.SIG, 0),
        (FakeConnection(pid=PID.CK_FIDO_CCID), KEY_REF.DEC, 1),
        (FakeConnection(pid=PID.CK_FIDO_CCID), KEY_REF.AUT, 2),
        (FakeConnection(), KEY_REF.SIG, 2),
        (FakeConnection(), KEY_REF.DEC, 1),
        (FakeConnection(), KEY_REF.AUT, 0),
    ],
)
def test_openpgp_certificate_occurrence(connection, key_ref, expected_occurrence):
    class Protocol:
        def __init__(self):
            self.connection = connection
            self.sent = []

        def send_apdu(self, *args):
            self.sent.append(args)

    protocol = Protocol()
    session = object.__new__(OpenPgpSession)
    session.protocol = cast(Any, protocol)
    session._version = Version(5, 5, 5)
    session._select_certificate(key_ref)
    assert protocol.sent[0][2] == expected_occurrence


@pytest.mark.parametrize(
    ("encoded", "expected"),
    [
        (b"1.3", Version(1, 3, 0)),
        (b"2.0.1", Version(2, 0, 1)),
        (b"3.0.3-437-ge1ee371-O", Version(3, 0, 3)),
        (b"v3.0.1+usbip", Version(3, 0, 1)),
    ],
)
def test_read_version(encoded, expected):
    conn = FakeConnection(
        [
            (select_apdu(), (b"", 0x9000)),
            (bytes([0, INS_READ_VERSION, 0, 0]), (encoded, 0x9000)),
        ],
        pid=PID.CK_FIDO_CCID,
    )
    session = CanoKeyAdminSession(conn)
    assert session.read_version() == expected


@pytest.mark.parametrize(
    "encoded",
    [
        b"69e562bcb07eedda015aae6064870c8548571e2b",
        b"release 3.0.1",
        b"\xff\xfe",
    ],
)
def test_read_version_rejects_non_firmware_values(encoded):
    conn = FakeConnection(
        [
            (select_apdu(), (b"", 0x9000)),
            (bytes([0, INS_READ_VERSION, 0, 0]), (encoded, 0x9000)),
        ],
        pid=PID.CK_FIDO_CCID,
    )
    with pytest.raises(BadResponseError):
        CanoKeyAdminSession(conn).read_version()


def test_parse_firmware_version_normalizes_catalog_short_version():
    assert parse_firmware_version("1.3") == Version(1, 3, 0)


@pytest.mark.parametrize(
    ("feature", "version", "expected"),
    [
        (
            CanoKeyFeature.OATH_MODERN_COMMANDS,
            Version(1, 3, 0),
            FeatureStatus.UNSUPPORTED,
        ),
        (
            CanoKeyFeature.OATH_MODERN_COMMANDS,
            Version(1, 5, 2),
            FeatureStatus.SUPPORTED,
        ),
        (
            CanoKeyFeature.OATH_MODERN_COMMANDS,
            Version(3, 0, 2),
            FeatureStatus.UNKNOWN,
        ),
        (
            CanoKeyFeature.OPENPGP_ALGORITHM_INFORMATION,
            Version(1, 5, 2),
            FeatureStatus.UNSUPPORTED,
        ),
        (
            CanoKeyFeature.OPENPGP_ALGORITHM_INFORMATION,
            Version(1, 6, 1),
            FeatureStatus.SUPPORTED,
        ),
        (
            CanoKeyFeature.PIV_METADATA,
            Version(2, 0, 0),
            FeatureStatus.SUPPORTED,
        ),
        (
            CanoKeyFeature.PIV_ECCP384,
            Version(1, 3, 0),
            FeatureStatus.SUPPORTED,
        ),
        (
            CanoKeyFeature.PIV_GENERATE_POLICIES,
            Version(1, 6, 2),
            FeatureStatus.UNSUPPORTED,
        ),
        (
            CanoKeyFeature.PIV_GENERATE_POLICIES,
            Version(2, 0, 0),
            FeatureStatus.SUPPORTED,
        ),
        (
            CanoKeyFeature.CTAP_RESET,
            Version(2, 0, 1),
            FeatureStatus.UNSUPPORTED,
        ),
        (
            CanoKeyFeature.CTAP_RESET,
            Version(3, 0, 0),
            FeatureStatus.SUPPORTED,
        ),
        (
            CanoKeyFeature.OPENPGP_GET_CHALLENGE,
            Version(2, 0, 1),
            FeatureStatus.UNSUPPORTED,
        ),
        (
            CanoKeyFeature.OPENPGP_GET_CHALLENGE,
            Version(3, 0, 0),
            FeatureStatus.SUPPORTED,
        ),
        (
            CanoKeyFeature.PIV_SET_RETRIES,
            Version(3, 0, 1),
            FeatureStatus.UNSUPPORTED,
        ),
        (
            CanoKeyFeature.PIV_SET_RETRIES,
            Version(3, 0, 2),
            FeatureStatus.UNKNOWN,
        ),
        (
            CanoKeyFeature.PIV_SIGNATURE_DEFAULT_ALWAYS,
            Version(3, 0, 1),
            FeatureStatus.UNSUPPORTED,
        ),
        (
            CanoKeyFeature.OPENPGP_ECDSA_P384_SIGNING,
            Version(3, 0, 1),
            FeatureStatus.UNSUPPORTED,
        ),
        (
            CanoKeyFeature.OPENPGP_ATTESTATION,
            Version(3, 0, 1),
            FeatureStatus.UNSUPPORTED,
        ),
        (
            CanoKeyFeature.OPENPGP_ATTESTATION,
            Version(3, 0, 2),
            FeatureStatus.UNKNOWN,
        ),
        (
            CanoKeyFeature.FIDO_PCSC,
            Version(1, 3, 0),
            FeatureStatus.UNSUPPORTED,
        ),
        (
            CanoKeyFeature.FIDO_PCSC,
            Version(1, 5, 2),
            FeatureStatus.SUPPORTED,
        ),
        (
            CanoKeyFeature.FIDO_PCSC,
            Version(3, 0, 2),
            FeatureStatus.UNKNOWN,
        ),
    ],
)
def test_firmware_feature_matrix(feature, version, expected):
    assert get_feature_status(version, feature) == expected


def test_every_feature_has_an_audited_rule():
    assert set(FEATURE_MATRIX) == set(CanoKeyFeature)
    assert all(
        rule.known_through == CATALOG_LATEST_VERSION for rule in FEATURE_MATRIX.values()
    )


def test_unknown_firmware_feature_is_not_automatically_enabled():
    with pytest.raises(UnknownFeatureError, match="support is unknown"):
        canokey.require_feature(Version(3, 0, 2), CanoKeyFeature.FIDO_PCSC)


def test_catalog_versions_are_ordered_and_unique():
    assert tuple(sorted(set(CATALOG_VERSIONS))) == CATALOG_VERSIONS


def test_management_does_not_hide_invalid_canokey_firmware_version():
    management_aid = bytes.fromhex("A000000527471117")
    select_management = bytes([0, 0xA4, 0x04, 0, len(management_aid)]) + management_aid
    conn = FakeConnection(
        [
            (select_management, (b"", 0x6A82)),
            (select_apdu(), (b"", 0x9000)),
            (
                bytes([0, INS_READ_VERSION, 0, 0]),
                (b"69e562bcb07eedda015aae6064870c8548571e2b", 0x9000),
            ),
        ],
        pid=PID.CK_FIDO_CCID,
    )
    with pytest.raises(BadResponseError):
        ManagementSession(conn)


def test_management_does_not_hide_unknown_canokey_firmware():
    management_aid = bytes.fromhex("A000000527471117")
    select_management = bytes([0, 0xA4, 0x04, 0, len(management_aid)]) + management_aid
    conn = FakeConnection(
        [
            (select_management, (b"", 0x6A82)),
            (select_apdu(), (b"", 0x9000)),
            (bytes([0, INS_READ_VERSION, 0, 0]), (b"3.0.2", 0x9000)),
            (bytes([0, INS_READ_VERSION, 1, 0]), (b"CanoKey", 0x9000)),
            (bytes([0, INS_READ_SN, 0, 0]), (b"\x00\x00\x00\x01", 0x9000)),
            (bytes([0, INS_READ_VERSION, 0, 0]), (b"3.0.2", 0x9000)),
        ],
        pid=PID.CK_FIDO_CCID,
    )

    session = ManagementSession(conn)
    with pytest.raises(UnknownFeatureError, match="nfc-status-without-pin"):
        session.read_device_info()


def test_reset_oath_accepts_explicit_default_pin():
    conn = FakeConnection(
        [
            (select_apdu(), (b"", 0x9000)),
            (bytes([0, INS_VERIFY, 0, 0]), (b"", 0x9000)),
            (bytes([0, INS_RESET_OATH, 0, 0]), (b"", 0x9000)),
        ],
        pid=PID.CK_FIDO_CCID,
    )
    CanoKeyAdminSession(conn, pin="123456").reset_oath()
    verify_apdu = conn.sent[1]
    assert verify_apdu[5:] == b"123456"


def test_reset_oath_reuses_already_verified_admin_session():
    conn = FakeConnection(
        [
            (select_apdu(), (b"", 0x9000)),
            (bytes([0, INS_VERIFY, 0, 0]), (b"", 0x9000)),
            (bytes([0, INS_RESET_OATH, 0, 0]), (b"", 0x9000)),
        ],
        pid=PID.CK_FIDO_CCID,
    )
    CanoKeyAdminSession(conn).reset_oath()
    assert conn.sent[1] == bytes([0, INS_VERIFY, 0, 0, 0])


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
            (bytes([0, INS_VERIFY, 0, 0]), (b"", 0x63C3)),
        ],
        pid=PID.CK_FIDO_CCID,
    )
    with pytest.raises(AdminPinRequired):
        CanoKeyAdminSession(conn).reset_oath()


def test_reset_oath_does_not_retry_default_pin_after_prior_failure():
    conn = FakeConnection(
        [
            (select_apdu(), (b"", 0x9000)),
            (bytes([0, INS_VERIFY, 0, 0]), (b"", 0x63C2)),
        ],
        pid=PID.CK_FIDO_CCID,
    )
    with pytest.raises(AdminPinRequired):
        CanoKeyAdminSession(conn).reset_oath()
    assert len(conn.sent) == 2


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
            (bytes([0, INS_VERIFY, 0, 0]), (b"", 0x9000)),
            (bytes([0, INS_READ_VERSION, 0, 0]), (b"3.0.1", 0x9000)),
            (bytes([0, INS_RESET_CTAP, 0, 0]), (b"", 0x9000)),
        ],
        pid=PID.CK_FIDO_CCID,
    )
    CanoKeyAdminSession(conn, pin="123456").reset_ctap()


def test_oath_reset_falls_back_to_admin():
    from yubikit.oath import OathSession

    select_oath = bytes([0, 0xA4, 0x04, 0, 7]) + bytes.fromhex("A0000005272101")
    oath_select_resp = (
        bytes.fromhex("7903") + b"\x05\x05\x05" + bytes.fromhex("7108") + b"12345678"
    )
    # Firmware before 3.0.1 needs an extra SEND_REMAINING after SW=9000.
    a5_done = (bytes([0, 0xA5, 0, 0]), (b"", 0x6985))
    conn = FakeConnection(
        [
            (select_apdu(), (b"", 0x9000)),
            (bytes([0, INS_READ_VERSION, 0, 0]), (b"3.0.0", 0x9000)),
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
    OathSession(conn).reset("123456")
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
            (select_apdu(), (b"", 0x9000)),
            (bytes([0, INS_READ_VERSION, 0, 0]), (b"3.0.0", 0x9000)),
            (select_oath, (locked_resp, 0x9000)),
            (bytes([0, 0xA5, 0, 0]), (b"", 0x6982)),  # locked: no more data
        ],
        pid=PID.CK_FIDO_CCID,
    )
    session = OathSession(conn)
    assert session.locked


def test_oath_fixed_firmware_does_not_send_unneeded_remaining_command():
    from yubikit.oath import OathSession

    select_oath = bytes([0, 0xA4, 0x04, 0, 7]) + bytes.fromhex("A0000005272101")
    oath_select_resp = (
        bytes.fromhex("7903") + b"\x06\x00\x00" + bytes.fromhex("7108") + b"12345678"
    )
    conn = FakeConnection(
        [
            (select_apdu(), (b"", 0x9000)),
            (bytes([0, INS_READ_VERSION, 0, 0]), (b"3.0.1", 0x9000)),
            (select_oath, (oath_select_resp, 0x9000)),
        ],
        pid=PID.CK_FIDO_CCID,
    )
    OathSession(conn)
    assert not conn._script
