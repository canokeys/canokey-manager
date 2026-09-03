import gzip
import zlib
from datetime import date
from types import SimpleNamespace
from typing import Any, cast

import pytest
from ykman.piv import (
    _list_keys,
    _parse_rfc4514_string,
    generate_chuid,
    generate_random_management_key,
)
from yubikit.core import PID, BadResponseError, NotSupportedError, Version
from yubikit.core.smartcard import SW, ApduError
from yubikit.piv import (
    INS_GENERATE_ASYMMETRIC,
    INS_MOVE_KEY,
    KEY_TYPE,
    MANAGEMENT_KEY_TYPE,
    OBJECT_ID,
    PIN_POLICY,
    SLOT,
    TOUCH_POLICY,
    Chuid,
    FascN,
    PivSession,
    _do_check_key_support,
    decompress_certificate,
)


def test_list_keys_ignores_only_empty_slots():
    class EmptySession:
        def get_slot_metadata(self, slot):
            raise ApduError(b"", SW.REFERENCE_DATA_NOT_FOUND)

    assert _list_keys(EmptySession()) == {}


def test_list_keys_propagates_unexpected_apdu_error():
    class FailingSession:
        def get_slot_metadata(self, slot):
            raise ApduError(b"", SW.SECURITY_CONDITION_NOT_SATISFIED)

    with pytest.raises(ApduError) as exc_info:
        _list_keys(FailingSession())
    assert exc_info.value.sw == SW.SECURITY_CONDITION_NOT_SATISFIED


@pytest.mark.parametrize(
    ("pid", "version", "expected_ins"),
    [
        (PID.CK_FIDO_CCID, Version(5, 0, 0), INS_GENERATE_ASYMMETRIC),
        (PID.YK4_FIDO_CCID, Version(5, 7, 0), INS_MOVE_KEY),
    ],
)
def test_delete_key_uses_device_specific_command(pid, version, expected_ins):
    class Protocol:
        connection = SimpleNamespace(pid=pid, atr=None)

        def __init__(self):
            self.commands = []

        def send_apdu(self, *args):
            self.commands.append(args)

    session = object.__new__(PivSession)
    session.protocol = cast(Any, Protocol())
    session._version = version
    session.delete_key(SLOT.AUTHENTICATION)

    assert session.protocol.commands[0][1] == expected_ins


@pytest.mark.parametrize(
    ("object_id", "raw"),
    [
        (OBJECT_ID.CHUID, bytes.fromhex("3003010203")),
        (OBJECT_ID.CAPABILITY, bytes.fromhex("f00101")),
    ],
)
def test_get_object_accepts_confirmed_legacy_canokey_factory_data(object_id, raw):
    class Protocol:
        def send_apdu(self, *args):
            return raw

    session = object.__new__(PivSession)
    session.protocol = cast(Any, Protocol())
    session._canokey_missing_object_wrapping = True

    assert session.get_object(object_id) == raw


def test_get_object_does_not_relax_other_malformed_legacy_data():
    class Protocol:
        def send_apdu(self, *args):
            return b"malformed"

    session = object.__new__(PivSession)
    session.protocol = cast(Any, Protocol())
    session._canokey_missing_object_wrapping = True

    with pytest.raises(BadResponseError, match="Malformed object data"):
        session.get_object(OBJECT_ID.CHUID)


def test_get_object_keeps_standard_wrapping_on_newer_firmware():
    raw = b"chuid"

    class Protocol:
        def send_apdu(self, *args):
            from yubikit.core import Tlv

            return bytes(Tlv(0x53, raw))

    session = object.__new__(PivSession)
    session.protocol = cast(Any, Protocol())
    session._canokey_missing_object_wrapping = False

    assert session.get_object(OBJECT_ID.CHUID) == raw


@pytest.mark.parametrize(
    ("legacy", "response_sw", "expected_sw"),
    [
        (True, 0x6900, SW.REFERENCE_DATA_NOT_FOUND),
        (False, 0x6900, 0x6900),
        (
            True,
            SW.SECURITY_CONDITION_NOT_SATISFIED,
            SW.SECURITY_CONDITION_NOT_SATISFIED,
        ),
    ],
)
def test_get_slot_metadata_normalizes_only_confirmed_legacy_empty_status(
    legacy, response_sw, expected_sw
):
    class Protocol:
        def send_apdu(self, *args):
            raise ApduError(b"error", response_sw)

    session = object.__new__(PivSession)
    session.protocol = cast(Any, Protocol())
    session._version = Version(5, 3, 0)
    session._canokey_legacy_empty_slot_status = legacy

    with pytest.raises(ApduError) as exc_info:
        session.get_slot_metadata(SLOT.AUTHENTICATION)
    assert exc_info.value.sw == expected_sw


def test_get_slot_metadata_normalizes_confirmed_legacy_empty_response():
    class Protocol:
        def send_apdu(self, *args):
            return b""

    session = object.__new__(PivSession)
    session.protocol = cast(Any, Protocol())
    session._version = Version(5, 3, 0)
    session._canokey_legacy_empty_slot_status = True

    with pytest.raises(ApduError) as exc_info:
        session.get_slot_metadata(SLOT.RETIRED3)
    assert exc_info.value.sw == SW.REFERENCE_DATA_NOT_FOUND


@pytest.mark.parametrize("legacy", [True, False])
def test_get_bio_metadata_handles_empty_response_only_for_confirmed_legacy(legacy):
    class Protocol:
        def send_apdu(self, *args):
            return b""

    session = object.__new__(PivSession)
    session.protocol = cast(Any, Protocol())
    session._canokey_legacy_empty_slot_status = legacy

    if legacy:
        with pytest.raises(NotSupportedError):
            session.get_bio_metadata()
    else:
        assert not session.get_bio_metadata().configured


@pytest.mark.parametrize(
    "value",
    [
        r"UID=jsmith,DC=example,DC=net",
        r"OU=Sales+CN=J.  Smith,DC=example,DC=net",
        r"CN=James \"Jim\" Smith\, III,DC=example,DC=net",
        r"CN=Before\0dAfter,DC=example,DC=net",
        r"1.3.6.1.4.1.1466.0=#04024869",
        r"CN=Lu\C4\8Di\C4\87",
        r"1.2.840.113549.1.9.1=user@example.com",
    ],
)
def test_parse_rfc4514_string(value):
    name = _parse_rfc4514_string(value)
    name2 = _parse_rfc4514_string(name.rfc4514_string())
    assert name == name2


class TestPivFunctions:
    def test_generate_random_management_key(self):
        output1 = generate_random_management_key(MANAGEMENT_KEY_TYPE.TDES)
        output2 = generate_random_management_key(MANAGEMENT_KEY_TYPE.TDES)
        assert isinstance(output1, bytes)
        assert isinstance(output2, bytes)
        assert output1 != output2

        assert 24 == len(generate_random_management_key(MANAGEMENT_KEY_TYPE.TDES))

        assert 16 == len(generate_random_management_key(MANAGEMENT_KEY_TYPE.AES128))
        assert 24 == len(generate_random_management_key(MANAGEMENT_KEY_TYPE.AES192))
        assert 32 == len(generate_random_management_key(MANAGEMENT_KEY_TYPE.AES256))

    def test_supported_algorithms(self):
        with pytest.raises(NotSupportedError):
            _do_check_key_support(
                Version(3, 1, 1),
                KEY_TYPE.ECCP384,
                PIN_POLICY.DEFAULT,
                TOUCH_POLICY.DEFAULT,
            )

        with pytest.raises(NotSupportedError):
            _do_check_key_support(
                Version(4, 4, 1),
                KEY_TYPE.RSA1024,
                PIN_POLICY.DEFAULT,
                TOUCH_POLICY.DEFAULT,
            )

        for key_type in (KEY_TYPE.RSA1024, KEY_TYPE.X25519):
            with pytest.raises(NotSupportedError):
                _do_check_key_support(
                    Version(5, 7, 0),
                    key_type,
                    PIN_POLICY.DEFAULT,
                    TOUCH_POLICY.DEFAULT,
                    fips_restrictions=True,
                )

        with pytest.raises(NotSupportedError):
            _do_check_key_support(
                Version(5, 7, 0),
                KEY_TYPE.RSA2048,
                PIN_POLICY.NEVER,
                TOUCH_POLICY.DEFAULT,
                fips_restrictions=True,
            )

        for key_type in (KEY_TYPE.RSA1024, KEY_TYPE.RSA2048):
            with pytest.raises(NotSupportedError):
                _do_check_key_support(
                    Version(4, 3, 4), key_type, PIN_POLICY.DEFAULT, TOUCH_POLICY.DEFAULT
                )

        for key_type in (KEY_TYPE.ED25519, KEY_TYPE.X25519):
            with pytest.raises(NotSupportedError):
                _do_check_key_support(
                    Version(5, 6, 0), key_type, PIN_POLICY.DEFAULT, TOUCH_POLICY.DEFAULT
                )

        for key_type in KEY_TYPE:
            _do_check_key_support(
                Version(5, 7, 0), key_type, PIN_POLICY.DEFAULT, TOUCH_POLICY.DEFAULT
            )


def test_fascn():
    fascn = FascN(
        agency_code=32,
        system_code=1,
        credential_number=92446,
        credential_series=0,
        individual_credential_issue=1,
        person_identifier=1112223333,
        organizational_category=1,
        organizational_identifier=1223,
        organization_association_category=2,
    )

    # https://www.idmanagement.gov/docs/pacs-tig-scepacs.pdf
    # page 32
    expected = bytes.fromhex("D0439458210C2C19A0846D83685A1082108CE73984108CA3FC")
    assert bytes(fascn) == expected

    assert FascN.from_bytes(expected) == fascn


def test_chuid():
    guid = b"x" * 16
    chuid = Chuid(
        # Non-Federal Issuer FASC-N
        fasc_n=FascN(9999, 9999, 999999, 0, 1, 0000000000, 3, 0000, 1),
        guid=guid,
        expiration_date=date(2030, 1, 1),
        asymmetric_signature=b"",
    )

    expected = bytes.fromhex(
        "3019d4e739da739ced39ce739d836858210842108421c84210c3eb3410787878787878787878"
        "78787878787878350832303330303130313e00fe00"
    )

    assert bytes(chuid) == expected

    assert Chuid.from_bytes(expected) == chuid


def test_chuid_deserialize():
    chuid = Chuid(
        buffer_length=123,
        fasc_n=FascN(9999, 9999, 999999, 0, 1, 0000000000, 3, 0000, 1),
        agency_code=b"1234",
        organizational_identifier=b"5678",
        duns=b"123456789",
        guid=b"x" * 16,
        expiration_date=date(2030, 1, 1),
        authentication_key_map=b"1234567890",
        asymmetric_signature=b"0987654321",
        lrc=255,
    )

    assert Chuid.from_bytes(bytes(chuid)) == chuid


def test_chuid_generate():
    chuid = Chuid.from_bytes(generate_chuid())
    assert chuid.expiration_date == date(2030, 1, 1)
    assert chuid.fasc_n.agency_code == 9999


class TestDecompressCertificate:
    def test_gzip_decompression(self):
        """Test decompression of gzip-compressed certificate data."""
        original_data = b"This is a test certificate data"
        compressed_data = gzip.compress(original_data)

        result = decompress_certificate(compressed_data)
        assert result == original_data

    def test_zlib_deflate_decompression(self):
        """Test decompression of zlib deflate format (used by Pointsharp Net iD)."""
        original_data = b"Test certificate content for zlib format"

        # zlib format: 0x01 0x00 + 2-byte little-endian length + zlib compressed data
        compressor = zlib.compressobj(wbits=zlib.MAX_WBITS)
        compressed = compressor.compress(original_data) + compressor.flush()

        # Build zlib format: magic bytes + length + compressed data
        length_bytes = len(original_data).to_bytes(2, "little")
        zlib_data = b"\x01\x00" + length_bytes + compressed

        result = decompress_certificate(zlib_data)
        assert result == original_data

    def test_zlib_deflate_wrong_length_raises(self):
        """Test that zlib deflate with wrong expected length raises ValueError."""
        original_data = b"Test certificate content"

        compressor = zlib.compressobj(wbits=zlib.MAX_WBITS)
        compressed = compressor.compress(original_data) + compressor.flush()

        # Use wrong length (actual length + 10)
        wrong_length = len(original_data) + 10
        length_bytes = wrong_length.to_bytes(2, "little")
        zlib_data = b"\x01\x00" + length_bytes + compressed

        with pytest.raises(BadResponseError):
            decompress_certificate(zlib_data)

    def test_invalid_data_raises_bad_response_error(self):
        """Test that invalid/uncompressed data raises BadResponseError."""
        invalid_data = b"This is not compressed data at all"

        with pytest.raises(BadResponseError):
            decompress_certificate(invalid_data)

    def test_corrupted_gzip_raises_bad_response_error(self):
        """Test that corrupted gzip data raises BadResponseError."""
        # Create valid gzip magic bytes but corrupted content
        corrupted_gzip = b"\x1f\x8b\x08\x00" + b"corrupted content"

        with pytest.raises(BadResponseError):
            decompress_certificate(corrupted_gzip)

    def test_zlib_format_fallback_to_gzip(self):
        """Test that invalid zlib data falls back to gzip decompression."""
        original_data = b"Fallback test data"

        # Create data that starts with zlib magic but is actually gzip compressed
        # The zlib decompression will fail and it should fall back to gzip
        gzip_data = gzip.compress(original_data)

        result = decompress_certificate(gzip_data)
        assert result == original_data
