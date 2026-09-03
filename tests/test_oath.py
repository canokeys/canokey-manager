#  vim: set fileencoding=utf-8 :

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from ykman._cli.oath import change
from ykman._cli.util import CliFail
from ykman.oath import calculate_steam
from yubikit.core import NotSupportedError
from yubikit.oath import (
    HASH_ALGORITHM,
    OATH_TYPE,
    CredentialData,
    _derive_key,
    _format_cred_id,
    _parse_cred_id,
)


@pytest.mark.parametrize("remember", [True, False])
def test_change_does_not_update_remembered_key_when_device_update_fails(
    monkeypatch, remember
):
    session = MagicMock(device_id="device-id")
    session.derive_key.return_value = b"key"
    session.set_key.side_effect = NotSupportedError("not supported")
    keys = MagicMock()
    keys.__contains__.return_value = True
    ctx = SimpleNamespace(obj={"session": session, "oath_keys": keys})
    monkeypatch.setattr("ykman._cli.oath._init_session", lambda *args, **kwargs: None)

    with pytest.raises(CliFail, match="not supported"):
        change.callback.__wrapped__(
            ctx,
            password=None,
            clear=False,
            new_password="new password",
            remember=remember,
        )

    keys.put_secret.assert_not_called()
    keys.__delitem__.assert_not_called()
    keys.write.assert_not_called()


@pytest.mark.parametrize(
    ("truncated", "response"),
    [
        (True, bytes.fromhex("01234567")),
        (False, bytes.fromhex("0000012345670000000000000000000000000002")),
    ],
)
def test_calculate_steam_accepts_audited_canokey_truncated_response(
    truncated, response
):
    class Session:
        _canokey_truncated_calculate_response = truncated

        def calculate(self, credential_id, challenge):
            assert credential_id == b"steam"
            return response

    credential = SimpleNamespace(id=b"steam")
    assert calculate_steam(Session(), credential, timestamp=30) == "FR3RK"


@pytest.mark.parametrize(
    ("raw", "issuer", "name", "period"),
    [
        (b"20/Issuer:name", "Issuer", "name", 20),
        (b"weird/Issuer:name", "weird/Issuer", "name", 30),
        (b"Issuer:name", "Issuer", "name", 30),
        (b"20/name", None, "name", 20),
        (b"name", None, "name", 30),
    ],
)
def test_parse_cred_id(raw, issuer, name, period):
    parsed_issuer, parsed_name, parsed_period = _parse_cred_id(raw, OATH_TYPE.TOTP)
    assert (parsed_issuer, parsed_name, parsed_period) == (issuer, name, period)


@pytest.mark.parametrize(
    ("issuer", "name", "period", "expected"),
    [
        (None, "name", None, b"name"),
        ("Issuer", "name", None, b"Issuer:name"),
        ("Issuer", "name", 20, b"20/Issuer:name"),
        ("Issuer", "name", 30, b"Issuer:name"),
        (None, "name", 20, b"20/name"),
    ],
)
def test_format_cred_id(issuer, name, period, expected):
    kwargs = {}
    if period is not None:
        kwargs["period"] = period
    assert _format_cred_id(issuer, name, OATH_TYPE.TOTP, **kwargs) == expected


@pytest.mark.parametrize(
    ("salt", "password", "expected"),
    [
        (
            b"\0" * 8,
            "foobar",
            b"\xb0}\xa1\xe7\xde\x87\xf8\x9a\x87\xa2\xb5\x98\xea\xa2\x18\x8c",
        ),
        (
            b"12345678",
            "Hallå världen!",
            b"\xda\x81\x8ek,\xf0\xa2\xd0\xbf\x19\xb3\xdd\xd3K\x83\xf5",
        ),
        (
            b"saltsalt",
            "Ťᶒśƫ ᵽĥřӓşḛ",
            b"\xf3\xdf\xa7\x81T\xc8\x102\x99E\xfb\xc4\xb55\xe57",
        ),
    ],
)
def test_derive_key(salt, password, expected):
    assert _derive_key(salt, password) == expected


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        ("otpauth://totp/account?secret=abba", None),
        ("otpauth://totp/account?secret=abba&issuer=Test", "Test"),
        ("otpauth://totp/Test:account?secret=abba", "Test"),
        ("otpauth://totp/TestA:account?secret=abba&issuer=TestB", "TestB"),
    ],
)
def test_parse_uri_issuer(uri, expected):
    assert CredentialData.parse_uri(uri).issuer == expected


def test_parse_uri_full_payload():
    data = CredentialData.parse_uri(
        "otpauth://totp/Issuer:account"
        "?secret=abba&issuer=Issuer"
        "&algorithm=SHA256&digits=7"
        "&period=20&counter=5"
    )
    assert data.secret == b"\0B"
    assert data.issuer == "Issuer"
    assert data.name == "account"
    assert data.oath_type == OATH_TYPE.TOTP
    assert data.hash_algorithm == HASH_ALGORITHM.SHA256
    assert data.digits == 7
    assert data.period == 20
    assert data.counter == 5
