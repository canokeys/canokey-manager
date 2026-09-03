from types import SimpleNamespace
from typing import cast

import pytest
from fido2.ctap import STATUS, CtapError
from fido2.ctap1 import Ctap1
from fido2.hid import CTAPHID
from ykman import pcsc
from yubikit.core import PID
from yubikit.core.fido import FidoConnection, SmartCardCtapDevice
from yubikit.core.smartcard import SW, ApduError, SmartCardProtocol

CTAP1_VERSION_APDU = bytes.fromhex("000300000000000000")


def _ctap_device(response=b"", sw=SW.OK, is_canokey=True):
    class Protocol:
        def send_apdu(self, *args):
            if sw != SW.OK:
                raise ApduError(response, sw)
            return response

    device = SmartCardCtapDevice.__new__(SmartCardCtapDevice)
    device.protocol = cast(SmartCardProtocol, Protocol())
    device._is_canokey = is_canokey
    return device


def test_default_reader_filter_includes_yubikey_and_canokey(monkeypatch):
    readers = [
        SimpleNamespace(name="Yubico YubiKey OTP+FIDO+CCID 00 00"),
        SimpleNamespace(name="CanoKey CCID 00 00"),
        SimpleNamespace(name="Generic USB Smart Card Reader 00 00"),
    ]
    monkeypatch.setattr(pcsc, "list_readers", lambda: readers)

    devices = pcsc.list_devices()

    assert [device.reader.name for device in devices] == [
        readers[0].name,
        readers[1].name,
    ]
    assert devices[1].pid == PID.CK_FIDO_CCID


def test_explicit_reader_filter_can_select_external_reader(monkeypatch):
    reader = SimpleNamespace(name="Generic USB Smart Card Reader 00 00")
    monkeypatch.setattr(pcsc, "list_readers", lambda: [reader])

    devices = pcsc.list_devices("Generic USB")

    assert len(devices) == 1
    assert devices[0].pid is None


def test_canokey_usb_reader_supports_fido_over_pcsc():
    device = pcsc.ScardYubiKeyDevice(SimpleNamespace(name="CanoKey CCID 00 00"))

    assert device.supports_connection(FidoConnection)
    assert device.supports_connection(SmartCardCtapDevice)


def test_yubikey_usb_reader_keeps_existing_fido_behavior():
    device = pcsc.ScardYubiKeyDevice(
        SimpleNamespace(name="Yubico YubiKey OTP+FIDO+CCID 00 00")
    )

    assert not device.supports_connection(FidoConnection)


def test_canokey_ctap1_response_restores_success_status():
    device = _ctap_device(b"U2F_V2")

    assert Ctap1(device).get_version() == "U2F_V2"


def test_canokey_ctap1_response_preserves_apdu_error():
    device = _ctap_device(b"error", SW.INCORRECT_PARAMETERS)

    assert device.call(CTAPHID.MSG, CTAP1_VERSION_APDU) == b"error\x6a\x80"


def test_canokey_ctap1_response_keeps_polling_during_touch():
    class Protocol:
        responses = iter([ApduError(bytes([STATUS.UPNEEDED]), 0x9100), b"registered"])

        def send_apdu(self, *args):
            response = next(self.responses)
            if isinstance(response, Exception):
                raise response
            return response

    device = SmartCardCtapDevice.__new__(SmartCardCtapDevice)
    device.protocol = cast(SmartCardProtocol, Protocol())
    device._is_canokey = True

    assert device.call(CTAPHID.MSG, CTAP1_VERSION_APDU) == b"registered\x90\x00"


def test_yubikey_smartcard_ctap_error_behavior_is_unchanged():
    device = _ctap_device(b"error", SW.INCORRECT_PARAMETERS, is_canokey=False)

    with pytest.raises(CtapError) as exc_info:
        device.call(CTAPHID.MSG, CTAP1_VERSION_APDU)
    assert exc_info.value.code == CtapError.ERR.OTHER
