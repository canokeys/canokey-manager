from types import SimpleNamespace

from ykman import pcsc
from yubikit.core import PID
from yubikit.core.fido import FidoConnection, SmartCardCtapDevice


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
