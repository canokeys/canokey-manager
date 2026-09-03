from fido2.ctap1 import Ctap1
from fido2.ctap2 import Ctap2
from yubikit.canokey import CanoKeyFeature

from . import condition


@condition.canokey(True)
@condition.canokey_feature(CanoKeyFeature.FIDO_PCSC)
def test_u2f_version_over_pcsc(pcsc_fido_connection):
    assert Ctap1(pcsc_fido_connection).get_version() == "U2F_V2"


@condition.canokey(True)
@condition.canokey_feature(CanoKeyFeature.FIDO_PCSC)
def test_get_info_over_pcsc(pcsc_fido_connection):
    info = Ctap2(pcsc_fido_connection).info

    assert "FIDO_2_0" in info.versions or "FIDO_2_1" in info.versions
    assert info.aaguid is not None
