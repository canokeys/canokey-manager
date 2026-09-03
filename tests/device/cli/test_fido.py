from yubikit.canokey import CanoKeyFeature

from .. import condition


@condition.canokey(True)
@condition.canokey_feature(CanoKeyFeature.FIDO_PCSC)
def test_fido_info_over_pcsc(ykman_cli):
    output = ykman_cli("fido", "info").output

    assert "PIN:" in output
    assert "Minimum PIN length:" in output
    assert "Not supported" not in output
