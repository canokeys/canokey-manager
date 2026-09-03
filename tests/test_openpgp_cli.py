from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from ykman._cli.openpgp import set_pin_retries
from ykman._cli.util import CliFail
from yubikit import canokey
from yubikit.core import Version


def test_set_pin_retries_reports_unknown_canokey_feature(monkeypatch):
    version = Version(3, 1, 1)
    session = MagicMock()
    ctx = SimpleNamespace(
        obj={"session": session, "info": SimpleNamespace(version=version)}
    )
    require_feature = MagicMock(
        side_effect=canokey.UnknownFeatureError(
            "openpgp-set-retries support is unknown for CanoKey firmware 3.1.1"
        )
    )
    monkeypatch.setattr(canokey, "is_canokey", lambda connection: True)
    monkeypatch.setattr(canokey, "require_feature", require_feature)

    with pytest.raises(CliFail, match="support is unknown"):
        set_pin_retries.callback.__wrapped__(
            ctx,
            admin_pin="12345678",
            user_pin_retries=3,
            reset_code_retries=3,
            admin_pin_retries=3,
            force=True,
        )

    require_feature.assert_called_once_with(
        version, canokey.CanoKeyFeature.OPENPGP_SET_RETRIES
    )
    session.verify_admin.assert_not_called()
    session.set_pin_attempts.assert_not_called()
