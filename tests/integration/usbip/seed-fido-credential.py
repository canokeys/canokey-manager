#!/usr/bin/env python3
"""Provision one resident FIDO credential for black-box CLI tests."""

import argparse
import hashlib
import os

from fido2.ctap2 import ClientPin, Ctap2
from ykman.pcsc import list_devices
from yubikit.core.fido import SmartCardCtapDevice

RP_ID = "ckman.usbip.test"
USER_ID = b"ckman-usbip-user-id"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("reader")
    args = parser.parse_args()

    devices = list_devices(args.reader)
    if len(devices) != 1:
        parser.error(f"expected one PC/SC reader, found {len(devices)}")

    pin = os.environ["CKMAN_TEST_FIDO_PIN"]
    with devices[0].open_connection(SmartCardCtapDevice) as device:
        ctap2 = Ctap2(device)
        client_pin = ClientPin(ctap2)
        token = client_pin.get_pin_token(
            pin,
            ClientPin.PERMISSION.MAKE_CREDENTIAL,
            RP_ID,
        )
        client_data_hash = hashlib.sha256(b"ckman USB/IP resident credential").digest()
        response = ctap2.make_credential(
            client_data_hash,
            {"id": RP_ID, "name": "ckman USB/IP"},
            {
                "id": USER_ID,
                "name": "usbip-user",
                "displayName": "USB/IP user",
            },
            [{"type": "public-key", "alg": -7}],
            extensions={"hmac-secret": True},
            options={"rk": True},
            pin_uv_param=client_pin.protocol.authenticate(token, client_data_hash),
            pin_uv_protocol=client_pin.protocol.VERSION,
        )

    credential_data = response.auth_data.credential_data
    if credential_data is None:
        raise RuntimeError("authenticator did not return attested credential data")
    print(credential_data.credential_id.hex())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
