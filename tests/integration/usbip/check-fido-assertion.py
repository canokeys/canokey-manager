#!/usr/bin/env python3
"""Exercise a non-discoverable FIDO credential over the PC/SC transport."""

import argparse
import hashlib
import os

from fido2.ctap2 import ClientPin, Ctap2
from ykman.pcsc import list_devices
from yubikit.core.fido import SmartCardCtapDevice

RP_ID = "ckman.assertion.test"


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
        permissions = (
            ClientPin.PERMISSION.MAKE_CREDENTIAL | ClientPin.PERMISSION.GET_ASSERTION
        )
        token = client_pin.get_pin_token(pin, permissions, RP_ID)
        create_hash = hashlib.sha256(b"ckman USB/IP create assertion key").digest()
        response = ctap2.make_credential(
            create_hash,
            {"id": RP_ID, "name": "ckman USB/IP assertion"},
            {"id": b"assertion-user", "name": "assertion-user"},
            [{"type": "public-key", "alg": -7}],
            options={"rk": False},
            pin_uv_param=client_pin.protocol.authenticate(token, create_hash),
            pin_uv_protocol=client_pin.protocol.VERSION,
        )
        credential_data = response.auth_data.credential_data
        if credential_data is None:
            raise RuntimeError("authenticator did not return credential data")

        assertion_hash = hashlib.sha256(b"ckman USB/IP get assertion").digest()
        assertion = ctap2.get_assertion(
            RP_ID,
            assertion_hash,
            [{"type": "public-key", "id": credential_data.credential_id}],
            pin_uv_param=client_pin.protocol.authenticate(token, assertion_hash),
            pin_uv_protocol=client_pin.protocol.VERSION,
        )
        if assertion.credential["id"] != credential_data.credential_id:
            raise RuntimeError("authenticator returned the wrong credential")
        assertion.verify(assertion_hash, credential_data.public_key)

    print("FIDO makeCredential/getAssertion signature verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
