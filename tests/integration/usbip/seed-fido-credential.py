#!/usr/bin/env python3
"""Exercise resident assertions and leave one credential for CLI tests."""

import argparse
import hashlib
import os

from fido2.ctap2 import ClientPin, CredentialManagement, Ctap2
from ykman.pcsc import list_devices
from yubikit.core.fido import SmartCardCtapDevice

RP_ID = "ckman.usbip.test"
USERS = (
    {
        "id": b"ckman-usbip-user-id",
        "name": "usbip-user",
        "displayName": "USB/IP user",
    },
    {
        "id": b"ckman-usbip-user-id-2",
        "name": "usbip-user-2",
        "displayName": "USB/IP user 2",
    },
)


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
        make_token = client_pin.get_pin_token(
            pin, ClientPin.PERMISSION.MAKE_CREDENTIAL, RP_ID
        )
        credentials = []
        for index, user in enumerate(USERS):
            client_data_hash = hashlib.sha256(
                f"ckman USB/IP resident credential {index}".encode()
            ).digest()
            response = ctap2.make_credential(
                client_data_hash,
                {"id": RP_ID, "name": "ckman USB/IP"},
                user,
                [{"type": "public-key", "alg": -7}],
                extensions={"hmac-secret": True},
                options={"rk": True},
                pin_uv_param=client_pin.protocol.authenticate(
                    make_token, client_data_hash
                ),
                pin_uv_protocol=client_pin.protocol.VERSION,
            )
            credential_data = response.auth_data.credential_data
            if credential_data is None:
                raise RuntimeError("authenticator did not return credential data")
            credentials.append(credential_data)

        assertion_hash = hashlib.sha256(
            b"ckman USB/IP resident getNextAssertion"
        ).digest()
        assertion_token = client_pin.get_pin_token(
            pin, ClientPin.PERMISSION.GET_ASSERTION, RP_ID
        )
        assertions = ctap2.get_assertions(
            RP_ID,
            assertion_hash,
            pin_uv_param=client_pin.protocol.authenticate(
                assertion_token, assertion_hash
            ),
            pin_uv_protocol=client_pin.protocol.VERSION,
        )
        if len(assertions) != len(credentials):
            raise RuntimeError(
                f"expected {len(credentials)} assertions, got {len(assertions)}"
            )
        public_keys = {
            credential.credential_id: credential.public_key
            for credential in credentials
        }
        returned_ids = {assertion.credential["id"] for assertion in assertions}
        if returned_ids != set(public_keys):
            raise RuntimeError("getNextAssertion returned unexpected credentials")
        for assertion in assertions:
            credential_id = assertion.credential["id"]
            assertion.verify(assertion_hash, public_keys[credential_id])

        management_token = client_pin.get_pin_token(
            pin, ClientPin.PERMISSION.CREDENTIAL_MGMT
        )
        credential_management = CredentialManagement(
            ctap2, client_pin.protocol, management_token
        )
        credential_management.delete_cred(
            {"type": "public-key", "id": credentials[1].credential_id}
        )

    print(credentials[0].credential_id.hex())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
