#!/usr/bin/env python3
"""Provision and exercise standard OpenPGP keys for CLI lifecycle tests."""

import argparse
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from ykman.pcsc import list_devices
from yubikit.core.smartcard import SmartCardConnection
from yubikit.openpgp import KEY_REF, RSA_SIZE, OpenPgpSession


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("reader")
    args = parser.parse_args()

    devices = list_devices(args.reader)
    if len(devices) != 1:
        parser.error(f"expected one PC/SC reader, found {len(devices)}")

    admin_pin = os.environ["CKMAN_TEST_OPENPGP_ADMIN_PIN"]
    pin = os.environ["CKMAN_TEST_OPENPGP_PIN"]
    with devices[0].open_connection(SmartCardConnection) as connection:
        session = OpenPgpSession(connection)
        session.verify_admin(admin_pin)
        public_keys = {
            key_ref: session.generate_rsa_key(key_ref, RSA_SIZE.RSA2048)
            for key_ref in (KEY_REF.SIG, KEY_REF.DEC, KEY_REF.AUT)
        }

        message = b"ckman USB/IP OpenPGP cryptographic lifecycle"
        session.verify_pin(pin)
        signature = session.sign(message, hashes.SHA256())
        public_keys[KEY_REF.SIG].verify(
            signature, message, padding.PKCS1v15(), hashes.SHA256()
        )

        session.verify_pin(pin, extended=True)
        ciphertext = public_keys[KEY_REF.DEC].encrypt(message, padding.PKCS1v15())
        if session.decrypt(ciphertext) != message:
            raise RuntimeError("OpenPGP RSA decryption mismatch")
        authentication = session.authenticate(message, hashes.SHA256())
        public_keys[KEY_REF.AUT].verify(
            authentication, message, padding.PKCS1v15(), hashes.SHA256()
        )

    print("OpenPGP SIG/DEC/AUT cryptographic operations verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
