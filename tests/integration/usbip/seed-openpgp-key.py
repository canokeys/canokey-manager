#!/usr/bin/env python3
"""Provision a standard OpenPGP key for black-box CLI lifecycle tests."""

import argparse
import os

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
    with devices[0].open_connection(SmartCardConnection) as connection:
        session = OpenPgpSession(connection)
        session.verify_admin(admin_pin)
        session.generate_rsa_key(KEY_REF.SIG, RSA_SIZE.RSA2048)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
