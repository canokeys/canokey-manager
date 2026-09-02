#!/usr/bin/env python3
"""Expose the production CanoKey firmware matrix to the shell smoke tests."""

import argparse

from yubikit.canokey import (
    CanoKeyFeature,
    get_feature_status,
    parse_firmware_version,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("normalize", "status"))
    parser.add_argument("version")
    parser.add_argument("feature", nargs="?")
    args = parser.parse_args()

    version = parse_firmware_version(args.version)
    if args.operation == "normalize":
        if args.feature is not None:
            parser.error("normalize does not accept a feature")
        print(version)
        return 0

    if args.feature is None:
        parser.error("status requires a feature")
    print(get_feature_status(version, CanoKeyFeature(args.feature)).value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
