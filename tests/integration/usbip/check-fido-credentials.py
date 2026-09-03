#!/usr/bin/env python3
"""Validate the CSV emitted by ``ckman fido credentials list``."""

import argparse
import csv
from pathlib import Path

EXPECTED = {
    "rp_id": "ckman.usbip.test",
    "user_name": "usbip-user",
    "user_display_name": "USB/IP user",
    "user_id": "636b6d616e2d75736269702d757365722d6964",
}
FIELDNAMES = [
    "credential_id",
    "rp_id",
    "user_name",
    "user_display_name",
    "user_id",
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("csv_file", type=Path)
    parser.add_argument("credential_id")
    parser.add_argument("state", choices=("present", "absent"))
    args = parser.parse_args()

    with args.csv_file.open(newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        if reader.fieldnames != FIELDNAMES:
            parser.error(f"unexpected CSV header: {reader.fieldnames!r}")
        rows = [row for row in reader if row.get("credential_id") == args.credential_id]
    if args.state == "absent":
        if rows:
            parser.error("deleted credential is still present")
        return 0

    if len(rows) != 1:
        parser.error(f"expected one credential row, found {len(rows)}")
    actual = {key: rows[0].get(key) for key in EXPECTED}
    if actual != EXPECTED:
        parser.error(f"credential metadata mismatch: {actual!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
