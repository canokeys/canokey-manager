#!/usr/bin/env bash
set -euo pipefail

: "${CANOKEY_USBIP:?This test must run under canokey-usbip}"
: "${CANOKEY_PCSC_READER:?canokey-usbip did not expose a PC/SC reader}"

CKMAN=(uv run ckman --reader "$CANOKEY_PCSC_READER")

echo "=== ckman info ==="
"${CKMAN[@]}" info

echo "=== ckman piv info ==="
"${CKMAN[@]}" piv info

echo "=== ckman oath info ==="
"${CKMAN[@]}" oath info

echo "=== ckman openpgp info ==="
"${CKMAN[@]}" openpgp info
