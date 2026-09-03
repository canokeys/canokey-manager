#!/usr/bin/env bash
set -euo pipefail

: "${CANOKEY_USBIP:?This test must run under canokey-usbip}"
: "${CANOKEY_PCSC_READER:?canokey-usbip did not expose a PC/SC reader}"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib.sh"

run_applet_tests() {
  local applet="$1"
  shift

  section "pytest real-device ${applet} coverage"
  uv run pytest \
    --no-header \
    --no-serial \
    --reader "$CANOKEY_PCSC_READER" \
    --tb=short \
    -q \
    -ra \
    "$@"
}

status=0

run_applet_tests \
  "common PC/SC" \
  tests/device/test_ccid.py \
  tests/device/cli/test_misc.py || status=1

run_applet_tests \
  "FIDO over PC/SC" \
  tests/device/test_interfaces.py \
  tests/device/cli/test_fido.py \
  tests/device/test_fido.py || status=1

run_applet_tests \
  "OATH" \
  tests/device/cli/test_oath.py \
  tests/device/test_oath.py || status=1

run_applet_tests \
  "PIV" \
  tests/device/cli/piv \
  tests/device/test_piv.py || status=1

run_applet_tests \
  "OpenPGP" \
  tests/device/cli/test_openpgp.py \
  tests/device/test_openpgp.py || status=1

exit "$status"
