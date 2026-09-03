#!/usr/bin/env bash
set -euo pipefail

: "${CANOKEY_USBIP:?This test must run under canokey-usbip}"
: "${CANOKEY_PCSC_READER:?canokey-usbip did not expose a PC/SC reader}"
: "${CANOKEY_FIRMWARE_VERSION:?canokey-usbip did not expose a firmware version}"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

export CANOKEY_USBIP_WORK_DIR="$work_dir"
export XDG_CONFIG_HOME="$work_dir/config"
export XDG_DATA_HOME="$work_dir/data"
export CKMAN_TEST_KEYRING_FILE="$work_dir/keyring.json"
export PYTHON_KEYRING_BACKEND="tests.integration.usbip.keyring_backend.Keyring"

source "$script_dir/lib.sh"

export CANOKEY_FIRMWARE_VERSION_NORMALIZED
CANOKEY_FIRMWARE_VERSION_NORMALIZED="$(
  uv run python "$script_dir/firmware.py" normalize "$CANOKEY_FIRMWARE_VERSION"
)"

section "ckman info"
device_info="$("${CKMAN[@]}" info)"
printf '%s\n' "$device_info"

reported_firmware="$(
  sed -n 's/^Firmware version:[[:space:]]*//p' <<<"$device_info"
)"
if [[ "$reported_firmware" != "$CANOKEY_FIRMWARE_VERSION_NORMALIZED" ]]; then
  echo "ERROR: admin applet reported firmware ${reported_firmware:-missing}, but canokey-usbip selected ${CANOKEY_FIRMWARE_VERSION_NORMALIZED}" >&2
  exit 1
fi
if [[ -n "${CANOKEY_FIRMWARE_ID:-}" ]]; then
  workflow_firmware="$(
    uv run python "$script_dir/firmware.py" normalize "$CANOKEY_FIRMWARE_ID"
  )"
  if [[ "$reported_firmware" != "$workflow_firmware" ]]; then
    echo "ERROR: workflow expected firmware ${workflow_firmware}, but the device reported ${reported_firmware}" >&2
    exit 1
  fi
fi
echo "CanoKey firmware identity verified: ${reported_firmware}."

"$script_dir/fido.sh"

section "ckman list"
list_output="$(uv run ckman list)"
printf '%s\n' "$list_output"
grep -Fq "CanoKey" <<<"$list_output"

reported_serial="$(
  sed -n 's/^Serial number:[[:space:]]*//p' <<<"$device_info"
)"
[[ "$reported_serial" =~ ^[0-9]+$ ]]
serials_output="$(uv run ckman list --serials)"
grep -Fxq "$reported_serial" <<<"$serials_output"

readers_output="$(uv run ckman list --readers)"
grep -Fxq "$CANOKEY_PCSC_READER" <<<"$readers_output"

section "ckman apdu"
capture_without_secrets \
  "RECV (SW=9000)" \
  "${CKMAN[@]}" apdu --app openpgp --no-pretty 00ca004f=
run_versioned_feature \
  "ckman apdu OpenPGP GET CHALLENGE" \
  "openpgp-get-challenge" \
  capture_without_secrets \
  "RECV (SW=9000)" \
  "${CKMAN[@]}" apdu --app openpgp --no-pretty 84/08=

"$script_dir/piv.sh"
"$script_dir/oath.sh"
"$script_dir/openpgp.sh"
"$script_dir/device-tests.sh"
