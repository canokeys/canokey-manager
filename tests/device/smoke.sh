#!/usr/bin/env bash
# Read-only smoke lifecycle: safe to run against real hardware. Verifies
# device identity and that every applet answers its info command.
set -euo pipefail

: "${CANOKEY_USBIP:?This test must run under canokey-usbip}"
: "${CANOKEY_PCSC_READER:?canokey-usbip did not expose a PC/SC reader}"
: "${CANOKEY_FIRMWARE_VERSION:?canokey-usbip did not expose a firmware version}"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

export CANOKEY_USBIP_WORK_DIR="$work_dir"

source "$script_dir/lib.sh"

export CANOKEY_FIRMWARE_VERSION_NORMALIZED
CANOKEY_FIRMWARE_VERSION_NORMALIZED="$(
  "$script_dir/firmware.sh" normalize "$CANOKEY_FIRMWARE_VERSION"
)"

section "ckman info"
device_info="$("${CKMAN[@]}" info)"
printf '%s\n' "$device_info"

reported_firmware="$(
  sed -n 's/^Firmware version:[[:space:]]*//p' <<<"$device_info"
)"
reported_firmware="$("$script_dir/firmware.sh" normalize "$reported_firmware")"
if [[ "$reported_firmware" != "$CANOKEY_FIRMWARE_VERSION_NORMALIZED" ]]; then
  echo "ERROR: admin applet reported firmware ${reported_firmware:-missing}, but canokey-usbip selected ${CANOKEY_FIRMWARE_VERSION_NORMALIZED}" >&2
  exit 1
fi
echo "CanoKey firmware identity verified: ${reported_firmware}."

section "ckman info: chip ID"
# The vendor chip-ID command exists on newer firmware; older firmware prints
# <unavailable> instead of failing the read-only info output. Either way the
# line must be present.
grep -Fq "Chip ID:" <<<"$device_info"

section "ckman list"
list_output="$("${CKMAN[@]}" list)"
printf '%s\n' "$list_output"
grep -Fq "CanoKey" <<<"$list_output"

reported_serial="$(sed -n 's/^Serial number:[[:space:]]*//p' <<<"$device_info")"
[[ "$reported_serial" =~ ^[0-9]+$ ]]
serials_output="$("${CKMAN[@]}" list --serials)"
grep -Fxq "$reported_serial" <<<"$serials_output"

section "ckman config info"
"${CKMAN[@]}" config info

section "ckman config admin-pin status"
# Read-only verification-state query (empty VERIFY); every catalog firmware
# answers it. Changing the Admin PIN is prompt-only by design (no argv
# secret) and therefore cannot run on a TTY-less runner.
run_versioned_feature \
  "ckman config admin-pin status" \
  "admin-pin-status" \
  "${CKMAN[@]}" config admin-pin status

section "ckman oath info"
"${CKMAN[@]}" oath info

section "ckman piv info"
"${CKMAN[@]}" piv info

section "ckman openpgp info"
"${CKMAN[@]}" openpgp info

section "ckman fido info"
# FIDO over CCID exists from firmware 1.5.2; on 1.3 the command errors
# cleanly before any I/O, and the matrix reports it UNSUPPORTED instead.
run_versioned_feature \
  "ckman fido info" \
  "fido-pcsc" \
  "${CKMAN[@]}" fido info

echo
echo "Smoke lifecycle passed on firmware ${CANOKEY_FIRMWARE_VERSION_NORMALIZED}."
