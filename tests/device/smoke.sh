#!/usr/bin/env bash
# Read-only smoke lifecycle: safe to run against real hardware. Verifies
# device identity and that every applet answers its info command.
set -euo pipefail

if [[ -z "${CANOKEY_USBIP:-}" && "${CANOKEY_TEST_PRIVATE_IFD:-}" != 1 ]]; then
  echo "ERROR: this test requires canokey-usbip or an isolated private test IFD" >&2
  exit 1
fi
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

# Remove the common --reader NAME suffix to exercise each global selector.
ckman_base=("${CKMAN[@]:0:$((${#CKMAN[@]} - 2))}")
reader_upper="$(tr '[:lower:]' '[:upper:]' <<<"$CANOKEY_PCSC_READER")"
for reader_filter in "$reader_upper" "${CANOKEY_PCSC_READER:1}"; do
  filtered_serials="$("${ckman_base[@]}" --reader "$reader_filter" list --serials)"
  grep -Fxq "$reported_serial" <<<"$filtered_serials"
done
filtered_serials="$("${ckman_base[@]}" --device "$reported_serial" list --serials)"
grep -Fxq "$reported_serial" <<<"$filtered_serials"
if grep -Fvxq "$reported_serial" <<<"$filtered_serials"; then
  echo "ERROR: --device list included a different serial" >&2
  exit 1
fi
all_serials="$("${ckman_base[@]}" list --serials)"
missing_serial=0
while grep -Fxq "$missing_serial" <<<"$all_serials"; do
  missing_serial=$((missing_serial + 1))
done
[[ -z "$("${ckman_base[@]}" --device "$missing_serial" list --serials)" ]]
[[ -z "$("${ckman_base[@]}" --reader nonexistent-ckman-audit-reader list --serials)" ]]

section "ckman config info"
"${CKMAN[@]}" config info

section "ckman config admin-pin status"
# Read-only verification-state query (empty VERIFY); every catalog firmware
# answers it. The Rust functional suite separately changes the Admin PIN
# through a pseudo-terminal, preserving the prompt-only secret interface.
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
