#!/usr/bin/env bash
# FIDO lifecycle over FIDO-over-CCID (the rig exposes no hidraw node): PIN
# set/verify, largeBlobs array round trip, and credential-management behavior
# on an empty device. DESTRUCTIVE: sets the FIDO2 PIN and writes the
# largeBlobs array. Requires CKMAN_DESTRUCTIVE=1 and a usbip test key.
#
# Deliberately not covered here: `fido touch-test` (user presence needs the
# HID path) and `fido config enable-long-touch-for-reset` (persistent; only a
# full reset clears it).
set -euo pipefail

: "${CKMAN_DESTRUCTIVE:?FIDO lifecycle writes to the device; set CKMAN_DESTRUCTIVE=1}"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

# compat/run invokes this script directly (not via smoke.sh), so it provides
# its own scratch dir and normalized version, like smoke.sh.
export CANOKEY_USBIP_WORK_DIR="$work_dir"
export CANOKEY_FIRMWARE_VERSION_NORMALIZED
CANOKEY_FIRMWARE_VERSION_NORMALIZED="$(
  "$script_dir/firmware.sh" normalize "$CANOKEY_FIRMWARE_VERSION"
)"

source "$script_dir/lib.sh"

FIDO_PIN="123456"

section "ckman fido info"
run_versioned_feature \
  "ckman fido info" \
  "fido-pcsc" \
  "${CKMAN[@]}" fido info

if [[ "$FEATURE_AVAILABLE" == true ]]; then
  section "ckman fido access set-pin / verify-pin"
  "${CKMAN[@]}" fido access set-pin --new-pin "$FIDO_PIN"
  "${CKMAN[@]}" fido access verify-pin --pin "$FIDO_PIN"
fi

fido_blobs_roundtrip() {
  # A complete serialized largeBlobs array: the leftmost 16 bytes of the
  # SHA-256 of the CBOR payload, followed by the payload (an empty CBOR
  # array).
  python3 -c '
import hashlib
import sys

payload = b"\x80"
with open(sys.argv[1], "wb") as output:
    output.write(hashlib.sha256(payload).digest()[:16] + payload)
' "$CANOKEY_USBIP_WORK_DIR/blobs.bin"
  "${CKMAN[@]}" fido blobs write "$CANOKEY_USBIP_WORK_DIR/blobs.bin" \
    --pin "$FIDO_PIN" \
    --force
  "${CKMAN[@]}" fido blobs read "$CANOKEY_USBIP_WORK_DIR/blobs-out.bin"
  cmp "$CANOKEY_USBIP_WORK_DIR/blobs.bin" "$CANOKEY_USBIP_WORK_DIR/blobs-out.bin"
}
run_versioned_feature \
  "ckman fido blobs write/read" \
  "fido-large-blobs" \
  fido_blobs_roundtrip

# The CLI cannot create resident credentials (no make-credential path), so on
# the fresh virtual device the rename must fail cleanly with "no matching
# credential" after enumerating an empty store.
fido_update_user_no_match() {
  expect_failure \
    "fido credentials update-user without resident credentials" \
    "${CKMAN[@]}" fido credentials update-user abcd \
    --username nobody \
    --pin "$FIDO_PIN" \
    --force
}
run_versioned_feature \
  "ckman fido credentials update-user (empty device)" \
  "fido-credential-management" \
  fido_update_user_no_match

echo "FIDO lifecycle passed."
