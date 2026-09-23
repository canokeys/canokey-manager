#!/usr/bin/env bash
# OATH lifecycle: vendor serial and KeePassXC-style HMAC-SHA1
# challenge-response from a PASS slot. DESTRUCTIVE: `config pass set` writes
# the slot configuration. Requires CKMAN_DESTRUCTIVE=1 and a usbip test key.
#
# Both vendor commands are gated to the pinned 3.1 evidence
# (oath-challenge-response); the script reports UNSUPPORTED and passes on
# older firmware.
set -euo pipefail

: "${CKMAN_DESTRUCTIVE:?OATH lifecycle writes to the device; set CKMAN_DESTRUCTIVE=1}"

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

HMAC_KEY="00112233445566778899aabbccddeeff00112233"
CHALLENGE="00112233445566778899"
# Factory default device Admin PIN.
ADMIN_PIN="123456"

oath_challenge_response_roundtrip() {
  section "ckman oath serial"
  local serial
  serial="$("${CKMAN[@]}" oath serial)"
  [[ "$serial" =~ ^[0-9]+$ ]]

  section "ckman config pass set (HMAC-SHA1 slot)"
  "${CKMAN[@]}" config pass set short hmac \
    --key "$HMAC_KEY" \
    --admin-pin "$ADMIN_PIN"

  section "ckman oath challenge-response"
  local response expected
  response="$("${CKMAN[@]}" oath challenge-response short "$CHALLENGE")"
  [[ "$response" =~ ^[0-9a-f]{40}$ ]]
  # Host-side known-answer: HMAC-SHA1 over the same key and challenge.
  expected="$(python3 -c '
import hmac
import hashlib
import sys

print(hmac.new(bytes.fromhex(sys.argv[1]), bytes.fromhex(sys.argv[2]), hashlib.sha1).hexdigest())
' "$HMAC_KEY" "$CHALLENGE")"
  if [[ "$response" != "$expected" ]]; then
    echo "ERROR: challenge-response mismatch: card $response, host $expected" >&2
    return 1
  fi
  echo "HMAC-SHA1 challenge-response matches the host-side known answer."
}

run_versioned_feature \
  "ckman oath serial / challenge-response" \
  "oath-challenge-response" \
  oath_challenge_response_roundtrip

echo "OATH lifecycle passed."
