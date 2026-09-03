#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib.sh"

FIDO_INITIAL_PIN="123456"
FIDO_PIN="654321"

fido_status="$(firmware_feature_status fido-pcsc)"
case "$fido_status" in
  supported) ;;
  unsupported)
    section "ckman fido command lifecycle"
    unsupported_feature \
      "the ckman FIDO command lifecycle" \
      "FIDO over PC/SC is unavailable."
    exit 0
    ;;
  unknown)
    echo "ERROR: UNKNOWN: fido-pcsc has not been validated for CanoKey firmware ${CANOKEY_FIRMWARE_VERSION_NORMALIZED}" >&2
    exit 1
    ;;
esac

# Keep this as the first device operation. Firmware 2.0.0 and newer only allow
# the standard CTAP reset command shortly after power-up.
section "ckman fido reset"
capture_without_secrets \
  "FIDO application data reset." \
  "${CKMAN[@]}" fido reset --force

section "ckman fido access change-pin (set)"
capture_without_secrets \
  "FIDO PIN updated." \
  "${CKMAN[@]}" fido access change-pin --new-pin "$FIDO_INITIAL_PIN"

section "ckman fido access verify-pin"
capture_without_secrets \
  "PIN verified." \
  "${CKMAN[@]}" fido access verify-pin --pin "$FIDO_INITIAL_PIN"

section "ckman fido access change-pin (change)"
capture_without_secrets \
  "FIDO PIN updated." \
  "${CKMAN[@]}" fido access change-pin \
  --pin "$FIDO_INITIAL_PIN" \
  --new-pin "$FIDO_PIN"

capture_without_secrets \
  "PIN verified." \
  "${CKMAN[@]}" fido access verify-pin --pin "$FIDO_PIN"

credential_status="$(firmware_feature_status fido-credential-management)"
case "$credential_status" in
  supported) ;;
  unsupported)
    unsupported_feature \
      "ckman fido credentials list/delete" \
      "Credential management is unavailable."
    exit 0
    ;;
  unknown)
    echo "ERROR: UNKNOWN: fido-credential-management has not been validated for CanoKey firmware ${CANOKEY_FIRMWARE_VERSION_NORMALIZED}" >&2
    exit 1
    ;;
esac

section "Provision resident FIDO credential"
export CKMAN_TEST_FIDO_PIN="$FIDO_PIN"
credential_id="$(
  uv run python "$script_dir/seed-fido-credential.py" "$CANOKEY_PCSC_READER"
)"
[[ "$credential_id" =~ ^[0-9a-f]+$ ]]

section "ckman fido credentials list"
credentials_file="$CANOKEY_USBIP_WORK_DIR/fido-credentials.csv"
"${CKMAN[@]}" fido credentials list \
  --pin "$FIDO_PIN" \
  --csv >"$credentials_file"
cat "$credentials_file"
uv run python "$script_dir/check-fido-credentials.py" \
  "$credentials_file" \
  "$credential_id" \
  present

section "ckman fido credentials delete"
capture_without_secrets \
  "Credential deleted." \
  "${CKMAN[@]}" fido credentials delete \
  --pin "$FIDO_PIN" \
  --force \
  "$credential_id"

"${CKMAN[@]}" fido credentials list \
  --pin "$FIDO_PIN" \
  --csv >"$credentials_file"
uv run python "$script_dir/check-fido-credentials.py" \
  "$credentials_file" \
  "$credential_id" \
  absent
echo "FIDO credential lifecycle cleanup complete."
