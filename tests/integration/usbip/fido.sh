#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib.sh"

FIDO_INITIAL_PIN="123456"
FIDO_PIN="654321"
FIDO_CONFIG_PIN="789012"

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

reset_window_status="$(
  firmware_feature_status fido-reset-requires-power-cycle
)"
case "$reset_window_status" in
  unsupported)
    section "ckman fido reset"
    capture_without_secrets \
      "FIDO application data reset." \
      "${CKMAN[@]}" fido reset --force
    ;;
  supported)
    section "ckman fido reset"
    echo "NOT RUN: firmware requires reset shortly after power-up, before the hosted PC/SC path exposes the card."
    ;;
  unknown)
    echo "ERROR: UNKNOWN: the FIDO reset window has not been validated for CanoKey firmware ${CANOKEY_FIRMWARE_VERSION_NORMALIZED}" >&2
    exit 1
    ;;
esac

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

section "FIDO makeCredential/getAssertion"
export CKMAN_TEST_FIDO_PIN="$FIDO_PIN"
uv run python "$script_dir/check-fido-assertion.py" "$CANOKEY_PCSC_READER"

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
credential_id="$(
  uv run python "$script_dir/seed-fido-credential.py" "$CANOKEY_PCSC_READER"
)"
[[ "$credential_id" =~ ^[0-9a-f]+$ ]]

section "ckman fido credentials list"
credentials_output="$(
  "${CKMAN[@]}" fido credentials list --pin "$FIDO_PIN"
)"
printf '%s\n' "$credentials_output"
grep -Fq "ckman.usbip.test" <<<"$credentials_output"
grep -Fq "usbip-user" <<<"$credentials_output"

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

config_status="$(firmware_feature_status fido-authenticator-config)"
case "$config_status" in
  supported)
    section "ckman fido config toggle-always-uv"
    read_always_uv() {
      "${CKMAN[@]}" fido info |
        sed -n 's/^Always Require UV:[[:space:]]*//p'
    }
    initial_always_uv="$(read_always_uv)"
    case "$initial_always_uv" in
      On)
        first_toggle="off"
        second_toggle="on"
        ;;
      Off)
        first_toggle="on"
        second_toggle="off"
        ;;
      *)
        echo "ERROR: unexpected Always Require UV state: ${initial_always_uv:-missing}" >&2
        exit 1
        ;;
    esac
    capture_without_secrets \
      "Always Require UV is ${first_toggle}." \
      "${CKMAN[@]}" fido config toggle-always-uv --pin "$FIDO_PIN"
    [[ "$(read_always_uv)" == "${first_toggle^}" ]]
    capture_without_secrets \
      "Always Require UV is ${second_toggle}." \
      "${CKMAN[@]}" fido config toggle-always-uv --pin "$FIDO_PIN"
    [[ "$(read_always_uv)" == "$initial_always_uv" ]]

    section "ckman fido access set-min-length"
    capture_without_secrets \
      "Minimum PIN length set." \
      "${CKMAN[@]}" fido access set-min-length --pin "$FIDO_PIN" 6
    minimum_pin_length="$(
      "${CKMAN[@]}" fido info |
        sed -n 's/^Minimum PIN length:[[:space:]]*//p'
    )"
    [[ "$minimum_pin_length" == 6 ]]

    section "ckman fido access force-change"
    capture_without_secrets \
      "Force PIN change set." \
      "${CKMAN[@]}" fido access force-change --pin "$FIDO_PIN"
    "${CKMAN[@]}" fido info | grep -Fq "must be changed before it can be used"
    expect_failure \
      "Verifying a FIDO PIN marked for forced change" \
      "${CKMAN[@]}" fido access verify-pin --pin "$FIDO_PIN"
    capture_without_secrets \
      "FIDO PIN updated." \
      "${CKMAN[@]}" fido access change-pin \
      --pin "$FIDO_PIN" \
      --new-pin "$FIDO_CONFIG_PIN"
    capture_without_secrets \
      "PIN verified." \
      "${CKMAN[@]}" fido access verify-pin --pin "$FIDO_CONFIG_PIN"
    ;;
  unsupported)
    unsupported_feature \
      "ckman fido authenticator configuration" \
      "Authenticator Configuration is unavailable."
    ;;
  unknown)
    echo "ERROR: UNKNOWN: fido-authenticator-config has not been validated for CanoKey firmware ${CANOKEY_FIRMWARE_VERSION_NORMALIZED}" >&2
    exit 1
    ;;
esac
