#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib.sh"
: "${CANOKEY_DEVICE_RESTART:?canokey-usbip did not expose its restart helper}"

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

# Restart in the background and issue reset as soon as PC/SC exposes the card.
# Waiting for the harness's complete readiness check can consume the reset window.
section "ckman fido reset"
restart_stdout="$CANOKEY_USBIP_WORK_DIR/fido-restart.stdout"
restart_stderr="$CANOKEY_USBIP_WORK_DIR/fido-restart.stderr"
reset_stdout="$CANOKEY_USBIP_WORK_DIR/fido-reset.stdout"
reset_stderr="$CANOKEY_USBIP_WORK_DIR/fido-reset.stderr"
"$CANOKEY_DEVICE_RESTART" >"$restart_stdout" 2>"$restart_stderr" &
restart_pid=$!

reset_complete=false
while kill -0 "$restart_pid" 2>/dev/null; do
  if "${CKMAN[@]}" fido reset --force >"$reset_stdout" 2>"$reset_stderr"; then
    reset_complete=true
    break
  fi
  sleep 0.2
done

if ! wait "$restart_pid"; then
  cat "$restart_stdout"
  cat "$restart_stderr" >&2
  exit 1
fi
if [[ "$reset_complete" != true ]] && \
  "${CKMAN[@]}" fido reset --force >"$reset_stdout" 2>"$reset_stderr"; then
  reset_complete=true
fi
if [[ "$reset_complete" != true ]]; then
  cat "$reset_stdout"
  cat "$reset_stderr" >&2
  exit 1
fi
grep -Fq "FIDO application data reset." "$reset_stdout"

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
