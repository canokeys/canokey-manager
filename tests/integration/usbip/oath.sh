#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib.sh"

OATH_SECRET="JBSWY3DPEHPK3PXP"
OATH_PASSWORD="usbip-oath-password"
OATH_NEW_PASSWORD="usbip-oath-password-2"

oath_status="$(firmware_feature_status oath-modern-commands)"
legacy_oath=false
case "$oath_status" in
  supported) ;;
  unsupported)
    legacy_status="$(firmware_feature_status oath-legacy-commands)"
    case "$legacy_status" in
      supported) legacy_oath=true ;;
      unsupported)
        echo "ERROR: no supported OATH command dialect for CanoKey firmware ${CANOKEY_FIRMWARE_VERSION_NORMALIZED}" >&2
        exit 1
        ;;
      unknown)
        echo "ERROR: UNKNOWN: oath-legacy-commands has not been validated for CanoKey firmware ${CANOKEY_FIRMWARE_VERSION_NORMALIZED}" >&2
        exit 1
        ;;
    esac
    ;;
  unknown)
    echo "ERROR: UNKNOWN: oath-modern-commands has not been validated for CanoKey firmware ${CANOKEY_FIRMWARE_VERSION_NORMALIZED}" >&2
    exit 1
    ;;
esac

section "ckman oath reset"
"${CKMAN[@]}" oath reset --admin-pin 123456 --force

section "ckman oath info"
"${CKMAN[@]}" oath info

section "ckman oath access forget"
"${CKMAN[@]}" oath access forget

section "ckman oath accounts add"
"${CKMAN[@]}" oath accounts add \
  --force \
  --issuer ckman \
  --algorithm SHA256 \
  "usbip-totp" "$OATH_SECRET"

section "ckman oath accounts list"
oath_accounts="$("${CKMAN[@]}" oath accounts list --oath-type --period)"
printf '%s\n' "$oath_accounts"
grep -Fq "ckman:usbip-totp, TOTP, 30" <<<"$oath_accounts"

section "ckman oath accounts code"
oath_code="$("${CKMAN[@]}" oath accounts code --single "ckman:usbip-totp")"
printf '%s\n' "$oath_code"
[[ "$oath_code" =~ ^[0-9]{6}$ ]]

section "ckman oath accounts rename"
primary_account="ckman:usbip-totp"
if [[ "$legacy_oath" == "true" ]]; then
  unsupported_feature \
    "ckman oath accounts rename" \
    "Firmware 1.3 does not implement credential rename."
else
  "${CKMAN[@]}" oath accounts rename \
    --force \
    "$primary_account" "ckman:usbip-renamed"
  primary_account="ckman:usbip-renamed"
fi

section "ckman oath accounts uri"
"${CKMAN[@]}" oath accounts uri \
  --force \
  "otpauth://totp/ckman:usbip-uri?secret=${OATH_SECRET}&issuer=ckman&digits=8"

section "Create OATH PSKC import fixture"
uv run python - "$CANOKEY_USBIP_WORK_DIR/oath-import.pskc" <<'PY'
import sys

from pskc import PSKC

pskc = PSKC()
pskc.add_key(
    secret=b"12345678901234567890",
    algorithm="urn:ietf:params:xml:ns:keyprov:pskc:totp",
    id="usbip-pskc",
    key_userid="CN=usbip-pskc",
    friendly_name="ckman:usbip-pskc",
    issuer="ckman",
    response_length="6",
    response_encoding="DECIMAL",
    algorithm_suite="SHA1",
    time_interval="30",
)
with open(sys.argv[1], "wb") as pskc_file:
    pskc.write(pskc_file)
PY

section "ckman oath accounts import"
"${CKMAN[@]}" oath accounts import \
  --force \
  "$CANOKEY_USBIP_WORK_DIR/oath-import.pskc"

section "ckman oath accounts add HOTP"
"${CKMAN[@]}" oath accounts add \
  --force \
  --oath-type HOTP \
  --digits 8 \
  --counter 4 \
  "usbip-hotp" "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
hotp_code="$("${CKMAN[@]}" oath accounts code --single "usbip-hotp")"
printf '%s\n' "$hotp_code"
[[ "$hotp_code" =~ ^[0-9]{8}$ ]]

section "ckman oath accounts add generated secret"
capture_without_secrets \
  "Generated credential secret" \
  "${CKMAN[@]}" oath accounts add \
  --force \
  --generate \
  "usbip-generated"
echo "Generated OATH account added without exposing its secret."

if [[ "$legacy_oath" == "true" ]]; then
  section "ckman oath access password protection"
  unsupported_feature \
    "ckman oath access password protection" \
    "Firmware 1.3 does not implement SET_CODE or VALIDATE."
else
  section "ckman oath access change"
  "${CKMAN[@]}" oath access change \
    --new-password "$OATH_PASSWORD"

  section "ckman oath access remember"
  "${CKMAN[@]}" oath access remember \
    --password "$OATH_PASSWORD"
  remembered_accounts="$("${CKMAN[@]}" oath accounts list)"
  grep -Fq "usbip-generated" <<<"$remembered_accounts"
  [[ "$(jq 'length' "$XDG_DATA_HOME/ykman/oath_keys.json")" -eq 1 ]]

  section "ckman oath access forget remembered password"
  "${CKMAN[@]}" oath access forget
  [[ "$(jq 'length' "$XDG_DATA_HOME/ykman/oath_keys.json")" -eq 0 ]]
  password_accounts="$("${CKMAN[@]}" oath accounts list --password "$OATH_PASSWORD")"
  grep -Fq "usbip-generated" <<<"$password_accounts"

  section "ckman oath access change and remember"
  "${CKMAN[@]}" oath access change \
    --password "$OATH_PASSWORD" \
    --new-password "$OATH_NEW_PASSWORD" \
    --remember
  remembered_accounts="$("${CKMAN[@]}" oath accounts list)"
  grep -Fq "usbip-generated" <<<"$remembered_accounts"

  section "ckman oath access clear password"
  "${CKMAN[@]}" oath access change \
    --password "$OATH_NEW_PASSWORD" \
    --clear
fi

section "ckman oath accounts delete"
for account in \
  "$primary_account" \
  "ckman:usbip-uri" \
  "ckman:usbip-pskc" \
  "usbip-hotp" \
  "usbip-generated"; do
  "${CKMAN[@]}" oath accounts delete --force "$account"
done

oath_accounts="$("${CKMAN[@]}" oath accounts list)"
if [[ -n "$oath_accounts" ]]; then
  echo "ERROR: OATH accounts remain after lifecycle cleanup" >&2
  printf '%s\n' "$oath_accounts" >&2
  exit 1
fi

section "ckman oath info after lifecycle"
"${CKMAN[@]}" oath info
