#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib.sh"

OATH_SECRET="JBSWY3DPEHPK3PXP"
OATH_PASSWORD="usbip-oath-password"
OATH_NEW_PASSWORD="usbip-oath-password-2"

if [[ "$(firmware_feature_status oath-modern-commands)" == "unsupported" ]]; then
  section "ckman oath command lifecycle"
  unsupported_feature \
    "the modern ckman OATH command lifecycle" \
    "Firmware before 1.5.2 uses the legacy CanoKey OATH instruction set."
  exit 0
fi

section "ckman oath reset"
"${CKMAN[@]}" oath reset --force

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
"${CKMAN[@]}" oath accounts rename \
  --force \
  "ckman:usbip-totp" "ckman:usbip-renamed"

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

section "ckman oath access change"
"${CKMAN[@]}" oath access change \
  --new-password "$OATH_PASSWORD"

section "ckman oath access remember"
"${CKMAN[@]}" oath access remember \
  --password "$OATH_PASSWORD"
remembered_accounts="$("${CKMAN[@]}" oath accounts list)"
grep -Fq "usbip-generated" <<<"$remembered_accounts"

section "ckman oath access forget remembered password"
"${CKMAN[@]}" oath access forget
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

section "ckman oath accounts delete"
for account in \
  "ckman:usbip-renamed" \
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
