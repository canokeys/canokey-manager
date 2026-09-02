#!/usr/bin/env bash
set -euo pipefail

: "${CANOKEY_USBIP:?This test must run under canokey-usbip}"
: "${CANOKEY_PCSC_READER:?canokey-usbip did not expose a PC/SC reader}"

CKMAN=(uv run ckman --reader "$CANOKEY_PCSC_READER")
PIV_PIN="123456"
PIV_MANAGEMENT_KEY="010203040506070801020304050607080102030405060708"
OATH_ACCOUNT="ckman-usbip"
OATH_SECRET="JBSWY3DPEHPK3PXP"

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

echo "=== ckman info ==="
"${CKMAN[@]}" info

echo "=== ckman piv info ==="
"${CKMAN[@]}" piv info

echo "=== ckman oath info ==="
"${CKMAN[@]}" oath info

echo "=== ckman openpgp info ==="
"${CKMAN[@]}" openpgp info

echo "=== ckman piv reset ==="
"${CKMAN[@]}" piv reset --force

echo "=== ckman piv P-256 key generation ==="
"${CKMAN[@]}" piv keys generate \
  --algorithm ECCP256 \
  --management-key "$PIV_MANAGEMENT_KEY" \
  9a "$work_dir/piv-public.pem"

echo "=== ckman piv self-signed certificate generation ==="
"${CKMAN[@]}" piv certificates generate \
  --management-key "$PIV_MANAGEMENT_KEY" \
  --pin "$PIV_PIN" \
  --subject "CN=ckman USB-IP integration" \
  9a "$work_dir/piv-public.pem"

echo "=== ckman piv certificate export ==="
"${CKMAN[@]}" piv certificates export 9a "$work_dir/piv-certificate.pem"
openssl x509 \
  -in "$work_dir/piv-certificate.pem" \
  -pubkey -noout >"$work_dir/piv-certificate-public.pem"
cmp "$work_dir/piv-public.pem" "$work_dir/piv-certificate-public.pem"
openssl verify \
  -CAfile "$work_dir/piv-certificate.pem" \
  "$work_dir/piv-certificate.pem"

echo "=== ckman piv info after provisioning ==="
"${CKMAN[@]}" piv info

echo "=== ckman oath reset ==="
"${CKMAN[@]}" oath reset --force

echo "=== ckman oath account add ==="
"${CKMAN[@]}" oath accounts add \
  --force \
  "$OATH_ACCOUNT" "$OATH_SECRET"

echo "=== ckman oath account list ==="
oath_accounts="$("${CKMAN[@]}" oath accounts list)"
printf '%s\n' "$oath_accounts"
grep -Fxq "$OATH_ACCOUNT" <<<"$oath_accounts"

echo "=== ckman oath account calculate ==="
oath_code="$("${CKMAN[@]}" oath accounts code --single "$OATH_ACCOUNT")"
printf '%s\n' "$oath_code"
[[ "$oath_code" =~ ^[0-9]{6}$ ]]

echo "=== ckman oath account delete ==="
"${CKMAN[@]}" oath accounts delete --force "$OATH_ACCOUNT"
oath_accounts="$("${CKMAN[@]}" oath accounts list)"
if grep -Fq "$OATH_ACCOUNT" <<<"$oath_accounts"; then
  echo "ERROR: OATH account still exists after deletion" >&2
  exit 1
fi
