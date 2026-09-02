#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib.sh"

OPENPGP_DEFAULT_PIN="123456"
OPENPGP_DEFAULT_ADMIN_PIN="12345678"
OPENPGP_PIN="654321"
OPENPGP_RECOVERY_PIN="112233"
OPENPGP_RESET_CODE="87654321"
OPENPGP_ADMIN_PIN="87654321"

section "ckman openpgp reset"
capture_without_secrets \
  "Reset complete." \
  "${CKMAN[@]}" openpgp reset --force
echo "OpenPGP reset complete."

section "ckman openpgp info"
"${CKMAN[@]}" openpgp info

section "ckman openpgp access set-retries"
unsupported_feature \
  "ckman openpgp access set-retries" \
  "CanoKey does not implement OpenPGP SET PIN RETRIES."

section "ckman openpgp access change-pin"
"${CKMAN[@]}" openpgp access change-pin \
  --pin "$OPENPGP_DEFAULT_PIN" \
  --new-pin "$OPENPGP_PIN"

section "ckman openpgp access change-reset-code"
"${CKMAN[@]}" openpgp access change-reset-code \
  --admin-pin "$OPENPGP_DEFAULT_ADMIN_PIN" \
  --reset-code "$OPENPGP_RESET_CODE"

section "ckman openpgp access unblock-pin"
"${CKMAN[@]}" openpgp access unblock-pin \
  --reset-code "$OPENPGP_RESET_CODE" \
  --new-pin "$OPENPGP_RECOVERY_PIN"

section "ckman openpgp access change-admin-pin"
"${CKMAN[@]}" openpgp access change-admin-pin \
  --admin-pin "$OPENPGP_DEFAULT_ADMIN_PIN" \
  --new-admin-pin "$OPENPGP_ADMIN_PIN"

section "ckman openpgp access set-signature-policy"
"${CKMAN[@]}" openpgp access set-signature-policy \
  once \
  --admin-pin "$OPENPGP_ADMIN_PIN"
openpgp_info="$("${CKMAN[@]}" openpgp info)"
grep -Fq "Require PIN for signature:  Once" <<<"$openpgp_info"

section "Generate OpenPGP attestation fixtures"
openssl genpkey \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:2048 \
  -out "$CANOKEY_USBIP_WORK_DIR/openpgp-attestation-private.pem" \
  2>/dev/null
openssl req \
  -new \
  -x509 \
  -key "$CANOKEY_USBIP_WORK_DIR/openpgp-attestation-private.pem" \
  -subj "/CN=ckman USB-IP OpenPGP attestation" \
  -days 1 \
  -out "$CANOKEY_USBIP_WORK_DIR/openpgp-attestation-certificate.pem" \
  2>/dev/null

section "ckman openpgp keys import"
probe_feature \
  "OpenPGP attestation key import" \
  "failed to import attestation key" \
  "${CKMAN[@]}" openpgp keys import \
  --admin-pin "$OPENPGP_ADMIN_PIN" \
  att "$CANOKEY_USBIP_WORK_DIR/openpgp-attestation-private.pem"

if [[ "$FEATURE_AVAILABLE" == true ]]; then
  section "ckman openpgp keys info"
  "${CKMAN[@]}" openpgp keys info att

  section "ckman openpgp keys set-touch"
  probe_feature \
    "OpenPGP attestation touch policy" \
    "touch policy not allowed|failed to set touch policy" \
    "${CKMAN[@]}" openpgp keys set-touch \
    --admin-pin "$OPENPGP_ADMIN_PIN" \
    --force \
    att off

fi

section "ckman openpgp certificates import"
probe_feature \
  "OpenPGP attestation certificate storage" \
  "failed to import certificate" \
  "${CKMAN[@]}" openpgp certificates import \
  --admin-pin "$OPENPGP_ADMIN_PIN" \
  att "$CANOKEY_USBIP_WORK_DIR/openpgp-attestation-certificate.pem"

if [[ "$FEATURE_AVAILABLE" == true ]]; then
  section "ckman openpgp certificates export"
  "${CKMAN[@]}" openpgp certificates export \
    att "$CANOKEY_USBIP_WORK_DIR/openpgp-exported-certificate.pem"
  openssl x509 \
    -in "$CANOKEY_USBIP_WORK_DIR/openpgp-attestation-certificate.pem" \
    -outform DER \
    -out "$CANOKEY_USBIP_WORK_DIR/openpgp-attestation-certificate.der"
  openssl x509 \
    -in "$CANOKEY_USBIP_WORK_DIR/openpgp-exported-certificate.pem" \
    -outform DER \
    -out "$CANOKEY_USBIP_WORK_DIR/openpgp-exported-certificate.der"
  cmp \
    "$CANOKEY_USBIP_WORK_DIR/openpgp-attestation-certificate.der" \
    "$CANOKEY_USBIP_WORK_DIR/openpgp-exported-certificate.der"

  section "ckman openpgp certificates delete"
  "${CKMAN[@]}" openpgp certificates delete \
    --admin-pin "$OPENPGP_ADMIN_PIN" \
    att
fi

section "Probe OpenPGP signing key"
probe_feature \
  "OpenPGP signing key" \
  "no key stored in slot sig" \
  "${CKMAN[@]}" openpgp keys info sig
if [[ "$FEATURE_AVAILABLE" == true ]]; then
  section "ckman openpgp keys attest"
  "${CKMAN[@]}" openpgp keys attest \
    --pin "$OPENPGP_RECOVERY_PIN" \
    sig "$CANOKEY_USBIP_WORK_DIR/openpgp-signing-attestation.pem"
else
  unsupported_feature \
    "ckman openpgp keys attest" \
    "No signing key is provisioned by this firmware."
fi

section "ckman openpgp reset after lifecycle"
capture_without_secrets \
  "Reset complete." \
  "${CKMAN[@]}" openpgp reset --force
echo "OpenPGP lifecycle cleanup complete."
