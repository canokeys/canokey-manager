#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib.sh"

PIV_DEFAULT_PIN="123456"
PIV_DEFAULT_PUK="12345678"
PIV_DEFAULT_MANAGEMENT_KEY="010203040506070801020304050607080102030405060708"
PIV_PIN="654321"
PIV_RECOVERY_PIN="112233"
PIV_PUK="87654321"
PIV_MANAGEMENT_KEY="111111111111111122222222222222223333333333333333"

section "ckman piv reset"
capture_without_secrets \
  "Reset complete." \
  "${CKMAN[@]}" piv reset --force
echo "PIV reset complete."

section "ckman piv access set-retries"
run_versioned_feature \
  "ckman piv access set-retries" \
  "piv-set-retries" \
  "${CKMAN[@]}" piv access set-retries \
  --management-key "$PIV_DEFAULT_MANAGEMENT_KEY" \
  --pin "$PIV_DEFAULT_PIN" \
  --force \
  3 3

section "ckman piv access change-pin"
"${CKMAN[@]}" piv access change-pin \
  --pin "$PIV_DEFAULT_PIN" \
  --new-pin "$PIV_PIN"

section "ckman piv access change-puk"
"${CKMAN[@]}" piv access change-puk \
  --puk "$PIV_DEFAULT_PUK" \
  --new-puk "$PIV_PUK"

section "ckman piv access change-management-key"
"${CKMAN[@]}" piv access change-management-key \
  --management-key "$PIV_DEFAULT_MANAGEMENT_KEY" \
  --new-management-key "$PIV_MANAGEMENT_KEY" \
  --force

section "ckman piv access unblock-pin"
for attempt in 1 2 3; do
  expect_failure \
    "Incorrect PIV PIN attempt $attempt" \
    "${CKMAN[@]}" piv access change-pin \
    --pin "000000" \
    --new-pin "$PIV_DEFAULT_PIN"
done
"${CKMAN[@]}" piv access unblock-pin \
  --puk "$PIV_PUK" \
  --new-pin "$PIV_RECOVERY_PIN"

section "Generate PIV test keys"
openssl genpkey \
  -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-256 \
  -out "$CANOKEY_USBIP_WORK_DIR/piv-import-private.pem" \
  2>/dev/null
openssl pkey \
  -in "$CANOKEY_USBIP_WORK_DIR/piv-import-private.pem" \
  -pubout \
  -out "$CANOKEY_USBIP_WORK_DIR/piv-import-public.pem" \
  2>/dev/null
openssl req \
  -new \
  -x509 \
  -key "$CANOKEY_USBIP_WORK_DIR/piv-import-private.pem" \
  -subj "/CN=ckman USB-IP imported PIV key" \
  -days 1 \
  -out "$CANOKEY_USBIP_WORK_DIR/piv-import-certificate.pem" \
  2>/dev/null
openssl genpkey \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:3072 \
  -out "$CANOKEY_USBIP_WORK_DIR/piv-rsa3072-private.pem" \
  2>/dev/null
openssl genpkey \
  -algorithm X25519 \
  -out "$CANOKEY_USBIP_WORK_DIR/piv-x25519-private.pem" \
  2>/dev/null

section "ckman piv keys generate"
"${CKMAN[@]}" piv keys generate \
  --algorithm ECCP256 \
  --management-key "$PIV_MANAGEMENT_KEY" \
  9a "$CANOKEY_USBIP_WORK_DIR/piv-generated-public.pem"

section "ckman piv keys info"
run_versioned_feature \
  "ckman piv keys info" \
  "piv-metadata" \
  "${CKMAN[@]}" piv keys info 9a

section "ckman piv keys export"
run_versioned_feature \
  "ckman piv keys export" \
  "piv-metadata" \
  "${CKMAN[@]}" piv keys export \
    --verify \
    --pin "$PIV_RECOVERY_PIN" \
    9a "$CANOKEY_USBIP_WORK_DIR/piv-exported-public.pem"
if [[ "$FEATURE_AVAILABLE" == true ]]; then
  cmp \
    "$CANOKEY_USBIP_WORK_DIR/piv-generated-public.pem" \
    "$CANOKEY_USBIP_WORK_DIR/piv-exported-public.pem"
fi

section "Probe PIV attestation provisioning"
probe_provisioning_state \
  "PIV attestation certificate" \
  "Error: No certificate found" \
  "${CKMAN[@]}" piv certificates export \
  f9 "$CANOKEY_USBIP_WORK_DIR/piv-attestation-root.pem"
if [[ "$FEATURE_AVAILABLE" == true ]]; then
  openssl x509 \
    -in "$CANOKEY_USBIP_WORK_DIR/piv-attestation-root.pem" \
    -noout \
    -subject

  section "ckman piv keys attest"
  "${CKMAN[@]}" piv keys attest \
    9a "$CANOKEY_USBIP_WORK_DIR/piv-attestation.pem"
  openssl x509 \
    -in "$CANOKEY_USBIP_WORK_DIR/piv-attestation.pem" \
    -noout \
    -subject
else
  unsupported_feature \
    "ckman piv keys attest" \
    "The PIV attestation certificate is absent."
fi

section "ckman piv certificates generate"
"${CKMAN[@]}" piv certificates generate \
  --management-key "$PIV_MANAGEMENT_KEY" \
  --pin "$PIV_RECOVERY_PIN" \
  --subject "CN=ckman USB-IP generated PIV key" \
  9a "$CANOKEY_USBIP_WORK_DIR/piv-generated-public.pem"

section "ckman piv certificates export"
"${CKMAN[@]}" piv certificates export \
  9a "$CANOKEY_USBIP_WORK_DIR/piv-generated-certificate.pem"
openssl verify \
  -CAfile "$CANOKEY_USBIP_WORK_DIR/piv-generated-certificate.pem" \
  "$CANOKEY_USBIP_WORK_DIR/piv-generated-certificate.pem"

section "ckman piv certificates request"
"${CKMAN[@]}" piv certificates request \
  --pin "$PIV_RECOVERY_PIN" \
  --subject "CN=ckman USB-IP PIV request" \
  9a \
  "$CANOKEY_USBIP_WORK_DIR/piv-generated-public.pem" \
  "$CANOKEY_USBIP_WORK_DIR/piv-request.pem"
openssl req \
  -in "$CANOKEY_USBIP_WORK_DIR/piv-request.pem" \
  -verify \
  -noout

section "ckman piv certificates delete"
"${CKMAN[@]}" piv certificates delete \
  --management-key "$PIV_MANAGEMENT_KEY" \
  9a

section "ckman piv certificates import"
"${CKMAN[@]}" piv certificates import \
  --management-key "$PIV_MANAGEMENT_KEY" \
  --pin "$PIV_RECOVERY_PIN" \
  --verify \
  9a "$CANOKEY_USBIP_WORK_DIR/piv-generated-certificate.pem"
"${CKMAN[@]}" piv certificates export \
  9a "$CANOKEY_USBIP_WORK_DIR/piv-reimported-certificate.pem"
openssl x509 \
  -in "$CANOKEY_USBIP_WORK_DIR/piv-generated-certificate.pem" \
  -outform DER \
  -out "$CANOKEY_USBIP_WORK_DIR/piv-generated-certificate.der"
openssl x509 \
  -in "$CANOKEY_USBIP_WORK_DIR/piv-reimported-certificate.pem" \
  -outform DER \
  -out "$CANOKEY_USBIP_WORK_DIR/piv-reimported-certificate.der"
cmp \
  "$CANOKEY_USBIP_WORK_DIR/piv-generated-certificate.der" \
  "$CANOKEY_USBIP_WORK_DIR/piv-reimported-certificate.der"

section "ckman piv keys import"
policy_status="$(firmware_feature_status "piv-generate-policies")"
if [[ "$policy_status" == supported ]]; then
  "${CKMAN[@]}" piv keys import \
    --management-key "$PIV_MANAGEMENT_KEY" \
    --pin-policy always \
    9c "$CANOKEY_USBIP_WORK_DIR/piv-import-private.pem"
elif [[ "$policy_status" == unsupported ]]; then
  unsupported_feature \
    "PIV key import PIN policy" \
    "The firmware feature matrix marks piv-generate-policies as unavailable."
  "${CKMAN[@]}" piv keys import \
    --management-key "$PIV_MANAGEMENT_KEY" \
    9c "$CANOKEY_USBIP_WORK_DIR/piv-import-private.pem"
else
  echo "ERROR: UNKNOWN: piv-generate-policies has not been validated for CanoKey firmware ${CANOKEY_FIRMWARE_VERSION_NORMALIZED}" >&2
  exit 1
fi
run_versioned_feature \
  "ckman piv keys info for imported key" \
  "piv-metadata" \
  "${CKMAN[@]}" piv keys info 9c
run_versioned_feature \
  "ckman piv keys export for imported key" \
  "piv-metadata" \
  "${CKMAN[@]}" piv keys export \
    --verify \
    --pin "$PIV_RECOVERY_PIN" \
    9c "$CANOKEY_USBIP_WORK_DIR/piv-import-exported-public.pem"
if [[ "$FEATURE_AVAILABLE" == true ]]; then
  cmp \
    "$CANOKEY_USBIP_WORK_DIR/piv-import-public.pem" \
    "$CANOKEY_USBIP_WORK_DIR/piv-import-exported-public.pem"
fi

section "ckman piv certificates import for imported key"
"${CKMAN[@]}" piv certificates import \
  --management-key "$PIV_MANAGEMENT_KEY" \
  --pin "$PIV_RECOVERY_PIN" \
  --verify \
  9c "$CANOKEY_USBIP_WORK_DIR/piv-import-certificate.pem"
"${CKMAN[@]}" piv certificates export \
  9c "$CANOKEY_USBIP_WORK_DIR/piv-import-exported-certificate.pem"

section "ckman piv keys move"
run_versioned_feature \
  "ckman piv keys move" \
  "piv-move-key" \
  "${CKMAN[@]}" piv keys move \
  --management-key "$PIV_MANAGEMENT_KEY" \
  9c 9d
if [[ "$FEATURE_AVAILABLE" == true ]]; then
  "${CKMAN[@]}" piv keys info 9d
  expect_failure \
    "Reading the emptied PIV source slot" \
    "${CKMAN[@]}" piv keys info 9c
  "${CKMAN[@]}" piv keys move \
    --management-key "$PIV_MANAGEMENT_KEY" \
    9d 9c
fi

section "ckman piv retired key slots"
run_versioned_feature \
  "PIV retired key slots" \
  "piv-retired-slots" \
  "${CKMAN[@]}" piv keys generate \
  --algorithm ECCP256 \
  --management-key "$PIV_MANAGEMENT_KEY" \
  82 "$CANOKEY_USBIP_WORK_DIR/piv-retired-public.pem"
if [[ "$FEATURE_AVAILABLE" == true ]]; then
  "${CKMAN[@]}" piv keys delete \
    --management-key "$PIV_MANAGEMENT_KEY" \
    82
fi

section "ckman piv extended algorithm CLI paths"
run_versioned_feature \
  "PIV standard extended algorithm IDs" \
  "piv-standard-algorithm-ids" \
  "${CKMAN[@]}" piv keys import \
  --management-key "$PIV_MANAGEMENT_KEY" \
  83 "$CANOKEY_USBIP_WORK_DIR/piv-rsa3072-private.pem"
if [[ "$FEATURE_AVAILABLE" == true ]]; then
  "${CKMAN[@]}" piv keys info 83
  "${CKMAN[@]}" piv keys delete \
    --management-key "$PIV_MANAGEMENT_KEY" \
    83
fi

run_versioned_feature \
  "PIV Ed25519 and X25519 CLI paths" \
  "piv-ed25519-x25519-fixes" \
  "${CKMAN[@]}" piv keys generate \
  --algorithm ED25519 \
  --management-key "$PIV_MANAGEMENT_KEY" \
  84 "$CANOKEY_USBIP_WORK_DIR/piv-ed25519-public.pem"
if [[ "$FEATURE_AVAILABLE" == true ]]; then
  "${CKMAN[@]}" piv keys import \
    --management-key "$PIV_MANAGEMENT_KEY" \
    85 "$CANOKEY_USBIP_WORK_DIR/piv-x25519-private.pem"
  "${CKMAN[@]}" piv keys info 84
  "${CKMAN[@]}" piv keys info 85
  "${CKMAN[@]}" piv keys delete \
    --management-key "$PIV_MANAGEMENT_KEY" \
    84
  "${CKMAN[@]}" piv keys delete \
    --management-key "$PIV_MANAGEMENT_KEY" \
    85
fi

section "ckman piv objects generate"
"${CKMAN[@]}" piv objects generate \
  --management-key "$PIV_MANAGEMENT_KEY" \
  chuid
"${CKMAN[@]}" piv objects generate \
  --management-key "$PIV_MANAGEMENT_KEY" \
  ccc

section "ckman piv objects export"
"${CKMAN[@]}" piv objects export \
  chuid "$CANOKEY_USBIP_WORK_DIR/piv-chuid.bin"
"${CKMAN[@]}" piv objects export \
  ccc "$CANOKEY_USBIP_WORK_DIR/piv-ccc.bin"
test -s "$CANOKEY_USBIP_WORK_DIR/piv-chuid.bin"
test -s "$CANOKEY_USBIP_WORK_DIR/piv-ccc.bin"

section "ckman piv objects import"
"${CKMAN[@]}" piv objects import \
  --management-key "$PIV_MANAGEMENT_KEY" \
  chuid "$CANOKEY_USBIP_WORK_DIR/piv-chuid.bin"
"${CKMAN[@]}" piv objects export \
  chuid "$CANOKEY_USBIP_WORK_DIR/piv-chuid-roundtrip.bin"
cmp \
  "$CANOKEY_USBIP_WORK_DIR/piv-chuid.bin" \
  "$CANOKEY_USBIP_WORK_DIR/piv-chuid-roundtrip.bin"

section "ckman piv PIN-protected objects"
protected_object_status="$(firmware_feature_status piv-protected-objects)"
case "$protected_object_status" in
  supported)
    printf 'ckman USB/IP protected PIV object\n' \
      >"$CANOKEY_USBIP_WORK_DIR/piv-printed.bin"
    "${CKMAN[@]}" piv objects import \
      --management-key "$PIV_MANAGEMENT_KEY" \
      printed "$CANOKEY_USBIP_WORK_DIR/piv-printed.bin"
    "${CKMAN[@]}" piv objects export \
      --pin "$PIV_RECOVERY_PIN" \
      printed "$CANOKEY_USBIP_WORK_DIR/piv-printed-roundtrip.bin"
    cmp \
      "$CANOKEY_USBIP_WORK_DIR/piv-printed.bin" \
      "$CANOKEY_USBIP_WORK_DIR/piv-printed-roundtrip.bin"
    ;;
  unsupported)
    unsupported_feature \
      "PIV PIN-protected data objects" \
      "The Printed Information object is unavailable."
    ;;
  unknown)
    echo "ERROR: UNKNOWN: piv-protected-objects has not been validated for CanoKey firmware ${CANOKEY_FIRMWARE_VERSION_NORMALIZED}" >&2
    exit 1
    ;;
esac

section "ckman piv certificates delete imported certificate"
"${CKMAN[@]}" piv certificates delete \
  --management-key "$PIV_MANAGEMENT_KEY" \
  9c

section "ckman piv keys delete"
"${CKMAN[@]}" piv keys delete \
  --management-key "$PIV_MANAGEMENT_KEY" \
  9c
"${CKMAN[@]}" piv keys delete \
  --management-key "$PIV_MANAGEMENT_KEY" \
  9a

section "ckman piv info after lifecycle"
"${CKMAN[@]}" piv info
