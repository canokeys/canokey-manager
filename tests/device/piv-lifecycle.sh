#!/usr/bin/env bash
# PIV lifecycle: reset, credentials, key generation/import, certificates.
# DESTRUCTIVE: writes and resets the device. Requires CKMAN_DESTRUCTIVE=1 and
# a usbip test key.
set -euo pipefail

: "${CKMAN_DESTRUCTIVE:?PIV lifecycle writes to the device; set CKMAN_DESTRUCTIVE=1}"

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

PIV_DEFAULT_PIN="123456"
PIV_DEFAULT_PUK="12345678"
PIV_DEFAULT_MANAGEMENT_KEY="010203040506070801020304050607080102030405060708"
PIV_PIN="654321"
PIV_PUK="87654321"
PIV_MANAGEMENT_KEY="111111111111111122222222222222223333333333333333"

section "ckman piv reset"
capture_without_secrets \
  "Reset complete." \
  "${CKMAN[@]}" piv reset --force --admin-pin "123456"

section "ckman piv access change-pin / change-puk"
"${CKMAN[@]}" piv access change-pin --pin "$PIV_DEFAULT_PIN" --new-pin "$PIV_PIN"
"${CKMAN[@]}" piv access change-puk --puk "$PIV_DEFAULT_PUK" --new-puk "$PIV_PUK"

section "ckman piv access change-management-key"
"${CKMAN[@]}" piv access change-management-key \
  --management-key "$PIV_DEFAULT_MANAGEMENT_KEY" \
  --new-management-key "$PIV_MANAGEMENT_KEY" \
  --force

section "ckman piv access unblock-pin"
for attempt in 1 2 3; do
  expect_failure \
    "Incorrect PIV PIN attempt $attempt" \
    "${CKMAN[@]}" piv access change-pin --pin "000000" --new-pin "$PIV_DEFAULT_PIN"
done
"${CKMAN[@]}" piv access unblock-pin --puk "$PIV_PUK" --new-pin "$PIV_DEFAULT_PIN"

section "Generate PIV test keys (host-side)"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out "$CANOKEY_USBIP_WORK_DIR/piv-import-private.pem" 2>/dev/null
openssl pkey -in "$CANOKEY_USBIP_WORK_DIR/piv-import-private.pem" -pubout \
  -out "$CANOKEY_USBIP_WORK_DIR/piv-import-public.pem" 2>/dev/null
openssl req -new -x509 -key "$CANOKEY_USBIP_WORK_DIR/piv-import-private.pem" \
  -subj "/CN=ckman usbip imported PIV key" -days 1 \
  -out "$CANOKEY_USBIP_WORK_DIR/piv-import-certificate.pem" 2>/dev/null

section "ckman piv keys generate"
"${CKMAN[@]}" piv keys generate \
  --algorithm ecc-p256 \
  --management-key "$PIV_MANAGEMENT_KEY" \
  9a "$CANOKEY_USBIP_WORK_DIR/piv-generated-public.pem"
grep -Fq "BEGIN PUBLIC KEY" "$CANOKEY_USBIP_WORK_DIR/piv-generated-public.pem"

section "ckman piv keys info"
run_versioned_feature \
  "ckman piv keys info" \
  "piv-metadata" \
  "${CKMAN[@]}" piv keys info 9a

section "ckman piv certificates generate + export"
"${CKMAN[@]}" piv certificates generate 9a \
  --management-key "$PIV_MANAGEMENT_KEY" \
  --pin "$PIV_DEFAULT_PIN" \
  --subject "CN=ckman usbip generated" --valid-days 1
"${CKMAN[@]}" piv certificates export 9a "$CANOKEY_USBIP_WORK_DIR/piv-generated-cert.pem"
openssl x509 -in "$CANOKEY_USBIP_WORK_DIR/piv-generated-cert.pem" -noout -text >/dev/null

section "ckman piv keys import + certificates import"
"${CKMAN[@]}" piv keys import 9c \
  --management-key "$PIV_MANAGEMENT_KEY" \
  "$CANOKEY_USBIP_WORK_DIR/piv-import-private.pem"
"${CKMAN[@]}" piv certificates import 9c \
  --management-key "$PIV_MANAGEMENT_KEY" \
  "$CANOKEY_USBIP_WORK_DIR/piv-import-certificate.pem"

section "ckman piv objects export/import round trip"
echo -n "ckman-object-test" > "$CANOKEY_USBIP_WORK_DIR/object.bin"
"${CKMAN[@]}" piv objects import 5fc10a "$CANOKEY_USBIP_WORK_DIR/object.bin" \
  --management-key "$PIV_MANAGEMENT_KEY"
"${CKMAN[@]}" piv objects export 5fc10a "$CANOKEY_USBIP_WORK_DIR/object-out.bin"
cmp "$CANOKEY_USBIP_WORK_DIR/object.bin" "$CANOKEY_USBIP_WORK_DIR/object-out.bin"

section "ckman piv sign"
echo -n "ckman-sign-test" > "$CANOKEY_USBIP_WORK_DIR/sign-message.bin"
"${CKMAN[@]}" piv sign 9a \
  "$CANOKEY_USBIP_WORK_DIR/sign-message.bin" \
  "$CANOKEY_USBIP_WORK_DIR/sign-signature.bin" \
  --pin "$PIV_DEFAULT_PIN"
openssl dgst -sha256 \
  -verify "$CANOKEY_USBIP_WORK_DIR/piv-generated-public.pem" \
  -signature "$CANOKEY_USBIP_WORK_DIR/sign-signature.bin" \
  "$CANOKEY_USBIP_WORK_DIR/sign-message.bin"

section "ckman piv keys generate-batch"
"${CKMAN[@]}" piv keys generate-batch \
  --slots 9d,9e \
  --algorithm ecc-p256 \
  --output-dir "$CANOKEY_USBIP_WORK_DIR" \
  --management-key "$PIV_MANAGEMENT_KEY"
openssl pkey -pubin -in "$CANOKEY_USBIP_WORK_DIR/9d.pem" -noout -text >/dev/null
openssl pkey -pubin -in "$CANOKEY_USBIP_WORK_DIR/9e.pem" -noout -text >/dev/null

section "ckman piv derive"
# Both-sides ECDH: the card's raw secret must match the host-side derivation.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out "$CANOKEY_USBIP_WORK_DIR/derive-peer-private.pem" 2>/dev/null
# The raw uncompressed SEC1 point is the tail of the SPKI DER encoding.
openssl pkey -in "$CANOKEY_USBIP_WORK_DIR/derive-peer-private.pem" \
  -pubout -outform DER 2>/dev/null \
  | tail -c 65 > "$CANOKEY_USBIP_WORK_DIR/derive-peer-public.bin"
"${CKMAN[@]}" piv derive 9d \
  "$CANOKEY_USBIP_WORK_DIR/derive-peer-public.bin" \
  "$CANOKEY_USBIP_WORK_DIR/derive-secret-card.bin" \
  --pin "$PIV_DEFAULT_PIN"
openssl pkeyutl -derive \
  -inkey "$CANOKEY_USBIP_WORK_DIR/derive-peer-private.pem" \
  -peerkey "$CANOKEY_USBIP_WORK_DIR/9d.pem" \
  -out "$CANOKEY_USBIP_WORK_DIR/derive-secret-host.bin"
cmp "$CANOKEY_USBIP_WORK_DIR/derive-secret-card.bin" \
  "$CANOKEY_USBIP_WORK_DIR/derive-secret-host.bin"

section "ckman piv decrypt"
# Raw RSA private operation: the padded block round-trips, message last.
"${CKMAN[@]}" piv keys generate \
  --algorithm rsa2048 \
  --management-key "$PIV_MANAGEMENT_KEY" \
  82 "$CANOKEY_USBIP_WORK_DIR/piv-rsa-public.pem"
echo -n "ckman-decrypt-test" > "$CANOKEY_USBIP_WORK_DIR/decrypt-message.bin"
openssl pkeyutl -encrypt \
  -pubin -inkey "$CANOKEY_USBIP_WORK_DIR/piv-rsa-public.pem" \
  -in "$CANOKEY_USBIP_WORK_DIR/decrypt-message.bin" \
  -out "$CANOKEY_USBIP_WORK_DIR/decrypt-cipher.bin"
"${CKMAN[@]}" piv decrypt 82 \
  "$CANOKEY_USBIP_WORK_DIR/decrypt-cipher.bin" \
  "$CANOKEY_USBIP_WORK_DIR/decrypt-padded.bin" \
  --pin "$PIV_DEFAULT_PIN"
message_bytes="$(wc -c < "$CANOKEY_USBIP_WORK_DIR/decrypt-message.bin")"
cmp \
  <(tail -c "$message_bytes" "$CANOKEY_USBIP_WORK_DIR/decrypt-padded.bin") \
  "$CANOKEY_USBIP_WORK_DIR/decrypt-message.bin"

# ML-KEM-768 decapsulation and SM2 key agreement exist on 3.1 only.
piv_decapsulate_roundtrip() {
  "${CKMAN[@]}" piv keys generate \
    --algorithm ml-kem768 \
    --management-key "$PIV_MANAGEMENT_KEY" \
    83 "$CANOKEY_USBIP_WORK_DIR/piv-kem-public.pem"
  # ML-KEM implicit rejection yields a 32-byte secret even for an invalid
  # ciphertext; this checks the round trip, not sender authenticity.
  head -c 1088 /dev/zero > "$CANOKEY_USBIP_WORK_DIR/kem-ciphertext.bin"
  "${CKMAN[@]}" piv decapsulate 83 \
    "$CANOKEY_USBIP_WORK_DIR/kem-ciphertext.bin" \
    "$CANOKEY_USBIP_WORK_DIR/kem-secret.bin" \
    --pin "$PIV_DEFAULT_PIN"
  [[ "$(wc -c < "$CANOKEY_USBIP_WORK_DIR/kem-secret.bin")" -eq 32 ]]
}
run_versioned_feature \
  "ckman piv decapsulate" \
  "piv-ml-kem" \
  piv_decapsulate_roundtrip

piv_agree_sm2_roundtrip() {
  "${CKMAN[@]}" piv keys generate \
    --algorithm sm2 \
    --management-key "$PIV_MANAGEMENT_KEY" \
    84 "$CANOKEY_USBIP_WORK_DIR/piv-sm2-public.pem"
  # Host-side SM2 peer: static and ephemeral points are the raw 65-byte
  # uncompressed SEC1 tail of the SPKI DER encoding.
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:SM2 \
    -out "$CANOKEY_USBIP_WORK_DIR/sm2-peer-private.pem" 2>/dev/null
  openssl pkey -in "$CANOKEY_USBIP_WORK_DIR/sm2-peer-private.pem" \
    -pubout -outform DER 2>/dev/null \
    | tail -c 65 > "$CANOKEY_USBIP_WORK_DIR/sm2-peer-public.bin"
  "${CKMAN[@]}" piv agree-sm2 84 \
    --peer-static "$CANOKEY_USBIP_WORK_DIR/sm2-peer-public.bin" \
    --peer-ephemeral "$CANOKEY_USBIP_WORK_DIR/sm2-peer-public.bin" \
    "$CANOKEY_USBIP_WORK_DIR/sm2-session-key.bin" \
    --pin "$PIV_DEFAULT_PIN"
  [[ "$(wc -c < "$CANOKEY_USBIP_WORK_DIR/sm2-session-key.bin")" -eq 16 ]]
}
run_versioned_feature \
  "ckman piv agree-sm2" \
  "piv-sm2-agree" \
  piv_agree_sm2_roundtrip

section "ckman piv logout"
"${CKMAN[@]}" piv logout

# The RNG command requires PIV application version 6.0+; the catalog firmware
# reports 5.7.0, so the matrix marks this unsupported everywhere for now.
piv_random_check() {
  local output
  output="$("${CKMAN[@]}" piv random 32)"
  [[ "$output" =~ ^[0-9a-f]{64}$ ]]
}
run_versioned_feature \
  "ckman piv random" \
  "piv-rng" \
  piv_random_check

section "ckman piv access set-retries"
run_versioned_feature \
  "ckman piv access set-retries" \
  "piv-set-retries" \
  "${CKMAN[@]}" piv access set-retries \
  --management-key "$PIV_MANAGEMENT_KEY" \
  --pin "$PIV_DEFAULT_PIN" \
  --force \
  3 3

section "cleanup: restore factory credentials"
"${CKMAN[@]}" piv reset --force --admin-pin "123456"
echo "PIV lifecycle passed."
