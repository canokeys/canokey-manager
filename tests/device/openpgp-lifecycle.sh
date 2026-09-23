#!/usr/bin/env bash
# OpenPGP lifecycle: reset, key generation, cardholder data, touch cache,
# public-key export. DESTRUCTIVE: writes and resets the device. Requires
# CKMAN_DESTRUCTIVE=1 and a usbip test key.
set -euo pipefail

: "${CKMAN_DESTRUCTIVE:?OpenPGP lifecycle writes to the device; set CKMAN_DESTRUCTIVE=1}"

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

# Factory default after `openpgp reset`.
OPENPGP_ADMIN_PIN="12345678"

section "ckman openpgp reset"
capture_without_secrets \
  "Reset complete." \
  "${CKMAN[@]}" openpgp reset --force --admin-pin "123456"

section "ckman openpgp keys generate"
"${CKMAN[@]}" openpgp keys generate sig \
  --algorithm ed25519 \
  --admin-pin "$OPENPGP_ADMIN_PIN"

section "ckman openpgp cardholder"
"${CKMAN[@]}" openpgp cardholder set-name "Alice Example" --admin-pin "$OPENPGP_ADMIN_PIN"
"${CKMAN[@]}" openpgp cardholder set-login "alice" --admin-pin "$OPENPGP_ADMIN_PIN"
"${CKMAN[@]}" openpgp cardholder set-language "en" --admin-pin "$OPENPGP_ADMIN_PIN"
"${CKMAN[@]}" openpgp cardholder set-sex female --admin-pin "$OPENPGP_ADMIN_PIN"
"${CKMAN[@]}" openpgp cardholder set-url "https://example.invalid/alice.pub" \
  --admin-pin "$OPENPGP_ADMIN_PIN"

section "ckman openpgp info shows cardholder data"
openpgp_info="$("${CKMAN[@]}" openpgp info)"
printf '%s\n' "$openpgp_info"
grep -Fq "Cardholder name:" <<<"$openpgp_info"
grep -Fq "Alice Example" <<<"$openpgp_info"
grep -Eq "^Language preferences:[[:space:]]+en" <<<"$openpgp_info"
# ISO/IEC 5218: female is the ASCII marker 2.
grep -Eq "^Sex:[[:space:]]+2" <<<"$openpgp_info"
grep -Eq "^Login:[[:space:]]+alice" <<<"$openpgp_info"
grep -Fq "https://example.invalid/alice.pub" <<<"$openpgp_info"

section "ckman openpgp access set-touch-cache"
# Card-wide UIF touch cache (1.5.2+; this script runs on 2.0+). Set, then
# restore the factory zero.
"${CKMAN[@]}" openpgp access set-touch-cache 15 --admin-pin "$OPENPGP_ADMIN_PIN"
"${CKMAN[@]}" openpgp access set-touch-cache 0 --admin-pin "$OPENPGP_ADMIN_PIN"

section "ckman openpgp keys export"
"${CKMAN[@]}" openpgp keys export sig "$CANOKEY_USBIP_WORK_DIR/openpgp-public.pem"
grep -Fq "BEGIN PUBLIC KEY" "$CANOKEY_USBIP_WORK_DIR/openpgp-public.pem"
openssl pkey -pubin -in "$CANOKEY_USBIP_WORK_DIR/openpgp-public.pem" \
  -noout -text >/dev/null

echo "OpenPGP lifecycle passed."
