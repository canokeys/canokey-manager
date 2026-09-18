#!/usr/bin/env bash
# Shared helpers for the CanoKey device-test harness. Language-agnostic: the
# scripts drive the Rust `ckman` binary as a black box.
#
# Environment contract (identical to the Python rig):
#   CANOKEY_USBIP                 must be set (guards against real hardware)
#   CANOKEY_PCSC_READER           PC/SC reader name to select
#   CANOKEY_FIRMWARE_VERSION      firmware under test (as reported by usbip)
#   CANOKEY_USBIP_WORK_DIR        scratch directory (smoke.sh provides one)
#
# Optional:
#   CKMAN_BIN                     path to the ckman binary (default:
#                                 target/debug/ckman, or `cargo run`)
#   CKMAN_DESTRUCTIVE=1           required to run scripts that write, reset,
#                                 or delete on the device

: "${CANOKEY_USBIP:?This test must run under canokey-usbip}"
: "${CANOKEY_PCSC_READER:?canokey-usbip did not expose a PC/SC reader}"
: "${CANOKEY_FIRMWARE_VERSION:?canokey-usbip did not expose a firmware version}"
: "${CANOKEY_USBIP_WORK_DIR:?smoke.sh did not provide a work directory}"

if [[ -n "${CKMAN_BIN:-}" ]]; then
  CKMAN=("$CKMAN_BIN" --reader "$CANOKEY_PCSC_READER")
elif [[ -x "$script_dir/../../target/debug/ckman" ]]; then
  CKMAN=("$script_dir/../../target/debug/ckman" --reader "$CANOKEY_PCSC_READER")
else
  CKMAN=(cargo run --quiet --bin ckman -- --reader "$CANOKEY_PCSC_READER")
fi

section() {
  printf '\n=== %s ===\n' "$1"
}

expect_failure() {
  local description="$1"
  shift

  if "$@" \
    >"$CANOKEY_USBIP_WORK_DIR/expected-failure.stdout" \
    2>"$CANOKEY_USBIP_WORK_DIR/expected-failure.stderr"; then
    echo "ERROR: $description unexpectedly succeeded" >&2
    return 1
  fi
  echo "$description rejected as expected."
}

capture_without_secrets() {
  local expected="$1"
  shift

  local output
  output="$("$@")"
  grep -Fq "$expected" <<<"$output"
}

# firmware.sh status <feature> prints supported|unsupported|unknown for the
# firmware under test, from the declarative matrix in features.tsv.
firmware_feature_status() {
  "$script_dir/firmware.sh" status "$CANOKEY_FIRMWARE_VERSION" "$1"
}

FEATURE_AVAILABLE=false

unsupported_feature() {
  echo "UNSUPPORTED: $1 on CanoKey firmware ${CANOKEY_FIRMWARE_VERSION_NORMALIZED}; $2 Continuing with the remaining commands."
}

run_versioned_feature() {
  local description="$1"
  local feature="$2"
  shift 2

  local status
  status="$(firmware_feature_status "$feature")"
  case "$status" in
    supported)
      FEATURE_AVAILABLE=true
      "$@"
      ;;
    unsupported)
      FEATURE_AVAILABLE=false
      unsupported_feature \
        "$description" \
        "The firmware feature matrix marks ${feature} as unavailable."
      ;;
    unknown)
      echo "ERROR: UNKNOWN: ${feature} has not been validated for CanoKey firmware ${CANOKEY_FIRMWARE_VERSION_NORMALIZED}" >&2
      return 1
      ;;
    *)
      echo "ERROR: unknown firmware feature status: $status" >&2
      return 1
      ;;
  esac
}
