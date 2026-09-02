#!/usr/bin/env bash

: "${CANOKEY_USBIP:?This test must run under canokey-usbip}"
: "${CANOKEY_PCSC_READER:?canokey-usbip did not expose a PC/SC reader}"
: "${CANOKEY_FIRMWARE_VERSION:?canokey-usbip did not expose a firmware version}"
: "${CANOKEY_USBIP_WORK_DIR:?smoke.sh did not provide a work directory}"

CKMAN=(uv run ckman --reader "$CANOKEY_PCSC_READER")

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

FEATURE_AVAILABLE=false

firmware_feature_status() {
  uv run python "$script_dir/firmware.py" \
    status "$CANOKEY_FIRMWARE_VERSION" "$1"
}

probe_feature() {
  local description="$1"
  local unsupported_pattern="$2"
  shift 2

  local stdout_file="$CANOKEY_USBIP_WORK_DIR/optional.stdout"
  local stderr_file="$CANOKEY_USBIP_WORK_DIR/optional.stderr"
  local status

  if "$@" >"$stdout_file" 2>"$stderr_file"; then
    FEATURE_AVAILABLE=true
    echo "$description is supported."
    return 0
  else
    status=$?
  fi

  if grep -Eiq "$unsupported_pattern" "$stdout_file" "$stderr_file"; then
    FEATURE_AVAILABLE=false
    echo "UNSUPPORTED: $description is not available on CanoKey firmware ${CANOKEY_FIRMWARE_VERSION_NORMALIZED}; continuing."
    return 0
  fi

  cat "$stdout_file"
  cat "$stderr_file" >&2
  return "$status"
}

unsupported_feature() {
  echo "UNSUPPORTED: $1 on CanoKey firmware ${CANOKEY_FIRMWARE_VERSION_NORMALIZED}; $2 Continuing with the remaining commands."
}

run_versioned_feature() {
  local description="$1"
  local feature="$2"
  local unsupported_pattern="$3"
  shift 3

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
      probe_feature "$description" "$unsupported_pattern" "$@"
      ;;
    *)
      echo "ERROR: unknown firmware feature status: $status" >&2
      return 1
      ;;
  esac
}
