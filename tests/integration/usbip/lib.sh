#!/usr/bin/env bash

: "${CANOKEY_USBIP:?This test must run under canokey-usbip}"
: "${CANOKEY_PCSC_READER:?canokey-usbip did not expose a PC/SC reader}"
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
