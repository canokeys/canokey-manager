#!/usr/bin/env bash
set -euo pipefail

: "${CANOKEY_USBIP:?This test must run under canokey-usbip}"
: "${CANOKEY_PCSC_READER:?canokey-usbip did not expose a PC/SC reader}"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

export CANOKEY_USBIP_WORK_DIR="$work_dir"
export XDG_CONFIG_HOME="$work_dir/config"
export XDG_DATA_HOME="$work_dir/data"
export CKMAN_TEST_KEYRING_FILE="$work_dir/keyring.json"
export PYTHON_KEYRING_BACKEND="tests.integration.usbip.keyring_backend.Keyring"

source "$script_dir/lib.sh"

section "ckman info"
"${CKMAN[@]}" info

section "ckman apdu"
apdu_output="$("${CKMAN[@]}" apdu --app openpgp --no-pretty 84/08=)"
printf '%s\n' "$apdu_output"
grep -Fq "RECV (SW=9000)" <<<"$apdu_output"

"$script_dir/piv.sh"
"$script_dir/oath.sh"
"$script_dir/openpgp.sh"
