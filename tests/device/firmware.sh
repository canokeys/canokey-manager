#!/usr/bin/env bash
# Firmware feature matrix for the device-test harness, replacing the Python
# firmware.py of the old rig. Reads tests/device/features.tsv:
#   <firmware-prefix>\t<feature>\tsupported|unsupported
# A firmware matches the longest listed prefix of the normalized version.
# Features absent from the matrix report "unknown" (a harness error), so the
# matrix is the auditable record of what has been validated.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

normalize() {
  # Strip development/build suffixes: 3.1.0-dev -> 3.1.0, 1.5.2+rc -> 1.5.2.
  sed -e 's/[-+].*$//' -e 's/^v//' <<<"$1"
}

status() {
  local version feature
  version="$(normalize "$1")"
  feature="$2"
  awk -F '\t' -v version="$version" -v feature="$feature" '
    $1 ~ /^#/ || NF == 0 { next }
    $2 == feature && index(version, $1) == 1 {
      if (length($1) > best) { best = length($1); status = $3 }
    }
    END { print (best ? status : "unknown") }
  ' "$script_dir/features.tsv"
}

case "${1:-}" in
  normalize) normalize "$2" ;;
  status) status "$2" "$3" ;;
  *)
    echo "usage: firmware.sh {normalize VERSION | status VERSION FEATURE}" >&2
    exit 2
    ;;
esac
