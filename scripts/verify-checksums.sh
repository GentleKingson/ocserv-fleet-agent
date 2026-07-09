#!/usr/bin/env sh
set -eu

checksum_file="${1:-dist/v0.2.0/SHA256SUMS}"

if [ ! -f "$checksum_file" ]; then
  printf 'checksum file not found: %s\n' "$checksum_file" >&2
  exit 1
fi

checksum_dir="$(CDPATH= cd -- "$(dirname -- "$checksum_file")" && pwd)"
checksum_name="$(basename -- "$checksum_file")"

(
  cd "$checksum_dir"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "$checksum_name"
  else
    shasum -a 256 -c "$checksum_name"
  fi
)
