#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  printf 'usage: %s VERSION OUTPUT_DIR\n' "$0" >&2
  exit 2
fi

version="$1"
output_dir="$2"
repo_root="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
case "$version" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) printf 'invalid release version: %s\n' "$version" >&2; exit 2 ;;
esac

mkdir -p "$output_dir"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}" cargo cyclonedx \
  --manifest-path "$repo_root/Cargo.toml" \
  --format json \
  --spec-version 1.5 \
  --all-features \
  --override-filename "ocfleet-$version.cdx"

for crate in ocfleet-protocol ocfleet-config ocfleet-agent ocfleet-cli ocfleet-api; do
  generated="$repo_root/crates/$crate/ocfleet-$version.cdx.json"
  destination="$output_dir/$crate-$version.cdx.json"
  mv "$generated" "$destination"
  jq -e '
    .bomFormat == "CycloneDX" and
    .specVersion == "1.5" and
    (.metadata.component.name | type == "string") and
    (.components | type == "array")
  ' "$destination" >/dev/null
done
