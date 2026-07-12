#!/usr/bin/env bash
set -euo pipefail

version="$(sed -n 's/^version = "\([0-9][0-9.]*\)"$/\1/p' Cargo.toml | head -1)"
if [[ -z "$version" ]]; then
  printf 'could not resolve workspace version\n' >&2
  exit 1
fi
tag="v$version"

grep -Fq '"version": "'"$version"'"' docs/api/openapi.yaml
test -s "docs/release-notes/$tag.md"
grep -Fq "default: $tag" .github/workflows/release.yml
grep -Fq "default: $tag" .github/workflows/install-smoke.yml
grep -Fq 'version="${1:-'"$tag"'}"' scripts/build-release.sh
grep -Fq "dist/$tag/SHA256SUMS" scripts/verify-checksums.sh
grep -Fq "./scripts/build-release.sh $tag" docs/install.md

for package in ocfleet-agent ocfleet-api ocfleet-cli ocfleet-config ocfleet-protocol; do
  awk -v package="$package" -v version="$version" '
    $0 == "name = \"" package "\"" { found = 1; next }
    found && $0 == "version = \"" version "\"" { matched = 1; exit }
    found && /^\[\[package\]\]/ { exit }
    END { exit matched ? 0 : 1 }
  ' Cargo.lock
done

printf 'Release version consistency passed for %s.\n' "$tag"
