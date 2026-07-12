#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  printf 'usage: %s RELEASE_DIR VERSION\n' "$0" >&2
  exit 2
fi

release_dir="$1"
version="$2"
identity_regexp='^https://github\.com/GentleKingson/ocserv-fleet-agent/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+([+-].*)?$'
issuer='https://token.actions.githubusercontent.com'

for arch in linux-x86_64 linux-aarch64; do
  for binary in ocfleet ocfleet-agent ocfleet-api ocfleet-ocserv-collector; do
    artifact="$release_dir/$binary-$version-$arch"
    test -f "$artifact"
    cosign verify-blob \
      --bundle "$artifact.sigstore.json" \
      --certificate-identity-regexp "$identity_regexp" \
      --certificate-oidc-issuer "$issuer" \
      "$artifact" >/dev/null
  done
  for crate in ocfleet-protocol ocfleet-config ocfleet-agent ocfleet-cli ocfleet-api; do
    sbom="$release_dir/$crate-$version-$arch.cdx.json"
    jq -e '.bomFormat == "CycloneDX" and .specVersion == "1.5"' "$sbom" >/dev/null
    cosign verify-blob \
      --bundle "$sbom.sigstore.json" \
      --certificate-identity-regexp "$identity_regexp" \
      --certificate-oidc-issuer "$issuer" \
      "$sbom" >/dev/null
  done
done
