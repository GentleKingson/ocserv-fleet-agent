#!/usr/bin/env sh
set -eu

version="${1:-v0.1.0}"
case "$version" in
  v*) ;;
  *) version="v$version" ;;
esac

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
out_dir="$repo_root/dist/$version"
cargo_bin="${CARGO:-cargo}"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="x86_64" ;;
  arm64|aarch64) arch="aarch64" ;;
esac

rm -rf "$out_dir"
mkdir -p "$out_dir"

"$cargo_bin" build --release --locked --workspace --bins

cp "$repo_root/target/release/ocfleet" "$out_dir/ocfleet-$version-$os-$arch"
cp "$repo_root/target/release/ocfleet-agent" "$out_dir/ocfleet-agent-$version-$os-$arch"

(
  cd "$out_dir"
  rm -f SHA256SUMS
  for artifact in ocfleet-*; do
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "$artifact"
    else
      shasum -a 256 "$artifact"
    fi
  done > SHA256SUMS
)

printf 'release_dir=%s\n' "$out_dir"
printf 'checksum_file=%s\n' "$out_dir/SHA256SUMS"
