#!/usr/bin/env sh
set -eu

version="${1:-v0.3.0}"
case "$version" in
  v*) ;;
  *) version="v$version" ;;
esac
case "$version" in
  *[!0-9A-Za-z.+-]*)
    printf 'invalid release version: unsupported character\n' >&2
    exit 2
    ;;
esac
if [ "${#version}" -gt 64 ]; then
  printf 'invalid release version: maximum length is 64 characters\n' >&2
  exit 2
fi
if ! printf '%s\n' "$version" | LC_ALL=C grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?(\+[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$'; then
  printf 'invalid release version: expected vMAJOR.MINOR.PATCH with optional semver suffix\n' >&2
  exit 2
fi

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
dist_root="$repo_root/dist"
out_dir="$dist_root/$version"
case "$out_dir" in
  "$dist_root"/v*) ;;
  *)
    printf 'refusing release output outside dist\n' >&2
    exit 2
    ;;
esac
if [ -L "$dist_root" ] || { [ -e "$dist_root" ] && [ ! -d "$dist_root" ]; }; then
  printf 'refusing release output through non-directory or symlink dist root\n' >&2
  exit 2
fi
if [ -L "$out_dir" ] || { [ -e "$out_dir" ] && [ ! -d "$out_dir" ]; }; then
  printf 'refusing release output through non-directory or symlink: %s\n' \
    "$out_dir" >&2
  exit 2
fi
cargo_bin="${CARGO:-cargo}"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="x86_64" ;;
  arm64|aarch64) arch="aarch64" ;;
esac

cd "$repo_root"
"$cargo_bin" build \
  --release \
  --locked \
  --workspace \
  --bins \
  --target-dir "$repo_root/target"

for binary in ocfleet ocfleet-agent ocfleet-api ocfleet-ocserv-collector; do
  source="$repo_root/target/release/$binary"
  if [ ! -x "$source" ]; then
    printf 'missing release binary: %s\n' "$binary" >&2
    exit 1
  fi
done

expected_version="${version#v}"
for binary in ocfleet ocfleet-agent ocfleet-api ocfleet-ocserv-collector; do
  reported="$("$repo_root/target/release/$binary" --version)"
  if [ "$reported" != "$binary $expected_version" ]; then
    printf 'binary version mismatch for %s: %s\n' "$binary" "$reported" >&2
    exit 1
  fi
done

rm -rf "$out_dir"
mkdir -p "$out_dir"
for binary in ocfleet ocfleet-agent ocfleet-api ocfleet-ocserv-collector; do
  install -m 0755 "$repo_root/target/release/$binary" \
    "$out_dir/$binary-$version-$os-$arch"
done

(
  cd "$out_dir"
  LC_ALL=C
  export LC_ALL
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
