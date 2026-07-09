#!/usr/bin/env bash
set -euo pipefail

repo_root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"

assert_validation_rejects() {
  local script="$1"
  local version="$2"
  shift 2

  local status
  set +e
  "$repo_root/scripts/$script" "$version" "$@" >/dev/null 2>&1
  status=$?
  set -e
  if [[ "$status" -ne 2 ]]; then
    printf '%s did not reject unsafe version during validation (status=%s): %q\n' \
      "$script" "$status" "$version" >&2
    exit 1
  fi
}

for version in \
  'v/../..' \
  'v1.2' \
  'v1.2.3/../../tmp' \
  'v1.2.3;touch-PWNED' \
  'v1.2.3 bad' \
  'v1.2.3%0Amalicious' \
  'v1.2.3-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  $'v1.2.3\nmalicious' \
  $'v1.2.3\rmalicious'; do
  assert_validation_rejects build-release.sh "$version"
  assert_validation_rejects ci-install-smoke.sh \
    "$version" linux-x86_64 ubuntu:24.04
done

printf 'Release version validation passed.\n'
