#!/usr/bin/env bash
set -euo pipefail

readonly README_PATH="${1:-README.md}"

failures=0

fail() {
  printf 'doc claim check failed: %s\n' "$1" >&2
  failures=$((failures + 1))
}

require_contains() {
  local needle="$1"
  if ! grep -Fq "$needle" "$README_PATH"; then
    fail "README is missing required text: $needle"
  fi
}

if [[ ! -f "$README_PATH" ]]; then
  printf 'README not found: %s\n' "$README_PATH" >&2
  exit 1
fi

require_contains "Phase 12 CLI observability is partially implemented / active implementation."
require_contains "Web/API dashboard is planned / not implemented yet."
require_contains "not production-complete"

if grep -Fq "ocfleet-api" "$README_PATH"; then
  fail "README must not mention ocfleet-api as an available binary"
fi

what_it_does="$(
  awk '
    $0 == "## What It Does" { in_section = 1; next }
    $0 == "## What It Does Not Do" { in_section = 0 }
    in_section { print }
  ' "$README_PATH"
)"

if [[ -z "$what_it_does" ]]; then
  fail "README is missing a non-empty What It Does section"
fi

danger_re='shell\.exec|command\.run|occtl\.raw|systemctl\.raw|journalctl\.raw|file\.read|shell execution|command execution|raw command|raw file|ocserv reload|ocserv restart|reload/restart|config apply|configuration apply|rollback|user disconnect|user management|systemctl|occtl|journalctl|write operations|ocserv write'
negative_re='does not|do not|not |cannot|no |never|disabled|without|must not|forbidden|planned but not|not implemented'

if printf '%s\n' "$what_it_does" | grep -Eiq "$danger_re"; then
  printf 'README What It Does contains forbidden capability wording:\n' >&2
  printf '%s\n' "$what_it_does" | grep -Ein "$danger_re" >&2 || true
  failures=$((failures + 1))
fi

in_negative_paragraph=0
while IFS= read -r line; do
  lower_line="$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')"
  if [[ -z "$lower_line" || "$lower_line" =~ ^##[[:space:]] ]]; then
    in_negative_paragraph=0
  elif [[ "$lower_line" =~ $negative_re ]]; then
    in_negative_paragraph=1
  fi

  if [[ "$lower_line" =~ $danger_re ]] \
    && [[ ! "$lower_line" =~ $negative_re ]] \
    && [[ "$in_negative_paragraph" -eq 0 ]]; then
    fail "README has a positive-looking dangerous claim: $line"
  fi
done < <(
  awk '
    $0 == "## What It Does Not Do" { skip = 1; next }
    skip && /^## / { skip = 0 }
    !skip { print }
  ' "$README_PATH"
)

if [[ "$failures" -gt 0 ]]; then
  exit 1
fi

printf 'README doc claim check passed.\n'
