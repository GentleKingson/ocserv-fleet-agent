#!/usr/bin/env bash
set -euo pipefail

readonly DEFAULT_WORKFLOW_DIR=".github/workflows"
readonly SHA_REF_RE='^[0-9a-fA-F]{40}$'
readonly DOCKER_DIGEST_RE='^docker://.+@sha256:[0-9a-fA-F]{64}$'

declare -a scan_roots=()
declare -a workflow_files=()

if [[ "$#" -eq 0 ]]; then
  scan_roots=("$DEFAULT_WORKFLOW_DIR")
else
  scan_roots=("$@")
fi

for root in "${scan_roots[@]}"; do
  if [[ -d "$root" ]]; then
    while IFS= read -r -d '' file; do
      workflow_files+=("$file")
    done < <(find "$root" -type f \( -name '*.yml' -o -name '*.yaml' \) -print0)
  elif [[ -f "$root" ]]; then
    case "$root" in
      *.yml | *.yaml) workflow_files+=("$root") ;;
      *) printf 'Skipping non-workflow file: %s\n' "$root" >&2 ;;
    esac
  else
    printf 'Workflow path not found: %s\n' "$root" >&2
    exit 1
  fi
done

if [[ "${#workflow_files[@]}" -eq 0 ]]; then
  printf 'No workflow YAML files found.\n' >&2
  exit 1
fi

failures=0

strip_yaml_quotes() {
  local value="$1"
  value="${value#\"}"
  value="${value%\"}"
  value="${value#\'}"
  value="${value%\'}"
  printf '%s' "$value"
}

check_uses_ref() {
  local file="$1"
  local line_no="$2"
  local uses_ref="$3"

  case "$uses_ref" in
    ./* | ../* | /*)
      return 0
      ;;
    docker://*)
      if [[ "$uses_ref" =~ $DOCKER_DIGEST_RE ]]; then
        return 0
      fi
      printf '%s:%s: docker action must be pinned by sha256 digest: %s\n' \
        "$file" "$line_no" "$uses_ref" >&2
      failures=$((failures + 1))
      return 0
      ;;
  esac

  if [[ "$uses_ref" != *@* ]]; then
    printf '%s:%s: remote action is missing an @ ref: %s\n' \
      "$file" "$line_no" "$uses_ref" >&2
    failures=$((failures + 1))
    return 0
  fi

  local ref="${uses_ref##*@}"
  if [[ ! "$ref" =~ $SHA_REF_RE ]]; then
    printf '%s:%s: remote action ref must be a 40-character commit SHA: %s\n' \
      "$file" "$line_no" "$uses_ref" >&2
    failures=$((failures + 1))
  fi
}

for file in "${workflow_files[@]}"; do
  line_no=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_no=$((line_no + 1))
    if [[ "$line" =~ ^[[:space:]-]*uses:[[:space:]]*([^[:space:]#]+) ]]; then
      uses_ref="$(strip_yaml_quotes "${BASH_REMATCH[1]}")"
      check_uses_ref "$file" "$line_no" "$uses_ref"
    fi
  done < "$file"
done

if [[ "$failures" -gt 0 ]]; then
  printf 'GitHub Actions pin check failed with %s violation(s).\n' "$failures" >&2
  exit 1
fi

printf 'GitHub Actions pin check passed for %s workflow file(s).\n' "${#workflow_files[@]}"
