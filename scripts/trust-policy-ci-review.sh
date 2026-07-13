#!/bin/sh
set -eu

if [ "$#" -ne 6 ]; then
  echo "usage: $0 <ocfleet> <database> <policy> <signature> <public-key> <artifact-dir>" >&2
  exit 2
fi

ocfleet=$1
database=$2
policy=$3
signature=$4
public_key=$5
artifact_dir=$6

umask 077
mkdir -p "$artifact_dir"
chmod 700 "$artifact_dir"

before=missing
if [ -f "$database" ]; then
  before=$(sha256sum "$database" | cut -d ' ' -f 1)
fi

"$ocfleet" --database "$database" trust policy plan "$policy" \
  --signature "$signature" \
  --public-key "$public_key" \
  --output "$artifact_dir/trust-policy-plan.json" \
  --markdown-output "$artifact_dir/trust-policy-review.md" \
  --json

after=missing
if [ -f "$database" ]; then
  after=$(sha256sum "$database" | cut -d ' ' -f 1)
fi
if [ "$before" != "$after" ]; then
  echo "trust policy review changed the controller database" >&2
  exit 1
fi

printf '%s\n' "$artifact_dir/trust-policy-plan.json"
printf '%s\n' "$artifact_dir/trust-policy-review.md"
