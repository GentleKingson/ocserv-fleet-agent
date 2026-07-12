#!/usr/bin/env bash
set -euo pipefail

required_files=(
  docs/release-policy.md
  docs/release-rollback-runbook.md
  docs/release-security.md
  docs/a8-migration-failure-inventory.md
)
for file in "${required_files[@]}"; do
  test -s "$file"
done

grep -Fq '| `v0.1.x` | `v0.3.x` |' docs/release-policy.md
grep -Fq '| `v0.2.x` | `v0.3.x` |' docs/release-policy.md
grep -Fq 'An older binary must never open a database migrated by a newer binary.' \
  docs/release-rollback-runbook.md
grep -Fq 'controlled writes remain default-off' docs/release-policy.md
grep -Fq 'migration_tests_legacy_fixtures_upgrade_to_current' \
  docs/a8-migration-failure-inventory.md

printf 'Release policy contract check passed.\n'
