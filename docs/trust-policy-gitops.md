# Trust Policy GitOps Review

Stage B6 is review-only. It creates signed policy and review artifacts but has
no policy apply command and never changes enrollment, trust, peers, path-probe
authorization, or agent state.

## Sign a revision

Every signed policy must set a bounded explicit revision:

```toml
[metadata]
name = "production-fleet"
revision = "git-4f18c92"
```

Create the signing key outside the repository and keep it owner-only. The
`sign` command reads an Ed25519 PKCS#8 key and writes detached, owner-only
signature and pinned-public-key documents:

```sh
mkdir -m 700 .policy-artifacts
ocfleet trust policy sign policy.toml \
  --key-file /run/secrets/policy-signing.pk8 \
  --key-id policy-ci-2026 \
  --output .policy-artifacts/policy.signature.json \
  --public-key-output .policy-artifacts/policy.public-key.json
```

The signature covers the canonical policy revision and SHA-256 digest. TOML
and YAML with equivalent ordered data produce the same digest. Pin the public
key document through normal repository review rather than accepting a public
key supplied by an untrusted policy author.

## Produce the CI plan

`plan` requires a valid detached signature and a pinned public key. The JSON
artifact is deterministic: it contains no generation timestamp or absolute
path, changes are sorted, and the list is capped at 512 entries while retaining
the total count and truncation flag.

```sh
ocfleet --database controller.sqlite trust policy plan policy.toml \
  --signature .policy-artifacts/policy.signature.json \
  --public-key .policy-artifacts/policy.public-key.json \
  --output .policy-artifacts/trust-policy-plan.json \
  --markdown-output .policy-artifacts/trust-policy-review.md \
  --json
```

The plan includes a closed `TRUST_POLICY_DRIFT` projection with active state,
severity, and bounded change count. Both JSON and Markdown remain review-only.
The command opens an existing checkpointed controller state as an immutable
SQLite snapshot; when the database is missing it compares against an empty
in-memory snapshot and creates no database. A non-empty WAL is rejected rather
than checkpointed or ignored, so capture or checkpoint the review snapshot
before CI.

For isolated CI, use:

```sh
scripts/trust-policy-ci-review.sh \
  ./ocfleet controller.sqlite policy.toml \
  .policy-artifacts/policy.signature.json \
  .policy-artifacts/policy.public-key.json \
  .policy-artifacts/ci
```

The script uses a private artifact directory and rejects a controller database
digest change.

## Approval and history

Approval is a separate signed artifact bound to the exact canonical plan hash
and the global `--actor` identity. The trust root is an independently managed,
owner-only reviewer keyring; approval artifacts carry only `key_id`, never a
self-asserted public key. Each key ID is globally unique and binds one actor to
one Ed25519 public key:

```json
{
  "schema": "ocfleet.trust_policy.reviewer-keyring.v1",
  "reviewers": [{
    "actor": "security-reviewer",
    "key_id": "security-review-2026",
    "public_key": "<base64-encoded 32-byte Ed25519 public key>"
  }]
}
```

```sh
ocfleet --actor security-reviewer trust policy approve \
  .policy-artifacts/trust-policy-plan.json \
  --key-file /run/secrets/review-approval.pk8 \
  --key-id security-review-2026 \
  --reviewer-keyring /run/secrets/reviewer-keyring.json \
  --output .policy-artifacts/approval.json
```

The signing key must match the actor/key ID binding in the keyring. Truncated
plans cannot be approved; regenerate a review artifact that covers the complete
change set before approval.

Append the verified plan and approval link to the bounded append-only history:

```sh
ocfleet trust policy history record \
  .policy-artifacts/trust-policy-plan.json \
  --approval .policy-artifacts/approval.json \
  --reviewer-keyring /run/secrets/reviewer-keyring.json \
  --history .policy-artifacts/history.jsonl

ocfleet trust policy history list .policy-artifacts/history.jsonl --json
```

History verifies approvals only against the external reviewer keyring and
rejects duplicate revisions, invalid approval signatures, mismatched plan
hashes, unknown fields, more than 256 entries, and files over 1 MiB. Record
holds an exclusive cross-process lock across validation and the single-buffer
append, so concurrent writers cannot admit the same revision.

## Non-mutation boundary

`validate`, `diff`, and `plan` do not migrate or create the selected controller
database. They have no RPC adapter, do not load the controller transport key,
and cannot approve enrollment or emit trust, peer, or path authorization. There
is intentionally no automatic or manual policy apply subcommand in Stage B6.
