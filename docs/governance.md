# Governance Model

This document describes the governance foundation for scaling `ocfleet` beyond a
single local operator while preserving the read-only ocserv fleet boundary.
Nothing in this model adds ocserv reload/restart, config apply, user management,
shell, script, raw command, raw file, or raw log access.

## Operator Identity

Controller-local CLI commands resolve one actor for every process:

```bash
ocfleet --actor alice@example.com node list
OCFLEET_ACTOR=alice@example.com ocfleet retention set observations --max-age 30d
```

Resolution order is:

1. `--actor`
2. `OCFLEET_ACTOR`
3. local `USER`
4. `local-cli`

Actor values are bounded printable ASCII. Invalid explicit `--actor` or
`OCFLEET_ACTOR` values fail closed before controller actions run. Local CLI mode
still defaults to the local user for developer ergonomics, but production
operators should set `OCFLEET_ACTOR` from a controlled login/session wrapper.

All controller audit events use the same resolver. Store APIs that already
accept an actor continue to validate it before writing audit rows.

## RBAC Roles

The role model is intentionally small:

| Role | Intended permissions |
| --- | --- |
| `viewer` | Read-only queries: node list/info, health, observations, jobs, runs, alerts, audit export views. |
| `operator` | Controller-local operational mutations: scheduler job create/enable/disable/run, retention policy changes, alert silence/resolve/delivery. |
| `security-admin` | Enrollment approval, EndpointID rotate/revoke/quarantine, trust policy review, and future explicitly audited trust apply operations. |

`ocfleet_cli::governance` implements this fixed policy vocabulary and tests the
three role boundaries. The local CLI does not enforce RBAC in this slice; it
relies on OS user, file permissions, and the resolved audit actor. The API
returns only `viewer` principals for local or bearer-authenticated requests and
exposes only read-only `GET` routes. Any future API write route must require
authenticated RBAC and must not be available anonymously.

## Audit Model

The target contract is that every controller SQLite mutation writes a
controller audit row with:

- resolved actor
- event name
- low-sensitive identifiers
- fixed method or command class where applicable
- success/failure and low-sensitive error code
- redacted detail JSON

Audit rows must not contain raw secrets, bearer tokens, HMAC secrets, raw RPC
bodies, raw stdout/stderr, raw logs, raw config, certificate material, usernames,
client IPs, or session IDs. Retention policies do not delete
`controller_audit_log`; long-term audit handling is export/archive based.

Current enforcement is partial and must not be overstated. Enrollment approval
and legacy claim, node/endpoint lifecycle, scheduler job configuration, and
scheduler run start/outcome/finish transitions are actor-bound `StoreWriter`
operations audited in their SQLite transaction. Failure-injection tests prove
that enrollment request/node/trust, endpoint lifecycle, scheduler job
configuration, observation, RPC audit, run state, and job-clock changes roll
back at their declared boundaries. Enrollment token/request transitions,
health/alert/delivery, retention, and other call sites remain to migrate.
Completing those families is required before claiming fully fail-closed
controller mutation audit. The API remains read-only while that work is
incomplete. The governing decision is recorded in
[ADR-atomic-audit-writes](adr/ADR-atomic-audit-writes.md).

Enrollment approval/claim and endpoint lifecycle CLI calls are routed through
`StoreWriter`. A static source guard rejects direct production calls to those
enrollment writers, node add/enable/disable/remove, and endpoint
rotate/revoke/quarantine outside the reviewed SQLite store and backend adapter.
This guard is a review backstop, not RBAC; the resolved actor and transactional
audit remain the authority record.

## Endpoint Authority

An Active endpoint status is necessary but not sufficient. Dispatch authority
requires an enabled registry node that points to the contacted EndpointID, an
Active trust row that points back to the same node, and exactly one Active trust
binding for that node. Scheduler workers repeat this complete source/path-target
snapshot after concurrency waits. A mismatch retains protocol-level
`ENDPOINT_NOT_ALLOWED`; fixed controller-local observation codes distinguish
unbound and binding-mismatch cases.

The controller never derives this binding from agent-supplied hostname or
labels. New approval atomically binds explicit operator node metadata. Existing
approved-unbound rows remain rejected until `enroll claim` verifies the exact
legacy approval shape and binds it in one audited transaction. There is no scan,
startup repair, implicit `node add` adoption, or trust-on-first-use fallback.
See
[ADR-enrollment-binding-ownership](adr/ADR-enrollment-binding-ownership.md).

## Trust Policy Workflow

Trust policy as code is a review and drift-detection workflow:

1. Operators edit a TOML or YAML policy file in version control.
2. `ocfleet trust policy validate <file>` checks schema, fixed lifecycle states,
   EndpointID shape, duplicate IDs, and explicit path-probe pairs.
3. `ocfleet trust policy diff <file>` compares the policy to controller SQLite
   registry/trust state.
4. Operators review diffs and then use existing explicit audited commands such
   as `node add`, `endpoint revoke`, or `endpoint quarantine`.

There is no trust policy `apply` command in this slice. Validation and diff never
create trust, approve enrollment, authorize path probes, or contact agents.

## Backend Options

SQLite remains the default and only implemented controller backend. It keeps the
existing private-file checks, migration backups, and local-first operating model.

Postgres is a planned optional backend for larger fleets and longer query
history. It must not be required for existing users, and it must not reduce
SQLite safety. See [backend.md](backend.md) for the abstraction plan and current
SQLite-only assumptions.
