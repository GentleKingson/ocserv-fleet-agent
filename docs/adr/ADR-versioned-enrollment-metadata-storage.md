# ADR: Versioned Enrollment Metadata Storage

## Status

Accepted as the eighth A2 typed-versioned-storage slice.

## Decision

Enrollment token labels and scope, plus join-request requested and approved
labels, persist `ocfleet.enrollment.metadata.v1`. The closed envelope carries a
fixed metadata kind and a typed scalar map whose values are limited to null,
boolean, JSON number, or bounded printable string. Writers canonicalize public
objects before persistence. Readers require the expected kind for each column
and return only the established public object.

Migration `0016` canonicalizes exact legacy objects transactionally after the
standard private backup. Unknown envelope fields, wrong kinds or schemas,
nested values, invalid keys or bounds, and sensitive/address-like data abort
migration. Non-approved requests must retain an empty approved-label map.
Current-schema readers fail closed on externally contaminated rows.

## Consequences

SQLite schema version increases from `15` to `16` without changing table
shapes. Rollback requires restoring the pre-migration backup before running an
older binary. Enrollment CLI behavior and public records retain plain label and
scope objects. Metadata cannot derive node identity, trust, endpoint ownership,
or authorization, and this change adds no automatic enrollment or API mutation.
