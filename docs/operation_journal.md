# Crash-safe local operation journal

v0.11 adds a durable single-operation journal for deterministic mutations that
span approvals, budgets, and evidence. Its purpose is narrow: after a process
crash, Defiant can finish a known local state transition without inventing an
external outcome or applying a reservation twice.

The journal covers:

- creating a held approval, including its exact budget reservation and pending
  evidence record;
- rejecting a held approval, releasing its reservation, and recording terminal
  evidence; and
- expiring a held approval, releasing its reservation, and recording terminal
  evidence; and
- reconciling a sealed approval-free authorization, including its exact budget
  resolution and terminal evidence.

Before the first store changes, the harness writes one prepared operation to
`operation_journal.json`. The entry binds an operation id, kind, preparation
time, strict payload schema, and canonical payload hash. It contains immutable
prepared approval/evidence snapshots and exact reservation identifiers. The
state directory remains confidential because these snapshots can contain held
action material and operator attestations.

v0.12 writes journal schema `0.2.0`. Readers continue to accept v0.11 schema
`0.1.0`, allowing an empty or active older journal to upgrade without losing
its recovery intent.

## Recovery

Every authority entry point checks the journal before the normal integrity
gate. Recovery recognizes or applies each step idempotently:

1. an exact reservation is created or recognized;
2. the exact prepared approval transition is created or recognized;
3. the exact prepared evidence record is appended or recognized; and
4. the journal is atomically marked inactive.

Rejection and expiry use the corresponding exact release instead of a new
reservation. A conflicting reservation, approval, evidence record, identifier,
signature, or release fails closed and leaves the operation available for
investigation. A crash after the final evidence append but before journal
completion does not duplicate evidence on restart.

Only one operation may be active. Concurrent preparation fails immediately.
As with the other state files, an `operation_journal.json.lock` left by a hard
crash requires the operator to confirm that no writer remains before resolving
the stale lock.

## External-outcome boundary

The journal never records or infers that a tool executed. An approval in
`executing`, or an authorization whose external result is unknown, remains on
the explicit operator reconciliation path. Only after the operator supplies an
outcome, identity, and note does v0.12 journal the resulting deterministic local
mutations. The journal cannot turn the absence of a response into `succeeded`,
`failed`, or `not_executed`.

## Read-only visibility

`dah doctor`, Command Core, and Command Center inspect the journal without
initializing, completing, or repairing it. A valid active operation is reported
as recovery required with only its id, kind, and preparation time. The payload,
held action, operator note, and attestation are excluded. A malformed or
tampered journal is critical and blocks authority.

Command Center remains visibility-only. There is no replay, repair, complete,
delete, or force-recovery endpoint.
