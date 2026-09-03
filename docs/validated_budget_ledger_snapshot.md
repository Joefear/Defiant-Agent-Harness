# Validated budget ledger snapshot

Budget state is an authority-bearing accounting boundary. Reservations reduce
available authority immediately; settlement, release, and reconciliation
determine whether exposure remains charged. Validation and publication must
therefore describe the same durable observation.

v0.63 gives `BudgetLedger` one explicit snapshot contract.

## Detached bounded observation

Every recovery read first passes the strict JSON loader under
`MAX_BUDGET_STATE_BYTES`, then captures one canonical built-in snapshot before
schema or accounting validation. Validation never traverses the loader's live
mapping. Mapping, list, and scalar subclasses supplied by an in-process caller
cannot provide a second iterator view or invoke copy, rendering, length, or
string-normalization hooks.

The ledger continues to use a mutable local dictionary while constructing one
atomic transition. That dictionary is not retained or published directly.
Immediately before publication, Defiant captures and validates a new detached
snapshot and gives only that finalized observation to the bounded JSON writer.
A refused capture or write leaves the previous durable bytes unchanged.

## Accounting input ownership

Request ids, action ids, completion evidence ids, grant notes, reconciliation
outcomes, operator identities, notes, and authorization evidence identifiers
are normalized to exact built-in strings before accounting comparisons.
Authorization reconciliation attestations are captured recursively before they
enter an idempotency check or durable marker. Later caller or result-projection
mutation cannot alter the persisted ledger.

The accounting rules do not change. `succeeded` and `failed` uncertain
executions charge the full durable exposure when actual cost is unknown. Only
an explicit `not_executed` outcome releases a live reservation. Conflicting
live and terminal state still fails closed.

## Read-only consumers

Command Core derives budget summary and estimate drift from one validated
ledger observation. The cross-store state auditor consumes the ledger's
validated snapshot instead of validating and then rereading raw JSON. Both
remain read-only and attempt no repair.

Command Core schema `0.72.0` publishes only the static `budget_state_bytes`
ceiling and `validated_budget_ledger_snapshot: true` posture alongside the
existing sanitized aggregates. Command Center renders those static facts but
receives no reservation, reconciliation, note, attestation, or mutation
surface.

This control does not discover whether an external side effect occurred,
refund uncertain exposure, make a privileged host untrusted, or turn Python
into an operating-system sandbox. Deployment quotas remain necessary because
the 64 MiB ceiling is per complete state capture, not a process-wide work
budget.
