# Crash-safe known-result recovery

v0.13 closes the local completion window after a tool has returned but before
Defiant has finished budget settlement, terminal evidence, and approval
consumption. At that point the tool outcome is known and must not be discarded,
guessed again, or routed to operator reconciliation after a process crash.

Immediately after the tool returns, the harness prepares an
`execution_complete` operation in `operation_journal.json`. The operation binds:

- the sealed authorization record id and hash;
- the action id, request id, authorization hash, and policy decision;
- the approval id when the execution was approval-backed;
- the exact reserved estimate and terminal cost;
- whether budget settlement is required; and
- the complete unsealed terminal evidence record.

The raw tool response is not stored in the journal. Terminal evidence retains
only its existing output hash and bounded summary contract.

## Recovery order

Authority startup verifies the complete evidence chain and the journal payload
before any recovery mutation. It then:

1. validates the sealed authorization and optional approval binding;
2. revalidates signed approval identity when signed mode is enrolled;
3. applies or recognizes the exact budget settlement;
4. appends or recognizes the exact terminal evidence;
5. consumes or recognizes the exact approval evidence reference; and
6. marks the journal inactive.

Every step is idempotent. A crash before settlement, after settlement, after
evidence, or after approval consumption can be retried without executing the
tool again, charging twice, or duplicating evidence. A different debit,
terminal record, approval reference, authority record, or journal payload fails
closed.

## Budget rule

When the adapter reports a positive cost, that exact cost is used. When a
non-dry-run tool returns without a cost but had a positive reserved estimate,
v0.13 settles at the conservative estimate. This applies to successful and
failed attempts because MCP and native hook results do not provide a standard,
trustworthy actual-cost field. Dry runs remain zero cost.

The terminal evidence cost and prepared post-settlement available balance are
bound into the journal. Recovery refuses a live reservation that already has a
prior debit, release, or reconciliation disposition.

Each known-result debit also retains the terminal evidence record id. The state
integrity auditor uses that durable cross-store marker to detect a missing,
truncated, duplicated, or mismatched terminal record after recovery completes.

## Operator and dashboard boundary

A valid `execution_complete` journal means the result is known and only local
completion remains. It is not an operator-reconciliation case. Doctor, Command
Core, and Command Center report deterministic recovery without putting the
action in the manual reconciliation count. Command Center remains strictly
read-only: it cannot replay, settle, consume, complete, delete, or clear the
journal.

The journal still cannot recover a result that was never returned or persisted.
If the process stops while the external outcome is genuinely unknown, the v0.6
approval reconciliation or v0.12 approval-free authorization reconciliation
procedure remains required.
