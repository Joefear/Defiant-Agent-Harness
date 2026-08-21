# Approval execution reconciliation

Defiant writes `executing` before a governed action can run. If the process
crashes in that interval, the external side effect may have happened even when
no terminal evidence was written. Defiant therefore refuses automatic replay
and marks the approval as requiring operator reconciliation.

## Operator procedure

1. Stop or positively rule out every executor that could still be processing
   the action. Reconciliation is not safe while the original worker can finish.
2. Inspect the approval with `dah pending` and inspect the relevant external
   provider, target system, logs, receipts, and existing evidence.
3. Choose exactly one outcome:

   - `succeeded`: the action completed.
   - `failed`: the action was attempted and ended in failure, or its cost may
     have been incurred without the intended effect completing.
   - `not_executed`: positive evidence shows the action was never dispatched.

4. Record the assertion with an explicit operator identity and useful note:

   ```bash
   dah --workdir .dah reconcile apr_... \
     --outcome succeeded \
     --operator operator-7 \
     --note "provider message id msg_123 confirms delivery"
   ```

Do not use `not_executed` merely because a success receipt is absent. It is the
only outcome that releases a live reservation and therefore requires positive
evidence that dispatch did not occur.

## Budget disposition

When a live reservation exists, `succeeded` and `failed` debit the full reserved
estimate because actual cost is unknowable after the crash. `not_executed`
releases it. If an earlier step already wrote a debit, reconciliation preserves
that debit. If the reservation is unexpectedly absent and no debit exists, an
executed outcome charges the durable approval estimate rather than creating
unearned budget headroom.

The ledger records a per-action reconciliation marker. An exact retry returns
the same disposition and cannot double charge. A different outcome, operator,
note, request, or estimate fails closed.

## Crash behavior and evidence

The approval first stores immutable reconciliation intent. Budget resolution is
then atomically marked, terminal evidence is appended, and the approval is
finally consumed. If the process dies between those steps, repeat the exact same
command. Defiant detects completed steps and finishes the remainder without
calling the tool.

If terminal evidence was written before the original crash, the asserted
outcome must agree with it. Reconciliation reuses that record rather than
creating a duplicate. New reconciliation evidence includes the outcome,
operator identity, note, timestamp, and conservative charged cost.

Command Core and the local Command Center show which approvals require
reconciliation. Those surfaces remain read-only. They intentionally exclude the
operator note and provide no reconcile button or mutation endpoint.

## Security limits

v0.9 can bind the operator identity, outcome, note, approval authority, and
timestamp to an Ed25519 key explicitly pinned to that identity. A runtime
configured with operator trust pins requires this signature before touching
budget or evidence. See `operator_identity.md`. Reconciliation still records
what the operator concluded; it cannot verify the external system or prove that
conclusion correct. Protect the state directory, retain provider receipts, and
treat reconciliation as a privileged operational procedure.
