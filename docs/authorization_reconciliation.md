# Approval-free authorization reconciliation

v0.12 closes the recovery gap for a sealed execution authorization that has no
approval record and no terminal evidence. This can occur when a directly
allowed tool call is authorized and the process stops before Defiant can record
whether the tool succeeded, failed, or was never dispatched.

Defiant never replays the tool and never infers success from silence. The
operator must inspect the external system and provide:

- the sealed authorization evidence record id;
- exactly one outcome: `succeeded`, `failed`, or `not_executed`;
- a non-empty operator identity; and
- a non-empty investigation note.

Run:

```bash
dah --workdir .dah reconcile-authorization evd_... \
  --outcome failed \
  --operator operator-7 \
  --note "provider accepted the request but returned no result"
```

Use `not_executed` only with positive evidence that dispatch did not occur. It
is the only outcome that releases a live reservation.

## Durable authority and crash behavior

The command binds the operator statement to the sealed authorization record id
and record hash, action id, request id, authorization hash, outcome, identity,
note, and time. In signed mode it uses a distinct Ed25519 domain and purpose;
an approval decision or approval reconciliation signature cannot be replayed
for this path.

Before budget or terminal evidence changes, the harness prepares an
`authorization_reconcile` operation in `operation_journal.json`. Recovery
revalidates the evidence chain and operator signature, applies or recognizes
the exact budget marker, appends or recognizes the exact terminal evidence,
and then completes the journal. Exact retries are idempotent. A changed
outcome, identity, note, authority record, signature, estimate, or terminal
record fails closed.

## Conservative budget disposition

`succeeded` and `failed` charge the durable reserved estimate when the actual
cost is unknown. `not_executed` releases a live reservation. If a prior debit
already records a known cost, reconciliation preserves that debit and terminal
evidence reports the durable debit rather than charging or counting it twice.
The budget marker retains the sealed authority binding and any operator
attestation for later integrity verification.

## Boundaries and visibility

This command is only for records whose sealed policy decision was `allow`. If
the evidence says `approval_required`, a missing approval record is corruption,
not permission to reclassify the action. If an approval owns the action, use
`dah reconcile <approval_id>` instead. Neither path discovers the external
truth automatically.

`dah doctor`, Command Core, and Command Center expose only the authorization
record id, request id, action id, tool name, timestamp, and recovery state.
Targets, payloads, notes, signatures, and raw results remain excluded. Command
Center remains strictly read-only and has no reconcile, replay, delete, or
force-complete endpoint.

An active `execution_complete` journal is different: the tool result is already
known and v0.13 will finish its exact local completion without operator input.
See `known_result_recovery.md`.
