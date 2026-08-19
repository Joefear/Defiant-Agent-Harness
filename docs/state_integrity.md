# State integrity auditing

v0.7 adds a read-only, cross-store audit over `evidence.jsonl`,
`approvals.json`, and `budget.json`. The audit distinguishes expected crash
recovery states from contradictions that make further authority unsafe.

Run it without initializing or modifying the state directory:

```bash
dah --workdir .dah doctor
```

The command emits schema `defiant.state_integrity` version `0.1.0` and exits
non-zero only when `safe_to_execute` is false. The report contains store status,
counts, sanitized issue codes, and operational identifiers. It never includes
targets, payload previews, reconciliation notes, or raw tool output.

## Health states

- `healthy`: all readable stores and cross-store bindings are consistent;
- `recovery_required`: state is structurally safe, but an execution outcome or
  durable snapshot requires operator attention;
- `unsafe`: at least one critical contradiction exists. Authority-bearing
  harness operations refuse to proceed.

An approval in `executing`, an in-progress reconciliation, or a live
reservation backed by a sealed external-execution authorization is a recovery
condition, not corruption. Defiant still refuses automatic replay. Use the
v0.6 operator reconciliation procedure where an approval id exists.

## Critical invariants

The auditor verifies:

- the complete evidence hash chain, record schema, and record-id uniqueness;
- approval structure, ids, active-action uniqueness, operator identity for
  approved states, and durable action/request bindings;
- budget structure and entry shape;
- every live reservation belongs to an active approval or sealed unfinished
  authorization;
- reservation request and amount match the durable approval;
- terminal approvals do not retain live reservations;
- consumed approvals reference matching terminal evidence;
- budget reconciliation markers match immutable operator reconciliation input;
- a reconciled action cannot simultaneously retain a live reservation; and
- store lock files stop new authority until an operator confirms no writer is
  alive and resolves the lock.

Malformed or unreadable stores are reported rather than repaired. Command Core
and Command Center remain available as read-only diagnostic surfaces, mark the
snapshot non-authoritative, and withhold projections from an invalid store.

## Execution gate

The harness audits state before a new action, approval resume, external
completion, expiry reconciliation, or operator execution reconciliation. A
critical issue raises `StateIntegrityError` before any new evidence, approval,
budget, or tool mutation occurs. Diagnostic commands do not construct a
harness and remain usable.

The audit is a local point-in-time consistency check, not a database
transaction, signature, repair engine, or OS sandbox. Defiant still assumes one
logical writer per state directory, uses per-file exclusive locks, and requires
the directory to be access-controlled. Restore corrupt state from a known-good
copy or investigate it offline; do not edit a live store merely to clear an
alert.
