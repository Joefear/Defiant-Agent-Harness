# State integrity auditing

v0.7 adds a read-only, cross-store audit over `evidence.jsonl`,
`approvals.json`, and `budget.json`. v0.10 extends it to durable
`operator_trust.json`, v0.11 adds the deterministic local
`operation_journal.json`, and v0.12 validates approval-free authorization
reconciliation across evidence and budget markers. v0.13 distinguishes a
journaled known result from a genuinely uncertain execution. The audit
distinguishes expected crash recovery states from contradictions that make
further authority unsafe.

Run it without initializing or modifying the state directory:

```bash
dah --workdir .dah doctor
```

For signed mode, add repeatable
`--trusted-operator-key IDENTITY=PUBLIC_KEY.pem` options to audit operator
decision and reconciliation attestations under the same policy used by the
runtime, as well as the durable trust-generation chain. Omitting them after
enrollment does not prevent this read-only command from starting; it reports
`operator_trust_unverified`, marks state unsafe, and makes no changes.

The command emits schema `defiant.state_integrity` version `0.5.0` and exits
non-zero only when `safe_to_execute` is false. The report contains store status,
counts, sanitized issue codes, and operational identifiers. It never includes
targets, payload previews, reconciliation notes, or raw tool output.

## Health states

- `healthy`: all readable stores and cross-store bindings are consistent;
- `recovery_required`: state is structurally safe, but deterministic local
  completion or an uncertain execution outcome remains outstanding;
- `unsafe`: at least one critical contradiction exists. Authority-bearing
  harness operations refuse to proceed.

An approval in `executing`, an in-progress reconciliation, a valid active local
operation journal, or a live reservation backed by a sealed external-execution
authorization is a recovery condition, not corruption. Deterministic journaled
local work is completed before the authority gate. Defiant still refuses
automatic external replay. A journaled v0.13 known result completes locally;
otherwise use the v0.6 operator reconciliation procedure where an approval id
exists, or the v0.12 authorization procedure where only sealed authorization
evidence exists.

## Critical invariants

The auditor verifies:

- the complete evidence hash chain, record schema, and record-id uniqueness;
- approval structure, ids, active-action uniqueness, operator identity for
  approved states, and durable action/request bindings;
- when trust pins are configured, signed operator purpose, outcome, identity,
  note, key assignment, signature, and approval-authority binding;
- durable signed-mode enrollment, canonical binding hashes, contiguous
  generations, strictly additive mappings, prior-generation signers, and every
  trust-transition signature;
- journal schema, canonical payload hash, operation-specific payload shape,
  exact approval/reservation/evidence bindings, and unsealed prepared evidence;
- known-result completion authority, exact settlement, terminal evidence,
  durable settlement-to-evidence markers that expose tail truncation, and
  optional approval-consumption bindings;
- every approval-free reconciliation marker binds the sealed authorization,
  durable estimate, explicit operator input, optional signature, and matching
  terminal evidence;
- a sealed `approval_required` authorization cannot be reclassified as
  approval-free when its approval record is absent;
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

The harness first recovers any valid prepared local operation, then audits state
before a new action, approval resume, external completion, expiry
reconciliation, or operator execution reconciliation. A critical issue raises
`StateIntegrityError` before any new authority-bearing work occurs. Malformed,
tampered, conflicting, or locked journal state cannot be recovered and remains
critical. Diagnostic commands do not construct a harness and remain usable
without completing or repairing the journal.

The audit is a local point-in-time consistency check, not a database
transaction, repair engine, or OS sandbox. A durable trust chain without
external pins is visible but cannot be authenticated and is therefore unsafe.
Defiant still assumes one
logical writer per state directory, uses per-file exclusive locks, and requires
the directory to be access-controlled. Restore corrupt state from a known-good
copy or investigate it offline; do not edit a live store merely to clear an
alert.
