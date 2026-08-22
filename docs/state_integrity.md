# State integrity auditing

v0.7 adds a read-only, cross-store audit over `evidence.jsonl`,
`approvals.json`, and `budget.json`. v0.10 extends it to durable
`operator_trust.json`, v0.11 adds the deterministic local
`operation_journal.json`, and v0.12 validates approval-free authorization
reconciliation across evidence and budget markers. v0.13 distinguishes a
journaled known result from a genuinely uncertain execution. The audit
in v0.15 also validates `authority_profile.json`, its generation chain,
pending rotation, optional operator signature, and configured candidate hash.
In v0.16 it also validates `runtime_artifacts.json`, its strict schema, and its
binding to the active authority profile. v0.17 adds the strict sanitized
`launch_envelope.json` observation and its profile binding. The audit
distinguishes expected crash recovery states from contradictions that make
further authority unsafe.
v0.18 validates the state root and every known durable file before interpreting
store contents, then checks `state_storage.json` against both the current root
identity and active authority profile.
v0.19 validates `control_plane_isolation.json`, its strict sanitized contract,
and its binding to the active authority profile.
v0.20 validates `workspace_integrity.json`, its profile binding, and, when the
caller supplies the configured workspace root, its current filesystem identity.
v0.21 validates `evidence_head.json`, its active-profile binding, and the exact
retained evidence prefix represented by its record count and head hash.
v0.22 validates the local `evidence_witness_policy.json` posture and, when
required, a caller-supplied external signed witness and trust keys against the
state-root identity, authority-profile history, and live evidence chain.

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

The command emits schema `defiant.state_integrity` version `0.13.0` and exits
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
- the profile-bound evidence checkpoint, distinguishing a provable forward
  append crash from critical tail rollback or chain divergence;
- the profile-bound external-witness policy and, in required mode, its exact
  trusted key set, signature, deployment/profile bindings, and witnessed prefix;
- approval structure, ids, active-action uniqueness, operator identity for
  approved states, and durable action/request bindings;
- when trust pins are configured, signed operator purpose, outcome, identity,
  note, key assignment, signature, and approval-authority binding;
- durable signed-mode enrollment, canonical binding hashes, contiguous
  generations, strictly additive mappings, prior-generation signers, and every
  trust-transition signature;
- durable authority-profile enrollment, contiguous old/new generations and
  hashes, bounded timestamps, pending-rotation binding, optional trusted
  signature, and candidate match when the caller supplies a runtime hash;
- sanitized runtime-artifact assurance structure and exact binding to the
  active authority-profile hash;
- sanitized launch-envelope structure, bounded counts and hashes, and exact
  binding to the active authority-profile hash;
- sanitized workspace-root structure, active-profile binding, and live root
  identity when the configured root is supplied;
- canonical state-root structure and identity, regular single-link state files,
  private POSIX ownership/modes, orphan atomic temporaries, and exact storage
  observation binding to the active authority-profile hash;
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

A missing or replaced configured workspace root is critical. Read-only callers
without a workspace argument report the durable observation as `profile_bound`;
they do not create a directory or claim a live check. Use `--workspace-root`
with Doctor and Command surfaces when live verification is required.

A valid chain extending its checkpoint is `recovery_required`; the next owning
authority startup advances the checkpoint without replaying a tool. A chain
behind or divergent from the checkpoint is `unsafe` and is never repaired.
Read-only diagnostics do not create, advance, or rebind the checkpoint.

An enrolled external witness policy without its caller-supplied witness and
trust keys is `unsafe`. An exact or forward-extending trusted witness is safe; a
shorter or divergent chain is critical. A missing local policy observation on
an existing profile is a migration warning, and only owning authority startup
may record it. Diagnostics never copy or mutate external witness material.

The audit is a local point-in-time consistency check, not a database
transaction, repair engine, or OS sandbox. A durable trust chain without
external pins is visible but cannot be authenticated and is therefore unsafe.
v0.14 enforces one authority-bearing writer per state directory with an
OS-released transaction lock; per-file exclusive locks remain the final write
guard. The persistent `authority.lock` file is not a stale-lock signal because
ownership lives in the operating system. Store `.lock` files retain the
conservative operator-resolution rule. The directory must remain
access-controlled. Restore corrupt state from a known-good copy or investigate
it offline; do not edit a live store merely to clear an alert.
