# Sealed approval record state

An approval is retained authority, not merely queue metadata. It binds an
operator decision to one action, request, policy result, optional budget
reservation, execution lifecycle, and any signed operator statements. If those
values change after validation, execution or crash reconciliation could rely on
authority the operator never reviewed.

v0.62 makes each `PendingApproval` an immutable ownership boundary.

## One bounded observation

Public construction and `PendingApproval.from_dict()` first capture one exact
canonical built-in snapshot under the approval-store ceiling. Mapping, list,
and scalar subclasses cannot supply a second view, invoke copy hooks, or change
values between field checks. Rejected input produces a sanitized
`ApprovalError` without rendering attacker-controlled values.

Held action, request, and decision documents are reconstructed through their
normal governed contracts from that observation. The approval binds their
request and action identities, tool and target, payload and authorization
hashes, approval scope, reason, and policy ids. Stale action hashes,
cross-request substitution, unknown fields, malformed attestations, and a
durable map key that differs from the retained approval id fail closed.

## Sealed retention and lifecycle transitions

Policy ids, action/request/decision snapshots, and decision/reconciliation
attestations are recursively frozen in private storage. Public properties and
`to_dict()` return fresh built-in projections. Mutating a supplied object or a
returned projection cannot change the retained record.

The record itself is frozen. Expiry, decision, begin-execution, consumption,
and reconciliation create a new fully validated record and atomically publish
the replacement. Earlier references keep their earlier state. Existing
idempotency and explicit operator-input requirements remain unchanged.

## Durable compatibility and resource symmetry

`approvals.json` keeps its established JSON keys and 64 MiB aggregate durable
allowance. v0.62 names that allowance `MAX_APPROVAL_STATE_BYTES` and applies it
to canonical capture, strict recovery reads, and atomic publication. A writer
cannot create a file its reader would refuse, and a refused update leaves the
previous bytes intact.

Older records that omit newer optional execution and reconciliation fields are
loaded with their conservative empty defaults. Foundational identity,
authority, creation-time, and approval-id fields remain required; silently
inventing them during recovery would change the durable story.

## Command boundary

Command Core schema `0.64.0` publishes only the static
`approval_state_bytes` ceiling and `sealed_approval_record_state: true` build
posture alongside the existing sanitized approval and
reconciliation-required projections. Command Center renders those facts but
remains strictly read-only. It receives no target, payload preview, held
snapshot, operator note, signature, or mutation endpoint.

This control does not infer an unknown external outcome, replay a stranded
action, optimistically release its reservation, or make Python an operating-
system sandbox. The explicit crash-safe reconciliation workflow remains the
only authority path for an approval stranded in `executing`.
