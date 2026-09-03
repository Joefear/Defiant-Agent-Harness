# Validated filesystem-authority state snapshots

Defiant v0.70 closes the durable ownership and recoverability gap across the
two remaining filesystem-authority observations: control-plane isolation and
workspace-root integrity.

## One observation per authority root

`ControlPlaneIsolationState.from_dict()` and
`WorkspaceIntegrityState.from_dict()` each capture their complete document
under the fixed authority canonical profile and an independent 64 KiB ceiling
before field validation.

The isolation observation binds the profile, isolation contract, governed
workspace, protected-root count, workspace/state relationship, and verification
time. The workspace observation binds the profile, workspace-root identity
hash, assurance mode, and verification time. Each validator consumes only its
own detached exact built-in observation.

Capture reads built-in container storage directly, normalizes accepted scalar
subclasses, detects container drift, and refuses cyclic, unsupported, or
oversized values with sanitized errors. Source mutation after capture cannot
change retained state, integrity projections, conflict checks, or publication.

## Candidate ownership and crash-safe publication

Each store captures the supplied profile hash and sanitized assurance fields
into one validated candidate before acquiring the authority lock. Existing
state comparison and eventual publication consume the same candidate, so later
caller mutation cannot substitute a different workspace, root, relationship,
contract, or mode.

Immediately before replacement, each writer projects and revalidates its state
again and passes only that detached built-in document to
`atomic_write_json()`. Canonical capture, recovery reads from the opened file,
and atomic publication share the same explicit 64 KiB ceiling for each store.
Invalid or oversized publication fails before replacement and preserves the
prior recoverable observation.

The durable schemas remain `defiant.control_plane_isolation` version `0.1.0`
and `defiant.workspace_integrity` version `0.1.0`.

## Combined authority boundary

These files are sanitized assurance records, not path allowlists or repair
instructions. Live startup and dispatch still verify the canonical workspace
root, filesystem identity, link/reparse posture, protected state roots, and
target containment. Cross-store integrity continues to bind both observations
to the same enrolled authority profile and fail closed on absence, mismatch, or
tampering.

Command Core schema `0.72.0` reports independent
`control_plane_isolation_state_bytes` and `workspace_integrity_state_bytes`
ceilings plus `validated_control_plane_isolation_state_snapshot: true` and
`validated_workspace_integrity_state_snapshot: true`. Command Center renders
only those static postures and the existing sanitized projections. It gains no
path, protected-root, profile-rotation, containment, relocation, repair, or
mutation route.

This release adds no DKE, Spartan, remote Command, or writable Command Center
feature.
