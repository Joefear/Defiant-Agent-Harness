# Crash-safe authority publication

v0.71 coordinates startup publication of profile-bound authority observations.
The active authority profile, state-storage assurance, control-plane isolation,
workspace-root integrity, evidence-witness policy, optional runtime-artifact and
launch-envelope assurances, and evidence-head profile binding no longer rely on
an unrecorded sequence of independent atomic writes.

## Durable protocol

Before activating a new authority-profile generation, the owning runtime
previews the exact candidate without mutating profile state. It builds a
sanitized manifest of every dependent authority observation and writes
`authority_publication.json` with:

- the exact target profile hash and generation;
- a SHA-256 hash of the complete bounded manifest;
- the preparation time; and
- the last completed checkpoint, when one exists.

Only then may profile activation and dependent-store publication begin. After
the evidence head is bound, the harness is constructed, and deterministic
startup recovery has completed, the active intent is atomically replaced by a
completed checkpoint. The state document and canonical manifest each have an
independent 64 KiB ceiling. Reads, validation, comparison, and writes use one
detached exact built-in snapshot under those same ceilings.

## Restart rules

An active intent means startup was interrupted. A restart may replay only when
its profile hash, generation, and complete manifest hash match exactly. A
different candidate is refused without changing the prepared state. Partial
old-generation observations can then be advanced by the exact authorized
publication; target-generation observations must still agree with their own
strict conflict rules.

After completion, a same-generation startup first verifies every required
dependent store. Missing, invalid, profile-mismatched, or authority-mismatched
state is treated as possible tampering and is refused rather than overwritten.
A deliberately staged authority-profile transition may prepare the next
generation while retaining the prior completed checkpoint until the new one
finishes.

The protocol does not replay an external tool, infer an execution result, or
weaken approval and budget reconciliation. It coordinates only sanitized
startup authority publication.

## Read-only visibility

Doctor and Command Core project `not_recorded`, `recovery_required`, `complete`,
or `invalid` state with only profile/generation, manifest hash, verification,
and timestamps. An active exact-replay intent is a warning-level recovery
condition; malformed state or disagreement with the active profile is
critical. Command Center displays that projection and remains strictly
read-only: it has no prepare, replay, complete, repair, acceptance, rotation,
approval, execution, or mutation endpoint.

v0.72 additionally recomputes a completed checkpoint's manifest from the
current durable dependent observations. See
`authority_publication_manifest_verification.md`.

## Limits

This is a local crash-recovery protocol, not a distributed transaction or
rollback witness. It cannot defeat a privileged host that replaces code and
all state consistently, prove durable-media behavior beyond the filesystem's
atomic-write guarantees, or make in-process Python untrusted. External signed
evidence witnessing and deployment isolation remain separate controls.
