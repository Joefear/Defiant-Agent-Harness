# Read-only active authority-publication verification

v0.73 classifies an interrupted authority publication from durable state instead
of treating every syntactically valid intent as the same recovery condition.
Doctor and Command Core perform this classification without replaying or
changing the publication.

v0.74 adds exact per-store target commitments so an already-written
target-generation dependency is also checked for value substitution during the
`applying` phase. See `active_authority_publication_commitments.md`.

v0.75 retains exact commitments in completed checkpoints so dependencies still
bound to the prior checkpoint profile are checked during the same phase. See
`active_authority_publication_checkpoint_commitments.md`.

## Recovery phases

An active intent has one of three valid read-only phases:

- `prepared`: the target is durably recorded, but the profile is not activated
  yet. During a rotation, the current profile, its pending transition, the prior
  completed checkpoint, and all prior dependent observations must still agree.
- `applying`: the target profile is active, but the evidence-head binding has
  not advanced. Required stores must remain present after a rotation, and every
  observed dependency must bind either the exact prior profile or the exact
  target profile.
- `ready_to_complete`: the evidence head binds the target profile and the
  manifest reconstructed from every durable dependency exactly matches the
  active intent.

The phase is recovery information, not authority. Only an owning runtime with
the exact configured profile and manifest may replay and complete the intent.

## Contradictions

The audit is critical when an active intent is unrelated to the current or
prior profile, does not match the staged transition, loses a required prior
dependency, observes a third profile generation, or reaches the final evidence
head with a different manifest. Expected old-profile observations during an
exact partial rotation are labeled `publication_recovery`; unrelated profile
mismatches remain critical.

## Read-only boundary

Doctor, Command Core, and Command Center expose only the phase, generation,
profile hash, manifest hash, and sanitized issue metadata already present in
the integrity report. They cannot prepare, activate, replay, repair, accept, or
complete a publication. Adversarial tests compare every durable byte before and
after inspection.

## Limits

Phase verification proves only the local state-machine relationships visible at
one point in time. It is not a distributed transaction, an external rollback
witness, or a defense against privileged replacement of the harness and all
state. The owning runtime remains responsible for exact replay and final live
checks.
