# Active authority-publication store commitments

v0.74 binds every target-generation authority observation into the durable
publication intent before profile activation. This closes the interval where a
read-only audit could classify partial replay but could not distinguish the
prepared target value from a different, structurally valid value carrying the
same target profile hash.

## Commitment set

The owning runtime captures the bounded sanitized manifest once and records an
exact SHA-256 commitment for each of its seven store projections:

- state-storage assurance;
- control-plane isolation;
- workspace-root integrity;
- evidence-witness policy;
- optional runtime-artifact assurance;
- optional launch-envelope assurance; and
- evidence-head authority mode and schema.

An absent optional store is committed as absent. Required commitments cannot be
null, unknown keys are refused, and every hash is validated as a canonical
SHA-256 identifier. The complete manifest and publication state retain their
independent 64 KiB ceilings.

## Partial replay verification

While an active publication is `applying`, Doctor and Command Core inspect each
dependency already bound to the target profile. Its exact sanitized authority
projection must hash to the commitment prepared before activation. A mismatch
is critical as `authority_publication_active_store_mismatch`; it is not deferred
until the evidence head advances or the complete manifest can be reconstructed.
Prior-generation dependencies remain valid only where the v0.73 phase rules
permit exact mixed-generation recovery.

v0.75 also retains completed per-store commitments and verifies dependencies
that remain on the checkpoint profile. See
`active_authority_publication_checkpoint_commitments.md`.

The projection exposes only `recorded`, `legacy_unavailable`, `not_applicable`,
or `invalid` commitment posture. It does not expose individual store hashes or
raw authority values. Command Center renders that posture and remains strictly
read-only.

## Compatibility and recovery

Publication state schema `0.2.0` writes store commitments for every new intent.
An active `0.1.0` intent left by a v0.73 crash remains readable and may be
replayed only by the owning runtime when its profile, generation, and complete
manifest hash still match exactly. It is projected as `legacy_unavailable` and
is migrated to a `0.2.0` completed checkpoint after successful recovery.

## Limits

These commitments improve local crash-state diagnosis; they are not signatures
or external rollback witnesses. A privileged attacker that can replace the
harness, publication intent, profile transition, and all dependent state
consistently remains outside this local assurance boundary. Immutable
deployment and off-box witnessing remain separate controls.
