# Active authority-publication checkpoint commitments

v0.75 retains the exact sanitized per-store commitments from each successful
authority publication in its completed checkpoint. This closes the remaining
mixed-generation interval where v0.74 could prove target-generation values but
could identify a dependency still on the prior profile only by that profile
binding.

## Completed commitment set

On successful completion, the owning runtime copies the prepared commitments
for all seven authority projections into the completed checkpoint:

- state-storage assurance;
- control-plane isolation;
- workspace-root integrity;
- evidence-witness policy;
- optional runtime-artifact assurance;
- optional launch-envelope assurance; and
- evidence-head authority mode and schema.

Required commitments remain exact SHA-256 identifiers. Optional absence remains
an explicit null commitment. Individual hashes and raw authority projections
are never included in Doctor, Command Core, or Command Center output.

## Mixed-generation verification

During an interrupted profile rotation, every dependency already bound to the
target profile is checked against the active intent as in v0.74. Every
dependency still bound to the completed checkpoint profile is now also checked
against that checkpoint's exact commitment. A structurally valid substitution
on the prior side is critical as
`authority_publication_active_checkpoint_store_mismatch` and makes Command Core
non-authoritative.

The diagnostic projection exposes only `recorded`, `legacy_unavailable`, or
`not_applicable` checkpoint-commitment posture. Inspection remains byte-for-byte
read-only and cannot prepare, replay, complete, repair, accept, or migrate a
publication.

## Compatibility and migration

Publication schema `0.3.0` stores completed checkpoint commitments. Existing
`0.1.0` and `0.2.0` documents remain readable. A legacy completed checkpoint is
shown as `legacy_unavailable`; its aggregate completed manifest is still
reconstructed and verified. A successful matching owning-runtime startup writes
a new `0.3.0` checkpoint with exact commitments. An active legacy `0.1.0` intent
is likewise upgraded only after exact replay and final manifest verification.

## Limits

These are local unsigned commitments. They detect inconsistent local
substitution during crash recovery, but do not defeat consistent privileged
replacement of the harness, publication state, profile transition, and every
dependent store. Immutable deployment and off-box witnessing remain separate
controls.
