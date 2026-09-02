# Completed authority-publication checkpoint verification

v0.76 verifies the exact per-store commitments retained by a stable completed
authority-publication checkpoint. This closes the interval where a corrupted
commitment could remain latent while the aggregate manifest still matched the
durable stores, then influence a later mixed-generation recovery comparison.

## Stable verification

Doctor and Command Core reconstruct the complete bounded manifest and all seven
per-store commitments from the same validated durable observations. When a
completed `0.3.0` checkpoint has retained commitments, each value must match:

- state-storage assurance;
- control-plane isolation;
- workspace-root integrity;
- evidence-witness policy;
- optional runtime-artifact assurance or committed absence;
- optional launch-envelope assurance or committed absence; and
- evidence-head authority mode and schema.

A mismatch is critical as
`authority_publication_checkpoint_store_mismatch`, makes Command Core
non-authoritative, and identifies only the sanitized store name. Individual
hashes and raw authority observations are not projected.

## Owning-runtime gate

Before reusing a completed checkpoint or preparing the next generation, the
owning runtime performs the same reconstruction under its authority
transaction. A retained commitment mismatch is refused before an active intent
or dependent target store can be written. Aggregate-manifest verification
remains independent and is still required.

Legacy `0.1.0` and `0.2.0` checkpoints have no per-store commitments. They
remain explicitly `legacy_unavailable`, continue to require aggregate-manifest
verification, and receive commitments only after a successful matching
owning-runtime startup. Read-only inspection never performs that migration.

## Read-only boundary and limits

Command Center displays only the existing sanitized verification and
commitment posture. It cannot accept, repair, migrate, prepare, replay, or
complete publication state.

These are local unsigned commitments. They detect inconsistent local
corruption but do not defeat a privileged actor that can replace the harness,
checkpoint, profile, and every dependent store consistently. That threat still
requires immutable deployment or an off-box witness.
