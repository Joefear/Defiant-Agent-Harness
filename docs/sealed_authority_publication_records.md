# Sealed authority-publication records

v0.77 binds every new authority-publication intent and completed checkpoint to
one canonical semantic record hash. The seal closes the interval in which a
single structurally valid field substitution could survive parsing and appear
recoverable until a later profile, manifest, or store comparison.

## Record contract

Schema `0.4.0` hashes the record type plus the complete semantic payload:

- profile hash and generation;
- aggregate manifest hash;
- preparation or completion timestamp; and
- the exact commitment or committed absence for every publication store.

The record type separates an intent from a checkpoint even when the remaining
values happen to match. Parsing recomputes and compares the hash before the
record is returned to recovery, audit, or startup code. A mismatch makes the
publication state invalid and blocks authority-bearing work without rewriting
the file.

## Crash recovery and migration

New prepare and complete transitions write sealed records atomically under the
existing publication lock and byte ceiling. The owning runtime validates an
existing seal before idempotent replay, completion, checkpoint reuse, or
next-generation preparation.

Schemas `0.1.0`, `0.2.0`, and `0.3.0` remain readable. Their absent record seal
is projected as `legacy_unavailable`, not falsely described as verified.
Read-only inspection never migrates them. A successful matching owning-runtime
startup writes the current `0.4.0` checkpoint with a verified seal.

## Read-only visibility

State Integrity reports `verified`, `legacy_unavailable`, `not_applicable`, or
`invalid` posture for the intent and checkpoint. Command Core carries the same
sanitized projection and a static validation-capability flag. Command Center
may display those values but receives no raw record hashes, commitment hashes,
or authority inputs. It has no prepare, seal, replay, complete, repair, accept,
or migration endpoint.

## Security boundary

v0.78 extends the record seal across publication transitions: intents bind the
exact prior checkpoint and checkpoints bind their originating intent. See
`sealed_authority_publication_transitions.md`.

The seal detects inconsistent local corruption and partial substitution. It is
not a signature or external rollback witness. A privileged actor that can
replace the record, its hash, the harness, and all dependent state consistently
still requires immutable deployment or an off-box signed witness.
