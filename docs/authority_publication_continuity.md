# Authority-publication continuity

v0.79 adds a compact rollback detector for authority-publication checkpoints.
It deliberately avoids an unbounded startup history while preserving a durable
cross-store ratchet.

## Contract

Publication schema `0.6.0` carries a non-negative `continuity_sequence`.
`authority_publication_continuity.json` schema `0.1.0` independently seals:

- the positive monotonic sequence;
- the exact completed-checkpoint record hash;
- that checkpoint's exact predecessor hash or `GENESIS`; and
- the anchor timestamp.

The anchor has the same fixed 64 KiB validation, read, canonical-snapshot, and
atomic-publication ceiling. It is a known protected state file and its lock is
part of read-only integrity inspection.

## Crash protocol

Completion atomically publishes the new checkpoint and incremented sequence
before atomically advancing the continuity anchor. If the process stops between
those writes, read-only audit reports `recovery_required` only when the new
checkpoint names the current anchor and advances exactly one step. The owning
runtime advances the anchor before preparing another publication. No external
tool is replayed.

The first enrolled checkpoint may recover a missing anchor at sequence one.
After that, deletion is critical rather than treated as re-enrollment. An
anchor ahead of publication is rollback; equal sequences with different
checkpoint seals, skipped sequences, an orphan anchor, and invalid anchor seals
are critical divergence.

## Legacy migration

Publication schemas `0.1.0` through `0.5.0` remain readable when no continuity
anchor exists. Read-only audit reports `legacy_unavailable` and never creates
one. A successful matching owning-runtime startup establishes the first anchor
from a verifiably linked checkpoint, or completes one current linked transition
before enrollment when older history cannot be proven. Missing history is not
fabricated.

## Read-only visibility and limits

State Integrity, Command Core, and Command Center expose only continuity state
and sequence. Raw checkpoint, predecessor, continuity-record, and record hashes
are withheld. Command Center has no advancement, recovery, enrollment, reset,
repair, acceptance, replay, completion, approval, execution, or other mutation
endpoint.

This ratchet detects inconsistent rollback or replacement across the two local
files. It is not an append-only external log, signature, trusted clock, or
privileged-host rollback witness. An actor able to restore the publication file
and continuity anchor together to a matching older pair remains outside this
local control; off-box signed witnessing is the appropriate boundary for that
threat.
