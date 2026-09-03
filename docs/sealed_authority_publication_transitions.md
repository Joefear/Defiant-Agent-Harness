# Sealed authority-publication transitions

v0.78 binds each authority-publication intent to its predecessor and each
completed checkpoint to the intent that produced it. This closes the remaining
gap where two records could each have a valid semantic seal but belong to
different publication histories.

## Transition contract

Schema `0.5.0` adds these sealed relationships:

- an active intent carries `prior_checkpoint_hash`, set to `GENESIS` for the
  first publication or to the exact retained completed-checkpoint record hash;
- a completed checkpoint retains the originating intent's `prepared_at`,
  `prior_checkpoint_hash`, and `intent_record_hash`; and
- the checkpoint's own record seal covers all three values as well as its
  existing semantic fields and completion time.

Parsing validates the checkpoint's outer record seal before validating the
reconstructed originating-intent seal. State validation then requires a current
active intent's predecessor to match the exact retained checkpoint. A
well-formed and independently sealed record from another transition is invalid,
not recoverable.

## Crash recovery and legacy state

Prepare writes the new active link before profile activation. Complete retains
the exact originating-intent link in the replacement checkpoint. Both remain
atomic, bounded, and idempotent under the existing publication lock.

Schemas `0.1.0` through `0.4.0` remain readable. Their absent historical links
are reported as `legacy_unavailable`; read-only audit does not infer, fabricate,
or migrate them. A matching owning-runtime startup may republish a stable legacy
checkpoint through a current intent, producing verified links. If startup is
already recovering a legacy active intent, completion preserves unavailable
origin linkage in the current checkpoint because the missing predecessor cannot
be proven retroactively.

## Read-only visibility

State Integrity projects `verified`, `legacy_unavailable`, `not_applicable`, or
`invalid` for both the intent-to-checkpoint and checkpoint-to-intent links.
Command Core carries those sanitized values and a static capability flag.
Command Center displays the posture but receives no raw linkage hashes,
authority inputs, manifests, commitments, or state paths. It has no prepare,
link, replay, complete, repair, acceptance, migration, approval, execution, or
other mutation endpoint.

## Security boundary

Transition seals detect local record splicing and inconsistent partial
replacement. They are not signatures, trusted time, distributed consensus, or
an external rollback witness. A privileged actor able to replace the harness,
all records, links, and dependent state consistently remains outside this local
control; immutable deployment and off-box signed witnessing are separate
controls.

v0.79 additionally ratchets completed transition seals across an independently
atomic compact continuity anchor. See `authority_publication_continuity.md`.
