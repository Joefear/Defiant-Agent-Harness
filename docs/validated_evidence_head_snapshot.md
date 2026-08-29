# Validated evidence-head snapshot

v0.64 makes the profile-bound evidence-head checkpoint a bounded ownership and
publication boundary. The checkpoint remains a rollback detector for the
append-only evidence chain; this change hardens how its small durable JSON
state is observed, retained, and replaced.

## One accepted observation

`EvidenceHeadState.from_dict()` first captures one detached canonical tree
using built-in containers and scalars. Schema validation, profile binding,
record position, checkpoint hash, and timestamp validation all consume that
same observation. Mapping or string subclasses cannot substitute alternate
values through iteration, comparison, rendering, prefix, replacement, or copy
hooks after capture.

Direct `EvidenceHeadState` construction and public profile/head hash inputs are
normalized to exact built-in values before retention. The frozen state object
therefore cannot carry caller-defined scalar behavior into later comparison,
projection, or publication.

## Symmetric bounded I/O

The established 64 KiB checkpoint allowance is now
`MAX_EVIDENCE_HEAD_STATE_BYTES`. The same value governs:

- canonical in-process state capture;
- the descriptor-backed recovery read; and
- atomic JSON publication.

The reader no longer depends on a separate size stat followed by an
implicitly broader read. The writer receives only the validated built-in
projection and cannot successfully publish a checkpoint that the next restart
would reject solely for size. A rejected candidate leaves the prior checkpoint
bytes unchanged.

The evidence history itself remains append-only and is not constrained by this
64 KiB checkpoint limit. Every evidence record retains its independent bound;
the checkpoint stores only profile hash, record count, head hash, mode, schema,
and time.

## Recovery semantics are unchanged

An evidence chain that validly extends an older checkpoint remains
`forward_recovery` and can advance only after its exact prefix is proven. A
shorter chain remains rollback, and a same-length or longer nonmatching chain
remains divergence. Neither condition is inferred, repaired, or accepted by
Command Center.

Command Core schema `0.63.0` publishes only the static
`evidence_head_state_bytes` ceiling and
`validated_evidence_head_snapshot: true` posture. The dashboard remains
strictly read-only and receives no checkpoint mutation, repair, acceptance,
profile-rebind, evidence append, DKE, or Spartan surface.
