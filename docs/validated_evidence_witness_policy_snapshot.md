# Validated evidence-witness policy snapshot

v0.65 makes `evidence_witness_policy.json` one bounded ownership and
publication boundary. This durable observation records whether signed external
head witnessing is required for an authority profile, the trusted public-key
identifiers, the optional maximum unwitnessed-record lag, and the recording
time. It does not contain witness documents, signatures, notes, key bytes, or
paths.

## One accepted policy observation

Loaded and directly constructed `EvidenceWitnessPolicyState` values are first
captured as detached canonical built-ins. Schema and version selection,
profile binding, mode, sorted unique key IDs, lag bound, and timestamp
validation consume that exact observation. The retained key collection is an
immutable tuple of exact built-in strings.

`EvidenceWitnessPolicyStore.record()` constructs the complete candidate before
comparison with existing state. Caller-owned profile hashes, key-ID sequences,
and lag values cannot substitute a second view between profile-consistency
checks and publication. Invalid inputs fail with sanitized errors that do not
render rejected objects.

## Symmetric bounded I/O

The established 256 KiB policy-document allowance is now
`MAX_EVIDENCE_WITNESS_POLICY_STATE_BYTES`. The same ceiling governs:

- canonical in-process policy capture;
- the descriptor-backed durable recovery read; and
- atomic JSON publication.

The store no longer relies on a separate size stat followed by an implicitly
broader read, and it cannot successfully publish policy state that the next
restart would reject solely for size. A refused candidate leaves the prior
policy bytes unchanged.

The separate external witness document retains its existing independent
256 KiB ingestion and output contract. v0.65 does not copy that file into
harness state or change signature, chain-position, profile-history, rollback,
divergence, or lag verification.

## Compatibility and projection

Policy schema v0.2 remains current. Existing v0.1 policy observations continue
to load with an unbounded lag and upgrade to v0.2 only when written through the
normal owning path.

Command Core schema `0.72.0` publishes only the static
`evidence_witness_policy_state_bytes` ceiling and
`validated_evidence_witness_policy_snapshot: true` posture. Command Center
continues to show sanitized witness assurance and remains strictly read-only.
It receives no witness contents, trust keys, signatures, notes, paths, policy
mutation, acceptance, signing, repair, DKE, or Spartan surface.
