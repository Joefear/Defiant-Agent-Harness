# Sealed authority-continuity state

Defiant v0.60 hardens the two durable roots that decide who may exercise
operator authority and which complete runtime authority profile is active:
`OperatorTrustState` and `AuthorityProfileState`.

## One validated state observation

Each `from_dict()` entry first captures one exact built-in snapshot under the
fixed authority canonical profile and the store's 1 MiB canonical-byte limit.
Schema, generation continuity, binding hashes, transition chains, timestamps,
and attestation bindings are validated only from that observation.

Capture reads built-in dictionary, list, and tuple storage directly, normalizes
accepted scalar subclasses, detects container drift, rejects cyclic or
unsupported values, and bounds depth, nodes, mapping entries, mapping sort
work, strings, numbers, and encoded bytes. Caller mapping, iteration, lookup,
rendering, or copy hooks cannot manufacture a second state during validation.

## Frozen retention and defensive projections

Validated binding maps, key-id lists, transition histories, pending rotations,
and nested attestations are recursively frozen in private runtime storage.
Public `bindings`, `initial_bindings`, `transitions`, and `pending_rotation`
accessors return fresh exact built-in projections. `to_dict()` independently
returns another fresh projection for durable serialization.

Mutating the source document, a returned property, or a prior `to_dict()` result
cannot alter later signature verification, rotation comparison, projection, or
publication. As with other in-process seals, code already trusted inside the
harness can still use private-object mechanisms; this is not an OS sandbox.

## Recoverability limit

Both stores refuse recovery files larger than 1 MiB. v0.60 applies the same
store-specific ceiling to canonical capture and `atomic_write_json()`.
Oversized proposed rotations fail before replacement, leaving the previously
valid generation intact. v0.66 makes the recovery read itself descriptor-
bounded under that ceiling and revalidates a detached candidate immediately
before publication. The durable JSON schemas remain unchanged and valid
existing state remains readable.

## Read-only projection

Command Core schema `0.69.0` publishes `authority_profile_state_bytes` and
`operator_trust_state_bytes` under `resource_limits` and reports
`sealed_authority_continuity_state: true` and
`bounded_authority_continuity_io: true` under `authority_configuration`.
Command Center renders only this static posture. It receives no binding map,
transition, attestation, operator note, signature, state path, or mutation
route.

These releases add no DKE, Spartan, remote Command, or Command Center authority.
