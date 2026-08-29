# Trusted public-key limits

Defiant v0.32 bounds every operator-supplied trusted public-key collection
before enrollment or verification work:

- maximum supplied keys: 1,024;
- maximum PEM bytes per public key: 65,536; and
- maximum aggregate PEM bytes per key set: 8,388,608.

These are fixed implementation contracts, not environment variables or
operator-tunable policy. They apply to operator identity pins, signed evidence
export verification, and external evidence-head witness pins. Private signing
keys remain separate inputs and are not members of a trusted public-key set.

## Preflight order

Defiant materializes at most 1,025 input entries solely to detect an excessive
count. An over-count collection is refused before resolving paths, opening a
key file, parsing PEM, computing a key identifier, verifying a signature,
enrolling trust, or mutating harness state.

For an accepted count, each file is read with the per-key ceiling plus one byte.
Aggregate bytes are accumulated before that key's PEM is parsed. Exceeding
either byte ceiling fails the whole request; Defiant does not truncate a key,
silently ignore an entry, or partially enroll a trust set.

The same count ceiling validates durable operator-trust bindings and durable
evidence-witness key identifiers. This prevents a corrupted store from
reintroducing a larger collection after external input preflight.

## Failure behavior

Operator trust construction raises its existing identity error. Signed-export
verification returns an invalid attestation status. Evidence-witness policy or
verification raises or reports its existing witness error. Native Copilot and
Codex hook key-list environment variables fail before gate creation. No failed
limit check creates authority or forwards an operation.

Normal key rotation remains supported by supplying the complete bounded old and
new set. Duplicate or conflicting ownership rules remain unchanged, and
external trust paths must still reside outside mutable harness state where that
boundary already applies.

## Read-only projection

Command Core schema `0.62.0` exposes the three fixed ceilings under
`resource_limits`. Command Center renders them with the existing static parser
and ingestion posture. Neither surface accepts keys, uploads PEM, edits a trust
set, enrolls or rotates trust, verifies an export on behalf of the browser, or
creates authority.

## Limits

These controls bound one process request's file reads, PEM parsing, key-id work,
and trust-set memory. They do not provide certificate validation, revocation
distribution, key discovery, hardware-backed custody, trusted time, a process
CPU quota, or OS containment. A set within the ceilings can still contain
mistakenly trusted keys; authenticated out-of-band distribution and operator
review remain required.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
