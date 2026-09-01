# Validated launch-envelope state snapshot

Defiant v0.68 makes the sanitized launch-envelope assurance record a bounded
ownership and recoverability boundary.

## One durable observation

`LaunchEnvelopeState.from_dict()` captures the complete document under the
fixed authority canonical profile and a 64 KiB byte ceiling before it validates
schema, profile binding, launch mode, environment and working-directory hashes,
variable counts, or verification time. Validation therefore consumes one
detached exact built-in observation.

Capture reads built-in container storage directly, normalizes accepted scalar
subclasses, detects container drift, and refuses cyclic, unsupported, or
oversized values with sanitized errors. Mutation of the source document after
capture cannot change retained state, conflict checks, dashboard projections,
or publication.

## Candidate ownership and crash-safe publication

`LaunchEnvelopeStateStore.record()` captures the profile hash and sanitized
assurance fields into one validated candidate before creating or locking the
durable state root. Existing-state comparison and publication both consume
that candidate, so later caller mutation cannot substitute a different
environment, working directory, mode, or count.

Immediately before replacement, the writer projects and revalidates the state
again and supplies only that detached built-in document to
`atomic_write_json()`. Canonical capture, recovery reads from the opened file,
and atomic publication share the same explicit 64 KiB ceiling. An invalid or
oversized candidate fails before replacement and leaves the prior recoverable
record unchanged.

The durable schema remains `defiant.launch_envelope` version `0.1.0`.

## Authority boundary

This file is a sanitized assurance record, not a launch configuration. The
operator-authored environment allowlist, secrets, values, unsafe-variable
acknowledgements, working-directory path, and process command remain outside
the record and are still verified before local process creation.

Command Core schema `0.69.0` reports the fixed
`launch_envelope_state_bytes` ceiling and
`validated_launch_envelope_state_snapshot: true`. Command Center renders only
that static posture and the existing sanitized launch-envelope projection. It
gains no environment, secret, path, profile-rotation, launch, repair, or
mutation route.

This release adds no DKE, Spartan, remote Command, or writable Command Center
feature.
