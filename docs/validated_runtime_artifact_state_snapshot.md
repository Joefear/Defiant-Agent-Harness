# Validated runtime-artifact state snapshot

Defiant v0.67 makes the sanitized runtime-artifact assurance record a bounded
ownership and recoverability boundary.

## One durable observation

`RuntimeArtifactState.from_dict()` first captures the complete document under
the fixed authority canonical profile and a 64 KiB byte ceiling. Schema and
legacy-version selection, profile binding, assurance mode, bundle hash,
artifact and dependency counts, executable-pin posture, and verification time
validate only from that detached exact built-in observation.

Capture reads built-in container storage directly, normalizes accepted scalar
subclasses, detects container drift, and refuses cyclic, unsupported, or
oversized values with sanitized errors. Mutating the source document after
capture cannot change the retained state, projections, conflict comparison, or
publication.

## Candidate ownership and publication

`RuntimeArtifactStateStore.record()` normalizes the profile hash and captures
the supplied assurance fields into one validated state candidate before
creating or locking the durable state root. Comparison with an existing record
and the eventual write both use that candidate, so later caller mutation cannot
substitute a different bundle, mode, count, or pin posture.

Immediately before replacement, the writer projects and revalidates the state
again and passes only the detached built-in document to `atomic_write_json()`.
The writer and recovery reader both receive the same explicit 64 KiB ceiling.
An oversized or invalid candidate fails before replacement and leaves the prior
valid observation intact.

The durable schema remains `defiant.runtime_artifacts`. Existing `0.1.0`
documents still load with zero dependency counts and upgrade to `0.2.0` on the
next successful write.

## Authority boundary

This state is a sanitized record of verification, not an artifact allowlist.
Executable pins and dependency manifests remain authenticated configuration;
the harness still verifies their bytes before authority-profile acceptance and
again immediately before local process creation.

Command Core schema `0.62.0` reports the fixed
`runtime_artifact_state_bytes` ceiling and
`validated_runtime_artifact_state_snapshot: true`. Command Center renders only
that static posture and its existing sanitized artifact projection. It gains no
artifact, manifest, profile-rotation, process-launch, repair, or mutation route.

This release adds no DKE, Spartan, remote Command, or writable Command Center
feature.
