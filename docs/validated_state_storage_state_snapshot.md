# Validated state-storage state snapshot

Defiant v0.69 makes the sanitized state-root assurance record a bounded
ownership and recoverability boundary.

## One durable observation

`StateStorageState.from_dict()` captures the complete document under the fixed
authority canonical profile and a 64 KiB byte ceiling before validating schema
version, profile and root binding, filesystem-security mode, permission and
directory-sync posture, Windows ACL posture, or verification time. Validation
therefore consumes one detached exact built-in observation.

Capture reads built-in container storage directly, normalizes accepted scalar
subclasses, detects container drift, and refuses cyclic, unsupported, or
oversized values with sanitized errors. Source mutation after capture cannot
change the retained state, conflict comparison, integrity projection, or
publication.

## Candidate ownership and crash-safe publication

`StateStorageStateStore.record()` captures the profile hash and sanitized
assurance fields into one validated candidate before acquiring the authority
lock. Existing-state comparison and publication both consume that candidate,
so later caller mutation cannot substitute a different root identity,
permission posture, ACL posture, or directory-sync guarantee.

Immediately before replacement, the writer projects and revalidates the state
again and supplies only that detached built-in document to
`atomic_write_json()`. Canonical capture, recovery reads from the opened file,
and atomic publication share the same explicit 64 KiB ceiling. Invalid or
oversized publication fails before replacement and preserves the prior
recoverable observation.

The durable schema remains `defiant.state_storage` version `0.2.0`. Existing
`0.1.0` observations remain readable and upgrade on the next successful write.

## Authority boundary

This state is a sanitized assurance record, not authority to relocate or repair
the state root. The live root identity, ownership, permissions, file types,
link counts, ACLs, temporary files, and replacement resistance remain verified
through the filesystem boundary before governed execution.

Command Core schema `0.63.0` reports the fixed
`state_storage_state_bytes` ceiling and
`validated_state_storage_state_snapshot: true`. Command Center renders only
that static posture and its existing sanitized state-storage projection. It
gains no path, ACL, permission, profile-rotation, relocation, repair, or
mutation route.

This release adds no DKE, Spartan, remote Command, or writable Command Center
feature.
