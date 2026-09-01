# Read-only authority-publication manifest verification

v0.72 lets read-only diagnostics independently verify the completed v0.71
authority-publication checkpoint. Doctor and Command Core no longer trust the
stored manifest hash merely because its schema and profile generation are
valid.

## Reconstruction

For a completed checkpoint, the state auditor reads the durable sanitized
observations for:

- state-storage assurance;
- control-plane isolation;
- workspace-root integrity;
- evidence-witness policy;
- optional runtime-artifact assurance;
- optional launch-envelope assurance; and
- evidence-head authority mode and schema.

Every required observation must exist and parse under its own fixed ceiling.
Every present observation must bind the checkpoint's exact profile hash. The
auditor rebuilds the same bounded canonical manifest used by the owning runtime
and compares its SHA-256 hash with the completed checkpoint.

Missing or invalid required dependencies produce
`authority_publication_dependency_invalid`. A well-formed but different
durable authority projection, including creation or removal of an optional
store, produces `authority_publication_manifest_mismatch`. Both are critical
and make the snapshot non-authoritative. No raw manifest, path, environment,
artifact filename, witness signature, or state body is projected.

An active publication remains `recovery_required`. v0.73 further verifies its
`prepared`, `applying`, or `ready_to_complete` phase from durable state. Only
the owning runtime can prove the configured candidate and finish it.
Operator-control and read-only paths cannot replay or complete the intent.
v0.74 also commits each target store separately so partial replay can detect a
same-profile value substitution before final manifest reconstruction. See
`active_authority_publication_commitments.md`.

## Read-only guarantee

Verification performs no enrollment, checkpoint advance, file creation,
repair, normalization, or timestamp update. Adversarial tests snapshot every
durable byte before Doctor and Command Core inspection and confirm that the
state is unchanged afterward. Command Center renders only the resulting
sanitized verification status and remains strictly read-only.

## Limits

The manifest proves agreement among current local sanitized observations. It
does not prove that an older internally consistent state set was never restored
or defeat a privileged host that replaces code and all state together. External
signed evidence witnessing, immutable deployment, and off-box monitoring remain
the controls for those threats.
