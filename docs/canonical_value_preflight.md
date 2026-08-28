# Canonical value preflight

Defiant v0.45 calculates the exact canonical JSON byte length of each complete
action-controlled value before JSON encoding begins. Earlier releases bounded
structure, individual scalars, escaped string tokens, numeric tokens, and the
stream consumed by SHA-256, but a collection of individually valid values
could exceed the complete byte ceiling only after encoder work started.

## Existing ceiling, earlier enforcement

The complete canonical value retains its 67,108,864-byte ceiling. v0.45 does
not introduce a smaller limit or a new canonical form. The structural preflight
now counts:

- mapping and sequence delimiters, separators, and mapping colons;
- exact `ensure_ascii=True` string-token bytes;
- finite integer and float tokens;
- normalized decimal strings;
- enum values; and
- JSON's quoted representation of supported non-string mapping keys.

Byte length does not depend on mapping order, so the traversal can refuse an
oversized value before `sort_keys=True` sorts a mapping and before
`JSONEncoder.iterencode()` emits any chunk. The encoder's streaming byte check
remains as an independent defense-in-depth assertion.

Exact limits pass. Failure remains the sanitized
`action_hash_canonical_bytes` limit. Tool-call and tool-result owners retain
their existing `tool_call_canonical_bytes` and
`tool_result_output_canonical_bytes` aliases. Accepted canonical bytes and
hashes are unchanged.

## Read-only projection

Command Core schema `0.56.0` reports `canonical_value_preflight: true` with the
existing fixed resource ceilings. Command Center renders only this posture. It
cannot submit a value, change a limit, approve, reconcile, or execute.

## Limits of the control

Preflight still performs one bounded traversal and accepted mappings are still
sorted by the canonical encoder. This is a deterministic per-value ceiling,
not a wall-clock timeout, cumulative traffic quota, operating-system sandbox,
or defense against trusted Python already executing inside the process.

As of v0.50, that traversal also produces the detached built-in snapshot used
by the encoder. The encoder therefore cannot observe a structurally different
live caller container after preflight. See `validated_canonical_snapshot.md`.

As of v0.51, action-controlled contract owners retain that same snapshot and
its digest directly, without a post-validation deep-copy pass. See
`validated_snapshot_ownership.md`.

This release adds no DKE, Spartan, remote Command, or Command Center authority.

v0.46 separately bounds the entry count of each accepted mapping before key
traversal or sorting. See `canonical_mapping_limits.md`.
