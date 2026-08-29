# Validated canonical snapshots

Defiant v0.50 binds canonical encoding to the exact detached structure produced
by bounded validation. Earlier releases validated the live action-controlled
object and then asked `JSONEncoder.iterencode()` to traverse that object again.
A concurrent mutation or container-subclass iteration hook could make the
second structure differ from the one whose resource limits had passed.

## One bounded source of truth

The shared canonical traversal now performs validation, exact byte accounting,
and detachment together. It produces built-in `dict`, `list`, and `tuple`
containers containing only values that passed the existing contract. The
streaming SHA-256 encoder consumes that snapshot rather than the caller's live
object.

For mappings and sequences, Defiant reads built-in container storage directly
with the corresponding built-in methods. Overridden `items()` or `__iter__()`
methods on container subclasses are not invoked. Plain Enum values are resolved
recursively during the bounded traversal, so a mutable Enum value cannot change
between validation and encoding. Decimal values are converted to their already
defined bounded canonical string during the same pass.

As of v0.53, accepted scalar subclasses and mapping keys are also converted to
exact built-in values during this pass. See `validated_scalar_ownership.md`.

The existing defenses still apply to the snapshot:

- nesting depth and total visited nodes;
- per-mapping entry count and homogeneous key families;
- complete mapping-key token validation and aggregate sort work;
- scalar, escaped-string-token, and canonical-number limits; and
- exact complete canonical bytes, followed by the independent streaming byte
  assertion.

## Compatibility and failure behavior

Ordinary mappings, lists, tuples, scalars, supported Enums, and Decimals retain
identical canonical JSON and SHA-256 hashes. The canonical encoder configuration
is unchanged: sorted keys, compact separators, ASCII escaping, and non-finite
number refusal.

Container-subclass iteration overrides are deliberately not part of the
canonical contract. Their built-in stored contents are validated and encoded.
Unsupported objects and unstable mappings still fail with sanitized owning
contract errors; tool calls and tool results retain their existing limit and
contract aliases. No rejected content is echoed.

## Read-only projection

Command Core schema `0.59.0` reports
`validated_canonical_snapshot: true`. Command Center renders only this static
posture. It cannot supply canonical input, modify limits, approve, reconcile,
or execute.

v0.51 extends the same invariant to contract ownership. Actions, pre-adapter
tool calls, and post-execution tool results now retain the validated snapshot
directly instead of traversing the caller object again with `deepcopy()`. See
`validated_snapshot_ownership.md`.

## Limits of the control

The snapshot binds one hash operation to one bounded observation. It does not
freeze caller-owned memory, serialize application threads, or provide an
operating-system sandbox. A caller may mutate its original object later; sealed
ownership and the final live capability check remain responsible for detecting
post-authorization action changes. As of v0.51, action-controlled contract
owners adopt this snapshot without a separate copy pass.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
