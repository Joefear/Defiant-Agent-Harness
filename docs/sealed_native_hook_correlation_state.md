# Sealed native-hook correlation state

Native hooks split one externally executed tool lifecycle across `PreToolUse`
and `PostToolUse`. Defiant must retain the exact authorized action, request,
decision, execution identity, and authorization evidence id between those
events. If that retained state changes after validation, a later completion
could be attributed to a different authorization context.

v0.61 makes each `HookExecution` an immutable ownership boundary.

## One bounded observation

Public construction and `HookExecution.from_dict()` first capture one fixed
canonical built-in snapshot. Mapping, list, and scalar subclasses cannot
provide a second iterator view, run copy hooks, or change values between field
validation steps. Invalid or oversized input fails with a sanitized
`HookStateError` that does not render rejected values.

The retained action, request, and decision documents are reconstructed through
their normal governed contracts from that same observation. The hook execution
therefore cannot durably correlate an object that those contracts would refuse.

## Sealed retention and copy-on-write completion

The action, request, and decision trees are recursively frozen in private
storage. Public properties and `to_dict()` return fresh built-in projections;
mutating a supplied object or returned projection cannot change the retained
authorization context.

`HookExecution` itself is frozen. Moving from `authorized` to `completed`
creates a new validated record, leaving every earlier reference unchanged.
Repeated completion with the same evidence id remains idempotent, while a
different completion id fails closed.

## Durable store symmetry

`hook_executions.json` retains its established 64 MiB durable-state ceiling.
v0.61 names that ceiling explicitly as `MAX_HOOK_EXECUTION_STATE_BYTES` and
uses it for:

- strict recovery reads;
- canonical capture of the complete loaded or proposed store; and
- atomic JSON publication.

The writer cannot publish a state document that its recovery reader would
reject. A refused update leaves the previous durable bytes in place. Loaded
records are adopted from the store's single bounded observation rather than
being repeatedly reconstructed from a live mapping.

## Command boundary

Command Core schema `0.69.0` publishes only the static
`hook_execution_state_bytes` ceiling and
`sealed_native_hook_correlation_state: true` build posture. Command Center
renders those static facts. Neither surface receives hook execution snapshots,
completion ids, targets, payloads, decisions, or a mutation endpoint.

This control does not make native hooks an operating-system sandbox, repair a
missing `PostToolUse` event, infer an external outcome, or change documented
runner timeout behavior. Unknown completion remains unknown and follows the
existing reconciliation rules.
