# Validated snapshot ownership

Defiant v0.51 makes each action-controlled contract owner retain the exact
detached canonical snapshot that passed bounded validation and produced its
digest. This closes the remaining copy boundary after v0.50: action, tool-call,
and tool-result sealing no longer validates a live container and then traverses
it again with `deepcopy()`.

## One observation becomes owned state

The bounded canonical traversal now has a shared snapshot-and-hash operation.
It returns both:

- a detached tree containing built-in `dict`, `list`, and `tuple` containers;
  and
- the SHA-256 digest produced by streaming the exact same tree through the
  established canonical JSON encoder.

`ProposedAction.seal_fingerprints()`, `ToolCall.seal_contract()`, and
`ToolResult.seal_contract()` adopt that returned tree directly. They do not
invoke caller-defined `__deepcopy__` hooks or perform an unbounded second copy.
The retained action payload is also the payload included in the validated
authorization snapshot.

Enum and Decimal extensions use their existing canonical representations in
owned snapshots. Enums become recursively validated values and Decimals become
bounded canonical decimal strings. Ordinary JSON values retain their types,
canonical bytes, and hashes.

## Boundary behavior

The existing owner-specific failures remain intact:

- action limit and canonical-contract failures remain action hash failures;
- tool-call failures retain sanitized `tool_call_*` limit aliases or the
  `tool_call_contract` outcome; and
- tool-result failures retain sanitized `tool_result_output_*` aliases or the
  `tool_result_output_contract` outcome.

Caller mutation after sealing affects only the caller's original containers.
Mutation of the owned action snapshot is still detected by the final live
capability check. Tool-call translation continues to call
`require_unchanged()`, and sealed tool-result top-level fields remain frozen.

## Read-only projection

Command Core schema `0.71.0` reports
`validated_snapshot_ownership: true` alongside
`validated_canonical_snapshot: true`. Command Center renders only this fixed
posture. It has no endpoint or control for supplying snapshots, changing the
contract, approving, reconciling, or executing.

## Limits of the control

This is deterministic ownership and resource hardening, not thread isolation
or a Python sandbox. The snapshot represents one bounded observation. Python
already executing inside the harness process remains trusted, and deployment
controls are still required for cumulative CPU, memory, wall-clock, filesystem,
and network containment.

v0.52 applies the same one-observation ownership principle to governed request
allowlists and inputs plus action provenance lists. See
`validated_contract_collection_snapshots.md`.

v0.53 ensures those owned canonical trees and governed contracts contain exact
built-in scalar values rather than caller-defined scalar subclasses. See
`validated_scalar_ownership.md`.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
