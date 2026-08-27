# Tool-call limits

Defiant v0.42 bounds and seals each `ToolCall` before an adapter translates it
into a `ProposedAction`. Earlier releases bounded transport documents,
governed requests, action fingerprints, and post-execution results, but a
direct/native caller could still provide a large or non-canonical in-memory
call before a bounded action existed. An adapter could also mutate nested call
data while deriving the action.

## Fixed ceilings

One accepted call allows at most:

- 4,096 characters in the non-empty tool name;
- 4,096 characters in each call or server identifier;
- 64 nested mappings or sequences across the complete call surface;
- 1,100,000 nodes, including mapping keys;
- 65,536 entries in any one mapping;
- 67,108,864 aggregate mapping sort-work units;
- 8,388,608 characters in one string;
- 67,108,864 bytes in one escaped canonical string token;
- 1,024 characters in one canonical integer, float, or decimal token; and
- 67,108,864 canonical UTF-8 bytes across the name, identifiers, arguments,
  and transport parameters together.

`arguments` and `transport_params` must be dictionaries. Their contents must
be canonical JSON-compatible data under the same enum and decimal rules used
for action fingerprints. Cyclic containers, unsupported objects, non-finite
numbers, and values outside a fixed ceiling are refused. Exact limits are
accepted. Diagnostics identify the contract or ceiling class without echoing
call content.

Each mapping's entry count, aggregate deterministic key sort work, and complete
canonical byte total are checked before mapping-key sorting or JSON encoding.
The streaming hash counter independently enforces the byte ceiling after
preflight.

Mapping-key eligibility and sortable families are checked in a key-only pass
before call values or encoder sorting. Existing invalid-key inputs retain the
sanitized `tool_call_contract` classification.

Every eligible key then receives its complete scalar, escaped-token,
finite/canonical-number, node, canonical-byte, and sort-work checks before any
mapping value is visited. A key ceiling breach retains the corresponding
sanitized `tool_call_*` limit classification.

v0.50 feeds the encoder only the detached built-in snapshot returned by this
bounded traversal. Mutation of the caller-owned call surface after validation
cannot introduce unvalidated structure into the hash.

v0.51 also makes the sealed `ToolCall` retain that validated snapshot directly.
No post-validation `deepcopy()` or caller-container traversal occurs before
adapter translation.

v0.53 normalizes accepted call identity, nested scalar values, and mapping keys
to exact built-ins before that snapshot is hashed and retained. Exotic keys
that collide after normalization are refused. See
`validated_scalar_ownership.md`.

## Owning-boundary behavior

Construction performs an initial validation. `Harness.handle_call()` and
`Harness.preflight_external_call()` then revalidate the call before adapter
translation, adopt both dictionaries from the validated snapshot, calculate
one bounded hash of that exact complete call surface, and freeze all top-level
contract fields.

Immediately after `AgentAdapter.to_action()` returns, the harness computes a
fresh bounded hash of the live call. A nested mutation during translation is
therefore refused before state recovery, policy evaluation, request-scope
checks, approval creation, budget reservation, evidence, capability creation,
external authorization, or local execution. Adapters must derive new values;
they must not normalize the sealed call in place.

MCP and hook byte documents retain their earlier pre-parse ceilings. This
contract additionally protects direct in-memory entry points and binds the
combined semantic call surface after parsing.

## Read-only projection

Command Core schema `0.50.0` publishes tool-call-specific name, identifier,
depth, node, mapping-entry, mapping-sort-work, string-character,
escaped-string-token, number, and canonical-byte ceilings under
`resource_limits` and reports
`tool_call_contract_preflight: true`. Command Center renders only that static
posture. Neither surface can submit a call, alter a ceiling, approve, reconcile,
or execute.

## Limits of the control

The ceilings bound one call and each validation/hash pass. They are not CPU
timeouts, cumulative traffic limits, or process-wide memory quotas. The
post-translation hash detects contract mutation but does not sandbox arbitrary
trusted Python code already running inside the harness process. Deployment
isolation remains necessary.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
