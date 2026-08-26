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
- 8,388,608 characters in one string or canonical decimal scalar; and
- 67,108,864 canonical UTF-8 bytes across the name, identifiers, arguments,
  and transport parameters together.

`arguments` and `transport_params` must be dictionaries. Their contents must
be canonical JSON-compatible data under the same enum and decimal rules used
for action fingerprints. Cyclic containers, unsupported objects, non-finite
numbers, and values outside a fixed ceiling are refused. Exact limits are
accepted. Diagnostics identify the contract or ceiling class without echoing
call content.

## Owning-boundary behavior

Construction performs an initial validation. `Harness.handle_call()` and
`Harness.preflight_external_call()` then revalidate the call before adapter
translation, detach both dictionaries from caller-owned containers, calculate
one bounded hash of the complete call surface, and freeze all top-level
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

Command Core schema `0.36.0` publishes tool-call-specific name, identifier,
depth, node, scalar, and canonical-byte ceilings under `resource_limits` and
reports `tool_call_contract_preflight: true`. Command Center renders only that
static posture. Neither surface can submit a call, alter a ceiling, approve,
reconcile, or execute.

## Limits of the control

The ceilings bound one call and each validation/hash pass. They are not CPU
timeouts, cumulative traffic limits, or process-wide memory quotas. The
post-translation hash detects contract mutation but does not sandbox arbitrary
trusted Python code already running inside the harness process. Deployment
isolation remains necessary.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
