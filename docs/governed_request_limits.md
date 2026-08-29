# Governed request limits

Defiant v0.40 bounds the request contract before an adapter can propose an
action. Earlier releases bounded transport documents, policy authority,
matching, and action fingerprints, but a direct or mutated `HarnessRequest`
could still supply an unbounded task, allowlist, policy context, or provenance
collection.

## Fixed ceilings

One governed request accepts at most:

- 1,048,576 characters in `task`;
- 4,096 characters in each user id, workspace id, request id, and task type;
- 4,096 allowed tools;
- 4,096 characters in each allowed-tool name;
- 100,000 provenance references in a request or action;
- 8,192 characters in each provenance reference id, origin, content hash, or
  label;
- 8,388,608 aggregate characters across request text, allowed tools, and input
  provenance metadata; and
- 8,388,608 aggregate characters across one action's provenance metadata.

Exact limits are accepted. `allowed_tools` and `inputs` must be lists when a
request is constructed; allowlist entries must be non-empty strings. Content
references retain an optional empty label, while their identity, origin, and
content hash remain required.

## Owning-boundary behavior

Construction performs the first validation. The owning harness repeats it
before calling `AgentAdapter.propose`, translating a direct tool call, or
reusing a durable request. As of v0.52, it snapshots built-in list storage
before validation, validates those exact tuples, adopts them without another
caller-list traversal, and seals every request field. See
`validated_contract_collection_snapshots.md`.

As of v0.53, request identity, scope, timestamps, allowlist entries, and
provenance metadata are also normalized to exact built-in strings before the
sealed contract retains them. See `validated_scalar_ownership.md`.

This second check is essential: Python callers can mutate an otherwise valid
dataclass between construction and submission. A changed task, identifier,
allowlist, budget, provenance list, timestamp, or context field is either
captured in the sealed request or refused; it cannot race later request-scope
or policy work through a stale validation.

Exceeding a ceiling raises a sanitized `RequestLimitError` with a stable limit
class. The adapter is not called, no action is accepted, and Defiant creates no
policy decision, approval, budget reservation, evidence claim, grant, or tool
execution for a request it could not safely accept.

## Read-only projection

Command Core schema `0.61.0` publishes all eight fixed ceilings under
`resource_limits` and reports `request_contract_preflight: true`. Command
Center renders only this static posture. Neither surface can submit or edit a
request, change a ceiling, accept an exception, approve, or execute.

## Limits of the control

These ceilings bound one request and its provenance metadata. They are not a
process-wide traffic, CPU, memory, or wall-clock quota. They do not improve an
adapter's provenance truthfulness, infer missing data flow, authenticate an
identifier, or prove that an operator-authored task is correct.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
