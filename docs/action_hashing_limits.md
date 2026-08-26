# Action hashing limits

Defiant v0.39 bounds the canonical hashing work used to fingerprint governed
actions. Earlier releases bounded transport documents and policy matching, but
the payload and complete authorization surface were still serialized by an
unbounded in-memory `json.dumps()` at every authority boundary.

## Fixed ceilings

Each action-controlled fingerprint accepts at most:

- 64 levels of mapping/sequence/scalar nesting;
- 1,100,000 visited nodes, including mapping keys;
- 8,388,608 characters in any one string;
- 1,024 characters in any canonical integer, float, or decimal token; and
- 67,108,864 bytes of canonical JSON consumed by SHA-256.

Exact limits are accepted. The canonical encoder retains the existing sorted
keys, compact separators, ASCII escaping, finite-number rule, enum values, and
normalized decimal strings, so hashes for every previously valid action remain
byte-for-byte compatible.

The node allowance covers the strict JSON transport maximum plus the bounded
authorization metadata Defiant adds around a payload. The canonical byte limit
covers worst-case escaping plus the separately bound target duplication of one
maximum-size MCP or native-hook document.

## Snapshot and capability behavior

The owning control path validates and fingerprints a governed action before
state recovery, policy evaluation, approval creation, reservation, or tool
execution. It detaches nested caller-owned containers, calculates the payload
and authorization hashes once, and seals all top-level authorization fields.
Policy, approval, evidence, and grant creation then reuse that immutable
fingerprint snapshot.

At the final capability spend, Defiant independently re-hashes the live action
surface. This deliberately costs one additional bounded pass: a nested mutation
after sealing cannot make a stale cached hash authorize changed content.

Content provenance created by the built-in adapter contract uses the same
bounded canonical hash helper. Cycles, unsupported Python objects, excessive
structure, scalars, or encoded bytes raise a sanitized `ActionHashLimitError`
before an action is accepted. No policy decision, approval, reservation, grant,
evidence claim about an exact payload, or tool execution is produced for input
that cannot be fingerprinted exactly.

## Read-only projection

Command Core schema `0.37.0` publishes the fixed ceilings under
`resource_limits` and reports `action_hash_preflight: true`. Command Center
renders the posture. Neither surface can change a ceiling, accept an exception,
submit an action, approve, or execute.

## Limits of the control

These are deterministic per-fingerprint ceilings, not CPU timeouts or
process-wide quotas. The final capability re-check is intentional. Evidence,
authority documents, runtime artifacts, and durable state retain their own
separate limits. A compromised host or trusted Python code inside the harness
process still requires deployment isolation and monitoring.

v0.40 separately bounds governed-request and provenance metadata before action
construction. See `governed_request_limits.md`.

v0.41 reuses the same bounded canonical-value mechanics for tool-result output
and publishes result-specific aliases for the shared depth, node, scalar, and
canonical-byte ceilings. Result summary text has its own smaller ceiling. See
`tool_result_limits.md`.

v0.42 also reuses these mechanics for the complete pre-adapter `ToolCall`
surface and publishes tool-call-specific aliases. See `tool_call_limits.md`.

v0.43 adds the shared pre-encoding numeric-token ceiling while preserving every
previously accepted canonical hash. See `canonical_number_limits.md`.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
