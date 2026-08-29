# Action hashing limits

Defiant v0.39 bounds the canonical hashing work used to fingerprint governed
actions. Earlier releases bounded transport documents and policy matching, but
the payload and complete authorization surface were still serialized by an
unbounded in-memory `json.dumps()` at every authority boundary.

## Fixed ceilings

Each action-controlled fingerprint accepts at most:

- 64 levels of mapping/sequence/scalar nesting;
- 1,100,000 visited nodes, including mapping keys;
- 65,536 entries in any one mapping;
- 67,108,864 aggregate canonical mapping sort-work units;
- 8,388,608 characters in any one string;
- 67,108,864 bytes in any one escaped canonical string token;
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

v0.45 calculates the complete encoded byte length during that structural
preflight, including container syntax and mapping-key representation. A value
that cannot fit is refused before mapping-key sorting or JSON encoding begins;
the streaming counter remains a second check.

## Read-only projection

Command Core schema `0.65.0` publishes the fixed ceilings under
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

v0.44 adds exact pre-render escaped-string token accounting. A string that
cannot fit the complete canonical byte ceiling is refused before the JSON
encoder materializes it. See `canonical_string_limits.md`.

v0.45 moves the complete canonical-byte ceiling into preflight without changing
the limit or accepted hashes. See `canonical_value_preflight.md`.

v0.46 adds a fixed per-mapping entry ceiling before key traversal or sorting.
This deliberately refuses some mappings accepted by earlier releases while
preserving canonical bytes and hashes for values within the ceiling. See
`canonical_mapping_limits.md`.

v0.47 charges each canonical mapping key byte once per idealized logarithmic
comparison round against one aggregate budget before encoder sorting. This is a
new compatibility ceiling; accepted canonical hashes remain unchanged. See
`canonical_mapping_sort_work.md`.

v0.48 validates mapping-key eligibility and mutually sortable families before
mapping values or encoder sorting. It preserves every previously successful
hash and moves existing sanitized contract failures earlier. See
`canonical_mapping_key_contract.md`.

v0.49 validates every eligible key's complete canonical token and charges its
node, byte, and aggregate sort-work costs before any mapping value is visited.
This preserves successful canonical bytes and hashes while making invalid-key
failure precedence deterministic. See `complete_mapping_key_preflight.md`.

v0.50 returns a detached built-in snapshot from the bounded traversal and feeds
that exact snapshot to the streaming encoder. Caller mutation or container
subclass iteration hooks cannot replace the already validated structure during
a second encoder pass. See `validated_canonical_snapshot.md`.

v0.51 returns that snapshot together with its digest and makes governed action,
tool-call, and tool-result owners adopt it directly. Sealing performs no later
`deepcopy()` or caller-container traversal. See
`validated_snapshot_ownership.md`.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
