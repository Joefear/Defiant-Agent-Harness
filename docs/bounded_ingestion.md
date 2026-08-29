# Bounded ingestion

Defiant v0.26 applies fixed byte ceilings before untrusted or durable documents
reach JSON, YAML, or SSE parsing. This limits single-document memory
amplification and makes resource exhaustion fail closed at the authority
boundary.

## Fixed ceilings

| Boundary | Maximum | Failure behavior |
| --- | ---: | --- |
| Aggregate durable JSON state file | 64 MiB | Store is invalid; authority blocks |
| One physical evidence JSONL record | 16 MiB | Existing chain is invalid or new append is refused |
| One request evidence export | 64 MiB | Refused before parsing, signing, verification, or publication |
| One MCP stdio message | 10 MiB | Client/upstream transport terminates fail closed |
| One Streamable HTTP response | 10 MiB | Remote transport fails before JSON/SSE parsing |
| One native-hook event document | 10 MiB | Hook returns its fail-closed response |
| MCP proxy YAML configuration | 1 MiB | Startup refuses configuration |
| One policy-pack YAML document | 1 MiB | Harness construction fails closed |

The constants live in `defiant_agent_harness.limits`. They are implementation
contracts, not environment variables or operator-tunable policy. Command Core
schema `0.65.0` projects them under `resource_limits`, and Command Center only
renders that projection.

v0.40 applies the same fail-closed discipline to governed request construction.
Task text, identity fields, tool allowlists, and request or action provenance
metadata have fixed item, count, and aggregate ceilings. The harness revalidates
and seals the request before adapter proposal or authority work, so mutation after
construction cannot evade those ceilings. See
[Governed request limits](governed_request_limits.md).

v0.41 extends bounded in-memory construction to post-execution tool results.
Accepted output is canonical, bounded, detached, hashed, and sealed before
terminal state changes. Refusal preserves an uncertain authorization for the
existing explicit reconciliation workflow. See
[Tool result limits](tool_result_limits.md).

v0.42 bounds the in-memory `ToolCall` before adapter translation. The complete
name, identifiers, arguments, and transport parameters are canonical,
detached, hashed, sealed, and checked again after adapter translation. See
[Tool-call limits](tool_call_limits.md).

v0.43 separately bounds in-memory canonical numeric tokens before JSON
encoding, including non-rendering preflight for large integers and
large-exponent decimals. See [Canonical number limits](canonical_number_limits.md).

v0.44 preflights the exact escaped byte width of each in-memory canonical JSON
string before encoding, preventing a rejected control, non-ASCII, or non-BMP
value from first materializing an oversized token. See
[Canonical string limits](canonical_string_limits.md).

v0.45 calculates the exact complete canonical JSON size during structural
preflight, refusing an oversized aggregate before mapping-key sorting or JSON
encoding begins. See
[Canonical value preflight](canonical_value_preflight.md).

v0.46 caps each in-memory canonical mapping at 65,536 entries before key
traversal or sorting. See
[Canonical mapping limits](canonical_mapping_limits.md).

v0.47 charges canonical key-token bytes by an idealized logarithmic comparison
round factor against one aggregate pre-sort budget. See
[Canonical mapping sort-work limits](canonical_mapping_sort_work.md).

v0.48 validates canonical mapping-key eligibility and homogeneous sortable
families before values or encoder sorting. See
[Canonical mapping-key contract](canonical_mapping_key_contract.md).

v0.27 extends the YAML boundary with the `strict_yaml_v1` parser profile for
both MCP configuration and policy packs. It rejects aliases and duplicate
mapping keys at any nesting depth before authority can be constructed. See
`authority_configuration_integrity.md`.

v0.34 advances that boundary to `strict_yaml_v2`, adding a pre-construction
maximum depth of 64 mappings/sequences and maximum 100,000 scalar/collection
nodes. See `yaml_structural_limits.md`.

v0.28 adds the shared `strict_json_v1` profile to durable state, evidence,
MCP, HTTP, native-hook, signed-export, and witness JSON ingress. Duplicate keys
at any depth, non-finite numbers, and non-UTF-8 byte documents are refused. See
`strict_json_integrity.md`.

v0.29 closes the aggregate signed-export gap with a 64 MiB ceiling before file
parsing and before export publication. Direct in-memory signing and verification
enforce the same bound. See `bounded_evidence_exports.md`.

v0.30 adds fixed shared JSON structural ceilings before object construction:
64 nested containers and 1,000,000 lexical tokens. These limits apply after
strict UTF-8 decoding and before the existing strict JSON decoder. See
`json_structural_limits.md`.

v0.31 adds fixed per-scalar JSON ceilings before conversion: 8,388,608 source
characters per string token and 1,024 source characters per number token. See
`json_scalar_limits.md`.

v0.32 separately bounds operator-supplied trusted public-key collections before
filesystem and cryptographic work. See `trusted_key_limits.md`.

v0.35 separately bounds semantically expensive MCP configuration collections
after strict YAML construction but before entry transformation, path handling,
hashing, or startup. See `mcp_configuration_limits.md`.

v0.36 separately bounds recognized policy text per item and across the complete
ruleset before rule construction or hashing. See `policy_text_limits.md`.

v0.37 separately bounds the semantic payload view and aggregate substring work
used by `payload_contains` rules. See `policy_payload_matching_limits.md`.

v0.38 separately bounds action-controlled glob subjects and decision-wide
known-tool/rule glob work. See `policy_glob_matching_limits.md`.

v0.39 separately bounds canonical action payload, provenance-content, and
authorization fingerprints. See `action_hashing_limits.md`.

## Parser discipline

File readers consume at most the ceiling plus one byte before deciding that a
document is oversized. Line protocols apply the ceiling independently to each
physical line, then terminate the affected transport rather than skipping the
remainder and risking message desynchronization. Serialized durable JSON and
new evidence records are checked before publication.

JSON duplicate keys and non-finite numbers are rejected, including `NaN` and
infinities. JSON byte input must be strict UTF-8. MCP YAML
aliases are rejected before construction so anchors cannot amplify a small
configuration into a much larger object graph. Diagnostics name the boundary
and ceiling but do not echo rejected input, payloads, targets, or absolute
state paths.

## Evidence history and recovery

The 16 MiB evidence limit applies to each record. Defiant does not impose an
aggregate evidence-history cap or silently compact the append-only chain.
Verification and Command projections therefore remain linear in total history;
operators should archive according to deployment retention policy while
preserving required evidence and external witnesses.

An oversized durable file is not truncated, partially parsed, or repaired
online. Restore a known-good copy or investigate and perform an explicitly
reviewed offline recovery. Native hooks and MCP transports may be retried only
after the producer sends a valid document within the fixed ceiling; normal
approval and exact-call rules still apply.

## Security boundary

These ceilings reduce single-input memory and parser-amplification risk. They
do not provide CPU quotas, total-history quotas, process memory limits, or OS
containment, and they cannot stop a privileged host from replacing the process
or code. This release adds no DKE, Spartan, remote Command, or Command Center
authority.
