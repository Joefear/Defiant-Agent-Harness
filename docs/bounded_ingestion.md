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
schema `0.24.0` projects them under `resource_limits`, and Command Center only
renders that projection.

v0.27 extends the YAML boundary with the `strict_yaml_v1` parser profile for
both MCP configuration and policy packs. It rejects aliases and duplicate
mapping keys at any nesting depth before authority can be constructed. See
`authority_configuration_integrity.md`.

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
