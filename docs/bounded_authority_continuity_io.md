# Bounded authority-continuity I/O

Defiant v0.66 makes recovery and publication for the durable authority profile
and operator-trust roots one symmetric byte-bounded contract.

## Opened-stream recovery ceiling

Before v0.66, each loader checked the path size against its 1 MiB allowance and
then called the durable JSON reader without that store-specific limit. A file
replacement between the path observation and the open could therefore expose a
different, larger file to the broader default reader.

Both loaders now pass their exact 1 MiB ceiling to `read_json()`. The
persistence layer opens and validates the state descriptor, reads at most one
byte beyond the limit, and refuses excess bytes before strict JSON decoding.
Path replacement between the preliminary existence check and the open can no
longer expand the read allowance; deletion, unsafe replacement, malformed JSON,
and oversize content all fail closed.

The first-start migration check for legacy signed approval records now passes
the approval store's existing 64 MiB ceiling explicitly. It remains a
read-only detection step and does not migrate, approve, or rewrite records.

## Detached publication revalidation

Authority-profile enrollment and rotation, and operator-trust enrollment and
rotation, already construct sealed state values. Immediately before atomic
publication, v0.66 takes a fresh built-in projection, validates it through the
same state parser, and gives only that detached validated candidate to the
bounded JSON writer.

The writer uses the same 1 MiB ceiling as recovery. A rejected candidate or
failed oversized write cannot replace the prior valid generation. Existing
`0.1.0` state documents remain valid; field sets, transition chains, signature
requirements, generation continuity, and downgrade refusal are unchanged.

## Read-only observability

Command Core schema `0.64.0` reports
`bounded_authority_continuity_io: true` under `authority_configuration` while
retaining the existing fixed byte ceilings. Command Center renders only that
static posture and the already-sanitized continuity summaries. It receives no
state bytes, bindings, key material, transitions, attestations, operator notes,
paths, enrollment, rotation, repair, or migration endpoint.

This hardening adds no DKE, Spartan, remote Command, or writable Command Center
feature. It is deterministic local authority-state recoverability hardening.
