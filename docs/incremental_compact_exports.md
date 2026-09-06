# Incremental compact-export encoding

v0.93 extends bounded output accumulation to `encode_export(..., pretty=False)`,
used before signing or verifying an in-memory export. Pretty and compact
exports share the same accumulator and existing 64 MiB byte ceiling. Compact
output has no trailing newline; pretty output still reserves its final newline.

## Canonical compatibility

`iter_canonical_json` performs the same full normalization as `canonical_json`,
then yields standard JSON encoder chunks with sorted keys, compact separators,
ASCII escaping, and non-finite-number refusal. Enum values, decimal money text,
tuples, numeric representations, Unicode escaping, and existing invalid-input
behavior retain their canonical rules. Accepted chunks concatenate to the
existing canonical bytes. Tests compare the exact representation and signatures
produced with the same key, payload, identity, note, and timestamp.

The existing `canonical_json`, `sha256_of`, and signature statement encoders
are unchanged. Since v0.94, the chunk path also feeds size-only export checks
and streaming export payload hashing, producing identical digests. See
`streaming_export_preflight.md`. The canonical chunk helper has no independent
byte ceiling and is not a replacement for bounded authority snapshots or
general hashing.

## Refusal and ordering

ASCII chunk length equals UTF-8 byte length. Each chunk is checked before its
UTF-8 copy and before accumulator growth. Exact-ceiling compact output is
accepted; one byte over is refused with the existing fixed-ceiling diagnostic,
without echoing document content. No remaining encoding chunks are consumed
after overflow. Signing and verification still apply this gate before export
schema validation, payload hashing, and key loading.

The complete normalization pass occurs before the first chunk. Normalization
errors therefore still precede size checks. Once encoding starts, an invalid
later value may be preempted by an earlier overflow, unlike the old
encode-all-before-size-check order. Both outcomes refuse the export; an
overflow is not proof that an unvisited encoding tail is valid. Direct signing
raises `EvidenceSigningError`; direct verification returns its existing failed
status. No partial artifact or new trust claim is produced.

## Deliberate limits

This avoids joining an oversized complete compact JSON string and byte buffer.
It does not cap selected-record memory, the full normalized tree, scalar
conversion, mapping sorting, individual encoder tokens, or traversal work.
The bytearray can reserve extra capacity, and its final immutable byte copy can
temporarily duplicate bounded output. v0.94 streams export payload hashing,
but normalization, per-record validation hashing, the signed-document copy,
and signature work retain their existing costs after the size gate.

This is not a fixed process-memory cap, CPU quota, new depth limit, caller-state
ownership guarantee, streaming signature, or incremental output publication.
File no-overwrite rules, signing requirements, schemas, and authority decisions
are unchanged. Command Core and Command Center remain unchanged and read-only.
No DKE or Spartan capability is introduced.
