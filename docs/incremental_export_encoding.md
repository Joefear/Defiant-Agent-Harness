# Incremental pretty-export encoding

v0.92 changes the pretty path of `encode_export`, shared by CLI export stdout,
export-file publication, and the completed signed-document size check. Instead
of constructing a full JSON string and byte buffer before applying the 64 MiB
artifact ceiling, it accumulates chunks only while they fit.

## Byte compatibility

The standard JSON encoder still uses indentation of two spaces, sorted keys,
ASCII escaping, and refusal of non-finite floats. Its chunks contain ASCII, so
character length equals UTF-8 byte length. Each chunk is checked before UTF-8
conversion and copying, with one byte reserved for the existing final newline.
An output exactly at the ceiling is accepted; an output one byte larger is
refused. Successful bytes match the previous pretty format, including escaped
Unicode and controls, numeric representation, whitespace, and newline.

In v0.92, the compact `pretty=False` path retained its full-text encoder and
post-encoding byte check. v0.93 also accumulates compact output incrementally;
see `incremental_compact_exports.md`. Canonical normalization, payload hashes,
signature statements, export schemas, and signature bytes remain unchanged.

## Failure and publication

Overflow raises the existing fixed-ceiling `EvidenceSigningError` without
echoing document content. Accumulation stops at the first overflowing chunk;
remaining values are not traversed. An invalid value reached before overflow
still produces the existing invalid-JSON diagnostic. An invalid value after an
overflow is not inspected, unlike the old encode-all-before-size-check order.
Both conditions refuse output; a size refusal does not certify the unvisited
tail as valid.

The encoder returns bytes only on success. It does not stream partial JSON to
stdout or a destination. CLI failures still report exit code 1 and a stderr
diagnostic, and file encoding still finishes before the no-overwrite publisher
is invoked. Existing destinations are preserved. Signing still checks its
compact payload before key work and checks the completed document in pretty
form before returning it.

## Deliberate limits

This bounds accumulated pretty-output length, not process memory. Input and
selected request records remain materialized. The standard encoder may
allocate a large individual escaped string or number token, sort a large
mapping, or build indentation before yielding a chunk; this change does not
preflight those costs. The bytearray may reserve extra capacity, and conversion
to the final immutable bytes can temporarily hold another bounded output copy.
Compact normalization and signing retain their existing allocations; v0.93
bounds compact output accumulation separately.

There is no new CPU quota, traversal-depth limit, detached input snapshot,
streaming signature, evidence truncation, lock behavior, or confidentiality
control. Caller mutation and privileged in-process code remain outside this
resource guarantee. Command Core and Command Center contracts are unchanged;
Command Center stays strictly read-only. No DKE or Spartan capability is added.
