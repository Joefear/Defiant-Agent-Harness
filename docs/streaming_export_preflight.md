# Streaming export preflight and payload hashing

v0.94 removes complete encoded-output buffers from export size-only checks and
joined canonical text from export payload hashing. The existing 64 MiB export
ceiling, canonical representation, signature format, and publication rules are
unchanged. This is an allocation improvement, not a new authority capability.

## Shared byte boundary

One bounded ASCII chunk iterator applies the existing pretty or compact JSON
settings, checks each chunk before handing it to a consumer, and reserves the
pretty path's trailing newline. Exact-ceiling output is accepted and overflow
raises the existing fixed-ceiling diagnostic. Compact normalization still runs
in full before yielding encoded chunks.

- Size-only checks consume all accepted chunks without UTF-8 copies or an
  accumulated output buffer. They are used before signing payload validation,
  before verification schema/hash/key work, and for the completed signed
  document's pretty-size check.
- Export payload hashing feeds compact chunks directly to SHA-256. It returns
  the same `sha256:` digest as the previous canonical hash and independently
  enforces the byte ceiling during that hash observation, rather than relying
  solely on an earlier check.
- `encode_export` still accumulates bounded UTF-8 output for actual publication.
  No partial stdout or destination artifact is published while chunks arrive.

The payload hasher keeps its existing invalid-canonical-JSON diagnostic; size
checks and publication encoding keep their invalid-JSON diagnostic. Overflow
stops consumption at the first excessive chunk. Normalization errors still
precede encoding, while later encoding errors can be preempted by overflow.
A late hashing error returns no partial digest and prevents signing. Private
key loading still precedes payload hashing in the existing signing sequence;
this slice does not claim that late hash failure avoids that prior key access.

## Compatibility and limits

Tests compare exact boundaries and no-copy/no-retention behavior, then compare
payload digests and same-key signatures against the legacy encoding and hashing
path. Schemas, signer identity and note requirements, trusted-key pinning,
general `canonical_json`/`sha256_of`, per-record validation, signature statement
bytes, and no-overwrite file publication are unchanged.

Input and selected records remain materialized. Full canonical normalization,
sorting, individual encoder tokens, per-record hashing, and the canonical
signed-document copy retain their existing allocations. Publication still
returns a complete bounded byte buffer. This is not a fixed process-memory or
CPU quota, streaming signature, detached caller-state guarantee, or change to
evidence retention. Separate size, validation, hashing, and copying observations
are not made atomic; trusted in-process callers must still avoid mutation.

Command Core and Command Center remain unchanged and strictly read-only.
No DKE or Spartan capability is introduced.
