# Bounded evidence exports

Defiant v0.29 places a fixed 64 MiB ceiling around each request-scoped evidence
export. The ceiling is an implementation contract, not an operator-tunable
policy value.

## Covered boundaries

The limit applies in four places:

- `dah verify-export` reads at most 64 MiB plus one byte and rejects an
  oversized file before UTF-8 decoding or JSON parsing;
- `dah export` refuses oversized serialized output before writing a file or
  emitting the document to standard output;
- `sign_export()` rejects an oversized payload and verifies that its completed
  signed document still fits; and
- `verify_export()` rejects an oversized direct in-memory document before
  structural, hashing, key-loading, or signature work.

The file boundary counts the exact bytes supplied or published. Direct
in-memory checks use deterministic compact JSON, while pretty-printed CLI/file
output must independently fit in the same ceiling. A document that fits only in
compact form therefore cannot be published in the standard pretty-printed
format.

Oversized input is not truncated, partially parsed, or partially written. The
diagnostic names only the evidence-export boundary and fixed byte ceiling; it
does not echo document content. Existing destinations retain the normal
no-overwrite rule.

## Read-only visibility

Command Core schema `0.63.0` publishes `evidence_export_bytes` under
`resource_limits`. Command Center renders that static value with the other
ceilings. Neither surface accepts an export, changes the limit, signs or
verifies a document, uploads a key, or mutates harness state.

## Deliberate limits

The ceiling bounds one handoff artifact. It does not cap, truncate, or compact
the live append-only evidence history, whose verification remains linear in
the total retained record count. An individual request whose selected records
cannot fit must be handed off through an externally reviewed segmentation or
retention workflow; Defiant does not silently split a cryptographically bound
export.

The ceiling is not a CPU quota, streaming signature format, confidentiality
control, retention policy, or proof of trusted time. Signed exports remain
point-in-time attestations and still require independently pinned public keys
and protected off-box retention.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
