# Strict JSON integrity

Defiant v0.28 applies one `strict_json_v1` parser profile to authority-relevant
JSON input. Durable state, evidence JSONL records, MCP client and upstream
messages, Streamable HTTP JSON/SSE data, native-hook events and embedded tool
arguments, operator key-list environment inputs, signed evidence exports, and
external evidence witnesses no longer accept ambiguous duplicate keys.

v0.30 advances that shared contract to `strict_json_v2`. Before the decoder
constructs Python objects, a lexical scan rejects more than 64 nested containers
or more than 1,000,000 lexical tokens. See `json_structural_limits.md`.

v0.31 advances the contract to `strict_json_v3`. The same scan rejects strings
over 8,388,608 source characters and number tokens over 1,024 source characters
before conversion. A finite JSON spelling that overflows to a non-finite
runtime float is also refused. See `json_scalar_limits.md`.

## Parser contract

The shared profile:

- accepts text or bytes and requires bytes to be strict UTF-8;
- rejects duplicate object keys at every nesting depth;
- rejects `NaN`, positive infinity, and negative infinity;
- rejects excessive nesting or lexical-token counts before object construction;
- rejects excessive string and number token lengths before object construction;
- fails closed on malformed JSON; and
- reports only the boundary and a sanitized reason, never a rejected key,
  value, source snippet, target, payload, or absolute state path.

At boundaries covered by v0.26, the existing byte ceilings remain pre-parse.
The strict JSON profile does not raise those limits or add a second input path.
v0.29 adds a 64 MiB aggregate ceiling before signed-export file parsing and
applies the same bound before export publication and direct sign/verify work.
See `bounded_evidence_exports.md`.

## Failure behavior

Ambiguous durable JSON invalidates the affected store and blocks new authority.
An ambiguous evidence record invalidates the chain before its fields or hash are
interpreted. A duplicate-key MCP client request returns JSON-RPC parse error
`-32700`; an ambiguous stdio or HTTP upstream response fails the transport and
is never forwarded. Native hooks return their existing fail-closed response
before creating state or invoking the shared gate.

This matters even when both values appear harmless. Last-key-wins behavior can
make a reviewed `method`, `decision`, `status`, `cost`, or target differ from the
value the runtime uses. Defiant therefore refuses the whole document rather
than choosing an interpretation.

## Read-only projection

Command Core schema `0.68.0` exposes `strict_json_v3`, strict UTF-8, structural
and scalar-preflight limits, duplicate-key refusal, and non-finite-number
refusal beside the existing YAML posture. Command Center renders this static
metadata read-only. Neither surface accepts JSON, changes a parser option or
limit, repairs state, retries a transport, or creates authority.

## Limits

Strict parsing removes representation ambiguity; it does not prove that a
unique document is truthful, correctly classified, or authorized. In-process
Python remains trusted, evidence verification remains linear in retained
history, and OS/process containment remains a deployment responsibility.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
