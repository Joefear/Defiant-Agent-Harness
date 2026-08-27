# JSON structural limits

Defiant v0.30 advances the shared authority JSON profile to `strict_json_v2`.
Every caller of `loads_strict_json()` now receives a structural preflight before
Python's JSON decoder constructs objects:

- maximum container nesting depth: 64; and
- maximum lexical tokens: 1,000,000.

Both values are fixed implementation contracts, not environment variables or
operator-tunable policy.

## Lexical contract

The scanner decodes byte input as strict UTF-8 first, then makes one pass over
the resulting text without constructing a token list or object graph. It tracks
JSON string and escape state so punctuation inside strings has no structural
effect.

A lexical token is counted for each opening object or array delimiter, each
string opening quote (including object keys), and each maximal scalar run
outside strings and JSON punctuation. Closing delimiters, commas, colons, and
whitespace do not count. Container depth increases on `{` or `[` and decreases
on a closing delimiter. A document exactly at either limit is accepted for
normal decoding; the next depth or token is refused.

The preflight is deliberately not a second JSON parser. It does not accept a
document or interpret fields. If input is structurally within the ceilings,
the existing strict decoder still validates syntax, rejects duplicate keys at
every depth, and rejects non-finite numbers.

## Failure behavior

Over-depth and over-token input fails before `json.loads()`. Durable state is
invalid, an evidence record breaks chain verification, an MCP client receives a
parse error, an ambiguous upstream transport terminates without forwarding,
and native hooks return their existing fail-closed response before creating
state. Diagnostics name only the boundary and configured ceiling; they do not
echo keys, strings, values, snippets, targets, payloads, or state paths.

The shared profile covers durable JSON, evidence JSONL records, MCP stdio and
HTTP/SSE messages, native-hook events and embedded arguments, operator key-list
documents, evidence exports, and external evidence witnesses.

## Read-only projection

Command Core schema `0.53.0` exposes the current `strict_json_v3` profile, the
two structural ceilings, and structural-preflight posture. Command Center
renders those values with the other fixed resource limits. Neither surface
accepts JSON, changes a ceiling, adds an exception, retries input, repairs
state, or creates authority. v0.31 adds independent per-scalar limits; see
`json_scalar_limits.md`.

## Limits

The scanner reduces decoder recursion and many-small-value amplification. It
does not provide a CPU quota, process memory cap, streaming JSON decoder,
schema-specific collection limits, truth guarantee, or OS containment. Existing
byte ceilings remain responsible for total document size at their respective
boundaries; evidence-history verification remains linear in retained records.

v0.31 bounds individual string and number tokens without changing these
structural definitions or ceilings.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
