# JSON scalar limits

Defiant v0.31 advances the shared authority JSON profile to `strict_json_v3`.
After strict UTF-8 decoding and during the existing non-materializing lexical
preflight, every JSON scalar is subject to fixed source-token ceilings:

- maximum string token: 8,388,608 source characters; and
- maximum number token: 1,024 source characters.

The values are implementation contracts, not environment variables or
operator-tunable policy. A document exactly at a ceiling proceeds to normal
strict decoding; the next character is refused before `json.loads()`.

## Lexical contract

String length counts the source characters between opening and closing quotes.
Escape syntax counts as written, so `\\n` consumes two source characters. The
scanner remains escape-aware, and an escaped quote cannot end a token early.
The ceiling applies equally to object keys and string values.

Number length counts the complete maximal scalar run beginning with `-` or an
ASCII digit, including a sign, integer digits, decimal point, fractional
digits, exponent marker, exponent sign, and exponent digits. The preflight does
not accept or normalize malformed numeric syntax; documents within the ceiling
still pass through Python's JSON syntax validation.

The decoder now also verifies that a syntactically finite floating-point token
produces a finite runtime value. Extreme exponents that would otherwise convert
to positive or negative infinity are refused under the same non-finite-number
contract. The 1,024-character token ceiling keeps integer conversion behavior
deterministic across supported Python 3.10 through 3.14 runtimes.

## Failure behavior

Oversized scalar tokens fail before object construction. Durable state becomes
invalid, an evidence record breaks chain verification, an MCP client receives
a parse error, an ambiguous upstream transport is not forwarded, and native
hooks return their existing fail-closed response before creating state.
Diagnostics contain only the affected boundary, token class, and fixed ceiling;
they never echo a key, value, number, snippet, target, payload, or state path.

The shared profile covers durable JSON, evidence JSONL records, MCP stdio and
HTTP/SSE messages, native-hook events and embedded arguments, operator key-list
documents, signed evidence exports, and external evidence witnesses.

## Read-only projection

Command Core schema `0.65.0` exposes `strict_json_v3`, both scalar ceilings,
scalar-preflight posture, and the existing structural and representation
controls. Command Center renders the static values with the other fixed limits.
Neither surface accepts JSON, changes a ceiling, retries rejected input,
repairs state, or creates authority.

## Limits

These ceilings reduce single-token conversion and allocation amplification.
They do not provide a CPU quota, process memory cap, streaming decoder,
schema-specific field limit, truth guarantee, or OS containment. Existing byte,
nesting, and lexical-token ceilings remain independently enforced. The string
limit measures source characters after byte decoding, not decoded Unicode size
or application-level semantic length.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
