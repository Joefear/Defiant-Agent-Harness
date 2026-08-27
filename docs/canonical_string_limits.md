# Canonical string limits

Defiant v0.44 preflights JSON string escaping for every string that crosses the
shared canonical hashing boundary. Direct in-memory callers can supply a value
that fits the 8,388,608-character scalar ceiling but expands substantially when
canonical JSON escapes control, non-ASCII, or non-BMP code points.

## Fixed ceiling

One canonical string token, including its opening and closing quotation marks,
accepts at most 67,108,864 ASCII bytes. This ceiling applies to strings used in:

- pre-adapter tool calls;
- governed payload and authorization fingerprints;
- provenance content; and
- post-execution tool-result output.

Exact limits are accepted. The complete canonical value retains its separate
67,108,864-byte ceiling, so mapping syntax, sequence syntax, separators,
numbers, and multiple accepted strings still count toward the whole value.

Failure raises a sanitized `ActionHashLimitError` with
`action_hash_string_token_bytes`. Tool-call and tool-result owners map that to
`tool_call_string_token_bytes` and
`tool_result_output_string_token_bytes` respectively.

## Pre-render behavior

Defiant counts the exact ASCII width produced by Python's existing
`ensure_ascii=True` canonical JSON contract without constructing the escaped
token. It accounts for quotation marks, printable ASCII, short control escapes,
six-byte `\uXXXX` escapes for other BMP code points, and paired escapes for
non-BMP code points.

A token that cannot fit is therefore refused before `JSONEncoder.iterencode()`
can allocate its expanded representation. Accepted canonical bytes and hashes
remain unchanged.

## Read-only projection

Command Core schema `0.44.0` publishes
`action_hash_string_token_bytes`, `tool_call_string_token_bytes`, and
`tool_result_output_string_token_bytes` under `resource_limits`, plus
`canonical_string_preflight: true`. Command Center renders only this static
posture. Neither surface can change a ceiling, submit data, approve, reconcile,
or execute.

## Limits of the control

This bounds one encoded string token and prevents its pre-rejection expansion.
It does not impose a cumulative process quota, contain trusted Python already
inside the harness process, or replace the complete canonical byte ceiling.

This release adds no DKE, Spartan, remote Command, or Command Center authority.

v0.45 separately preflights the complete canonical value before sorting or
encoding. See `canonical_value_preflight.md`.
