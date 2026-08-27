# Canonical number limits

Defiant v0.43 bounds numeric rendering for every value that crosses the shared
canonical hashing boundary. Strict JSON ingress already rejects number tokens
over 1,024 characters, but direct in-memory callers could supply Python values
without passing through that textual parser.

## Fixed ceiling

Each canonical numeric token accepts at most 1,024 characters, including a
minus sign, decimal point, and exponent notation where applicable. The rule
applies to:

- integers inside tool calls, action fingerprints, provenance content, and
  tool-result output;
- finite Python floats; and
- non-negative `Decimal` values rendered through Defiant's existing
  non-exponent money-text contract.

Exact limits are accepted. Non-finite floats and decimals remain invalid.
Failure raises a sanitized `ActionHashLimitError` with
`action_hash_number_characters`; owning tool-call and tool-result contracts map
that to `tool_call_number_characters` and
`tool_result_output_number_characters` respectively.

## Pre-render behavior

Positive and negative integers are compared against a power-of-ten boundary,
so an oversized integer is rejected without first converting all its digits to
text. Negative values reserve one character for the sign.

For `Decimal`, Defiant validates finiteness and sign, caps coefficient digits,
then calculates the exact length of its canonical fixed-point form from
coefficient digits and exponent. Trailing fractional zeros follow the existing
canonical money-text rule within that coefficient ceiling. A large coefficient
or positive exponent is therefore refused before `format(value, "f")` can
materialize the expanded number.

Finite floats use their deterministic Python JSON token representation, which
is checked before the streaming JSON encoder runs. Canonical output for every
previously accepted value remains byte-for-byte unchanged.

As of v0.53, accepted integer, float, and Decimal subclasses are first converted
to exact built-in numeric values without invoking caller conversion or
formatting hooks. See `validated_scalar_ownership.md`.

## Read-only projection

Command Core schema `0.48.0` publishes
`action_hash_number_characters`, `tool_call_number_characters`, and
`tool_result_output_number_characters` under `resource_limits`, plus
`canonical_number_preflight: true`. Command Center renders only this static
posture. Neither surface can change a ceiling, submit data, approve, reconcile,
or execute.

## Limits of the control

This is a per-value encoding limit. It does not constrain arithmetic that
trusted code performs before handing a value to Defiant, cumulative work over
many accepted values, process memory, CPU time, or hostile Python already
running inside the harness process.

This release adds no DKE, Spartan, remote Command, or Command Center authority.

v0.44 separately preflights canonical string escape expansion. See
`canonical_string_limits.md`.
