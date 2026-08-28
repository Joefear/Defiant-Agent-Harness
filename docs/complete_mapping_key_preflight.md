# Complete canonical mapping-key preflight

Defiant v0.49 completes validation of every canonical mapping key before the
first value in that mapping is traversed. v0.48 moved key-family eligibility
ahead of values and encoder sorting, but scalar, escaped-token, numeric, byte,
node, and sort-work checks still occurred one key at a time immediately before
that key's value. A late invalid key could therefore lose failure precedence to
an earlier unsupported or adversarial value.

## Key-first order

For each mapping, Defiant now performs these bounded phases:

1. check the fixed per-mapping entry ceiling without traversing keys or values;
2. check every key's eligible and mutually sortable family;
3. validate every key's complete canonical token and charge all key-controlled
   node, byte, and aggregate sort-work costs; and
4. only after every key passes, traverse mapping values and account for the
   remaining canonical syntax.

The complete key pass enforces the existing controls; it introduces no larger
limit and no new canonical representation. It covers scalar-character and
escaped-string-token bounds, finite floats, canonical integer/float/decimal
token bounds, node and nesting accounting, the complete canonical-byte budget,
and the aggregate deterministic mapping sort-work budget.

An oversized late string key, an overlong numeric key, a non-finite float key,
or an aggregate sort-work breach now fails before `items()` is used to traverse
mapping values and before `JSONEncoder.iterencode()` begins. Diagnostics remain
sanitized and never echo key or value content.

## Compatibility and owning failures

Accepted inputs retain byte-for-byte identical canonical JSON and SHA-256
hashes. The traversal order used only for preflight accounting changes; the
canonical encoder and its sorted-key output do not.

Pure key failures retain their existing public type and limit identifier.
Tool-call and tool-result boundaries continue to translate shared failures to
their `tool_call_*` and `tool_result_output_*` aliases. When one mapping contains
both an invalid late key and an invalid earlier value, the key failure now wins
deterministically because the key-controlled surface is completed first.

## Read-only projection

Command Core schema `0.56.0` reports
`complete_mapping_key_preflight: true` alongside the existing key-family,
mapping-size, sort-work, canonical-value, string, and number posture. Command
Center renders only static posture. It cannot submit input, alter limits,
approve, reconcile, or execute.

## Limits of the control

This is a per-fingerprint deterministic resource control, not a wall-clock
timeout or cumulative process quota. Accepted mappings still require value
traversal and encoder sorting. Trusted Python subclasses remain inside the
process trust boundary, and Python already executing in the harness process
still requires deployment isolation.

v0.50 additionally detaches the validated built-in structure before encoder
sorting, closing mutation between this key/value preflight and encoding. See
`validated_canonical_snapshot.md`.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
