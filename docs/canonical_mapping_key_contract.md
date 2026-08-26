# Canonical mapping-key contract

Defiant v0.48 validates mapping-key eligibility and sort compatibility before
canonical JSON visits mapping values or sorts keys. Earlier structural
preflight counted exact key bytes and deterministic sort work, but mixed key
families and unsupported key objects still reached `sort_keys=True`, where the
JSON encoder rejected them only after sorting began.

## Pre-sort contract

Each mapping first receives one bounded key-only pass after its 65,536-entry
ceiling is checked. The pass accepts the same key families that already encoded
successfully:

- string keys, including string-backed enum subclasses;
- numeric `int`, finite `float`, and `bool` keys, including `IntEnum`;
- a single `None` key; and
- empty mappings.

All keys in a multi-entry mapping must belong to one mutually sortable family:
string or numeric. `None` mixed with another key, string/numeric mixtures,
`Decimal`, plain `Enum`, and arbitrary objects are refused. The pass uses no
key comparison operator and performs no sort.

Unsupported or mixed keys fail with the same sanitized
`ValueError("action hash input is not canonical JSON data")` already produced
by the encoder. Tool-call and tool-result owners therefore retain their
existing `tool_call_contract` and `tool_result_output_contract` failures. Keys,
values, and exception details are not echoed.

v0.49 completes the key-only pass before values: every eligible key receives
the existing numeric, string, node, canonical-byte, and aggregate sort-work
checks before mapping value traversal begins. See
`complete_mapping_key_preflight.md`.

## Compatibility

The accepted canonical surface does not change. Every mapping that encoded and
hashed successfully before v0.48 retains identical canonical bytes and hashes.
Mappings rejected by the older encoder are rejected earlier with the same
sanitized public failure type and owning contract classification.

## Read-only projection

Command Core schema `0.43.0` reports
`canonical_mapping_key_preflight: true` and
`complete_mapping_key_preflight: true`. Command Center renders only that static
posture. It cannot submit a mapping, alter the contract, approve, reconcile, or
execute.

## Limits of the control

The preflight handles built-in canonical key families and trusted subclasses;
it is not an operating-system sandbox against malicious Python already running
inside the harness process. It does not call comparison operators, prove
business meaning, impose a process-wide traffic quota, or replace the existing
sort-work budget and deployment isolation.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
