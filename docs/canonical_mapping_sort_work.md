# Canonical mapping sort-work limits

Defiant v0.47 applies a fixed aggregate work budget before canonical JSON sorts
mapping keys. v0.46 capped every mapping at 65,536 entries, but a valid mapping
could still devote much of the 67,108,864-byte canonical ceiling to long keys
with shared prefixes. Repeated comparison rounds could therefore multiply the
key text inspected during sorting.

## Deterministic cost model

For each mapping, preflight calculates:

`canonical key-token bytes * ceil(log2(mapping entries))`

The comparison-round factor is zero for empty and single-entry mappings. Key
width is the exact quoted `ensure_ascii=True` JSON representation already used
by canonical byte preflight, including supported non-string key forms. Work is
charged across every mapping in the complete value against one fixed budget of
67,108,864 units. Exact budgets pass.

This is a stable conservative resource model, not an attempt to count
implementation-specific CPython Timsort comparisons. It captures both key
volume and the logarithmic comparison depth implied by mapping cardinality
without sorting, copying, or rendering the mapping first.

When the next key would exceed the budget, preflight raises the sanitized
`action_hash_mapping_sort_work_units` limit before visiting that key's value and
before `sort_keys=True` or `JSONEncoder.iterencode()` can run. Tool-call and
tool-result owners map the same refusal to
`tool_call_mapping_sort_work_units` and
`tool_result_output_mapping_sort_work_units`.

The existing 65,536-entry per-mapping ceiling, 1,100,000-node aggregate
ceiling, 67,108,864-byte canonical ceiling, and streaming byte check remain in
force independently.

## Compatibility

This is a new production ceiling. Some previously accepted values with large
or numerous mapping keys are now refused even if they fit the existing entry,
node, and canonical-byte limits. Accepted canonical bytes and hashes are
unchanged.

## Read-only projection

Command Core schema `0.58.0` publishes the action, tool-call, and tool-result
budgets under `resource_limits` and reports
`canonical_mapping_sort_preflight: true`. Command Center renders only those
fixed values and posture. It cannot submit a value, change a budget, approve,
reconcile, or execute.

## Limits of the control

The model bounds deterministic per-fingerprint admitted work; it is not a
wall-clock timeout, exact CPU counter, cumulative traffic quota, or
operating-system sandbox. Accepted mappings still sort, Python code already
running inside the harness process remains trusted, and repeated accepted
requests still require deployment monitoring and isolation.

This release adds no DKE, Spartan, remote Command, or Command Center authority.

v0.48 separately refuses unsupported or mutually unsortable key families
before values or encoder sorting. See `canonical_mapping_key_contract.md`.
