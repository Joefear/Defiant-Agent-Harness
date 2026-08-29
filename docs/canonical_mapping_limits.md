# Canonical mapping limits

Defiant v0.46 limits every mapping in an action-controlled canonical value to
65,536 entries. Canonical JSON sorts mapping keys before hashing. Earlier
releases bounded total nodes and exact encoded bytes, but a mapping that fit
both ceilings could still approach the 1,100,000-node allowance and force a
disproportionately large key sort.

## Fixed preflight

The structural preflight checks a mapping's entry count before visiting its
keys or values and before `sort_keys=True` or `JSONEncoder.iterencode()` can
run. Exact limits pass. A mapping with 65,537 entries fails with the sanitized
`action_hash_mapping_entries` limit; neither keys nor values are included in
the error.

The ceiling applies independently to every nested mapping. The existing
1,100,000-node and 67,108,864-byte limits continue to bound the complete value,
so splitting entries across many smaller mappings cannot make total traversal
or canonical output unbounded. The streaming canonical-byte counter remains a
separate defense-in-depth check.

Tool-call construction maps the shared failure to
`tool_call_mapping_entries`. Tool-result capture maps it to
`tool_result_output_mapping_entries`. No policy decision, approval,
reservation, grant, terminal result, or evidence claim is created for a value
that fails its owning preflight.

## Compatibility

This is a deliberate production ceiling, not only earlier enforcement of an
existing limit. A previously accepted in-memory mapping with more than 65,536
entries is now refused even when its structure and encoded bytes satisfy the
older aggregate ceilings. Canonical bytes and hashes for accepted values are
unchanged.

## Read-only projection

Command Core schema `0.64.0` publishes the action, tool-call, and tool-result
aliases under `resource_limits` and reports
`canonical_mapping_preflight: true`. Command Center renders only these fixed
values and posture. It cannot submit a mapping, change a ceiling, approve,
reconcile, or execute.

## Limits of the control

This bounds the largest individual sort and combines with the existing
aggregate node and byte ceilings. It is not a CPU timeout, a cumulative traffic
quota, an operating-system sandbox, or protection from trusted Python already
running in the harness process. Accepted mappings still require deterministic
key sorting, and repeated accepted requests still require deployment-level
monitoring and isolation.

This release adds no DKE, Spartan, remote Command, or Command Center authority.

v0.47 separately bounds aggregate key-comparison amplification across all
mappings in one fingerprint. See `canonical_mapping_sort_work.md`.

v0.48 separately validates key eligibility and sortable families before values
or encoder sorting. See `canonical_mapping_key_contract.md`.
