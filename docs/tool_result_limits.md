# Tool result limits

Defiant v0.41 bounds and seals the result returned after a governed tool may
already have executed. Earlier releases bounded transport documents and action
fingerprints, but a local handler or direct external-completion caller could
still return an oversized, deeply nested, cyclic, or otherwise non-canonical
Python value. Hashing that value after execution could fail before terminal
evidence, budget settlement, or approval consumption.

## Fixed ceilings

One accepted `ToolResult` allows at most:

- 65,536 characters in its summary;
- 64 nested output mappings or sequences;
- 1,100,000 output nodes;
- 8,388,608 characters in one output string or canonical scalar; and
- 67,108,864 canonical UTF-8 bytes across the complete output.

Output must be canonical JSON-compatible data. Cyclic containers, unsupported
objects, non-finite numbers, and values outside a fixed ceiling are refused.
Exact limits are accepted. Failure messages identify the ceiling class without
echoing result content.

## Owning-boundary behavior

Construction performs an initial validation. Immediately before known-result
journaling, the owning harness validates scalar fields again, selects the
conservative completion cost, revalidates output, detaches it from
caller-owned containers, computes its bounded hash, and seals the complete
result contract. Later top-level mutation is refused.

If a local handler raises `ToolResultContractError` while constructing its
post-execution result, the tool registry does not translate that into an
ordinary terminal tool failure. The single-use capability has already been
spent, so Defiant preserves the pre-execution authorization and any budget
reservation. Approval-backed execution remains `executing`; approval-free
execution remains an open sealed authorization. Existing operator
reconciliation then requires an explicit outcome, identity, and note and never
replays the tool.

The same behavior applies when an external-completion caller supplies a result
that cannot be accepted. No terminal evidence or settlement is fabricated from
rejected output.

## Read-only projection

Command Core schema `0.36.0` publishes the summary and output ceilings under
`resource_limits` and reports `tool_result_contract_preflight: true`. Command
Center renders only that static posture plus the existing sanitized
reconciliation-required state. Neither surface can submit a result, change a
ceiling, reconcile, approve, or execute.

## Limits of the control

These ceilings bound one in-memory result and its canonical hash work. They do
not prevent a tool from performing a side effect before returning invalid
output, cap cumulative traffic or process resources, prove a tool's reported
status, or discover an external provider's actual outcome. Operator inspection
and reconciliation remain necessary when the post-execution contract fails.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
