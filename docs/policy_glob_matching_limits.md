# Policy glob matching limits

Defiant v0.38 bounds action-controlled subjects and aggregate work for policy
glob matching. Earlier releases bounded policy pattern text and collection
counts, but one decision could still compare a long tool name or target against
many `known_tools`, rule `tools`, and rule `targets` patterns.

## Fixed ceilings

- tool-name glob subject before and after platform normalization: 4,096
  characters;
- target glob subject before and after platform normalization: 1,048,576
  characters; and
- aggregate glob work per policy decision: 67,108,864 units.

One attempted comparison costs the normalized subject length plus the
normalized pattern length. The budget is shared by known-tool classification
and every rule tool/target comparison. Patterns are tested in their existing
order and stop at the first match, preserving `fnmatch.fnmatch` semantics and
prior short-circuit behavior. Exact limits are accepted.

The subject ceiling is lazy. A tool name is checked only when the loaded policy
has `known_tools` or an evaluated rule has `tools`. A target is checked only
when a rule has already passed its tool and side-effect conditions and then
reaches `targets`. Actions that never use a subject for glob matching do not
acquire a new length restriction.

Policy patterns retain the v0.36 per-item 4,096-character and complete-ruleset
8,388,608-character authority ceilings. The v0.33 pattern-count ceilings also
remain in force.

## Evaluation and failure behavior

One decision-scoped match state accounts for known-tool classification and all
rule evaluation. v0.38 also removes the duplicate tool/target prefix pass that
v0.37 used to decide whether payload materialization was needed. The searchable
payload is now created lazily by the first otherwise-applicable
`payload_contains` rule and remains shared for the decision.

Exceeding a subject or work ceiling produces a deterministic `block` with the
stable policy id `policy_match_limit`. The reason names only the fixed ceiling.
Glob-limit decision inputs omit both tool name and target, and contain only the
side-effect level, policy name, and limit class. Normal access-controlled
evidence still retains the action fields required by the evidence contract;
the sanitized diagnostic does not add or echo the rejected subject. No tool is
executed and no approval is created.

## Read-only projection

Command Core schema `0.37.0` publishes all three ceilings under
`resource_limits` and reports `policy_glob_match_preflight: true` in the static
authority posture. Command Center renders the values. Neither surface can
change a limit, grant an exception, upload policy, approve, or execute.

## Limits of the control

Work units are a deterministic implementation budget, not measured CPU time.
This control does not replace the Python runtime's glob implementation, impose
process-wide CPU/memory/wall-clock quotas, or contain a compromised host. v0.39
separately bounds action payload and authorization fingerprints; v0.40 bounds
the fixed request context supplied to policy. Deployment review, monitoring,
and OS resource controls remain necessary.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
