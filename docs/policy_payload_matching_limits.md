# Policy payload matching limits

Defiant v0.37 bounds the governed-action work performed by
`payload_contains` policy rules. Policy text and collection limits constrain
operator authority, but a large or deeply nested action payload could still be
flattened once per rule and searched repeatedly during one decision.

## Fixed ceilings

- flattened payload nesting depth: 64 containers/scalars;
- visited payload nodes: 100,000;
- flattened, case-normalized payload text: 1,048,576 characters; and
- aggregate payload substring work per decision: 67,108,864 units.

The node count includes the root and every visited mapping, sequence, and
scalar. Mapping keys are not searchable and do not count separately; values
retain insertion order. Lists and tuples retain element order. Nested values
retain the prior single-space join semantics, including separators adjacent to
empty collections. Exact limits are accepted.

Substring work is charged for each term actually tested after that rule's
tool, side-effect, and target conditions pass. One test costs the length of the
normalized payload text plus the normalized term. Work accumulates across all
rules in the decision and stops at the first matching term in each rule, as it
did before v0.37.

## Evaluation and failure behavior

Unknown tools are still refused before payload traversal. If no
`payload_contains` rule passes its tool, side-effect, and target conditions,
the payload is not materialized for matching. Otherwise Defiant flattens and
normalizes it exactly once and shares that immutable text across the rule
evaluation.

Exceeding any ceiling returns a normal deterministic `block` decision with the
stable policy id `policy_match_limit`. The reason identifies only the fixed
limit. Its decision inputs contain the tool, side-effect level, policy name,
and limit class; they exclude the payload, target, rejected text, and substring
terms. The control loop records the block in the append-only evidence chain and
does not execute or create an approval.

This is a fail-closed runtime decision, not invalid authority. The active
policy version and ruleset hash remain attached so the event is attributable.

## Read-only projection

Command Core schema `0.45.0` publishes the four ceilings under
`resource_limits` and reports `policy_payload_match_preflight: true` in the
static authority posture. Command Center renders those values. Neither surface
can change a limit, exempt an action, upload policy, approve, or execute.

## Limits of the control

This bounds payload flattening and deterministic substring-search work. v0.38
separately bounds tool/target glob subjects and aggregate glob work; see
`policy_glob_matching_limits.md`. v0.39 separately bounds canonical action
fingerprints. Python scalar `str()` behavior in payload matching for non-JSON
direct callers, total process CPU or memory, and wall-clock time remain outside
this control.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
