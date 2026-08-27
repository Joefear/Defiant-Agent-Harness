# Policy text complexity limits

Defiant v0.36 bounds text volume across one complete loaded policy ruleset.
The existing 1 MiB ceiling applies to each policy YAML document and v0.33 caps
collection counts, but up to 64 individually valid packs could still carry a
large aggregate of patterns, terms, descriptions, reasons, and redactions into
normalization, authority hashing, and governed-action matching.

## Fixed ceilings

- one recognized policy text item: 4,096 constructed characters; and
- all recognized policy text in the complete ruleset: 8,388,608 constructed
  characters.

The item ceiling applies to pack `version`, `name`, and `description`; every
`known_tools` value; rule `id`, `description`, `side_effect_at_least`,
`max_payload_trust`, `effect`, `reason`, and `approval_scope`; and every value
in `tools`, `targets`, `payload_contains`, `sensitivities`, and `redactions`.
The aggregate is the sum of those accepted string lengths across all packs.

Counts use the strings produced by strict YAML construction, not UTF-8 byte
length or YAML escape-source length. Duplicate text counts each time it is
supplied. The synthetic registry pack and its additional known-tool names use
the same per-item and aggregate budgets. Exact limits are accepted; the first
character beyond either limit is refused.

## Ordering and failure behavior

The preflight runs over the already bounded, ambiguity-free YAML tree alongside
the v0.33 collection-count checks. It completes before `Rule` objects are
constructed, rules or tool patterns are normalized, the complete ruleset is
hashed, or any governed action is evaluated. Direct `PolicyEngine`
construction uses the same checks. Invalid types and unknown fields remain
subject to the existing strict schema after the complexity preflight.

Failure rejects the complete ruleset and creates no partial policy authority.
Diagnostics report only the fixed item or aggregate ceiling. They do not echo
pack names, rule ids, match patterns, payload terms, descriptions, reasons,
redactions, or source paths.

## Read-only projection

Command Core schema `0.51.0` publishes `policy_text_item_characters` and
`policy_text_characters` under `resource_limits`, plus the static
`policy_text_preflight` posture. Command Center only renders these values. It
cannot upload policy, change a ceiling, grant an exception, activate a ruleset,
or execute an action.

## Limits of the control

This control bounds operator-authored policy text, not all matcher work. v0.37
adds governed-payload depth, node, text, and aggregate substring-work ceilings;
v0.38 adds tool/target glob-subject and aggregate-work ceilings. See
`policy_payload_matching_limits.md` and `policy_glob_matching_limits.md`.
v0.39 adds bounded canonical action fingerprints; process-wide resources and
host containment remain separate. See `action_hashing_limits.md`.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
