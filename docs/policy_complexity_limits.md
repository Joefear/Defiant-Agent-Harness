# Policy complexity limits

Defiant v0.33 bounds the complete policy ruleset before rule construction,
normalization, hashing, or governed-action evaluation. The existing 1 MiB
ceiling remains in force for each YAML policy pack; these additional ceilings
prevent many individually valid packs or many small matcher entries from
creating unbounded repeated work.

## Fixed ceilings

- 64 loaded policy packs;
- 4,096 policy rules across all packs;
- 4,096 known-tool patterns across all packs;
- 4,096 items in any one rule list field; and
- 65,536 total items across all rule list fields.

Rule list fields are `tools`, `targets`, `payload_contains`, `sensitivities`,
and `redactions`. Registry-provided additional known tools participate in the
same pack and known-tool totals. Duplicate entries count as supplied; callers
cannot evade a ceiling through later sorting or deduplication.

The pack-count check occurs before any requested policy file is opened. The
remaining checks run over the parsed direct YAML tree before `Rule` objects are
constructed or the ruleset hash is calculated. An oversized configuration is
rejected as a whole, creates no state or workspace, and cannot partially extend
authority.

## Operational behavior

These values are implementation contracts, not environment variables or policy
settings. Splitting one large policy into more files does not increase the
complete-ruleset ceilings. Operators whose reviewed rulesets exceed a ceiling
must reduce or consolidate policy rather than weakening the control at runtime.

Command Core schema `0.67.0` publishes the five fixed ceilings under
`resource_limits`. Command Center displays them with the other static limits.
Both surfaces remain strictly read-only: they cannot upload a pack, change a
limit, grant an exception, or activate policy.

## Limits of the control

These ceilings bound collection-driven policy work; they are not a wall-clock,
CPU, or memory quota. v0.38 separately bounds action-controlled glob subjects
and aggregate glob comparisons, but does not prove that a rule is correct,
replace adversarial policy tests, or contain a compromised host.

v0.36 adds per-item and aggregate character ceilings for the recognized text
inside these bounded collections. See `policy_text_limits.md`.

v0.37 separately bounds governed payload materialization and aggregate
substring-search work. See `policy_payload_matching_limits.md`.

v0.38 separately bounds tool/target glob subjects and aggregate glob work. See
`policy_glob_matching_limits.md`.

v0.39 separately bounds canonical action fingerprints. See
`action_hashing_limits.md`.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
