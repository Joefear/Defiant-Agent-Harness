# Validated policy snapshot ownership

Defiant v0.55 makes the policy state retained by `PolicyEngine` the same
bounded observation from which it constructs rules and publishes
`ruleset_hash`.

## Authority boundary

Policy configuration can enter through strictly parsed YAML, loaded policy
packs, registry-supplied known-tool patterns, or programmatic authority inputs.
Before v0.55, the engine hashed that configuration at construction time but
could retain references to caller-owned nested lists and mappings. Mutating an
original rule list or authority-input mapping later could therefore change
future policy decisions or decision inputs while the published hash continued
to identify the earlier state.

The engine now:

- captures policy packs and authority inputs under the stable 64 MiB canonical
  authority snapshot profile;
- reads built-in list and mapping storage without invoking subclass iteration,
  lookup, string-conversion, or deep-copy hooks;
- normalizes accepted scalar subclasses and mapping keys to canonical built-in
  values;
- runs the existing policy pack, rule, known-tool, list, and text ceilings on
  the detached policy tree;
- constructs `Rule` objects and known-tool state only from that tree; and
- hashes the retained rules, tools, and detached authority inputs using the
  existing canonical ruleset shape.

Ordinary accepted policy configuration produces the same `ruleset_hash` as
before. Unsupported, cyclic, over-limit, or mutation-inconsistent canonical
data fails closed with a sanitized policy-configuration error.

## Stable limits

Policy authority capture uses the fixed authority snapshot profile recorded
when the contracts module loads. Tests or trusted code that change live
action-hash limit constants cannot silently loosen or tighten policy ownership
afterward. Policy-specific count and text ceilings still apply independently
after capture.

## Read-only projection

Command Core schema `0.51.0` reports
`validated_policy_snapshot_ownership: true` under
`authority_configuration`. Command Center renders that posture only as text in
its fixed-limit summary. Neither surface receives policy contents, changes a
rule, replaces authority inputs, or exposes an execution or approval control.

## Limits

This is a deterministic data-ownership guarantee, not an operating-system
sandbox or general transaction system. Concurrent mutation at the instant an
input snapshot is taken fails when detectable, but callers must still
synchronize shared memory. v0.56 additionally seals the public runtime state
derived from this snapshot; see `sealed_policy_runtime_state.md`. Python code
already trusted inside the harness process can still modify private memory or
replace the engine. Operators must protect policy files, review
classifications, and use process and host isolation appropriate to their
deployment.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
