# Sealed policy runtime state

Defiant v0.56 seals the in-memory policy state derived from the validated v0.55
configuration snapshot. The public `PolicyEngine` surface can no longer be
used to change enforcement after `ruleset_hash` is published.

## Runtime contract

At construction, the engine validates and hashes the same canonical policy
surface as v0.55, then adopts it as:

- frozen `Rule` records;
- immutable tuples for tool, target, payload-substring, sensitivity, and
  redaction patterns;
- an immutable tuple of known-tool patterns;
- read-only name, version, rules, known-tools, and ruleset-hash properties; and
- a recursively frozen private authority-input tree.

Reading `authority_inputs` returns a fresh built-in mapping/list projection.
Changing that projection cannot change the private tree used by later policy
decisions. Rule construction also snapshots its supplied pattern collections,
so later mutation of those original lists has no effect.

The canonical ruleset surface is hashed before its lists are represented as
tuples internally. Canonical JSON already represents tuples and lists
identically, so every ordinary policy accepted by v0.55 keeps the same
`ruleset_hash` in v0.56.

## Failure behavior

Assignments to public policy identity properties fail. Assignments to frozen
rule fields fail, and immutable pattern/known-tool tuples have no mutating list
operations. A caller may freely mutate an `authority_inputs` projection because
it owns only that detached copy; subsequent reads and decisions retain the
sealed values.

## Read-only projection

Command Core schema `0.57.0` reports `sealed_policy_runtime_state: true` under
`authority_configuration`. Command Center renders only that static posture in
its fixed-limit summary. It receives no policy contents and has no route or
control for rule mutation, policy replacement, approval, reconciliation, or
execution.

## Limits

This seal protects supported public references from accidental or integration
level mutation. Python code already trusted inside the harness process can use
private attributes, `object.__setattr__`, monkeypatching, memory modification,
or complete engine replacement. Defiant remains an authority data/control
boundary, not an in-process security sandbox; production deployment still
requires appropriate process and host isolation.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
