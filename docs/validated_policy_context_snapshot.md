# Validated policy context snapshot

Defiant v0.57 treats policy evaluation context as authority-bearing request
metadata. `PolicyEngine.evaluate()` captures one bounded exact string mapping
before any rule can inspect it, then retains that same observation in the
resulting decision evidence.

## Context contract

The public evaluation boundary accepts `None` or a mapping with:

- at most 64 entries;
- string keys no longer than 256 characters;
- string values no longer than 4,096 characters; and
- at most 262,144 aggregate key and value characters.

The harness supplies only `sensitivity`, `task_type`, and `workspace_id`, all as
strings. Context is metadata, not a payload transport; callers must place bulk
or structured content in the governed action contract instead.

## One observation

Snapshot capture reads built-in dictionary storage directly. Dictionary
subclass truth, length, iteration, key, item, and lookup overrides are not used.
Accepted string subclasses are normalized to exact built-in strings without
calling their formatting or length hooks. Entry count, key identity, types,
per-field text, and aggregate text are checked while constructing the owned
snapshot.

Rules and decision attribution both consume that snapshot. Caller mutation
after capture therefore cannot make the recorded context disagree with the
observation that selected a policy rule.

## Failure behavior

Wrong root or member types, ambiguous normalized keys, mutation detected during
capture, and any exceeded ceiling produce a deterministic `block` decision
with policy id `policy_context_contract`. The reason and `limit_enforced` alias
identify only the violated contract; rejected keys and values are not retained
or rendered. Rule matching does not begin after a context failure.

## Read-only projection

Command Core schema `0.63.0` publishes the four fixed ceilings under
`resource_limits` and reports `validated_policy_context_snapshot: true` under
`authority_configuration`. Command Center renders only those constants and the
static posture. It cannot submit context, change a limit, reevaluate a decision,
approve, reconcile, or execute.

## Boundary

This is deterministic ownership of data crossing the policy API, not thread
transaction isolation or a Python sandbox. Code already trusted inside the
harness process can replace private engine state or the engine itself and still
requires process and host isolation.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
