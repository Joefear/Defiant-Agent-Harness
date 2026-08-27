# Validated scalar ownership

Defiant v0.53 normalizes accepted scalar subclasses to exact built-in values
before canonical hashing or governed-contract ownership. Earlier validated
snapshots detached built-in containers, but could retain caller-defined
subclasses of strings, integers, floats, and decimals. Those objects could
carry custom comparison, hashing, formatting, or copy behavior into later
policy, registry, approval, persistence, or evidence work.

## Covered values

The shared canonical snapshot converts accepted scalar values as follows:

- string subclasses become exact `str` values;
- integer subclasses, including accepted integer-backed enums, become exact
  `int` values;
- float subclasses become exact `float` values;
- Decimal subclasses become exact `Decimal` values before their established
  bounded canonical string conversion; and
- accepted mapping-key subclasses become exact built-in keys.

Enum values retain their existing recursive normalization. Boolean and null
values are already exact built-ins. Container subclasses continue to be read
through built-in storage as documented for v0.50.

If distinct exotic mapping keys normalize to the same canonical built-in key,
the mapping is refused as non-canonical. Defiant never silently drops or
overwrites one value. Ordinary accepted mappings retain identical key order
semantics, canonical bytes, and SHA-256 digests.

## Governed contracts

The same rule applies to scalar fields retained by:

- `ContentRef` provenance;
- `HarnessRequest` identity, scope, timestamps, and allowlist entries;
- `ProposedAction` identity, target, timestamps, cost, and canonical payload;
- pre-adapter `ToolCall` identity and canonical arguments; and
- post-execution `ToolResult` status, summary, cost, and canonical output.

Construction performs the first normalization. The owning seal repeats it so a
caller cannot replace an unsealed field with a scalar subclass between
construction and submission. Later authority work therefore receives exact
built-in scalar values rather than caller-defined hooks.

Existing resource ceilings and sanitized owner-specific error aliases are
unchanged. Rejected pre-execution values do not enter policy, approval,
reservation, evidence, grant, adapter, or execution work. A rejected tool
result may follow a side effect that already happened; it cannot become
terminal evidence input, and the existing explicit reconciliation workflow
remains responsible for that uncertain outcome.

## Read-only projection

Command Core schema `0.53.0` reports `validated_scalar_ownership: true`.
Command Center renders only this static posture. It cannot submit a scalar,
alter normalization or limits, approve, reconcile, authorize, or execute.

## Limits of the control

This is deterministic contract ownership, not general thread isolation or a
Python sandbox. It governs values crossing Defiant's declared contract and
canonical-hash boundaries. Code already executing inside the process remains
part of the trusted computing base, and deployment controls remain responsible
for cumulative CPU, memory, wall-clock, filesystem, and network containment.

This release adds no DKE, Spartan, remote Command, or Command Center authority.

v0.54 extends this ownership rule to policy decisions, capability grants, and
evidence records. See `validated_authority_record_ownership.md`.
