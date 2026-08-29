# Validated authority-record ownership

Defiant v0.54 extends validated ownership to the authority records created
after action evaluation: `GuardrailDecision`, `CapabilityGrant`, and
`EvidenceRecord`. These objects sit between policy, execution authority, and
durable evidence, so they must not retain caller-defined scalar or container
behavior after their contract has been accepted.

## One bounded observation

Decision policy identifiers and redactions, decision inputs, evidence policy
identifiers, and evidence input references are captured from built-in list and
mapping storage under the established canonical depth, node, scalar, number,
mapping, sort-work, and byte ceilings. Accepted nested values become detached
built-in snapshots. Distinct exotic mapping keys that collide after scalar
normalization remain non-canonical and are refused.

All retained text fields become exact `str` values. Capability-grant claims
repeat this normalization immediately before signing, verification, and spend.
Evidence records repeat full record normalization immediately before producing
a body, sealing a chain link, or serializing. Decimal subclasses become exact
`Decimal` values before use.

The result is that `asdict()`, canonical hashing, HMAC signing, evidence JSON
serialization, and later comparisons see only validated built-in state. They
do not invoke caller-defined iteration, key-view, string, numeric, formatting,
or deep-copy hooks retained by an accepted authority record.

## Evidence and budget behavior

Evidence still records an actual model or tool overrun honestly. A finite
negative `budget_remaining_usd` is normalized and rendered with a bounded
canonical signed-decimal representation. This does not relax the non-negative
rule for grants, estimates, reservations, settlements, or `cost_usd`.

An invalid post-execution record cannot be converted into fabricated terminal
evidence. If an external effect may already have occurred, the sealed
authorization and conservative reservation remain subject to the existing
explicit reconciliation workflow.

## Read-only projection

Command Core schema `0.61.0` reports
`validated_authority_record_ownership: true`. Command Center renders only this
static posture. It cannot submit or alter a decision, grant, evidence record,
budget value, approval, reconciliation, policy, or execution.

## Limits of the control

This control owns declared authority-record data; it is not a Python or
operating-system sandbox. Code already executing inside the harness process is
trusted, and deployment controls remain responsible for cumulative CPU,
memory, wall-clock, filesystem, and network containment.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
