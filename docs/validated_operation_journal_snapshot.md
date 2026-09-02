# Validated operation-journal snapshot

Defiant v0.58 hardens the crash-recovery journal as an authority ownership
boundary. A prepared or loaded operation is now derived from one bounded
canonical snapshot, and its payload hash is computed from that exact
observation before recovery schema validation.

## Snapshot contract

Journal operations use the fixed authority canonical profile with an additional
4 MiB canonical-byte ceiling. Capture reads built-in dictionary, list, and tuple
storage directly, normalizes accepted scalar subclasses to exact built-ins,
detects container drift, refuses unsupported or cyclic values, and bounds
depth, nodes, mappings, sort work, strings, numbers, and encoded bytes.

The previous `deepcopy()` passes are gone. Caller copy, iteration, lookup,
formatting, comparison, and numeric hooks cannot create a second unvalidated
operation after capture. Schema validation and `payload_hash` both consume the
owned built-in snapshot.

## Sealed runtime payload

After validation, the journal recursively freezes its private payload tree.
The public `payload` property and `to_dict()` each return a fresh built-in
projection. Mutating the caller's original mapping or a returned projection
cannot change later recovery, durable serialization, or the retained hash.

As with other in-process seals, Python code already trusted inside the harness
can use private attributes or `object.__setattr__`; process isolation remains a
deployment control.

## Symmetric publication limit

`operation_journal.json` already had a 4 MiB recovery-read ceiling. v0.58 gives
the JSON writer the same store-specific ceiling. An over-limit prepared
operation fails before any approval, budget, or evidence store mutation, and a
partial temporary file is removed. The writer therefore cannot create a
journal that a restarted harness rejects solely because of size.

Journal schema `0.4.0` records newly written state. Readers continue to accept
schemas `0.1.0`, `0.2.0`, and `0.3.0`; accepted older entries are validated,
hashed, and sealed through the v0.58 runtime contract before recovery.

## Read-only projection

Command Core schema `0.71.0` publishes `operation_journal_bytes` under
`resource_limits` and reports `validated_operation_journal_snapshot: true`
under `authority_configuration`. The active-operation projection remains
limited to operation id, kind, and preparation time. Command Center receives no
payload, note, attestation, held action, recovery command, or mutation route.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
