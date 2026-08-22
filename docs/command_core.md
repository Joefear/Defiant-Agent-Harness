# Command Core

Command Core is the read-only bridge between Defiant Agent Harness state and
Defiant Command surfaces. It does not approve, execute, classify, or alter an
action. Its only job is to validate local records and project a small
operational snapshot.

Run it with:

```bash
dah --workdir .dah command
```

The JSON result uses schema `defiant.command.snapshot` version `0.9.0` and
contains:

- evidence-chain and cross-store integrity plus an overall `authoritative` flag;
- record, request, action, decision, and execution-status counts;
- exact-decimal aggregate cost and observed ruleset hashes;
- approval status counts, reconciliation-required state, and safe metadata for
  currently actionable items;
- durable operator-trust generation, mapping hash, operator/key counts, and
  verification status;
- durable authority-profile generation, active and pending hashes,
  verified/mismatched/rotation-required state, and sanitized transition
  assurance without operator names, notes, or signatures;
- local-operation recovery state with only operation id, kind, and preparation
  time when a valid journal is active;
- approval-free authorization recovery counts and bounded items containing only
  authority record, request, action, tool, timestamp, and state;
- known-result journal recovery state that is excluded from manual
  reconciliation counts;
- budget balance, reservations, spend, and estimate drift;
- a bounded list of recent operational events.

Use `--request <request_id>` to project one request and `--limit <count>` to
bound recent activity.

## Trust behavior

Command Core verifies the complete evidence chain before producing evidence
aggregates. If verification fails, `authoritative` is false, the process exits
non-zero, and both `evidence` and `recent_activity` are withheld. The integrity
failure itself remains visible so an operator can investigate it.

The `state_integrity` object is the sanitized `defiant.state_integrity` audit.
It reports `healthy`, `recovery_required`, or `unsafe`, whether execution is
safe, per-store status, counts, and issue codes. If approvals or budget state is
malformed, Command Core marks the snapshot non-authoritative and substitutes an
`invalid` projection for that store instead of hiding the diagnostic behind a
server error. No repair is attempted.

The projection deliberately excludes evidence targets, payload previews,
decision inputs, and raw results. Actionable approval entries expose only ids,
tool name, status, timestamps, whether operator reconciliation is required,
and sanitized identity assurance: operator, key id, signing time, and
verification status. Signatures and operator notes remain excluded. The
underlying local state directory still
contains confidential operational data and must remain access-controlled.
Issue output excludes targets, payload previews, reconciliation notes, and raw
results. The `operation_journal` projection never includes its prepared
approval, evidence, held action, operator note, or attestation. Reading a
snapshot does not initialize, recover, complete, or clear the journal.

Signed evidence exports are deliberately outside this live-state projection.
Command Core never loads private keys, imports signed exports, or treats an
export signature as authority over current state. With repeatable
`--trusted-operator-key IDENTITY=PUBLIC_KEY.pem` options it can verify approval
attestations and the enrolled trust-generation chain read-only; those public
pins cannot create authority. If signed mode is enrolled but pins are omitted
or mismatched, the snapshot remains available but is non-authoritative and
reports the trust failure. Command Core never enrolls or rotates trust. Use the
offline `dah verify-export` workflow documented in `evidence_signing.md`.

## Boundary

Command Core remains a local, on-demand read model with no server, execution,
approval, or mutation behavior of its own. The loopback-only Command Center UI
consumes this contract without gaining an authority path into the harness. See
`command_center.md` for that local HTTP surface. Multi-user identity, remote
ingestion, account authentication, and off-box evidence replication remain absent.
