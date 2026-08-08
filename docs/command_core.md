# Command Core

Command Core is the read-only bridge between Defiant Agent Harness state and a
future Defiant Command interface. It does not approve, execute, classify, or
alter an action. Its only job is to validate local records and project a small
operational snapshot.

Run it with:

```bash
dah --workdir .dah command
```

The JSON result uses schema `defiant.command.snapshot` version `0.1.0` and
contains:

- evidence-chain integrity and an overall `authoritative` flag;
- record, request, action, decision, and execution-status counts;
- exact-decimal aggregate cost and observed ruleset hashes;
- approval status counts plus safe metadata for currently actionable items;
- budget balance, reservations, spend, and estimate drift;
- a bounded list of recent operational events.

Use `--request <request_id>` to project one request and `--limit <count>` to
bound recent activity.

## Trust behavior

Command Core verifies the complete evidence chain before producing evidence
aggregates. If verification fails, `authoritative` is false, the process exits
non-zero, and both `evidence` and `recent_activity` are withheld. The integrity
failure itself remains visible so an operator can investigate it.

The projection deliberately excludes evidence targets, payload previews,
decision inputs, and raw results. Actionable approval entries expose only ids,
tool name, status, and timestamps. The underlying local state directory still
contains confidential operational data and must remain access-controlled.

## Boundary

This is Command Core, not Command Center. It is a local, on-demand read model;
there is no web server, dashboard, authentication system, multi-user identity,
remote ingestion, or off-box evidence replication yet. A future UI can consume
this contract without gaining an authority path into the harness.
