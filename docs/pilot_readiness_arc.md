# Pilot Readiness Arc

This arc follows the owner's Master Handoff v1.0, Pilot Readiness Arc,
prepared September 6, 2026, against v0.94.0 at
`61ab23cbae48b3d2153c82f71da86273ddda1b42`. The evidence inspection and export
bounding arc (v0.85 through v0.94) is closed. This file tracks implementation;
it does not replace the source handoff or independently verify all of its
baseline assessments.

The finish line is **Pilot Ready**, not Production Ready and not automatically
v1.0. The owner has asked that, when this handoff is complete, work stop and
the next handoff be requested. Do not invent an additional arc.

## Pilot scope

- USAVEprocessing merchant statement review on the owner's Windows machine,
  with one operator and a dedicated governed workspace.
- Codex CLI through the Harness MCP proxy to the pinned official filesystem
  MCP server. The proxy is the authoritative governance boundary.
- Native Codex hooks remain a secondary preview seam, not the sole basis for
  prevention claims. One real Hermes path must demonstrate a second runner.
- Workspace draft writes are the only real side effects. No email, publishing,
  deletion, external spend, or customer data committed to this repository.
- Command Core and Command Center remain read-only; Command Center remains
  loopback-only. No DKE, Spartan, or separate Command product features.
- The owner holds approvals, uncertain-outcome reconciliation, keys, backups,
  retention, and any configured witnesses. OS/network containment is external
  to Harness authority. Witnessing is optional validation unless the selected
  threat model requires it.
- Measure resource use first; obtain owner-approved ceilings before claiming
  workload acceptance. Do not infer a ceiling from per-operation input limits.

## Slice tracker

| Slice | Deliverable | Dependencies | Status |
| --- | --- | --- | --- |
| S1 | Windows CI and explicit skip inventory | None | Implemented for v0.95.0; main/tag CI gates and evidence in `testing.md` |
| S2 | Real Windows private-state ACL tests | S1 | Implemented for v0.96.0; requires successful native Windows execution and main/tag CI gates; evidence in `testing.md` |
| S3 | Automated live pinned filesystem MCP integration | S1 | Implemented for v0.97.0; completion requires both-platform negative proof, final branch/main/tag green gates, and cold review; see `live_mcp_ci.md` |
| S4 | Explicit disposition of non-tool MCP methods | S3 | Not started |
| S5 | Real process-kill crash recovery | S3 | Not started |
| S6 | Distinguishable preview-hook enforcement basis and measured latency | S1 | Not started |
| S7 | Exercised consistent backup and restore | S1 | Not started |
| S8 | Real merchant review workspace and policy workflow | S3, S4 | Not started |
| S9 | Eighteen-scenario Windows pilot acceptance target | S2, S4, S5, S7, S8 | Not started |
| S10 | Measured resources and owner-proposed ceilings | S9 | Not started |
| S11 | Operator runbook executed and corrected | S5, S7 | Not started |
| S12 | Evidence-linked capability classifications | S9, S10, S11 | Not started |
| S13 | Real Hermes smoke and arc-close review | S4, S9; full gate below | Not started |

S1 targets v0.95.0. Later target labels in the source handoff are ordering
hints, not authorization to declare a stable release. Resolve its `v1.00.0`
and subsequent version labels with the owner before that transition; the final
arc tag remains an owner decision. The source's introductory safety/readiness
grouping differs from S7's explicit readiness classification; use the concrete
slice goals and acceptance criteria, not the grouping, to track completion.

## Evidence and completion rules

Each slice needs its own reviewed change and concrete acceptance evidence.
Tests passing alone do not establish pilot readiness. S1 adds Windows CI; it
does not demonstrate the real ACL inspection, live MCP server, real runner,
process-kill recovery, or backup/restore obligations of later slices.

Before claiming arc completion, demonstrate all eighteen acceptance scenarios
on the real Windows pilot with the real upstream: allowed read; blocked path;
approval hold; exact approved retry; rejection; expiry; budget refusal;
untrusted-content injection refusal; tamper detection; process kill;
known-result recovery; explicit uncertain-outcome reconciliation; no unsafe
replay; backup/restore; real ACL inspection; non-mutating Command Center;
live official filesystem execution; and real Codex integration.

The gate also requires ten genuine statement reviews, one real Hermes allow
and refusal smoke, an executed runbook, threat review of forwarded MCP methods,
green Windows CI, automatic live integration, no unresolved Critical or High
safety defects, and evidence-linked capability classifications. Classify each
capability as demonstrated on pilot, implemented but not pilot-demonstrated,
or unsupported/deferred. Only the first category supports pilot claims.

Keep unknown outcomes conservative. In particular, a side effect occurring
before settlement is not sufficient for known-result recovery: that result
must actually be durable. Never fabricate a result to satisfy an acceptance
scenario. A process kill is not a simulation of every power-loss condition.

Real pilot data, owner walkthroughs, resource approvals, key custody choices,
and the final tag require owner participation. Stop at those gates rather
than substituting synthetic results or making the decisions silently.
