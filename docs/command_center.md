# Command Center

Command Center is Defiant's first local graphical operations view. It serves the
sanitized `CommandCore.snapshot()` contract over a loopback-only HTTP server and
renders evidence integrity, decision totals, approval visibility, budget state,
and recent activity in a browser.

It is deliberately an observation surface, not an authority surface.

## Run it

```bash
dah --workdir .dah command-center
```

The command prints the exact local URL, which defaults to
`http://127.0.0.1:8765/`. Choose another local port with `--port`; set the
default recent-activity bound with `--limit`:

```bash
dah --workdir .dah command-center --port 9000 --limit 50
```

Press `Ctrl+C` in the serving terminal to stop it.

## What the interface shows

- complete evidence-chain integrity and snapshot generation time;
- cross-store state health, recovery warnings, and fail-closed integrity alerts;
- record, request, and action totals;
- allow, block, and approval-required decision counts;
- exact-decimal evidence cost and observed ruleset count;
- actionable approval metadata without payloads or targets;
- signed-operator assurance, operator, key id, and signing time without the
  signature or operator note;
- durable operator-trust generation and verified, unverified, mismatched, or
  invalid status without trust-transition signatures or notes;
- durable authority-profile generation, active/pending hash, verification, and
  rotation-required status without operator identity, note, or signature;
- a prominent reconciliation-required alert for approvals stranded in
  `executing`, without exposing the operator note or adding an action control;
- budget balance, availability, reservations, spend, and estimate drift;
- bounded recent activity without payloads, targets, decision inputs, or raw
  tool results;
- an optional request-id focus applied through a read-only snapshot query.

The browser refreshes from Command Core every 15 seconds. Refresh and filtering
change only the browser view; they do not change Defiant state.

## Read-only boundary

The server binds to `127.0.0.1` and does not accept a host override. Its HTTP
surface is intentionally small:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET`, `HEAD` | `/` and `/assets/*` | Packaged local interface |
| `GET`, `HEAD` | `/api/snapshot` | Current Command Core projection |
| `GET`, `HEAD` | `/api/health` | Static local read-only health signal |
| `OPTIONS` | any path | Advertises only `GET`, `HEAD`, and `OPTIONS` |

`POST`, `PUT`, `PATCH`, and `DELETE` return `405 Method Not Allowed`. There are
no endpoints for execution, approval decisions, policy changes, state writes,
evidence signing, key upload, signed-export import, authentication, DKE, or
Spartan features. Browser assets use same-origin fetch,
ship without external dependencies, and are served with no-store, content-type,
frame, referrer, and content-security headers.

The snapshot endpoint accepts `request_id` and a bounded `limit` from 0 through
100. Unknown, repeated, oversized, or invalid parameters fail with `400`
instead of being guessed.

## Integrity behavior

Command Center preserves Command Core's fail-closed evidence behavior. The full
hash chain is verified before any evidence aggregate is rendered. If the chain
is broken, the integrity alert remains visible while evidence totals, decision
mix, and recent activity are withheld. Approval and budget projections remain
separate local-state observations; the page never presents altered evidence as
dashboard truth.

The state-integrity banner separately reports recoverable crash conditions or
critical cross-store contradictions. Critical issues make the snapshot
non-authoritative and authority-bearing harness operations fail closed. If one
JSON store is malformed, its projection is marked `invalid`; the sanitized
doctor result remains visible and no browser repair control is added.

If a snapshot cannot be built because of an unexpected read failure outside the
audited stores, the API returns `503` and the interface shows an availability
error while retaining the last valid view already in the browser.

A valid active v0.11 local operation journal appears as recovery required with
only its operation id, kind, and preparation time. Its payload, held action,
operator note, and attestation never enter the browser snapshot. The dashboard
does not recover, retry, complete, delete, or force-clear an operation; normal
authority startup performs deterministic recovery before its integrity gate.

v0.12 also places approval-free uncertain authorizations in the operator queue.
Each item contains only the sealed authority record id, request and action ids,
tool name, timestamp, and recovery state. The banner distinguishes approval and
approval-free counts. Targets, payloads, operator notes, attestations, and raw
results remain excluded, and no reconciliation control or endpoint is added.

v0.13 distinguishes a journaled known result from an uncertain execution. The
operation-recovery banner remains visible, but matching approval and
approval-free items are not counted as requiring manual reconciliation. The UI
cannot settle budget, append evidence, consume an approval, or complete the
journal; authority startup performs that deterministic recovery.

v0.14 does not add an authority-lock control to the dashboard. Command Center
never acquires, releases, deletes, or probes ownership of `authority.lock`.
Because snapshots remain point-in-time, a read during an active writer may
temporarily report an in-progress or locked store; refresh after the writer
finishes.

v0.15 adds an authority-profile metric and read-only rotation warning. It does
not add a rotation, activation, cancellation, policy upload, or profile-repair
endpoint. The operator CLI stages a reviewed candidate, and only the exact
authority runtime can activate it under the authority lock.

v0.16 extends that metric with sanitized runtime-artifact assurance: pinned or
unverified state, declared artifact count, a shortened canonical bundle hash,
and profile-binding status. It does not expose local paths or individual file
digests. There is no manifest editor, rehash, acceptance, rotation, launch, or
repair endpoint; the dashboard remains strictly read-only.

## Security scope

Loopback binding is a local-development boundary, not authentication or remote
access control. Do not place this server behind a network proxy, expose its port
to another host, or treat it as a multi-user service. The underlying state
directory still contains confidential operational material and must remain
access-controlled.

v0.8 evidence signing remains an operator CLI and offline-verification workflow.
v0.10 and later may give Command Center operator public-key pins at startup so its
read-only snapshot can verify persisted approval attestations and the durable
trust-generation chain. If pins are missing or mismatched, it remains available
as a non-authoritative diagnostic view. Command Center never enrolls or rotates
trust and never receives a private key, passphrase, signed export, key-upload
endpoint, or trusted-key mutation path.

See `command_core.md` for the JSON projection contract,
`state_integrity.md` for the audit contract, and `architecture.md` for the
authority-boundary rationale.
