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

## Security scope

Loopback binding is a local-development boundary, not authentication or remote
access control. Do not place this server behind a network proxy, expose its port
to another host, or treat it as a multi-user service. The underlying state
directory still contains confidential operational material and must remain
access-controlled.

v0.8 evidence signing is an operator CLI and offline-verification workflow.
Command Center never receives a private key, passphrase, signed export, or
trusted-key mutation path.

See `command_core.md` for the JSON projection contract,
`state_integrity.md` for the audit contract, and `architecture.md` for the
authority-boundary rationale.
