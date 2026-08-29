# Command Center

Command Center is Defiant's first local graphical operations view. It serves the
sanitized `CommandCore.snapshot()` contract over a loopback-only HTTP server and
renders evidence integrity, decision totals, approval visibility, budget state,
and recent activity in a browser.

It is deliberately an observation surface, not an authority surface.

## Run it

```bash
dah --workdir .dah --workspace-root workspace command-center
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
- signed external evidence-head witness posture, witnessed count, current lag,
  optional maximum, and sanitized signer/key/time assurance without paths,
  signature, or note;
- a prominent reconciliation-required alert for approvals stranded in
  `executing`, without exposing the operator note or adding an action control;
- budget balance, availability, reservations, spend, and estimate drift;
- bounded recent activity without payloads, targets, decision inputs, or raw
  tool results;
- an optional request-id focus applied through a read-only snapshot query; and
- the fixed pre-parse byte ceilings enforced by the running harness;
- the fixed evidence-export parse and publication ceiling; and
- the fixed symmetric operation-journal read/write and snapshot ceiling;
- the fixed trusted-public-key count, per-key, and aggregate byte ceilings; and
- the fixed complete-policy pack, rule, known-tool, per-field, and
  aggregate-list ceilings; and
- the fixed per-item and complete-ruleset policy text ceilings;
- the fixed governed-payload matching depth, node, text, and aggregate work
  ceilings;
- the fixed policy glob tool-name/target subject and aggregate work ceilings;
- the fixed policy-context entry, key, value, and aggregate text ceilings;
- the fixed action-hash depth, node, per-mapping entry, scalar-character,
  escaped-string-token, number-token, and canonical-byte ceilings;
- canonical mapping-entry preflight before key traversal or sorting;
- canonical mapping-key eligibility before value traversal or sorting;
- complete canonical mapping-key token validation before any mapping value;
- detached validated canonical snapshots before encoder traversal;
- direct validated-snapshot ownership without post-validation deep copies;
- validated built-in snapshots for request and action-provenance collections;
- validated built-in scalar ownership across governed contracts;
- validated built-in ownership across policy decisions, capability grants, and
  evidence records;
- validated bounded snapshot ownership across policy rules, registered known
  tools, and authority inputs;
- immutable policy runtime rules and known-tool patterns with read-only policy
  identity and defensive authority projections;
- bounded exact policy decision context shared by rule matching and evidence;
- bounded exact operation-journal snapshots sealed behind defensive payload
  projections;
- one bounded exact native-hook event observation shared by retry identity,
  authorization translation, target selection, payload, and completion;
- sealed authority-profile and operator-trust state with defensive projections
  and symmetric bounded capture, publication, and recovery reads;
- detached bounded evidence-head checkpoint state with symmetric capture,
  recovery-read, and publication limits;
- detached bounded evidence-witness policy state with symmetric capture,
  recovery-read, and publication limits;
- aggregate canonical mapping sort-work preflight before encoder sorting;
- complete canonical-value byte preflight before sorting or encoding;
- the fixed pre-encoding canonical-number token ceiling;
- the fixed pre-render escaped canonical-string token ceiling;
- the fixed pre-adapter tool-call name, identifier, depth, node, per-mapping
  entry, scalar-character, escaped-string-token, number-token, and
  canonical-byte ceilings;
- the fixed post-execution tool-result summary, depth, node, per-mapping entry,
  scalar-character, escaped-string-token, number-token, and canonical-byte
  ceilings;
- the fixed governed-request task, identifier, allowlist, provenance, and
  aggregate-text ceilings;
- the fixed authority-YAML nesting-depth and constructed-node ceilings;
- the fixed per-collection and aggregate MCP authority-configuration
  ceilings; and
- the strict authority-YAML and authority-JSON profiles, including alias,
  structural-complexity, scalar-complexity, duplicate-key, non-finite-number,
  and strict-UTF-8 refusal posture.

The browser refreshes from Command Core every 15 seconds. Refresh and filtering
change only the browser view; they do not change Defiant state.

The displayed ceilings and parser posture come from Command Core schema
`0.61.0`. The browser cannot raise, disable, or replace them and never receives
rejected input bytes.

v0.61 adds only the static native-hook correlation-state byte ceiling and
sealed-state posture. The dashboard does not receive held action, request,
decision, authorization, approval, or completion records and gains no hook
completion or repair control.

v0.62 adds only the static approval-state byte ceiling and sealed-record
posture. Actionable approval cards remain sanitized operational metadata. The
browser never receives held action/request/decision snapshots, payload
previews, targets, operator notes, attestations, or a decision, execution,
reconciliation, repair, or record-update endpoint.

v0.63 adds only the static budget-state byte ceiling and validated-ledger
snapshot posture. The existing budget cards remain sanitized aggregate
projections. The browser receives no reservation map, reconciliation record,
operator note, attestation, or ledger mutation, settlement, release, grant,
repair, or acceptance endpoint.

v0.64 adds only the static evidence-head-state byte ceiling and validated
checkpoint-snapshot posture. The browser continues to receive the existing
sanitized checkpoint position and verification projection. It gains no
checkpoint write, advance, repair, acceptance, profile-rebind, evidence append,
or other authority endpoint.

v0.65 adds only the static evidence-witness-policy-state byte ceiling and
validated policy-snapshot posture. Existing witness cards remain sanitized.
The browser gains no witness upload, signing, acceptance, trust-key, lag-policy,
profile-rotation, repair, or other mutation endpoint.

v0.66 adds only the static bounded-authority-continuity-I/O posture. The
existing 1 MiB authority-profile and operator-trust ceilings and sanitized
continuity projections are unchanged. The browser receives no bindings,
transitions, attestations, operator identity or note, state bytes, paths,
rotation, enrollment, migration, repair, or other mutation endpoint.

v0.67 adds only the static runtime-artifact-state byte ceiling and validated
snapshot posture. Existing artifact cards remain sanitized to mode, bundle
hash, counts, executable-pin posture, profile binding, and verification time.
The browser receives no artifact paths, dependency roots, relative filenames,
individual digests, raw state, manifest edits, drift acceptance, profile
rotation, process launch, repair, or other mutation endpoint.

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

v0.17 adds sanitized launch-envelope posture to the same read-only authority
metric: restricted, inherited-unrestricted, or remote-not-applicable mode plus
the effective variable count. The snapshot contains bounded hashes and counts,
not variable names, values, secrets, or the working-directory path. There is no
environment editor, secret input, unsafe-variable acknowledgement, launch, or
repair endpoint.

v0.18 adds the sanitized state-storage mode and checked-file count to the
authority metric. The underlying snapshot also carries only the root hash,
profile binding, permission and directory-sync posture, orphan-temporary count,
and last verification time. It never exposes the canonical state path, device,
inode/file identifier, file contents, SIDs, account names, or ACL entries.
Strict Windows state mode exposes only the sanitized ACL policy, protected-root
status, and allow-principal count. Command Center has no
chmod, relink, move, delete, restore, acceptance, or repair endpoint.

v0.19 adds the sanitized control-plane isolation mode, protected-root count,
and workspace/state relationship to the same authority metric. The snapshot
contains bounded contract and workspace hashes but no paths. Command Center
cannot exempt a path, change a tool scope, move state, authorize a profile
transition, or dispatch a tool.

v0.20 adds sanitized workspace-root mode, shortened root hash, and live
verification state to the authority metric. The server receives the configured
root only to perform read-only inspection. It cannot create, accept, relink,
move, repair, rotate, approve, or dispatch anything.

v0.21 adds sanitized evidence-head mode, verification, and checkpointed record
count to the authority metric. A behind checkpoint is shown as recovery
required; rollback or divergence makes the snapshot non-authoritative. The
dashboard cannot advance, reset, accept, repair, or delete a checkpoint and
cannot append evidence.

v0.22 adds sanitized external witness mode, verification, and witnessed record
count to the same metric. The server may receive an external witness and public
trust keys only as read-only startup inputs. It cannot create, upload, copy,
rotate, replace, accept, or repair them, and never receives a private key or
passphrase. Missing or invalid required input makes the snapshot
non-authoritative.

## Security scope

Loopback binding is a local-development boundary, not authentication or remote
access control. Do not place this server behind a network proxy, expose its port
to another host, or treat it as a multi-user service. The underlying state
directory still contains confidential operational material and must remain
access-controlled.

v0.8 evidence signing remains an operator CLI and offline-verification workflow.
v0.23 renders declared runtime dependency closure as a sanitized root count,
file count, and shortened bundle hash. It receives no filesystem paths,
relative filenames, or individual file digests. The dashboard cannot generate
or edit a manifest, accept drift, rotate authority, or launch an upstream.

v0.10 and later may give Command Center operator public-key pins at startup so its
read-only snapshot can verify persisted approval attestations and the durable
trust-generation chain. If pins are missing or mismatched, it remains available
as a non-authoritative diagnostic view. Command Center never enrolls or rotates
trust and never receives a private key, passphrase, signed export, key-upload
endpoint, or trusted-key mutation path.

See `command_core.md` for the JSON projection contract,
`state_integrity.md` for the audit contract, and `architecture.md` for the
authority-boundary rationale.
