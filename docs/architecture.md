# Architecture

## The one rule

No side-effecting tool action executes unless it passed the policy decision path and produced an evidence record first.

Everything below is in service of making that rule true in a way that survives contact with a real codebase, a real contributor, and a code-generating agent working inside this repository.

## Why the gate is a capability, not a check

A policy check is a line of code someone can route around. Three ways it happens, none of them malicious:

- a developer adds a fast path for a tool that "obviously doesn't need review";
- a test helper calls the tool directly and the helper leaks into production;
- a code-generating agent, asked to add a feature, imports the tool function because that is the shortest path to a passing test.

So tool callables are held privately inside `ToolRegistry` and the execution
path is `execute(action, grant)`. Before execution, the registry validates the
adapter's claims against authoritative `ToolSpec` metadata. The grant is a
`CapabilityGrant` that:

- is signed by the registry only after the control loop presents a sealed
  authorization record;
- names one action, tool, and evidence record;
- binds the target, payload, provenance, request, side-effect classification,
  and cost estimate through `authorization_hash`;
- is single-use, and raises on replay;
- refuses if any authorization-relevant input differs from what was authorized.

That last property is the confused-deputy defence. Without it, an approved
message could be exchanged for wire instructions, or its recipient could be
changed after approval. Payload and target substitution both have regression
tests.

This is an in-process control boundary, not privilege separation. Code already
running inside the harness process is trusted; OS sandboxing is future
deployment work.

## Order of operations

```
classify -> policy decide -> budget preflight -> reserve
         -> WRITE EVIDENCE -> mint grant -> execute -> settle -> WRITE EVIDENCE
```

Evidence is written before execution. A crash between the grant and the tool call therefore leaves a record saying an action was authorized and its outcome is unknown — which is the honest state, and one an operator can investigate. The reverse order would allow an action to execute and leave no trace, which is the single failure this product cannot have.

Blocked, rejected, and expired actions produce evidence too. "Nothing happened" is a finding, and in a compliance conversation it is usually the finding the customer most wants proof of.

Pending approvals persist the complete action, request, and decision snapshot.
They resume after a new process starts, but only if the loaded ruleset hash is
identical. A policy change voids the stale approval and requires re-proposal.
For MCP stdio, the first call returns a pending handle. Approval records the
human decision without executing in the CLI process; an exact-call retry through
the proxy owns execution. This prevents the approval CLI from impersonating an
upstream connection it does not control.

## Trust and provenance

`Trust` has three values and one propagation rule.

- `TRUSTED` — operator-authored, or approved knowledge under operator control.
- `UNTRUSTED` — anything read from the outside world: web pages, inbound email, third-party MCP results, downloaded files.
- `DERIVED` — produced by the agent from a mix.

The rule is that trust is contagious downward: any untrusted input taints
everything derived from it (`worst_trust`). An adapter that cannot prove
provenance must return `DERIVED`, never `TRUSTED`. An action with no provenance
also defaults to `DERIVED`.

Policy can then gate on `max_payload_trust`. The default pack refuses any action at or above `external_send` whose payload trust is worse than `derived`. The agent may read the untrusted thing, reason about it, and summarize it; it simply cannot make that content cause an effect outside the workspace without a human.

This is the mechanical form of the Defiant invariant that knowledge can inform execution but cannot authorize it, and it is a strictly stronger position than "we told the model to be careful."

## Determinism

The policy engine performs no model call, no network access, and no clock-dependent branching outside explicit approval expiry. Same action plus same ruleset yields the same decision, always — asserted 50 times over in `test_engine_is_deterministic`.

That matters commercially, not just technically. A consultant can tell a client exactly what will be blocked, and a compliance reviewer can read the YAML instead of trusting a model's judgement. The prohibited-claim rules in `merchant_services.yaml` are deterministic string matches for precisely this reason: their weakness (they can be paraphrased around) is visible and auditable, where a model-based classifier's weakness would not be.

The tradeoff is stated plainly rather than hidden: deterministic matching catches the exact phrasings listed and nothing else. It is a floor, not a ceiling. A model-based reviewer belongs later, layered above this floor, never replacing it.

## Default deny, twice

1. The registry refuses unknown tools, path escapes, and any adapter-side
   classification that disagrees with authoritative `ToolSpec` metadata.
2. A tool not declared in any loaded pack's `known_tools` is refused before
   rules are consulted.
3. Among classified tools, anything with a side effect and no matching rule is
   blocked; anything with no side effect and no matching rule is allowed.

Rule order is not load-bearing: every matching rule is evaluated and the strictest outcome wins, so a permissive rule cannot be positioned to shadow a restrictive one.

## Budgets, honestly

You cannot reliably predict what an agent turn will cost before it runs, so the harness does not pretend to. What it does instead is enforceable:

- a persisted exact-decimal balance;
- a preflight check against the **worst-case** estimate, not the expected case;
- a reservation bound to one request and action id, reducing available balance
  immediately;
- a hard debit of actual cost after execution;
- a release when an action is blocked, rejected, or expires;
- `drift()`, which reports the gap between estimates and actuals rather than hiding it.

An in-flight overrun cannot be prevented. It is always visible, and it reduces the next action's headroom immediately. Say this to a technical buyer before they ask.

## MCP transport boundary in v0.3

The proxy launches one upstream command without a shell. Its stdout is reserved
for newline-delimited MCP messages. Initialization, discovery, notifications,
and non-tool requests pass through. `tools/call` is translated to a harness
action; allowed calls use a private upstream request id and the original
upstream result or JSON-RPC error is restored under the client's request id with
`_defiant` evidence metadata.

Protocol negotiation is capped at `2025-06-18`. The `2025-11-25` task
augmentation is intentionally not advertised until task creation, durable
status, cancellation, and result retrieval can all share the same authority and
evidence model.

The Streamable HTTP upstream preserves that same stdio-facing boundary for the
runner while sending one JSON-RPC message per HTTP POST to a configured remote
endpoint. It supports JSON and finite SSE responses, optional MCP session ids,
and session DELETE on shutdown. Remote authentication values are loaded from
environment variables. See `streamable_http.md`.

## Command read boundary in v0.5

Command Core is a one-way, read-only projection over evidence, approvals, and
budget state. It verifies the complete evidence chain before calculating any
evidence-derived aggregate. A broken chain produces a visible integrity alert
but no evidence totals or recent activity, preventing altered records from
silently becoming dashboard truth.

The snapshot excludes targets, payload previews, decision inputs, and raw tool
results. It has no execution, approval, policy, or mutation API.

Command Center consumes that snapshot through a loopback-only HTTP server. The
server is fixed to `127.0.0.1`, accepts only bounded read query parameters, and
implements no mutating HTTP methods. Refresh and request filtering generate a
new projection; they do not modify harness state. The packaged browser UI has
no execution or approval controls and no external runtime dependencies. See
`command_core.md` and `command_center.md`.

Configured tool specs extend `known_tools` for that registry instance, and the
extension participates in the ruleset hash. Side effect, conservative cost,
dry-run support, target scope, workspace root, and the hashed upstream command
identity participate too. A changed authority contract therefore voids a stale
approval instead of silently changing what it means. This is safe only because
the same operator-authored mapping supplies the authoritative metadata. An
advertised but unmapped tool fails both request scope and registry checks.

`examples/filesystem` proves the boundary against the official MCP filesystem
reference server. In that integration, Defiant validates each mapped path
against its configured workspace and the upstream server independently applies
its own allowed-directory boundary. The example intentionally leaves the
multi-target `read_multiple_files` and `move_file` tools unmapped until the
registry can validate every member of a target collection.

The boundary is transport control, not containment. It says nothing about
native tools, direct HTTP, subprocesses, filesystem access outside an MCP
server, or a runner that connects directly to the upstream server.

## Crash recovery boundary in v0.6

An approval moves to `executing` before a governed tool can run. If the process
dies after that write, Defiant cannot distinguish "never dispatched" from
"completed but not recorded" and continues to refuse automatic replay.

The v0.6 operator reconciliation path is a separate CLI mutation, not a Command
Center feature. It first validates any terminal evidence already written, then
durably binds an explicit outcome, operator identity, and non-empty note to the
approval. Budget reconciliation, evidence append, and final consumption each
have an idempotent durable marker or lookup. Repeating the exact command after a
crash completes remaining steps; changing the story is refused.

When actual cost is unknown, `succeeded` and `failed` charge the full durable
reservation. Only `not_executed` releases a live reservation. A missing
reservation with no prior debit is charged at the approval estimate rather than
silently treated as free. See `approval_reconciliation.md`.

## State integrity boundary in v0.7

The three durable stores are individually atomic but do not form one database
transaction. v0.7 therefore audits their shared authority bindings before each
authority-bearing harness entry point. Evidence must be intact; approval ids,
action snapshots, requests, reservations, terminal records, and reconciliation
markers must agree; terminal approvals cannot retain reservations; and a store
lock stops new authority.

The auditor explicitly models valid crash windows. An `executing` approval or a
sealed unfinished external authorization is recovery-required, not corrupt.
Critical contradictions raise `StateIntegrityError` before new evidence, budget,
approval, or tool mutation. `dah doctor`, Command Core, and Command Center read
the same sanitized audit contract without creating or repairing state. See
`state_integrity.md`.

## Evidence authenticity boundary in v0.8

The live JSONL chain remains the local system of record. v0.8 adds a separate,
operator-invoked export attestation rather than introducing a private key into
the runtime authority path. A request export binds its selected records to the
verified full-chain count and head hash. Ed25519 signs a domain-separated
statement containing the canonical payload hash, signing time, public-key
identifier, asserted signer identity, and required note.

Private keys are encrypted and supplied from outside `.dah`. Verifiers accept
only explicitly pinned public keys received out of band; the export cannot
appoint its own trust root. Repeated trust-key arguments support planned key
rotation while old public keys remain usable for historical verification. This
proves that the holder of a pinned key signed one exact export. It does not
provide certificate identity, trusted time, hardware-backed custody, automatic
revocation, or proof that no later chain tail was removed. See
`evidence_signing.md`.

## Native agent hook boundary (Preview)

The workspace `PreToolUse` hook covers supported native VS Code and Copilot CLI
tools that do not cross MCP. It translates the complete native tool input into
a bound action, returns a deterministic allow or deny decision, and uses the
same durable exact-call approval model. Allowed pre-events create only an
execution-pending authorization record. A correlated `PostToolUse` event seals
the successful external result and consumes any approval.

The hook policy blocks terminal, subagent, unknown, path-escape, and trusted
enforcement-file mutation attempts. Missing post-events never become guessed
successes. See `native_hooks.md`.

## What is deliberately absent from v0.8

- **Remote or multi-user Command.** Command Center is a local loopback view, not
  a hosted service. It has no authentication, remote ingestion, or identity
  system and must not be exposed as one.
- **DKE / the knowledge engine.** `memory_sources_used` exists in the evidence contract as an empty field so the schema does not change when DKE arrives.
- **Spartan Swarm.** Multi-agent missions need a working single-agent gate first.
- **Complete runner containment.** The preview native hook covers supported
  lifecycle tool events. Direct activity with no event, plus documented
  fail-open hook timeouts, still requires OS/network isolation.
- **Real reference-tool side effects.** The built-ins still simulate writes,
  sends, publishes, exports, deletes, and spends. Proxied upstream tools are
  real and must be classified accordingly.
- **Multi-user identity.** `approved_by` is a string. Real identity binding is a later arc.
- **Automatic state repair.** The auditor detects contradictions and fails
  closed. Repair requires offline investigation or restore from a known-good
  copy; the dashboard has no repair or mutation path.

## Known limits

- **Approval state contains sensitive payloads.** Durable restart-safe resume
  requires the local approval store to retain the held action. The state
  directory must be access-controlled and is not suitable for evidence export.
- **Evidence is append-only by convention at the filesystem layer.** Anyone with write access to the file can truncate it; the chain makes alteration and deletion *detectable*, not impossible. Off-box replication is the answer, and it belongs to Command.
- **Deterministic phrase matching is bypassable by paraphrase.** See above.
- **`estimate_cost` is a stub** for everything except explicit spend amounts. Token-cost estimation per runner is adapter work.
- **MCP has no standard actual-cost field.** The proxy settles successful paid
  calls at the conservative configured estimate unless a later adapter can
  prove an actual amount.
- **Generic provenance is coarse.** The proxy defaults arguments to `DERIVED`.
  It cannot reconstruct a runner's cross-call data flow; native hooks are
  needed for source-specific taint.
- **Exact-call retry requires client cooperation.** After approval, the MCP
  client or agent must repeat the same tool params before expiry.
- **MCP task augmentation is not yet supported.** Initialization is negotiated
  down to `2025-06-18`; task-aware governance belongs in a later release.
- **A command fingerprint is not binary attestation.** It binds approvals to the
  configured argument vector, not to the bytes loaded from disk. The live
  filesystem example pins the direct npm package version, but `npx` may still
  resolve transitive dependency ranges. Production deployments should use a
  reviewed lockfile, immutable container digest, or equivalent artifact
  attestation.
- **In-process code is trusted.** Signed grants constrain adapters and normal
  control flow; they do not sandbox malicious Python already executing inside
  the harness process.
- **Hook timeouts fail open.** Current VS Code and Copilot CLI behavior falls
  back to normal runner permissions when a hook times out. Hook errors are
  converted to explicit deny responses, but the platform timeout rule requires
  an outer OS sandbox for production.
- **Reconciliation does not discover the truth automatically.** The operator
  must inspect the external provider or target system and assert the outcome.
  v0.6 makes that assertion explicit, durable, conservative, and auditable; it
  cannot prove that the human conclusion was correct.
- **Cross-store auditing is point-in-time.** It does not turn local JSON files
  into a transactional database. Defiant assumes one logical writer per state
  directory and uses conservative per-file locks to reject concurrent writes.
- **Signing identity is key-based, not account-based.** A valid v0.8
  attestation proves possession of a pinned private key. The signer string and
  note are cryptographically bound assertions, not authentication against an
  identity provider. Key custody and the mapping from key id to accountable
  operator remain deployment controls.
- **Signed exports are point-in-time.** They authenticate one exported payload
  and its stated full-chain head. They do not prove that the live evidence file
  was never extended or later truncated; off-box retention is still required.
