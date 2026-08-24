# Defiant Agent Harness

Control, approvals, budgets, memory discipline, and audit evidence for business-grade AI agents.

Defiant Agent Harness wraps MCP-capable and other agentic AI systems with
business-grade controls: tool permissions, human approval gates, budget limits,
provenance discipline, prompt-injection resistance, and Command-ready evidence
logs. A full trusted-memory/DKE system is not part of v0.26.

## The invariant

Everything in this repository exists to enforce one rule:

> No side-effecting tool action executes unless it passed the policy decision path and produced an evidence record first.

That rule is enforced at the registered tool boundary. Execution requires a
single-use, registry-signed `CapabilityGrant` issued against a sealed
authorization record. The grant binds the action id, tool, target, payload,
provenance, side-effect classification, request, and cost estimate. A forged
grant, a grant from another registry, or any post-authorization change is
refused.

The trusted boundary is stated honestly: code already running inside the
harness process is trusted. Python is not an operating-system sandbox. The
grant prevents accidental bypasses and untrusted adapter claims; OS isolation
is a later deployment layer.

A second rule follows from the first, and it is the one that answers the security objection people actually raise about always-on agents:

> Knowledge can inform execution. Knowledge cannot authorize execution.

Adapters carry provenance for content the agent used. External content is
tagged `untrusted`, missing provenance defaults to `derived`, and trust flows
into the proposed action. Policy can then refuse outbound actions derived from
untrusted material. The mock adapter proves this path; every real adapter must
be reviewed and tested for provenance quality.

## What v0.26 is

A headless local control loop plus generic MCP stdio and Streamable HTTP
upstream transports. Each local proxy speaks stdio to the agent, transparently
forwards ordinary protocol traffic, and intercepts `tools/call`. It validates
an intercepted action against the authoritative operator-authored tool map,
evaluates deterministic policy, checks budget, holds durably for human
approval, executes through the gated path, and writes a hash-chained evidence
trail—including for actions that never ran.

The v0.1 reference tools remain safe fixtures: only `read_file` performs real
I/O, confined to one workspace, while their side effects are simulated. The
v0.3 proxies are real execution boundaries: a permitted or approved call is
forwarded to the configured upstream server and can therefore have real side
effects.

The repository also includes preview native-agent hook adapters for current
VS Code, Copilot CLI, and Codex sessions. `PreToolUse` sends native read, write,
search, terminal, subagent, and unknown-tool attempts through the same policy
and approval path. `PostToolUse` seals successful external execution into
evidence. This closes the principal bypass exposed by runners whose built-in
tools cannot be removed from their UI.

v0.4 added the first thin **Command Core** read model. It verifies the complete
evidence chain and emits a safe operational snapshot containing decision and
execution counts, actionable approvals, budget state, and bounded recent
activity. It is read-only and deliberately withholds evidence aggregates when
the chain is broken.

v0.5 adds the first **Command Center** UI on top of that contract. It is a
dependency-free local dashboard bound only to loopback, with live evidence,
approval, budget, and recent-activity views plus request filtering. It has no
mutation, execution, approval-decision, policy, authentication, DKE, or Spartan
surface.

v0.6 begins production hardening with an explicit recovery path for approvals
stranded in `executing` after a process crash. Automatic replay remains
forbidden. An operator must inspect the external system, select `succeeded`,
`failed`, or `not_executed`, and supply both identity and a non-empty note. The
intent, conservative budget disposition, evidence, and final approval state are
individually durable and idempotent across repeated crashes. Command Core and
Command Center report the required intervention, but Command Center remains
strictly read-only.

v0.7 adds a read-only cross-store state auditor and fail-closed execution gate.
It verifies evidence, approvals, budgets, reservations, terminal evidence, and
reconciliation markers together before an authority-bearing operation. Expected
crash windows remain recoverable and visible; contradictions block new
authority. `dah doctor`, Command Core, and Command Center remain usable for
sanitized diagnostics without repairing or mutating state.

v0.8 adds offline-verifiable Ed25519 attestations for request evidence exports.
Signing requires an encrypted private key kept outside harness state, an
explicit signer identity, and a non-empty note. Verification pins public keys
out of band and supports deliberate rotation without trusting a key embedded in
the export. A broken chain, empty request, cross-request record, malformed
schema, or inconsistent chain metadata cannot be signed. Command Center remains
strictly read-only and never receives private-key material.

v0.9 adds cryptographically bound operator decisions. Approval and crash
reconciliation statements can be signed with an encrypted Ed25519 private key
and verified against an out-of-band `IDENTITY=PUBLIC_KEY.pem` trust mapping.
The signature binds the exact approval authority, outcome, identity, required
note, and timestamp. A runtime configured with trust pins fails closed on
unsigned, invalid, untrusted, or replayed authority before execution or budget
reconciliation. Command Core and Command Center expose sanitized assurance
metadata while remaining read-only and never receiving private-key material.

v0.10 makes signed operator mode durable. The first authority-bearing startup
with trust pins enrolls a nonsecret identity/key-ID mapping in
`.dah/operator_trust.json`. Later authority startup without pins, or with a
different mapping, fails before evidence, approval, budget, or tool mutation.
Planned rotation is an explicit old-key-signed, strictly additive generation;
online key removal and identity reassignment are refused and reserved for an
offline compromise-recovery procedure. Doctor, Command Core, and Command Center
remain read-only and expose enrolled, verified, mismatched, or invalid trust
state without enrolling or repairing it.
Existing v0.9 work directories containing signed operator attestations must
supply their current pins on first v0.10 authority startup; unsigned migration
is refused.

v0.11 adds a crash-safe local operation journal for deterministic mutations
that span approvals, budget reservations, and evidence. Prepared approval
creation, rejection, and expiry operations recover idempotently after a process
crash without double-reserving, double-releasing, or duplicating evidence.
Conflicting partial state fails closed. External tool outcomes are never
inferred or replayed: approvals stranded in `executing` still require the
explicit v0.6 operator reconciliation workflow. Command Core and Command Center
show only sanitized recovery metadata, and Command Center remains strictly
read-only.

v0.12 closes the remaining operator-path gap for approval-free execution
authorizations. A sealed authorization with no terminal outcome can now be
resolved by evidence record id only after the operator supplies `succeeded`,
`failed`, or `not_executed`, a non-empty identity, and a non-empty note. Signed
mode binds the statement to the exact sealed authorization under a distinct
Ed25519 purpose. Budget disposition and terminal evidence recover idempotently
through the operation journal, while Command Core and the strictly read-only
Command Center expose only sanitized recovery metadata.

v0.13 journals a known tool result before budget settlement, terminal evidence,
or approval consumption. If the process stops after the tool returns, restart
finishes those exact local mutations without calling the tool again, charging
twice, duplicating evidence, or asking an operator to guess an outcome the
harness had already received. Missing actual-cost data settles at the
conservative reserved estimate for non-dry-run attempts. Doctor, Command Core,
and the strictly read-only Command Center distinguish this deterministic
recovery from manual reconciliation.

v0.14 enforces one authority-bearing writer per state directory. A nonblocking,
cross-process transaction lock now spans startup recovery, policy and integrity
checks, authorization, internal execution, external preflight and completion,
settlement, and terminal state. It
is reentrant for nested harness operations and is released by the operating
system when a process crashes, so contention fails closed without creating a
stale-lock repair step. Per-file locks remain the final atomic-write guard.
Command Core and Command Center do not acquire or mutate this authority lock.

v0.15 adds durable continuity for the complete runtime authority profile. The
first authority startup pins the canonical hash of policy rules, known tools,
security-relevant tool contracts, workspace root, dry-run posture, and
adapter/upstream identity. Later drift fails before operational-store recovery
or mutation. A reviewed change requires an explicit operator identity, note,
and exact next hash; signed mode binds it to a trusted Ed25519 key. Rotation is
staged atomically and activates only when that exact candidate runtime starts.
Doctor, Command Core, and the strictly read-only Command Center expose only
sanitized verified, mismatched, invalid, or rotation-required state.

v0.16 adds content-addressed runtime artifact assurance for local stdio MCP
upstreams. Production configurations can require an operator-authored SHA-256
manifest containing the executable and declared supporting artifacts. Defiant
resolves and hashes every file before authority-profile resolution, launches
the verified executable by its absolute path, re-verifies the bundle immediately
before spawning, and binds the canonical bundle hash into the durable v0.15
profile. Missing, replaced, forged, symlinked, or state-directory artifacts fail
closed; a reviewed artifact update requires the normal explicit profile
rotation. Doctor, Command Core, and Command Center show only sanitized pinned,
unverified, mismatched, or invalid assurance and never expose paths or add a
dashboard mutation endpoint.

v0.17 adds launch-envelope integrity around those verified local processes. A
strict stdio MCP configuration starts from an empty child environment, passes
only explicit literal, inherited, or secret variables, requires an explicit
canonical working directory outside harness state, and refuses loader or path
injection variables unless each name is acknowledged. Nonsecret effective
values and the working directory are hashed into the v0.15 authority profile;
secret values are required at launch but deliberately excluded from persisted
hashes so credential rotation neither leaks values nor silently changes launch
policy. Legacy inheritance remains available but is visibly unrestricted.
Doctor, Command Core, and Command Center expose only sanitized counts, hashes,
mode, and profile binding. Command Center remains strictly read-only.

v0.18 hardens the local state filesystem beneath approvals, budgets, evidence,
recovery journals, operator trust, and authority continuity. The canonical
state-root path and filesystem identity enter the complete authority profile;
durable observations reject copied, relocated, or replaced roots. State files
and locks must be regular single-link objects, never symlinks or reparse points,
and path identity is compared with the opened descriptor before use. POSIX
storage additionally requires current-user ownership with `0700` root and
`0600` files. Atomic JSON replacement now validates both sides and syncs the
directory entry where supported. Doctor, Command Core, and Command Center show
only sanitized posture and counts and cannot repair or mutate storage.

v0.19 isolates that protected control plane from governed workspace tools. The
canonical Defiant state root is registered as a protected root before policy
construction and bound into the complete authority profile. Workspace-scoped
file and directory targets are rejected when they enter, alias, or contain
protected state, including through symlinks; validation repeats inside grant
execution so retargeting after authorization fails before dispatch. The
profile-bound durable observation and read-only dashboard expose only hashes,
counts, and the sanitized workspace/state relationship. No exception or
mutation surface is added to Command Center.

v0.20 binds the configured workspace root to its canonical filesystem identity.
Authority startup creates a missing root, rejects final symlink/reparse and
non-directory roots, records a profile-bound sanitized observation, and checks
it before every new harness authority action. Workspace-scoped tools repeat the
identity check immediately before handler or MCP dispatch, before spending the
grant. Workspace contents remain mutable. Doctor, Command Core, and Command
Center expose only hashes and verification state; all remain read-only and the
dashboard gains no acceptance or repair action.

v0.21 adds a profile-bound durable evidence-head checkpoint. Each evidence line
is fsynced before its count and head hash are atomically checkpointed. A valid
chain that extends an older checkpoint is an explicit crash-recovery state and
may advance only after its prefix is proven; a shorter chain or divergent head
blocks authority without repair. Authorized profile activation may rebind only
a matching checkpoint. Doctor, Command Core, and Command Center expose sanitized
checkpoint posture, while Command Center remains strictly read-only.

v0.22 adds optional operator-signed external evidence-head witnessing. Required
mode and trusted Ed25519 key identifiers are bound into the complete authority
profile. Startup verifies that the newest supplied witness belongs to this
state-root identity and an enrolled profile generation, then requires the live
chain to equal or validly extend its witnessed head before profile activation.
This detects restoring evidence and its local checkpoint together when the
newer witness is retained independently. Doctor, Command Core, and the strictly
read-only Command Center expose only sanitized posture; signing, trust files,
and witness retention stay outside `.dah`.

v0.23 adds an opt-in closed dependency-bundle mode for local MCP runtimes.
Operator-authored manifests now can cover complete declared directory trees,
not only individually selected artifacts. Startup rejects any added, missing,
changed, linked/reparse, special, overlapping, or state-directory content;
binds the deterministic closure into the complete authority profile; and
repeats verification immediately before process creation. State Integrity,
Command Core, and the strictly read-only Command Center expose only sanitized
mode, hashes, and counts. This is not an OS sandbox and does not cover loading
surfaces outside the declared roots.

v0.24 adds an optional authority-profile-bound freshness ceiling for signed
external evidence witnesses. Operators may cap how many live evidence records
can exist beyond the retained signed head. Startup and authority gates fail
closed with a distinct `lag_exceeded` diagnostic when the enrolled ceiling is
crossed; refreshing the external witness restores authority. The bound uses
record counts rather than pretending local wall-clock time is trusted. Doctor,
Command Core, and the strictly read-only Command Center expose only the bound
and current lag, never witness paths, signatures, or notes.

v0.25 adds opt-in native Windows private-state ACL assurance. An owning runtime
started with `--require-windows-private-state-acl` requires the state root and
known state files to be owned by the current process user, limits allow ACEs to
that user, LocalSystem, and Builtin Administrators, requires current-user full
control, and requires a protected root DACL that propagates current-user full
control to children. The sanitized posture is authority-profile-bound and is
rechecked by State Integrity; it never exposes paths, SIDs, account names, or
ACE details. The default Windows mode remains `structural_only` for compatible
migration. Command Center remains strictly read-only.

v0.26 adds fixed pre-parse resource ceilings at untrusted ingestion boundaries.
Durable JSON state, individual evidence records, MCP stdio and HTTP messages,
native-hook events, and MCP YAML configuration now fail closed before an
oversized document reaches a parser. YAML aliases and non-finite JSON numbers
are rejected. Command Core and the strictly read-only Command Center expose the
active ceilings without exposing input contents, paths, or a configuration
control. Append-only evidence history remains unlimited in total; each record
is bounded independently.

## Install

```bash
git clone https://github.com/Joefear/Defiant-Agent-Harness.git
cd Defiant-Agent-Harness
pip install -e ".[dev]"
```

Python 3.10+. Runtime dependencies are PyYAML and `cryptography`.

## Try it

Six scenarios, one command each. The first is the demo worth showing anyone.

```bash
# an agent tries to exfiltrate a customer list because a web page told it to
dah demo injected_exfiltration
```

```
tool         send_email -> attacker@evil.example
side effect  external_send
payload      sha256:f7c49caf30efea89...  trust=untrusted
decision     block  [block_untrusted_side_effect]
reason       Payload derives from untrusted external content. Knowledge can
             inform execution; knowledge cannot authorize execution.
status       blocked
evidence     evd_6a2eb246797c45d6
```

```bash
dah demo send_email --auto-approve   # held, approved, then simulated
dah demo overspend                   # blocked: worst-case estimate exceeds budget
dah demo blocked_folder              # blocked: path outside the workspace
dah demo delete                      # blocked: destructive actions off by default
dah demo read_statement              # allowed and logged: no side effect
dah --policy merchant_services demo prohibited_claim   # blocked: guaranteed-savings language
dah --policy legal_intake demo legal_advice            # blocked: advice during intake
```

If `dah pending` reports an approval in `executing`, first confirm that no
executor is still alive and inspect the real external outcome. Then reconcile
it from the operator CLI:

```bash
dah --workdir .dah reconcile apr_... \
  --outcome not_executed \
  --operator operator-7 \
  --note "worker crashed before dispatch"
```

See `docs/approval_reconciliation.md` before using `succeeded` or `failed`.

If `dah doctor` instead reports an approval-free authorization requiring
reconciliation, use its sealed evidence record id:

```bash
dah --workdir .dah reconcile-authorization evd_... \
  --outcome failed \
  --operator operator-7 \
  --note "provider accepted the request but returned no result"
```

See `docs/authorization_reconciliation.md` for its signature, crash, and
conservative budget rules. Command Center displays both queues but remains
strictly read-only.

Then look at what happened:

```bash
dah pending             # what is waiting on a human
dah history             # the full trail, including everything that was refused
dah show <record_id>    # one record in full
dah verify              # confirm the hash chain is intact
dah signing-keygen      # generate an encrypted Ed25519 signing key pair
dah operator-keygen     # generate an encrypted operator identity key pair
dah operator-trust-rotate ... # authorize an additive trust generation
dah authority-profile-rotate ... # stage one exact reviewed runtime profile
dah verify-export ...   # verify a signed export against pinned public keys
dah doctor              # read-only cross-store integrity and recovery audit
dah budget              # ledger, spend, and estimate drift
dah policy              # loaded rules and the ruleset hash
dah export <request_id> # a Command-ready evidence pack
dah command             # read-only Command Core operational snapshot
dah command-center      # local read-only Command Center UI
```

`dah verify` is the one to try tampering with. Edit any line of `.dah/evidence.jsonl` and it will tell you which record broke and how.

To hand evidence to an external reviewer, sign a request export with an
encrypted Ed25519 private key and explicit operator context, then verify it
against a public key distributed through a separate trusted channel. See
`docs/evidence_signing.md` for key generation, signing, verification, rotation,
and compromise handling.

For production approvals, configure signed operator identity on both the
decision command and the runtime that will consume it. The required operator
note is part of the signed statement. See `docs/operator_identity.md` for the
PowerShell commands, native-hook environment configuration, rotation, and
compromise handling.

`dah --workdir .dah command-center` prints the exact loopback URL for the local
dashboard. It never opens an execution or approval path; see
`docs/command_center.md` for the boundary and options.

## Run the MCP stdio proxy

The repository includes a dependency-free demo server and a fully classified
proxy configuration:

```bash
dah --workdir .dah-demo mcp-proxy --config examples/mcp-proxy.yaml
```

That command speaks MCP on stdin/stdout, so it is normally placed in an MCP
client's server configuration rather than run interactively:

```json
{
  "command": "dah",
  "args": [
    "--workdir",
    ".dah",
    "mcp-proxy",
    "--config",
    "/absolute/path/to/mcp-proxy.yaml"
  ]
}
```

The YAML `tools` map is the authority boundary. Each upstream tool declares its
side effect, target argument, conservative cost, dry-run support, target scope,
and argument provenance. Unknown fields fail configuration loading. Tools the
upstream advertises but the operator did not map remain visible in `tools/list`
but are blocked if called.

Approval does not hold a fragile process open:

1. The first `tools/call` returns `isError: true` with a durable approval id.
2. The operator runs `dah --workdir .dah approve <approval_id> --note "..."`
   with the configured operator key and public trust binding.
3. The client retries the exact same tool params.
4. The proxy recognizes the payload fingerprint, re-checks current policy,
   consumes the single-use approval, and forwards the call.

The proxy may restart between steps 1 and 3. Any changed parameter creates a
different authorization hash and cannot use the approval. Rejections remain
terminal for the approval window, preventing an agent from spamming identical
re-proposals.

The fingerprint also binds the runner, user, workspace, authoritative tool
contract, and upstream transport identity. Changing the server command or URL,
side effect, cost, target scope, or workspace root cannot inherit a stale
approval.

The upstream command is always an argument vector and is launched without a
shell. Stdout remains protocol-only; server diagnostics inherit stderr.
For production local upstreams, add a required `server.artifact_integrity`
manifest so the executable and each declared entrypoint, lockfile, or package
artifact are verified before launch. See
`docs/runtime_artifact_integrity.md` for the schema, rotation procedure, and
limits. Configurations without a manifest remain explicitly `unverified` in
read-only diagnostics.
Also configure `server.launch_environment` with an explicit `server.cwd` to
remove ambient child-environment authority. See
`docs/launch_envelope_integrity.md`; omitted launch settings remain visibly
`inherited_unrestricted` for compatibility.

v0.3 negotiates at most MCP protocol revision `2025-06-18`. Newer clients are
downgraded during `initialize` so an upstream server cannot advertise the
experimental task-augmented calls added in `2025-11-25`, which this release
does not yet govern. The complete core `tools/call` params object is bound into
the approval fingerprint. Only the ephemeral `_meta.progressToken` is excluded
so a client may legitimately replace its correlation token on an exact retry.

## Run the Streamable HTTP upstream proxy

Remote MCP servers use the same local stdio-facing shape:

```powershell
$env:REMOTE_MCP_AUTH = "Bearer <token>"
dah --workdir .dah mcp-http-proxy --config examples/mcp-http-proxy.yaml
```

The proxy sends MCP POST requests to the configured HTTPS endpoint, accepts
JSON or SSE responses, maintains the optional MCP session id, and attempts a
session DELETE on shutdown. Auth values come from environment variables rather
than YAML. Remote redirects are refused, response sizes are bounded, and plain
HTTP is allowed only for loopback test servers.

The policy, approval, budget, exact-retry, and evidence behavior is identical
to the stdio upstream. See `docs/streamable_http.md` for configuration,
transport behavior, and current bidirectional-streaming limits.

### Run against a real MCP server

The repository now includes a live integration with the official filesystem
reference server:

```bash
python examples/filesystem/live_demo.py
```

It downloads a pinned server release with `npx`, creates a new disposable
workspace, permits a real read, blocks an unapproved mutation, holds a real
write, asks the operator to approve it, repeats the exact MCP call, and verifies
the resulting evidence chain. The upstream server and Defiant independently
confine paths to the same workspace. Run with `--yes` for a non-interactive
smoke test. See `examples/filesystem/README.md`.

### Connect VS Code and Copilot agents

The committed Windows workspace profile at `.vscode/mcp.json` connects VS Code
to the same official filesystem server through Defiant and binds evidence to
the `vscode-copilot` runner identity. The root `.mcp.json` provides the current
Copilot CLI format and binds its evidence to `copilot-cli-mcp`. Both profiles
are confined to the disposable `examples/vscode_agent/workspace` folder.

The workspace hook at `.github/hooks/defiant.json` covers the separate native
tool path used by local agents and Copilot CLI. It blocks terminal, subagent,
unknown, out-of-workspace, and enforcement-mutation attempts; local writes are
held for exact human approval and completed by a matching `PostToolUse`.

Open the repository folder in VS Code and follow
`examples/vscode_agent/README.md`. It documents both proofs: the MCP transport
boundary and the stronger native hook path.

### Connect Codex

The project-scoped `.codex/config.toml` connects Codex to the Defiant filesystem
proxy, while `.codex/hooks.json` governs supported native Codex tools. The
integration uses separate `codex-hook` and `codex-mcp` runner identities,
model-bound exact approvals, repository-root discovery from nested working
directories, and Codex's official hook output dialect.

Trust the project, restart Codex, review the exact definitions with `/hooks`,
and confirm the server with `/mcp`. Follow `docs/codex_runner.md` for the read,
approval, exact-retry, evidence, and native-bypass proofs.

## Architecture

```
adapter (MCP or hook) ->  orchestrator  ->  policy engine
                              |                  |
                              |            budget ledger
                              |                  |
                              |            approval store  (durable, expiring,
                              |                  |          bound to full action)
                              |                  v
                              +--> evidence store (append-only, hash-chained)
                              |
                              +--> capability grant --> tool registry --> effect
```

The adapter boundary is the design decision that matters most. Hermes, OpenClaw, NanoClaw, Claude Code, and Codex do not hand you a plan and wait for permission — they run their own loop and call their own tools. So the adapter contract here is not "produce a plan for review." It is: intercept a tool call at the transport boundary, hand it to the harness as a `ProposedAction`, and return the harness's outcome to the agent as the tool's result. Since that boundary is overwhelmingly MCP `tools/call`, vendor-neutrality is a property of the design rather than a roadmap item. See `docs/adapter_contract.md`.

## Repository layout

```
src/defiant_agent_harness/
  contracts.py          request, action, decision, evidence, capability grant, provenance
  policy/               deterministic engine + YAML rule packs
  approvals/            durable, expiring, action-bound approval queue
  budgets/              exact-decimal, action-bound reservation and settlement
  command/              integrity-gated projection + loopback-only local UI
  evidence/             append-only hash-chained JSONL store
  tools/                capability-gated registry + reference tools
  adapters/             adapter contract (MCP-shaped) + mock adapter
  mcp/                  strict config + stdio/HTTP transports + tools/call proxy
  hooks/                native PreToolUse/PostToolUse adapter + durable correlation
  orchestrator/         the control loop
  cli/                  local controls + MCP proxy entry point
docs/                   architecture, contracts, threat model, policy examples
tests/                  policy, evidence, grants, approvals, budget, red team
```

## Policy

Rules are YAML so a consultant can read them and a compliance reviewer can audit them without reading Python. The engine is deterministic, strictest-wins, default-deny for side effects, and refuses any tool not declared in a loaded pack's `known_tools` — an unclassified tool must never inherit a permissive rule written for a different one.

```yaml
- id: block_untrusted_side_effect
  side_effect_at_least: external_send
  max_payload_trust: derived
  effect: block
  reason: >
    Payload derives from untrusted external content. Knowledge can inform
    execution; knowledge cannot authorize execution.
```

Ships with `default`, `merchant_services`, and `legal_intake`. Vertical packs layer on top of the default and can tighten it but never loosen it below the engine's own default-deny floor.

## Evidence

One JSONL line per record, each carrying the hash of the record before it.
Payload and output bodies are represented by hashes, while operational metadata
such as targets and identities remains visible. Evidence must therefore be
handled as confidential business data. Every record carries a schema version,
policy version, ruleset hash, and decision-input snapshot. The store refuses to
append when the existing chain is corrupt.

Durable approvals necessarily retain the full held action in the local
`approvals.json` state file so it can resume after a restart. Protect the state
directory accordingly; it is not an export artifact.

See `docs/evidence_contract.md` for the field-by-field evidence contract,
`docs/evidence_signing.md` for offline-verifiable exports,
`docs/operator_identity.md` for signed approval authority,
`docs/approval_reconciliation.md` for crash recovery,
`docs/state_integrity.md` for cross-store auditing, and
`docs/command_core.md` for the read-only snapshot contract. See
`docs/command_center.md` for the local UI and HTTP boundary.

## Tests

```bash
pytest
```

Offline tests plus one opt-in live integration test cover Command Core,
Command Center, and both the MCP and native-hook boundaries. The suite includes a
real subprocess MCP flow across initialization, tool discovery, allow, durable
approval, proxy restart, exact-call retry, destructive block, unmapped-tool
block, and evidence-chain verification. Native-hook tests cover exact approval
retry, payload changes, terminal and subagent bypass, unknown tools,
out-of-workspace paths, guardrail self-modification, result correlation, and
evidence sealing. Known-result tests crash before settlement, after settlement,
after evidence, and before approval consumption, then verify restart without
tool replay, duplicate debit, or duplicate evidence. Authority-lock tests cover
same-thread reentrancy, thread and process contention, crash release, startup
exclusion, and tool-call serialization. Set `DAH_LIVE_MCP=1` to add the pinned
official filesystem server to a test run.

## Status

v0.26 — local control loop, generic MCP stdio and Streamable HTTP upstreams,
preview native VS Code/Copilot and Codex hook adapters, a read-only Command Core
snapshot, a loopback-only read-only Command Center UI, and crash-safe operator
reconciliation for approval-backed and approval-free uncertain executions,
known-result completion recovery, deterministic local operation recovery,
cross-store integrity gating, cross-process authority serialization,
durable full-authority-profile continuity and explicit staged rotation,
content-addressed local runtime artifact assurance with opt-in closed declared
dependency roots,
restricted and authority-bound local process launch envelopes,
authority-bound state-root identity, hardened local persistence, and optional
profile-bound native Windows private-state ACL assurance,
profile-bound control-plane path isolation for governed workspace tools,
profile-bound workspace-root identity and replacement detection,
profile-bound crash-safe evidence-head checkpointing,
profile-bound operator-signed external evidence-head witnessing with optional
maximum unwitnessed-record lag,
fixed fail-closed pre-parse resource ceilings across durable state, evidence,
MCP transports, native hooks, and MCP configuration,
offline-verifiable signed evidence exports, signed operator authority, and
durable downgrade-resistant operator trust enrollment. Not a hosted platform.
The hook controls tool calls that emit supported lifecycle events. Direct
process activity outside those events, and the documented fail-open
hook-timeout behavior, still require OS/network isolation. See
`docs/architecture.md`, `docs/approval_reconciliation.md`,
`docs/authorization_reconciliation.md`, `docs/operation_journal.md`,
`docs/known_result_recovery.md`, `docs/authority_lock.md`,
`docs/authority_profile.md`,
`docs/runtime_artifact_integrity.md`,
`docs/launch_envelope_integrity.md`,
`docs/state_storage_integrity.md`,
`docs/control_plane_isolation.md`,
`docs/workspace_root_integrity.md`,
`docs/evidence_head_integrity.md`,
`docs/evidence_head_witness.md`,
`docs/bounded_ingestion.md`,
`docs/state_integrity.md`,
`docs/evidence_signing.md`,
`docs/operator_identity.md`,
`docs/command_center.md`, `docs/streamable_http.md`, `docs/native_hooks.md`, and
`docs/codex_runner.md`.
