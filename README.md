# Defiant Agent Harness

Control, approvals, budgets, memory discipline, and audit evidence for business-grade AI agents.

Defiant Agent Harness wraps MCP-capable and other agentic AI systems with
business-grade controls: tool permissions, human approval gates, budget limits,
provenance discipline, prompt-injection resistance, and Command-ready evidence
logs. A full trusted-memory/DKE system is not part of v0.10.

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

## What v0.10 is

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

Then look at what happened:

```bash
dah pending             # what is waiting on a human
dah history             # the full trail, including everything that was refused
dah show <record_id>    # one record in full
dah verify              # confirm the hash chain is intact
dah signing-keygen      # generate an encrypted Ed25519 signing key pair
dah operator-keygen     # generate an encrypted operator identity key pair
dah operator-trust-rotate ... # authorize an additive trust generation
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
evidence sealing. Set `DAH_LIVE_MCP=1` to add the pinned official filesystem
server to a test run.

## Status

v0.10 — local control loop, generic MCP stdio and Streamable HTTP upstreams,
preview native VS Code/Copilot and Codex hook adapters, a read-only Command Core
snapshot, a loopback-only read-only Command Center UI, and crash-safe operator
reconciliation, cross-store integrity gating, offline-verifiable signed
evidence exports, signed operator approval authority, and durable downgrade-
resistant operator trust enrollment. Not a hosted platform.
The hook controls tool calls that emit supported lifecycle events. Direct
process activity outside those events, and the documented fail-open
hook-timeout behavior, still require OS/network isolation. See
`docs/architecture.md`, `docs/approval_reconciliation.md`,
`docs/state_integrity.md`, `docs/evidence_signing.md`,
`docs/operator_identity.md`,
`docs/command_center.md`, `docs/streamable_http.md`, `docs/native_hooks.md`, and
`docs/codex_runner.md`.
