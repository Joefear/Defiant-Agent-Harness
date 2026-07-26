# Defiant Agent Harness

Control, approvals, budgets, memory discipline, and audit evidence for business-grade AI agents.

Defiant Agent Harness wraps MCP-capable and other agentic AI systems with
business-grade controls: tool permissions, human approval gates, budget limits,
provenance discipline, prompt-injection resistance, and Command-ready evidence
logs. A full trusted-memory/DKE system is not part of v0.2.

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

## What v0.2 is

A headless local control loop plus a generic MCP stdio proxy. The proxy launches
one configured upstream MCP server, transparently forwards ordinary protocol
traffic, and intercepts `tools/call`. It validates an intercepted action against
the authoritative operator-authored tool map, evaluates deterministic policy,
checks budget, holds durably for human approval, executes through the gated
path, and writes a hash-chained evidence trail—including for actions that never
ran.

The v0.1 reference tools remain safe fixtures: only `read_file` performs real
I/O, confined to one workspace, while their side effects are simulated. The
v0.2 proxy is a real execution boundary: a permitted or approved call is
forwarded to the configured upstream server and can therefore have real side
effects.

The dashboard is Defiant Command, and it comes after the records are real and stable. This repository produces the records Command will consume.

## Install

```bash
git clone https://github.com/Joefear/Defiant-Agent-Harness.git
cd Defiant-Agent-Harness
pip install -e ".[dev]"
```

Python 3.10+. The only runtime dependency is PyYAML.

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

Then look at what happened:

```bash
dah pending             # what is waiting on a human
dah history             # the full trail, including everything that was refused
dah show <record_id>    # one record in full
dah verify              # confirm the hash chain is intact
dah budget              # ledger, spend, and estimate drift
dah policy              # loaded rules and the ruleset hash
dah export <request_id> # a Command-ready evidence pack
```

`dah verify` is the one to try tampering with. Edit any line of `.dah/evidence.jsonl` and it will tell you which record broke and how.

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
2. The operator runs `dah --workdir .dah approve <approval_id>`.
3. The client retries the exact same tool params.
4. The proxy recognizes the payload fingerprint, re-checks current policy,
   consumes the single-use approval, and forwards the call.

The proxy may restart between steps 1 and 3. Any changed parameter creates a
different authorization hash and cannot use the approval. Rejections remain
terminal for the approval window, preventing an agent from spamming identical
re-proposals.

The fingerprint also binds the runner, user, workspace, authoritative tool
contract, and upstream command identity. Changing the server command, side
effect, cost, target scope, or workspace root cannot inherit a stale approval.

The upstream command is always an argument vector and is launched without a
shell. Stdout remains protocol-only; server diagnostics inherit stderr.

v0.2 negotiates at most MCP protocol revision `2025-06-18`. Newer clients are
downgraded during `initialize` so an upstream server cannot advertise the
experimental task-augmented calls added in `2025-11-25`, which this release
does not yet govern. The complete core `tools/call` params object, including
`_meta`, is forwarded and bound into the approval fingerprint.

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

## Architecture

```
adapter (MCP-shaped)  ->  orchestrator  ->  policy engine
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
  evidence/             append-only hash-chained JSONL store
  tools/                capability-gated registry + reference tools
  adapters/             adapter contract (MCP-shaped) + mock adapter
  mcp/                  strict config + stdio transport + tools/call proxy
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

See `docs/evidence_contract.md` for the field-by-field contract that Defiant Command consumes.

## Tests

```bash
pytest
```

120 offline tests plus one opt-in live integration test. The suite includes a
real subprocess MCP flow across initialization, tool discovery, allow, durable
approval, proxy restart, exact-call retry, destructive block, unmapped-tool
block, and evidence-chain verification. Set `DAH_LIVE_MCP=1` to add the pinned
official filesystem server to a test run.

## Status

v0.2 — headless local control loop and generic MCP stdio proxy. Not a platform.
The proxy controls only calls actually routed through it; native tools, direct
network access, subprocesses, and other runner escape paths require native
permission hooks or OS isolation. See `docs/architecture.md`.
