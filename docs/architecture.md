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

## What is deliberately absent from v0.1

- **A dashboard.** That is Defiant Command. Building a control panel before the records exist produces an empty control panel.
- **DKE / the knowledge engine.** `memory_sources_used` exists in the evidence contract as an empty field so the schema does not change when DKE arrives.
- **Spartan Swarm.** Multi-agent missions need a working single-agent gate first.
- **Real MCP proxy adapters.** The contract is defined and the mock adapter proves the loop; the stdio and HTTP proxies are the next build.
- **Real side effects.** Only workspace-confined reads perform I/O. Writes,
  sends, publishes, exports, deletes, and spends are simulated.
- **Signed evidence.** The chain detects tampering by anyone without write access to the whole file. It does not yet prove authorship to a third party, which needs a signing key and a key-management story.
- **Multi-user identity.** `approved_by` is a string. Real identity binding is a later arc.

## Known limits

- **Approval state contains sensitive payloads.** Durable restart-safe resume
  requires the local approval store to retain the held action. The state
  directory must be access-controlled and is not suitable for evidence export.
- **Evidence is append-only by convention at the filesystem layer.** Anyone with write access to the file can truncate it; the chain makes alteration and deletion *detectable*, not impossible. Off-box replication is the answer, and it belongs to Command.
- **Deterministic phrase matching is bypassable by paraphrase.** See above.
- **`estimate_cost` is a stub** for everything except explicit spend amounts. Token-cost estimation per runner is adapter work.
- **In-process code is trusted.** Signed grants constrain adapters and normal
  control flow; they do not sandbox malicious Python already executing inside
  the harness process.
- **An `executing` approval requires reconciliation after a crash.** The store
  marks execution intent before calling a tool. If the process dies in that
  window, automatic replay is refused because the prior side effect may have
  occurred. An operator must reconcile the evidence and external system.
