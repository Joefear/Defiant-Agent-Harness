# Adapter contract

## The design decision

The intuitive adapter design is: ask the agent for a plan, inspect the plan, then run it. It is wrong, and it is worth being explicit about why, because the v0.1 planning documents assumed it.

Hermes, OpenClaw, NanoClaw, Claude Code, and Codex do not produce a plan and wait for permission. They run their own loop and call their own tools. An architecture that depends on the agent volunteering its intentions only governs agents that agree to be governed — which is not the population anyone is worried about.

Each runner needs a real interception boundary where tools reach the outside
world. For MCP-capable tool surfaces, that boundary is `tools/call`. Native
permission hooks or OS/network sandboxing are required where a runner can act
outside the proxied MCP surface.

So the adapter contract is:

> Intercept a tool call at the transport boundary, hand it to the harness as a `ProposedAction`, and return the harness's outcome to the agent as that tool's result.

An adapter is a proxy. The harness is a decision service behind it. Three consequences follow.

**The control contract is vendor-neutral.** MCP-capable runners can share the
same proxy implementation. Runner-specific configuration still needs review,
and non-MCP action paths remain outside coverage until intercepted separately.

**A block is a tool error, not a kill.** The agent receives a normal `isError` result saying permission was denied, reasons about it, and continues. Killing the agent produces a worse user experience and no additional safety.

**An approval hold is a pending handle.** The agent can wait on it or abandon the call and be informed later. Either way the authority sits with the harness, not the agent.

## Implementing one

Subclass `AgentAdapter` and supply four things:

```python
class HermesAdapter(AgentAdapter):
    runner_name = "hermes"

    # 1. Tool name -> proposed side effect classification.
    #    The registry independently verifies this against ToolSpec.
    tool_side_effects = {
        "read_file": SideEffect.NONE,
        "send_email": SideEffect.EXTERNAL_SEND,
        ...
    }

    def provenance_for(self, call: ToolCall) -> list[ContentRef]:
        # 2. Where did this call's arguments come from? If you cannot prove it,
        #    return DERIVED. Never TRUSTED by default.
        ...

    def estimate_cost(self, call: ToolCall) -> Decimal:
        # 3. Worst case, not expected case. Overestimating is the safe direction.
        ...

    def propose(self, task: str) -> Iterable[ToolCall]:
        # 4. For a proxy adapter this yields calls as they arrive on the wire.
        ...
```

`ToolCall` deliberately mirrors the MCP `tools/call` shape (`name`, `arguments`, `call_id`, `server`) so a proxy adapter is a translation rather than a rewrite. `ToolCallOutcome.as_mcp_result()` emits a result an MCP client accepts without special-casing, with harness metadata under a `_defiant` key.

## Provenance is the adapter's real job

Policy quality is capped by provenance quality. An adapter that marks everything
`TRUSTED` can disable the injection defence while appearing to work. Every real
adapter therefore needs adversarial provenance tests before it is supported.

So the default in `AgentAdapter.provenance_for` is `DERIVED`, and adapters must actively downgrade to `UNTRUSTED` for content the runner pulled from outside. The reference `read_file` tool shows the minimum viable version: any path containing `inbound`, `external`, `web`, `email`, `downloads`, or `shared` returns `UNTRUSTED`. A real adapter should do better, using whatever the runner knows about its own context sources — retrieval results, fetched URLs, message bodies, MCP server identity.

Getting this wrong is the most likely way to ship a harness that does nothing while looking correct. Review adapters on this point specifically.

## Build order

1. **Mock adapter** — done. Scripted, deterministic, carries the red-team fixtures.
2. **MCP stdio proxy** — sits between a runner and its MCP servers. This is the next build and unlocks most of the target list at once.
3. **MCP HTTP proxy** — same contract, remote servers.
4. **Runner config shims** — `hermes`, `claude-code`, `codex`, `nanoclaw`: side-effect maps and provenance rules, no new integration logic.
5. **Native permission hooks** — for runners that expose a permission callback, which gives better provenance than the proxy can infer.
