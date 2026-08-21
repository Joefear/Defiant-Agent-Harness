# Native agent hook boundary

## Purpose

Some runners expose built-in file, terminal, browser, and subagent tools that
cannot be removed from their agent UI. Those calls never cross an MCP proxy.
The native hook adapter covers that second authority boundary.

VS Code and Copilot CLI emit a structured `PreToolUse` event before a supported
tool call and a `PostToolUse` event after success. Defiant converts the pre
event into the same `ProposedAction` used by MCP, then returns `allow` or `deny`
through the hook protocol.

## Flow

```text
agent native tool
      |
      v
PreToolUse -> Defiant policy / budget / approval / evidence
      |                 |
      | deny            +-- pending exact-call approval
      v
 external tool executes
      |
      v
PostToolUse -> correlate exact session/tool/arguments -> seal result -> consume approval
```

An allowed pre-event produces a sealed `skipped` record whose detail is
`authorized; external execution pending`. It does not claim the external tool
already succeeded. Only the matching post-event can append the terminal
`succeeded` record.

## Native mapping

The adapter accepts both the Claude-compatible names reported by Copilot CLI
and common VS Code runtime names.

| Native family | Defiant action | Classification |
| --- | --- | --- |
| Read/view | `read_file` | `none` |
| Write/edit/create | `write_file` | `local_write` |
| Grep/glob/workspace search | `search_native` | `none` |
| Web fetch/search | `search_web` | `none` |
| Ask-user/todo control | `agent_control` | `none` |
| Known `defiant-filesystem-*` MCP tools | `proxied_mcp` | `none` (delegated) |
| Shell/terminal | `native_terminal` | `destructive` |
| Subagent/task spawn | `native_agent` | `destructive` |
| Anything else | `native_unknown` | `destructive` |

Unknown tools are deliberately registered with the most dangerous
classification so the default destructive rule blocks them and records why.
Copilot prefixes MCP tools with their configured server name. The hook permits
only the exact tool inventory under the operator-controlled
`defiant-filesystem` namespace, then the inner MCP proxy performs the real
per-tool policy, approval, and evidence decision. An unknown tool in that
namespace remains destructive and fails closed.

Delegated MCP calls do not use the outer hook's `PostToolUse` correlation
store. Copilot does not emit `PostToolUse` after every MCP error, including an
approval-required result, so duplicating the inner proxy's lifecycle state
would strand an otherwise valid exact retry. The outer hook records its
delegation decision; the inner proxy exclusively owns approval, retry,
completion, and terminal evidence for the MCP call.

## Exact approval binding

The external execution fingerprint binds:

- hook mapping version;
- enforcement-owner fingerprint;
- session id;
- workspace root;
- original native tool name; and
- the complete native tool input object.

The first sensitive call is denied and stored durably. CLI approval does not
execute anything. An exact retry is recognized, current policy is checked
again, and the approval moves to `executing`. A changed path, content byte,
command, recipient, session, workspace, mapping, or policy cannot inherit it.

If the process stops after authorization but before `PostToolUse`, Defiant does
not claim success. An approval left in `executing` is treated as uncertain and
automatic replay is refused.

For v0.9 signed mode, set `DAH_TRUSTED_OPERATOR_KEYS` to a JSON array of
`IDENTITY=PUBLIC_KEY.pem` bindings before starting the runner. The hook loads
only public keys and fails closed on malformed configuration or an unsigned,
invalid, untrusted, or replayed approval. See `operator_identity.md`.

Current Copilot CLI camel-case payloads do not include a tool invocation ID.
Defiant therefore derives a stable correlation key from the session, working
directory, tool name, and complete normalized arguments. Sequential identical
calls are supported. A second indistinguishable call that arrives before the
first completes is refused because its result cannot be correlated safely.

## Self-protection

The `copilot_hook` strictest-wins policy blocks native writes to:

- `.github/hooks`;
- `.dah-hooks`;
- `.mcp.json` and `.vscode/mcp.json`;
- `examples/filesystem/mcp-proxy.yaml`;
- `scripts`; and
- `src/defiant_agent_harness`.

Terminal, subagent, unknown, and path-escape attempts are blocked before
execution. These controls protect the hook's user-space trusted computing base
from the agent it is currently governing.

## Honest limits

Hooks are a Preview runner feature, not an operating-system sandbox.

- VS Code documents command-hook timeouts as fail-open into the runner's normal
  permission flow.
- A direct process action that emits no lifecycle event cannot be seen here.
- `PostToolUse` reports successful completion; a missing post-event remains
  authorization-pending or execution-uncertain rather than being guessed.
- Hook code runs with the VS Code process permissions.
- Operator or administrator changes to hook configuration remain trusted.

Production deployment still needs OS, process, and network containment around
the runner. The hook materially closes the native-tool gap; it does not erase
the outer sandbox requirement.
