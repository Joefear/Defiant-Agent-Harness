# Codex runner integration

The repository includes a project-scoped Codex shim with two enforcement
boundaries:

1. `.codex/hooks.json` sends supported local tool calls through Defiant before
   execution and seals the result afterward.
2. `.codex/config.toml` exposes the disposable proof workspace through the
   Defiant MCP proxy instead of directly exposing the upstream filesystem
   server.

Both layers use the same policy, exact-call approval, budget, and hash-chained
evidence machinery. They use separate durable state:

- `.dah-codex-hooks/` for native Codex lifecycle events
- `.dah-codex-mcp/` for the governed filesystem MCP server

## Start a governed Codex session

Open the repository root in Codex and trust the project. Codex loads
project-scoped `.codex/config.toml`, hooks, and rules only for trusted projects.
Restart the Codex session after changing those files.

In Codex:

1. Run `/hooks`, inspect the two Defiant command hooks, and trust their exact
   definitions.
2. Run `/mcp` and confirm `defiant_filesystem` is enabled.
3. Ask Codex to use only `defiant_filesystem` to list allowed directories and
   read `briefing.txt`.

The committed MCP server has `default_tools_approval_mode = "auto"` on purpose.
That disables a redundant outer Codex prompt; Defiant still evaluates and,
when required, durably holds the exact inner `tools/call`.

These behaviors follow the current official Codex references for
[project configuration](https://learn.chatgpt.com/docs/config-file/config-reference.md),
[hooks](https://learn.chatgpt.com/docs/hooks.md),
[MCP servers](https://learn.chatgpt.com/docs/extend/mcp.md), and
[AGENTS.md](https://learn.chatgpt.com/docs/agent-configuration/agents-md).

## Prove a governed MCP write

Ask Codex:

```text
Use only defiant_filesystem.write_file.
Write exactly this file:
C:\Users\samcf\Desktop\Dev\Defiant Agent Harness\examples\vscode_agent\workspace\generated\codex-mcp-note.txt

With exactly this content:
Codex completed the Defiant-governed MCP write.

Do not use native file or terminal tools. If blocked, report the approval ID.
```

Defiant should return an approval ID. In a normal PowerShell terminal at the
repository root, approve it:

```powershell
$env:PYTHONPATH="src"
python -m defiant_agent_harness.cli.main --workdir ".dah-codex-mcp" --workspace-root "examples/vscode_agent/workspace" --user "codex-operator" approve "<approval-id>"
```

Then tell Codex to retry the exact same `defiant_filesystem.write_file` call
without changing the path, content, or arguments. The file should be written
and the evidence chain completed.

## Prove the native hook

Ask Codex to run `Get-Location` with its terminal tool. The native `Bash` tool
is classified as destructive by this preview policy and should be denied
before execution.

Ask Codex to create `native-codex-note.txt` with its native patch or write
tool. A normal derived local write should be held for approval. Approve it from
PowerShell with the hook state directory:

```powershell
$env:PYTHONPATH="src"
python -m defiant_agent_harness.cli.main --workdir ".dah-codex-hooks" --workspace-root "." --user "codex-operator" approve "<approval-id>"
```

Then retry the exact same native tool input. `PostToolUse` seals the external
result in the evidence chain.

Codex cannot use the governed native write path to alter `.codex/`, `.git/`,
the hook launcher, the policy implementation, or durable Defiant state. The
target extractor also inspects every file named by an `apply_patch` payload,
so putting a protected file second does not bypass the guardrail.

## Scope and limitations

- Codex hooks cover local function tools that emit supported lifecycle events,
  including the shell, `apply_patch`, MCP tools, and agent spawning. Hosted
  tools such as web search are not currently hook-covered.
- The outer hook recognizes only the configured Defiant filesystem MCP tool
  names. Those calls are delegated to the inner proxy; unknown MCP tools fail
  closed.
- A hook is a strong policy and evidence interception point, not an operating
  system sandbox. Direct process or network activity outside emitted tool
  events still requires OS, container, and network isolation.
- Approval is bound to the runner, model, session, workspace, canonical tool
  map, and exact tool input. Changing any of those creates a different action.
