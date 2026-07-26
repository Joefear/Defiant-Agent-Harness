# VS Code real-agent proof

This workspace profile connects VS Code's agent mode to the Defiant-governed
official filesystem MCP server. It is the first proof using a real model-driven
runner rather than the repository's scripted MCP client.

## Open the correct folder

Open this exact folder in VS Code:

```text
C:\Users\samcf\Documents\Codex\2026-07-25\defiant-agent-harness\work\publish-checkout
```

The Explorer should show `.github`, `.vscode`, `docs`, `examples`, `src`, and
`tests`. If it shows `_to_delete`, that is the older build copy.

## Start the governed server

1. Press `Ctrl+Shift+P`.
2. Run **MCP: List Servers**.
3. Select **defiant-filesystem**, then **Start Server**.
4. Review the command in `.vscode/mcp.json` and accept VS Code's trust prompt.
5. If the server was already cached, run **MCP: Reset Cached Tools**, then
   restart it.

The first start can take a moment while `npx` downloads the pinned official
filesystem server. Its access is restricted to `workspace/` below.

## Restrict the agent for this proof

VS Code has built-in editing and terminal tools that do not cross the MCP
proxy. In the Chat tools picker, disable built-in write/edit and terminal tools
for this session and enable the `defiant-filesystem` MCP tools. This is required
for an honest boundary test; prompt instructions alone are not containment.

Use this prompt in Agent mode:

```text
Use only the defiant-filesystem MCP tools.
First list the allowed directories and list the workspace root.
Read briefing.txt.
Then write generated/agent-note.txt with:
"VS Code agent completed the governed merchant follow-up."
Do not use built-in file, edit, or terminal tools.
```

VS Code may show its own MCP confirmation before the call. Defiant then returns
a durable pending approval instead of executing the write.

## Approve and retry

Open a terminal yourself and run:

```powershell
$env:PYTHONPATH="$PWD\src"
python -m defiant_agent_harness.cli.main --workdir .dah-vscode pending
python -m defiant_agent_harness.cli.main --workdir .dah-vscode --user vscode-operator approve <approval_id>
```

Then tell the agent:

```text
Retry the exact same defiant-filesystem write_file call now.
After it succeeds, read generated/agent-note.txt back to me.
```

Finally verify the evidence:

```powershell
python -m defiant_agent_harness.cli.main --workdir .dah-vscode verify
python -m defiant_agent_harness.cli.main --workdir .dah-vscode history
```

The expected trail contains allowed root/list/read records, a held
`write_file`, an authorization record, the successful real write, and the
read-back.

## Boundary statement

This proves that VS Code can choose and use Defiant-governed MCP tools. It does
not prevent the runner from using enabled native tools, direct subprocesses, or
another unproxied MCP configuration. Production containment requires native
permission hooks or OS isolation in addition to this transport boundary.
