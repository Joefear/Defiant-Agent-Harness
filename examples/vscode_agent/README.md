# VS Code and Copilot real-agent proofs

This repository exposes two real model-driven boundaries:

1. the generic MCP proxy, for calls voluntarily routed through the
   `defiant-filesystem` server; and
2. native `PreToolUse`/`PostToolUse` hooks, for built-in VS Code and Copilot CLI
   tools that do not cross an MCP proxy.

The native hook proof is the stronger test for the current Agents window.

## Open the correct folder

Open this exact folder in VS Code:

```text
C:\Users\samcf\Desktop\Dev\Defiant Agent Harness
```

The Explorer should show `.github`, `.vscode`, `.mcp.json`, `docs`, `examples`,
`src`, and `tests`. If it shows `_to_delete`, that is the archived Claude
build.

## Proof A: govern Copilot CLI native tools

The workspace hook configuration is `.github/hooks/defiant.json`. VS Code loads
it automatically and runs `scripts/defiant_hook.py` before and after supported
agent tool calls.

1. Open the **Agents** window.
2. Start a new **Copilot CLI** session for this repository.
3. Select **Folder isolation** so the proof operates in this exact checkout.
4. Leave the native tools enabled. Defiant now governs them at the hook
   boundary; disabling them is not required for this proof.
5. Use **Default Approvals**, not Bypass Approvals or Autopilot.

Submit:

```text
Read examples/vscode_agent/workspace/briefing.txt.
Then create examples/vscode_agent/workspace/generated/native-agent-note.txt
with exactly:
"Copilot CLI completed the Defiant-governed native write."
Use the normal file tools. Do not use the terminal.
```

The read should be authorized. The native write should be denied with a durable
Defiant approval id before it executes.

Open a terminal yourself in the repository root:

```powershell
$env:PYTHONPATH="$PWD\src"
python -m defiant_agent_harness.cli.main --workdir .dah-hooks --workspace-root . pending
python -m defiant_agent_harness.cli.main --workdir .dah-hooks --workspace-root . --user vscode-operator approve <approval_id>
```

Tell the same agent:

```text
Retry the exact same native file-write tool call now.
After it succeeds, read the file back to me.
```

The exact retry is allowed once. `PostToolUse` then seals the successful external
result and consumes the approval.

Verify:

```powershell
python -m defiant_agent_harness.cli.main --workdir .dah-hooks --workspace-root . verify
python -m defiant_agent_harness.cli.main --workdir .dah-hooks --workspace-root . history
```

The default hook policy blocks:

- terminal and shell tools;
- subagent spawning;
- unknown native tools;
- workspace path escapes;
- edits to `.github/hooks`, `.dah-hooks`, `scripts`, or the Defiant Python
  package.

## Proof B: govern the official filesystem MCP server

The repository carries both supported client formats:

- `.vscode/mcp.json` for VS Code; and
- `.mcp.json` for Copilot CLI.

The Copilot CLI profile uses `scripts/defiant_mcp.cmd` to find Python through
the standard Windows launcher because Copilot's MCP process does not resolve
PowerShell App Paths. Set `DAH_PYTHON` to an absolute Python executable path
only when Python is installed in a nonstandard location.

Press `Ctrl+Shift+P`, run **MCP: List Servers**, select
**defiant-filesystem**, and start it. The first start can take a moment while
`npx` downloads the pinned official server. The MCP server is independently
confined to `examples/vscode_agent/workspace`.

Use the standard main-window Chat view with a local Agent. In the per-request
**Configure Tools** picker, disable built-in write/edit and terminal tools and
enable the `defiant-filesystem` group. Copilot CLI tools in the separate Agents
window cannot be removed, which is why Proof A uses native hooks instead.

Submit:

```text
Use only the defiant-filesystem MCP tools.
First list the allowed directories and list the workspace root.
Read briefing.txt.
Then write generated/agent-note.txt with:
"VS Code agent completed the governed merchant follow-up."
Do not use built-in file, edit, or terminal tools.
```

Approve the held MCP write:

```powershell
$env:PYTHONPATH="$PWD\src"
python -m defiant_agent_harness.cli.main --workdir .dah-vscode pending
python -m defiant_agent_harness.cli.main --workdir .dah-vscode --user vscode-operator approve <approval_id>
```

Then ask the agent to retry the exact same `write_file` call and read the file
back. Verify `.dah-vscode` with the same `verify` and `history` commands.

For Copilot CLI, start a new session after `.mcp.json` is present, enter
`/mcp list`, and confirm that `defiant-filesystem` is connected. Its independent
ledger is `.dah-copilot-mcp`, its runner identity is `copilot-cli-mcp`, and it
uses the same disposable filesystem workspace. Use the same proof prompt, then
approve and verify with:

```powershell
$env:PYTHONPATH="$PWD\src"
python -m defiant_agent_harness.cli.main --workdir .dah-copilot-mcp pending
python -m defiant_agent_harness.cli.main --workdir .dah-copilot-mcp --user copilot-cli-operator approve <approval_id>
python -m defiant_agent_harness.cli.main --workdir .dah-copilot-mcp verify
```

## Boundary statement

The MCP proof is transport control, not containment. The native hook proof
covers supported lifecycle tool events across current VS Code agent types, but
hooks are still a Preview feature. VS Code documents hook timeouts as fail-open;
a timed-out hook falls back to the runner's normal permission flow. Direct
activity that emits no hook event also remains outside this layer. Production
containment therefore still requires OS and network isolation.
