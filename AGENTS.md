# Defiant Agent Harness contributor instructions

- Treat Defiant as the authority boundary. Do not bypass a hook or MCP denial
  with a native terminal, a different file tool, or another agent.
- Use the `defiant_filesystem` MCP server for the disposable proof workspace at
  `examples/vscode_agent/workspace`.
- When Defiant returns an approval ID, stop and report it. After the operator
  approves it, retry the exact same tool call without changing any arguments.
- Never modify `.codex/`, `.github/hooks/`, the Defiant policy or hook code, or
  durable `.dah-*` state through a governed agent session.
- Run `python -m pytest` and `python -m ruff check .` before proposing a commit.
