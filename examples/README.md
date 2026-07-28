# Examples

Workspaces mirroring the demo workflows in the build document. Each is a
folder plus the policy pack it runs under; the scenarios themselves live in the
mock adapter's `SCRIPTS` so they stay deterministic and testable.

    usaveprocessing/     merchant statement review   --policy merchant_services
    legal_intake/        attorney intake             --policy legal_intake
    content_publishing/  drafting and publishing     default pack
    filesystem/          live official MCP server    real governed file I/O
    vscode_agent/        real VS Code/Copilot proof  MCP profile + native hooks

Run one:

    cd examples/usaveprocessing
    dah demo prohibited_claim --policy merchant_services
    dah demo send_email --policy merchant_services --auto-approve
    dah history
    dah verify

Run the live MCP integration from the repository root:

    python examples/filesystem/live_demo.py

It uses the pinned official filesystem reference server, confines it to a fresh
workspace, holds a real write for approval, retries the exact MCP call, and
verifies the evidence chain. See `filesystem/README.md`.

For a model-driven run, open the repository in VS Code and follow
`vscode_agent/README.md`. The committed `.vscode/mcp.json` governs MCP calls;
`.github/hooks/defiant.json` governs supported native agent tool calls.
