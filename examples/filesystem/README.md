# Live official filesystem demo

This demo puts Defiant in front of the official
`@modelcontextprotocol/server-filesystem` reference server. It exercises a real
MCP SDK server and real filesystem I/O in a newly created disposable workspace.

The flow is:

1. initialize the official MCP server and discover its tools;
2. allow and record a workspace read;
3. block an unapproved local mutation before it reaches the server;
4. hold a real file write for a human;
5. approve or reject it with the normal `dah` CLI;
6. repeat the exact `tools/call`;
7. execute the approved write and verify the evidence chain.

## Prerequisites

- Python 3.10+ with this repository installed (`pip install -e ".[dev]"`)
- Node.js with `npx`
- network access the first time `npx` downloads the pinned official server

Run from the repository root:

```bash
python examples/filesystem/live_demo.py
```

Use `--yes` for a non-interactive smoke test:

```bash
python examples/filesystem/live_demo.py --yes
```

Every run gets its own ignored folder under `examples/filesystem/runs/`. The
workspace and `.dah` evidence state are retained so the result can be inspected.

## Automatic live CI

S3 runs the existing end-to-end pytest case on Linux and Windows daily,
on manual CI dispatch, and on `v*` tag pushes. Ordinary pytest remains opt-in
and offline by default. To run the same fail-on-skip entry point in PowerShell:

```powershell
$env:DAH_LIVE_MCP = '1'
python examples/filesystem/live_ci.py
Remove-Item Env:DAH_LIVE_MCP
```

CI installs Node 22 and runs
`@modelcontextprotocol/server-filesystem@2026.7.10`. The test creates a
fresh temporary workspace and npm cache; it does not use real merchant data.
The CLI `--yes` is fixture-only operator approval for that disposable write,
not unattended approval for a deployed workspace. See `../../docs/live_mcp_ci.md`
for trigger, failure-proof, and release-validation requirements.

## Configuration

`mcp-proxy.yaml` is an operator-authored classification of a useful subset of
the official server. Read-only tools have `side_effect: none`; `write_file` and
`create_directory` are local writes; edits are destructive. File paths use
`target_scope: workspace`; directory tools use `workspace_path`, which also
allows the workspace root. The upstream server independently receives only the
same allowed directory.

Tool paths may be relative to that allowed directory or absolute paths inside
it. The live script uses absolute paths to match real IDE-agent behavior;
Defiant canonicalizes them to `workspace/...` for policy and evidence while
binding and forwarding the unchanged transport payload. Both confinement layers
still resolve them against the same workspace root.

`read_multiple_files` and `move_file` are intentionally not mapped because they
have multiple path targets and do not fit the proxy's current single-target
confinement contract. They remain visible in `tools/list` but Defiant blocks
them if called. This is fail-closed, not an accidental omission.

The package version is pinned so an upstream release cannot silently change the
demo's authority boundary. Review and update the tool map before changing that
pin. The current official package may emit an npm deprecation warning for its
`glob` dependency; that is an upstream diagnostic on stderr and does not corrupt
the MCP stream. Resolve and lock the complete dependency tree before treating
this example as a production deployment.
