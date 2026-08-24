# Streamable HTTP upstream

Defiant v0.3 can govern a remote MCP server that implements Streamable HTTP.
The agent still launches Defiant as a local stdio MCP server:

```text
agent <-- local stdio --> Defiant <-- HTTPS POST/SSE --> remote MCP server
```

Defiant does not open a local HTTP listener. This keeps the runner integration
identical to the stdio proxy and avoids creating an unauthenticated local
network endpoint.

## Configure the remote server

Start from `examples/mcp-http-proxy.yaml`:

```yaml
server:
  name: remote-example
  url: https://mcp.example.com/v1
  timeout_seconds: 30
  header_env:
    Authorization: REMOTE_MCP_AUTH

runner: generic-mcp-client

tools:
  lookup:
    side_effect: none
  send_email:
    side_effect: external_send
    target_arg: to
```

`header_env` maps an HTTP header name to the name of an environment variable.
The secret value is read only when the process starts:

```powershell
$env:REMOTE_MCP_AUTH = "Bearer <token>"
dah --workdir .dah mcp-http-proxy --config examples/mcp-http-proxy.yaml
```

Point the agent's MCP configuration at that `dah` command. The YAML `tools`
map has the same fail-closed authority contract as the stdio proxy. Unmapped
tools may appear in `tools/list`, but calling one is refused.

## Transport behavior

The client implements the MCP `2025-06-18` Streamable HTTP contract:

- each client JSON-RPC message is one HTTP POST;
- `Accept` advertises both `application/json` and `text/event-stream`;
- later requests carry the negotiated `Mcp-Session-Id` and
  `MCP-Protocol-Version`;
- JSON responses and finite SSE event streams are supported;
- a session DELETE is attempted when the proxy closes;
- a `404` session response clears local session state and requires a fresh
  initialize;
- each local stdio MCP message and each remote HTTP response body is capped at
  10 MiB before JSON or SSE parsing;
- redirects are refused so an authorization header cannot silently move to a
  different endpoint.

Initialization is capped at protocol revision `2025-06-18`. Credentials must
be supplied through `header_env`; transport-controlled headers such as
`Content-Type`, `Accept`, `Mcp-Session-Id`, and `MCP-Protocol-Version` cannot be
overridden. Plain HTTP is accepted only for a loopback address. Remote servers
must use HTTPS and the operating system trust store.

## Approval behavior

The first governed side effect is stopped before the HTTP `tools/call` is sent.
Defiant returns a durable approval id to the agent. After the operator approves
it, the agent repeats the exact call. A fresh proxy process and a fresh remote
MCP session may perform that retry.

The approval binds the server URL, runner, user, workspace, tool contract,
arguments, and all policy-bearing MCP metadata. Only the ephemeral
`_meta.progressToken` may differ. A successful retry consumes the approval and
records the remote result in the hash-chained evidence trail.

## Current limits

- The proxy does not open the optional long-lived GET SSE channel.
- SSE responses must finish within the configured request timeout.
- A server-initiated JSON-RPC request received during a governed synchronous
  `tools/call` fails closed. Bidirectional sampling, elicitation, and roots
  handling require a later transport state machine.
- Stream resumption and `Last-Event-ID` are not implemented.
- The configured remote endpoint is trusted infrastructure. Defiant governs
  calls sent to it; it does not attest its implementation or prevent the
  runner from reaching that service through another network path.
- Approval identity binds header environment-variable names, not secret values.
  Reject pending approvals when rotating a credential to an account with
  different remote authority.
