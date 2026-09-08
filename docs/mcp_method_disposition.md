# S4 method inventory and disposition

## Inventory before implementation

Baseline: v0.97.0, `56316a9a2614f8514a584a04fedde64784744647`.
The unmodified `@modelcontextprotocol/server-filesystem@2026.7.10` was
downloaded with lifecycle scripts disabled and inspected on September 8, 2026.
Its dependency declaration is `@modelcontextprotocol/sdk: ^1.29.0`; the inspected
installation resolved SDK 1.30.0. This is a package pin, not a transitive lock.

An observation wrapper around the unchanged S3 client's request/notification
methods then ran the real synthetic demo through the Harness proxy. It observed
`initialize` (request), `notifications/initialized` (notification), `tools/list`
(request), and six `tools/call` requests. The demo completed its governed
read/block/approval/exact retry/read-back flow and verified ten evidence records.
Initialization returned protocol `2025-06-18`, capability
`tools: {listChanged: true}`, and `secure-filesystem-server` version `0.2.0`.
That serverInfo version is not the npm package version.

The package's `dist/index.js` registers fourteen tools through `McpServer`.
The inspected SDK's `server/mcp.js` installs `tools/list` and `tools/call` for
those registrations. No resources, prompts, completion, logging capability,
or task store is registered by this server. `server/index.js` installs
`initialize` and `notifications/initialized`; `shared/protocol.js` installs
`ping`, `notifications/cancelled`, and `notifications/progress`.

The filesystem package also installs `notifications/roots/list_changed`.
That handler requests `roots/list` from the client and can **replace** its
allowed directories. Its initialization callback does the same if client
roots support was advertised. These are not harmless discovery operations.
The S3 flow advertises no client capabilities and uses command-line directories.

| Method / direction | Form | S4 pilot disposition | Basis |
| --- | --- | --- | --- |
| `initialize`, client to server | Request | Allow with bounded protocol and no advertised client capabilities | Observed; SDK initialization handler |
| `notifications/initialized`, client to server | Notification only | Allow | Observed; filesystem post-initialization setup |
| `tools/list`, client to server | Request only | Allow | Observed; SDK tool inventory handler |
| `tools/call`, client to server | Request only | Govern | Observed; existing policy/approval/capability path |
| `ping`, client to server | Request only | Allow | SDK automatic empty-result handler; not used by the baseline demo |
| `notifications/roots/list_changed`, client to server | Notification | Deny | Can replace configured filesystem roots |
| `notifications/cancelled`, client to server | Notification | Deny | Unneeded by synchronous pilot flow; private governed-call IDs are not client authority |
| `notifications/progress`, client to server | Notification | Deny | No server-to-client request is negotiated by this pilot |
| `roots/list`, server to client | Request | Not negotiated | Client capability advertisement is suppressed; client response envelopes have no upstream forwarding path |
| `notifications/tools/list_changed`, server to client | Notification | Existing transport handling, not a client-method allow rule | Advertised tool list-change capability; no tool registrations change during the observed flow |
| Resource, prompt, completion, logging, and task methods, client to server | Request | Deny | Not required/registered for this pinned pilot flow |
| Any other client method, or unclassified form | Either | Deny | No implicit forwarding |

The [supported MCP lifecycle](https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle)
distinguishes initialization requests from the initialized notification.
[JSON-RPC notifications](https://www.jsonrpc.org/specification#notification)
do not receive responses, including when refused. S4 does not expand protocol
support beyond `2025-06-18`, add task augmentation, or establish safety for
arbitrary MCP implementations. Any server/package update needs a fresh method
inventory and disposition review, even if its advertised tool names are unchanged.

## Configuration and binding

`method_dispositions` contains exactly `protocol_version`, `reviewed_server`,
`requests`, and `notifications`. Each form maps exact method names to `allow`,
`deny`, or `governed`. Missing entries mean unclassified/deny, not inheritance
from the opposite form. Only `tools/call` requests can use `governed`; declaring
that method `allow` is invalid. The known core request methods `initialize`,
`tools/list`, and `ping` cannot be allowed as notifications, nor can
`notifications/...` be allowed as requests. Other exact allow declarations
still require operator review of their method's actual message form.

Names are case-sensitive ASCII path-like identifiers, 1–128 characters, with
letter-led segments and letters, digits, underscore, hyphen, or dot inside a
segment. Empty segments, whitespace, controls, Unicode lookalikes, wildcard
syntax, and reserved `rpc.` names are rejected. No case-folding, Unicode
normalization, URL decoding, or wildcard matching occurs. JSON escapes are
decoded once by the existing strict parser: escaped `tools/call` is still
governed. Duplicate YAML keys, unknown fields/values, conflicting duplicate
in-memory entries, malformed maps, ambiguous transport binding, and more than
4,096 entries in a collection fail closed. Existing YAML byte/node/depth limits
also apply; accepted review state is immutable and projections are detached.
In-memory review values are type-checked before comparison or truthiness, so
unsupported objects cannot execute callbacks during those validation steps.

`reviewed_server` contains `name` and either `commands` (a nonempty list of
exact argument vectors) or `url`. The filesystem review lists only the Linux
`npx -y PACKAGE workspace` vector and the equivalent Windows
`cmd /d /s /c npx -y PACKAGE workspace` vector, with PACKAGE pinned to 2026.7.10.
CLI command overrides must match one reviewed vector exactly. A changed name,
package version, argument, URL, or protocol cannot reuse that review unnoticed,
even in fresh state. The protocol review currently accepts only `2025-06-18`.

The review enters the existing proxy fingerprint, which already binds server
identity, runner, tool contracts, timeout, artifacts, and launch context. That
fingerprint participates in approvals and the complete durable authority
profile. No parallel trust store, signer, or rotation mechanism is added.
Verified artifact paths are launch outputs; review matching uses the original
configured vector, while resolved artifact/launch assurance remains in the
fingerprint. Editing both the launch and its review is an explicit operator
configuration change, not independent certification of the new server.

## Request, notification, and evidence behavior

The client envelope must have `jsonrpc: "2.0"`, a valid exact method, no
unexpected envelope fields, and, for requests, an integer or nonempty string
ID (at most 256 characters). Null, boolean, fractional, object, and empty IDs
are rejected. Batch, parse, and ingress-limit handling remain fail closed.

An unknown or explicitly denied request receives `-32601` with a durable
evidence record ID. Malformed method/envelope requests receive `-32600`, using
a null response ID when the supplied ID is invalid. Non-object params on an
allowed protocol request, or invalid initialization params, receive `-32602`.
Notifications receive no response, even for wrong-form
`tools/call`; they are recorded and dropped. Client response envelopes are also
recorded and dropped, not mistaken for methods or answered with response loops.

An allowed initialization offers exactly the reviewed revision upstream and
projects client capabilities to `{}`. It cannot enable client roots, sampling,
elicitation, or other server-to-client request paths. This is a tools-only
pilot restriction, not generic MCP capability negotiation. Non-tool forwarding
never constructs `ToolCall`, consumes an approval, reserves budget, or mints a
capability. The operator's reviewed upstream handler still determines what an
allowed protocol method does; arbitrary unsafe allow declarations are not safe.

Refusal uses the existing evidence schema and append/checkpoint mechanism under
the authority writer lock. `decision_inputs.event_type=mcp_method_refusal`
distinguishes a protocol event; it carries direction, request/notification/
response kind, valid method name (or an invalid marker plus hash), disposition,
server and proxy fingerprints, protocol, and hashed wire ID where present.
The existing record timestamp, record ID, block decision, and reason complete
the event. The original message is hashed, never stored as raw params.

Schema-required `request_id` and `action_id` hold a generated `rpc_event_...`
correlation identifier, **not** a claimed JSON-RPC request ID or proposed tool
action. `tool_name=mcp.protocol` labels the event; the authorization hash is
empty, cost is zero, and status is blocked. Notifications have no wire ID/hash.
No evidence schema migration or Command Center mutation path is introduced.
If durable evidence cannot be appended, the exception propagates; the message
still is not forwarded, and no response claims that evidence was recorded.
Malformed JSON/batches and inputs beyond existing parser limits retain their
existing transport errors rather than manufacturing parsed method metadata.

## Migration and verification

An omitted review preserves only the existing governed `tools/call` path; all
non-tool methods, including initialize, are denied. There is no permissive
legacy fallback or wildcard allow switch. Existing deployments need an
operator-reviewed method map and the existing exact authority-profile rotation
procedure when reusing enrolled state; do not delete state to bypass rotation.
The remote example is a placeholder, not a reviewed server, and intentionally
does not acquire an allow map. The repository's simulated local demo has a
separate exact map reviewed against `examples/demo_mcp_server.py`.

The S4 subprocess fixture optionally writes every received message to a separate
receipt log **before** dispatch. Tests submit unknown/explicitly denied requests,
unknown/root-change/tool notifications, then a ping barrier and a governed tool
call. The receipt log must contain only initialize, initialized, ping, and the
authorized tool call. This proves non-forwarding independently of error codes;
the tool marker independently proves the sole actual tool dispatch.

Focused tests additionally cover config drift/overrides, immutable review state,
existing authority-profile drift refusal, malformed envelopes and IDs, exact
matching and Unicode tricks, silent notification evidence, client responses,
batches, privacy, and allowed protocol traffic carrying tool-shaped params
without gaining tool authority. The S3 real-server test remains opt-in and
retains every existing governed assertion; the demo additionally verifies ping.

Completion requires a separate cold review of the final diff, full local
regression/lint/format/package checks, exact-final-SHA ordinary CI and real
Linux/Windows live jobs, then PR merge, clean Desktop main, green ordinary and
live main runs, and only then v0.98.0 creation. Tag ordinary and both live jobs
must pass at the intended merge SHA before only the merged S4 branch is removed.
The release PR records observed counts, SHAs, findings, and hosted run links.

Limits remain: this is not bidirectional/full-MCP governance, trusted upstream
code inspection at every launch, a transitive dependency lock, proof of future
SDK behavior, a process-resource quota, OS containment, or real-pilot acceptance.
Server-to-client notifications and responses retain existing transport handling;
the chosen pinned server must honor its reviewed protocol/capability behavior.
Command Core/Command Center stay read-only. S5 is not started.
