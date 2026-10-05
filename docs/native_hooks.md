# Native agent hook boundary

## Purpose

Some runners expose built-in file, terminal, browser, and subagent tools that
cannot be removed from their agent UI. Those calls never cross an MCP proxy.
The native hook adapter adds secondary preview checks on that path. It is not
an authoritative enforcement boundary: preview hook decisions do not support
pilot deployment claims. Supported events, successful invocation, and a timely
response are all host-runner dependencies; a fail-closed JSON response from
Defiant cannot defeat a host's fail-open timeout.

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

The local `hook_executions.json` correlation record is also an authority
boundary. v0.61 captures each complete record once, revalidates its action,
request, and decision contracts, seals those trees behind defensive
projections, and records completion by replacing the immutable record with a
new validated state. Its 64 MiB ceiling is identical for canonical capture,
recovery reads, and atomic publication. See
`sealed_native_hook_correlation_state.md`.

For signed mode, set `DAH_TRUSTED_OPERATOR_KEYS` to a JSON array of
`IDENTITY=PUBLIC_KEY.pem` bindings before starting the runner. The hook loads
only public keys and fails closed on malformed configuration or an unsigned,
invalid, untrusted, or replayed approval. See `operator_identity.md`.
The first trusted hook startup durably enrolls that mapping. Later hook startup
with the variable missing or changed fails closed before processing an event;
planned changes use the operator trust rotation CLI.

When signed external evidence-head witnessing is enrolled, set
`DAH_EVIDENCE_HEAD_WITNESS` to the newest retained witness path and
`DAH_TRUSTED_EVIDENCE_KEYS` to a JSON array of public-key paths before starting
Copilot or Codex. Both variables are required together. The hook passes them to
the same authority preflight used by MCP proxies and fails closed on omission,
malformed JSON, trust mismatch, signature failure, rollback, or divergence.
If the enrolled authority profile has a finite witness-lag ceiling, also set
`DAH_MAX_UNWITNESSED_RECORDS` to that exact non-negative integer. Omission or a
different value fails closed rather than weakening the enrolled policy.
Private keys and passphrases never enter the hook environment. See
`evidence_head_witness.md`.

Both trusted-key JSON arrays are limited to 1,024 entries before gate creation.
The shared operator and witness loaders then enforce 65,536 bytes per public
key and 8,388,608 aggregate key-set bytes. Limit failure creates no hook state
or authority. See `trusted_key_limits.md`.

On Windows, an owning native-hook runtime can require the v0.25 private state
ACL policy by setting `DAH_REQUIRE_WINDOWS_PRIVATE_STATE_ACL=1`. The value must
be exactly `1`; malformed values fail closed. Once that posture is enrolled in
the authority profile, later owning hook runtimes must preserve it. The hook
only inspects ACLs and never changes them. See `state_storage_integrity.md`.

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

Each hook event is capped at 10 MiB before JSON parsing. An oversized or
malformed event produces the runner-specific fail-closed response and a
sanitized diagnostic; raw event content is not copied into that response.

- VS Code documents command-hook timeouts as fail-open into the runner's normal
  permission flow.
- A direct process action that emits no lifecycle event cannot be seen here.
- `PostToolUse` reports successful completion; a missing post-event remains
  authorization-pending or execution-uncertain rather than being guessed.
- Hook code runs with the VS Code process permissions.
- Operator or administrator changes to hook configuration remain trusted.

Production deployment still needs OS, process, and network containment around
the runner. The MCP proxy is the authority boundary for traffic actually routed
through it. Keeping hooks enabled is useful defense in depth, not proof that
native tools cannot bypass that routing.

## S6 enforcement basis

New Codex and Copilot hook records carry the hash-covered field
`enforcement_basis: native_hook_preview`, including denials, preflight allows,
post-event completion, and outer delegation to a Defiant MCP tool. A delegated
tool name does not upgrade the outer record; only the inner proxy writes
`mcp_proxy`. Other local Harness execution writes `harness_control_loop`.
None of these labels by itself proves pilot readiness or successful execution.

The label is chosen by trusted runtime construction, not caller event metadata
or configurable runner identity. Operator reconciliation and later lifecycle
records preserve the originating label. Old evidence and prepared recovery
journals with no label retain their original serialization and hashes; CLI
history and Command Center display them as `legacy_unspecified`. The dashboard
is still strictly read-only. Post-entrypoint errors return explicit block JSON
even though the hook protocol's process exit status is zero; this cannot undo
an external action already completed before the post-event.

## Reproducible latency measurement

Run explicitly from a development checkout with the project installed:

```powershell
python examples/hooks/latency.py --rounds 3 --workers 4 --history-pairs 10 --output hook-latency.json
```

This offline benchmark uses disposable synthetic workspace/state directories.
It launches the actual Python hook `main` entrypoints in fresh subprocesses,
measuring wall time from process launch through response and exit (including
Python startup). Both pre and matched post phases run serially, in synchronized
four-process batches sharing a state directory, and while the parent holds the
real authority lock. Held-lock calls must return explicit busy refusals and
leave evidence unchanged. Ordinary concurrent refusals are counted separately
from successful allows/seals; errors, malformed output, and deadline expiry
cannot masquerade as fast successful enforcement. The benchmark checks the
final evidence chain and records every observation, maximum and remaining
margin against the unchanged 10-second budget. It is not part of default pytest.

This is a finite local measurement, not a latency guarantee. State starts with
20 records and grows during each hook's run; larger histories, slower storage,
runner overhead, antivirus, cold caches, and other host load can reduce margin.
The configured shell wrapper and the actual VS Code/Codex runner are not timed.
No timeout is increased, no platform behavior changed, and no network, upstream
server, or real native tool is invoked. See the S6 review report for the observed
Windows values; do not substitute those values for a deployment measurement.

### Observed Windows measurement

In the first run on the owner's Windows 10.0.26100 host with Python 3.11.9,
the S6 command above completed 108 measured invocations. Each hook started with 20 synthetic evidence
records and ended with 59. No observed invocation exceeded the budget; all busy
responses were explicit refusals, and both final chains verified. Times below
are seconds, rounded to three decimal places.

| Hook | Mode | Pre maximum / margin | Post maximum / margin | Outcomes per phase |
|---|---|---|---|---|
| Codex | Serial | 1.510 / 8.490 | 1.450 / 8.550 | 3 successful |
| Codex | Four concurrent | 1.900 / 8.100 | 1.871 / 8.129 | 3 successful, 9 busy refusals |
| Codex | Held authority lock | 0.715 / 9.285 | 0.782 / 9.218 | 12 busy refusals |
| Copilot | Serial | 1.450 / 8.550 | 1.503 / 8.497 | 3 successful |
| Copilot | Four concurrent | 1.782 / 8.218 | 1.870 / 8.130 | 3 successful, 9 busy refusals |
| Copilot | Held authority lock | 0.725 / 9.275 | 0.739 / 9.261 | 12 busy refusals |

Successful means preflight allow or post-event evidence sealed, not execution
of a real native tool. In particular, quick refusals are not a successful-tool
throughput result. This run's smallest observed margin was 8.100 seconds.

A second run against the final runtime, while the full regression suite was
also running on the host, FAILED the timing check. Of 108 invocations, 17 had
end-to-end elapsed times over 10 seconds: 13 timed out, three returned busy
refusals late, and one returned an allow late. Codex held-lock post calls had a
16.654-second maximum (margin -6.654); Copilot serial pre calls reached 11.902
seconds (margin -1.902), and held-lock post calls reached 11.328 seconds
(margin -1.328). Elapsed time includes process creation and timeout cleanup;
these numbers do not isolate time spent inside Python hook logic. The precise
cause of the host delays was not diagnosed. Both final evidence chains verified,
and held-lock cases left evidence unchanged, but those facts do not erase the
missed deadlines. Both raw runs are retained in the S6 review evidence.

Therefore latency acceptance is not established. Do not treat the favorable
first run as a reliable safety margin, raise the configured timeout, or make
pilot prevention claims from this preview seam. Independent review must consider
the failed repeat before any S6 release decision.
