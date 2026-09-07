# S3 automatic live filesystem MCP integration

The live CI job runs the unmodified
`@modelcontextprotocol/server-filesystem@2026.7.10` through the Harness stdio
proxy on `ubuntu-latest` and `windows-latest`, with Python 3.12 and Node 22.
Checkout, Python setup, and Node setup actions use full commit pins. The server
package pin is identical in the example launcher and operator tool map. This
does not lock the complete npm transitive dependency tree or establish OS
containment; neither is a production-deployment assurance claim.

## Event and failure contract

The existing `CI` workflow keeps its six ordinary offline test jobs. The two
additional `live-mcp` matrix jobs run only for these events:

| Event | Live integration |
| --- | --- |
| Daily schedule, 06:23 UTC | Both platforms on the default branch |
| `workflow_dispatch` | Both platforms on the explicitly selected ref |
| Push of a tag beginning `v` | Both platforms on that tag's commit |
| Ordinary branch push or pull request | Live jobs skipped; ordinary suite runs |

GitHub schedules run from the default branch and may be delayed or dropped;
manual dispatch exercises the same job body on a feature branch but is not
evidence that a scheduled event has already fired. Keep that distinction in
release evidence. No secrets, deployed state, merchant data, policy changes,
or external write services are needed. Network access is intentional only for
the opt-in live integration and dependency installation.

Each live job sets `DAH_LIVE_MCP=1` and runs
`python examples/filesystem/live_ci.py`. The entry point refuses an absent or
different value before invoking pytest. It selects exactly
`test_official_filesystem_server_end_to_end`, clears ambient pytest selection
options, and requires exactly one collected identity and successful setup,
call, and teardown reports. Missing execution, skip, xfail, xpass, error,
duplicate execution, deselection, or a nonzero pytest exit fails the gate.
There is no `continue-on-error`, tolerated network outage, or success fallback.
The upstream timeout is 60 seconds, the live-test subprocess limit is 180
seconds, and the hosted job has a 15-minute cap including dependency setup.
Timeout/cancellation is never release evidence.

The dependent `live-mcp-gate` job uses `always()` on live events and accepts
only a successful matrix result. Failure, cancellation, or skipping either
platform invalidates it. On a release tag its error explicitly declares the
tag invalid. This gate does not delete a failed tag or publish a GitHub release.
Git tags can exist before CI completes: presence of a tag alone is never a
release certificate. Repository administrator access could bypass a process
gate; S3 does not silently change repository branch protection or permissions.

## What actually executes

The test starts `live_demo.py --yes` in a new temporary run directory with a
fresh npm cache. `McpClient` launches the Harness `mcp-proxy` CLI, which starts
the real pinned upstream using `npx` (`cmd /d /s /c npx` on Windows). All
initialize/discovery and tool requests use that proxy's stdio, not a direct
test-to-server connection. No fake MCP server or patched adapter is involved.

The demo verifies a governed root listing and exact seed-file read; a blocked
directory creation with no directory created; a held write with no premature
file; operator approval via the normal CLI; the exact unchanged call retry;
and both proxy read-back and actual disk content matching the approved text.
Finally the CLI verifies the evidence chain and prints recent history. These
checks prove the exercised synthetic tool path, not the later real Codex,
merchant, non-tool-method, process-kill, or pilot acceptance obligations.
Command Core and Command Center stay read-only and unchanged. S4 is not begun.

## Required proof and release sequence

1. On the S3 feature branch only, temporarily break the mapped upstream read
   tool name. Dispatch CI on that exact commit. Require BOTH real live jobs
   to fail at the governed read after successful upstream initialization and
   discovery; require the dependent gate to fail. Inspect logs, not just colors.
2. Restore the original tool map. Confirm no deliberate failure remains.
   Run local regression/lint/format/build checks, and dispatch the final branch
   SHA. Require both live jobs and ordinary CI to be green at that exact SHA.
3. Stop editing for a cold self-review of the full diff, events, live code,
   claims, hosted logs, skips, release behavior, failure residue, and scope.
   Any finding requires a fix and fresh verification. Open/update the PR only
   after these gates; inspect the complete PR diff again before merging.
4. Merge through the repository PR workflow, sync the owner's Desktop main,
   and require main ordinary CI to pass. Dispatch main live CI as well; require
   both platforms green before tagging. Only then create/push `v0.97.0`.
5. Require successful ordinary CI, both tag live jobs, and the dependent live
   gate at the intended main SHA. Verify the annotated tag dereferences to
   that SHA. A failed/missing tag run means the release is NOT valid; stop and
   investigate without moving an existing tag or claiming completion.
6. Delete only the verified merged S3 feature branch. Do not start S4.

Record exact SHAs and hosted run links with observed results. A schedule entry,
passing unit count, dispatch request, or green result from an earlier SHA is
not a substitute for the corresponding execution evidence.
