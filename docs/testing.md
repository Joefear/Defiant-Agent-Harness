# Testing and platform coverage

## S1 Windows CI

v0.95 adds `windows-latest` with Python 3.12 to the existing `ubuntu-latest`
Python 3.10, 3.11, 3.12, 3.13, and 3.14 jobs. Both platforms run the full
default suite with `python -m pytest -q -rs`; `-rs` prints skipped tests and
their reasons. Python 3.12 also runs lint, formatting, and wheel building on
both platforms. The pinned checkout/setup actions are unchanged. Linux keeps
its ten-minute timeout; Windows has a twenty-minute timeout based on the
observed hosted run below. Matrix fail-fast remains disabled so all results are
visible; test failures are not allowed to continue as a successful job.

Run the same checks locally from the repository using its development
environment:

```text
python -m pytest -q -rs
python -m ruff check .
python -m ruff format --check src tests examples
python -m pip wheel --no-deps . --wheel-dir dist
```

The live official MCP test remains opt-in with `DAH_LIVE_MCP=1`. S1 does not
set that variable, install a live server, add macOS, weaken an assertion, or
add a skip to obtain a green Windows result. Automatic live-server coverage
belongs to S3. Real Windows ACL object coverage belongs to S2, not this CI
matrix change. See `pilot_readiness_arc.md` for the remaining arc gates.

## Reviewable skip inventory

This is the complete inventory of skip sites in the default suite at S1.
Conditional link-creation skips depend on runner permissions and filesystem
support, not merely its operating-system name. A hosted Windows runner can
exercise a link test that skips inside a restricted local Windows session.
Always inspect the actual `-rs` output; a skip is not evidence that its safety
assertion passed. No platform-specific failure may be converted into a skip
merely to satisfy this matrix.

| Test file and function | Exact reason | Condition |
| --- | --- | --- |
| `test_authority_lock.py::test_forked_child_does_not_inherit_reentrant_authority` | `requires POSIX fork` | `os.fork` unavailable; normally Windows |
| `test_filesystem_live_example.py::test_official_filesystem_server_end_to_end` | `set DAH_LIVE_MCP=1 to download and exercise the official MCP server` | Opt-in variable absent; both CI platforms in S1 |
| `test_state_storage.py::test_nonregular_state_file_is_rejected_without_blocking_on_open` | `FIFO creation is unavailable` | `os.mkfifo` unavailable; normally Windows |
| `test_state_storage.py::test_posix_state_modes_are_private_and_overbroad_file_fails_closed` | `POSIX permission semantics` | Non-POSIX platform; Windows |
| `test_control_plane_isolation.py::test_direct_and_symlinked_state_targets_are_refused` | `directory symlink creation is unavailable` | Directory symlink creation fails |
| `test_control_plane_isolation.py::test_symlink_retarget_after_authorization_is_refused_before_execution` | `directory symlink creation is unavailable` | Directory symlink creation fails |
| `test_runtime_artifacts.py::test_symlinked_artifact_is_refused_when_supported` | `symlink creation is unavailable` | File symlink creation fails |
| `test_runtime_artifacts.py::test_closed_dependency_roots_reject_links_and_overlap` | `symlink creation is unavailable` | File symlink creation fails |
| `test_state_storage.py::test_symlinked_state_root_is_refused_when_supported` | `directory symlink creation is unavailable` | Directory symlink creation fails |
| `test_state_storage.py::test_symlinked_state_file_is_never_read_or_repaired` | `file symlink creation is unavailable` | File symlink creation fails |
| `test_state_storage.py::test_symlinked_evidence_is_reported_without_auditor_crash` | `file symlink creation is unavailable` | File symlink creation fails |
| `test_workspace_integrity.py::test_symlinked_workspace_root_is_rejected` | `directory symlink creation is unavailable` | Directory symlink creation fails |
| `test_runtime_artifacts.py::test_closed_dependency_roots_reject_hard_links_when_supported` | `hard-link creation is unavailable` | Hard-link creation fails |
| `test_state_storage.py::test_hard_linked_state_file_is_refused` | `hard-link creation is unavailable` | Hard-link creation fails |

The S1 local Windows run recorded 1,410 passed and 12 skipped. Its skipped
set was the first twelve rows above: fork, live MCP, FIFO, POSIX modes, and
eight symlink cases. The two hard-link tests ran. The focused platform suite
recorded 94 passed and the same twelve skips. These local results do not
substitute for the hosted Windows run or for a real pilot acceptance run.

## Negative-control method

Before opening the release PR, a temporary additional test asserted
`os.name != "nt"` with the diagnostic
`S1 intentional Windows CI failure propagation probe`. It was pushed on the
S1 feature branch only, at `65d742b75e664337f16f9f9f6e31cfd9200b4636`, to make
the real Windows pytest step exit unsuccessfully. The probe is not a runtime
defect or a permanent test and must not exist in the release tree. Existing
tests and their assertions remain unchanged.

The corresponding [negative-control run](https://github.com/Joefear/Defiant-Agent-Harness/actions/runs/34009789424)
retains the original job logs. Review the failed test identity and step exit
code, not just the run color. A final green branch/PR run after removing the
probe, followed by green main and tag runs, is required before declaring S1
complete. No `continue-on-error`, swallowed exit code, or test deselection is
an acceptable substitute.

## Observed hosted results

The negative-control run completed with exactly one Windows failure: the
temporary probe. Its Windows Python 3.12 pytest step reported **1 failed,
1,418 passed, 4 skipped**, in 341.69 seconds, and exited with code 1. The job
and the overall workflow both failed. There were no additional Windows
failures to repair and no existing test content was changed to make it pass.

The hosted Windows skip set was exactly:

- `test_forked_child_does_not_inherit_reentrant_authority`: requires POSIX fork.
- `test_official_filesystem_server_end_to_end`: live MCP opt-in not enabled.
- `test_nonregular_state_file_is_rejected_without_blocking_on_open`: FIFO
  creation is unavailable.
- `test_posix_state_modes_are_private_and_overbroad_file_fails_closed`: POSIX
  permission semantics.

The Ubuntu Python 3.12 job reported **1,422 passed, 1 skipped**: only the live
official MCP opt-in test skipped. That pass count includes the one temporary
probe, which passes on Linux. After probe removal, the unchanged default
suite contains 1,422 cases: 1,421 pass plus one skip on this Linux runner, and
1,418 pass plus four skips on this Windows runner. The positive release runs
must confirm these results independently; the negative-control run is not a
green release verification. All five Linux jobs in that control run passed.

The actual reason strings and full test identifiers appear in the inventory
above and in the linked run's logs. No new Windows-only skip was introduced.
The eight local symlink skips did not occur on hosted Windows; both hard-link
cases also ran. This is evidence about the tests that executed, not about the
real Windows private-ACL inspection deferred to S2.

## Hosted Windows timeout finding

The first clean-tree [PR run](https://github.com/Joefear/Defiant-Agent-Harness/actions/runs/34010251610)
passed on Windows: 1,418 passed and four skips in 394.22 seconds, followed by
successful lint, formatting, and wheel building. The simultaneous
[branch run](https://github.com/Joefear/Defiant-Agent-Harness/actions/runs/34010251168)
reached 1,100 passed and two skips in 564.15 seconds before the original
ten-minute job timeout cancelled it. Timestamped progress advanced through
75 percent; this was not a completed passing suite, nor did it report an
assertion failure. The remaining tests and build checks were not verified by
that cancelled run.

S1 therefore gives only Windows a twenty-minute job budget and retains ten
minutes on Linux. This allows completion on the observed slower hosted worker
without altering tests, suppressing failures, changing Harness runtime
timeouts, or setting a pilot resource ceiling. Require fresh successful runs
at the revised commit. Cancellation, timeout, and skipped jobs never satisfy
the release gate; inspect each check's conclusion rather than relying only on
a watch command's exit status. Investigate recurring stalls or overruns rather
than treating the additional CI time budget as a performance guarantee.
