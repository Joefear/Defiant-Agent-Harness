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

This is the inventory of skip sites in the default suite, extended for S2.
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
| `test_windows_acl_native.py` (all eleven cases) | `requires real Windows security APIs and NTFS ACLs` | Non-Windows only; Windows provisioning/API failures fail the test |

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

## S2 real Windows private-state ACL coverage

v0.96 adds eleven cases in `tests/test_windows_acl_native.py`. They invoke the
production `inspect_windows_private_acl` function and its ctypes calls to
`GetNamedSecurityInfoW`, `GetSecurityDescriptorControl`, `GetAce`, token-user
lookup, and SID conversion against real disposable Windows filesystem objects.
No inspector, native helper, or current-user lookup is monkeypatched. Existing
synthetic evaluator and mocked caller tests remain useful fast unit coverage,
but are not presented as native Windows evidence.

The fixture uses built-in PowerShell/.NET to set a deterministic DACL and
independently observe its owner, protection flag, and security descriptor.
Every ACL-write target must resolve to an existing descendant of its pytest
temporary directory, never that directory itself, a real project, or a deployed
state root.
The current process user retains full control, including in the negative
cases. No administrator privilege, third-party ACL package, production ACL
repair, or Windows emulation is introduced. Fixture subprocesses have a
30-second timeout; setup errors on Windows fail rather than skip.

Coverage includes:

- A Harness-created root **after explicit test/operator ACL provisioning**,
  with current-user ownership, a protected DACL, inheritable full control,
  and either the current user alone or also System and Administrators.
- A newly created child file inheriting private permissions without a
  protected file DACL, as the file contract permits.
- Refusal of Everyone full control on both a directory and a file, a private
  but unprotected root, and a protected root lacking child inheritance.
- Real strict Harness startup, healthy read-only Command Core inspection,
  then root or `budget.json` ACL drift: invalid storage/authority observations,
  blocked tool handling, unchanged durable bytes, and no ACL repair.
- Refusal of an initially broad root before any durable authority files are
  created. Strict-state opt-in is never relaxed to obtain a passing result.

Run this coverage directly with:

```text
python -m pytest -q -rs tests/test_windows_acl_native.py tests/test_windows_acl.py
```

The native module has one explicit non-Windows skip marker covering eleven cases.
On the S1 hosted runner configuration, expected totals after this addition and
the launch-test correction below are 1,430 passed / four skipped on Windows
and 1,422 passed / twelve skipped on Linux. These are expected counts, not proof
of an executed release run. Inspect
the actual platform logs and require every check to succeed. In a restricted
local Windows environment, the eight existing symlink cases may still skip.

The focused Windows Python 3.11 run completed with **19 passed and no skips**
in 38.44 seconds: ten native cases plus the nine existing evaluator cases.
It ran as the normal owning Windows user after the restricted automation
sandbox refused fixture ACL writes. That restriction was not turned into a
skip, and no real project/state ACL was changed. Fixture setup writes only the
owner and DACL, not the SACL (which would require an unrelated audit privilege).
The wheel's version and bundled Command Center assets were also checked by
importing directly from the built v0.96.0 wheel. Require the full regression
suite and hosted main/tag gates separately; this focused result is not a
substitute for them.

### Launch-test startup race found by full Windows regression

The first full S2 local run reported **1 failed, 1,419 passed, 12 skipped**.
All native ACL cases passed. The existing
`test_effective_environment_reaches_child_without_ambient_injection` failed
because its child had not created the environment marker. Its empty client
input immediately began the production two-second shutdown grace; a separate
probe with a 2.5-second child startup delay reproduced the missing marker.

The test now waits for a real child readiness notification before providing
client EOF, with a ten-second test-only failure bound. It checks both ordinary
startup and a deliberate 2.5-second delay, adding one case to the suite. The
original allowed-variable and ambient-injection assertions remain. No Harness
shutdown timeout, transport behavior, environment policy, or CI skip changed.
This is a fixture synchronization correction, not live MCP acceptance; S3
remains separate. The corrected launch module together with both ACL modules
passed all **36 tests** in 124.71 seconds on local Windows Python 3.11.
The fresh full run then passed **1,421 tests with 12 skips** in 592.95 seconds.
All ten native ACL cases ran; the skips were the same fork, live MCP, FIFO,
POSIX-mode, and eight symlink cases recorded for the local S1 environment.
Ruff lint and formatting (112 files) passed. Hosted Windows/Linux and main/tag
CI must still independently pass before release completion.

### Hosted creation-owner and Python-version findings

The first hosted [branch run](https://github.com/Joefear/Defiant-Agent-Harness/actions/runs/34146200056)
at `b07fbf2670f603c3842d6b539daed0410377e6c1` reported **4 failed, 1,425 passed,
4 skipped** on Windows Python 3.12.10. A new child file was actually owned by
Builtin Administrators, not the current user. Strict startup consequently
refused its newly created state files. This refusal is required; allowing
Administrators-owned state would weaken the current-owner contract.

The fixtures now make the creation precondition explicit for the inherited-file
and healthy-startup cases. A duplicate of the current process token selects
the same user's SID as default owner and is used only on the current test
thread. User identity, groups, privileges, process token, other threads, and
machine policy are unchanged. Existing impersonation is refused; successful
setup is always reverted and handles closed. No production inspector is
replaced. Windows documents how the [creation token determines ownership](https://learn.microsoft.com/en-us/windows/win32/secauthz/owner-of-a-new-object)
and permits [same-identity impersonation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-impersonateloggedonuser).
A separate native case keeps ambient ownership untouched and asserts refusal
when it is not the current user's, with no repair. This is not a claim that
an elevated runner's unmodified default ownership satisfies strict mode.

The unprotected-root fixture also no longer assumes `mkdir(0o700)` leaves a
Windows DACL inherited: [Python 3.12.4 added Windows handling of that mode](https://docs.python.org/3.12/library/os.html#os.mkdir).
It explicitly provisions and independently checks an unprotected private DACL
before requiring the inspector to refuse it. No CI account or machine-wide
security setting changes, production ACL repairs, or additional Windows skips
are used. The revised ACL modules passed **20 tests** (eleven native plus nine
evaluator cases) locally in 34.83 seconds. The fresh full Windows Python 3.11
run then passed **1,422 tests with the same 12 existing skips** in 621.89
seconds; every native ACL case ran. Ruff lint and formatting remained green.
Require fresh hosted Windows/Linux and main/tag results at the corrected
commit before release completion.

These tests establish behavior on the tested Windows filesystem and process
identity. They do not audit the owner's real pilot directory, simulate a
hostile kernel/administrator, prove race-free OS containment, or satisfy the
later real-pilot acceptance gate. The inspector remains point-in-time,
read-only assurance; operators still provision and protect their state roots.
