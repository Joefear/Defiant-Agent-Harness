# S5 real process-kill recovery proof

Target: v0.99.0, based on v0.98.0 / `2d41aadb25fd8fb6d30b4ba0cb6b2739ffea24c9`.
Independent Claude Code review and branch/main/tag release gates are required;
implementation and local passes alone do not close S5.

## What runs

`tests/test_process_kill_recovery.py` installs the exact
`@modelcontextprotocol/server-filesystem@2026.7.10` package into a temporary
directory with npm lifecycle scripts disabled. It launches the real Harness
proxy and the package's unmodified entry point on Windows and Linux. This is
synthetic workspace data, not real merchant data or a real agent-runner pilot.

`tests/fixtures/record_real_mcp.mjs` executes **inside that real Node server
process**. It wraps the installed SDK's stdio `onmessage` callback with a
synchronous append/fsync receipt recorder, then invokes the original callback
unchanged. It registers no tool handlers, synthesizes no responses, and neither
forwards requests to a fake server nor substitutes a filesystem implementation.
The package manifest must match the exact name/version. The real entry point's
bytes are checked unchanged after the tests. The SDK resolution layout is
explicit; an incompatible layout fails rather than silently disabling recording.
The npm package pin is not a complete transitive dependency lock.

All requests enter through the Harness proxy. The test-specific reviewed launch
vector names Node, the observer, the real entry point, workspace, and receipt
path. It copies the pilot's method dispositions and binds them to that exact
vector. Only a synthetic five-dollar write estimate is added to exercise budget
reservations; no actual spend occurs. Production example configuration, method
gating, policy, and recovery code are not loosened for the proof.

The receipt includes the real server PID and parsed incoming messages. These
payloads are synthetic test data; the observer is not a production telemetry
feature. The test matches the exact full tool params, not only a method count.
At each initial kill it also matches the complete sequence of received methods.

## Real death and ordered barriers

The first proxy runs the ordinary CLI through a test-only Python launcher. It
adds blocking barriers around the real call, journal prepare, or evidence write.
The parent verifies the reported interpreter PID equals its subprocess PID,
then calls `Popen.kill()` and waits for a nonzero exit: SIGKILL on POSIX or
TerminateProcess on Windows. No `SimulatedCrash` exception performs the kill.
Windows uses the base interpreter explicitly so a virtualenv launcher cannot
be mistaken for the actual proxy. Restarts use the **unmodified CLI**, without
the crash launcher.

An acknowledged real `ping` synchronizes the pre-call receipt check and every
post-retry check. After killing the proxy, the observer must record ordered
stdin EOF and normal exit for the same real server PID before receipt counts
are asserted. This drain barrier prevents queued bytes being mistaken for no
dispatch, and proves the original upstream is no longer processing work before
operator reconciliation. It also detects an orphan that fails to exit; timeout
is a failure, not an absence assertion.

## Scenarios and expected arrivals

| Kill point | Exact write arrivals | Restart behavior |
| --- | --- | --- |
| After authorization, before `call_tool` dispatch | 0 | Executing approval remains uncertain; five-dollar reservation remains; retry cannot execute; explicit `not_executed` reconciliation releases it |
| After real successful write/response, before result journaling | 1 | Still uncertain despite the real file; reservation remains; explicit `succeeded` assertion charges five dollars; no replay |
| After durable `execution_complete` journal, before settlement | 1 | Startup completes only local settlement, evidence and approval consumption; one debit and one terminal record; no upstream replay |
| During terminal evidence append, after the first half is flushed/fsynced | 1 | Torn chain reported unsafe; stale evidence lock retained; restart and reconciliation refuse; damaged bytes remain unchanged |

The last case splits the actual serialized append inside the real evidence
store's open file/lock scope. It does not corrupt an already completed run.
The known-result journal and prior five-dollar settlement remain; no budget
headroom is invented. Integrity repair is **not** operator outcome assertion:
an outcome assertion cannot make a torn chain trusted. This proof neither
trims evidence nor removes stale locks nor implements S7 backup/restore.

Both uncertain cases reject missing or blank outcome, operator, and note.
Exact repeated reconciliation is idempotent. The known and reconciled cases
assert exact debit/terminal counts and verify the chain and integrity audit.
A later identical call requires a **new pending approval**; the old consumed
approval cannot authorize a second arrival. Fresh approval for a new deliberate
action is distinct from automatic replay and is not granted by these tests.

## Running and CI

In PowerShell, from the repository root:

```powershell
$env:DAH_LIVE_MCP = '1'
python examples/filesystem/crash_ci.py
Remove-Item Env:DAH_LIVE_MCP
```

The gate selects all four exact parameterized cases and requires successful
setup, call, and teardown for each. Empty collection, missing cases, skips,
xfails/xpasses, duplicate phases, or pytest failure are failures. Offline tests
exercise those gate failures. Default pytest skips the four network-dependent
cases before package setup, preserving offline development.

The existing Linux/Windows live jobs run the unchanged S3 gate followed by the
S5 gate on dispatch, schedule, and version-tag pushes. Ordinary branch/PR jobs
remain offline. Both steps must succeed for the aggregate live gate. Require
exact final-SHA ordinary and live results, independent review, and final PR
diff review before merge. Require main ordinary and dispatched live success
before creating v0.99.0, then all tag jobs before declaring release closure.

## Limits

These are selected process-death windows, not all crash interleavings, storage
failure, power loss, disk-controller durability, OS containment, or real pilot
acceptance. The torn write is deliberately controlled fault injection combined
with actual process death. Test barriers and the observer are trusted test code,
not shipped runtime controls. Existing fast simulated-crash tests remain.
Command Core and Command Center stay read-only. No S6, DKE, or Spartan work is
included. Release and independent review evidence belongs in the review handoff;
do not infer it from this description or from a passing test count.
