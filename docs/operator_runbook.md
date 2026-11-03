# Operator backup and restore procedure

S7 adds an operator-controlled snapshot and a separate-directory restore. It
does not undo an external write. Restored approved actions become uncertain
before any startup can expire, consume or execute them. Resolve each against
the actual target with an explicit outcome, operator identity and investigation
note. Never infer `not_executed` from restored files, a refusal or a timeout.

This procedure is awaiting its owner walkthrough and release gates. It is not
yet a demonstrated pilot recovery capability. S8 and the full S11 runbook are
outside this change.

## Supported boundary

The source must be a retained, verifiable original from a v0.101+ supported
entry point. The snapshot must match its independently retained SHA-256 digest.
The original evidence must extend the snapshot exactly. Restore refuses new
post-snapshot approvals, unrepresentable post-snapshot authorizations, changed
authority/trust, and known costs exceeding the snapshot's reserved exposure.
These refusals preserve the original; they do not establish an action outcome.
An approval that was pending at capture and later rejected can return as pending;
that is not execution authority and still requires a fresh explicit decision.

Required external evidence/publication witnesses are not migrated. Never delete
their enrollment, replace a newer witness with an older one, or mint a witness
to conceal rollback. Lost originals and unverifiable evidence tails cannot be
accounted for by this procedure and are refused. This is not general disaster
recovery. Retain originals, snapshots, witness history and recovery reports.

Snapshots contain the complete present state-file inventory: evidence and head,
approvals, budget, journal, profile, publication and continuity, assurance and
trust-policy state, and hook correlations when present. Absence of optional
stores is recorded. Unknown files, stale writer locks, temporary files, active
publication and active journals are refused. Live OS lock files are not copied.
Files are limited to 64 MiB each and 256 MiB collectively; exceeding these limits
refuses the procedure without truncation. These are operation limits, not pilot
workload ceilings.

Private signing keys, passphrases and retained witnesses remain in separate
operator custody outside state and the governed workspace. Back them up through
the operator's existing secure procedure; these commands neither read private
keys nor place them in the snapshot. Preserve corresponding public-key bindings
and supply trusted operator keys for signed-state verification. Profile rotation
and reconciliation still require their normal signatures in signed mode.

## Stop and capture one root

1. Name the authoritative proxy root and the separate hook root in the recovery
   record. Capture each independently. There is no cross-root transaction.
2. Stop the runner, proxy and upstream. For native hooks, also stop or establish
   completion of every host-run tool. Observe upstream EOF and process exit;
   killing only a launcher or checking that a transaction lock is free is
   insufficient. S5 proved only the direct Python/direct Node topology.
3. Supported proxy entry points hold `runtime.lease` until upstream teardown;
   supported hook entry points hold it for their invocation. Maintenance holds
   that lease and the transaction lock throughout capture/restore. An idle proxy
   therefore blocks maintenance. The lease cannot detect older binaries,
   unwrapped library users, another state root or a host tool outliving its hook.
   Do not proceed if those might still be operating. Library integrations must
   hold `runtime_session(root)` around their full lifetime to participate.
4. Use a new output directory outside both state and the governed workspace:

   ```powershell
   dah --workdir C:\DAH\proxy-state --workspace-root C:\Pilot\workspace snapshot --output C:\DAH-Backups\proxy-001 --operator sam --note "Runner stopped; direct upstream EOF and exit confirmed"
   ```

5. Retain the printed `manifest_sha256` independently of the snapshot directory.
   A digest inside the same replaceable backup is not a trusted pin. The manifest
   is not a digital signature. Protect backup confidentiality through operator
   custody; encryption/offsite replication are outside S7. For an enrolled
   Windows private-ACL root, the procedure preserves its verified owner and
   protected DACL on the newly created empty staging directory before copying
   state bytes, then checks the new directory and files using the same native
   ACL reader. It never repairs or loosens the original ACL. Structural-only
   Windows roots remain explicitly structural-only; no ACL claim is added.
6. Repeat separately for the hook root after it is quiescent. Outstanding native
   hook authorizations are refused because they may represent live host tools.

## Restore and activate explicitly

1. Keep the original intact at its original path. Stop all writers and retire
   the original runner configuration before cutover. Never run both roots against
   the same workspace. This procedure does not provide cross-root fencing.
2. Run restore with the original as `--workdir`, the pinned snapshot, and an
   absent target directory. Its parent must already exist:

   ```powershell
   dah --workdir C:\DAH\proxy-state --workspace-root C:\Pilot\workspace restore --snapshot C:\DAH-Backups\proxy-001 --target C:\DAH\proxy-restored --expect-manifest-sha256 sha256:REPLACE_WITH_RETAINED_DIGEST --operator sam --note "All writers stopped; original configuration retired; actual target retained for investigation"
   ```

3. A refusal leaves the original intact. Do not delete stale locks, truncate a
   torn tail, reset continuity or substitute a different original to force a
   pass. S5 torn-append and S6 interrupted-publication stores are retained and
   reported; S7 does not repair them. Escalate when accounting is unavailable.
4. A successful copy still requires an explicit authority transition because
   its path and filesystem identity differ. A read-only `doctor` correctly
   reports that mismatch before activation. The new root must retain the
   original's verified private Windows ACL posture when enrolled; failure to
   preserve or verify it refuses the copy. Use the original runtime configuration and workspace to attempt
   startup at the new root. It refuses with the exact candidate profile hash
   before launching the upstream. Do not change MCP targets or policy to make
   it pass.
5. Authorize that exact hash with `authority-profile-rotate`, operator identity,
   note, and the existing signing options when required. Start the owning runtime
   once to activate. This is a new profile generation, not silent rebinding.
6. Read pending/reconciliation state in the CLI or read-only Command Center.
   Restored previously approved approvals are `executing` (uncertain), including
   expired ones. This status does not claim that restore dispatched anything.
   `restore_receipt.json` identifies the affected approvals and operator restore
   statement; it is diagnostic provenance, not an execution grant or signature.
7. Inspect the actual external target and reconcile each uncertain approval:

   ```powershell
   dah --workdir C:\DAH\proxy-restored --workspace-root C:\Pilot\workspace reconcile APPROVAL_ID --outcome succeeded --operator sam --note "Verified exact expected file contents at the actual target; one observed upstream receipt"
   ```

   Use `failed` or `not_executed` only when the investigation supports that exact
   outcome. `not_executed` requires positive evidence of no dispatch. Uncertainty
   alone never releases a reservation. Existing reconciliation remains idempotent
   and never calls the tool. If the outcome is unknown, leave it uncertain.
8. Run `doctor` and `verify`. Audit the other root separately if desired. Restore
   never reads, mutates or repairs that other root. Retain the original even
   after cutover and do not reuse it as an active authority.

## Interruption and owner acceptance record

Candidates are built in create-exclusive sibling directories and published by
directory rename. A preserved staging candidate is beside the requested target,
named `.<target-name>.restore-<uuid>` (for example,
`C:\DAH\.proxy-restored.restore-<uuid>`). Inspect that parent directory after a
refusal; the error response does not currently include the candidate path.
An interrupted partial candidate retains an incomplete marker
and refuses owning startup. Preserve it; do not remove the marker manually.
Directory synchronization on Windows retains the existing best-effort limitation;
process-kill tests do not prove power-loss durability for every filesystem.

The owner walkthrough must record both roots, snapshot digest, shutdown and
upstream-exit evidence, original preservation, explicit profile transition,
actual-target investigation, reconciliation outcome/identity/note, before/after
receipt counts, and final audits. It must include a real pinned-MCP write after
the snapshot and unchanged exact receipt counts across restore/reconciliation.
Synthetic fixture results do not substitute for this owner-run pilot gate.
