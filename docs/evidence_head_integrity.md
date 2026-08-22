# Evidence-head integrity

v0.21 adds a profile-bound durable checkpoint for the append-only evidence
chain. The JSONL chain already detects edits, deletion from the middle, and
reordering. The checkpoint additionally detects an otherwise valid retained
prefix after accidental tail truncation or a partial state restore.

## Durable ordering

`EvidenceStore` verifies the existing chain before every append. It then seals
and appends one record, flushes and fsyncs the evidence file, and only then
atomically advances `evidence_head.json`. The checkpoint contains the active
authority-profile hash, checkpoint mode, record count, head hash, and update
time. It contains no target, payload, result, operator note, or path.

This ordering has one expected crash window: the evidence file may contain a
valid extension while the checkpoint still names an earlier prefix. Doctor,
Command Core, and Command Center report `forward_recovery` and a recovery
warning without changing either file. The next owning authority startup checks
that the retained record at the checkpoint count has the exact checkpoint hash,
then advances to the current valid head. It never replays a tool or invents an
evidence record.

If the evidence file has fewer records than the checkpoint, the audit reports
`evidence_tail_rollback` and blocks authority. If it has the same or greater
count but does not contain the checkpoint as the exact prefix,
`evidence_head_divergence` blocks authority. Neither state is repaired or
accepted automatically.

## Profile continuity and migration

The checkpoint contract enters the complete authority profile. The first v0.21
startup against v0.20 state therefore requires the normal explicit profile
transition. After that reviewed candidate activates, startup creates
`evidence_head.json` at the current verified chain position.

Later profile activation may rebind the checkpoint only when
`AuthorityProfileStore` actually activated an authorized transition and the
chain still matches or validly extends the prior checkpoint. A plain profile
mismatch remains critical.

Execution-disabled operator rejection and reconciliation paths require an
existing checkpoint. They do not initialize a missing file or downgrade to
uncheckpointed evidence. During upgrade, start and activate the owning v0.21
authority runtime before using those auxiliary paths.

## Read-only projection and limits

The state-integrity report and Command snapshot expose only mode, verification,
profile hash, record count, head hash, and last checkpoint time. Command Center
renders that sanitized posture but has no checkpoint, repair, acceptance,
rotation, approval, reconciliation, or execution endpoint.

This is a local crash/rollback detector, not an external witness. A writer able
to replace both evidence and checkpoint consistently, a privileged host able to
replace code and complete state, or restoration of an older internally matched
pair remains outside this boundary. Signed exports and off-box head retention
are still required when the threat includes local state administrators or
host-level rollback.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
