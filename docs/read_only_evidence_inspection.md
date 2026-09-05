# Read-only evidence inspection

v0.85 extends the non-initializing evidence reader to `dah history`, `dah show`,
and `dah verify`. They open an existing log directly, without constructing a
writable store, enrolling a directory, recreating evidence, acquiring a writer
lock, advancing a checkpoint, or repairing state.

Missing directories or logs, invalid JSON, duplicate keys, non-object records,
oversized records, and filesystem read failures return exit code 1 with a
diagnostic on stderr and no partial output on stdout. An existing empty log
remains valid: history reports no evidence, verify reports an intact zero-record
chain, and show reports a missing record.

Each command uses the strict parser and existing per-record and filesystem
checks. Since v0.89, history streams the log and retains only bounded display
rows. v0.90 streams show and verify as well: show retains its first match, and
verify keeps chain state and its first hash failure. Each requires a successful
full read before output, so malformed tails are not hidden by an early match
or hash failure. See `streaming_inspection.md` for complete-read semantics.

v0.87 additionally validates the six history projection fields as strings before
filtering, limiting, or printing. History escapes and truncates displayed cells;
negative limits are refused and zero selects no rows. See
`safe_history_rendering.md`. Show remains a JSON inspection path.

v0.88 also escapes and bounds the commands' human-readable error text, missing
show IDs, and verify's broken-chain detail. Full JSON values remain unchanged.
See `safe_inspection_diagnostics.md` for the covered output paths and limits.

## Deliberate limits

History and show are inspection tools, not hash-integrity endorsements. A
readable but hash-corrupt record remains inspectable; verify reports
`CHAIN BROKEN` and returns exit code 1. These commands do not validate every
evidence contract field or establish that a hash-valid log is complete.

Observations are point-in-time. They neither exclude writers nor clear an
uncertain writer lock, and successful inspection never authorizes execution.
Later writes require a new observation. Verify checks the captured chain, not
the durable checkpoint, external witness, or full cross-store state.

The complete log remains unbounded and inspection is linear in its size;
history's display limit is not a read limit. History retention follows the
requested row count, show retains at most one selected record, and verify keeps
chain state or its first failure detail, all in addition to per-record working
storage. See `streaming_history.md` and `streaming_inspection.md`. Export,
signing, ordinary writer initialization, and authority lock lifecycles are
unchanged. Command Core and
Command Center contracts are unchanged; Command Center remains read-only.
No DKE or Spartan capability is added.
