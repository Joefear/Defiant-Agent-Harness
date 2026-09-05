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

Each command materializes one sequence using the strict parser and existing
per-record and filesystem checks. Show now reads the complete sequence before
returning an early match, so malformed data later in the log is not ignored.

## Deliberate limits

History and show are inspection tools, not hash-integrity endorsements. A
readable but hash-corrupt record remains inspectable; verify reports
`CHAIN BROKEN` and returns exit code 1. These commands do not validate every
evidence contract field or establish that a hash-valid log is complete.

Observations are point-in-time. They neither exclude writers nor clear an
uncertain writer lock, and successful inspection never authorizes execution.
Later writes require a new observation. Verify checks the captured chain, not
the durable checkpoint, external witness, or full cross-store state.

The complete history remains unbounded and inspection is linear in its size;
history's display limit is not a read limit. Export, signing, ordinary writer
initialization, and authority lock lifecycles are unchanged. Command Core and
Command Center contracts are unchanged; Command Center remains read-only.
No DKE or Spartan capability is added.
