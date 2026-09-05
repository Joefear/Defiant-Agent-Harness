# Streaming show and verification

v0.90 extends the existing-log streaming reader to `dah show` and `dah verify`.
Neither command retains the complete decoded evidence history. Both preserve
the strict parser, per-record limits, non-initializing behavior, terminal-safe
diagnostics, and existing exit-code conventions.

## Show retains one match

Show remembers only the first matching record in stored order and continues
reading to the end. A malformed or unreadable tail still produces a diagnostic
on stderr and no JSON on stdout, even when an early record matched. A missing
record is reported only after the read succeeds. Successful output is the same
full, lossless JSON projection; display limits do not truncate it. Duplicate
record IDs retain the existing first-match behavior, not a new uniqueness
guarantee.

## Verify preserves full-read precedence

The CLI calls `verify_evidence_records` with `require_complete_read=True` inside
the context-managed stream. It remembers the first hash failure, then drains
the remaining records without doing further hash comparisons. A later reader
`EvidenceError` is raised to the CLI, which emits only its stderr diagnostic.
This preserves the precedence of the old read-all-before-verifying path.

If the read finishes, an intact chain reports its complete record count, while
a broken chain reports the same first failure as before. In particular,
`ChainStatus.count` and `broken_at` keep their original failure-prefix meaning;
draining the tail does not claim those later records were hash-verified. The
helper's default remains early-stop verification with reader errors returned
as failed chain status. Writers, exports, witnesses, and other existing callers
retain that default behavior.

## Resource and authority limits

Retained data consists of per-record parsing/hashing work, at most one selected
record for show, and chain state or the first failure detail for verify. This
does not establish a fixed process-memory cap or reduce the cost of an
individual record below the existing parser and record-byte ceilings. Full-log
read time remains linear, and an actively growing log can prolong inspection.

The single stream closes on completion or failure. It does not initialize or
repair state, lock out writers, reopen the log for a second observation, or
create an immutable filesystem snapshot. Show does not authenticate its result;
verify still does not prove completeness or replace checkpoint, witness, or
cross-store checks. The list-returning capture API and its other consumers are
unchanged. Command Core and Command Center remain unchanged and read-only. No
DKE or Spartan capability is introduced.
