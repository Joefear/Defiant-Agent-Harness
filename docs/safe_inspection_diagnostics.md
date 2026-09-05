# Safe evidence inspection diagnostics

v0.88 extends the history cell renderer to handler-owned human-readable output
from `dah history`, `dah show`, `dah verify`, and `dah export`.

## Presentation boundary

The shared renderer emits ASCII JSON-style escapes for control characters,
non-ASCII text, bidirectional formatting characters, quotes, and backslashes.
Untrusted text cannot introduce extra terminal lines, cursor movement, a window
title, or terminal colors through these messages. Harness-owned formatting and
colors remain. The renderer processes at most the first 1,024 source characters
per diagnostic fragment and bounds the escaped result to 1,024 display
characters, using an ellipsis when truncated. Existing history cells retain
their smaller v0.87 widths.

Covered fragments are evidence-reader errors in history/show/verify, the missing
record ID in show, the verifier's broken-chain detail, export evidence/signing
errors, and the destination path in export's success message. A broken chain
still has a separate fixed failure heading and numeric record index, even when
its detail is truncated. Ordinary ASCII diagnostics without quoting or escaping
characters retain their wording and all command exit codes are unchanged.

## Data and authority remain unchanged

This is a display projection, not a modification of `ChainStatus`, evidence,
hashes, signatures, record matching, or filesystem paths. Show and stdout export
still emit full JSON using their existing serialization and limits; decoding
that JSON recovers the original values, including text longer than the
diagnostic ceiling. Export file output writes to the exact requested path and
keeps the existing signing and no-overwrite rules.

History, show, and verify remain non-initializing and read-only. Export still
requires existing evidence and uses its existing transient lock; explicitly
requested export publication is a write. Command Core and Command Center are
unchanged, and Command Center stays strictly read-only. No DKE or Spartan
capability is added.

## Limits

The display ceiling is per fragment, not per command or per log. It does not
bound the allocation that originally constructed an exception or chain detail,
redact secrets, repair evidence, or authenticate terminal output. Truncated
diagnostics are not lossless; inspect JSON when complete values are needed.
Other CLI commands, argument-parser diagnostics, unexpected tracebacks, and
trusted in-process replacement of implementation objects are outside this
guarantee. This does not turn Python into a hostile-code sandbox.
