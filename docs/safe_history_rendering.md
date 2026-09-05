# Safe history rendering

v0.87 hardens `dah history` without changing stored evidence or granting any
new authority to Command Core or Command Center.

## Validate before display

History requires timestamp, tool name, decision, result status, record ID, and
request ID to be JSON strings. Validation covers the entire captured sequence
before request filtering or limiting, so those options cannot hide malformed
projection fields. A missing or wrongly typed field returns exit code 1 with a
fixed field-name diagnostic on stderr and no partial table on stdout. The
diagnostic never echoes the invalid value.

After validation and selection, rows are rendered before the table is printed.
Evidence text is converted to ASCII JSON-style escapes: newline, escape, bell,
non-ASCII, and bidirectional formatting characters cannot act as terminal
controls. Harness-owned status colors remain. Timestamps retain their existing
first-19-character projection before escaping. Escaping processes only a bounded
prefix of each cell. Overlong escaped cells are truncated with an ellipsis;
display widths are 19 for timestamps, 13 for tools, 18 for decisions,
20 for result statuses, and 80 for record IDs. This is a display projection, not
a lossless serialization; use `show` to inspect the underlying JSON record.

## Limit semantics

The default remains 25 rows. Positive limits select the latest matching rows
in stored order. Negative CLI limits are rejected during argument
parsing, before evidence is read. Direct handler calls also refuse negative,
boolean, and non-integer limits.

Zero means no selected rows, not every row. It still reads and validates the
log, so missing evidence or malformed projection fields remain failures. An
existing empty log retains the usual no-evidence message.

## Limits of the guarantee

History still reads the full existing log and remains non-initializing and
read-only. No total-history memory bound or maximum positive row count is added.
These checks do not validate every contract field, authenticate records, check
hashes, or establish completeness. Readable hash-corrupt records remain
inspectable. Show, verify, export, signing, and writer lifecycles are unchanged.
This does not claim terminal safety for every other CLI command.

Command Center stays read-only; its schema is unchanged. No DKE or Spartan
capability is introduced.
