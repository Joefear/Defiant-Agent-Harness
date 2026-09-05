# Streaming history inspection

v0.89 makes `dah history` retain display rows instead of the complete decoded
evidence log. The default remains the latest 25 matching records in stored
order, with the existing table, escaping, and exit-code conventions.

## One read, bounded retention

`EvidenceStore.stream_existing_records(path)` is a context-managed iterator over
the existing strict, descriptor-backed reader. It never constructs a writable
store, initializes a missing root or log, acquires a writer lock, or repairs
state. Once iteration starts, the same opened stream is used until completion
or failure. Leaving the context closes the iterator and its descriptor, even
when the consumer stops early or raises an exception.

History validates each record's six projection fields before applying its
request filter. Matching records are rendered immediately into bounded ASCII
rows, and a deque keeps only the requested tail. Full decoded records and their
unused payloads are not retained across the log. No table or success message is
printed until the full read and validation succeed. A malformed or unreadable
tail discards the buffered display, including with zero limits or no matches.

Retained display storage is proportional to the smaller of the requested limit
and the number of matching records, plus the current per-record parsing work.
Replacing the oldest row briefly needs one extra bounded row. Zero retains no
rows and skips rendering, but still reads and validates. Very large positive
limits remain accepted without preallocating a correspondingly large buffer.

## Deliberate limits

This is not a fixed process-memory or whole-history byte cap. Existing
per-record JSON and byte ceilings remain; the caller can request a large number
of rows, and processing time still grows with the entire log. An actively
growing file can prolong inspection. The stream does not exclude writers or
create an immutable filesystem snapshot. Validation failures may stop the read
early, but successful output always requires reaching the end of the stream.

History still does not authenticate records, verify hashes, prove completeness,
or authorize execution. Show, verify, exports, witnesses, signing, ordinary
writer lifecycles, and the list-returning `read_existing_records` API are
unchanged. Command Core and Command Center are unchanged and read-only. No DKE
or Spartan capability is introduced.
