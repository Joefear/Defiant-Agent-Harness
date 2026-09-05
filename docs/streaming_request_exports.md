# Streaming request exports

v0.91 changes `EvidenceStore.export_existing_request`, and therefore the
instance `export_request` API and `dah export`, to select and verify from one
context-managed existing-log stream. The normal existing-root exclusive file
lock covers the entire scan; no writable store is constructed, root enrolled,
evidence initialized, checkpoint advanced, or state repaired.

## Retention and capture

A pass-through iterator retains every matching request record in stored order,
without retaining unrelated decoded history. It also observes the final head
hash from that same stream. Request values and extra JSON fields remain
lossless; duplicates are not deduplicated or newly validated. There is no
second read to select records or determine the head. Both the iterator and
reader close before the lock is released, including on failure.

## Failure compatibility

The verifier uses its opt-in complete-read mode. An intact chain reports the
complete logical record count and final head, or the genesis hash for an empty
log. A readable broken chain retains its original first-failure status and
failure-prefix count, with a null head. Despite its legacy name,
`full_chain_record_count` still contains that failure-prefix count when broken;
draining does not claim the later records were hash-verified.

Selection continues after a hash failure, so an unsigned diagnostic export
still includes matching records later in the log. Hash comparisons stop at
the first failure, but strict reading continues. A later malformed record or
reader error raises `EvidenceError` instead of returning that diagnostic
export. The CLI emits only its existing stderr diagnostic and exit code 1,
without reaching signing, serialization, stdout publication, or destination
creation. Existing destinations and stranded locks remain untouched.

Signing still refuses a broken chain and empty request. Export schema, field
meanings, signing identity and note requirements, key pinning, no-overwrite
publication, and the 64 MiB artifact ceiling are unchanged. Default early-stop
verification for other callers is unchanged.

## Deliberate limits

Memory grows with selected request data plus per-record parsing and hashing
work, not with all unrelated records. This is not a fixed process-memory cap:
all selected records remain materialized, and a very large request can consume
substantial memory before existing signing or serialization ceilings reject
it. Serialization and signing are not streamed. No records are truncated,
silently split, or removed from the evidence log.

The entire log is read, including malformed tails after an early hash failure.
Scan time and cooperating-writer exclusion remain linear in history size;
non-cooperating appenders can prolong the scan. The transient lock changes
directory metadata and is not privileged-host containment or an immutable
filesystem snapshot. Export remains an operator command that can publish an
explicit artifact, not a strictly read-only command. It does not prove log
completeness or replace checkpoints, witnesses, or cross-store checks.

Command Core and Command Center contracts remain unchanged and read-only.
No DKE or Spartan capability is introduced.
