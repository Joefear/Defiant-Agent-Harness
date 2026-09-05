# Existing-only evidence exports

v0.86 removes writable evidence-store construction from `dah export`.
`EvidenceStore.export_existing_request(path, request_id)` first requires an
existing evidence file, then captures it under the normal exclusive file lock.
The instance `export_request` method delegates to the same path.

The lock's new `require_existing_root=True` option inspects the state directory
without creating it. Export therefore refuses a missing directory or log,
including deletion between the initial check and locking or capture, without
recreating evidence or its directory. Ordinary writers retain their existing
directory-initialization behavior.

Verification and request selection now consume one captured record sequence.
The returned chain status, full-chain count, selected records, and head hash
cannot come from separate reads of a changing log. The capture retains the
existing strict parser, per-record limits, and filesystem identity checks.

## Failure and compatibility contract

- Missing or malformed evidence returns CLI exit code 1 with no partial export
  on stdout or at the requested destination.
- A present empty log can still produce an empty export with the genesis head.
- A readable broken chain can still produce an unsigned diagnostic export
  carrying a failed chain status; the signing path continues to reject it.
- An existing writer lock fails immediately and remains untouched. It is never
  cleared or treated as proof that the writer has stopped.

Export is not a strictly read-only command: it creates and removes its transient
lock and may publish an explicitly requested output. Locking can change directory
metadata even when a later read fails. No evidence repair or initialization is
performed. Signing requirements, pinned verification keys, byte ceilings,
no-overwrite output, and export schemas are unchanged.

This is a point-in-time observation under cooperating writer exclusion, not a
defense against a compromised host or later replacement of the exported file.
The full history remains materialized in memory; no new total-history bound is
introduced. Command Core and Command Center contracts remain unchanged and
Command Center stays read-only. No DKE or Spartan capability is added.
