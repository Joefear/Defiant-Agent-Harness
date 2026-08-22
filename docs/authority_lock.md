# Single-writer authority transactions

v0.14 enforces the repository's one-writer safety assumption instead of leaving
it solely to deployment discipline. Every authority-bearing harness entry point
acquires a nonblocking lock for the complete state directory before recovery,
integrity checks, authorization, tool execution, settlement, or reconciliation.

The lock covers:

- harness construction that can enroll trust or initialize stores;
- normal and externally executed tool authorization;
- approval resume, rejection, expiry, and execution reconciliation;
- approval-free authorization reconciliation;
- known-result completion and operation-journal recovery; and
- a complete `run()` call, including its nested action calls.

## Crash and contention behavior

`authority.lock` is a persistent one-byte file, but ownership is an operating
system file-region lock attached to an open descriptor. If another thread or
process owns it, acquisition fails immediately with `AuthorityLockError`; Defiant
does not wait, mutate state, or call a tool. Nested entry points in the owning
thread are reentrant.

When a process exits or crashes, the operating system closes the descriptor and
releases the region automatically. The file itself remains and must not be
deleted as stale state. This differs from the conservative per-store
`*.json.lock` files: those are creation sentinels and a hard crash can require an
operator to confirm that no writer remains before removing one.

## Security boundary

The transaction lock prevents ordinary cooperating harness processes from
interleaving authority-bearing operations. It does not defend against an
administrator who patches the process, bypasses the harness, or edits files
directly. It also does not make the JSON stores a transactional database. The
operation journal still provides deterministic crash recovery, per-file locks
still protect atomic writes, and the state-integrity auditor still validates
cross-store bindings.

Doctor, Command Core, and Command Center remain read-only. They never acquire,
release, clear, or expose a mutation endpoint for the authority lock.
