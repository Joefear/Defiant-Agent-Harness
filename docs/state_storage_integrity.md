# State-storage integrity

v0.18 hardens the filesystem boundary beneath Defiant's durable approvals,
budgets, evidence, recovery journals, trust state, authority profile, and other
local observations. A valid JSON schema or hash chain is not sufficient if the
path being read can silently redirect to another file.

## Root identity and authority

Every authority-bearing startup creates or validates one canonical state root.
The root must be a real directory, not a symbolic link or Windows reparse point.
Defiant records a sanitized root hash derived from the canonical path and the
filesystem device/file identity. The hash, platform storage mode, permission
posture, and directory-sync posture enter the complete authority profile.

`state_storage.json` records the same observation under `authority.lock` and
binds it to the active profile hash. A copied, replaced, relocated, remounted,
or security-posture-changed root therefore produces profile drift before
operational recovery. The path, device number, and inode/file identifier are
never emitted by Doctor, Command Core, or Command Center.

Profiles are intentionally state-root-specific beginning in v0.18. To stage any
authority change, run the reviewed candidate configuration against the real
state directory, let the existing profile reject it, and copy the `configured
sha256:...` value from that fail-closed error. Authorize that exact hash through
`authority-profile-rotate` with an operator identity and note. A candidate hash
from a disposable state directory is not interchangeable.

## File invariants

Before a durable state file or lock is read or mutated, Defiant:

1. validates the state root;
2. uses `lstat` to reject symbolic links, reparse points, directories, devices,
   sockets, pipes, and other non-regular objects;
3. requires exactly one hard link;
4. on POSIX, requires current-user ownership plus mode `0600` for files and
   `0700` for the root;
5. opens with `O_NOFOLLOW` and close-on-exec where the platform exposes them;
6. compares the pre-open path identity with `fstat` on the opened descriptor;
7. rechecks the descriptor, path, and root identities before closing.

Windows stdlib does not provide a portable ACL equivalence to the POSIX owner
and mode checks. Windows is therefore reported as `structural_only`; symlink,
reparse-point, type, hard-link, path/descriptor identity, root binding, and
atomic-write checks still apply. Protect the directory with an operator-only
NTFS ACL as a deployment control.

## Atomic replacement and crash posture

JSON state writes create a private, exclusive temporary file in the state root,
serialize strict JSON, flush and `fsync` the file, revalidate the temporary and
destination identities, replace atomically, validate the published file, and
sync the directory entry. Directory synchronization is required on POSIX and
best-effort on Windows where opening a directory for `fsync` may be unsupported.

Append-only evidence opens the already validated single-link file, appends one
sealed line, and `fsync`s the file before returning. State-file locks use the
same structural checks. A lock that changes while held is not removed as if it
were the original lock.

An orphan `.<name>.<token>.tmp` file is a critical read-only Doctor finding. It
may represent a process crash or an interrupted/hostile writer. Defiant does
not delete or promote it automatically; preserve the state directory and
investigate offline.

## Upgrade from v0.17

The first v0.18 authority start against v0.17 state intentionally reports a new
candidate profile because storage identity is now an authority input. Review
the real state path and its protection, stage that exact candidate with the
existing explicit profile-rotation workflow, then restart the candidate to
activate it and create `state_storage.json`.

On POSIX, older state created with group/other permission bits fails closed
before rotation. After taking a backup and confirming no Defiant process is
running, restrict the root to `0700` and its Defiant state files and lock to
`0600`. Do not recursively chmod unrelated workspace content. On Windows,
review and restrict the root's NTFS ACL with normal administrator tooling.

Doctor and Command Center remain read-only: they report mode, bounded hashes,
profile binding, checked-file and orphan-temporary counts, permission posture,
directory-sync posture, and last verification time. They cannot chmod, relink,
move, delete, restore, accept, or repair state.

## Limits

This is not protection from a privileged or same-user host attacker who can
replace the running harness, patch memory, alter code and state together, or
restore an older complete root plus its authority history. Device/inode identity
is a local filesystem signal, not a globally unique storage identity or an
off-box rollback witness. Network filesystems and unusual filesystems may have
different durability or identity semantics and require deployment testing.

Use least-privilege service identities, operator-only ACLs, encrypted storage,
backups, immutable deployment artifacts, and off-box signed observations as
complementary controls. This release adds no DKE, Spartan, remote Command, or
Command Center authority.
