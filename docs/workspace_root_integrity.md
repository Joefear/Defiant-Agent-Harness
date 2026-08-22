# Workspace-root integrity

v0.20 binds the governed workspace directory itself to one filesystem identity.
Workspace contents are intentionally mutable; the control protects the root
from silent replacement, relocation, or indirection between authorization and
tool dispatch.

## Authority startup

An authority-bearing startup creates the configured workspace directory when
it is absent, then inspects it without following a final symbolic link or
Windows reparse point. The root must be a real directory. Its canonical path,
device, and inode/file identity form a sanitized `root_hash`; only the mode and
hash enter the complete authority profile.

The matching `workspace_integrity.json` observation is written under
`authority.lock` and bound to that exact profile. An existing v0.19 directory
therefore needs the normal explicit profile transition before v0.20 authority
can proceed. Derive the candidate against the real production workspace, not a
temporary copy, and activate only the reviewed candidate.

Doctor, Command Core, and Command Center never create a missing workspace or
write this observation. Pass the real root to obtain a live check:

```powershell
.\.venv\Scripts\dah.exe --workdir C:\path\to\.dah `
  --workspace-root C:\path\to\workspace doctor
```

Without a supplied root, programmatic Command Core callers report
`profile_bound` rather than claiming a live filesystem verification.

## Enforcement

The state-integrity gate re-observes the configured root before every new
authority-bearing harness operation. A missing, replaced, symlinked,
reparse-point, or non-directory root makes state unsafe before new evidence,
budget, approval, or tool mutation.

The tool registry independently repeats the identity check immediately before
every `workspace` or `workspace_path` handler or MCP dispatch. This closes the
authorization-to-dispatch replacement window. Refusal happens before the
single-use grant is spent, so restoring the original root permits the same
otherwise-valid grant to be retried. A replacement root is never accepted
automatically.

Files and subdirectories below the root may be created, edited, renamed, or
deleted normally. Their identities are not part of this contract. Runtime
artifact assurance, state-storage integrity, and control-plane path isolation
cover different boundaries and remain independently enforced.

## Read-only projection and limits

The diagnostic projection includes only mode, root hash, profile hash,
verification state, and last verification time. It never exposes the canonical
path or raw filesystem identity. Command Center adds no accept, relink, move,
create, repair, profile-rotation, approval, or execution control.

This is a same-process path-identity check, not an operating-system sandbox or
rollback witness. A privileged host can replace code and state together, patch
the running process, or manipulate storage after the final check. Upstreams
with broader mounts can ignore their declared path. Production still needs
least-privilege mounts, immutable deployment inputs, OS containment, and
off-box observations where host-level rollback matters.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
