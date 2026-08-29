# Control-plane path isolation

v0.19 prevents governed workspace tools from using Defiant's own durable state
as agent data. This matters when the normal `.dah` state directory is nested
under the configured workspace: private file modes and structurally safe opens
do not help if the governed tool is itself allowed to name that directory.

## Authority contract

Before policy construction, every authority-bearing runtime canonicalizes the
workspace and binds the canonical state root into the tool registry as a
protected control-plane root. A sanitized contract containing the workspace
hash, protected-root count, overlap relationship, and complete contract hash
enters the v0.15 authority profile.

`control_plane_isolation.json` records that same contract under
`authority.lock` and binds it to the active profile. Changing the workspace,
state root, protected-root relationship, or isolation contract therefore
requires the normal explicit authority-profile rotation.

No canonical path or filesystem identity is written to Doctor, Command Core,
or Command Center. The relationship is reported only as `separate`,
`state_within_workspace`, `workspace_within_state`, or `same_root`.

## Enforcement

For every tool whose operator-authored contract uses `target_scope: workspace`
or `target_scope: workspace_path`, the registry resolves the target and rejects
it when either:

- the target is the protected state root or one of its descendants; or
- a directory-scope target is an ancestor that would include protected state.

Resolution follows existing symbolic links before comparison, so an apparently
safe alias to `.dah` is still protected. Validation runs before policy and
again immediately inside grant execution. If a symlink changes after
authorization, the second check refuses execution before the single-use grant
is spent. A contract failure becomes terminal blocked evidence and is never
forwarded to an MCP upstream.

The ancestor rule is deliberately conservative. If `.dah` is inside the
workspace, a recursive or directory-wide tool cannot safely target the
workspace root because its declared scope includes `.dah`. Move Defiant state
outside the governed workspace or narrow the workspace/tool target instead of
adding a bypass.

## Upgrade from v0.18

The isolation contract is a new authority input. The first v0.19 authority
startup against v0.18 state reports profile drift before tool execution. Review
the real workspace and state relationship, then stage the exact candidate hash
with `authority-profile-rotate`, an operator identity, and a non-empty note.
Restart that exact candidate to activate it and create
`control_plane_isolation.json`.

If Doctor reports `workspace_within_state` or `same_root`, relocate the
workspace or state as part of the reviewed transition. The runtime remains
fail-closed for every workspace target overlapping the state root; it does not
silently exempt nested files.

## Read-only diagnostics and limits

Doctor, Command Core, and Command Center expose only mode, hashes, profile
binding, protected-root count, relationship, and verification time. They cannot
add an exception, alter a target scope, move state, rotate the authority
profile, or execute a tool.

This is a policy-bound target isolation control, not an operating-system
sandbox. It governs paths named through accurately classified tool contracts.
An upstream that ignores its declared target argument, accesses unrelated paths
internally, receives a broader host mount, or is reached outside Defiant still
requires process, filesystem, and network containment. A same-user or
privileged attacker able to patch the running harness remains outside this
boundary.

This release adds no DKE, Spartan, remote Command, or Command Center authority.

v0.20 additionally protects the workspace boundary itself from root replacement;
see `workspace_root_integrity.md`. The two controls are complementary: this
document governs targets relative to the root, while v0.20 verifies that the
root is still the enrolled directory.

v0.70 makes the sanitized `control_plane_isolation.json` observation one
detached canonical built-in snapshot. Capture, descriptor-backed recovery, and
atomic publication share an explicit 64 KiB ceiling; caller mutation cannot
change conflict checks or publication, and failed oversized publication leaves
prior recoverable bytes unchanged. See
`validated_filesystem_authority_state_snapshots.md`.
