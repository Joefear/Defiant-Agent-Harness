# Durable authority-profile continuity

v0.15 pins the complete runtime authority profile before Defiant initializes or
recovers operational stores. The profile hash is the policy engine's canonical
`ruleset_hash`, which includes normalized policy rules, known tools, every
security-relevant `ToolSpec` field, the workspace-root hash, dry-run posture,
and adapter/upstream authority inputs.

This is configuration continuity, not binary attestation. It prevents an
accidental or unapproved policy, tool map, workspace, mode, or upstream change
from silently inheriting the authority of an existing state directory.

## Startup behavior

The first v0.15 authority-bearing startup atomically enrolls its profile as
generation 1 in `authority_profile.json`. This is the v0.14 migration boundary:
the operator must verify the first v0.15 configuration before starting it.

Later startup has only three valid outcomes:

- exact active hash: proceed without changing the profile state;
- exact operator-authorized pending hash: atomically activate the next
  generation, then proceed;
- anything else: fail before approval, budget, evidence, journal recovery, or
  tool mutation.

The durable transition binds the old and new generations and hashes, operator,
non-empty note, and request time. If signed operator trust is enrolled, the
pending transition also requires a trusted Ed25519 signature under the distinct
`authority_profile_rotation` purpose and signing domain.

## Planned rotation

Beginning in v0.18, start the candidate runtime once against the real state
directory and use the hash printed by its fail-closed mismatch error. Storage
identity is now an authority input, so a disposable directory produces a
different hash. Review the complete policy, tool map, workspace, execution
mode, adapter/upstream configuration, and state-root posture that produced it.
Then stage exactly that hash from PowerShell:

```powershell
cd "C:\Users\samcf\Desktop\Dev\Defiant Agent Harness"
.\.venv\Scripts\dah.exe --workdir C:\path\to\.dah `
  authority-profile-rotate sha256:<candidate-hash> `
  --operator release-operator `
  --note "Reviewed policy and upstream rollout for release 2026-08-21"
```

In signed mode, supply the current pins and signing material:

```powershell
.\.venv\Scripts\dah.exe --workdir C:\path\to\.dah `
  authority-profile-rotate sha256:<candidate-hash> `
  --operator alice `
  --note "Reviewed production authority change CHG-1042" `
  --trusted-operator-key "alice=C:\keys\alice-public.pem" `
  --operator-key C:\keys\alice-private.pem `
  --operator-passphrase-file C:\keys\alice.passphrase
```

The command stages intent; it does not activate the candidate or execute a
tool. The old profile remains valid during the cutover. The next startup with
the exact candidate hash activates generation N+1 atomically. A third profile
still fails closed. A different pending request cannot overwrite the first;
inspect and resolve a mistaken or compromised request offline rather than
adding an ambiguous online cancel path.

Private keys, passphrases, policy sources, tool maps, workspace paths, operator
names, notes, and signatures are not exposed through Command Core or Command
Center. Their projection includes only generation, active and pending hashes,
verification state, rotation-required state, transition counts, and assurance.

## Crash and concurrency behavior

Rotation is a single atomic JSON replacement protected by both the v0.14
state-directory authority lock and the profile store's conservative file lock.
A crash before replacement leaves the prior generation. A crash after
replacement leaves the complete staged or activated generation. Activation
precedes operational-store recovery, so restart never observes a half-written
profile transition. Exact staging retries are idempotent.

The execution-disabled operator-control path used for rejection and
reconciliation can verify the enrolled profile without pretending its local
mock policy is the MCP or hook runtime. It cannot run, preflight, resume, or
complete a tool action.

## Recovery and limits

Do not edit `authority_profile.json` to make a mismatch disappear. Preserve the
state directory, identify why the candidate hash changed, and either restore
the reviewed configuration or stage an explicit rotation. A present
`authority_profile.json.lock` is a critical doctor finding until the operator
confirms that no writer remains.

Like durable operator-trust enrollment, this file has no external witness. A
host administrator who can replace code and state can restore an older
internally valid generation. Use access controls, immutable deployment inputs,
and off-box generation/hash observations when host-level rollback detection is
required.

v0.18 additionally binds the canonical state-root device/file identity and
security posture into the profile. A copied, relocated, or replaced root needs
an explicit profile transition. See `state_storage_integrity.md` for the
filesystem contract and upgrade procedure.

v0.19 additionally binds the protected control-plane path contract: sanitized
workspace hash, protected-root count, workspace/state relationship, and
contract hash. The first v0.19 start against v0.18 state therefore requires an
explicit profile transition. Derive the candidate against the real workspace
and state root, then follow the existing staged rotation procedure. See
`control_plane_isolation.md`.

v0.20 additionally binds the workspace root's canonical path and filesystem
identity through a sanitized mode and root hash. The first v0.20 start against
v0.19 state requires an explicit profile transition derived against the real
workspace root. A copied, replaced, relocated, symlinked, or reparse-point root
is not accepted automatically. See `workspace_root_integrity.md`.
