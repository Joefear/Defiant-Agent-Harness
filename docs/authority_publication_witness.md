# External authority-publication witness

v0.80 can require an independently retained Ed25519 witness for the current
authority-publication continuity head. This closes the matched-local-rollback
gap left by the compact local ratchet: a valid older pair of
`authority_publication.json` and `authority_publication_continuity.json` is
behind the signed external sequence and therefore fails closed.

This feature is optional. Enabling it changes the authority profile and
requires the normal explicit profile-rotation procedure. Once enrolled,
omitting the witness or trusted keys does not downgrade the runtime; it blocks
authority.

## Signed contract

The witness binds:

- deployment-root hash;
- authority-profile generation and hash;
- publication-continuity sequence;
- exact completed-checkpoint hash;
- observation and signing times;
- Ed25519 key id, signer assertion, and required operator note.

The trusted key ids and required mode are authority-profile inputs and are also
committed by the combined publication manifest. The durable policy lives in
`authority_publication_witness_policy.json`. Private keys, public keys,
passphrase files, and witness documents must be outside `.dah` and outside any
agent-writable area.

## Operator flow

Generate a key pair once, using an external passphrase file:

```powershell
dah operator-keygen --private-key C:\Defiant-Secrets\publication-private.pem --public-key C:\Defiant-Witness\publication-public.pem --passphrase-file C:\Defiant-Secrets\publication-passphrase.txt
```

Create a new, non-overwriting witness for the current verified publication
head:

```powershell
dah --workdir .dah witness-authority-publication --signing-key C:\Defiant-Secrets\publication-private.pem --passphrase-file C:\Defiant-Secrets\publication-passphrase.txt --signer "release-operator" --note "retain current authority publication" --output C:\Defiant-Witness\publication-0001.json
```

Verify the document independently against live state:

```powershell
dah --workdir .dah verify-authority-publication-witness C:\Defiant-Witness\publication-0001.json --trusted-key C:\Defiant-Witness\publication-public.pem
```

Supply the witness and every trusted rotation key to the owning runtime and to
read-only diagnostics:

```powershell
dah --workdir .dah --authority-publication-witness C:\Defiant-Witness\publication-0001.json --trusted-authority-publication-key C:\Defiant-Witness\publication-public.pem doctor
```

On first enablement, the candidate runtime reports the new configured profile
hash. Authorize that exact hash with `authority-profile-rotate`, then repeat the
startup with the same witness and trusted-key set.

An owning-runtime startup accepts only an exact current witness. Successful
startup publishes a new checkpoint, so the retained witness is then exactly
one sequence behind. `doctor`, Command Core, and Command Center report
`publication_witness_refresh_required`; this state is safe to inspect, but the
operator must sign and distribute a fresh witness before the next owning
startup. The old file is never overwritten—publish a new file and update the
external deployment reference.

## v0.81 issuance verification

`witness-authority-publication` now acquires the same nonblocking,
cross-process `authority.lock` used by owning runtimes and retains it through
verification, signing, and external file publication. While holding that lock
it rechecks the live state-root identity and enrolled security posture, refuses
an active recovery intent, requires the completed checkpoint to match the
active profile generation and continuity head, independently reconstructs the
complete durable authority manifest, and compares every retained per-store
commitment. Only that coherent point-in-time checkpoint is signed.

If another authority transaction is active, a dependency was substituted, a
policy write was interrupted, or the state root changed, issuance fails and no
external witness file is created. The command does not repair local state or
overwrite an existing output. This issuance gate strengthens what the operator
signs; it does not turn local time into trusted time or replace independent
witness retention.

## v0.82 crash-durable publication verification

After the signed temporary file is flushed, the non-overwriting publication
path atomically links it to the requested final name. The writer synchronizes
the containing directory before removing the temporary link, removes that
link, synchronizes the directory again, and reads the final file back under
the still-held authority transaction lock. Success requires a constant-time
match with the exact serialized signed document. Directory synchronization is
required on POSIX and best effort on Windows, matching the platform contract
used by harness persistence.

If final-link durability cannot be confirmed, temporary cleanup fails, cleanup
durability cannot be confirmed, the final file cannot be read, or its bytes do
not match, issuance fails. Because the final link may already exist, the writer
does not delete or overwrite it. The operator must treat the destination as
ambiguous, inspect or independently verify it, and either retain it as the
published witness or deliberately remove it and publish to a new name. A retry
against the same existing path remains refused.

## Failure posture

The harness refuses authority for an invalid signature, untrusted key,
deployment-root or profile mismatch, a local sequence behind the witness,
more than one unwitnessed publication, policy substitution, malformed or
oversized input, an external path inside state, or missing witness material
after enrollment. It never repairs or rewrites external material.

Publication success is a point-in-time claim. It does not prevent an actor
with later write access to the external directory from replacing the file;
independent retention and access control remain required.

Command Core and Command Center project only mode, verification state,
profile generation, witnessed sequence, lag, key id, signer, and signing time.
They do not receive the raw checkpoint hash, signature, payload, note, or
external paths, and Command Center remains strictly read-only.

The guarantee depends on truly independent retention. An attacker who can
replace local state and the external witness or trusted-key channel together
can still manufacture a consistent rollback. Use off-host or append-only
storage, controlled key distribution, and audited key custody.
