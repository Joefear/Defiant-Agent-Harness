# Signed evidence-head witnesses and lag bounds

v0.22 can require an operator-signed evidence-head witness retained outside the
Defiant state directory. This closes the local comparison gap in v0.21: if an
older `evidence.jsonl` and matching `evidence_head.json` are restored together,
the newest external witness still identifies the later count and head hash.

The witness is schema `defiant.evidence.head_witness` version `0.1.0`. It binds:

- the state-storage root hash for one deployment;
- an enrolled authority-profile generation and hash;
- the complete evidence record count and head hash;
- observation and signing times;
- an explicit signer identity and required note; and
- a detached Ed25519 signature from an explicitly trusted key.

The private key, passphrase, public trust keys, witness output, and witness input
must remain outside `.dah`. Command Center never receives private-key material
and has no upload, signing, acceptance, repair, or rotation endpoint.

## Create and verify a witness

The existing encrypted evidence-signing key format is reused:

```bash
dah --workdir .dah witness-evidence-head \
  --signing-key /secure/defiant/evidence-private.pem \
  --passphrase-file /secure/defiant/evidence-passphrase \
  --signer operator-7 \
  --note "nightly retained evidence head" \
  --output /offbox/defiant/head-2026-08-22.json

dah --workdir .dah verify-evidence-head-witness \
  /offbox/defiant/head-2026-08-22.json \
  --trusted-key /trusted/defiant/evidence-public.pem
```

Signing is read-only with respect to `.dah`. It refuses a broken chain, missing
authority/storage/checkpoint observations, profile mismatch, or a chain that
does not exactly match its crash-safe local checkpoint. Output creation refuses
overwrite.

Verification checks strict JSON/schema shape, payload hash, trusted key,
signature, deployment root, authority-profile history, and live chain position.
The chain may equal or validly extend the witness. A shorter or divergent chain
fails closed.

To evaluate a configured freshness ceiling without changing state, put the
global option before the verification subcommand:

```bash
dah --workdir .dah --max-unwitnessed-records 100 \
  verify-evidence-head-witness /offbox/defiant/head-2026-08-22.json \
  --trusted-key /trusted/defiant/evidence-public.pem
```

## Enroll required mode

Required mode, the sorted trusted key identifiers, and any configured maximum
unwitnessed-record count enter the complete authority profile. For an existing
deployment:

1. create a witness under the current profile;
2. start the candidate runtime with global
   `--evidence-head-witness <file>` and repeatable
   `--trusted-evidence-key <public.pem>` options, plus optional
   `--max-unwitnessed-records <count>`, to obtain its candidate profile hash;
3. stage that exact hash with the normal explicit authority-profile rotation;
4. restart with the same external inputs to activate it.

After enrollment, owning and operator-control harness construction refuses to
proceed when the witness or trust keys are omitted. Key-set changes use the same
explicit profile-rotation procedure. An old-profile witness remains valid after
rotation because its exact generation and hash must remain in the verified
profile history.

The maximum is inclusive: `100` permits a valid live chain with at most 100
records after the signed head. `0` requires an exact match at the next authority
gate and is useful as a deliberate freeze posture; normal operation will append
evidence and then require a refreshed witness before another gated step. If the
option is omitted, the v0.22 behavior remains compatible and the valid tail is
unbounded. Enabling, changing, or removing a finite bound changes the complete
authority profile and therefore requires the normal explicit rotation.

Lag is measured in hash-chained evidence records, not elapsed time. This avoids
claiming that the local clock is trusted. The check runs during owning and
operator-control startup and through State Integrity at later authority gates.
An already-authorized operation can append records after its check, so size the
ceiling for the deployment's operation shape and refresh before the next gate
when necessary. A failure reports `lag_exceeded`; it is distinct from a forged,
rolled-back, or divergent witness. Create a new signed witness for the current
head and restart or retry with that external file to recover.

`evidence_witness_policy.json` records only the profile binding, required mode,
trusted key identifiers, optional maximum lag, and time. It contains no paths,
keys, signature, operator note, or witness contents. Policy schema v0.2 reads
existing v0.1 observations as unbounded. A normal owning startup records an
explicit `not_configured` posture for migration; operator-control paths cannot
initialize a missing observation.

## Read-only operations

Doctor, Command Core, and Command Center accept the same global external-input
options. They never copy, advance, replace, or acknowledge the witness. Their
projection contains only verification state, hashes, witnessed and unwitnessed
counts, the optional maximum, key id, signer, and signing time; paths,
signatures, and notes are withheld. If required input is absent, invalid, or
too stale, the view remains available but is non-authoritative. Command Center
has no refresh, acceptance, repair, policy-change, or signing control.

## Security boundary

The newest retained witness is the rollback floor. Without a finite bound,
supplying an older valid witness cannot detect rollback of records written after
that witness. A finite bound limits this exposure in record-count terms but
does not prove that no later records once existed. Operators must distribute
trust keys authentically, retain witnesses off-host or in independently
protected storage, and supply the newest accepted witness.

This feature does not provide automatic replication, trusted time, key
revocation distribution, hardware-backed custody, host compromise prevention,
or remote/multi-user Command. A privileged attacker who can replace code,
external configuration, trusted keys, and the retained witness remains outside
the boundary.
