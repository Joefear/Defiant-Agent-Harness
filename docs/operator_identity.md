# Signed operator identity

v0.9 can require an Ed25519 signature for every approval decision and crash
reconciliation. This replaces a caller-supplied operator string with proof that
the holder of a key explicitly pinned to that exact operator authorized one
exact action.

v0.10 makes that choice durable. The first authority-bearing startup supplied
with trust bindings enrolls signed-required mode in
`.dah/operator_trust.json`. It stores only sorted operator/key IDs, hashes,
timestamps, and signed rotation records—not public-key paths or private
material. Once enrolled, authority-bearing startup without matching pins fails
closed. Omitting the flags can no longer silently return the work directory to
legacy unsigned mode.

When upgrading an existing v0.9 work directory that already contains signed
approval or reconciliation attestations, the first v0.10 authority startup
also requires the complete current pins and enrolls them. It refuses to treat
those records as legacy authority merely because `operator_trust.json` does not
exist yet.

Signed mode is enabled by supplying one or more trust bindings in this form:

```text
IDENTITY=/absolute/path/to/operator-public.pem
```

The identity is part of the trust configuration, not taken from the signed
record. A trusted key assigned to `alice` cannot sign as `bob`. Trust files must
remain outside the harness work directory.

## Generate an operator key

Create a passphrase file through the operating system's secret-management
workflow, then generate the encrypted private key and public trust key:

```powershell
dah --workdir .dah operator-keygen `
  --private-key C:\DefiantKeys\alice-private.pem `
  --public-key C:\DefiantKeys\alice-public.pem `
  --passphrase-file C:\DefiantKeys\alice.passphrase
```

The private key and passphrase must remain outside `.dah`, must not be readable
by the governed agent, and should be stored separately in production. The
public key is distributed to each runtime through an authenticated operator
channel.

## Approve or reject

An operator note is mandatory. The command signs the approval id, action id,
request id, authorization hash, outcome, identity, note, and timestamp. The
store verifies the signature and the identity-to-key pin before changing state.

```powershell
dah --workdir .dah --user alice approve apr_... `
  --note "Reviewed recipient and final attachment" `
  --operator-key C:\DefiantKeys\alice-private.pem `
  --operator-passphrase-file C:\DefiantKeys\alice.passphrase `
  --trusted-operator-key alice=C:\DefiantKeys\alice-public.pem
```

Use the same signing arguments with `reject`. Unsigned legacy mode remains
available only for a work directory that has never enrolled operator trust.
After enrollment, every authority-bearing CLI, proxy, or hook process must
receive the complete enrolled mapping. It refuses missing or changed pins as
well as unsigned, invalid, replayed, or untrusted approvals before execution.

## Reconcile an uncertain execution

Reconciliation uses a separate signature purpose so an approval signature
cannot be replayed as a recovery decision. The required outcome, operator, and
note remain explicit:

```powershell
dah --workdir .dah reconcile apr_... `
  --outcome failed `
  --operator alice `
  --note "Provider accepted the request; no success response was returned" `
  --operator-key C:\DefiantKeys\alice-private.pem `
  --operator-passphrase-file C:\DefiantKeys\alice.passphrase `
  --trusted-operator-key alice=C:\DefiantKeys\alice-public.pem
```

Verification happens before budget, evidence, or terminal approval mutation.
If the outcome might have incurred cost, the existing conservative
reconciliation rule charges the reserved worst case. `not_executed` releases
the reservation only when the operator has established that dispatch did not
occur. Exact retries remain idempotent; a conflicting outcome, identity, or
note is refused.

Approval-free executions use the sealed authorization evidence record instead
of an approval id:

```powershell
dah --workdir .dah reconcile-authorization evd_... `
  --outcome not_executed `
  --operator alice `
  --note "Provider confirms that dispatch never occurred" `
  --operator-key C:\DefiantKeys\alice-private.pem `
  --operator-passphrase-file C:\DefiantKeys\alice.passphrase `
  --trusted-operator-key alice=C:\DefiantKeys\alice-public.pem
```

This path uses a distinct authorization-reconciliation schema, purpose, and
signing domain. Its signature binds the sealed record id and hash, action,
request, authorization hash, explicit outcome, operator, note, and timestamp.
Approval decision and approval-reconciliation attestations cannot be replayed
on it. See `authorization_reconciliation.md` for the crash and budget rules.

## Long-running proxies and native hooks

The process that consumes an approval must use the same trust pins:

```powershell
dah --workdir .dah mcp-proxy --config .\mcp-proxy.yaml `
  --trusted-operator-key alice=C:\DefiantKeys\alice-public.pem
```

The HTTP proxy accepts the same option. Native hooks read a JSON array from
`DAH_TRUSTED_OPERATOR_KEYS`, for example:

```powershell
$env:DAH_TRUSTED_OPERATOR_KEYS = '["alice=C:\\DefiantKeys\\alice-public.pem"]'
```

Malformed trust configuration makes hook startup fail closed. The private key
and passphrase are never provided to a proxy, hook, Command Core, or Command
Center.

## Read-only inspection

Pass the public trust bindings to `dah doctor`, `dah command`, or
`dah command-center` to verify persisted attestations. Command Core exposes
only assurance, operator, key id, and signing time. It excludes the signature
and operator note. Command Center renders this projection but has no key upload,
approval, reconciliation, or other mutation endpoint.

These diagnostic paths never enroll or rotate trust. If durable signed mode is
present but pins are omitted, they still start, mark the snapshot unsafe and
non-authoritative, and report `operator_trust_unverified`. A malformed state or
different mapping is likewise visible without repair.

## Rotation and compromise

Online rotation is deliberately additive. Supply the complete current mapping,
the complete post-rotation mapping, a private key already trusted in the current
generation, its identity, and a non-empty note:

```powershell
dah --workdir .dah operator-trust-rotate `
  --trusted-operator-key alice=C:\DefiantKeys\alice-2026-public.pem `
  --new-trusted-operator-key alice=C:\DefiantKeys\alice-2026-public.pem `
  --new-trusted-operator-key alice=C:\DefiantKeys\alice-2027-public.pem `
  --operator-key C:\DefiantKeys\alice-2026-private.pem `
  --operator-passphrase-file C:\DefiantKeys\alice-2026.passphrase `
  --operator alice `
  --note "Stage the reviewed 2027 key"
```

The transition signature binds the prior and next generation, both mapping
hashes, operator, note, signer key ID, and time. The durable chain also records
each resulting key-ID mapping, allowing every transition to be verified on
restart. A newly introduced key cannot authorize its own addition. Exact
retries are idempotent.

Removal, reassignment, or replacement is refused online because it would make
the durable history unverifiable or let a changed startup configuration bypass
the old trust root. For compromise recovery, stop all writers, preserve the
state and evidence for investigation, and perform a separately governed offline
recovery. v0.10 intentionally provides no automatic delete, reset, or force
rotation command.

This mechanism proves key possession under an explicit local trust mapping. It
does not provide certificate identity, remote authentication, trusted time,
hardware-backed custody, automatic revocation, or multi-user Command access.
