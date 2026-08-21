# Signed operator identity

v0.9 can require an Ed25519 signature for every approval decision and crash
reconciliation. This replaces a caller-supplied operator string with proof that
the holder of a key explicitly pinned to that exact operator authorized one
exact action.

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
available only when no trust pins are configured. A runtime started with any
`--trusted-operator-key` is strict: it refuses unsigned, invalid, replayed, or
untrusted approvals immediately before execution.

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

## Rotation and compromise

Repeat `--trusted-operator-key` to trust old and new public keys for the same
identity during a planned rotation. Remove a compromised key from every runtime
trust set after reviewing all decisions made with that key. Historical records
signed by a removed key become untrusted under the current policy; retain a
separately governed historical trust manifest if audit policy requires it.

This mechanism proves key possession under an explicit local trust mapping. It
does not provide certificate identity, remote authentication, trusted time,
hardware-backed custody, automatic revocation, or multi-user Command access.
