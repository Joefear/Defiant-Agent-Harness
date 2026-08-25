# Signed evidence exports

v0.8 adds offline-verifiable Ed25519 attestations for request-scoped evidence
exports. The signature covers the complete canonical export payload: request
records, chain status, complete-chain record count and head hash, export time,
and schema metadata. A signer must provide an explicit identity and non-empty
note. Signing refuses a broken chain, an empty export, inconsistent counts, or
a record belonging to another request.

This feature does not place a private key in the Defiant state directory and
does not add a signing or import endpoint to Command Center.

## Create a signing key

Provision a non-empty passphrase file using the organization's secret-management
process. Keep that file and the encrypted private key outside `.dah`, restrict
both to the signing operator or service account, and back them up according to
the organization's key policy.

```bash
dah signing-keygen \
  --private-key /secure/defiant/evidence-private.pem \
  --public-key /secure/defiant/evidence-public.pem \
  --passphrase-file /secure/defiant/evidence-passphrase
```

The private key is encrypted PKCS8 PEM. The public key is SubjectPublicKeyInfo
PEM and may be distributed to reviewers over an authenticated, out-of-band
channel. The CLI refuses private, public, passphrase, or verification trust-key
files located inside the harness work directory. Key and export creation refuse
to overwrite an existing file.

## Sign an export

```bash
dah --workdir .dah export req_... \
  --signing-key /secure/defiant/evidence-private.pem \
  --passphrase-file /secure/defiant/evidence-passphrase \
  --signer operator-7 \
  --note "Q3 control evidence handoff" \
  --output request-evidence.signed.json
```

Schema `defiant.evidence.export` version `0.2.0` contains an attestation using
schema `defiant.evidence.attestation` version `0.1.0`. The attestation contains:

- algorithm `Ed25519`;
- a `sha256:` public-key identifier;
- signing time, asserted signer identity, and required note;
- `sha256:` of the canonical export payload; and
- a base64-encoded detached signature over a domain-separated statement.

The key id is
`sha256(canonical_json({"algorithm":"Ed25519","public_key":<raw-key-hex>}))`
with the repository's usual `sha256:` prefix. The signed bytes are the ASCII
domain `Defiant Agent Harness evidence export attestation v0.1.0`, a null byte,
and canonical JSON of every attestation field except `signature`.

The public key itself is deliberately not embedded as a trust decision. A
recipient must pin a public key received independently.

## Verify offline

```bash
dah verify-export request-evidence.signed.json \
  --trusted-key /trusted/defiant/evidence-public.pem
```

Successful verification means the payload is structurally valid, its hash
matches, the signature is valid, and the signing key is in the explicit trust
set. The command exits non-zero for malformed JSON, duplicate keys, non-finite
numbers, payload or attestation tampering, unsupported schemas or algorithms,
an invalid signature, or an untrusted key.

v0.29 limits each serialized export to 64 MiB. Verification reads at most the
ceiling plus one byte and rejects oversized input before decoding or parsing.
Export file/stdout publication and direct `sign_export()`/`verify_export()`
entry points enforce the same ceiling. Oversized documents are not truncated,
silently segmented, or partially published. See `bounded_evidence_exports.md`.

The signer identity is still an assertion bound into the signature. A verifier
must map the pinned public-key identifier to an accountable person or service
through its own identity and key-custody process.

v0.32 bounds each verification trust set at 1,024 supplied public keys, 65,536
bytes per PEM, and 8,388,608 aggregate PEM bytes. An excessive count fails
before any key file is opened; per-key or aggregate overflow invalidates the
whole verification rather than ignoring a key. See `trusted_key_limits.md`.

## Rotation and revocation

Generate a new pair instead of overwriting an old one. During an intentional
rotation, a verifier can accept both public keys:

```bash
dah verify-export request-evidence.signed.json \
  --trusted-key evidence-public-2026.pem \
  --trusted-key evidence-public-2027.pem
```

Keep an old public key available for historical verification after its private
key is retired. Remove a compromised key from the active trust set and handle
previous exports under the organization's incident policy; Defiant does not
claim that a signature reveals when a private key was stolen.

## Security boundary

An attestation proves that the holder of a pinned private key signed one exact
point-in-time export. It does not prevent copying confidential evidence, prove
that the human-readable signer string is true, prove that no later evidence was
written, or make a truncated live chain complete. Off-box retention, trusted
time, hardware-backed keys, certificate identity, revocation distribution, and
multi-user Command remain deployment or later-release concerns.
