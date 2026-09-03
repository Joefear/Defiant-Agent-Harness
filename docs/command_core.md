# Command Core

Command Core is the read-only bridge between Defiant Agent Harness state and
Defiant Command surfaces. It does not approve, execute, classify, or alter an
action. Its only job is to validate local records and project a small
operational snapshot.

Run it with:

```bash
dah --workdir .dah command
```

The JSON result uses schema `defiant.command.snapshot` version `0.74.0` and
contains:

- evidence-chain and cross-store integrity plus an overall `authoritative` flag;
- record, request, action, decision, and execution-status counts;
- exact-decimal aggregate cost and observed ruleset hashes;
- fixed pre-parse and publication ceilings, including the evidence-export cap;
- the fixed symmetric operation-journal read/write and canonical snapshot
  ceiling;
- fixed symmetric authority-profile and operator-trust state read/write and
  canonical snapshot ceilings;
- the fixed symmetric authority-publication continuity-anchor read/write and
  canonical snapshot ceiling;
- the fixed symmetric authority-publication witness-policy read/write and
  canonical snapshot ceiling;
- the fixed symmetric runtime-artifact-state read/write and canonical snapshot
  ceiling;
- the fixed symmetric native-hook correlation-state read/write and canonical
  snapshot ceiling;
- the fixed symmetric approval-state read/write and canonical snapshot ceiling;
- the fixed symmetric budget-state read/write and canonical snapshot ceiling;
- the fixed symmetric evidence-head-state read/write and canonical snapshot
  ceiling;
- the fixed symmetric evidence-witness-policy-state read/write and canonical
  snapshot ceiling;
- fixed trusted-public-key count, per-key byte, and aggregate key-set ceilings;
- fixed complete-policy pack, rule, known-tool, per-field, and aggregate-list
  ceilings;
- fixed per-item and complete-ruleset policy text ceilings;
- fixed governed-payload matching depth, node, text, and aggregate work ceilings;
- fixed policy glob tool-name/target subject and aggregate work ceilings;
- fixed policy-context entry, key, value, and aggregate text ceilings;
- fixed action-hash depth, node, per-mapping entry, aggregate mapping-sort-work,
  scalar-character, escaped-string-token, number-token, and canonical-byte
  ceilings;
- fixed pre-adapter tool-call name, identifier, depth, node, per-mapping entry,
  aggregate mapping-sort-work, scalar-character, escaped-string-token,
  number-token, and canonical-byte ceilings;
- fixed post-execution tool-result summary, depth, node, per-mapping entry,
  aggregate mapping-sort-work, scalar-character, escaped-string-token,
  number-token, and canonical-byte ceilings;
- fixed governed-request task, identifier, allowlist, provenance, and
  aggregate-text ceilings;
- fixed authority-YAML nesting-depth and constructed-node ceilings;
- fixed per-collection and aggregate MCP authority-configuration ceilings;
- approval status counts, reconciliation-required state, and safe metadata for
  currently actionable items;
- durable operator-trust generation, mapping hash, operator/key counts, and
  verification status;
- durable authority-profile generation, active and pending hashes,
  verified/mismatched/rotation-required state, and sanitized transition
  assurance without operator names, notes, or signatures;
- sanitized authority-publication state, exact target generation, manifest
  hash, independently reconstructed completed-manifest verification, active
  recovery phase, target and completed-checkpoint commitment posture, stable
  checkpoint-commitment verification, semantic intent/checkpoint seal posture,
  exact predecessor/originating-intent link posture, sanitized monotonic
  continuity state and sequence, and timestamps without raw record, linkage,
  checkpoint, or continuity hashes, raw manifests, individual commitment
  hashes, or state paths;
- sanitized external authority-publication witness mode, verification,
  witnessed sequence, current lag, profile generation, key id, signer, and
  signing time without the checkpoint hash, signature, payload, operator note,
  witness path, or key path;
- sanitized runtime-artifact mode, bundle hash, count, executable-pin posture,
  last verification time, and binding to the active authority profile, without
  artifact paths or individual file digests;
- sanitized state-storage mode, root hash, profile binding, private-permission
  and directory-sync posture, checked-file count, and orphan-temporary count;
  strict Windows mode additionally reports only its ACL policy identifier,
  protected-root status, and allow-principal count, without the state path,
  filesystem identity components, SIDs, account names, ACEs, or masks;
- sanitized control-plane isolation mode, contract/workspace hashes,
  protected-root count, overlap relationship, profile binding, and last
  verification time, without canonical paths or exception controls;
- sanitized workspace-root mode, root hash, profile binding, and live or
  profile-only verification state, without canonical path or filesystem ids;
- sanitized evidence-head checkpoint mode, record count, head/profile hashes,
  verification state, and checkpoint time without evidence bodies or paths;
- sanitized external-witness mode, verification, witnessed count/head,
  current unwitnessed-record count, optional profile-bound maximum, profile
  generation, key id, signer, and signing time without paths, signatures, or
  operator notes;
- sanitized launch-envelope mode, environment and working-directory hashes,
  variable, secret, and explicitly acknowledged unsafe counts, last
  verification time, and profile binding, without environment names or values;
- local-operation recovery state with only operation id, kind, and preparation
  time when a valid journal is active;
- approval-free authorization recovery counts and bounded items containing only
  authority record, request, action, tool, timestamp, and state;
- known-result journal recovery state that is excluded from manual
  reconciliation counts;
- budget balance, reservations, spend, and estimate drift;
- a bounded list of recent operational events; and
- fixed byte ceilings for durable JSON, each evidence record, MCP messages,
  native-hook events, MCP configuration, and each policy pack; and
- the static authority-YAML and authority-JSON parser profiles plus explicit
  alias, nesting, lexical-token, scalar-token, canonical-number,
  canonical-string, canonical-mapping-key-family, complete-mapping-key,
  validated-canonical-snapshot, validated-snapshot-ownership,
  validated-contract-collection-snapshot,
  validated-scalar-ownership,
  validated-authority-record-ownership,
  validated-policy-snapshot-ownership,
  sealed-policy-runtime-state,
  validated-policy-context-snapshot,
  validated-operation-journal-snapshot,
  validated-native-hook-event-snapshot,
  sealed-authority-continuity-state,
  bounded-authority-continuity-I/O,
  crash-safe-authority-publication,
  validated-authority-publication-snapshot,
  validated-authority-publication-record-seals,
  validated-authority-publication-transition-links,
  verified-authority-publication-continuity,
  verified-authority-publication-manifest,
  verified-active-authority-publication-phase,
  verified-active-authority-publication-store-commitments,
  verified-active-authority-publication-checkpoint-store-commitments,
  verified-completed-authority-publication-checkpoint-store-commitments,
  validated-runtime-artifact-state-snapshot,
  sealed-native-hook-correlation-state,
  sealed-approval-record-state,
  validated-budget-ledger-snapshot,
  validated-evidence-head-snapshot,
  validated-evidence-witness-policy-snapshot,
  canonical-mapping-size,
  canonical-mapping-sort-work,
  complete-canonical-value, MCP-collection, policy-text,
  policy-payload-matching, policy-glob-matching, duplicate-key,
  non-finite-number, and strict-UTF-8 posture.

Use `--request <request_id>` to project one request and `--limit <count>` to
bound recent activity.

## Trust behavior

Command Core verifies the complete evidence chain before producing evidence
aggregates. If verification fails, `authoritative` is false, the process exits
non-zero, and both `evidence` and `recent_activity` are withheld. The integrity
failure itself remains visible so an operator can investigate it.

The `state_integrity` object is the sanitized `defiant.state_integrity` audit.
It reports `healthy`, `recovery_required`, or `unsafe`, whether execution is
safe, per-store status, counts, and issue codes. If approvals or budget state is
malformed, Command Core marks the snapshot non-authoritative and substitutes an
`invalid` projection for that store instead of hiding the diagnostic behind a
server error. No repair is attempted.

The projection deliberately excludes evidence targets, payload previews,
decision inputs, and raw results. Actionable approval entries expose only ids,
tool name, status, timestamps, whether operator reconciliation is required,
and sanitized identity assurance: operator, key id, signing time, and
verification status. Signatures and operator notes remain excluded. The
underlying local state directory still
contains confidential operational data and must remain access-controlled.
Issue output excludes targets, payload previews, reconciliation notes, and raw
results. The `operation_journal` projection never includes its prepared
approval, evidence, held action, operator note, or attestation. Reading a
snapshot does not initialize, recover, complete, or clear the journal.

Signed evidence exports are deliberately outside this live-state projection.
Command Core never loads private keys, imports signed exports, or treats an
export signature as authority over current state. With repeatable
`--trusted-operator-key IDENTITY=PUBLIC_KEY.pem` options it can verify approval
attestations and the enrolled trust-generation chain read-only; those public
pins cannot create authority. If signed mode is enrolled but pins are omitted
or mismatched, the snapshot remains available but is non-authoritative and
reports the trust failure. Command Core never enrolls or rotates trust. Use the
offline `dah verify-export` workflow documented in `evidence_signing.md`.

When external head witnessing is enrolled, Command Core must receive global
`--evidence-head-witness` and repeatable `--trusted-evidence-key` inputs. It
verifies them without mutation. Missing, mismatched, rolled-back, or divergent
input makes the snapshot non-authoritative while preserving the sanitized
diagnostic. See `evidence_head_witness.md`.

v0.23 runtime-artifact projections distinguish selected-file `pinned` mode
from declared-root `closed` mode. Closed mode adds only dependency-root and
dependency-file counts; paths, relative filenames, and individual hashes are
withheld.

## Boundary

Command Core remains a local, on-demand read model with no server, execution,
approval, or mutation behavior of its own. The loopback-only Command Center UI
consumes this contract without gaining an authority path into the harness. See
`command_center.md` for that local HTTP surface. Multi-user identity, remote
ingestion, account authentication, and off-box evidence replication remain absent.
The resource-limit projection is descriptive and fixed by the running build;
it is not a runtime configuration or mutation surface.
The `authority_configuration` projection is likewise descriptive. Command Core
does not load, upload, edit, approve, or replace policy or MCP configuration.
Its authority-record ownership flag is static build posture; it does not expose
decision, grant, or evidence mutation.
