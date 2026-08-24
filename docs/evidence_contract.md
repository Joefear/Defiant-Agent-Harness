# Evidence contract

The interface between the harness and Defiant Command. Command does not need to exist for these records to be worth writing, but these records need to exist before Command is worth building.

Format is JSON Lines: one record per line, append-only, UTF-8. A consultant can open it, a customer can be handed it, and Command can ingest it without a database dependency.

## Fields

| field | type | meaning |
|---|---|---|
| `schema_name` | string | `defiant.agent_harness.evidence_record` |
| `schema_version` | string | evidence contract version |
| `record_id` | string | unique per record |
| `timestamp` | RFC3339 UTC | when the record was written |
| `request_id` | string | links every record produced for one user request |
| `action_id` | string | links the records produced for one proposed action |
| `agent_runner` | string | `hermes`, `openclaw`, `claude-code`, `codex`, `mock`, ... |
| `model_id` | string | model identity when the runner exposes it |
| `user_id` | string | operator identity |
| `workspace_id` | string | client or project workspace |
| `tool_name` | string | the tool the agent tried to use |
| `target` | string | path, recipient, URL, payee |
| `side_effect_level` | enum | `none`, `local_write`, `external_send`, `external_publish`, `spend`, `destructive` |
| `decision` | enum | `allow`, `block`, `approval_required` |
| `policy_ids` | string[] | every rule that produced the winning decision |
| `policy_version` | string | version string of the loaded packs |
| `ruleset_hash` | string | `sha256:` over the full ruleset |
| `decision_reason` | string | human-readable, shown to the operator verbatim |
| `decision_inputs` | object | snapshot of exactly what the engine saw |
| `approved_by` | string / null | operator identity copied from the verified approval when signed mode is configured |
| `approved_at` | RFC3339 / null | when they approved |
| `payload_hash` | string | `sha256:` over the canonical payload |
| `authorization_hash` | string | binds the complete policy-relevant action |
| `payload_trust` | enum | `trusted`, `derived`, `untrusted` |
| `input_refs` | object[] | provenance of the material behind the payload |
| `result_status` | enum | `succeeded`, `failed`, `not_executed`, `blocked`, `skipped`, `pending_approval`, `expired`, `rejected` |
| `result_summary` | string | short human summary |
| `output_hash` | string | `sha256:` over the tool output |
| `cost_usd` | decimal string | actual cost of this action |
| `budget_remaining_usd` | decimal string | available balance after this action |
| `dry_run` | bool | whether the effect was simulated |
| `reconciliation_outcome` | string | explicit operator outcome for an uncertain execution, otherwise empty |
| `reconciled_by` | string | operator identity copied from verified reconciliation when signed mode is configured, otherwise empty |
| `reconciled_at` | RFC3339 / null | when reconciliation intent was durably recorded |
| `reconciliation_note` | string | required operator explanation, otherwise empty |
| `previous_record_hash` | string | hash of the preceding record |
| `record_hash` | string | `sha256:` over every other field |

For v0.12 approval-free authorization reconciliation, the terminal evidence
uses the reconciliation fields without fabricating `approved_by`. Its outcome,
operator, note, timestamp, action, request, authorization hash, and conservative
cost must agree with the authorization-bound budget reconciliation marker.

For v0.13 known-result recovery, the unsealed terminal record is prepared in the
operation journal after the tool returns. Its output hash, result, cost, and
post-settlement available balance are fixed before cross-store completion. The
raw tool response is not added to the journal.

## Hashing

All hashes are `"sha256:" + sha256(canonical_json(value))`, where canonical
JSON uses sorted keys and compact separators. Enums serialize to string values,
timestamps normalize to UTC, and exact decimal values serialize as plain
decimal strings. Non-finite numbers are rejected.

`record_hash` covers every field except itself, including `previous_record_hash`. The first record chains to `GENESIS` (`sha256:` followed by 64 zeros).

## What the chain proves, and what it does not

It proves that no record was altered in place, deleted from the middle, or
reordered without detection. `verify()` reports the failing index. The writer
refuses to append if the existing file is malformed or the chain is broken.

Beginning in v0.21, a separate profile-bound checkpoint detects when the local
file is shorter than or diverges from its last durable count and head hash. A
valid extension beyond the checkpoint is a recoverable append crash. This does
not prevent a writer from replacing both evidence and checkpoint with an older
matched pair. Off-box replication answers that stronger truncation threat and
belongs to Command. v0.8 can prove that the holder of an explicitly trusted
Ed25519 key signed one exact point-in-time request export; it does not turn the
mutable local files into immutable off-box storage. See
`evidence_head_integrity.md`.

## Export and attestation contract

`dah export` emits schema `defiant.evidence.export` version `0.2.0`. It binds
request-scoped records to the verified complete-chain record count and head
hash, includes the export timestamp, and preserves the complete chain status.
Unsigned exports remain useful local artifacts but make no authorship claim.

With `--signing-key`, the document also contains schema
`defiant.evidence.attestation` version `0.1.0`. Ed25519 signs a domain-separated
statement containing the canonical payload hash, public-key id, signing time,
asserted signer identity, and required note. The public key is not embedded as
a trust decision. `dah verify-export` requires one or more independently pinned
public-key files and rejects an untrusted key even when the mathematics of the
signature is otherwise valid.

Signing refuses a broken chain, empty request, cross-request record, malformed
hash or timestamp, inconsistent count, unsupported schema, or non-canonical
JSON value. See `evidence_signing.md` for the operator and rotation procedures.

v0.22's separate signed head witness covers the complete chain position rather
than one request export. It binds the deployment root and an authority-profile
generation so the newest independently retained document can detect restoring
`evidence.jsonl` together with its local checkpoint. It does not add fields to
evidence records or make Command Center an import/signing authority. See
`evidence_head_witness.md`.

## Data handling

Each physical JSONL evidence record, including its newline, is limited to
16 MiB before decoding. A larger existing record makes the chain invalid and
blocks authority; a larger new record is refused before append. This is a
per-record ceiling, not a cap on total append-only evidence history.

Evidence records carry hashes of payload and output bodies rather than the
bodies themselves. Operational metadata—including target paths, recipients,
user ids, workspace ids, rule reasons, and provenance labels—remains visible.
Treat evidence as confidential business data; it is lower-risk than a payload
archive, not automatically safe for unrestricted distribution.

The separate local approval store does retain the complete held action so an
approval can resume after a process restart. It is not part of an evidence
export and must be protected with local filesystem access controls.

`redactions` on a policy rule is reserved for future operator-facing display
logic. v0.1 does not claim automatic redaction of evidence metadata.

## Reserved for later

`memory_sources_used` is reserved for DKE. It is absent in v0.1 rather than fabricated, so that adding DKE extends the schema rather than changing it.

## Reading it

```bash
dah history                # tail of the trail
dah show <record_id>       # one record in full
dah verify                 # chain integrity
dah export <request_id>    # a pack: records + chain status, ready for Command
dah verify-export <file> --trusted-key <public.pem>  # offline authenticity
```
