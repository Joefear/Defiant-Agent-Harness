# Validated contract collection snapshots

Defiant v0.52 binds governed request collections and action provenance to one
validated built-in-storage snapshot. Earlier releases revalidated a live list
and then converted it to an owned tuple in a separate traversal. A list
subclass could expose a different iterator view during validation, and a
validation-time mutation could enter the later copy.

## Covered collections

The control applies to:

- `HarnessRequest.allowed_tools`;
- `HarnessRequest.inputs`; and
- `ProposedAction.payload_sources`.

Each collection must still be a list when the unsealed contract is submitted.
Defiant reads its size and elements through built-in `list` methods, enforcing
the existing count ceiling while capturing the snapshot. Subclass `__len__`
and `__iter__` hooks are not invoked. A size change observed during capture
fails with a sanitized contract-snapshot error.

Defiant validates types, non-empty allowlist entries, item lengths, aggregate
text volume, and provenance counts against the captured tuple. The owning
request or action then retains that exact tuple. It does not iterate the caller
list again after validation.

v0.53 additionally normalizes accepted entries and provenance metadata to exact
built-in strings before retaining the tuple. See
`validated_scalar_ownership.md`.

## Authority behavior

Request sealing repeats scalar normalization and collection capture immediately
before adapter proposal or direct call translation. The exact validated
allowlist therefore drives request-scope authorization, and the exact validated
input references become the sealed request context.

Action sealing repeats the complete action-field and provenance validation
before payload and authorization fingerprinting. The exact validated source
tuple drives payload trust, policy, approvals, evidence, and the authorization
hash. Mutation after construction cannot bypass the existing provenance count
or aggregate-text ceilings.

Existing error classes and stable aliases are preserved:

- `request_allowed_tools` for request allowlist count;
- `request_provenance_refs` for request input count;
- `action_provenance_refs` for action source count;
- `request_text_item` and `request_text_characters`; and
- `provenance_text_item` and `action_provenance_text_characters`.

Rejected content is not included in error text. No policy decision, approval,
reservation, evidence claim, grant, or tool execution follows a failed owning
snapshot.

## Read-only projection

Command Core schema `0.73.0` reports
`validated_contract_collection_snapshots: true`. Command Center renders only
this static posture. It cannot submit or alter a request, provenance, limit,
approval, reconciliation, policy, or execution.

## Limits of the control

This control makes one bounded collection observation authoritative; it is not
general thread isolation or an operating-system sandbox. Content provenance is
still only as truthful as the adapter that creates it. Deployment controls
remain responsible for cumulative traffic and process-level containment.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
