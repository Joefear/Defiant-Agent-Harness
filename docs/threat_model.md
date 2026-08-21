# Threat model

The harness assumes the agent is capable, useful, and completely untrustworthy as a source of authority. Not because models are bad, but because the failure modes below do not require the model to be bad.

## What we defend against

### 1. Indirect prompt injection

Untrusted content the agent reads — a web page, an inbound email, a PDF, a third-party MCP result — contains instructions, and the agent follows them.

This is the failure mode behind most "always-on agents are insecure" complaints, and it is not fixable at the prompt layer, because the agent cannot reliably distinguish instructions it was given from instructions it read. Defence is authorization, not detection: content is tagged at ingestion, taint propagates to anything derived from it, and policy refuses outbound actions carrying untrusted payloads.

Result: the agent can read the poisoned page, summarize it, and reason about it. It cannot make that page cause an email to be sent.

Covered by `test_injected_exfiltration_is_blocked`, `test_injected_publish_is_blocked`, `test_untrusted_content_cannot_drive_an_outbound_send`, and — importantly — `test_untrusted_content_can_still_be_read_and_summarized`, which asserts the defence does not break the actual use case.

### 2. Payload substitution after authorization

An action is approved, then a different payload is executed under that approval. The classic confused-deputy attack, and the one that turns an audit log into an alibi.

Both the approval and capability grant bind to `authorization_hash`, which
covers the tool, target, payload, provenance, request, side-effect level, and
cost estimate. Changing the body, recipient, target, or trust inputs voids the
authority. Covered by the payload and target substitution tests.

### 3. Gate bypass

Code — human-written or agent-generated — reaches a tool without going through the decision path.

Tool callables are private to the registry; `execute()` demands a valid
registry-signed grant; and issuance requires a sealed, execution-pending
authorization record. Unsigned, mutated, blocked-evidence, and cross-registry
grants are refused. Covered by `tests/test_capability_gate.py`.

### 4. Grant or approval replay

An old authorization is reused for a new action.

Grants and approvals are both single-use, and approvals expire. Covered by `test_grant_is_single_use`, `test_approval_is_single_use`, `test_approval_cannot_be_replayed`, `test_expired_approval_cannot_be_granted`.

### 5. Evidence tampering

Someone edits, deletes, or reorders records to hide what happened.

Hash chaining makes all three detectable, and `verify()` names the failing index and the failure mode. Covered by the alter, delete, and reorder tests in `test_evidence_store.py`.

The writer also fails closed: malformed JSON or a broken existing chain prevents
new evidence from being appended and therefore prevents controlled execution.

### 6. Scope escalation

The agent uses a tool the request never authorized, or one nobody classified.

`allowed_tools` narrows per request. The registry rejects unknown tools,
adapter attempts to downgrade side effects, absolute paths, traversal, drive
paths, and UNC paths before policy can authorize them. Policy then refuses
undeclared tools.

### 7. Runaway spend

The agent loops, retries, or calls a paid endpoint repeatedly.

Preflight uses exact decimals. Reservations are action- and request-bound,
negative/non-finite values are rejected, duplicate reservations fail, and
settlement requires the original reservation.

Crash-stranded executions never replay automatically. Reconciliation requires
an explicit outcome, operator identity, and note. Confirmed or possibly
attempted executions consume the full reservation when actual cost is unknown;
only an explicit `not_executed` outcome releases it. Exact retries are
idempotent, while a changed outcome, identity, or note is rejected.

### 8. Divergent or partially corrupted local state

A crash, concurrent writer, or manual edit leaves evidence, approval, and
budget files individually readable but mutually contradictory.

v0.7 audits the complete evidence chain and cross-store authority bindings
before new execution, resume, completion, or reconciliation. Orphan or mismatched
reservations, terminal reservation leaks, absent consumed evidence, conflicting
reconciliation markers, malformed stores, and live lock files fail closed.
Expected crash windows remain visible as recovery-required warnings. The doctor,
Command Core, and Command Center paths are read-only and remain available for
sanitized diagnosis.

## What we do not defend against

Stated plainly, because a buyer will find these anyway and it is better they hear them from us.

**A compromised host.** Anyone with root on the machine can edit the evidence file, replace the policy pack, or patch the registry. The chain makes tampering detectable to someone who has an off-box copy of a later hash; it does not make it impossible. Off-box replication belongs to Command.

**Truncation of the tail.** Deleting the last N records leaves a valid chain. Only an external witness — a periodic hash pushed off-box — detects it.

**Paraphrase around deterministic phrase rules.** `merchant_services.yaml` catches the listed phrasings and nothing else. This is a floor, deliberately auditable, not a claim of completeness. A model-based reviewer layered above it is future work; it must never replace the floor.

**Bad provenance from an adapter.** An adapter that marks external input trusted
disables the injection defence for that input. Missing provenance defaults to
`DERIVED`, but incorrect positive claims remain a trusted-adapter defect. Every
real adapter requires adversarial provenance tests.

**The agent being wrong.** The harness controls what an agent may *do*. It does not make the agent's output correct. Human review at the approval gate is the only control on quality, which is why approval scope is recorded per rule and shown to the reviewer verbatim.

**Actions outside the proxy.** v0.3 governs MCP calls routed through its local
stdio proxy, whether the configured upstream uses stdio or Streamable HTTP.
The preview `PreToolUse` adapter additionally governs supported native VS Code
and Copilot CLI tool events. Direct process or network activity that emits no
event, a direct connection to the upstream server, and the platform's
documented fail-open hook-timeout path still require OS/network containment.

**Misclassified upstream tools.** The operator-authored MCP map is trusted
configuration. If a mutating tool is classified as `none`, the registry has no
independent way to discover the lie. Tool-map review is a deployment control.

**Upstream binary substitution.** The proxy binds approvals to the configured
command vector, but does not hash or attest the executable and its dependency
tree. A package name and version are stronger than `latest`, but a production
install still needs a reviewed lockfile, immutable image digest, or equivalent
artifact verification.

**Side channels in real-write adapters.** A tool allowed to write into a folder
watched by another publisher creates an indirect outward path and needs its own
policy boundary.

**Model-level exfiltration through allowed channels.** If a rule permits summaries to be emailed, a sufficiently motivated injection can encode data into a summary. Narrower approval scopes and human review reduce this; nothing eliminates it.

## Assumptions

- The operator running the harness is trusted; there is no privilege
  separation between operator and harness in v0.3.
- Python code already executing inside the harness process is trusted. Grants
  are not an OS sandbox.
- Policy files are under operator control and not writable by the agent.
- The evidence file is on storage the agent cannot write to directly.
- The local state directory is access-controlled; durable approvals retain held
  payloads there.
- `approved_by` is an assertion by the CLI caller. Real identity binding is a later arc.
