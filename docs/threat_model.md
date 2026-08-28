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

v0.11 journals deterministic approval creation, rejection, and expiry before
their first cross-store mutation. Restart recovery recognizes or applies the
exact reservation, approval transition, and evidence record once; conflicting
partial state or a forged payload fails closed and leaves the journal intact.
The journal never claims an external tool outcome. Unknown or stranded external
execution remains on the explicit operator reconciliation path.

v0.12 extends that explicit path to sealed approval-free authorizations. The
operator outcome, identity, note, sealed record id and hash, action, request,
authorization hash, budget exposure, optional signature, and terminal evidence
must agree. Exact retries cannot double charge or duplicate evidence; tampered
markers, signatures, estimates, or terminal records fail closed.

v0.13 persists a returned tool result before its cross-store completion. Exact
settlement, terminal evidence, sealed authorization, and optional approval
consumption must agree. Restart never calls the tool and cannot double debit or
duplicate evidence. A result that was not returned and journaled remains
uncertain and cannot use this deterministic path.

v0.14 closes the concurrent-writer gap around those checks and mutations. One
nonblocking authority transaction lock spans startup recovery and every public
authority-bearing harness entry point. A second thread or process fails before
state or tool mutation. The operating system releases ownership on process
death, while nested operations in the owning thread remain reentrant. Per-file
locks still protect each atomic store write.

### 9. Signed-mode downgrade or unauthorized trust replacement

A process restarts without operator trust pins, or with a different mapping,
and attempts to reinterpret signed-required state as legacy unsigned authority.

v0.10 durably enrolls signed mode and the canonical identity/key-ID mapping on
the first trusted authority startup. Every later authority startup resolves it
before other stores can mutate. Missing or changed pins fail closed. Online
rotation must be strictly additive, is signed by a key from the prior
generation, and binds both generation numbers and mapping hashes. A new key
cannot authorize itself; removal and reassignment have no online command.
Read-only diagnostics expose unverified, mismatched, malformed, and locked
trust state without changing it.

### 10. Unapproved authority-configuration drift

A restarted process changes policy, a tool classification, workspace root,
dry-run posture, or adapter/upstream identity while reusing an established
state directory.

v0.15 durably enrolls the canonical complete authority-profile hash before
operational state recovery. Exact restarts proceed; every other candidate fails
before approval, budget, evidence, journal, or tool mutation unless an operator
staged that exact next hash with identity and a non-empty note. Signed mode
binds the old and new generations and hashes to a currently trusted Ed25519
key. The staged record remains visible through read-only diagnostics, and only
the exact candidate can activate it atomically. This prevents configuration
drift and third-profile substitution. v0.16 additionally binds a verified
operator-declared local artifact bundle when required, but neither control
defeats a privileged host attacker who can replace code and state together.

### 11. Local runtime artifact substitution

The configured MCP command still names the same executable or entrypoint, but
an update, package-manager action, path alias, or attacker has replaced its
bytes before startup.

v0.16 required artifact mode resolves the command to one exact pinned
executable, verifies its SHA-256 digest and every operator-declared support
artifact, canonicalizes the manifest independent of input order, and binds the
bundle hash into the durable authority profile. A mismatch fails before state
enrollment or process creation. A reviewed replacement changes the profile and
must use explicit staged rotation. Defiant verifies the same bundle again
immediately before spawn and records only sanitized assurance for read-only
diagnostics.

This does not discover dependencies or provide code signing, immutable storage,
trusted boot, or a complete answer to time-of-check/time-of-use races. A
privileged host attacker remains outside the boundary.

### 12. Ambient launch-context injection

The executable and declared files are unchanged, but the parent adds
`PYTHONPATH`, `LD_PRELOAD`, `NODE_OPTIONS`, a shell startup hook, a replacement
`PATH`, or a different working directory that redirects runtime behavior.

v0.17 restricted launch mode constructs the child environment from an empty
mapping, admits only declared sources, requires separate acknowledgement for
known loader/path controls, and resolves an explicit canonical cwd outside
harness state. Nonsecret values and cwd identity are bound into the complete
authority profile before spawn. Secret values are required and passed without
entering persisted hashes. Profile mismatch, missing inputs, unsafe undeclared
variables, cwd replacement, or assurance-state contradiction fails closed
before process creation.

This cannot enumerate every runtime-specific control or contain a process after
launch. Immutable dependencies, least privilege, and OS/network sandboxing
remain deployment requirements.

### 13. State-path indirection or root replacement

An attacker or broken deployment replaces a durable JSON/evidence path with a
symlink, reparse point, hard link, pipe, device, or different regular file, or
copies and restores the complete state directory under a new filesystem
identity. Schema validation alone may then inspect bytes other than the store
the operator intended.

v0.18 binds the canonical state-root identity and security posture into the
complete authority profile and records a matching profile-bound observation.
Every known state file and lock must be regular and single-link; POSIX storage
must be current-user-owned and private. Opens compare lstat and fstat identity,
atomic replacement revalidates its source and destination, and orphan temporary
files fail the read-only integrity gate. Contradictions block authority before
operational recovery or a tool side effect.

This is not a defense against a privileged host that can replace the running
harness plus complete state and authority history. Windows ACL evaluation,
encrypted storage, backups, and off-box rollback witnessing remain deployment
controls.

### 14. Governed tools targeting Defiant control state

When `.dah` is nested under the configured workspace, a filesystem tool can
otherwise name approvals, budgets, evidence, trust state, or recovery records
as ordinary agent data. Private modes do not separate two processes running as
the same user.

v0.19 binds the canonical state root into every tool registry as a protected
control-plane root and into the complete authority profile. Workspace-scoped
targets are refused when they enter, alias, or contain protected state.
Resolution follows symlinks, validation repeats inside grant execution, and a
denial is sealed as terminal evidence without forwarding the call upstream.

This depends on an honest operator-authored target contract and does not
sandbox an upstream process that ignores its declared argument or accesses a
broader host mount. Least-privilege filesystem mounts and OS containment remain
deployment controls.

### 15. Workspace-root replacement after authorization

An attacker or broken deployment renames the governed workspace and creates a
different directory at the same path after policy authorization. Path
containment alone would then dispatch an otherwise valid grant into a new
filesystem object.

v0.20 binds the real root's canonical path and device/file identity into the
authority profile and `workspace_integrity.json`. The harness checks it before
new authority work, and the registry checks again immediately before each
workspace-scoped handler or MCP dispatch. Missing, replaced, symlinked,
reparse-point, or non-directory roots fail closed before the grant is spent.
Content beneath the root remains mutable by design.

This does not stop a privileged host from patching the harness, replacing code
and state together, manipulating storage after the final check, or giving an
upstream a broader mount. OS containment and off-box witnessing remain separate
deployment controls.

### 16. Valid evidence-tail truncation or partial restore

Removing the final records from a hash chain leaves the retained prefix
internally valid. Likewise, restoring `evidence.jsonl` without its matching
newer state can erase terminal findings without creating an in-chain hash
failure.

v0.21 checkpoints the fsynced evidence count and head hash in a separate,
profile-bound durable state file. A valid extension beyond an older checkpoint
is recognized as an append crash only when the checkpoint hash is the exact
retained prefix. A shorter chain or any divergent prefix is critical and blocks
authority without automatic repair. Operator-only auxiliary paths cannot
downgrade to uncheckpointed evidence.

This is not an external witness. An attacker able to replace both files with an
older matched pair, or a privileged host able to replace code and complete
state, can evade the local comparison. Off-box signed exports or head
observations remain required for that threat.

### 17. Matched evidence/checkpoint rollback with an external witness

v0.22 can require an Ed25519-signed count and head retained outside `.dah`.
Required mode and trusted key ids are authority-profile inputs. Before profile
activation, Defiant verifies the signature, state-root identity, exact enrolled
profile generation, and witnessed prefix. Restoring an older internally matched
evidence/checkpoint pair is therefore rejected when the newer external witness
is supplied.

The witness is only as current and independent as deployment operations make
it. v0.24 can authority-bind a maximum live-record tail after the witness and
fail closed with a distinct lag diagnostic when that ceiling is crossed. This
bounds stale-witness exposure by record count without claiming trusted time.
It still cannot prove that no later records once existed. Replacing code,
external configuration, trusted keys, and witness storage remains a
privileged-host compromise outside this boundary.

### 18. Undeclared dependency substitution inside a runtime tree

Pinning an interpreter and selected entrypoint does not detect replacement of
an imported module, plugin, native extension, or configuration file omitted
from the selected list. It also does not detect a newly injected file that wins
runtime discovery order.

v0.23 can close operator-declared dependency roots. Every regular file must
appear in a strict relative manifest, every digest must match, and the observed
set must contain no additions or omissions. Links, reparse points, special
entries, overlapping roots, and overlap with mutable harness state fail closed.
The deterministic closure is authority-profile input and is verified again
immediately before process creation.

This control cannot prove that the declared roots are complete. A runtime can
still load code from an unlisted search path, the network, process memory, or a
broader host mount. Restricting those sources requires loader configuration,
least-privilege mounts, immutable images, and OS containment.

### 19. Broad or ambiguous Windows state ACLs

A structurally ordinary state file can still be readable or writable by an
unintended Windows principal. v0.25 can opt into native owner/DACL assurance
for the state root and known files. It requires current-user ownership, a
protected root DACL, current-user full control and child inheritance, and
limits allow ACE trustees to the current user, LocalSystem, and Builtin
Administrators. Foreign allow trustees, NULL DACLs, and unsupported or
ambiguous ACE forms fail closed before authority mutation. The sanitized
posture is bound to the complete authority profile so later omission is drift.

The check is read-only and point-in-time. It does not establish OS containment,
repair permissions, hide state from administrators or LocalSystem, or defeat a
privileged host that can replace the process, token, code, and state together.
Default Windows deployments remain visibly `structural_only` until explicitly
enrolled.

### 20. Ambiguous JSON objects at authority and transport boundaries

Standard JSON decoders commonly accept duplicate object keys and retain the
last value. A reviewed method, decision, status, cost, or target can therefore
differ from the value a runtime interprets. v0.28 uses one strict JSON profile
for durable state, evidence, MCP and HTTP traffic, native-hook inputs, signed
exports, and external witnesses. Duplicate keys at every depth, non-finite
numbers, and non-UTF-8 byte input fail closed before field interpretation.

The parser reports no rejected key, value, or source snippet. This removes
representation ambiguity but cannot establish that a unique document is true,
correctly classified, or produced by an honest upstream.

### 21. Oversized request evidence exports

An offline verifier that reads an entire attacker-supplied export before
checking its size can suffer avoidable memory amplification. v0.29 reads no
more than 64 MiB plus one byte before rejecting an export file, prior to UTF-8
decoding or strict JSON parsing. File/stdout publication and direct in-memory
sign/verify entry points enforce the same fixed ceiling and do not emit partial
documents or content-bearing size diagnostics.

The bound applies to one request-scoped handoff artifact, not the live
append-only evidence chain. It does not provide a CPU quota, streaming
verification, confidentiality, retention, or host containment.

### 22. Excessive JSON structural complexity

A byte-bounded JSON document can still contain deeply nested containers or a
large number of tiny values that amplify decoder recursion, allocations, and
validation work. v0.30 performs a string- and escape-aware lexical scan before
object construction. Input with more than 64 nested containers or 1,000,000
lexical tokens fails closed without reaching `json.loads()` or echoing content.

The scan is not a schema validator, CPU quota, streaming decoder, or process
memory limit. Documents within the structural and byte ceilings still require
the normal strict syntax, duplicate-key, finite-number, authority, and evidence
checks.

### 23. Excessive JSON scalar complexity

A byte-bounded and structurally shallow document can still contain one enormous
integer, fraction, exponent, object key, or string value. Numeric conversion can
consume disproportionate CPU and differs across Python versions; an extreme
finite spelling can also overflow to an infinite runtime float. v0.31 caps each
string token at 8,388,608 source characters and each number token at 1,024
source characters before decoding. Converted floats must remain finite.

Failures are sanitized and reach no authority interpretation or upstream
forwarding. These per-token limits do not replace total byte ceilings, provide
streaming parsing, constrain application-level decoded text, establish a CPU or
memory quota, or contain the host process.

### 24. Unbounded trusted public-key collections

An operator-facing API, CLI, hook environment, corrupted durable policy, or
offline verifier can otherwise supply a very large set of individually valid
key paths. Loading every file, parsing every PEM, computing identifiers, and
constructing verification maps amplifies filesystem, CPU, and memory work
before the requested signature's key is selected.

v0.32 caps one trusted set at 1,024 supplied keys, 65,536 bytes per public-key
PEM, and 8,388,608 aggregate PEM bytes. Count is checked before path or file
work, aggregate size before PEM parsing, and durable operator/witness metadata
uses the same count ceiling. Failure is whole-request and creates no partial
trust or authority.

These bounds do not establish that a key is correctly trusted, distribute
revocation, validate certificates, protect private keys, provide trusted time,
or impose a process-wide CPU/memory quota. Authenticated key distribution and
operator review remain deployment controls.

### 25. Unbounded complete policy complexity

Per-file byte ceilings do not bound the number of policy files, and compact
rules can contain many glob patterns, payload terms, sensitivity labels, or
redactions. Those collections amplify ruleset construction and hashing, then
repeat matcher work for every governed action.

v0.33 caps one complete ruleset at 64 packs, 4,096 rules, 4,096 known-tool
patterns, 4,096 items in one rule list field, and 65,536 rule list items in
aggregate. The pack count is checked before file access; all other counts are
checked before rule construction or ruleset hashing. Registry-provided known
tools participate, and failure creates no partial authority.

The ceilings do not prove policy correctness, impose a wall-clock or process
resource quota, or contain a compromised host. Reviewed rules and OS resource
controls remain necessary.

### 26. Deep or node-heavy authority YAML

Per-document byte limits do not directly bound nesting depth or the number of
small mapping, sequence, key, and value nodes. Without a structural preflight,
PyYAML can recurse or allocate a large constructed graph before policy or MCP
schema validation rejects the document.

v0.34 caps authority YAML at 64 nested mappings/sequences and 100,000 scalar or
collection nodes. Parser events are counted before safe construction. Policy
failure precedes state/workspace initialization; MCP failure precedes upstream
creation. Exact limits pass, failures are sanitized, and aliases remain
refused.

These ceilings do not impose process-wide resource quotas, stream construction,
or establish that accepted authority is correct. The 1 MiB document limit,
complete-policy collection limits, deployment review, and OS controls remain
separate defenses.

### 27. MCP configuration collection amplification

Byte and YAML-node ceilings do not directly limit the number of entries in one
semantically expensive MCP field. Large command vectors, tool maps, header
maps, artifact manifests, dependency pin sets, and launch-environment fields
can amplify validation, path construction, hashing, and startup work. CLI
command overrides also bypass the YAML byte boundary.

v0.35 caps every relevant collection at 4,096 items before element validation
or path construction. It separately caps dependency file pins at 8,192 across
all roots and launch-environment entries at 4,096 across all four fields.
Duplicates count as supplied, failures are sanitized, and no upstream process
or remote session is created after refusal.

These bounds do not validate the correctness of accepted authority, cap the
size or cost of hashing referenced files, impose a process-wide resource
quota, or contain a compromised host. Artifact inventory limits, operator
review, immutable deployment, and OS controls remain separate defenses.

### 28. Aggregate policy text amplification

Per-file byte and complete-ruleset collection ceilings do not bound text
volume across many policy packs. Long glob patterns, payload terms,
descriptions, reasons, scopes, and redactions can amplify normalization,
authority hashing, storage, and repeated matcher work even when every
collection count remains valid.

v0.36 caps each recognized policy text item at 4,096 constructed characters
and all recognized text in one complete ruleset at 8,388,608 characters. The
synthetic registry pack participates, duplicates count as supplied, exact
limits pass, and failures precede rule construction and ruleset hashing without
echoing policy content.

These bounds do not cap governed action payloads or establish a wall-clock
matcher budget, prove policy correctness, or contain a compromised host.
Adversarial policy tests, deployment review, monitoring, and OS resource
controls remain necessary.

### 29. Governed payload substring amplification

A valid action can carry deeply nested, node-heavy, or long payload values.
Before v0.37, every applicable `payload_contains` rule independently flattened
and normalized that payload, multiplying allocation and search work by the
number of rules even though policy authority itself was bounded.

v0.37 constructs one shared searchable view per decision and caps its depth at
64, nodes at 100,000, and normalized text at 1,048,576 characters. Individual
substring tests consume a shared 67,108,864-unit budget. A breach fails closed
as `policy_match_limit`, records sanitized blocked evidence, and never creates
an approval or invokes the tool.

This does not bound tool/target glob work, process-wide resources, or a
compromised host. v0.38 adds a separate glob contract and v0.39 adds bounded
action fingerprints; process controls remain deployment concerns.

### 30. Policy glob subject and work amplification

An action controls its tool name and target while authority can contain many
bounded glob patterns. Before v0.38, known-tool classification and rule
tool/target matching had no shared work budget. v0.37 also evaluated rule
tool/target prefixes once to discover payload matching and again during final
rule evaluation.

v0.38 caps tool-name glob subjects at 4,096 characters and target subjects at
1,048,576. Known-tool and rule comparisons share 67,108,864 deterministic work
units, charged as subject length plus pattern length per attempted comparison.
Checks remain ordered and short-circuit on the first match. A breach fails
closed as `policy_match_limit`, adds no approval or execution, and omits the
glob subject from its diagnostic inputs.

The budget approximates search work rather than measuring CPU. v0.39 separately
bounds action fingerprints; non-glob context comparisons, process-wide
resources, and a compromised host remain outside this control.

## What we do not defend against

Stated plainly, because a buyer will find these anyway and it is better they hear them from us.

**A compromised host.** Anyone with root on the machine can edit the evidence file, replace the policy pack, or patch the registry. The chain makes tampering detectable to someone who has an off-box copy of a later hash; it does not make it impossible. Off-box replication belongs to Command.

**Rollback after the supplied witness.** A finite v0.24 lag ceiling limits how
far the live chain may advance beyond the independently retained witness before
authority stops. It does not prove that later records never existed, provide a
trusted clock, or transport/refresh witnesses automatically. Without a
configured ceiling, v0.22-compatible valid tails remain unbounded.

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

**Undeclared upstream dependency substitution.** Required v0.16 manifests hash
the executable and declared support files, but Defiant does not discover the
complete runtime dependency tree. An interpreter or executable can still load
undeclared libraries, native extensions, configuration, plugins, or remote
code. Production still needs reviewed lockfiles, locked installations,
immutable image digests, and OS policy.

**Evidence export forgery or alteration.** v0.8 signs the canonical request
export with Ed25519 only after the complete live chain verifies. Verification
requires an independently pinned public key and rejects payload, signer, note,
timestamp, schema, signature, or key-id tampering. The export cannot appoint its
own trust key. v0.29 also refuses exports beyond the fixed 64 MiB ceiling before
file parsing or cryptographic verification.

**Signing-key theft.** Encryption protects a private-key file at rest, not while
an authorized signer is using it. A stolen private key can produce valid
signatures. Keep the key and passphrase outside `.dah`, separate them where
practical, rotate after compromise, and distribute revocation through the
organization's trust process. Defiant does not backdate-proof signatures or
provide trusted hardware or certificate identity.

**Forged operator approval or reconciliation.** In v0.9 signed mode, the
authority statement binds the approval, action, request, authorization hash,
purpose, outcome, identity, note, and time. The consuming runtime pins public
keys to operator identities out of band and verifies again before execution or
reconciliation mutation. Changed fields, another approval, a decision reused as
reconciliation, an unsigned legacy record, or a key assigned to another
operator fails closed. A stolen unlocked operator key remains able to authorize
actions as its pinned identity until that key is removed from runtime trust.
Approval decisions, approval reconciliation, and approval-free authorization
reconciliation use separate schemas, purposes, and signing domains, so a valid
attestation for one cannot be replayed as another.

**Trust-state rollback or host compromise.** Durable enrollment prevents an
accidental or configuration-only downgrade; it is not an external witness. A
host administrator who can replace code, state, and external trust pins can
replace the local root or restore an older internally valid generation. Protect
the state directory, keep pins in an authenticated deployment channel, and
retain off-box generation/hash observations when rollback detection is needed.

**Side channels in real-write adapters.** A tool allowed to write into a folder
watched by another publisher creates an indirect outward path and needs its own
policy boundary.

**Model-level exfiltration through allowed channels.** If a rule permits summaries to be emailed, a sufficiently motivated injection can encode data into a summary. Narrower approval scopes and human review reduce this; nothing eliminates it.

**Oversized or amplified parser input.** A tool result, runner event, local
protocol peer, corrupted state file, or hostile configuration can attempt to
force large allocation before schema validation. v0.26 bounds bytes before
JSON, YAML, or SSE parsing at each documented boundary, rejects YAML aliases
and non-finite JSON numbers, and fails closed with sanitized diagnostics. The
limits are per document or evidence record; total evidence history, cumulative
traffic, parser CPU within a permitted document, and process-wide memory still
require deployment monitoring and OS resource controls.

**Oversized or repeatedly hashed action input.** v0.39 validates action hash
structure and scalars before canonical encoding, streams a maximum of 64 MiB
per fingerprint into SHA-256, and reuses one detached, sealed fingerprint
snapshot through policy, approval, and evidence. Capability spend performs one
fresh bounded authorization hash so a nested post-seal mutation is refused.
Input that cannot be fingerprinted exactly is rejected before authority or
execution; the control does not provide a process-wide CPU or memory quota.

**Oversized or post-construction request input.** Before v0.40, a direct caller
could create or mutate a request with a large task, identifier, allowlist, or
provenance collection and amplify adapter prompting, membership checks, policy
context, or durable snapshots before a later store limit intervened. v0.40
applies fixed item, collection, and aggregate text ceilings at construction,
revalidates at the owning boundary, detaches collections, and seals the request
before proposal. Refusal is sanitized and creates no partial authority. This
does not authenticate identifiers, prove provenance, or impose process-wide
resource quotas.

**Oversized or non-canonical post-execution output.** Before v0.41, a local
handler or direct external-completion caller could return a large, deeply
nested, cyclic, or unsupported value. Unbounded canonical hashing then ran
after the tool may have produced a side effect and could fail before terminal
evidence, budget settlement, or approval consumption. v0.41 applies fixed
summary, depth, node, scalar, and canonical-byte ceilings; revalidates,
detaches, hashes, and seals accepted results; and sanitizes refusal. A refusal
preserves the sealed authorization and reservation for explicit operator
reconciliation instead of fabricating an outcome or replaying the tool. This
does not contain the tool, prove its reported status, or impose process-wide
resource quotas.

**Oversized or mutated pre-adapter tool calls.** Before v0.42, direct/native
callers could construct or later mutate large, deeply nested, cyclic, or
non-canonical `ToolCall` arguments and transport parameters before a bounded
`ProposedAction` existed. An adapter could also rewrite nested call data during
translation. v0.42 validates the complete call at construction and again at
the owning boundary, detaches and seals it before `to_action`, then performs a
fresh bounded hash before any authority work. Refusal is sanitized and creates
no policy decision, approval, reservation, evidence, or execution. This
detects contract drift; it does not sandbox arbitrary trusted Python code or
provide a process-wide resource quota.

**Oversized in-memory canonical numbers.** Strict JSON ingress limits numeric
tokens, but before v0.43 a direct caller could provide a huge Python integer or
a `Decimal` with a large positive exponent. Shared canonical hashing treated
numbers as scalar primitives and could attempt decimal or fixed-point rendering
before the canonical-byte ceiling intervened. v0.43 caps each rendered numeric
token at 1,024 characters, compares integer magnitude without rendering, and
caps decimal coefficient digits and calculates rendered length from tuple
metadata before expansion.
Non-finite floats remain refused. This bounds rendering at Defiant's canonical
boundary, not arithmetic performed earlier or cumulative process resources.

**Canonical JSON string escape expansion.** Strict transport ceilings and the
shared scalar-character ceiling bound source values, but before v0.44 one
8,388,608-character in-memory string could still expand beyond the complete
67,108,864-byte canonical ceiling when `ensure_ascii` emitted paired escapes
for non-BMP code points. The streaming byte counter refused the value only
after Python materialized that expanded token. v0.44 counts the exact canonical
token width without rendering it and fails closed before the encoder. This is
a per-token allocation defense, not a cumulative CPU/memory quota or process
sandbox.

**Aggregate canonical encoding before byte refusal.** Before v0.45, every
individual component of an in-memory mapping or sequence could satisfy its
fixed ceiling while their combined canonical JSON exceeded 67,108,864 bytes.
The streaming counter failed closed, but only after `sort_keys` and encoder
emission began. v0.45 counts the exact complete canonical size during the
bounded structural traversal and refuses an oversized aggregate before sorting
or encoding. The streaming counter remains a second check. This does not remove
sorting work for accepted mappings or impose a cumulative process quota.

**Canonical mapping-sort amplification.** Before v0.46, one mapping could fit
the aggregate node and canonical-byte ceilings while still approaching roughly
half the 1,100,000-node allowance as key/value pairs. Canonical hashing would
then sort that large key set. v0.46 refuses any mapping above 65,536 entries
before visiting its keys or values and before the encoder can sort it. The
existing aggregate node and byte ceilings still apply across nested mappings.
Accepted mappings still sort, and this remains a per-fingerprint control rather
than a CPU timeout or cumulative quota.

**Long canonical key comparison amplification.** The v0.46 entry ceiling still
allowed an accepted value to devote much of its canonical byte allowance to
long keys with shared prefixes, whose text may be inspected across repeated
sort comparisons. v0.47 charges every exact canonical key-token byte once per
idealized logarithmic comparison round against one 67,108,864-unit budget
shared by all mappings. A breach fails before encoder sorting. The cost model
is deterministic and version-stable, not an exact Timsort comparison counter,
wall-clock timeout, or cumulative process quota.

**Late canonical mapping-key incompatibility.** Before v0.48, mixed string and
numeric keys, `None` mixed with another key, and unsupported key objects passed
structural byte/work preflight and reached `sort_keys=True`. The encoder still
failed closed, but only after beginning its sorting/encoding path. v0.48 checks
key eligibility and homogeneous sortable families in a bounded key-only pass
before values or sorting. Existing successful hashes and sanitized owning
contract failures are unchanged. Trusted Python subclasses remain inside the
process trust boundary.

**Late canonical mapping-key token failure.** v0.48 established key-family
eligibility before values, but complete scalar, escaped-token, numeric, byte,
node, and sort-work checks were still interleaved with value traversal. A valid
early key could therefore expose its unsupported or adversarial value before a
later key was rejected as oversized, non-finite, or over budget. v0.49 completes
all key-controlled validation and accounting before the first mapping value is
visited. Accepted canonical bytes and hashes do not change. This remains a
per-fingerprint deterministic control, not a Python sandbox, wall-clock limit,
or cumulative quota.

**Preflight-to-encoder structural drift.** Before v0.50, bounded canonical
preflight validated one traversal of a live caller container and the streaming
encoder traversed that object again. Concurrent mutation or container-subclass
iteration behavior could make the encoded structure differ from the one whose
depth, nodes, mapping entries, keys, bytes, and sort work had passed preflight.
v0.50 builds a detached tree from built-in container storage during the bounded
traversal, resolves mutable Enum values there, and encodes only that snapshot.
Ordinary accepted canonical bytes and hashes remain unchanged. This does not
provide transaction isolation for caller memory or make in-process Python code
untrusted; final capability checks continue to detect later action changes.

**Post-validation ownership copy.** Through v0.50, contract sealing still
performed `deepcopy()` after bounded validation for action payloads,
pre-adapter tool calls, and post-execution tool results. That second traversal
could invoke subclass copy hooks or materialize a structure that had not been
the bounded observation. v0.51 returns the digest with its detached canonical
snapshot and makes each owner retain that exact tree. Ordinary JSON semantics
and accepted hashes are unchanged. This prevents an owner-induced second copy;
it does not sandbox arbitrary Python already running in the harness process.

**Validate-to-detach collection drift.** Through v0.51, governed request
allowlists and inputs were validated through their live iterable view and then
converted to tuples in a later traversal. Action provenance was initially
validated the same way and later copied from built-in storage without repeating
its dedicated limits. A list subclass or validation-time mutation could make
the owned collection differ from the validated view. v0.52 captures built-in
list storage first, validates that exact bounded tuple, and adopts it directly.
This is deterministic contract ownership, not general thread isolation.

**Scalar-subclass behavior after validation.** Through v0.52, validated
snapshots detached built-in containers but could retain subclasses of accepted
strings, integers, floats, decimals, and mapping keys. Caller-defined hashing,
comparison, formatting, numeric conversion, or copy hooks could therefore run
after validation during registry lookup, durable snapshotting, or evidence
work. v0.53 normalizes accepted scalars to exact built-ins before hashing and
ownership, and refuses keys that collide after normalization. This does not
sandbox arbitrary Python already executing inside the harness process.

**Caller-owned authority records after action validation.** Through v0.53,
policy decisions, capability grants, and evidence records remained separate
construction boundaries that could retain scalar or container subclasses.
Later HMAC claims, `asdict()` traversal, evidence hashing, and serialization
could invoke their hooks even though the action contract itself was safe.
v0.54 repeats bounded normalization at each authority-record use and owns the
exact built-in decision/evidence snapshots. Invalid post-execution evidence
still leaves the uncertain authorization on explicit reconciliation; it is not
converted into a fabricated terminal outcome. This remains an in-process data
contract, not an operating-system sandbox.

**Caller-owned policy configuration after ruleset hashing.** Through v0.54,
`PolicyEngine` hashed policy rules and authority inputs once but retained
caller-owned nested mappings and lists. A later caller mutation could change
rule matching or decision inputs while the published `ruleset_hash` remained
unchanged. v0.55 captures a bounded canonical built-in snapshot first and
constructs both engine state and the hash from that observation. Directly
modifying engine-owned memory still requires already-trusted in-process Python;
this control is an ownership boundary, not thread isolation or an OS sandbox.

**Mutable engine-owned policy state after ruleset hashing.** v0.55 detached
caller-owned configuration, but the public engine still exposed mutable rule
objects, pattern lists, known-tool lists, and its retained authority mapping. A
trusted integration bug could alter future enforcement through those public
references without changing `ruleset_hash`. v0.56 freezes rules and pattern
collections, publishes policy identity through read-only properties, and
returns a fresh built-in authority projection instead of the frozen internal
tree. Private Python object mutation remains inside the trusted process
boundary; this is not protection against malicious code already executing in
the harness process.

**Live policy context observed more than once.** Through v0.56, policy rules
could read a caller-owned context mapping and decision construction could
traverse it again. Mapping overrides or mutation could therefore make the
evidence describe a different observation from the one used for matching, and
value rendering could invoke caller hooks. v0.57 captures bounded exact string
metadata once from built-in dictionary storage and uses that owned snapshot for
both operations. Invalid context blocks with sanitized metadata before
matching. This remains an in-process data contract, not thread transaction
isolation or a Python sandbox.

**Operation-journal copy drift and asymmetric size limits.** Through v0.57,
prepared and loaded crash operations were deep-copied around validation and
hashing, retained a publicly mutable nested payload, and could be written under
the broader durable-state limit even though recovery refused journals above
4 MiB. Copy hooks, later mutation, or an interrupted oversized operation could
therefore make recovery diverge from the accepted observation. v0.58 captures
and hashes one bounded canonical snapshot, seals the private retained tree, and
enforces the 4 MiB ceiling on both publication and recovery reads. It does not
infer an unknown external outcome or make trusted in-process Python untrusted.

**Native-hook event observation drift.** Through v0.58, the native hook gate
read one caller-owned event repeatedly while deriving its execution key,
target, governed payload, and completion input, and deep-copied tool arguments
before the `ToolCall` ownership boundary. In-process mapping or copy hooks, or
mutation between observations, could therefore make retry correlation describe
a different call than the one submitted for authorization. v0.59 captures one
bounded canonical built-in event snapshot at every public gate and adapter
entry and derives every downstream value from it. The CLI still bounds and
strictly parses raw JSON first. This closes an in-process ownership and
translation gap; it does not contain direct activity that emits no hook event,
change documented runner timeout behavior, or make trusted process code
untrusted.

**Mutable or unrecoverable authority-continuity state.** Through v0.59, frozen
authority-profile and operator-trust dataclasses retained mutable nested
bindings, transitions, and attestations, and returned those live objects from
their public projections. A caller could change later verification or
publication beneath an already validated state instance. Their writers also
used the broad durable JSON ceiling despite 1 MiB recovery-read limits, so a
long valid rotation history could be published successfully and then rejected
on restart. v0.60 validates one fixed-profile snapshot, recursively freezes the
retained tree, returns only detached projections, and applies each 1 MiB limit
to capture, publication, and recovery reads. This protects state-object
ownership and recoverability; it does not make already-trusted process code or
a privileged host untrusted.

**Mutable native-hook correlation after authorization.** Through v0.60,
`HookExecution` retained public action, request, and decision dictionaries and
changed completion fields in place. Dataclass serialization could traverse
those values again, allowing an in-process caller mutation or subclass hook to
make durable completion correlation differ from the accepted authorization
context. v0.61 captures one bounded canonical record, revalidates governed
snapshots from that observation, recursively freezes retained trees, and uses
copy-on-write completion. The established 64 MiB store limit now applies to
capture, recovery, and atomic publication. This does not create OS containment,
guarantee that a runner emits `PostToolUse`, or infer an unknown outcome.

**Mutable approval records after authority capture.** Through v0.61,
`PendingApproval` retained public policy, held action/request/decision, and
operator-attestation containers, changed lifecycle fields in place, and relied
on dataclass traversal for persistence. A caller mutation or container-subclass
hook could therefore make later validation, execution, reconciliation, or
publication observe authority different from the accepted record. v0.62
captures one bounded canonical record, reconstructs and binds governed
snapshots from that observation, recursively freezes retained trees, returns
only detached projections, and advances lifecycle state copy-on-write. The
complete store is key-bound and symmetrically limited for capture, read, and
write. This does not decide whether an uncertain external action ran, release a
stranded reservation optimistically, make trusted in-process Python untrusted,
or turn Command Center into an authority surface.

**Ambiguous authority YAML.** YAML normally permits aliases and many loaders
silently accept duplicate keys using last-key-wins semantics. A malicious or
mistaken pack could therefore show a reviewer one apparent policy while the
parser applies another. v0.27 uses one bounded strict safe-loader for policy
packs and MCP configuration, rejects aliases and duplicate mapping keys at any
depth, and refuses unknown top-level policy fields before authority or an
upstream process is created. This does not prove that a syntactically clear
policy expresses the operator's intended business rule; review and tests remain
deployment controls.

## Assumptions

- The operator running the harness is trusted; there is no privilege
  separation between operator and harness in v0.3.
- Python code already executing inside the harness process is trusted. Grants
  are not an OS sandbox.
- Policy files are under operator control and not writable by the agent.
- The evidence file is on storage the agent cannot write to directly.
- Evidence-export private keys and passphrases are outside agent-writable and
  harness state paths; trusted public keys reach verifiers through an
  authenticated out-of-band channel.
- Operator private keys and passphrases are outside agent-writable and harness
  state paths. Runtime trust pins are distributed through an authenticated
  operator channel and are not writable by the governed agent.
- The local state directory is access-controlled; durable approvals retain held
  payloads there.
- In a work directory that has never enrolled operator trust, legacy
  `approved_by` and `reconciled_by` values remain assertions. Production
  runtimes enroll signed mode; after enrollment, missing pins fail closed.
