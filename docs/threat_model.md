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
