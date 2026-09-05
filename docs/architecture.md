# Architecture

## The one rule

No side-effecting tool action executes unless it passed the policy decision path and produced an evidence record first.

Everything below is in service of making that rule true in a way that survives contact with a real codebase, a real contributor, and a code-generating agent working inside this repository.

## Why the gate is a capability, not a check

A policy check is a line of code someone can route around. Three ways it happens, none of them malicious:

- a developer adds a fast path for a tool that "obviously doesn't need review";
- a test helper calls the tool directly and the helper leaks into production;
- a code-generating agent, asked to add a feature, imports the tool function because that is the shortest path to a passing test.

So tool callables are held privately inside `ToolRegistry` and the execution
path is `execute(action, grant)`. Before execution, the registry validates the
adapter's claims against authoritative `ToolSpec` metadata. The grant is a
`CapabilityGrant` that:

- is signed by the registry only after the control loop presents a sealed
  authorization record;
- names one action, tool, and evidence record;
- binds the target, payload, provenance, request, side-effect classification,
  and cost estimate through `authorization_hash`;
- is single-use, and raises on replay;
- refuses if any authorization-relevant input differs from what was authorized.

That last property is the confused-deputy defence. Without it, an approved
message could be exchanged for wire instructions, or its recipient could be
changed after approval. Payload and target substitution both have regression
tests.

This is an in-process control boundary, not privilege separation. Code already
running inside the harness process is trusted; OS sandboxing is future
deployment work.

## Order of operations

```
classify -> policy decide -> budget preflight -> reserve
         -> WRITE EVIDENCE -> mint grant -> execute -> settle -> WRITE EVIDENCE
```

Evidence is written before execution. A crash between the grant and the tool call therefore leaves a record saying an action was authorized and its outcome is unknown — which is the honest state, and one an operator can investigate. The reverse order would allow an action to execute and leave no trace, which is the single failure this product cannot have.

Blocked, rejected, and expired actions produce evidence too. "Nothing happened" is a finding, and in a compliance conversation it is usually the finding the customer most wants proof of.

Pending approvals persist the complete action, request, and decision snapshot.
They resume after a new process starts, but only if the loaded ruleset hash is
identical. A policy change voids the stale approval and requires re-proposal.
For MCP stdio, the first call returns a pending handle. Approval records the
human decision without executing in the CLI process; an exact-call retry through
the proxy owns execution. This prevents the approval CLI from impersonating an
upstream connection it does not control.

## Trust and provenance

`Trust` has three values and one propagation rule.

- `TRUSTED` — operator-authored, or approved knowledge under operator control.
- `UNTRUSTED` — anything read from the outside world: web pages, inbound email, third-party MCP results, downloaded files.
- `DERIVED` — produced by the agent from a mix.

The rule is that trust is contagious downward: any untrusted input taints
everything derived from it (`worst_trust`). An adapter that cannot prove
provenance must return `DERIVED`, never `TRUSTED`. An action with no provenance
also defaults to `DERIVED`.

Policy can then gate on `max_payload_trust`. The default pack refuses any action at or above `external_send` whose payload trust is worse than `derived`. The agent may read the untrusted thing, reason about it, and summarize it; it simply cannot make that content cause an effect outside the workspace without a human.

This is the mechanical form of the Defiant invariant that knowledge can inform execution but cannot authorize it, and it is a strictly stronger position than "we told the model to be careful."

## Determinism

The policy engine performs no model call, no network access, and no clock-dependent branching outside explicit approval expiry. Same action plus same ruleset yields the same decision, always — asserted 50 times over in `test_engine_is_deterministic`.

That matters commercially, not just technically. A consultant can tell a client exactly what will be blocked, and a compliance reviewer can read the YAML instead of trusting a model's judgement. The prohibited-claim rules in `merchant_services.yaml` are deterministic string matches for precisely this reason: their weakness (they can be paraphrased around) is visible and auditable, where a model-based classifier's weakness would not be.

The tradeoff is stated plainly rather than hidden: deterministic matching catches the exact phrasings listed and nothing else. It is a floor, not a ceiling. A model-based reviewer belongs later, layered above this floor, never replacing it.

## Default deny, twice

1. The registry refuses unknown tools, path escapes, and any adapter-side
   classification that disagrees with authoritative `ToolSpec` metadata.
2. A tool not declared in any loaded pack's `known_tools` is refused before
   rules are consulted.
3. Among classified tools, anything with a side effect and no matching rule is
   blocked; anything with no side effect and no matching rule is allowed.

Rule order is not load-bearing: every matching rule is evaluated and the strictest outcome wins, so a permissive rule cannot be positioned to shadow a restrictive one.

## Budgets, honestly

You cannot reliably predict what an agent turn will cost before it runs, so the harness does not pretend to. What it does instead is enforceable:

- a persisted exact-decimal balance;
- a preflight check against the **worst-case** estimate, not the expected case;
- a reservation bound to one request and action id, reducing available balance
  immediately;
- a hard debit of actual cost after execution;
- a release when an action is blocked, rejected, or expires;
- `drift()`, which reports the gap between estimates and actuals rather than hiding it.

An in-flight overrun cannot be prevented. It is always visible, and it reduces the next action's headroom immediately. Say this to a technical buyer before they ask.

## MCP transport boundary in v0.3

The proxy launches one upstream command without a shell. Its stdout is reserved
for newline-delimited MCP messages. Initialization, discovery, notifications,
and non-tool requests pass through. `tools/call` is translated to a harness
action; allowed calls use a private upstream request id and the original
upstream result or JSON-RPC error is restored under the client's request id with
`_defiant` evidence metadata.

Protocol negotiation is capped at `2025-06-18`. The `2025-11-25` task
augmentation is intentionally not advertised until task creation, durable
status, cancellation, and result retrieval can all share the same authority and
evidence model.

The Streamable HTTP upstream preserves that same stdio-facing boundary for the
runner while sending one JSON-RPC message per HTTP POST to a configured remote
endpoint. It supports JSON and finite SSE responses, optional MCP session ids,
and session DELETE on shutdown. Remote authentication values are loaded from
environment variables. See `streamable_http.md`.

## Command read boundary in v0.5

Command Core is a one-way, read-only projection over evidence, approvals, and
budget state. It verifies the complete evidence chain before calculating any
evidence-derived aggregate. A broken chain produces a visible integrity alert
but no evidence totals or recent activity, preventing altered records from
silently becoming dashboard truth.

The snapshot excludes targets, payload previews, decision inputs, and raw tool
results. It has no execution, approval, policy, or mutation API.

Command Center consumes that snapshot through a loopback-only HTTP server. The
server is fixed to `127.0.0.1`, accepts only bounded read query parameters, and
implements no mutating HTTP methods. Refresh and request filtering generate a
new projection; they do not modify harness state. The packaged browser UI has
no execution or approval controls and no external runtime dependencies. See
`command_core.md` and `command_center.md`.

Configured tool specs extend `known_tools` for that registry instance, and the
extension participates in the ruleset hash. Side effect, conservative cost,
dry-run support, target scope, workspace root, and the hashed upstream command
identity participate too. A changed authority contract therefore voids a stale
approval instead of silently changing what it means. This is safe only because
the same operator-authored mapping supplies the authoritative metadata. An
advertised but unmapped tool fails both request scope and registry checks.

`examples/filesystem` proves the boundary against the official MCP filesystem
reference server. In that integration, Defiant validates each mapped path
against its configured workspace and the upstream server independently applies
its own allowed-directory boundary. The example intentionally leaves the
multi-target `read_multiple_files` and `move_file` tools unmapped until the
registry can validate every member of a target collection.

The boundary is transport control, not containment. It says nothing about
native tools, direct HTTP, subprocesses, filesystem access outside an MCP
server, or a runner that connects directly to the upstream server.

## Crash recovery boundary in v0.6

An approval moves to `executing` before a governed tool can run. If the process
dies after that write, Defiant cannot distinguish "never dispatched" from
"completed but not recorded" and continues to refuse automatic replay.

The v0.6 operator reconciliation path is a separate CLI mutation, not a Command
Center feature. It first validates any terminal evidence already written, then
durably binds an explicit outcome, operator identity, and non-empty note to the
approval. Budget reconciliation, evidence append, and final consumption each
have an idempotent durable marker or lookup. Repeating the exact command after a
crash completes remaining steps; changing the story is refused.

When actual cost is unknown, `succeeded` and `failed` charge the full durable
reservation. Only `not_executed` releases a live reservation. A missing
reservation with no prior debit is charged at the approval estimate rather than
silently treated as free. See `approval_reconciliation.md`.

## State integrity boundary in v0.7

The three durable stores are individually atomic but do not form one database
transaction. v0.7 therefore audits their shared authority bindings before each
authority-bearing harness entry point. Evidence must be intact; approval ids,
action snapshots, requests, reservations, terminal records, and reconciliation
markers must agree; terminal approvals cannot retain reservations; and a store
lock stops new authority.

The auditor explicitly models valid crash windows. An `executing` approval or a
sealed unfinished external authorization is recovery-required, not corrupt.
Critical contradictions raise `StateIntegrityError` before new evidence, budget,
approval, or tool mutation. `dah doctor`, Command Core, and Command Center read
the same sanitized audit contract without creating or repairing state. See
`state_integrity.md`.

## Evidence authenticity boundary in v0.8

The live JSONL chain remains the local system of record. v0.8 adds a separate,
operator-invoked export attestation rather than introducing a private key into
the runtime authority path. A request export binds its selected records to the
verified full-chain count and head hash. Ed25519 signs a domain-separated
statement containing the canonical payload hash, signing time, public-key
identifier, asserted signer identity, and required note.

Private keys are encrypted and supplied from outside `.dah`. Verifiers accept
only explicitly pinned public keys received out of band; the export cannot
appoint its own trust root. Repeated trust-key arguments support planned key
rotation while old public keys remain usable for historical verification. This
proves that the holder of a pinned key signed one exact export. It does not
provide certificate identity, trusted time, hardware-backed custody, automatic
revocation, or proof that no later chain tail was removed. See
`evidence_signing.md`.

## Operator authority boundary in v0.9

An approval string is not authority when signed mode is configured. The
operator CLI creates a domain-separated Ed25519 attestation over the approval,
action, request, authorization hash, explicit outcome, operator identity,
required note, and timestamp. The approval store verifies it against an
out-of-band identity-to-public-key mapping before changing state. Execution
verifies the persisted decision again immediately before consuming authority.

Crash reconciliation has a distinct signature purpose, so an ordinary approval
cannot be replayed as a terminal outcome. Verification occurs before budget or
evidence mutation. MCP proxies receive public trust pins at startup; native
hooks receive the same pins through a JSON environment setting. Private keys
and passphrases exist only in the operator decision process and must remain
outside harness state. See `operator_identity.md`.

## Durable operator trust boundary in v0.10

Signed mode is a persistent property of a work directory after its first
trusted authority startup. `operator_trust.json` records a canonical hash of
the enrolled identity/key-ID mapping. Authority construction resolves this
store before evidence, approval, budget, or tool objects can mutate state.
Missing pins or a mapping mismatch therefore stop startup instead of falling
back to legacy unsigned authority.

Trust changes form a generation chain. Each online transition is
domain-separated, signed by a key present in the prior generation, and binds
the prior and next mapping hashes, operator identity, required note, and time.
Only strict additions are accepted. Key removal and reassignment require an
offline, separately governed compromise procedure; the runtime supplies no
force or reset path.

State integrity audits the complete mapping and signature chain. Diagnostic
processes may read external public pins to verify it, but `dah doctor`, Command
Core, and Command Center never enroll, rotate, repair, or receive private-key
material. Their projection contains generation, counts, mapping hash, and
verification status only.

## Crash-safe local operation boundary in v0.11

Approval creation, rejection, and expiry each update more than one local store.
v0.11 prepares those deterministic transitions in a single-operation journal
before changing approvals, reservations, or evidence. Recovery reapplies or
recognizes each exact step idempotently and clears the journal only after all
prepared state is durable. A mismatch fails closed and preserves the journal
for investigation.

This is intentionally not a general transaction engine. The journal contains
only local outcomes that the harness already knows. It cannot replay an
external tool or infer whether one succeeded. An approval stranded in
`executing` remains subject to explicit operator reconciliation with an
outcome, identity, and note. Doctor, Command Core, and Command Center expose
only sanitized journal metadata and never recover, repair, or clear it.

## Approval-free recovery boundary in v0.12

A sealed execution authorization can exist without an approval when policy
allowed the action directly. If the process stops before terminal evidence, the
authorization proves permission but not whether the tool ran. v0.12 gives this
state an explicit operator path keyed by the sealed evidence record rather than
inventing an approval.

The operator must assert `succeeded`, `failed`, or `not_executed` with identity
and a non-empty note. Signed mode uses a separate Ed25519 domain bound to the
authorization record id and hash, action, request, and authorization hash. The
operation journal makes the resulting budget marker and terminal evidence
idempotent across crashes. A prior debit is preserved; otherwise possible
execution consumes the durable estimate and only positive `not_executed`
evidence releases it.

This path does not replay tools, discover provider truth, or apply to an action
owned by an approval. Doctor, Command Core, and Command Center expose sanitized
recovery metadata, but the dashboard remains read-only.

## Known-result completion boundary in v0.13

After a tool returns, the external outcome is no longer uncertain, but budget,
terminal evidence, and approval consumption are still separate durable stores.
v0.13 prepares their exact completion in the local operation journal before the
first of those mutations. Restart verifies the sealed authorization and then
recognizes or applies settlement, evidence, and consumption once without
invoking the tool.

The journal contains terminal evidence metadata and an output hash, not the raw
tool response. A reported positive cost is preserved; otherwise a non-dry-run
attempt with reserved exposure settles at that conservative estimate. Valid
known-result recovery is shown separately from manual reconciliation in doctor,
Command Core, and Command Center. The dashboard remains read-only.

## Native agent hook boundary (Preview)

The workspace `PreToolUse` hook covers supported native VS Code and Copilot CLI
tools that do not cross MCP. It translates the complete native tool input into
a bound action, returns a deterministic allow or deny decision, and uses the
same durable exact-call approval model. Allowed pre-events create only an
execution-pending authorization record. A correlated `PostToolUse` event seals
the successful external result and consumes any approval.

The hook policy blocks terminal, subagent, unknown, path-escape, and trusted
enforcement-file mutation attempts. Missing post-events never become guessed
successes. See `native_hooks.md`.

## Authority serialization in v0.14

Per-file locks prevent simultaneous writes to one JSON file, but they cannot by
themselves make an audit-authorize-execute-settle sequence exclusive across the
whole state directory. v0.14 adds `authority.lock`, an operating-system byte
lock held across each authority-bearing entry point and startup recovery.
Contention fails immediately before state or tool mutation. Nested calls in the
same thread are reentrant, while other threads and processes are refused.

The file remains present, but lock ownership is maintained by the operating
system. A process crash closes its descriptor and releases authority without an
operator deleting a stale PID file. The existing per-store `.lock` files remain
conservative atomic-write sentinels and retain their existing stale-lock rule.
Read-only doctor, Command Core, and Command Center paths never acquire or mutate
the authority lock.

## Authority-profile continuity in v0.15

The policy ruleset hash is also the complete runtime authority-profile hash. It
commits to normalized rules and known tools plus the authoritative tool
contracts, workspace-root hash, dry-run posture, and adapter/upstream authority
inputs. `build_harness` resolves this hash under `authority.lock` before
operational-store construction or recovery.

First startup enrolls generation 1. Exact restarts proceed. Configuration drift
fails closed unless an operator has staged the exact next hash with identity and
a non-empty note; signed operator mode additionally requires a signature from a
currently trusted key. The old generation remains active until the exact
candidate starts, at which point one atomic profile write activates the next
generation. A different candidate cannot consume that authorization.

Operator rejection and uncertain-outcome reconciliation sometimes belong to an
MCP or hook runtime whose full authority inputs cannot be reconstructed by the
CLI. Those terminal-only commands use an execution-disabled harness that
verifies the enrolled profile and cross-store state but cannot run, preflight,
resume, or complete a tool action. Command Center remains a separate read-only
projection and never acquires the authority lock.

## Runtime artifact assurance in v0.16 and v0.23

Required local MCP manifests bind one exact executable plus operator-declared
supporting files to SHA-256 digests. Verification happens before authority
profile resolution. The executable command is rewritten to the verified
absolute path, and the bundle is verified again immediately before process
creation. The normalized bundle assurance is part of the adapter authority
inputs, so an artifact update changes the v0.15 profile and requires its
explicit staged rotation.

The sanitized `runtime_artifacts.json` observation is written under the global
authority lock before operational recovery and is cross-checked against the
active profile by the state auditor. It is a diagnostic projection, not an
allowlist. Command Core and Command Center can report its posture but cannot
edit a manifest, accept a digest, rotate authority, or launch a process.

See `runtime_artifact_integrity.md` for the strict configuration schema,
startup ordering, and limits.

v0.23 extends this boundary with optional complete manifests for declared
dependency roots. The verifier recursively inventories each root without
following links, requires exact file-set equality, hashes every regular file,
and binds the root identities and deterministic observations into the runtime
bundle. Added, removed, modified, linked/reparse, special, overlapping, and
state-overlapping content fails before launch. The same inventory runs again
immediately before the upstream process starts.

The `closed` projection exposes only bundle hash and counts. Command Core and
Command Center do not receive roots, relative filenames, or per-file hashes and
remain unable to mutate configuration or start the process. Closure is limited
to operator-declared roots; OS loader policy and containment remain deployment
boundaries.

## Launch-envelope integrity in v0.17

For local stdio upstreams, an optional strict launch contract starts the child
from an empty environment and admits only operator-declared literals, inherited
variables, and rotatable secrets. Common loader, runtime, path, and shell
variables need a second explicit acknowledgement. Nonsecret effective values,
counts, mode, and an explicit canonical working directory are bound into the
complete authority profile before process creation. Secret values are passed to
the child but excluded from persisted hashes and projections.

The sanitized `launch_envelope.json` observation is written under
`authority.lock` and cross-checked against the active profile. Command Core and
Command Center expose only hashes, counts, and posture; they cannot supply
secrets, edit the environment, acknowledge an unsafe variable, or launch a
process. See `launch_envelope_integrity.md`.

## State-storage integrity in v0.18 and v0.25

All authority-bearing runtimes resolve a canonical, non-indirected state root
before policy construction. Its path/device/file identity hash, platform mode,
private-permission posture, and directory-sync posture enter the complete
authority profile. The matching `state_storage.json` observation is written
under `authority.lock` before operational recovery and cross-checked on every
read-only integrity audit.

The persistence layer refuses symlink, reparse-point, non-regular, and
multi-hard-link state files; compares path and descriptor identities around
each open; creates private files; and validates both sides of atomic replacement
before publishing and syncing the directory entry. POSIX roots/files require
current-user ownership and `0700`/`0600`. Windows remains structural-only by
default. v0.25 optionally requires native owner/DACL inspection: current-user
ownership, a protected root DACL, a bounded current-user/LocalSystem/Builtin
Administrators allow-trustee set, current-user full control, and child
inheritance. Unsupported or ambiguous ACL forms fail closed. This sanitized
policy is authority-profile-bound and rechecked on known state files; Defiant
does not modify ACLs.

Command Core and Command Center expose only the sanitized posture, bounded
hashes, and counts. They cannot repair, move, relink, chmod, accept, or restore
state. See `state_storage_integrity.md`.

## Control-plane path isolation in v0.19

Every registry is bound to the canonical Defiant state root before the policy
hash is computed. A `workspace` or `workspace_path` tool contract cannot name
that root, a descendant, a symlink alias, or a directory scope that contains
it. The same check runs at initial contract validation and inside grant
execution, so a path retargeted after authorization is refused before the tool
handler or MCP upstream receives it.

The sanitized contract hash, workspace hash, protected-root count, and overlap
relationship enter the complete authority profile. A matching
`control_plane_isolation.json` observation is recorded under the authority
lock. Doctor and the read-only Command surfaces can report that posture but
cannot create exceptions or change tool scope. See `control_plane_isolation.md`.

## Workspace-root integrity in v0.20

Authority startup binds the configured workspace's canonical path and
device/file identity into the complete profile and records the sanitized
observation in `workspace_integrity.json`. Final symlink/reparse and
non-directory roots are refused. The state-integrity gate rechecks the root
before every new authority operation, while the registry repeats the check
immediately before any workspace-scoped handler or MCP dispatch and before the
grant is spent.

The root is the boundary, not immutable content: ordinary files and
subdirectories remain editable. Doctor and the Command surfaces can live-check
a supplied root without creating or repairing it and expose no paths or raw
identity. See `workspace_root_integrity.md`.

## Evidence-head integrity in v0.21

Every authority-bound evidence append fsyncs the JSONL record before atomically
advancing a profile-bound count and head hash in `evidence_head.json`. Startup
and the read-only state auditor require the current valid chain to equal or
provably extend that checkpoint. A forward extension is a recoverable append
crash; a shorter or divergent chain is rollback evidence and blocks authority.

Only activation of an explicitly authorized authority-profile transition may
rebind a matching checkpoint to a new profile. Operator-only auxiliary paths
cannot initialize a missing checkpoint. Command surfaces expose sanitized
posture and never advance, accept, or repair it. See
`evidence_head_integrity.md`.

## External evidence-head witnessing in v0.22 and v0.24

An optional signed witness moves the rollback comparison point outside local
harness state. Its trusted key ids and required mode enter the complete
authority profile. Before any candidate profile activates, Defiant verifies the
strict Ed25519 document, its state-root hash, its exact historical profile
generation, and its count/head position in the current valid evidence chain.
A shorter or divergent chain blocks authority; a valid extension is allowed
only while it remains within any v0.24 profile-bound maximum unwitnessed-record
count. Lag is counted from the witnessed head and does not rely on local time.

The external document and public keys are runtime inputs, never copied into
`.dah`. A small profile-bound local policy observation records only mode, key
ids, and the optional maximum so omission or configuration downgrade blocks
later owning and operator-control paths. Diagnostic surfaces verify read-only,
show current/max lag, and withhold paths, signatures, and notes. See
`evidence_head_witness.md`.

## What is deliberately absent from v0.60

- **Automatic witness transport or remote/multi-user Command.** Command Center
  is a local loopback view, not
  a hosted service. It has no authentication, remote ingestion, or identity
  system and must not be exposed as one.
- **DKE / the knowledge engine.** `memory_sources_used` exists in the evidence contract as an empty field so the schema does not change when DKE arrives.
- **Spartan Swarm.** Multi-agent missions need a working single-agent gate first.
- **Complete runner containment.** The preview native hook covers supported
  lifecycle tool events. Direct activity with no event, plus documented
  fail-open hook timeouts, still requires OS/network isolation.
- **Real reference-tool side effects.** The built-ins still simulate writes,
  sends, publishes, exports, deletes, and spends. Proxied upstream tools are
  real and must be classified accordingly.
- **Remote identity administration.** Local operator actions can be bound to
  pinned keys and additive rotations are durably chained. Accounts, roles,
  automatic online removal, remote authentication, certificate identity,
  automatic revocation, and hosted trust distribution remain absent.
- **Automatic state repair.** The auditor detects contradictions and fails
  closed. Repair requires offline investigation or restore from a known-good
  copy; the dashboard has no repair or mutation path.
- **Workspace-root acceptance or repair.** Root replacement requires restoring
  the enrolled root or reviewing an explicit authority-profile transition;
  Command Center cannot accept a new identity.

## Bounded ingestion

v0.26 places fixed byte ceilings before documents cross parser boundaries.
Aggregate durable JSON is read and written through a 64 MiB ceiling; evidence
is binary-line scanned with a 16 MiB ceiling per physical record; MCP stdio
messages, Streamable HTTP responses, and native-hook events are limited to
10 MiB; and MCP YAML configuration is limited to 1 MiB. YAML aliases and JSON
non-finite numbers are refused.

Oversized durable state becomes a sanitized State Integrity failure and blocks
new authority. Oversized live protocol input terminates or denies the affected
operation without echoing the input. The append-only evidence chain has no
aggregate cap: verification cost remains linear in retained history. Command
Core projects the fixed values and Command Center renders them read-only; no
limit editor or ingestion endpoint is introduced. See `bounded_ingestion.md`.

v0.27 applies one `strict_yaml_v1` loader to authority-bearing policy packs and
MCP configuration. It limits each policy pack to 1 MiB, rejects aliases and
duplicate mapping keys at every depth, and rejects unknown top-level pack
fields. This prevents last-key-wins behavior from making machine authority
differ from a human review. Failures occur before state/workspace initialization
or upstream process launch and report no input snippets or absolute paths. Command
Core and Command Center expose only the static profile and limits; neither can
submit or accept configuration. See `authority_configuration_integrity.md`.

v0.28 applies `strict_json_v1` to authority-relevant JSON ingress. Durable
state, evidence records, MCP client and upstream traffic, Streamable HTTP JSON
and SSE data, native-hook events and embedded arguments, operator key lists,
signed exports, and external witnesses reject duplicate keys at every depth,
non-finite numbers, and non-UTF-8 byte input. Durable ambiguity blocks
authority; transport ambiguity is never forwarded; hook ambiguity fails before
state creation. Diagnostics do not echo rejected keys or values. Command Core
and Command Center expose the static posture only. See
`strict_json_integrity.md`.

v0.29 bounds every request-scoped evidence export at 64 MiB. File verification
rejects the document before UTF-8 decoding or JSON parsing, while file/stdout
publication and direct sign/verify entry points enforce the same fixed limit.
Oversized exports are neither truncated nor partially published. The live
append-only evidence history keeps its existing unlimited aggregate and linear
verification behavior. Command Core and Command Center expose only the static
ceiling. See `bounded_evidence_exports.md`.

v0.30 advances the shared JSON profile to `strict_json_v2`. After strict UTF-8
decoding and before object construction, one non-materializing lexical pass caps
container nesting at 64 and lexical tokens at 1,000,000. String and escape state
prevents content punctuation from affecting the count. Input within the fixed
ceilings still passes through the existing syntax, duplicate-key, and
non-finite-number checks. Command Core and Command Center expose only the static
posture. See `json_structural_limits.md`.

v0.31 advances the shared JSON profile to `strict_json_v3`. The lexical pass
also caps each string token at 8,388,608 source characters and each number token
at 1,024 source characters before conversion. Number tokens include sign,
fraction, and exponent syntax; finite-looking floats that convert to infinity
are refused after conversion. This makes scalar processing deterministic across
supported Python releases without changing any byte or structural ceiling.
Command Core and Command Center expose only the static posture. See
`json_scalar_limits.md`.

v0.32 bounds trusted public-key sets before path resolution, file reads, PEM
parsing, key-id calculation, or signature verification. Operator identity,
evidence-export verification, and external witness trust accept at most 1,024
supplied keys, 65,536 bytes per PEM, and 8,388,608 aggregate PEM bytes. Durable
operator and witness trust metadata enforce the same count ceiling. Command
Core and Command Center expose only the static limits. See
`trusted_key_limits.md`.

v0.33 bounds the complete loaded policy ruleset before rule construction,
normalization, hashing, or evaluation. A ruleset may contain at most 64 packs,
4,096 rules, 4,096 known-tool patterns, 4,096 items in one rule list field, and
65,536 rule list items in aggregate. Registry-provided additional known tools
use the same totals. Command Core and Command Center expose only the static
limits. See `policy_complexity_limits.md`.

v0.34 advances authority YAML to `strict_yaml_v2`. Its event-stream preflight
refuses more than 64 nested mappings/sequences or 100,000 scalar/collection
nodes before PyYAML constructs a policy pack or MCP configuration. Exact limits
remain accepted; existing byte, alias, duplicate-key, UTF-8, and safe-loader
controls remain in force. Command Core and Command Center expose only the
static posture. See `yaml_structural_limits.md`.

v0.35 adds an MCP-specific collection preflight after YAML construction and
before element validation, path handling, runtime object construction, hashing,
or startup. Each effective command, header, tool, artifact, dependency-root,
dependency-file, or launch-environment collection is capped at 4,096 items;
dependency pins are capped at 8,192 across roots and launch-environment entries
at 4,096 across fields. CLI command overrides use the same path. Command Core
and Command Center expose only the static ceilings and cannot mutate authority.
See `mcp_configuration_limits.md`.

v0.36 adds complete-ruleset policy text preflight alongside the v0.33
collection checks. Each recognized policy string is capped at 4,096
constructed characters and all recognized policy text across loaded packs,
including the synthetic registry pack, is capped at 8,388,608. It runs before
rule construction, normalization, authority hashing, or action evaluation.
Command Core and Command Center expose only the static limits. See
`policy_text_limits.md`.

v0.37 bounds governed-action payload substring matching. When any loaded rule
uses `payload_contains`, the engine flattens and case-normalizes the payload
once, preserving the existing value-order and separator semantics. The shared
view is capped at 64 levels, 100,000 nodes, and 1,048,576 characters; substring
tests share 67,108,864 deterministic work units across the decision. Any breach
returns a sanitized `policy_match_limit` block through the normal evidence
path. Command Core and Command Center expose only the fixed static posture. See
`policy_payload_matching_limits.md`.

v0.38 gives known-tool classification and every rule one decision-scoped glob
budget. Tool-name subjects are capped at 4,096 characters, target subjects at
1,048,576, and attempted comparisons share 67,108,864 work units. Subject
checks are lazy, comparisons preserve ordered short-circuit `fnmatch`
semantics, and breaches return sanitized `policy_match_limit` blocks through
the normal evidence path. The shared state also eliminates v0.37's duplicate
tool/target prefix evaluation. See `policy_glob_matching_limits.md`.

v0.39 bounds canonical action fingerprints before an action reaches policy,
approval, reservation, grants, or execution. Payload and authorization hashes
retain their exact existing canonical bytes while enforcing 64 levels,
1,100,000 nodes, 8,388,608 characters per scalar, and 67,108,864 canonical
bytes per hash. The owning control path detaches caller containers and reuses
one sealed snapshot; capability spend re-hashes live fields once to detect
nested mutation. Command Core and Command Center expose only static posture.
See `action_hashing_limits.md`.

v0.40 bounds governed-request construction before adapter proposal or any
authority work. Tasks, identifiers, allowlists, and provenance metadata have
fixed item, collection, and aggregate text ceilings. The owning harness
revalidates, detaches, and seals the request so mutation after construction
cannot amplify proposal, request-scope membership, policy context, approval,
or evidence work. Command Core and Command Center expose only static posture.
See `governed_request_limits.md`.

v0.41 bounds post-execution tool-result capture before known-result journaling,
budget settlement, or terminal evidence. Accepted summaries and canonical
outputs have fixed ceilings, are detached, hashed, and sealed. Refused output
leaves the authorization and any reservation open for explicit reconciliation
instead of inventing a terminal result or replaying the tool. Command Core and
Command Center expose only static posture and sanitized recovery state. See
`tool_result_limits.md`.

v0.42 moves bounded canonical ownership one step earlier, before an adapter can
translate a `ToolCall` into a `ProposedAction`. The complete name, call/server
identifiers, arguments, and transport parameters are revalidated, detached,
hashed, and sealed. A second live hash after `to_action` detects nested adapter
mutation before recovery, policy, approval, reservation, evidence, or tool
execution. Command Core and Command Center expose only static posture. See
`tool_call_limits.md`.

v0.43 completes the scalar preflight for shared canonical hashing. Integers,
finite floats, and canonical decimal strings are limited to 1,024 characters
before JSON encoding. Integer magnitude is compared without decimal rendering;
`Decimal` coefficient and rendered lengths are checked from tuple metadata
before fixed-point expansion. Accepted canonical bytes and hashes do not change.
Command Core and Command Center expose only static posture. See
`canonical_number_limits.md`.

v0.44 preflights the exact escaped byte width of each canonical JSON string
token. The guard accounts for quotation marks, short escapes, BMP escapes, and
paired non-BMP escapes before `JSONEncoder` can materialize one expanded string
chunk. It adds no new canonical form and preserves all accepted hashes. Tool
calls, action fingerprints, and tool results map the shared sanitized failure
to their own resource-limit aliases. Command Core and Command Center expose
only static posture. See `canonical_string_limits.md`.

v0.45 counts the exact complete canonical JSON size during the same bounded
structural traversal. Container syntax, keys, scalars, enum values, and decimal
strings participate without sorting or encoding. A breach therefore fails
before `sort_keys` or `JSONEncoder`; the existing streaming counter remains a
second assertion. Command Core and Command Center expose only static posture.
See `canonical_value_preflight.md`.

v0.46 caps every canonical mapping at 65,536 entries before the structural
preflight visits its keys or values and before the encoder sorts them. This
bounds the largest individual key sort while the existing node and byte
ceilings bound total traversal and output. Tool calls, action fingerprints,
and tool results expose their own sanitized aliases. Accepted canonical hashes
are unchanged, but mappings above the new ceiling are deliberately refused.
Command Core and Command Center expose only static posture. See
`canonical_mapping_limits.md`.

v0.47 charges every exact canonical key-token byte once per idealized
`ceil(log2(mapping entries))` comparison round against a 67,108,864-unit budget
shared across the complete value. A breach fails before encoder sorting. Tool
calls, action fingerprints, and tool results expose their own sanitized aliases.
Accepted hashes are unchanged, but over-budget values are deliberately refused.
Command Core and Command Center expose only static posture. See
`canonical_mapping_sort_work.md`.

v0.48 gives every mapping a bounded key-only pass before values or encoder
sorting. It accepts the same homogeneous string or numeric key families,
supported enum subclasses, single `None` keys, and empty mappings that already
hashed successfully. Mixed or unsupported key families retain the same
sanitized contract failure but are now refused before `sort_keys=True` starts.
Command Core and Command Center expose only static posture. See
`canonical_mapping_key_contract.md`.

v0.49 completes the mapping key-only pass before value traversal. After family
eligibility, every key is charged against the existing node, scalar, escaped
token, finite/canonical number, complete byte, and aggregate sort-work ceilings.
Only after all keys pass does Defiant traverse mapping values. This changes no
successful canonical encoding or hash. Command Core and Command Center expose
only static posture. See `complete_mapping_key_preflight.md`.

v0.50 makes that bounded traversal produce the exact built-in container
snapshot consumed by the encoder. Live caller containers are not traversed a
second time, built-in container storage is read without subclass iteration
hooks, and mutable Enum values are resolved into the snapshot. This closes
preflight-to-encoder structural drift without changing ordinary successful
canonical bytes or hashes. See `validated_canonical_snapshot.md`.

v0.51 makes action, pre-adapter tool-call, and post-execution tool-result
owners retain that validated snapshot directly. Sealing no longer invokes
`deepcopy()` after validation or traverses caller containers a second time.
Ordinary JSON values and every accepted canonical hash remain unchanged; Enum
and Decimal extensions retain their established canonical representations in
owned state. Command Core and Command Center expose only static posture. See
`validated_snapshot_ownership.md`.

v0.52 snapshots request allowlists, request input references, and action
provenance from built-in list storage before validating them. The exact bounded
tuples that pass count, type, item, and aggregate-text checks become the owned
contract collections. List-subclass iterator views and mutations triggered
during validation cannot enter a later detach pass. Existing limit aliases and
accepted ordinary-list behavior are unchanged. See
`validated_contract_collection_snapshots.md`.

v0.53 converts accepted scalar subclasses and canonical mapping keys to exact
built-in values before hashing and ownership. Sealed requests, provenance,
actions, tool calls, and tool results therefore cannot carry caller-defined
scalar comparison, hashing, formatting, numeric-conversion, or copy behavior
into later authority work. Normalization collisions between exotic mapping
keys fail closed. See `validated_scalar_ownership.md`.

v0.54 extends exact validated ownership to `GuardrailDecision`,
`CapabilityGrant`, and `EvidenceRecord`. Decision and evidence collections are
captured from built-in storage under the canonical ceilings, retained text and
decimals are normalized, and each record revalidates before propagation,
grant claims, evidence hashing, or serialization. A finite negative remaining
balance uses bounded signed-decimal rendering so an actual overrun remains
representable without permitting negative costs or reservations. See
`validated_authority_record_ownership.md`.

v0.55 captures policy packs, registry-supplied known tools, and authority
inputs into one bounded canonical built-in tree before `PolicyEngine` creates
rules or publishes `ruleset_hash`. Evaluation retains only data descended from
that observation, so later mutations to caller-owned nested containers cannot
change policy behavior under a stale hash. The stable authority snapshot
profile is independent of live action-limit constant changes. See
`validated_policy_snapshot_ownership.md`.

v0.56 converts the retained result into sealed runtime state. `Rule` objects
and pattern collections are immutable, the engine exposes rules, known tools,
name, version, and hash through read-only properties, and nested authority
inputs remain recursively frozen behind a defensive built-in projection. The
same pre-seal canonical surface still determines `ruleset_hash`, so ordinary
policy identity is unchanged. See `sealed_policy_runtime_state.md`.

v0.57 captures policy evaluation context once from built-in dictionary storage,
normalizes its bounded string keys and values to exact built-ins, and gives the
same owned snapshot to rule matching and decision attribution. Invalid,
oversized, ambiguous, or capture-unstable context blocks before matching and is
not retained in the refusal. See `validated_policy_context_snapshot.md`.

v0.58 gives every prepared or loaded crash-journal operation one bounded
canonical observation. Its hash and schema validation consume that snapshot,
then the retained payload is recursively frozen and exposed only through fresh
built-in projections. The store-specific 4 MiB limit applies to both reads and
writes. See `validated_operation_journal_snapshot.md`.

v0.59 captures each native hook event once at the public adapter or gate
boundary. Pre-tool retry correlation, model attribution, tool classification,
target derivation, and the governed `ToolCall` consume the same exact built-in
tree; post-tool correlation and result completion do the same. The adapter no
longer deep-copies caller-controlled hook values. The CLI's existing bounded
strict JSON ingestion remains the outer transport limit, while in-process
callers receive the fixed canonical authority profile. See
`validated_native_hook_event_snapshot.md`.

v0.60 makes the authority-profile and operator-trust state objects immutable
ownership boundaries. Loading captures one bounded exact built-in tree before
schema or signature-chain validation. Runtime retention recursively freezes
bindings, transitions, and attestations; public attributes and `to_dict()`
return detached projections. Their established 1 MiB recovery-read ceilings
also constrain canonical capture and atomic publication, preserving the prior
generation if a proposed rotation is too large. See
`sealed_authority_continuity_state.md`.

v0.61 makes durable native-hook correlation an immutable ownership boundary.
The complete store and every public record construction are captured under one
fixed canonical ceiling before field or governed-contract validation. Retained
action, request, and decision snapshots are recursively frozen and exposed
only as detached projections. `authorized` to `completed` is copy-on-write,
and the established 64 MiB state ceiling applies symmetrically to canonical
capture, recovery reads, and atomic publication. See
`sealed_native_hook_correlation_state.md`.

v0.62 applies the same ownership rule to durable approvals. A
`PendingApproval` is a sealed value, not a mutable row: construction and load
adopt one bounded canonical observation; held action, request, decision,
policy, and attestation trees are recursively frozen; public properties return
fresh projections; and status, operator decision, execution, consumption, and
reconciliation advance through validated copy-on-write records. The store
adopts records from one bounded complete-store observation, binds each map key
to the retained approval id, and uses the same 64 MiB ceiling for publication
and recovery. Legacy optional reconciliation fields default safely, while
unknown fields or inconsistent authority snapshots fail closed. Command Core
projects only static posture and sanitized queue state, and Command Center
remains a read-only observer. See `sealed_approval_record_state.md`.

v0.63 makes the budget ledger's mutable working dictionary a deliberate local
transition copy instead of an unbounded authority input. Every recovery read
and proposed publication is first captured as one detached canonical built-in
snapshot under an explicit 64 MiB ceiling. Validation and accounting consume
that exact observation, and the JSON writer sees only the finalized validated
snapshot. Public accounting identifiers and operator reconciliation context
are normalized before comparisons; nested attestations are detached before
retention. Command Core computes summary and drift from one observation, and
the state auditor reuses ledger validation rather than rereading raw JSON. The
conservative disposition of uncertain execution is unchanged. See
`validated_budget_ledger_snapshot.md`.

v0.64 makes `evidence_head.json` one bounded durable-state observation.
Loading captures exact built-in values before schema, profile, count, head,
and timestamp validation; public hash inputs are normalized before comparison
or retention. The established 64 KiB checkpoint allowance now applies to the
canonical capture, descriptor-backed recovery read, and atomic publication.
The append-only evidence history remains independently bounded per record, and
the prior checkpoint remains intact if a proposed publication is refused. The
forward-recovery, rollback, divergence, and profile-rebind rules do not change.
See `validated_evidence_head_snapshot.md`.

v0.65 makes `evidence_witness_policy.json` a matching bounded ownership root.
One detached built-in observation drives schema compatibility, profile and
mode checks, trusted key-ID ordering, optional lag validation, retention, and
publication. The established 256 KiB allowance now governs canonical capture,
descriptor-backed recovery reads, and atomic replacement. Failed publication
preserves the prior policy, v0.1 observations remain readable, and the external
signed witness itself remains outside harness state under its existing
verification contract. See `validated_evidence_witness_policy_snapshot.md`.

v0.66 closes the recovery I/O race in the two authority-continuity roots.
`authority_profile.json` and `operator_trust.json` no longer use a separate
file-size observation followed by a broader JSON read: `read_json()` bounds the
opened descriptor at the same 1 MiB ceiling used for canonical capture and
atomic publication. The legacy signed-approval migration probe is likewise
bounded at the approval store's 64 MiB ceiling. Before replacement, each writer
recaptures and revalidates a detached state projection. State schemas,
generation and signature rules, rotation behavior, and Command Center's
read-only boundary remain unchanged. See `bounded_authority_continuity_io.md`.

v0.67 makes `runtime_artifacts.json` one bounded ownership root. One detached
canonical built-in observation drives schema compatibility, profile binding,
assurance mode, bundle hash, artifact and dependency counts, executable-pin
posture, verification time, conflict comparison, and publication. The state
candidate is captured before locking and revalidated before replacement; its
explicit 64 KiB ceiling now governs canonical capture, descriptor-backed
recovery reads, and atomic publication. Existing v0.1 state remains readable
and upgrades on write. Artifact hashing, dependency inventory, pre-spawn
reverification, profile rotation, and Command Center's read-only boundary are
unchanged. See `validated_runtime_artifact_state_snapshot.md`.

v0.68 makes `launch_envelope.json` one bounded ownership root. A detached
canonical built-in observation drives schema validation, profile binding,
launch mode, environment and working-directory hashes, counts, verification
time, conflict comparison, and publication. The candidate is captured before
locking and revalidated before replacement. The same explicit 64 KiB ceiling
now governs canonical capture, descriptor-backed recovery reads, and atomic
publication, preserving prior recoverable bytes on failure. Environment
construction, secret handling, unsafe-variable acknowledgement, pre-spawn
working-directory verification, profile rotation, and Command Center's
read-only boundary remain unchanged. See
`validated_launch_envelope_state_snapshot.md`.

v0.69 makes `state_storage.json` one bounded ownership root. A detached
canonical built-in observation drives schema compatibility, profile and root
binding, filesystem-security mode, permission and directory-sync posture,
Windows ACL posture, verification time, conflict comparison, and publication.
The candidate is captured before the authority lock and revalidated before
replacement. The same explicit 64 KiB ceiling governs canonical capture,
descriptor-backed recovery reads, and atomic publication, preserving prior
recoverable bytes on failure. Live filesystem inspection, identity and ACL
replacement checks, profile rotation, and Command Center's read-only boundary
remain unchanged. See `validated_state_storage_state_snapshot.md`.

v0.70 closes the same ownership and recoverability gap in
`control_plane_isolation.json` and `workspace_integrity.json`. Each store
captures one detached canonical built-in observation before validation or
locking, uses it for profile-bound conflict checks, and revalidates it before
atomic replacement. Independent 64 KiB ceilings govern canonical capture,
descriptor-backed recovery reads, and publication for both stores. Prior bytes
survive an invalid or oversized attempted replacement. Live root identity,
link/reparse and protected-target checks, cross-store integrity gating,
profile rotation, and Command Center's read-only boundary remain unchanged.
See `validated_filesystem_authority_state_snapshots.md`.

## v0.71 authority-publication transaction

The authority-profile file is the generation root for several independently
atomic observations. A crash between those writes previously left no durable
proof that a mixed generation was an interrupted authorized rollout rather
than later modification. `authority_publication.json` now supplies that proof.

The owner previews the candidate profile, hashes one bounded manifest of all
dependent authority projections, and durably prepares the exact profile,
generation, and manifest before profile activation. Exact restart replays are
permitted until the evidence head and startup recovery finish, then a completed
checkpoint replaces the intent. A completed same-generation checkpoint forces
read-before-write verification of every dependent store; disagreement fails
closed. Read-only surfaces report the checkpoint but cannot drive it. See
`authority_publication_recovery.md`.

## v0.72 read-only publication verification

Doctor and Command Core reconstruct a completed authority-publication manifest
from the strict durable dependent observations and compare it with the
checkpoint hash. Required stores must exist; every present store must bind the
same profile; optional-store presence is part of the manifest. Missing,
invalid, added, removed, or authority-mismatched state is therefore visible and
critical before another owning runtime starts. Active partial publication
remains a recovery state that read-only and operator-control paths cannot
complete. See `authority_publication_manifest_verification.md`.

## v0.73 active-publication phase verification

Read-only diagnostics now reconcile an active publication against the durable
profile state machine and dependent-store generation bindings. A target that
has not activated is `prepared`; an activated target whose evidence head still
binds the prior generation is `applying`; and a target whose final reconstructed
manifest matches is `ready_to_complete`. During a proven partial rotation,
exact prior-generation dependencies are recovery state instead of false
tampering alarms. A missing prior dependency, unrelated profile, invalid staged
transition, or final manifest mismatch is critical. Only the owning runtime can
replay or complete the intent. See
`active_authority_publication_verification.md`.

## v0.74 active-publication store commitments

Before profile activation, the owning runtime now records exact hashes for all
seven sanitized target-store projections alongside the complete manifest hash.
During `applying`, read-only diagnostics verify every already-written target
store against its prepared commitment, so a structurally valid same-profile
substitution is critical before evidence-head advancement. Optional absence is
committed explicitly, individual hashes are never projected, and v0.73 schema
`0.1.0` crash intents remain exact-replay compatible before migration to
`0.2.0` on completion. Command Center receives only sanitized commitment
posture and has no recovery authority. See
`active_authority_publication_commitments.md`.

## v0.75 completed-checkpoint store commitments

Each successful publication now retains the prepared per-store commitments in
its completed checkpoint. During a mixed-generation replay, read-only
diagnostics verify target-profile stores against the active intent and stores
still bound to the checkpoint profile against the completed commitments. This
detects a structurally valid same-prior-profile substitution before enough
stores remain to reconstruct the prior aggregate manifest. Schema `0.3.0`
represents unavailable legacy checkpoint commitments explicitly; `0.1.0` and
`0.2.0` documents remain readable and migrate only after a successful matching
owning-runtime startup. Command Center receives only sanitized posture and has
no replay or migration authority. See
`active_authority_publication_checkpoint_commitments.md`.

## v0.76 stable completed-checkpoint verification

Read-only diagnostics now reconstruct both the completed manifest and all seven
per-store commitments from the same durable observations. A retained
commitment that differs from its stable store is critical even when the
aggregate manifest hash remains valid. The owning runtime applies the same gate
before reusing the checkpoint or preparing a later generation, so latent
commitment poisoning cannot become recovery input. Legacy checkpoints remain
aggregate-verified and explicitly unavailable for per-store comparison until a
successful matching startup migrates them. See
`completed_authority_publication_checkpoint_verification.md`.

## v0.77 sealed authority-publication records

Every new schema `0.4.0` intent and checkpoint carries a canonical SHA-256
record hash over its record type, profile hash, generation, manifest hash,
timestamp, and exact per-store commitments. Parsing validates that seal before
the publication can be classified, compared, reused, or completed. This makes
a single-field substitution invalid immediately instead of allowing it to
masquerade as a recoverable prepared or completed record.

Schemas `0.1.0` through `0.3.0` remain readable for exact owning-runtime
migration and project `legacy_unavailable` seal posture. State Integrity,
Command Core, and Command Center expose only the posture; raw record hashes are
not projected, and Command Center remains read-only. See
`sealed_authority_publication_records.md`.

## v0.78 sealed authority-publication transitions

Schema `0.5.0` extends the semantic seals into a chain. Each active intent
commits to the exact retained checkpoint record hash, or the explicit
`GENESIS` predecessor for the first publication. Each completed checkpoint
retains the intent preparation time, prior-checkpoint link, and intent record
hash, so it can be verified against the exact intent that authorized the
transition. Substituting an independently valid intent or checkpoint therefore
fails closed before recovery authority is granted.

Schemas `0.1.0` through `0.4.0` remain readable. Missing historical linkage is
reported honestly as `legacy_unavailable`; read-only inspection never invents
or migrates it. A stable legacy checkpoint can be republished by a successful
matching owning-runtime startup into a fully linked current transition, while
completion of an already-active legacy intent preserves unavailable origin
linkage rather than fabricating it. Command Core and Command Center expose only
sanitized posture, never raw linkage hashes, and Command Center remains
read-only. See `sealed_authority_publication_transitions.md`.

## v0.79 authority-publication continuity ratchet

Publication schema `0.6.0` adds a non-negative continuity sequence while an
independently atomic, self-sealed `authority_publication_continuity.json`
anchors each enrolled completed checkpoint. Normal completion writes the new
checkpoint first and advances the ratchet second. A crash between those writes
is recognizable only when the new checkpoint links the current anchor and the
sequence advances exactly once; owning-runtime startup then advances the anchor
before preparing more work.

An anchor ahead of publication is rollback. Equal sequences with different
checkpoint seals, skipped sequences, an orphan anchor, a sequence reset, or a
missing anchor after sequence one are critical divergence. Legacy publication
schemas remain readable without an anchor and enroll through a successful
matching startup. The compact ratchet does not retain an unbounded local event
log and does not claim to detect matched rollback of the publication file and
anchor together. See `authority_publication_continuity.md`.

## v0.80 external authority-publication witness

An optional external Ed25519 document now witnesses the retained publication
head and its compact continuity sequence. The signed payload binds deployment
root identity, authority-profile generation and hash, continuity sequence,
checkpoint hash, signer, key id, and observation time. Trusted key identifiers
and required mode are part of the authority profile and the combined
authority-publication manifest; the durable policy state is stored separately
in `authority_publication_witness_policy.json`. Witnesses and key material must
remain outside the state root.

Owning-runtime startup requires an exact current witness. After that startup
publishes its new checkpoint, read-only diagnostics accept the cryptographically
provable one-step forward relation as safe but recovery-required, directing the
operator to publish a refreshed witness. A second startup, older lag, matched
local rollback, signature failure, trust substitution, root mismatch, or
post-enrollment omission fails closed. Command Core and Command Center receive
only sanitized mode, verification, sequence, lag, signer, and time; they cannot
write policy, accept a witness, sign, recover, or advance publication. See
`authority_publication_witness.md`.

## v0.81 verified publication-witness issuance

Witness verification is useful only if issuance cannot notarize a locally
inconsistent checkpoint. The high-level issuance path now holds
`authority.lock` across live root verification, completed-checkpoint and
continuity verification, independent durable-manifest reconstruction,
per-store commitment comparison, signing, and non-overwriting external
publication. Contention fails immediately, and a substituted dependency or
interrupted witness-policy writer blocks issuance without creating an output.
Low-level payload and signing primitives remain available for explicit library
composition, while the operator CLI always uses the serialized verified path.
No Command Center endpoint or mutation capability is added.

## v0.82 durable publication-witness output

The external witness writer now treats the final filesystem publication as a
separate fail-closed boundary. It fsyncs the signed temporary file, creates the
final name without replacement, synchronizes the output directory, removes the
temporary hard link, synchronizes the directory again, and reads back the
exact final bytes before the serialized issuance transaction returns success.
Directory synchronization follows the persistence platform contract: required
on POSIX and best effort on Windows.

Failure after the final link is created is deliberately not rolled back. The
file may be the only durable copy, and deleting it would turn uncertainty into
data loss. Issuance instead reports the ambiguity and preserves the final path
for operator inspection. No runtime state or Command Core schema changes, and
Command Center receives no path, content, durability control, or mutation
endpoint.

## v0.83 verified evidence-head witness issuance

Evidence-head witness creation now uses one high-level transaction rather than
independent build, sign, and write CLI steps. Under `authority.lock`, it
revalidates live state-storage identity, captures the evidence file once with
the secure bounded reader, verifies that exact owned sequence and its durable
checkpoint, signs it, and retains the lock until non-overwriting external
publication is durable and byte-verified. A missing evidence store is an error,
not an initialization request.

The external writer uses the same conservative final-link, directory-sync,
temporary-cleanup, and exact read-back posture as authority-publication
witnesses. Post-link uncertainty preserves the final file for operator
inspection and returns failure. Command Core and Command Center schemas do not
change, and no browser mutation capability is added.

## v0.84 read-only evidence capture

v0.84 introduces `EvidenceStore.read_existing_records(path)` for observations
that must never initialize a store. It materializes one sequence with the same
strict descriptor-backed parser used by ordinary store reads. Evidence witness
issuance and verification use this reader; the verification CLI validates the
chain and witness against one capture. This closes missing-file initialization
and verify/reopen gaps without changing ordinary writer initialization,
authority locking, or the Command Core and Command Center contracts.

## Known limits

- **Approval state contains sensitive payloads.** Durable restart-safe resume
  requires the local approval store to retain the held action. The state
  directory must be access-controlled and is not suitable for evidence export.
- **Evidence is append-only by convention at the filesystem layer.** Anyone with write access to the file can truncate it; the chain makes alteration and deletion *detectable*, not impossible. Off-box replication is the answer, and it belongs to Command.
- **Deterministic phrase matching is bypassable by paraphrase.** See above.
- **Action hash limits are per fingerprint, not process quotas.** v0.39 bounds
  each canonical payload, provenance-content, and authorization fingerprint.
  Total traffic, CPU, memory, and wall-clock consumption across many accepted
  actions still require deployment monitoring and OS controls.
- **Canonical-number limits are per value, not arithmetic quotas.** v0.43
  prevents unbounded decimal rendering during canonical hashing. It does not
  cap arithmetic performed before a value reaches Defiant or cumulative work
  across many accepted values.
- **Canonical-string limits are per token, not process quotas.** v0.44 prevents
  one rejected string from first expanding beyond the complete canonical byte
  ceiling. Total traffic and repeated accepted hashing still require deployment
  monitoring and OS resource controls.
- **Canonical-value preflight is per fingerprint.** v0.45 prevents rejected
  aggregate values from entering encoder sorting or emission, but accepted
  mappings are still sorted and repeated hashing still consumes CPU. Deployment
  quotas and monitoring remain necessary.
- **Canonical-mapping limits do not eliminate sorting.** v0.46 bounds each
  mapping at 65,536 entries before traversal. v0.47 also applies an aggregate
  deterministic key-volume/comparison-round budget, but it is not an exact CPU
  counter or wall-clock timeout. Accepted mappings still sort their keys and
  repeated accepted hashing still consumes CPU. All ceilings are per
  fingerprint, not process-wide quotas.
- **Canonical key preflight is not a Python sandbox.** v0.49 validates built-in
  sortable families and complete key tokens without invoking comparisons, but
  trusted subclasses can still define process-local behavior. Python already
  running inside the harness remains trusted and requires deployment isolation.
- **Validated snapshots are not transaction isolation.** v0.50 ensures the
  encoder consumes only the bounded structure it validated. It does not freeze
  caller memory, serialize other application threads, or make arbitrary Python
  code untrusted. v0.51 makes contract owners adopt that bounded observation
  directly instead of running a later deep copy. Final live capability checks
  still detect later action drift.
- **Tool-result limits do not contain the tool.** v0.41 bounds post-execution
  result capture, but a handler may have performed its side effect before it
  returns invalid output. Defiant preserves the uncertain authorization for
  explicit operator reconciliation; it cannot discover the truth itself.
- **Tool-call limits do not sandbox trusted adapter code.** v0.42 detects
  bounded-contract mutation before authority work, but Python already running
  inside the harness process remains trusted and still requires deployment
  isolation against arbitrary process-level behavior.
- **`estimate_cost` is a stub** for everything except explicit spend amounts. Token-cost estimation per runner is adapter work.
- **MCP has no standard actual-cost field.** The proxy settles successful paid
  calls at the conservative configured estimate unless a later adapter can
  prove an actual amount.
- **Generic provenance is coarse.** The proxy defaults arguments to `DERIVED`.
  It cannot reconstruct a runner's cross-call data flow; native hooks are
  needed for source-specific taint.
- **Exact-call retry requires client cooperation.** After approval, the MCP
  client or agent must repeat the same tool params before expiry.
- **Native-hook correlation is finite local state.** v0.61 explicitly bounds
  `hook_executions.json` at 64 MiB and refuses further publication once the
  complete document cannot fit. It does not prune completed records, infer a
  missing post-event, or replace external retention and deployment monitoring.
- **MCP task augmentation is not yet supported.** Initialization is negotiated
  down to `2025-06-18`; task-aware governance belongs in a later release.
- **Declared hashes are not dependency discovery or binary attestation.** v0.16
  verifies the executable and operator-declared support files, but an
  interpreter may load undeclared modules, native extensions, configuration,
  or plugins. Production deployments should also use reviewed lockfiles,
  locked installations, immutable images, and OS policy.
- **In-process code is trusted.** Signed grants constrain adapters and normal
  control flow; they do not sandbox malicious Python already executing inside
  the harness process.
- **Hook timeouts fail open.** Current VS Code and Copilot CLI behavior falls
  back to normal runner permissions when a hook times out. Hook errors are
  converted to explicit deny responses, but the platform timeout rule requires
  an outer OS sandbox for production.
- **Reconciliation does not discover the truth automatically.** v0.13 recovers
  a result only when it was returned and durably journaled. Otherwise the
  operator must inspect the external provider or target system and assert the
  outcome. The reconciliation procedures make that assertion explicit,
  durable, conservative, and auditable; they cannot prove that the human
  conclusion was correct.
- **Cross-store auditing is point-in-time.** It does not turn local JSON files
  into a transactional database. v0.14 serializes authority-bearing writers
  across a state directory, while conservative per-file locks still guard each
  atomic write. Read-only diagnostics may observe a transient in-progress
  state and should refresh after the writer finishes.
- **Artifact integrity is not host integrity.** The profile now binds a verified
  declared local bundle when required, but a privileged attacker can replace
  bytes after the final check, patch the harness or process, alter undeclared
  dependencies, replace code and state together, or restore an older internally
  valid generation unless an external witness retains the observed generation
  and hash.
- **Launch-envelope integrity is not process containment.** A restricted child
  can still load declared writable files, open the network, invoke other
  processes, or use runtime mechanisms outside environment variables. A
  privileged host can replace the cwd after the final identity check or patch
  process memory. OS sandboxing and immutable deployment remain separate.
- **State-storage identity is not a rollback witness.** Local device/inode or
  file-identifier signals detect ordinary path replacement and relocation, but
  a privileged host can replace code and complete state together or restore an
  older internally consistent root. Off-box signed observations remain the
  answer to host-level rollback.
- **Windows ACL assurance is point-in-time, not process containment.** Native
  checks bound owners and allow trustees and repeat at authority boundaries,
  but they cannot defeat a privileged host that can replace the process, token,
  code, or complete state between checks. Default Windows mode remains visibly
  `structural_only` until an operator explicitly enrolls strict mode.
- **Protected targets are not an upstream sandbox.** v0.19 blocks accurately
  declared workspace targets that overlap Defiant state. It cannot stop a
  dishonest or compromised upstream from ignoring its target argument or
  accessing a broader host mount; OS containment remains required.
- **Signing identity is key-based, not account-based.** A valid v0.8
  attestation proves possession of a pinned private key. The signer string and
  note are cryptographically bound assertions, not authentication against an
  identity provider. Key custody and the mapping from key id to accountable
  operator remain deployment controls.
- **Operator identity is also key-based.** v0.9 prevents a trusted key from
  claiming an identity other than the one in the explicit trust mapping. It
  does not prove legal identity, provide trusted time, protect an unlocked key,
  or replace organizational key custody and revocation procedures.
- **Signed exports are point-in-time.** They authenticate one exported payload
  and its stated full-chain head. They do not prove that the live evidence file
  was never extended or later truncated; off-box retention is still required.
