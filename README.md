# Defiant Agent Harness

Control, approvals, budgets, memory discipline, and audit evidence for business-grade AI agents.

Defiant Agent Harness wraps MCP-capable and other agentic AI systems with
business-grade controls: tool permissions, human approval gates, budget limits,
provenance discipline, prompt-injection resistance, and Command-ready evidence
logs. A full trusted-memory/DKE system is not part of v0.88.

## The invariant

Everything in this repository exists to enforce one rule:

> No side-effecting tool action executes unless it passed the policy decision path and produced an evidence record first.

That rule is enforced at the registered tool boundary. Execution requires a
single-use, registry-signed `CapabilityGrant` issued against a sealed
authorization record. The grant binds the action id, tool, target, payload,
provenance, side-effect classification, request, and cost estimate. A forged
grant, a grant from another registry, or any post-authorization change is
refused.

The trusted boundary is stated honestly: code already running inside the
harness process is trusted. Python is not an operating-system sandbox. The
grant prevents accidental bypasses and untrusted adapter claims; OS isolation
is a later deployment layer.

A second rule follows from the first, and it is the one that answers the security objection people actually raise about always-on agents:

> Knowledge can inform execution. Knowledge cannot authorize execution.

Adapters carry provenance for content the agent used. External content is
tagged `untrusted`, missing provenance defaults to `derived`, and trust flows
into the proposed action. Policy can then refuse outbound actions derived from
untrusted material. The mock adapter proves this path; every real adapter must
be reviewed and tested for provenance quality.

## What v0.88 is

A headless local control loop plus generic MCP stdio and Streamable HTTP
upstream transports. Each local proxy speaks stdio to the agent, transparently
forwards ordinary protocol traffic, and intercepts `tools/call`. It validates
an intercepted action against the authoritative operator-authored tool map,
evaluates deterministic policy, checks budget, holds durably for human
approval, executes through the gated path, and writes a hash-chained evidence
trail—including for actions that never ran.

The v0.1 reference tools remain safe fixtures: only `read_file` performs real
I/O, confined to one workspace, while their side effects are simulated. The
v0.3 proxies are real execution boundaries: a permitted or approved call is
forwarded to the configured upstream server and can therefore have real side
effects.

The repository also includes preview native-agent hook adapters for current
VS Code, Copilot CLI, and Codex sessions. `PreToolUse` sends native read, write,
search, terminal, subagent, and unknown-tool attempts through the same policy
and approval path. `PostToolUse` seals successful external execution into
evidence. This closes the principal bypass exposed by runners whose built-in
tools cannot be removed from their UI.

v0.4 added the first thin **Command Core** read model. It verifies the complete
evidence chain and emits a safe operational snapshot containing decision and
execution counts, actionable approvals, budget state, and bounded recent
activity. It is read-only and deliberately withholds evidence aggregates when
the chain is broken.

v0.5 adds the first **Command Center** UI on top of that contract. It is a
dependency-free local dashboard bound only to loopback, with live evidence,
approval, budget, and recent-activity views plus request filtering. It has no
mutation, execution, approval-decision, policy, authentication, DKE, or Spartan
surface.

v0.6 begins production hardening with an explicit recovery path for approvals
stranded in `executing` after a process crash. Automatic replay remains
forbidden. An operator must inspect the external system, select `succeeded`,
`failed`, or `not_executed`, and supply both identity and a non-empty note. The
intent, conservative budget disposition, evidence, and final approval state are
individually durable and idempotent across repeated crashes. Command Core and
Command Center report the required intervention, but Command Center remains
strictly read-only.

v0.7 adds a read-only cross-store state auditor and fail-closed execution gate.
It verifies evidence, approvals, budgets, reservations, terminal evidence, and
reconciliation markers together before an authority-bearing operation. Expected
crash windows remain recoverable and visible; contradictions block new
authority. `dah doctor`, Command Core, and Command Center remain usable for
sanitized diagnostics without repairing or mutating state.

v0.78 seals authority-publication transitions, not just each record in
isolation. Every new active intent identifies the exact retained completed
checkpoint—or the explicit `GENESIS` predecessor—and every new completed
checkpoint identifies the exact intent that produced it. Individually valid
records cannot therefore be spliced into a false recovery sequence. Legacy
schemas remain readable with explicit unavailable linkage posture; only a
successful matching owning-runtime startup migrates state. Command Core and
Command Center expose sanitized verification posture without raw linkage
hashes, and Command Center remains strictly read-only.

v0.79 adds a compact sealed continuity ratchet beside authority publication.
Each successful checkpoint advances a monotonic sequence bound to the exact
checkpoint and predecessor. A crash after checkpoint publication but before
ratchet advancement is visible and deterministically recoverable; publication
rollback, post-enrollment anchor deletion, a forged sequence reset, or a valid
but unrelated anchor blocks authority. Pre-v0.79 state remains readable with
explicit legacy posture and enrolls only during a matching owning-runtime
startup. Command Center remains strictly read-only and receives no raw ratchet
or checkpoint hashes.

v0.80 adds an optional authority-bound external Ed25519 witness for the
authority-publication continuity head. The signed witness binds the deployment
root, authority profile, publication checkpoint, monotonic sequence, signer,
and observation time. Exact current state is accepted for owning-runtime
startup; the checkpoint written by that startup leaves a visible one-step
refresh requirement. Older lag, matched local rollback, an untrusted key,
tampering, or omission after enrollment fails closed. The witness and public
keys must remain outside `.dah`, while Command Core and Command Center expose
only sanitized verification posture and never gain signing or mutation
authority.

v0.81 hardens publication-witness issuance itself. The signing command now
holds the cross-process authority transaction lock through state verification,
signing, and non-overwriting external publication. It rechecks live state-root
identity and security posture, requires an exact completed checkpoint for the
active profile, and independently reconstructs the complete durable authority
manifest and retained per-store commitments before signing. Corrupted,
substituted, active, or concurrently changing authority state cannot be
accidentally notarized. Read-only integrity diagnostics also treat a retained
publication-witness policy lock as an unsafe writer/crash signal.

v0.82 makes the final external witness publication step explicit and
conservative. The non-overwriting writer synchronizes the final directory
entry and temporary-link cleanup where the platform supports directory sync,
then reads back and constant-time compares the exact published bytes before
reporting success. A sync, cleanup, read-back, or byte-identity failure returns
an error and leaves any already-created final file untouched for operator
inspection; it is never silently accepted, removed, repaired, or overwritten.

v0.83 applies coherent issuance and durable publication to external
evidence-head witnesses. The operator command holds the cross-process
authority lock across live state-root verification, one descriptor-backed
evidence capture, verification of that exact captured chain against its
durable checkpoint, signing, durable non-overwriting output, and exact
read-back comparison. Missing evidence is refused without recreation, and
contention or ambiguous publication fails without reporting success.

v0.84 removes evidence-store initialization from witness capture and
verification. Both paths read an existing log directly; missing evidence,
including deletion after issuance's existence check, fails without recreating
the file. The verification CLI checks the chain and signed witness against
one captured sequence and reports malformed or missing evidence as a
structured failure. See `docs/evidence_head_witness.md`.

v0.85 makes `history`, `show`, and `verify` non-initializing evidence
inspections. Missing or malformed JSONL logs fail without creating state,
acquiring locks, or printing a successful observation. An existing empty log
remains distinct from a missing one. See `docs/read_only_evidence_inspection.md`
for point-in-time and chain-verification limits.

v0.86 makes request exports require existing evidence. Export locking can no
longer initialize a missing state directory, and chain status, selected records,
and head hash come from one locked capture. Signing, output limits, and
no-overwrite rules remain unchanged. See `docs/existing_evidence_exports.md`.

v0.87 validates history display fields before filtering or printing, escapes
evidence-supplied terminal controls, and bounds displayed cell widths.
Negative history limits are refused; zero selects no rows while still requiring
readable evidence. See `docs/safe_history_rendering.md`.

v0.88 extends bounded, terminal-safe text rendering to the human-readable
diagnostics of history, show, verify, and export. Untrusted record IDs, broken
chain details, and export paths cannot insert terminal controls into those
messages. JSON inspection/export output and integrity decisions stay unchanged.
See `docs/safe_inspection_diagnostics.md` for the precise scope and limits.

v0.8 adds offline-verifiable Ed25519 attestations for request evidence exports.
Signing requires an encrypted private key kept outside harness state, an
explicit signer identity, and a non-empty note. Verification pins public keys
out of band and supports deliberate rotation without trusting a key embedded in
the export. A broken chain, empty request, cross-request record, malformed
schema, or inconsistent chain metadata cannot be signed. Command Center remains
strictly read-only and never receives private-key material.

v0.9 adds cryptographically bound operator decisions. Approval and crash
reconciliation statements can be signed with an encrypted Ed25519 private key
and verified against an out-of-band `IDENTITY=PUBLIC_KEY.pem` trust mapping.
The signature binds the exact approval authority, outcome, identity, required
note, and timestamp. A runtime configured with trust pins fails closed on
unsigned, invalid, untrusted, or replayed authority before execution or budget
reconciliation. Command Core and Command Center expose sanitized assurance
metadata while remaining read-only and never receiving private-key material.

v0.10 makes signed operator mode durable. The first authority-bearing startup
with trust pins enrolls a nonsecret identity/key-ID mapping in
`.dah/operator_trust.json`. Later authority startup without pins, or with a
different mapping, fails before evidence, approval, budget, or tool mutation.
Planned rotation is an explicit old-key-signed, strictly additive generation;
online key removal and identity reassignment are refused and reserved for an
offline compromise-recovery procedure. Doctor, Command Core, and Command Center
remain read-only and expose enrolled, verified, mismatched, or invalid trust
state without enrolling or repairing it.
Existing v0.9 work directories containing signed operator attestations must
supply their current pins on first v0.10 authority startup; unsigned migration
is refused.

v0.11 adds a crash-safe local operation journal for deterministic mutations
that span approvals, budget reservations, and evidence. Prepared approval
creation, rejection, and expiry operations recover idempotently after a process
crash without double-reserving, double-releasing, or duplicating evidence.
Conflicting partial state fails closed. External tool outcomes are never
inferred or replayed: approvals stranded in `executing` still require the
explicit v0.6 operator reconciliation workflow. Command Core and Command Center
show only sanitized recovery metadata, and Command Center remains strictly
read-only.

v0.12 closes the remaining operator-path gap for approval-free execution
authorizations. A sealed authorization with no terminal outcome can now be
resolved by evidence record id only after the operator supplies `succeeded`,
`failed`, or `not_executed`, a non-empty identity, and a non-empty note. Signed
mode binds the statement to the exact sealed authorization under a distinct
Ed25519 purpose. Budget disposition and terminal evidence recover idempotently
through the operation journal, while Command Core and the strictly read-only
Command Center expose only sanitized recovery metadata.

v0.13 journals a known tool result before budget settlement, terminal evidence,
or approval consumption. If the process stops after the tool returns, restart
finishes those exact local mutations without calling the tool again, charging
twice, duplicating evidence, or asking an operator to guess an outcome the
harness had already received. Missing actual-cost data settles at the
conservative reserved estimate for non-dry-run attempts. Doctor, Command Core,
and the strictly read-only Command Center distinguish this deterministic
recovery from manual reconciliation.

v0.14 enforces one authority-bearing writer per state directory. A nonblocking,
cross-process transaction lock now spans startup recovery, policy and integrity
checks, authorization, internal execution, external preflight and completion,
settlement, and terminal state. It
is reentrant for nested harness operations and is released by the operating
system when a process crashes, so contention fails closed without creating a
stale-lock repair step. Per-file locks remain the final atomic-write guard.
Command Core and Command Center do not acquire or mutate this authority lock.

v0.15 adds durable continuity for the complete runtime authority profile. The
first authority startup pins the canonical hash of policy rules, known tools,
security-relevant tool contracts, workspace root, dry-run posture, and
adapter/upstream identity. Later drift fails before operational-store recovery
or mutation. A reviewed change requires an explicit operator identity, note,
and exact next hash; signed mode binds it to a trusted Ed25519 key. Rotation is
staged atomically and activates only when that exact candidate runtime starts.
Doctor, Command Core, and the strictly read-only Command Center expose only
sanitized verified, mismatched, invalid, or rotation-required state.

v0.16 adds content-addressed runtime artifact assurance for local stdio MCP
upstreams. Production configurations can require an operator-authored SHA-256
manifest containing the executable and declared supporting artifacts. Defiant
resolves and hashes every file before authority-profile resolution, launches
the verified executable by its absolute path, re-verifies the bundle immediately
before spawning, and binds the canonical bundle hash into the durable v0.15
profile. Missing, replaced, forged, symlinked, or state-directory artifacts fail
closed; a reviewed artifact update requires the normal explicit profile
rotation. Doctor, Command Core, and Command Center show only sanitized pinned,
unverified, mismatched, or invalid assurance and never expose paths or add a
dashboard mutation endpoint.

v0.17 adds launch-envelope integrity around those verified local processes. A
strict stdio MCP configuration starts from an empty child environment, passes
only explicit literal, inherited, or secret variables, requires an explicit
canonical working directory outside harness state, and refuses loader or path
injection variables unless each name is acknowledged. Nonsecret effective
values and the working directory are hashed into the v0.15 authority profile;
secret values are required at launch but deliberately excluded from persisted
hashes so credential rotation neither leaks values nor silently changes launch
policy. Legacy inheritance remains available but is visibly unrestricted.
Doctor, Command Core, and Command Center expose only sanitized counts, hashes,
mode, and profile binding. Command Center remains strictly read-only.

v0.18 hardens the local state filesystem beneath approvals, budgets, evidence,
recovery journals, operator trust, and authority continuity. The canonical
state-root path and filesystem identity enter the complete authority profile;
durable observations reject copied, relocated, or replaced roots. State files
and locks must be regular single-link objects, never symlinks or reparse points,
and path identity is compared with the opened descriptor before use. POSIX
storage additionally requires current-user ownership with `0700` root and
`0600` files. Atomic JSON replacement now validates both sides and syncs the
directory entry where supported. Doctor, Command Core, and Command Center show
only sanitized posture and counts and cannot repair or mutate storage.

v0.19 isolates that protected control plane from governed workspace tools. The
canonical Defiant state root is registered as a protected root before policy
construction and bound into the complete authority profile. Workspace-scoped
file and directory targets are rejected when they enter, alias, or contain
protected state, including through symlinks; validation repeats inside grant
execution so retargeting after authorization fails before dispatch. The
profile-bound durable observation and read-only dashboard expose only hashes,
counts, and the sanitized workspace/state relationship. No exception or
mutation surface is added to Command Center.

v0.20 binds the configured workspace root to its canonical filesystem identity.
Authority startup creates a missing root, rejects final symlink/reparse and
non-directory roots, records a profile-bound sanitized observation, and checks
it before every new harness authority action. Workspace-scoped tools repeat the
identity check immediately before handler or MCP dispatch, before spending the
grant. Workspace contents remain mutable. Doctor, Command Core, and Command
Center expose only hashes and verification state; all remain read-only and the
dashboard gains no acceptance or repair action.

v0.21 adds a profile-bound durable evidence-head checkpoint. Each evidence line
is fsynced before its count and head hash are atomically checkpointed. A valid
chain that extends an older checkpoint is an explicit crash-recovery state and
may advance only after its prefix is proven; a shorter chain or divergent head
blocks authority without repair. Authorized profile activation may rebind only
a matching checkpoint. Doctor, Command Core, and Command Center expose sanitized
checkpoint posture, while Command Center remains strictly read-only.

v0.22 adds optional operator-signed external evidence-head witnessing. Required
mode and trusted Ed25519 key identifiers are bound into the complete authority
profile. Startup verifies that the newest supplied witness belongs to this
state-root identity and an enrolled profile generation, then requires the live
chain to equal or validly extend its witnessed head before profile activation.
This detects restoring evidence and its local checkpoint together when the
newer witness is retained independently. Doctor, Command Core, and the strictly
read-only Command Center expose only sanitized posture; signing, trust files,
and witness retention stay outside `.dah`.

v0.23 adds an opt-in closed dependency-bundle mode for local MCP runtimes.
Operator-authored manifests now can cover complete declared directory trees,
not only individually selected artifacts. Startup rejects any added, missing,
changed, linked/reparse, special, overlapping, or state-directory content;
binds the deterministic closure into the complete authority profile; and
repeats verification immediately before process creation. State Integrity,
Command Core, and the strictly read-only Command Center expose only sanitized
mode, hashes, and counts. This is not an OS sandbox and does not cover loading
surfaces outside the declared roots.

v0.24 adds an optional authority-profile-bound freshness ceiling for signed
external evidence witnesses. Operators may cap how many live evidence records
can exist beyond the retained signed head. Startup and authority gates fail
closed with a distinct `lag_exceeded` diagnostic when the enrolled ceiling is
crossed; refreshing the external witness restores authority. The bound uses
record counts rather than pretending local wall-clock time is trusted. Doctor,
Command Core, and the strictly read-only Command Center expose only the bound
and current lag, never witness paths, signatures, or notes.

v0.25 adds opt-in native Windows private-state ACL assurance. An owning runtime
started with `--require-windows-private-state-acl` requires the state root and
known state files to be owned by the current process user, limits allow ACEs to
that user, LocalSystem, and Builtin Administrators, requires current-user full
control, and requires a protected root DACL that propagates current-user full
control to children. The sanitized posture is authority-profile-bound and is
rechecked by State Integrity; it never exposes paths, SIDs, account names, or
ACE details. The default Windows mode remains `structural_only` for compatible
migration. Command Center remains strictly read-only.

v0.26 adds fixed pre-parse resource ceilings at untrusted ingestion boundaries.
Durable JSON state, individual evidence records, MCP stdio and HTTP messages,
native-hook events, and MCP YAML configuration now fail closed before an
oversized document reaches a parser. YAML aliases and non-finite JSON numbers
are rejected. Command Core and the strictly read-only Command Center expose the
active ceilings without exposing input contents, paths, or a configuration
control. Append-only evidence history remains unlimited in total; each record
is bounded independently.

v0.27 makes authority-bearing YAML unambiguous. Every policy pack is limited
to 1 MiB before parsing, and policy packs and MCP configuration both use one
strict safe-loader contract that rejects aliases and duplicate mapping keys at
any depth. Policy packs also reject unknown top-level fields. Load failures are
sanitized and fail closed before state/workspace initialization or upstream launch.
Command Core and the strictly read-only Command Center expose the parser
profile and policy-pack ceiling without adding an upload, editing, acceptance,
or mutation surface.

v0.28 makes authority-relevant JSON unambiguous. Durable state, evidence,
MCP stdio and HTTP traffic, native-hook events and embedded arguments, operator
key lists, signed exports, and external witnesses share one strict UTF-8 parser
that rejects duplicate keys at every depth and non-finite numbers. Durable
ambiguity blocks authority, upstream ambiguity is never forwarded, and hook
ambiguity fails closed. Diagnostics do not echo rejected keys or values.
Command Core and Command Center expose only the static parser posture.

v0.29 bounds each request-scoped evidence export at 64 MiB. Offline
verification rejects an oversized file before UTF-8 decoding or JSON parsing;
export publication, direct signing, and direct verification enforce the same
ceiling without partial output or content-bearing diagnostics. Live append-only
evidence history remains unlimited in aggregate and is never silently split or
compacted. Command Core and the strictly read-only Command Center expose only
the static export ceiling and gain no import, signing, key, or configuration
surface.

v0.30 advances authority JSON to `strict_json_v2`. A shared lexical preflight
rejects more than 64 nested containers or more than 1,000,000 lexical tokens
before Python's JSON decoder constructs objects. It tracks strings and escapes,
so punctuation inside content cannot forge structure. The existing strict
UTF-8, duplicate-key, non-finite-number, and byte-ceiling rules remain in force.
Command Core and the strictly read-only Command Center expose only the fixed
posture; neither can upload input or change a limit.

v0.31 advances authority JSON to `strict_json_v3`. The same pre-decoder scan
now refuses any string token beyond 8 Mi source characters or number token
beyond 1,024 source characters, covering keys, values, integers, fractions,
and exponents. Floating-point tokens that convert to infinity are also refused.
The behavior is deterministic across supported Python releases, failures remain
sanitized and fail closed, and Command Core plus the strictly read-only Command
Center expose only the fixed posture.

v0.32 bounds trusted public-key collections before filesystem and cryptographic
work: at most 1,024 supplied keys, 64 KiB per PEM, and 8 MiB aggregate PEM
bytes. The contract covers operator identity, signed evidence-export
verification, external evidence witnesses, durable trust metadata, and native
hook key-list environments. Failures are conservative and create no partial
trust. Command Core and the strictly read-only Command Center expose only the
fixed ceilings.

v0.33 bounds complete policy-ruleset complexity before rule construction,
normalization, hashing, or action evaluation: at most 64 packs, 4,096 rules,
4,096 known-tool patterns, 4,096 items in one rule list field, and 65,536 rule
list items in aggregate. Registry-provided tool classifications participate in
the same totals. Command Core and the strictly read-only Command Center expose
only these fixed ceilings.

v0.34 advances authority YAML to `strict_yaml_v2`. Policy packs and MCP proxy
configuration now refuse more than 64 nested mappings/sequences or more than
100,000 scalar/collection nodes before safe construction. Existing byte,
strict-UTF-8, alias, duplicate-key, and safe-tag rules remain in force. Command
Core and the strictly read-only Command Center expose only the fixed posture.

v0.35 bounds MCP authority-configuration collections before element
validation, path handling, runtime object construction, hashing, or startup.
Any one command, header, tool, artifact, dependency-root, dependency-file, or
launch-environment collection may contain at most 4,096 items; dependency file
pins are additionally capped at 8,192 in aggregate and launch-environment
entries at 4,096 in aggregate. CLI command overrides participate in the same
preflight. Command Core and the strictly read-only Command Center expose only
the fixed ceilings and posture.

v0.36 bounds policy text before rule construction, normalization, authority
hashing, or governed-action evaluation. One recognized pack field, rule field,
pattern, term, or redaction may contain at most 4,096 constructed characters,
and one complete loaded ruleset may contain at most 8,388,608. Duplicates and
the synthetic registry tool pack count as supplied. Command Core and the
strictly read-only Command Center expose only the fixed ceilings and posture.

v0.37 bounds governed payload substring matching. A payload is flattened and
case-normalized once per decision, with fixed ceilings of 64 levels, 100,000
nodes, and 1 MiB of searchable text. All `payload_contains` tests share a
64 MiB aggregate work budget. Exceeding any ceiling fails closed with sanitized
blocked evidence and no execution or approval. Command Core and the strictly
read-only Command Center expose only the fixed ceilings and posture.

v0.38 bounds policy glob subjects and work. Tool names used by glob matching
are capped at 4,096 characters, targets at 1 MiB, and known-tool plus rule
tool/target comparisons share a 64 MiB deterministic work budget per decision.
Exact limits retain existing `fnmatch` and short-circuit semantics; breaches
produce a sanitized `policy_match_limit` decision in blocked evidence without
execution or approval. Command Core and the strictly read-only Command Center
expose only the fixed ceilings and posture.

v0.39 bounds action-controlled canonical hashing before policy, approvals,
budget reservation, grants, or execution. Payload and complete authorization
fingerprints accept at most 64 levels, 1,100,000 nodes, 8 Mi characters in one
scalar, and 64 MiB of canonical JSON per hash. Governed actions detach caller
containers and reuse one sealed fingerprint snapshot; the final capability
spend independently re-hashes live fields so nested mutation still fails
closed. Hashes for existing valid actions remain byte-for-byte compatible.
Command Core and the strictly read-only Command Center expose only the fixed
ceilings and posture.

v0.40 bounds governed requests before adapter proposal, request-scope checks,
policy context, approval persistence, or evidence. It caps task and identifier
text, allowed-tool count and names, provenance-reference count and metadata,
and aggregate request/action-provenance text. The owning harness revalidates,
detaches, and seals request collections so post-construction mutation cannot
bypass the boundary. Failures are sanitized and create no partial authority.
Command Core and the strictly read-only Command Center expose only the fixed
ceilings and posture.

v0.41 bounds and seals post-execution tool results before terminal evidence or
budget settlement. It caps summaries and canonical output depth, nodes, scalar
text, and bytes; refuses cyclic or non-canonical output; and detaches accepted
output from caller-owned containers. A rejected result never becomes a
fabricated terminal outcome: the sealed authorization and reservation remain
open for the existing explicit operator reconciliation path. Command Core and
the strictly read-only Command Center expose only the fixed ceilings, posture,
and sanitized reconciliation-required state.

v0.42 closes the matching pre-adapter construction gap. Every `ToolCall` now
has fixed name and identifier ceilings plus bounded canonical depth, node,
scalar, and byte limits across arguments and transport parameters. The owning
harness revalidates, detaches, hashes, and seals the complete call before
adapter translation, then re-hashes it immediately afterward. Oversized,
cyclic, non-canonical, or adapter-mutated calls fail before policy, approval,
budget, evidence, or execution. Command Core and the strictly read-only Command
Center expose only the fixed ceilings and fail-closed posture.

v0.43 closes the canonical-number rendering gap shared by tool calls, action
fingerprints, and tool-result output. Signed integers, finite floats, and
canonical decimal strings are capped at 1,024 characters before JSON encoding.
Large integers are rejected by magnitude comparison, and oversized `Decimal`
coefficients or exponents are rejected from tuple metadata before fixed-point
rendering can allocate their expanded form. Existing accepted hashes remain unchanged.
Command Core and the strictly read-only Command Center expose only the fixed
ceiling and fail-closed posture.

v0.44 closes the corresponding canonical-string expansion gap. A direct
in-memory string may satisfy the character ceiling yet expand beyond the
complete canonical byte ceiling when JSON escapes control, non-ASCII, or
non-BMP code points. Defiant now counts the exact escaped token width before
calling the encoder, rejects an impossible token without materializing it, and
preserves every previously accepted canonical hash. Tool calls, action
fingerprints, and tool-result output share this protection. Command Core and
the strictly read-only Command Center expose only the fixed ceiling and
fail-closed posture.

v0.45 advances that preflight from individual values to the complete canonical
surface. Defiant now counts every container delimiter, separator, mapping key,
escaped string, number, enum value, and normalized decimal before sorting or
encoding. An aggregate value that cannot fit the existing 64 MiB ceiling is
therefore refused before `JSONEncoder` starts, while the streaming check remains
as defense in depth. Accepted canonical bytes and hashes remain unchanged.
Command Core and the strictly read-only Command Center expose only the static
preflight posture.

v0.46 bounds canonical mapping-sort amplification. Every mapping shared by
tool-call construction, action fingerprints, and tool-result capture is capped
at 65,536 entries before its keys or values are traversed and before the JSON
encoder can sort them. The complete node and byte ceilings remain in force,
accepted canonical hashes are unchanged, and Command Core plus the strictly
read-only Command Center expose only the fixed limits and preflight posture.
Mappings above the new ceiling are deliberately no longer accepted.

v0.47 bounds the remaining long-key comparison amplification with one
67,108,864-unit sort-work budget across every mapping in a canonical value.
Each exact canonical key-token byte is charged once per idealized logarithmic
comparison round, so both key volume and mapping cardinality participate before
the encoder can sort. Accepted hashes are unchanged. Command Core and the
strictly read-only Command Center expose only the fixed budget and posture.

v0.48 moves canonical mapping-key eligibility ahead of value traversal and
sorting. A bounded key-only pass accepts the same homogeneous string or numeric
families, string/int enum subclasses, single `None` keys, and empty mappings
that already encoded successfully. Mixed families and unsupported key objects
now fail before `sort_keys=True` with the same sanitized contract outcome as
before. Accepted bytes and hashes are unchanged; Command Center remains
strictly read-only.

v0.49 completes that key-only boundary before mapping values. Every eligible
key now receives its scalar, escaped-token, finite-number, canonical-number,
node, byte, and aggregate sort-work checks before the first value is traversed.
A late invalid or over-budget key therefore cannot cause an earlier
attacker-controlled value to be inspected first. Exact accepted canonical bytes
and hashes remain unchanged; Command Core exposes static posture and Command
Center remains strictly read-only.

v0.50 binds encoding to the exact built-in snapshot produced by bounded
canonical validation. The encoder no longer traverses live caller containers a
second time, so mutation between preflight and encoding cannot introduce
unvalidated depth, nodes, mapping entries, keys, or sort work. Built-in
container storage is copied without invoking subclass iteration hooks, and
mutable Enum values are resolved during the validated pass. Ordinary accepted
canonical bytes and hashes remain unchanged; Command Center remains read-only.

v0.51 makes the action, pre-adapter tool-call, and post-execution tool-result
owners retain those validated snapshots directly. Sealing no longer performs a
post-validation `deepcopy()` or invokes caller-defined copy hooks. The exact
bounded observation that produced each digest becomes the owned contract state;
ordinary JSON values and accepted hashes remain unchanged. Command Core reports
only static posture, and Command Center remains strictly read-only.

v0.52 applies the same exact-observation rule to request allowlists, request
input references, and action provenance. Built-in list storage is captured
under the existing count ceilings, then the exact tuple is validated and
retained. List-subclass iterator views or validation-time caller mutations
cannot enter a later detach pass. Existing accepted ordinary-list behavior and
limit aliases remain unchanged; Command Center remains strictly read-only.

v0.53 normalizes accepted scalar subclasses to exact built-in strings,
integers, floats, decimals, and mapping keys before canonical hashing or
governed-contract ownership. Caller-defined comparison, hashing, formatting,
numeric-conversion, and copy hooks cannot remain inside sealed action,
tool-call, tool-result, request, or provenance state. Canonical key collisions
created by normalization fail closed instead of overwriting a value. Ordinary
accepted canonical bytes and hashes remain unchanged; Command Center remains
strictly read-only.

v0.54 applies the same exact-observation ownership rule to the remaining
authority records. Policy decisions, capability grants, and evidence records
normalize retained scalars and capture bounded built-in collection snapshots
before decision propagation, HMAC claims, chain hashing, or JSON serialization.
Evidence sealing no longer carries accepted caller-defined iteration,
comparison, formatting, or deep-copy hooks into later authority work. Finite
negative remaining balances now use a bounded signed-decimal representation so
real overruns can be recorded honestly without relaxing non-negative cost or
reservation rules. Command Center remains strictly read-only.

v0.55 seals the policy configuration observation used by `PolicyEngine`.
Policy packs, registered known-tool additions, and authority inputs are
captured as bounded canonical built-ins before rules are constructed. The
engine evaluates and publishes `ruleset_hash` from that detached state, so a
caller cannot mutate its original nested lists or mappings after construction
and silently change enforcement beneath the published hash. Ordinary policy
hashes remain unchanged. Command Core and Command Center expose only this
static posture; Command Center remains strictly read-only.

v0.56 seals the retained policy runtime derived from that observation. Rules
and their pattern collections are frozen, known-tool patterns are immutable,
policy identity metadata is read-only, and authority inputs are held in a
recursively frozen private tree exposed only through detached built-in
projections. Direct mutation through the public engine API can no longer alter
future decisions beneath an existing `ruleset_hash`. Ordinary policy hashes
remain unchanged. Command Center remains strictly read-only.

v0.57 closes the next policy API boundary by capturing evaluation context once
as bounded exact string metadata. Rules and decision evidence now consume the
same owned observation, so caller mapping hooks or later mutation cannot make
the attributed context disagree with the context that selected a rule. Invalid
or oversized context blocks under a sanitized contract outcome before matching.
Command Core exposes only fixed posture and ceilings; Command Center remains
strictly read-only.

v0.58 hardens the crash-recovery journal with one bounded canonical operation
snapshot, an exact hash of that observation, and a recursively sealed private
payload exposed only through defensive projections. The former `deepcopy()`
passes and their caller hooks are gone. The existing 4 MiB recovery-read limit
now also governs writes, so the harness cannot publish a journal that restart
would reject solely for size. Command Center remains strictly read-only.

v0.59 hardens native hook translation by capturing one bounded canonical event
snapshot at each public pre-tool, post-tool, and adapter entry. Retry identity,
tool classification, target selection, governed payload, and result completion
now descend from that same owned observation. Caller copy, mapping, list, and
scalar hooks cannot substitute a second event between those decisions. Command
Core and the strictly read-only Command Center expose only static posture.

v0.60 seals the nested state retained by the durable authority profile and
operator-trust roots. Each loaded state is validated from one bounded canonical
snapshot, internal transition, binding, and attestation trees are recursively
frozen, and public access returns fresh built-in projections. The existing
1 MiB file allowances also govern canonical capture and atomic writes, so a
successful rotation cannot exceed the documented recovery contract.
Command Center remains strictly read-only.

v0.61 seals durable native-hook authorization/completion correlation state.
Each record is captured once under the fixed canonical profile, validates its
action, request, and decision snapshots from that observation, recursively
freezes retained trees, and exposes only detached projections. Completion is a
copy-on-write transition, and the established 64 MiB store ceiling now applies
explicitly to canonical capture, recovery reads, and atomic publication.
Command Center remains strictly read-only.

v0.62 seals each durable approval record and its held authority context. One
bounded canonical observation now owns the action, request, decision, policy,
and operator-attestation trees; public access returns detached projections and
every lifecycle change creates a new validated record. The approval store uses
the same explicit 64 MiB ceiling for canonical capture, recovery reads, and
atomic publication, rejects stale hashes, cross-request substitution, unknown
fields, and record-key mismatch, and continues to load older records that omit
newer optional reconciliation fields. Command Core and the strictly read-only
Command Center expose only the static hardening posture and fixed ceiling;
approval payloads, targets, notes, attestations, and mutation remain excluded.

v0.63 gives the durable budget ledger one bounded observation and publication
contract. Recovery reads, validation, accounting logic, cross-store audit, and
atomic writes now consume detached canonical built-in snapshots under the same
explicit 64 MiB ceiling. Request, action, operator, note, completion, and
authorization-reconciliation inputs are normalized before comparisons, and
nested attestations are detached before accounting or persistence. Command
Core derives summary and drift from one ledger observation. Conservative crash
rules remain unchanged, and Command Center receives only the static posture and
fixed ceiling while remaining strictly read-only.

v0.64 hardens the profile-bound evidence-head checkpoint as one detached,
bounded durable-state observation. Schema, profile, position, hash, and time
validation consume exact built-in values; recovery reads and atomic writes use
the same explicit 64 KiB ceiling. Failed oversized publication preserves the
prior checkpoint, and public hash inputs cannot retain caller-defined scalar
hooks. Forward-only crash recovery, rollback and divergence refusal, and the
strictly read-only Command Center boundary remain unchanged.

v0.65 applies the same ownership and recoverability contract to the durable
external-witness policy. Profile binding, required mode, trusted key IDs,
optional unwitnessed-record lag, and time validate from one detached canonical
observation; public policy inputs are captured before consistency checks. The
same explicit 256 KiB ceiling governs capture, recovery reads, and atomic
publication. Signed witness files remain external, and their cryptographic,
rollback, divergence, and lag rules do not change.

v0.66 closes the remaining size-check/read race in the durable authority
profile and operator-trust roots. Recovery now bounds the bytes read from the
opened state descriptor under each root's exact 1 MiB publication ceiling,
and the legacy signed-approval migration probe uses the approval store's fixed
64 MiB ceiling. Publication recaptures and revalidates a detached state
projection immediately before atomic replacement. Durable schemas, rotation
semantics, signer requirements, and the read-only Command Center boundary do
not change.

v0.67 makes the sanitized runtime-artifact assurance record one detached,
bounded durable-state observation. Profile binding, assurance mode, bundle
hash, artifact and dependency counts, executable-pin posture, and verification
time validate and persist from exact built-in values. Canonical capture,
opened-stream recovery, and atomic publication now share one explicit 64 KiB
ceiling; the candidate is captured before the state lock and revalidated before
replacement. Legacy `0.1.0` records remain readable and upgrade on write.
Executable and dependency verification, profile rotation, and the strictly
read-only Command Center boundary do not change.

v0.68 applies that bounded ownership contract to the sanitized launch-envelope
assurance record. Profile binding, launch mode, environment and working-
directory hashes, variable counts, and verification time now validate and
persist from one detached exact built-in observation. Canonical capture,
opened-stream recovery, and atomic publication share one explicit 64 KiB
ceiling; publication revalidates the candidate before replacement and preserves
the prior state on failure. Launch configuration, secrets, process creation,
profile rotation, and the strictly read-only Command Center boundary do not
change.

v0.69 makes the sanitized state-root assurance record one detached, bounded
durable-state observation. Profile and root binding, filesystem-security mode,
permission and directory-sync posture, Windows ACL posture, and verification
time now validate and persist from exact built-in values. Canonical capture,
opened-stream recovery, and atomic publication share one explicit 64 KiB
ceiling; the candidate is captured before the authority lock and revalidated
before replacement. Existing v0.1 observations remain readable. State-root
inspection, ACL enforcement, profile rotation, and the strictly read-only
Command Center boundary do not change.

v0.70 completes the bounded durable-snapshot contract across the remaining
filesystem-authority observations: control-plane isolation and workspace-root
integrity. Each store now validates, compares, and publishes from one detached
exact built-in observation under an independent 64 KiB ceiling shared by
canonical capture, opened-stream recovery, and atomic publication. Candidates
are captured before the authority lock and revalidated before replacement;
failed publication preserves prior recoverable bytes. Live path containment,
root-identity checks, cross-store profile binding, and the strictly read-only
Command Center boundary do not change.

v0.71 makes publication of profile-bound startup authority observations
crash-safe as one recoverable local protocol. Before profile activation, the
runtime writes an exact target generation and bounded manifest hash to a
write-ahead checkpoint. Restart may replay only that exact candidate;
different prepared authority is refused. Once a publication is complete,
dependent-store disagreement is treated as possible tampering and is never
silently overwritten. Doctor, Command Core, and Command Center expose the
sanitized recovery state, while Command Center remains strictly read-only.

v0.72 makes that completed publication independently verifiable from read-only
surfaces. Doctor and Command Core reconstruct the same bounded manifest from
the durable dependent stores, require every observation to bind the checkpoint
profile, and report missing, invalid, added, removed, or changed authority state
as critical. Command Center displays only the sanitized verification result and
gains no replay, acceptance, repair, or mutation path.

v0.73 verifies the active side of the crash protocol. Read-only diagnostics
classify an exact intent as `prepared`, `applying`, or `ready_to_complete` from
the durable profile transition, prior checkpoint, dependency profile bindings,
and final reconstructed manifest. Expected mixed generations during a proven
partial rotation remain recoverable; unrelated profiles, missing prior stores,
or a final manifest contradiction are critical. Command Center exposes only the
sanitized phase and remains unable to replay or complete publication.

v0.74 commits every target store's exact sanitized authority projection before
profile activation. During partial replay, each already-written target store is
checked immediately against that prepared commitment instead of waiting for the
evidence head and final manifest. Same-profile substitution is critical, absent
optional stores remain explicitly committed as absent, and v0.73 crash intents
remain recoverable through a read-only-visible legacy posture. Command Center
shows only sanitized commitment status and remains strictly read-only.

v0.75 retains those exact per-store commitments in every successful completed
checkpoint. During mixed-generation recovery, dependencies still bound to the
checkpoint profile are verified against their completed values while target-
generation dependencies continue to be verified against the active intent.
Same-profile substitution on either side is critical, legacy `0.1.0` and
`0.2.0` publication documents remain readable, and successful exact replay
migrates them to `0.3.0`. Command Center exposes only sanitized checkpoint-
commitment posture and remains strictly read-only.

v0.76 verifies every retained commitment while its completed checkpoint is
stable, not only after a later rotation becomes active. A poisoned commitment
is critical even when the aggregate manifest still matches, the owning runtime
refuses it before preparing another publication, and legacy checkpoints remain
aggregate-verified until successful migration. Command Center receives only
the sanitized mismatch posture and remains strictly read-only.

v0.77 seals the complete semantic content of every new authority-publication
intent and completed checkpoint. Profile, generation, manifest, timestamp, and
per-store commitment substitutions are rejected before recovery
classification or checkpoint reuse. Legacy `0.1.0` through `0.3.0` documents
remain readable with an explicit `legacy_unavailable` seal posture and migrate
only during a successful matching owning-runtime startup. Command Center shows
only sanitized seal posture and remains strictly read-only.

## Install

```bash
git clone https://github.com/Joefear/Defiant-Agent-Harness.git
cd Defiant-Agent-Harness
pip install -e ".[dev]"
```

Python 3.10+. Runtime dependencies are PyYAML and `cryptography`.

## Try it

Six scenarios, one command each. The first is the demo worth showing anyone.

```bash
# an agent tries to exfiltrate a customer list because a web page told it to
dah demo injected_exfiltration
```

```
tool         send_email -> attacker@evil.example
side effect  external_send
payload      sha256:f7c49caf30efea89...  trust=untrusted
decision     block  [block_untrusted_side_effect]
reason       Payload derives from untrusted external content. Knowledge can
             inform execution; knowledge cannot authorize execution.
status       blocked
evidence     evd_6a2eb246797c45d6
```

```bash
dah demo send_email --auto-approve   # held, approved, then simulated
dah demo overspend                   # blocked: worst-case estimate exceeds budget
dah demo blocked_folder              # blocked: path outside the workspace
dah demo delete                      # blocked: destructive actions off by default
dah demo read_statement              # allowed and logged: no side effect
dah --policy merchant_services demo prohibited_claim   # blocked: guaranteed-savings language
dah --policy legal_intake demo legal_advice            # blocked: advice during intake
```

If `dah pending` reports an approval in `executing`, first confirm that no
executor is still alive and inspect the real external outcome. Then reconcile
it from the operator CLI:

```bash
dah --workdir .dah reconcile apr_... \
  --outcome not_executed \
  --operator operator-7 \
  --note "worker crashed before dispatch"
```

See `docs/approval_reconciliation.md` before using `succeeded` or `failed`.

If `dah doctor` instead reports an approval-free authorization requiring
reconciliation, use its sealed evidence record id:

```bash
dah --workdir .dah reconcile-authorization evd_... \
  --outcome failed \
  --operator operator-7 \
  --note "provider accepted the request but returned no result"
```

See `docs/authorization_reconciliation.md` for its signature, crash, and
conservative budget rules. Command Center displays both queues but remains
strictly read-only.

Then look at what happened:

```bash
dah pending             # what is waiting on a human
dah history             # the full trail, including everything that was refused
dah show <record_id>    # one record in full
dah verify              # confirm the hash chain is intact
dah signing-keygen      # generate an encrypted Ed25519 signing key pair
dah operator-keygen     # generate an encrypted operator identity key pair
dah operator-trust-rotate ... # authorize an additive trust generation
dah authority-profile-rotate ... # stage one exact reviewed runtime profile
dah verify-export ...   # verify a signed export against pinned public keys
dah doctor              # read-only cross-store integrity and recovery audit
dah budget              # ledger, spend, and estimate drift
dah policy              # loaded rules and the ruleset hash
dah export <request_id> # a Command-ready evidence pack
dah command             # read-only Command Core operational snapshot
dah command-center      # local read-only Command Center UI
```

`dah verify` is the one to try tampering with. Edit any line of `.dah/evidence.jsonl` and it will tell you which record broke and how.

To hand evidence to an external reviewer, sign a request export with an
encrypted Ed25519 private key and explicit operator context, then verify it
against a public key distributed through a separate trusted channel. See
`docs/evidence_signing.md` for key generation, signing, verification, rotation,
and compromise handling.

For production approvals, configure signed operator identity on both the
decision command and the runtime that will consume it. The required operator
note is part of the signed statement. See `docs/operator_identity.md` for the
PowerShell commands, native-hook environment configuration, rotation, and
compromise handling.

`dah --workdir .dah command-center` prints the exact loopback URL for the local
dashboard. It never opens an execution or approval path; see
`docs/command_center.md` for the boundary and options.

## Run the MCP stdio proxy

The repository includes a dependency-free demo server and a fully classified
proxy configuration:

```bash
dah --workdir .dah-demo mcp-proxy --config examples/mcp-proxy.yaml
```

That command speaks MCP on stdin/stdout, so it is normally placed in an MCP
client's server configuration rather than run interactively:

```json
{
  "command": "dah",
  "args": [
    "--workdir",
    ".dah",
    "mcp-proxy",
    "--config",
    "/absolute/path/to/mcp-proxy.yaml"
  ]
}
```

The YAML `tools` map is the authority boundary. Each upstream tool declares its
side effect, target argument, conservative cost, dry-run support, target scope,
and argument provenance. Unknown fields fail configuration loading. Tools the
upstream advertises but the operator did not map remain visible in `tools/list`
but are blocked if called.

Approval does not hold a fragile process open:

1. The first `tools/call` returns `isError: true` with a durable approval id.
2. The operator runs `dah --workdir .dah approve <approval_id> --note "..."`
   with the configured operator key and public trust binding.
3. The client retries the exact same tool params.
4. The proxy recognizes the payload fingerprint, re-checks current policy,
   consumes the single-use approval, and forwards the call.

The proxy may restart between steps 1 and 3. Any changed parameter creates a
different authorization hash and cannot use the approval. Rejections remain
terminal for the approval window, preventing an agent from spamming identical
re-proposals.

The fingerprint also binds the runner, user, workspace, authoritative tool
contract, and upstream transport identity. Changing the server command or URL,
side effect, cost, target scope, or workspace root cannot inherit a stale
approval.

The upstream command is always an argument vector and is launched without a
shell. Stdout remains protocol-only; server diagnostics inherit stderr.
For production local upstreams, add a required `server.artifact_integrity`
manifest so the executable and each declared entrypoint, lockfile, or package
artifact are verified before launch. See
`docs/runtime_artifact_integrity.md` for the schema, rotation procedure, and
limits. Configurations without a manifest remain explicitly `unverified` in
read-only diagnostics.
Also configure `server.launch_environment` with an explicit `server.cwd` to
remove ambient child-environment authority. See
`docs/launch_envelope_integrity.md`; omitted launch settings remain visibly
`inherited_unrestricted` for compatibility.

v0.3 negotiates at most MCP protocol revision `2025-06-18`. Newer clients are
downgraded during `initialize` so an upstream server cannot advertise the
experimental task-augmented calls added in `2025-11-25`, which this release
does not yet govern. The complete core `tools/call` params object is bound into
the approval fingerprint. Only the ephemeral `_meta.progressToken` is excluded
so a client may legitimately replace its correlation token on an exact retry.

## Run the Streamable HTTP upstream proxy

Remote MCP servers use the same local stdio-facing shape:

```powershell
$env:REMOTE_MCP_AUTH = "Bearer <token>"
dah --workdir .dah mcp-http-proxy --config examples/mcp-http-proxy.yaml
```

The proxy sends MCP POST requests to the configured HTTPS endpoint, accepts
JSON or SSE responses, maintains the optional MCP session id, and attempts a
session DELETE on shutdown. Auth values come from environment variables rather
than YAML. Remote redirects are refused, response sizes are bounded, and plain
HTTP is allowed only for loopback test servers.

The policy, approval, budget, exact-retry, and evidence behavior is identical
to the stdio upstream. See `docs/streamable_http.md` for configuration,
transport behavior, and current bidirectional-streaming limits.

### Run against a real MCP server

The repository now includes a live integration with the official filesystem
reference server:

```bash
python examples/filesystem/live_demo.py
```

It downloads a pinned server release with `npx`, creates a new disposable
workspace, permits a real read, blocks an unapproved mutation, holds a real
write, asks the operator to approve it, repeats the exact MCP call, and verifies
the resulting evidence chain. The upstream server and Defiant independently
confine paths to the same workspace. Run with `--yes` for a non-interactive
smoke test. See `examples/filesystem/README.md`.

### Connect VS Code and Copilot agents

The committed Windows workspace profile at `.vscode/mcp.json` connects VS Code
to the same official filesystem server through Defiant and binds evidence to
the `vscode-copilot` runner identity. The root `.mcp.json` provides the current
Copilot CLI format and binds its evidence to `copilot-cli-mcp`. Both profiles
are confined to the disposable `examples/vscode_agent/workspace` folder.

The workspace hook at `.github/hooks/defiant.json` covers the separate native
tool path used by local agents and Copilot CLI. It blocks terminal, subagent,
unknown, out-of-workspace, and enforcement-mutation attempts; local writes are
held for exact human approval and completed by a matching `PostToolUse`.

Open the repository folder in VS Code and follow
`examples/vscode_agent/README.md`. It documents both proofs: the MCP transport
boundary and the stronger native hook path.

### Connect Codex

The project-scoped `.codex/config.toml` connects Codex to the Defiant filesystem
proxy, while `.codex/hooks.json` governs supported native Codex tools. The
integration uses separate `codex-hook` and `codex-mcp` runner identities,
model-bound exact approvals, repository-root discovery from nested working
directories, and Codex's official hook output dialect.

Trust the project, restart Codex, review the exact definitions with `/hooks`,
and confirm the server with `/mcp`. Follow `docs/codex_runner.md` for the read,
approval, exact-retry, evidence, and native-bypass proofs.

## Architecture

```
adapter (MCP or hook) ->  orchestrator  ->  policy engine
                              |                  |
                              |            budget ledger
                              |                  |
                              |            approval store  (durable, expiring,
                              |                  |          bound to full action)
                              |                  v
                              +--> evidence store (append-only, hash-chained)
                              |
                              +--> capability grant --> tool registry --> effect
```

The adapter boundary is the design decision that matters most. Hermes, OpenClaw, NanoClaw, Claude Code, and Codex do not hand you a plan and wait for permission — they run their own loop and call their own tools. So the adapter contract here is not "produce a plan for review." It is: intercept a tool call at the transport boundary, hand it to the harness as a `ProposedAction`, and return the harness's outcome to the agent as the tool's result. Since that boundary is overwhelmingly MCP `tools/call`, vendor-neutrality is a property of the design rather than a roadmap item. See `docs/adapter_contract.md`.

## Repository layout

```
src/defiant_agent_harness/
  contracts.py          request, action, decision, evidence, capability grant, provenance
  policy/               deterministic engine + YAML rule packs
  approvals/            durable, expiring, action-bound approval queue
  budgets/              exact-decimal, action-bound reservation and settlement
  command/              integrity-gated projection + loopback-only local UI
  evidence/             append-only hash-chained JSONL store
  tools/                capability-gated registry + reference tools
  adapters/             adapter contract (MCP-shaped) + mock adapter
  mcp/                  strict config + stdio/HTTP transports + tools/call proxy
  hooks/                native PreToolUse/PostToolUse adapter + durable correlation
  orchestrator/         the control loop
  cli/                  local controls + MCP proxy entry point
docs/                   architecture, contracts, threat model, policy examples
tests/                  policy, evidence, grants, approvals, budget, red team
```

## Policy

Rules are YAML so a consultant can read them and a compliance reviewer can audit them without reading Python. The engine is deterministic, strictest-wins, default-deny for side effects, and refuses any tool not declared in a loaded pack's `known_tools` — an unclassified tool must never inherit a permissive rule written for a different one.

```yaml
- id: block_untrusted_side_effect
  side_effect_at_least: external_send
  max_payload_trust: derived
  effect: block
  reason: >
    Payload derives from untrusted external content. Knowledge can inform
    execution; knowledge cannot authorize execution.
```

Ships with `default`, `merchant_services`, and `legal_intake`. Vertical packs layer on top of the default and can tighten it but never loosen it below the engine's own default-deny floor.

## Evidence

One JSONL line per record, each carrying the hash of the record before it.
Payload and output bodies are represented by hashes, while operational metadata
such as targets and identities remains visible. Evidence must therefore be
handled as confidential business data. Every record carries a schema version,
policy version, ruleset hash, and decision-input snapshot. The store refuses to
append when the existing chain is corrupt.

Durable approvals necessarily retain the full held action in the local
`approvals.json` state file so it can resume after a restart. Protect the state
directory accordingly; it is not an export artifact.

See `docs/evidence_contract.md` for the field-by-field evidence contract,
`docs/evidence_signing.md` for offline-verifiable exports,
`docs/operator_identity.md` for signed approval authority,
`docs/approval_reconciliation.md` for crash recovery,
`docs/state_integrity.md` for cross-store auditing, and
`docs/command_core.md` for the read-only snapshot contract. See
`docs/command_center.md` for the local UI and HTTP boundary.

## Tests

```bash
pytest
```

Offline tests plus one opt-in live integration test cover Command Core,
Command Center, and both the MCP and native-hook boundaries. The suite includes a
real subprocess MCP flow across initialization, tool discovery, allow, durable
approval, proxy restart, exact-call retry, destructive block, unmapped-tool
block, and evidence-chain verification. Native-hook tests cover exact approval
retry, payload changes, terminal and subagent bypass, unknown tools,
out-of-workspace paths, guardrail self-modification, result correlation,
evidence sealing, hostile container and copy hooks, and mutation immediately
after canonical capture. Known-result tests crash before settlement, after settlement,
after evidence, and before approval consumption, then verify restart without
tool replay, duplicate debit, or duplicate evidence. Authority-lock tests cover
same-thread reentrancy, thread and process contention, crash release, startup
exclusion, and tool-call serialization. Set `DAH_LIVE_MCP=1` to add the pinned
official filesystem server to a test run.

## Status

v0.88 — local control loop, generic MCP stdio and Streamable HTTP upstreams,
preview native VS Code/Copilot and Codex hook adapters, a read-only Command Core
snapshot, a loopback-only read-only Command Center UI, and crash-safe operator
reconciliation for approval-backed and approval-free uncertain executions,
known-result completion recovery, deterministic local operation recovery,
cross-store integrity gating, cross-process authority serialization,
durable full-authority-profile continuity and explicit staged rotation,
crash-safe exact-replay publication of profile-bound authority observations,
read-only reconstruction and verification of completed authority manifests,
read-only active-publication phase plus target, mixed-generation checkpoint,
stable completed-checkpoint store commitment verification, and sealed semantic
authority-publication intent/checkpoint records with exact predecessor and
originating-intent transition links plus a sealed monotonic publication
continuity ratchet,
optional authority-bound external signing of the retained publication head
with exact-startup verification and a one-checkpoint refresh window,
serialized, independently reconstructed publication-witness issuance that
refuses inconsistent or concurrently changing authority state, plus
crash-durable final-link publication and exact post-write byte verification,
content-addressed local runtime artifact assurance with opt-in closed declared
dependency roots,
restricted and authority-bound local process launch envelopes,
authority-bound state-root identity, hardened local persistence, and optional
profile-bound native Windows private-state ACL assurance,
profile-bound control-plane path isolation for governed workspace tools,
profile-bound workspace-root identity and replacement detection,
profile-bound crash-safe evidence-head checkpointing,
profile-bound operator-signed external evidence-head witnessing with optional
maximum unwitnessed-record lag plus serialized exact-snapshot issuance and
crash-durable verified output,
fixed fail-closed pre-parse resource ceilings across durable state, evidence,
MCP transports, native hooks, and MCP configuration,
strict bounded and ambiguity-free authority YAML parsing for policy packs and
MCP configuration,
fixed pre-construction YAML nesting and node-count ceilings,
fixed pre-transformation MCP authority-configuration collection ceilings,
strict UTF-8 and duplicate-safe JSON parsing across durable state, evidence,
MCP transports, native hooks, and signed external documents,
fixed 64 MiB parse and publication ceilings for request evidence exports,
fixed pre-decoder JSON nesting and lexical-token ceilings,
fixed pre-decoder JSON string-token and number-token ceilings with finite
floating-point conversion,
fixed trusted-public-key count, per-key, and aggregate key-set ceilings,
fixed complete-policy pack, rule, known-tool, per-field, and aggregate-list
complexity ceilings,
fixed per-item and complete-ruleset policy text ceilings,
fixed single-pass governed-payload depth, node, text, and aggregate substring
matching ceilings,
fixed lazy tool-name/target glob-subject and decision-wide glob-work ceilings,
fixed bounded canonical action fingerprints with a final live capability check,
fixed per-mapping canonical-entry ceilings before key traversal or sorting,
fixed aggregate canonical mapping sort-work ceilings before encoder sorting,
fixed canonical mapping-key eligibility before value traversal or sorting,
fixed complete canonical mapping-key token validation before any mapping value,
fixed detached validated canonical snapshots before encoder traversal,
fixed validated-snapshot ownership without post-validation deep copies,
fixed complete canonical-value byte preflight before sorting or encoding,
fixed pre-render canonical-string token byte ceilings,
fixed pre-encoding canonical-number token ceilings,
fixed governed-request and provenance metadata complexity ceilings,
fixed validated built-in snapshots for request and provenance collections,
fixed validated built-in scalar ownership across governed contracts,
fixed validated built-in ownership across policy decisions, capability grants,
and evidence records,
fixed validated snapshot ownership across policy rules, known tools, and
authority inputs,
fixed sealed policy runtime rules, known-tool patterns, identity metadata, and
defensive authority projections,
fixed bounded exact policy evaluation context shared by matching and evidence,
fixed bounded and sealed operation-journal snapshots with symmetric I/O limits,
fixed bounded exact native-hook events shared by retry identity, authorization,
targeting, payload, and completion,
fixed bounded and sealed authority-profile and operator-trust continuity state
with defensive projections, descriptor-backed recovery reads, detached
publication revalidation, and symmetric I/O limits,
fixed detached and validated runtime-artifact assurance state with exact scalar
ownership and symmetric 64 KiB capture, recovery-read, and publication limits,
fixed detached and validated launch-envelope assurance state with exact scalar
ownership and symmetric 64 KiB capture, recovery-read, and publication limits,
fixed detached and validated state-storage assurance with exact scalar
ownership and symmetric 64 KiB capture, recovery-read, and publication limits,
fixed detached and validated control-plane isolation and workspace-root
integrity observations with independent symmetric 64 KiB limits,
fixed bounded and sealed native-hook authorization/completion correlation state
with defensive projections and copy-on-write transitions,
fixed bounded and sealed approval records and held authority snapshots with
defensive projections, key binding, and copy-on-write lifecycle transitions,
fixed detached and validated budget-ledger snapshots with normalized accounting
inputs and symmetric capture, recovery-read, and publication limits,
fixed detached and validated evidence-head checkpoint snapshots with symmetric
64 KiB capture, recovery-read, and publication limits,
fixed detached and validated external-witness policy snapshots with symmetric
256 KiB capture, recovery-read, and publication limits,
fixed bounded and sealed pre-adapter tool-call translation,
fixed bounded and sealed post-execution tool-result capture,
offline-verifiable signed evidence exports, signed operator authority, and
durable downgrade-resistant operator trust enrollment. Not a hosted platform.
The hook controls tool calls that emit supported lifecycle events. Direct
process activity outside those events, and the documented fail-open
hook-timeout behavior, still require OS/network isolation. See
`docs/architecture.md`, `docs/approval_reconciliation.md`,
`docs/authorization_reconciliation.md`, `docs/operation_journal.md`,
`docs/validated_budget_ledger_snapshot.md`,
`docs/validated_evidence_head_snapshot.md`,
`docs/validated_evidence_witness_policy_snapshot.md`,
`docs/known_result_recovery.md`, `docs/authority_lock.md`,
`docs/authority_profile.md`,
`docs/authority_publication_recovery.md`,
`docs/authority_publication_manifest_verification.md`,
`docs/active_authority_publication_verification.md`,
`docs/active_authority_publication_commitments.md`,
`docs/active_authority_publication_checkpoint_commitments.md`,
`docs/completed_authority_publication_checkpoint_verification.md`,
`docs/sealed_authority_publication_records.md`,
`docs/sealed_authority_publication_transitions.md`,
`docs/authority_publication_continuity.md`,
`docs/authority_publication_witness.md`,
`docs/runtime_artifact_integrity.md`,
`docs/validated_runtime_artifact_state_snapshot.md`,
`docs/launch_envelope_integrity.md`,
`docs/validated_launch_envelope_state_snapshot.md`,
`docs/state_storage_integrity.md`,
`docs/validated_state_storage_state_snapshot.md`,
`docs/validated_filesystem_authority_state_snapshots.md`,
`docs/control_plane_isolation.md`,
`docs/workspace_root_integrity.md`,
`docs/evidence_head_integrity.md`,
`docs/evidence_head_witness.md`,
`docs/bounded_ingestion.md`,
`docs/authority_configuration_integrity.md`,
`docs/strict_json_integrity.md`,
`docs/bounded_evidence_exports.md`,
`docs/json_structural_limits.md`,
`docs/json_scalar_limits.md`,
`docs/trusted_key_limits.md`,
`docs/policy_complexity_limits.md`,
`docs/policy_text_limits.md`,
`docs/policy_payload_matching_limits.md`,
`docs/policy_glob_matching_limits.md`,
`docs/action_hashing_limits.md`,
`docs/canonical_mapping_key_contract.md`,
`docs/complete_mapping_key_preflight.md`,
`docs/validated_canonical_snapshot.md`,
`docs/validated_snapshot_ownership.md`,
`docs/validated_contract_collection_snapshots.md`,
`docs/validated_scalar_ownership.md`,
`docs/validated_authority_record_ownership.md`,
`docs/validated_policy_snapshot_ownership.md`,
`docs/sealed_policy_runtime_state.md`,
`docs/validated_policy_context_snapshot.md`,
`docs/validated_operation_journal_snapshot.md`,
`docs/validated_native_hook_event_snapshot.md`,
`docs/sealed_authority_continuity_state.md`,
`docs/bounded_authority_continuity_io.md`,
`docs/sealed_native_hook_correlation_state.md`,
`docs/canonical_mapping_sort_work.md`,
`docs/canonical_mapping_limits.md`,
`docs/canonical_value_preflight.md`,
`docs/canonical_string_limits.md`,
`docs/canonical_number_limits.md`,
`docs/governed_request_limits.md`,
`docs/tool_call_limits.md`,
`docs/tool_result_limits.md`,
`docs/yaml_structural_limits.md`,
`docs/mcp_configuration_limits.md`,
`docs/state_integrity.md`,
`docs/evidence_signing.md`,
`docs/operator_identity.md`,
`docs/command_center.md`, `docs/streamable_http.md`, `docs/native_hooks.md`, and
`docs/codex_runner.md`.
