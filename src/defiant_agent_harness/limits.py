"""Fixed resource ceilings for data crossing Defiant trust boundaries."""

MIB = 1024 * 1024

# Aggregate JSON state remains bounded while append-only evidence may grow
# across any number of individually bounded records.
MAX_DURABLE_JSON_BYTES = 64 * MIB
MAX_EVIDENCE_RECORD_BYTES = 16 * MIB

# Request-scoped handoff artifacts are bounded independently from the live,
# append-only evidence history. The limit applies before parsing and before an
# export is published or emitted.
MAX_EVIDENCE_EXPORT_BYTES = 64 * MIB

# The crash-recovery journal contains authority-bearing prepared operations.
# Keep its canonical snapshot and durable JSON publication under one symmetric
# ceiling so the writer cannot create a journal the recovery reader refuses.
MAX_OPERATION_JOURNAL_BYTES = 4 * MIB

# Operator trust and the complete authority profile are independently bounded
# continuity roots. Their canonical in-process snapshot, durable publication,
# and recovery read all use the same store-specific ceilings.
MAX_AUTHORITY_PROFILE_STATE_BYTES = 1 * MIB
MAX_OPERATOR_TRUST_STATE_BYTES = 1 * MIB

# Native-hook correlation retains the exact authorization context needed to
# bind PostToolUse completion to its PreToolUse decision. Keep canonical
# capture, durable recovery reads, and atomic publication under the same
# explicit ceiling. This preserves the established durable-state allowance.
MAX_HOOK_EXECUTION_STATE_BYTES = MAX_DURABLE_JSON_BYTES

# Approval records retain the exact action, request, policy decision, and
# operator attestations that authorize execution. Apply one symmetric ceiling
# to in-process canonical capture, recovery reads, and atomic publication while
# preserving the established aggregate durable-state allowance.
MAX_APPROVAL_STATE_BYTES = MAX_DURABLE_JSON_BYTES

# The shared strict JSON loader scans structure and scalar lexemes before
# constructing Python objects. Count container nesting and lexical
# value/container/string starts; punctuation inside strings is ignored. String
# length is the number of source characters between quotes, including escape
# sequences. Numeric length is the complete source token, including sign,
# fraction, and exponent.
MAX_JSON_NESTING_DEPTH = 64
MAX_JSON_LEXICAL_TOKENS = 1_000_000
MAX_JSON_STRING_TOKEN_CHARACTERS = 8 * MIB
MAX_JSON_NUMBER_TOKEN_CHARACTERS = 1_024

# Trusted public-key collections are operator-supplied authority inputs. Bound
# the number of filesystem/crypto operations, each PEM, and aggregate bytes
# loaded by one trust-set construction or verification request.
MAX_TRUSTED_PUBLIC_KEYS = 1_024
MAX_TRUSTED_PUBLIC_KEY_BYTES = 64 * 1024
MAX_TRUSTED_PUBLIC_KEY_SET_BYTES = 8 * MIB

# MCP HTTP already uses the same 10 MiB response ceiling. Apply it symmetrically
# to local stdio and native-hook event documents.
MAX_MCP_MESSAGE_BYTES = 10 * MIB
MAX_HOOK_EVENT_BYTES = 10 * MIB

# Operator-authored YAML should remain reviewable and is never a bulk payload.
# Structural preflight counts each scalar plus each mapping/sequence start as
# one node before PyYAML constructs the authority document.
MAX_MCP_CONFIG_BYTES = 1 * MIB
# MCP configuration is authority input, not a bulk manifest. Bound each
# collection before transforming entries into runtime objects or resolving
# paths, and separately bound the aggregate startup work that spans fields.
MAX_MCP_CONFIG_COLLECTION_ITEMS = 4_096
MAX_MCP_DEPENDENCY_FILE_PINS = 8_192
MAX_MCP_LAUNCH_ENVIRONMENT_ENTRIES = 4_096
MAX_POLICY_PACK_BYTES = 1 * MIB
MAX_YAML_NESTING_DEPTH = 64
MAX_YAML_NODES = 100_000

# Policy is evaluated for every governed action. Bound the complete loaded
# ruleset, not only each YAML file, so many individually valid packs cannot
# amplify matching, normalization, or hashing without limit.
MAX_POLICY_PACKS = 64
MAX_POLICY_RULES = 4_096
MAX_POLICY_KNOWN_TOOLS = 4_096
MAX_POLICY_RULE_FIELD_ITEMS = 4_096
MAX_POLICY_RULE_LIST_ITEMS = 65_536
# Text volume is counted across the complete loaded ruleset, including the
# synthetic registry pack, before Rule construction or authority hashing.
MAX_POLICY_TEXT_ITEM_CHARACTERS = 4_096
MAX_POLICY_TEXT_CHARACTERS = 8 * MIB

# Payload substring rules operate on a flattened, case-normalized view of the
# governed action. Bound that one-time materialization and the aggregate search
# work across every applicable rule in one policy decision.
MAX_POLICY_MATCH_PAYLOAD_NESTING_DEPTH = 64
MAX_POLICY_MATCH_PAYLOAD_NODES = 100_000
MAX_POLICY_MATCH_PAYLOAD_CHARACTERS = 1 * MIB
MAX_POLICY_PAYLOAD_MATCH_WORK_UNITS = 64 * MIB

# Glob subjects are action-controlled while patterns are bounded authority
# text. Bound both subject size and aggregate classification/rule search work
# across one policy decision.
MAX_POLICY_MATCH_TOOL_NAME_CHARACTERS = 4_096
MAX_POLICY_MATCH_TARGET_CHARACTERS = 1 * MIB
MAX_POLICY_GLOB_MATCH_WORK_UNITS = 64 * MIB

# Evaluation context is authority-bearing request metadata, not a bulk payload.
# Bound and own one exact string-to-string observation before any rule reads it
# and before the same observation is retained in decision evidence.
MAX_POLICY_CONTEXT_ENTRIES = 64
MAX_POLICY_CONTEXT_KEY_CHARACTERS = 256
MAX_POLICY_CONTEXT_VALUE_CHARACTERS = 4_096
MAX_POLICY_CONTEXT_CHARACTERS = 256 * 1024

# Every policy decision, approval, capability grant, and evidence record binds
# the governed action through canonical SHA-256 fingerprints.  Bound action-
# controlled structure before JSON encoding and bound the encoded byte stream
# consumed by each fingerprint calculation.  The byte ceiling accommodates
# the worst-case canonical escaping of one maximum-size MCP or hook document
# without turning a transport-valid call into an authority bypass.
MAX_ACTION_HASH_NESTING_DEPTH = 64
MAX_ACTION_HASH_NODES = 1_100_000
# Canonical JSON sorts each mapping's keys. Keep one attacker-controlled sort
# from approaching the broader node allowance even when the encoded value fits
# the complete byte ceiling.
MAX_ACTION_HASH_MAPPING_ENTRIES = 65_536
# Charge every canonical key-token byte once per idealized comparison round and
# share the budget across all mappings in one fingerprint. This bounds long,
# common-prefix key amplification in addition to mapping cardinality.
MAX_ACTION_HASH_MAPPING_SORT_WORK_UNITS = 64 * MIB
MAX_ACTION_HASH_SCALAR_CHARACTERS = 8 * MIB
MAX_ACTION_HASH_NUMBER_CHARACTERS = 1_024
MAX_ACTION_HASH_CANONICAL_BYTES = 64 * MIB
# Python's JSON encoder emits one complete escaped string as a single chunk.
# Refuse a token that cannot fit in the complete canonical byte ceiling before
# the encoder can materialize that expanded chunk in memory.
MAX_ACTION_HASH_STRING_TOKEN_BYTES = MAX_ACTION_HASH_CANONICAL_BYTES

# A ToolCall exists before an adapter can construct a ProposedAction. Bound its
# explicit transport identity fields independently, then apply the complete
# bounded canonical-value contract above to its combined arguments and
# transport parameters before any adapter translation work begins.
MAX_TOOL_CALL_NAME_CHARACTERS = 4_096
MAX_TOOL_CALL_IDENTIFIER_CHARACTERS = 4_096

# A governed request is consumed before an action exists: its task reaches the
# adapter, its allowlist drives request-scope authorization, and its context and
# provenance may be copied into approvals and evidence. Bound collection and
# constructed-text volume at contract creation rather than relying on later
# action, state-file, or evidence ceilings.
MAX_REQUEST_TEXT_ITEM_CHARACTERS = 1 * MIB
MAX_REQUEST_IDENTIFIER_CHARACTERS = 4_096
MAX_REQUEST_ALLOWED_TOOLS = 4_096
MAX_REQUEST_ALLOWED_TOOL_CHARACTERS = 4_096
MAX_PROVENANCE_REFS = 100_000
MAX_PROVENANCE_TEXT_ITEM_CHARACTERS = 8_192
MAX_REQUEST_TEXT_CHARACTERS = 8 * MIB
MAX_PROVENANCE_TEXT_CHARACTERS = 8 * MIB

# Tool handlers and external runtimes return data only after execution may have
# occurred. Keep summaries small enough for durable evidence and apply the
# bounded canonical-value contract to output before completion is claimed.
MAX_TOOL_RESULT_SUMMARY_CHARACTERS = 64 * 1024
