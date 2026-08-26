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
