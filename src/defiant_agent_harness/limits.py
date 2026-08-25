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
MAX_MCP_CONFIG_BYTES = 1 * MIB
MAX_POLICY_PACK_BYTES = 1 * MIB
