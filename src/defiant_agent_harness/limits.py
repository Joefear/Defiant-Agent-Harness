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

# MCP HTTP already uses the same 10 MiB response ceiling. Apply it symmetrically
# to local stdio and native-hook event documents.
MAX_MCP_MESSAGE_BYTES = 10 * MIB
MAX_HOOK_EVENT_BYTES = 10 * MIB

# Operator-authored YAML should remain reviewable and is never a bulk payload.
MAX_MCP_CONFIG_BYTES = 1 * MIB
MAX_POLICY_PACK_BYTES = 1 * MIB
