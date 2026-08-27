# YAML structural limits

Defiant v0.34 advances operator-authored authority YAML to the
`strict_yaml_v2` parser profile. Before PyYAML constructs a policy pack or MCP
proxy configuration, an event-stream preflight enforces two fixed ceilings:

- maximum mapping/sequence nesting depth: 64; and
- maximum constructed nodes: 100,000.

A node is one scalar value or one mapping/sequence start. Mapping keys count as
scalars, and empty mappings and sequences each count as a node. Aliases remain
refused rather than counted as expansions. The existing strict UTF-8, 1 MiB
per-document byte ceilings, safe construction, and duplicate-key refusal remain
unchanged.

## Failure behavior

Depth and node counts are checked while consuming parser events, before the
safe loader constructs the authority object. An over-limit policy pack fails
before state or workspace initialization. An over-limit MCP configuration fails
before local subprocess or remote-session creation. Diagnostics identify only
the fixed ceiling and document label; they do not echo source content or an
absolute path.

Both exact limits are accepted. The first node or collection level beyond a
limit is refused. These values are implementation contracts, not environment
variables or policy settings.

## Read-only projection

Command Core schema `0.48.0` publishes `yaml_nesting_depth`, `yaml_nodes`, and
the `strict_yaml_v2` profile. Command Center displays that fixed posture. It
cannot upload authority YAML, change either ceiling, accept an exception, or
launch an upstream.

## Limits of the control

The preflight bounds constructed structure; it is not a wall-clock, CPU, or
memory quota and does not stream construction. The existing 1 MiB byte ceiling
bounds individual scalar content. Policy-specific collection limits separately
bound the complete ruleset across files. Operators must still review policy and
MCP authority, protect configuration paths, and apply OS resource controls.

v0.35 adds lower semantic collection ceilings for MCP configuration after this
parser preflight and before entry transformation. See
`mcp_configuration_limits.md`.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
