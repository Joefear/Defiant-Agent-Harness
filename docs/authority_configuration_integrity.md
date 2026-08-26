# Authority configuration integrity

Defiant v0.27 makes the interpretation of operator-authored authority YAML
explicit and fail closed. Policy packs and MCP proxy configuration use the same
`strict_yaml_v2` parser profile before a harness or upstream process is created.

## Parser contract

The profile:

- decodes strict UTF-8 only;
- limits each MCP configuration and each policy pack to 1 MiB before parsing;
- limits mapping/sequence nesting to 64 and scalar/collection nodes to 100,000
  before construction;
- uses PyYAML safe construction, so arbitrary Python object tags are refused;
- rejects every YAML alias;
- rejects duplicate mapping keys at any nesting depth instead of accepting a
  last-key-wins interpretation; and
- rejects unknown top-level policy-pack fields.

Aliases are refused even when their intended use is benign. This keeps the
reviewed document tree direct and prevents a compact input from constructing a
shared or amplified object graph. Duplicate-key diagnostics identify only the
line number; they do not echo the key or nearby source text.

## Failure behavior

An unreadable, oversized, invalid, aliased, or duplicate-key policy pack raises
a `PolicyError` before state or workspace initialization. MCP configuration
fails before a local upstream subprocess or remote session is created. CLI
diagnostics include only the configuration filename and a sanitized reason,
never the source snippet or absolute path.

The normalized policy rules, known tools, and other authority inputs continue
to determine the existing `ruleset_hash`. The parser profile does not create a
second policy language or weaken strictest-wins and default-deny behavior.

## Read-only projection

Command Core schema `0.33.0` reports the static parser profile, both refusal
flags, and the policy-pack byte ceiling. Command Center renders this metadata
read-only. Neither surface receives configuration source, uploads a pack,
changes a limit, accepts a parser exception, rotates a profile, or launches an
upstream process.

## Limits

This control removes YAML interpretation ambiguity; it does not establish that
a clear policy is correct or complete. Operators still must review tool
classifications, write adversarial policy tests, protect configuration paths,
and use immutable deployment controls where required. The ceiling is per file;
in-process callers remain trusted under the existing Python boundary.

This release adds no DKE, Spartan, remote Command, or Command Center authority.

v0.28 extends the same ambiguity-free principle to JSON without changing this
YAML contract. See `strict_json_integrity.md`.

v0.33 adds complete-ruleset collection ceilings without changing the YAML
parser profile or per-file byte limit. See `policy_complexity_limits.md`.

v0.34 advances the parser profile to `strict_yaml_v2` by adding fixed
pre-construction depth and node ceilings. See `yaml_structural_limits.md`.

v0.35 adds MCP-specific per-collection and aggregate ceilings after YAML
construction and before configuration transformation. See
`mcp_configuration_limits.md`.

v0.36 adds complete-ruleset per-item and aggregate policy text ceilings after
YAML construction and before rule construction or hashing. See
`policy_text_limits.md`.
