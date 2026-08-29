# MCP authority-configuration collection limits

Defiant v0.35 bounds collection-driven work in operator-authored MCP proxy
configuration. The existing 1 MiB and `strict_yaml_v2` ceilings constrain one
document's bytes and constructed YAML graph, but compact collections can still
amplify schema validation, path handling, runtime object construction, hashing,
and local-process startup.

## Fixed ceilings

The loader applies these implementation contracts:

| Scope | Maximum |
| --- | ---: |
| Any one MCP configuration collection | 4,096 items |
| Dependency file pins across all declared roots | 8,192 pins |
| Launch-environment entries across all four fields | 4,096 entries |

The per-collection ceiling covers the effective command argument vector,
`server.header_env`, the root `tools` map, artifact pins, dependency roots,
each dependency root's `files`, and the launch-environment `inherit`,
`secret_env`, `set`, and `allow_unsafe` collections. A CLI command override is
the effective command and is subject to the same ceiling as YAML input.

Aggregate dependency count is the sum of the supplied `files` lengths across
all roots. Aggregate launch-environment count is the sum of all entries in its
four fields. Duplicate or conflicting entries count as supplied; they are not
deduplicated to evade a ceiling and remain subject to normal schema checks.
Exact limits are accepted and the first item beyond a limit is refused.

## Ordering and failure behavior

Collection preflight runs immediately after strict YAML parsing and strict
top-level mapping checks. It precedes element validation, path construction or
resolution, runtime artifact objects, tool classifications, launch-environment
sorting, dependency hashing, remote-session creation, and local subprocess
startup. Oversized configuration therefore creates no partial authority and
performs no pin verification or launch.

Diagnostics contain only a stable field label, count class, and fixed maximum.
They do not echo command arguments, tool names, header values, environment
names or values, artifact paths, dependency paths, or absolute configuration
paths.

## Read-only projection

Command Core schema `0.67.0` publishes
`mcp_config_collection_items`, `mcp_dependency_file_pins`, and
`mcp_launch_environment_entries` under `resource_limits`, plus the static
`mcp_collection_preflight` posture. Command Center renders those values but
cannot upload configuration, change a ceiling, accept an exception, hash a
manifest, or start an upstream.

## Limits of the control

These ceilings bound configuration-driven counts, not the bytes or contents of
the referenced runtime files. Runtime artifact verification retains its own
per-root inventory ceilings and hashes every accepted declared file. The
control is not a wall-clock, CPU, memory, process, filesystem, or network quota.
The existing Python boundary also treats direct in-process construction of
configuration dataclasses as trusted; v0.35 hardens the file/CLI loader used by
the MCP proxy authority path.

Operators must still protect configuration and artifact paths, review tool
classifications and launch inputs, and use OS isolation and resource controls.
This release adds no DKE, Spartan, remote Command, or Command Center authority.
