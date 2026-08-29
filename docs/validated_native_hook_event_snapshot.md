# Validated native-hook event snapshot

Defiant v0.59 hardens native `PreToolUse` and `PostToolUse` translation as an
authority ownership boundary. Each public gate or adapter entry captures one
bounded canonical event observation before it reads tool identity, arguments,
correlation metadata, targets, or results.

## One observation per decision

The pre-tool gate now derives all of these values from the same owned built-in
tree:

- native and canonical tool names;
- model attribution and synthetic or supplied tool-use id;
- approval retry and external-execution identity;
- workspace target classification;
- governed `ToolCall` arguments and provenance.

The post-tool gate similarly uses one observation for tool/input correlation
and result completion. A caller mutation immediately after capture cannot
change the authorization payload, and a matching post event is compared with
the exact pre-tool identity rather than a later reading of the original object.

## Canonical capture contract

In-process entries use the fixed authority canonical profile. Capture reads
built-in dictionary, list, and tuple storage directly, normalizes accepted
scalar subclasses to exact built-ins, detects container drift, rejects cycles
and unsupported values, and enforces fixed depth, node, mapping, sort-work,
scalar, number, string-token, and canonical-byte ceilings.

The hook adapter no longer uses `deepcopy()`. Overridden copy, lookup,
membership, iteration, formatting, or scalar rendering methods on accepted
built-in subclasses cannot manufacture a second unvalidated event. Invalid
input fails before approvals, hook execution correlation, or evidence is
created, and the error does not echo rejected content.

The executable hook remains additionally protected by the existing 10 MiB
bounded read and strict duplicate-safe JSON parser before the in-process
snapshot. That transport limit measures source bytes; the canonical snapshot
uses the separately published fixed authority ceilings.

## Compatibility and read-only posture

Ordinary JSON hook requests preserve their existing tool mapping, approval,
retry, target, result, and evidence behavior. MCP proxy requests are unchanged:
they already enter through the bounded strict JSON transport and are outside
this release's authority gap.

Command Core schema `0.67.0` reports
`validated_native_hook_event_snapshot: true` under
`authority_configuration`. Command Center renders only that static posture. It
receives no hook event, tool arguments, target, result, approval note, mutation
route, or execution control.

This release adds no DKE, Spartan, remote Command, or Command Center authority.
Direct runtime activity that emits no supported hook event and documented
fail-open runner timeouts remain deployment-containment concerns.
