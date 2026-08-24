# Policy examples

Rules are YAML so a consultant can read them, a client can be shown them, and a compliance reviewer can audit them without reading Python.

Each pack is limited to 1 MiB and parsed with the `strict_yaml_v1` safe-loader
profile. YAML aliases, duplicate mapping keys at any depth, invalid UTF-8, and
unknown top-level pack fields fail closed. This ensures the reviewer and parser
cannot silently disagree about which repeated key controls authority.

## How a decision is made

1. The registry validates the tool, authoritative side-effect level, and any
   workspace path boundary.
2. If the tool is not in any loaded pack's `known_tools`, block.
3. Otherwise evaluate every rule. All present conditions must match.
4. Strictest outcome wins: `block` > `approval_required` > `allow`.
5. If nothing matched: block a side effect, allow no side effect.

Every decision records the ruleset hash and a snapshot of its inputs, so it can be replayed later against the exact rules that produced it.

## Conditions

| condition | matches when |
|---|---|
| `tools` | tool name matches any glob in the list |
| `side_effect_at_least` | action's side effect is at or above this level |
| `targets` | target matches any glob in the list |
| `payload_contains` | any listed term appears in the payload, case-insensitive |
| `max_payload_trust` | payload trust is *worse* than this ceiling |
| `sensitivities` | request sensitivity is in the list |

Side-effect order, low to high: `none`, `local_write`, `external_send`, `external_publish`, `spend`, `destructive`.

Trust order, best to worst: `trusted`, `derived`, `untrusted`.

## Outcomes

| field | effect |
|---|---|
| `effect` | `allow`, `block`, or `approval_required` |
| `reason` | shown to the operator verbatim; write it for a non-expert |
| `approval_scope` | what exactly the human is agreeing to |
| `redactions` | fields to suppress in operator-facing display |

## Worked examples

**Everything outbound needs a human.**

```yaml
- id: approve_outbound_send
  side_effect_at_least: external_send
  effect: approval_required
  reason: Action sends or publishes outside the workspace.
  approval_scope: Approve this exact payload for this exact recipient or target.
```

**Untrusted content cannot cause an outbound effect.** The injection floor.

```yaml
- id: block_untrusted_side_effect
  side_effect_at_least: external_send
  max_payload_trust: derived
  effect: block
  reason: >
    Payload derives from untrusted external content. Knowledge can inform
    execution; knowledge cannot authorize execution.
```

**Express workspace intent in policy.** These rules are human-readable policy;
the actual path security boundary is the registry's canonical path resolver,
which also rejects traversal, absolute, drive, UNC, and symlink escapes.

```yaml
- id: allow_workspace_write
  tools: ["write_file"]
  targets: ["workspace/*"]
  effect: allow

- id: block_write_outside_workspace
  tools: ["write_file", "read_file"]
  targets: ["/*", "~*", "../*", "C:*"]
  effect: block
  reason: Path is outside the approved workspace.
```

Strictest-wins still applies, but glob patterns are not treated as the only
filesystem sandbox.

**Prohibited claims for a vertical.**

```yaml
- id: ms_block_guaranteed_savings
  payload_contains:
    - "guaranteed savings"
    - "we guarantee"
    - "risk free"
  effect: block
  reason: >
    Payload contains guaranteed-savings language, which is prohibited in
    merchant-services communications.
```

Deterministic, therefore auditable, therefore bypassable by paraphrase. That tradeoff is deliberate and should be said out loud to a client: this is a floor that catches the listed phrasings, not a claim of completeness.

**Tighten by sensitivity.**

```yaml
- id: block_cloud_model_on_regulated
  tools: ["cloud_*"]
  sensitivities: ["regulated", "legal", "financial"]
  effect: block
  reason: Sensitive material may not be sent to a cloud model under this policy.
```

## Writing a vertical pack

Layer it on the default; never replace it.

```bash
dah --policy merchant_services demo prohibited_claim
dah --policy merchant_services policy   # see the merged rule set and hash
```

Give every rule a test with an allow case, a block case, and an approval case. The rules are the product; untested rules are a liability wearing a product's clothes.

## Shipped packs

- `default.yaml` — baseline; safe starting configuration for any workspace.
- `merchant_services.yaml` — statement review; prohibited claims and rate promises.
- `legal_intake.yaml` — intake captures facts, never advises; attorney review on all client contact.
