"""CLI for the local control loop and generic MCP proxies.

dah demo <scenario>       run a scripted scenario end to end
dah pending               list actions waiting on a human
dah approve <id>          approve one held action
dah reject <id>           reject one held action
dah history               show the evidence trail
dah show <record_id>      show one evidence record in full
dah verify                verify the evidence hash chain
dah budget                show the spend ledger
dah policy                show the loaded rules and ruleset hash
dah export <request_id>   emit a Command-ready evidence pack
dah command               emit a read-only Command Core snapshot
dah mcp-proxy             govern one configured MCP stdio server
dah mcp-http-proxy        govern one remote Streamable HTTP MCP server
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..adapters.mock import SCRIPTS, MockAgentAdapter
from ..approvals.store import ApprovalStore
from ..command.core import CommandCore, CommandError
from ..contracts import HarnessRequest, Sensitivity
from ..evidence.store import EvidenceStore
from ..mcp.config import McpConfigError, load_proxy_config
from ..mcp.proxy import run_http_upstream_proxy, run_stdio_proxy
from ..mcp.session import McpTransportError
from ..orchestrator.harness import build_harness

DEFAULT_WORKDIR = Path(".dah")

GREEN, RED, YELLOW, DIM, RESET = (
    "\033[32m",
    "\033[31m",
    "\033[33m",
    "\033[2m",
    "\033[0m",
)

STATUS_COLOR = {
    "succeeded": GREEN,
    "blocked": RED,
    "rejected": RED,
    "failed": RED,
    "expired": RED,
    "pending_approval": YELLOW,
    "skipped": DIM,
}


def _c(status: str) -> str:
    return f"{STATUS_COLOR.get(status, '')}{status}{RESET}"


# ---------------------------------------------------------------------------


def cmd_demo(args) -> int:
    scenario = args.scenario
    if scenario not in SCRIPTS:
        print(f"unknown scenario '{scenario}'. available:", file=sys.stderr)
        for name in sorted(SCRIPTS):
            print(f"  {name}", file=sys.stderr)
        return 2

    adapter = MockAgentAdapter(script=SCRIPTS[scenario])
    harness = build_harness(
        args.workdir,
        adapter,
        policy_packs=args.policy or [],
        dry_run=args.dry_run,
        workspace_root=args.workspace_root,
    )
    request = HarnessRequest(
        task=f"demo: {scenario}",
        user_id=args.user,
        workspace_id=args.workspace,
        task_type=scenario,
        sensitivity=Sensitivity(args.sensitivity),
    )

    print(f"\nrequest {request.request_id}  scenario={scenario}")
    print(f"policy  {harness.policy.name} v{harness.policy.version}")
    print(f"ruleset {harness.policy.ruleset_hash[:23]}...\n")

    for outcome in harness.run(request):
        a = outcome.action
        print(f"  tool         {a.tool_name} -> {a.target}")
        print(f"  side effect  {a.side_effect_level.value}")
        print(f"  payload      {a.payload_hash[:23]}...  trust={a.payload_trust.value}")
        print(
            f"  decision     {outcome.decision.decision.value}  [{', '.join(outcome.decision.policy_ids)}]"
        )
        print(f"  reason       {outcome.decision.reason.strip()}")
        print(f"  status       {_c(outcome.status.value)}")
        print(f"  evidence     {outcome.evidence_record_id}")
        if outcome.approval_id:
            print(f"  approval     {outcome.approval_id}")
            if args.auto_approve or args.auto_reject:
                approved = bool(args.auto_approve)
                verb = "approving" if approved else "rejecting"
                print(f"\n  {DIM}[{verb} as {args.user}]{RESET}")
                resumed = harness.resume(
                    outcome.approval_id, approved, args.user, note="cli auto-decision"
                )
                print(f"  status       {_c(resumed.status.value)}")
                print(f"  detail       {resumed.detail}")
                print(f"  evidence     {resumed.evidence_record_id}")
            else:
                print(f"  {DIM}re-run with --auto-approve to complete the loop{RESET}")
        print()
    return 0


def cmd_pending(args) -> int:
    harness = _harness(args)
    pend = harness.approvals.list_actionable()
    if not pend:
        print("nothing waiting on a human.")
        return 0
    for p in pend:
        print(
            f"\n{YELLOW}{p.approval_id}{RESET}  "
            f"status={p.status}  expires {p.expires_at}"
        )
        print(f"  {p.tool_name} -> {p.target}")
        print(f"  why    {p.reason.strip()}")
        print(f"  scope  {p.approval_scope}")
        print(f"  rules  {', '.join(p.policy_ids)}")
        print(f"  payload:\n{_indent(p.payload_preview)}")
    print()
    return 0


def cmd_decide(args, approved: bool) -> int:
    store = ApprovalStore(Path(args.workdir) / "approvals.json")
    pending = store.get(args.approval_id)
    if (
        approved
        and pending is not None
        and pending.execution_owner.startswith(
            ("mcp_stdio:", "mcp_http:", "agent_hook:")
        )
    ):
        try:
            decided = store.decide(
                args.approval_id,
                True,
                args.user,
                args.note,
            )
        except Exception as exc:
            print(f"{RED}{exc}{RESET}", file=sys.stderr)
            return 1
        print(f"{args.approval_id} -> {_c('approved')} by {args.user}")
        print(
            "execution remains held; the external agent must retry the exact "
            f"tool call before {decided.expires_at}"
        )
        return 0

    harness = _harness(args)
    try:
        outcome = harness.resume(
            args.approval_id,
            approved,
            args.user,
            args.note,
        )
    except Exception as exc:
        print(f"{RED}{exc}{RESET}", file=sys.stderr)
        return 1
    print(f"{args.approval_id} -> {_c(outcome.status.value)} by {args.user}")
    print(f"evidence {outcome.evidence_record_id}")
    print(f"detail   {outcome.detail}")
    return 0


def cmd_history(args) -> int:
    store = EvidenceStore(Path(args.workdir) / "evidence.jsonl")
    recs = store.records()
    if args.request:
        recs = [r for r in recs if r["request_id"] == args.request]
    if not recs:
        print("no evidence yet.")
        return 0
    print(f"\n{'time':<22} {'tool':<14} {'decision':<18} {'status':<20} record")
    print("-" * 100)
    for r in recs[-args.limit :]:
        print(
            f"{r['timestamp'][:19]:<22} {r['tool_name'][:13]:<14} "
            f"{r['decision']:<18} {_c(r['result_status']):<29} {r['record_id']}"
        )
    print()
    return 0


def cmd_show(args) -> int:
    store = EvidenceStore(Path(args.workdir) / "evidence.jsonl")
    rec = store.get(args.record_id)
    if rec is None:
        print(f"no record {args.record_id}", file=sys.stderr)
        return 1
    print(json.dumps(rec, indent=2, sort_keys=True))
    return 0


def cmd_verify(args) -> int:
    store = EvidenceStore(Path(args.workdir) / "evidence.jsonl")
    status = store.verify()
    if status.ok:
        print(f"{GREEN}chain intact{RESET}  {status.count} records")
        return 0
    print(f"{RED}CHAIN BROKEN{RESET} at record {status.broken_at}")
    print(f"  {status.detail}")
    return 1


def cmd_budget(args) -> int:
    harness = _harness(args)
    print(json.dumps(harness.budget.summary(), indent=2))
    print(json.dumps(harness.budget.drift(), indent=2))
    return 0


def cmd_policy(args) -> int:
    harness = _harness(args)
    print(f"pack     {harness.policy.name}")
    print(f"version  {harness.policy.version}")
    print(f"hash     {harness.policy.ruleset_hash}")
    print(f"rules    {len(harness.policy.rules)}\n")
    for r in harness.policy.rules:
        print(f"  {r.effect:<18} {r.id}")
        if r.description:
            print(f"  {DIM}{' ' * 18} {r.description.strip()}{RESET}")
    print()
    return 0


def cmd_export(args) -> int:
    store = EvidenceStore(Path(args.workdir) / "evidence.jsonl")
    print(json.dumps(store.export_request(args.request_id), indent=2, sort_keys=True))
    return 0


def cmd_command(args) -> int:
    try:
        snapshot = CommandCore(args.workdir).snapshot(
            limit=args.limit,
            request_id=args.request,
        )
    except CommandError as exc:
        print(f"{RED}{exc}{RESET}", file=sys.stderr)
        return 1
    print(json.dumps(snapshot, indent=2, sort_keys=True))
    return 0 if snapshot["authoritative"] else 1


def cmd_mcp_proxy(args) -> int:
    command = list(args.command)
    if command[:1] == ["--"]:
        command = command[1:]
    try:
        config = load_proxy_config(
            args.config,
            command_override=command or None,
            runner_override=args.runner or None,
        )
        return run_stdio_proxy(
            config,
            workdir=args.workdir,
            user_id=args.user,
            workspace_id=args.workspace,
            workspace_root=args.workspace_root,
            policy_packs=args.policy or [],
            sensitivity=Sensitivity(args.sensitivity),
            dry_run=args.dry_run,
        )
    except (McpConfigError, McpTransportError, OSError) as exc:
        print(f"MCP proxy failed: {exc}", file=sys.stderr)
        return 2


def cmd_mcp_http_proxy(args) -> int:
    try:
        config = load_proxy_config(
            args.config,
            runner_override=args.runner or None,
        )
        return run_http_upstream_proxy(
            config,
            workdir=args.workdir,
            user_id=args.user,
            workspace_id=args.workspace,
            workspace_root=args.workspace_root,
            policy_packs=args.policy or [],
            sensitivity=Sensitivity(args.sensitivity),
            dry_run=args.dry_run,
        )
    except (McpConfigError, McpTransportError, OSError) as exc:
        print(f"MCP HTTP proxy failed: {exc}", file=sys.stderr)
        return 2


# ---------------------------------------------------------------------------


def _harness(args):
    policy_packs = getattr(args, "policy", None) or []
    if not policy_packs and getattr(args, "approval_id", ""):
        approval = ApprovalStore(Path(args.workdir) / "approvals.json").get(
            args.approval_id
        )
        if approval and approval.decision_snapshot:
            policy_name = approval.decision_snapshot.get("decision_inputs", {}).get(
                "policy_name", ""
            )
            names = [name for name in policy_name.split("+") if name]
            if names and names[0] == "default":
                policy_packs = names[1:]
    return build_harness(
        args.workdir,
        MockAgentAdapter(),
        policy_packs=policy_packs,
        workspace_root=args.workspace_root,
    )


def _indent(text: str, pad: str = "    ") -> str:
    return "\n".join(pad + line for line in text.splitlines())


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dah", description="Defiant Agent Harness")
    p.add_argument("--workdir", default=str(DEFAULT_WORKDIR))
    p.add_argument("--user", default="operator")
    p.add_argument("--workspace", default="default")
    p.add_argument(
        "--workspace-root",
        default="workspace",
        help="only local directory read_file may access",
    )
    p.add_argument("--policy", action="append", help="extra policy pack (repeatable)")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("demo", help="run a scripted scenario")
    d.add_argument("scenario", choices=sorted(SCRIPTS))
    d.add_argument(
        "--sensitivity",
        default="internal",
        choices=[value.value for value in Sensitivity],
    )
    d.add_argument("--dry-run", action="store_true")
    auto = d.add_mutually_exclusive_group()
    auto.add_argument(
        "--auto-approve",
        action="store_true",
        help="approve the durable held action",
    )
    auto.add_argument(
        "--auto-reject",
        action="store_true",
        help="reject the durable held action",
    )
    d.set_defaults(fn=cmd_demo)

    s = sub.add_parser("pending", help="list actions awaiting approval")
    s.set_defaults(fn=cmd_pending)

    a = sub.add_parser("approve")
    a.add_argument("approval_id")
    a.add_argument("--note", default="")
    a.set_defaults(fn=lambda args: cmd_decide(args, True))

    r = sub.add_parser("reject")
    r.add_argument("approval_id")
    r.add_argument("--note", default="")
    r.set_defaults(fn=lambda args: cmd_decide(args, False))

    h = sub.add_parser("history")
    h.add_argument("--limit", type=int, default=25)
    h.add_argument("--request", default="")
    h.set_defaults(fn=cmd_history)

    sh = sub.add_parser("show")
    sh.add_argument("record_id")
    sh.set_defaults(fn=cmd_show)

    v = sub.add_parser("verify")
    v.set_defaults(fn=cmd_verify)

    b = sub.add_parser("budget")
    b.set_defaults(fn=cmd_budget)

    pol = sub.add_parser("policy")
    pol.set_defaults(fn=cmd_policy)

    e = sub.add_parser("export")
    e.add_argument("request_id")
    e.set_defaults(fn=cmd_export)

    command = sub.add_parser(
        "command",
        help="emit a read-only Defiant Command operational snapshot",
    )
    command.add_argument("--limit", type=int, default=10)
    command.add_argument("--request", default="")
    command.set_defaults(fn=cmd_command)

    mcp = sub.add_parser(
        "mcp-proxy",
        help="govern a configured MCP stdio server",
    )
    mcp.add_argument("--config", required=True, help="proxy YAML configuration")
    mcp.add_argument(
        "--runner",
        default="",
        help="evidence identity for the connected runner (overrides YAML)",
    )
    mcp.add_argument(
        "--sensitivity",
        default="internal",
        choices=[value.value for value in Sensitivity],
    )
    mcp.add_argument("--dry-run", action="store_true")
    mcp.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="optional upstream command override after --",
    )
    mcp.set_defaults(fn=cmd_mcp_proxy)

    http = sub.add_parser(
        "mcp-http-proxy",
        help="govern a remote Streamable HTTP MCP server",
    )
    http.add_argument("--config", required=True, help="proxy YAML configuration")
    http.add_argument(
        "--runner",
        default="",
        help="evidence identity for the connected runner (overrides YAML)",
    )
    http.add_argument(
        "--sensitivity",
        default="internal",
        choices=[value.value for value in Sensitivity],
    )
    http.add_argument("--dry-run", action="store_true")
    http.set_defaults(fn=cmd_mcp_http_proxy)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
