"""CLI for the local control loop and generic MCP proxies.

dah demo <scenario>       run a scripted scenario end to end
dah pending               list actions waiting on a human
dah approve <id>          approve one held action
dah reject <id>           reject one held action
dah reconcile <id>        resolve one crash-stranded executing approval
dah history               show the evidence trail
dah show <record_id>      show one evidence record in full
dah verify                verify the evidence hash chain
dah signing-keygen        create an encrypted Ed25519 signing key pair
dah operator-keygen       create an encrypted operator identity key pair
dah operator-trust-rotate authorize an additive operator trust rotation
dah verify-export         verify a signed export against pinned public keys
dah budget                show the spend ledger
dah policy                show the loaded rules and ruleset hash
dah export <request_id>   emit a Command-ready evidence pack
dah doctor                audit cross-store state without mutating it
dah command               emit a read-only Command Core snapshot
dah command-center        serve the local read-only Command Center UI
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
from ..command.server import CommandCenterError, CommandCenterServer, command_center_url
from ..contracts import HarnessRequest, Sensitivity
from ..evidence.signing import (
    EvidenceSigningError,
    generate_key_pair,
    load_export,
    read_passphrase,
    sign_export,
    verify_export,
    write_export,
)
from ..evidence.store import EvidenceError, EvidenceStore
from ..mcp.config import McpConfigError, load_proxy_config
from ..mcp.proxy import run_http_upstream_proxy, run_stdio_proxy
from ..mcp.session import McpTransportError
from ..orchestrator.harness import build_harness
from ..operator_identity import (
    DECISION_PURPOSE,
    RECONCILIATION_PURPOSE,
    OperatorIdentityError,
    OperatorTrustPolicy,
    sign_operator_action,
    sign_trust_transition,
)
from ..operator_trust_state import OperatorTrustStateStore
from ..persistence import PersistenceError
from ..state_integrity import StateIntegrityAuditor

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
    "not_executed": RED,
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
        trusted_operator_keys=getattr(args, "trusted_operator_key", None),
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
                pending = harness.approvals.get(outcome.approval_id)
                attestation = _operator_attestation(
                    args,
                    pending,
                    purpose=DECISION_PURPOSE,
                    outcome="approved" if approved else "rejected",
                    operator=args.user,
                    note="cli auto-decision",
                )
                resumed = harness.resume(
                    outcome.approval_id,
                    approved,
                    args.user,
                    note="cli auto-decision",
                    attestation=attestation,
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
    try:
        trust = _operator_trust(args)
        store = ApprovalStore(
            Path(args.workdir) / "approvals.json", operator_trust=trust
        )
        pending = store.get(args.approval_id)
        attestation = _operator_attestation(
            args,
            pending,
            purpose=DECISION_PURPOSE,
            outcome="approved" if approved else "rejected",
            operator=args.user,
            note=args.note,
        )
    except (OperatorIdentityError, EvidenceSigningError) as exc:
        print(f"{RED}{exc}{RESET}", file=sys.stderr)
        return 1
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
                attestation=attestation,
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
            attestation=attestation,
        )
    except Exception as exc:
        print(f"{RED}{exc}{RESET}", file=sys.stderr)
        return 1
    print(f"{args.approval_id} -> {_c(outcome.status.value)} by {args.user}")
    print(f"evidence {outcome.evidence_record_id}")
    print(f"detail   {outcome.detail}")
    return 0


def cmd_reconcile(args) -> int:
    try:
        harness = _harness(args)
        pending = harness.approvals.get(args.approval_id)
        attestation = _operator_attestation(
            args,
            pending,
            purpose=RECONCILIATION_PURPOSE,
            outcome=args.outcome,
            operator=args.operator,
            note=args.note,
        )
        reconciled = harness.reconcile_execution(
            args.approval_id,
            args.outcome,
            args.operator,
            args.note,
            attestation=attestation,
        )
    except Exception as exc:
        print(f"{RED}{exc}{RESET}", file=sys.stderr)
        return 1
    print(
        f"{args.approval_id} -> {_c(reconciled.status.value)} "
        f"reconciled by {args.operator}"
    )
    print(f"evidence {reconciled.evidence_record_id}")
    print(f"detail   {reconciled.detail}")
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
    try:
        store = EvidenceStore(Path(args.workdir) / "evidence.jsonl")
        document = store.export_request(args.request_id)
        if args.signing_key:
            if not args.passphrase_file:
                raise EvidenceSigningError(
                    "--passphrase-file is required with --signing-key"
                )
            _require_external_secret(args.workdir, args.signing_key, "signing key")
            _require_external_secret(
                args.workdir, args.passphrase_file, "passphrase file"
            )
            document = sign_export(
                document,
                args.signing_key,
                read_passphrase(args.passphrase_file),
                signer=args.signer,
                note=args.note,
            )
        elif args.passphrase_file or args.signer or args.note:
            raise EvidenceSigningError(
                "--passphrase-file, --signer, and --note require --signing-key"
            )
        if args.output:
            write_export(args.output, document)
            print(f"wrote evidence export {args.output}")
        else:
            print(json.dumps(document, indent=2, sort_keys=True))
        return 0
    except (EvidenceError, EvidenceSigningError) as exc:
        print(f"{RED}{exc}{RESET}", file=sys.stderr)
        return 1


def cmd_signing_keygen(args) -> int:
    try:
        _require_external_secret(args.workdir, args.private_key, "private key")
        _require_external_secret(args.workdir, args.public_key, "public key")
        _require_external_secret(args.workdir, args.passphrase_file, "passphrase file")
        key_id = generate_key_pair(
            args.private_key,
            args.public_key,
            read_passphrase(args.passphrase_file),
        )
    except EvidenceSigningError as exc:
        print(f"{RED}{exc}{RESET}", file=sys.stderr)
        return 1
    print(f"private key  {args.private_key}")
    print(f"public key   {args.public_key}")
    print(f"key id       {key_id}")
    return 0


def _require_external_secret(workdir: str | Path, path: str | Path, label: str) -> None:
    state_root = Path(workdir).resolve()
    candidate = Path(path).resolve()
    if candidate == state_root or candidate.is_relative_to(state_root):
        raise EvidenceSigningError(f"{label} must be stored outside the workdir")


def cmd_verify_export(args) -> int:
    try:
        for trusted_key in args.trusted_key:
            _require_external_secret(args.workdir, trusted_key, "trusted public key")
        document = load_export(args.export_path)
        status = verify_export(document, args.trusted_key)
    except EvidenceSigningError as exc:
        print(json.dumps({"ok": False, "detail": str(exc)}, indent=2))
        return 1
    print(json.dumps(status.to_dict(), indent=2, sort_keys=True))
    return 0 if status.ok else 1


def cmd_command(args) -> int:
    try:
        _validate_trusted_operator_paths(args)
        snapshot = CommandCore(
            args.workdir,
            trusted_operator_keys=args.trusted_operator_key,
        ).snapshot(
            limit=args.limit,
            request_id=args.request,
        )
    except (CommandError, OperatorIdentityError, EvidenceSigningError) as exc:
        print(f"{RED}{exc}{RESET}", file=sys.stderr)
        return 1
    print(json.dumps(snapshot, indent=2, sort_keys=True))
    return 0 if snapshot["authoritative"] else 1


def cmd_doctor(args) -> int:
    try:
        trust = _operator_trust(args, authority=False)
        report = StateIntegrityAuditor(args.workdir, operator_trust=trust).audit()
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        return 0 if report.safe_to_execute else 1
    except (OperatorIdentityError, EvidenceSigningError) as exc:
        print(f"{RED}{exc}{RESET}", file=sys.stderr)
        return 1


def cmd_operator_trust_rotate(args) -> int:
    try:
        current_specs = args.trusted_operator_key or []
        candidate_specs = args.new_trusted_operator_key or []
        if not current_specs or not candidate_specs:
            raise OperatorIdentityError(
                "rotation requires current and new trusted operator keys"
            )
        _validate_operator_specs(args.workdir, current_specs)
        _validate_operator_specs(args.workdir, candidate_specs)
        _require_external_secret(
            args.workdir, args.operator_key, "operator private key"
        )
        _require_external_secret(
            args.workdir,
            args.operator_passphrase_file,
            "operator passphrase file",
        )
        current = OperatorTrustPolicy.from_specs(current_specs)
        candidate = OperatorTrustPolicy.from_specs(candidate_specs)
        store = OperatorTrustStateStore(Path(args.workdir) / "operator_trust.json")
        state = store.get()
        if state is None:
            raise OperatorIdentityError(
                "operator trust is not enrolled; start an authority path once first"
            )
        attestation = sign_trust_transition(
            args.operator_key,
            read_passphrase(args.operator_passphrase_file),
            from_generation=state.generation,
            from_bindings_hash=state.bindings_hash,
            to_bindings_hash=candidate.bindings_hash,
            operator=args.operator,
            note=args.note,
        )
        rotated = store.rotate(current, candidate, attestation)
    except (OperatorIdentityError, EvidenceSigningError, PersistenceError) as exc:
        print(f"{RED}{exc}{RESET}", file=sys.stderr)
        return 1
    print(f"operator trust generation {rotated.generation}")
    print(f"bindings {rotated.bindings_hash}")
    print(
        f"operators {len(rotated.bindings)}  "
        f"keys {sum(len(keys) for keys in rotated.bindings.values())}"
    )
    return 0


def cmd_command_center(args) -> int:
    try:
        _validate_trusted_operator_paths(args)
        server = CommandCenterServer(
            args.workdir,
            port=args.port,
            default_limit=args.limit,
            trusted_operator_keys=args.trusted_operator_key,
        )
    except (
        CommandCenterError,
        OperatorIdentityError,
        EvidenceSigningError,
        OSError,
    ) as exc:
        print(f"{RED}cannot start Command Center: {exc}{RESET}", file=sys.stderr)
        return 1

    url = command_center_url(server)
    print(f"Defiant Command Center (read-only)\n{url}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nCommand Center stopped")
    finally:
        server.server_close()
    return 0


def cmd_mcp_proxy(args) -> int:
    command = list(args.command)
    if command[:1] == ["--"]:
        command = command[1:]
    try:
        _validate_trusted_operator_paths(args)
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
            trusted_operator_keys=args.trusted_operator_key,
        )
    except (McpConfigError, McpTransportError, OperatorIdentityError, OSError) as exc:
        print(f"MCP proxy failed: {exc}", file=sys.stderr)
        return 2


def cmd_mcp_http_proxy(args) -> int:
    try:
        _validate_trusted_operator_paths(args)
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
            trusted_operator_keys=args.trusted_operator_key,
        )
    except (McpConfigError, McpTransportError, OperatorIdentityError, OSError) as exc:
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
        trusted_operator_keys=getattr(args, "trusted_operator_key", None),
    )


def _operator_trust(args, *, authority: bool = True) -> OperatorTrustPolicy | None:
    specs = getattr(args, "trusted_operator_key", None) or []
    _validate_trusted_operator_paths(args)
    if authority:
        return OperatorTrustStateStore(
            Path(args.workdir) / "operator_trust.json"
        ).resolve_for_authority(specs)
    return OperatorTrustPolicy.from_specs(specs) if specs else None


def _validate_trusted_operator_paths(args) -> None:
    _validate_operator_specs(
        args.workdir, getattr(args, "trusted_operator_key", None) or []
    )


def _validate_operator_specs(workdir: str | Path, specs: list[str]) -> None:
    for spec in specs:
        _, separator, path = spec.partition("=")
        if not separator or not path.strip():
            raise OperatorIdentityError(
                "trusted operator keys must use IDENTITY=PUBLIC_KEY.pem"
            )
        _require_external_secret(workdir, path.strip(), "trusted operator public key")


def _operator_attestation(
    args,
    approval,
    *,
    purpose: str,
    outcome: str,
    operator: str,
    note: str,
) -> dict | None:
    specs = getattr(args, "trusted_operator_key", None) or []
    private_key = getattr(args, "operator_key", None)
    passphrase_file = getattr(args, "operator_passphrase_file", None)
    configured = bool(specs or private_key or passphrase_file)
    if not configured:
        return None
    if not specs or not private_key or not passphrase_file:
        raise OperatorIdentityError(
            "signed operator actions require --operator-key, "
            "--operator-passphrase-file, and --trusted-operator-key"
        )
    if approval is None:
        raise OperatorIdentityError("cannot sign an unknown approval")
    _validate_trusted_operator_paths(args)
    _require_external_secret(args.workdir, private_key, "operator private key")
    _require_external_secret(args.workdir, passphrase_file, "operator passphrase file")
    return sign_operator_action(
        approval,
        private_key,
        read_passphrase(passphrase_file),
        purpose=purpose,
        outcome=outcome,
        operator=operator,
        note=note,
    )


def _indent(text: str, pad: str = "    ") -> str:
    return "\n".join(pad + line for line in text.splitlines())


def _add_operator_trust(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--trusted-operator-key",
        action="append",
        default=[],
        metavar="IDENTITY=PUBLIC_KEY.pem",
        help="trusted operator identity/key binding (repeatable for rotation)",
    )


def _add_operator_signing(parser: argparse.ArgumentParser) -> None:
    _add_operator_trust(parser)
    parser.add_argument(
        "--operator-key",
        help="encrypted Ed25519 private key used for this operator action",
    )
    parser.add_argument(
        "--operator-passphrase-file",
        help="file containing the operator key passphrase",
    )


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
    _add_operator_signing(d)
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
    _add_operator_trust(s)
    s.set_defaults(fn=cmd_pending)

    a = sub.add_parser("approve")
    a.add_argument("approval_id")
    a.add_argument("--note", required=True)
    _add_operator_signing(a)
    a.set_defaults(fn=lambda args: cmd_decide(args, True))

    r = sub.add_parser("reject")
    r.add_argument("approval_id")
    r.add_argument("--note", required=True)
    _add_operator_signing(r)
    r.set_defaults(fn=lambda args: cmd_decide(args, False))

    reconcile = sub.add_parser(
        "reconcile",
        help="terminally resolve a crash-stranded executing approval",
    )
    reconcile.add_argument("approval_id")
    reconcile.add_argument(
        "--outcome",
        required=True,
        choices=["succeeded", "failed", "not_executed"],
    )
    reconcile.add_argument("--operator", required=True)
    reconcile.add_argument("--note", required=True)
    _add_operator_signing(reconcile)
    reconcile.set_defaults(fn=cmd_reconcile)

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
    _add_operator_trust(b)
    b.set_defaults(fn=cmd_budget)

    pol = sub.add_parser("policy")
    _add_operator_trust(pol)
    pol.set_defaults(fn=cmd_policy)

    e = sub.add_parser("export")
    e.add_argument("request_id")
    e.add_argument("--signing-key", help="encrypted Ed25519 private key PEM")
    e.add_argument("--passphrase-file", help="file containing the key passphrase")
    e.add_argument("--signer", default="", help="required signer identity")
    e.add_argument("--note", default="", help="required signing rationale")
    e.add_argument("--output", help="new output file; existing files are refused")
    e.set_defaults(fn=cmd_export)

    keygen = sub.add_parser(
        "signing-keygen",
        help="generate an encrypted Ed25519 evidence-signing key pair",
    )
    keygen.add_argument("--private-key", required=True)
    keygen.add_argument("--public-key", required=True)
    keygen.add_argument("--passphrase-file", required=True)
    keygen.set_defaults(fn=cmd_signing_keygen)

    operator_keygen = sub.add_parser(
        "operator-keygen",
        help="generate an encrypted Ed25519 operator identity key pair",
    )
    operator_keygen.add_argument("--private-key", required=True)
    operator_keygen.add_argument("--public-key", required=True)
    operator_keygen.add_argument("--passphrase-file", required=True)
    operator_keygen.set_defaults(fn=cmd_signing_keygen)

    rotate = sub.add_parser(
        "operator-trust-rotate",
        help="authorize a signed, strictly additive operator trust rotation",
    )
    _add_operator_trust(rotate)
    rotate.add_argument(
        "--new-trusted-operator-key",
        action="append",
        required=True,
        metavar="IDENTITY=PUBLIC_KEY.pem",
        help="complete post-rotation identity/key binding (repeatable)",
    )
    rotate.add_argument("--operator-key", required=True)
    rotate.add_argument("--operator-passphrase-file", required=True)
    rotate.add_argument("--operator", required=True)
    rotate.add_argument("--note", required=True)
    rotate.set_defaults(fn=cmd_operator_trust_rotate)

    verify_export_parser = sub.add_parser(
        "verify-export",
        help="verify a signed evidence export using pinned public keys",
    )
    verify_export_parser.add_argument("export_path")
    verify_export_parser.add_argument(
        "--trusted-key",
        action="append",
        required=True,
        help="trusted Ed25519 public key PEM (repeatable for rotation)",
    )
    verify_export_parser.set_defaults(fn=cmd_verify_export)

    doctor = sub.add_parser(
        "doctor",
        help="audit evidence, approval, and budget state without mutation",
    )
    _add_operator_trust(doctor)
    doctor.set_defaults(fn=cmd_doctor)

    command = sub.add_parser(
        "command",
        help="emit a read-only Defiant Command operational snapshot",
    )
    command.add_argument("--limit", type=int, default=10)
    command.add_argument("--request", default="")
    _add_operator_trust(command)
    command.set_defaults(fn=cmd_command)

    center = sub.add_parser(
        "command-center",
        help="serve the local read-only Defiant Command Center UI",
    )
    center.add_argument("--port", type=int, default=8765)
    center.add_argument("--limit", type=int, default=25)
    _add_operator_trust(center)
    center.set_defaults(fn=cmd_command_center)

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
    _add_operator_trust(mcp)
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
    _add_operator_trust(http)
    http.set_defaults(fn=cmd_mcp_http_proxy)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except (OperatorIdentityError, PersistenceError) as exc:
        print(f"{RED}{exc}{RESET}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
