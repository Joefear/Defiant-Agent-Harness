"""Run Defiant against the official MCP filesystem reference server."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EXAMPLE_DIR = Path(__file__).resolve().parent
REPO_ROOT = EXAMPLE_DIR.parents[1]
CONFIG = EXAMPLE_DIR / "mcp-proxy.yaml"
SEED = EXAMPLE_DIR / "seed"
PACKAGE = "@modelcontextprotocol/server-filesystem@2026.7.10"


class McpClient:
    """Small synchronous client used only to make the live boundary visible."""

    def __init__(
        self,
        run_root: Path,
        state: Path,
        workspace: Path,
        environment: dict[str, str],
    ):
        upstream = _upstream_command()
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "defiant_agent_harness.cli.main",
                "--workdir",
                str(state),
                "--workspace-root",
                str(workspace),
                "--user",
                "demo-operator",
                "--workspace",
                "official-filesystem-demo",
                "mcp-proxy",
                "--config",
                str(CONFIG),
                "--",
                *upstream,
            ],
            cwd=run_root,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        if self.process.stdin is None or self.process.stdout is None:
            raise RuntimeError("failed to open the proxy stdio pipes")
        self._next_id = 0

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict:
        self._next_id += 1
        request_id = self._next_id
        message: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
        }
        if params is not None:
            message["params"] = params
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        self.process.stdin.flush()

        assert self.process.stdout is not None
        while True:
            line = self.process.stdout.readline()
            if not line:
                raise RuntimeError(
                    f"proxy exited before replying (code {self.process.poll()})"
                )
            response = json.loads(line)
            if response.get("id") == request_id:
                return response
            if "id" in response:
                raise RuntimeError(f"unexpected upstream request: {response}")

    def notify(self, method: str) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(
            json.dumps({"jsonrpc": "2.0", "method": method}, separators=(",", ":"))
            + "\n"
        )
        self.process.stdin.flush()

    def close(self) -> None:
        if self.process.poll() is not None:
            return
        assert self.process.stdin is not None
        self.process.stdin.close()
        try:
            self.process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=10)
        if self.process.returncode:
            raise RuntimeError(f"proxy exited with code {self.process.returncode}")


def _upstream_command() -> list[str]:
    command = ["npx", "-y", PACKAGE, "workspace"]
    if os.name == "nt":
        return ["cmd", "/d", "/s", "/c", *command]
    return command


def _environment(npm_cache: Path) -> dict[str, str]:
    environment = dict(os.environ)
    prior = environment.get("PYTHONPATH", "")
    environment["PYTHONPATH"] = str(REPO_ROOT / "src") + (
        os.pathsep + prior if prior else ""
    )
    environment["NPM_CONFIG_CACHE"] = str(npm_cache)
    return environment


def _new_run_root(requested: str) -> Path:
    if requested:
        path = Path(requested).resolve(strict=False)
    else:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = EXAMPLE_DIR / "runs" / f"{stamp}-{uuid.uuid4().hex[:8]}"
    path.mkdir(parents=True, exist_ok=False)
    return path


def _result_text(response: dict) -> str:
    result = response.get("result", {})
    return " ".join(
        block.get("text", "")
        for block in result.get("content", [])
        if isinstance(block, dict) and isinstance(block.get("text"), str)
    ).strip()


def _status(response: dict) -> str:
    return str(response.get("result", {}).get("_defiant", {}).get("status", ""))


def _decide(
    state: Path,
    approval_id: str,
    approved: bool,
    run_root: Path,
    environment: dict[str, str],
) -> None:
    verb = "approve" if approved else "reject"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "defiant_agent_harness.cli.main",
            "--workdir",
            str(state),
            "--user",
            "demo-operator",
            verb,
            approval_id,
            "--note",
            "official filesystem live demo",
        ],
        cwd=run_root,
        env=environment,
        check=True,
    )


def _show_evidence(
    state: Path,
    run_root: Path,
    environment: dict[str, str],
) -> None:
    base = [
        sys.executable,
        "-m",
        "defiant_agent_harness.cli.main",
        "--workdir",
        str(state),
    ]
    subprocess.run([*base, "verify"], cwd=run_root, env=environment, check=True)
    subprocess.run(
        [*base, "history", "--limit", "10"],
        cwd=run_root,
        env=environment,
        check=True,
    )


def run(args: argparse.Namespace) -> Path:
    run_root = _new_run_root(args.run_root)
    workspace = run_root / "workspace"
    state = run_root / ".dah"
    shutil.copytree(SEED, workspace)

    npm_cache = (
        Path(args.npm_cache).resolve(strict=False)
        if args.npm_cache
        else REPO_ROOT / ".npm-cache"
    )
    npm_cache.mkdir(parents=True, exist_ok=True)
    environment = _environment(npm_cache)

    print(f"Run directory: {run_root}")
    print(f"Official server: {PACKAGE}")
    client = McpClient(run_root, state, workspace, environment)
    try:
        initialized = client.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "defiant-live-demo", "version": "1"},
            },
        )
        server = initialized["result"]["serverInfo"]
        print(f"\n1. Connected to {server['name']} {server['version']}")
        client.notify("notifications/initialized")

        listed = client.request("tools/list")
        names = {tool["name"] for tool in listed["result"]["tools"]}
        required = {"read_text_file", "write_file", "create_directory"}
        if not required <= names:
            raise RuntimeError(
                f"official server tool inventory changed: {sorted(names)}"
            )
        print(f"2. Discovered {len(names)} upstream tools")

        root_listing = client.request(
            "tools/call",
            {
                "name": "list_directory",
                "arguments": {"path": "."},
            },
        )
        if _status(root_listing) != "succeeded":
            raise RuntimeError(f"governed root listing failed: {root_listing}")
        if "briefing.txt" not in _result_text(root_listing):
            raise RuntimeError(f"seed file missing from root listing: {root_listing}")
        print("3. Allowed a directory listing at the workspace root")

        read_response = client.request(
            "tools/call",
            {
                "name": "read_text_file",
                "arguments": {"path": "briefing.txt"},
            },
        )
        if _status(read_response) != "succeeded":
            raise RuntimeError(f"governed read failed: {read_response}")
        print("4. Allowed read:")
        print(f"   {_result_text(read_response).replace(chr(10), ' | ')}")

        blocked = client.request(
            "tools/call",
            {
                "name": "create_directory",
                "arguments": {"path": "unapproved"},
            },
        )
        if _status(blocked) != "blocked":
            raise RuntimeError(f"unapproved mutation was not blocked: {blocked}")
        if (workspace / "unapproved").exists():
            raise RuntimeError("blocked directory creation reached the upstream server")
        print("5. Blocked unapproved directory creation before execution")

        write_params = {
            "name": "write_file",
            "arguments": {
                "path": "approved-note.txt",
                "content": (
                    "Operator-approved internal note for demo-merchant-1042.\n"
                    f"Run: {run_root.name}\n"
                ),
            },
        }
        pending = client.request("tools/call", write_params)
        metadata = pending["result"]["_defiant"]
        if metadata["status"] != "pending_approval":
            raise RuntimeError(f"write was not held for approval: {pending}")
        approval_id = metadata["approval_id"]
        print(f"6. Held write for approval: {approval_id}")

        approved = args.yes
        if not approved:
            answer = input("Approve this exact workspace write? [y/N] ").strip().lower()
            approved = answer in {"y", "yes"}
        _decide(state, approval_id, approved, run_root, environment)

        repeated = client.request("tools/call", write_params)
        expected = "succeeded" if approved else "rejected"
        if _status(repeated) != expected:
            raise RuntimeError(f"exact retry produced an unexpected result: {repeated}")
        if not approved:
            print("7. Rejected exact retry; no file was written")
        else:
            print("7. Approved exact retry and executed the real upstream write")
            confirmed = client.request(
                "tools/call",
                {
                    "name": "read_text_file",
                    "arguments": {"path": "approved-note.txt"},
                },
            )
            if _status(confirmed) != "succeeded":
                raise RuntimeError(f"could not read the approved file: {confirmed}")
            print(f"8. Read back: {_result_text(confirmed).splitlines()[0]}")
    finally:
        client.close()

    print("\nEvidence verification:")
    _show_evidence(state, run_root, environment)
    print(f"Evidence and workspace retained at: {run_root}")
    return run_root


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Govern the official MCP filesystem server end to end."
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="approve the held demo write without prompting",
    )
    parser.add_argument(
        "--run-root",
        default="",
        help="new empty directory to retain this run (default: examples/.../runs)",
    )
    parser.add_argument(
        "--npm-cache",
        default="",
        help="npm cache directory (default: repository .npm-cache)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    run(build_parser().parse_args(argv))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
