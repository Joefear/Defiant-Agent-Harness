"""Loopback-only, read-only HTTP surface for Defiant Command Center."""

from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .core import CommandCore, CommandError

LOOPBACK_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
DEFAULT_LIMIT = 25
MAX_LIMIT = 100

_ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/assets/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/assets/app.js": ("app.js", "text/javascript; charset=utf-8"),
}


class CommandCenterError(RuntimeError):
    """The local Command Center could not start safely."""


class CommandCenterServer(ThreadingHTTPServer):
    """HTTP server carrying only a Command Core read projection."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        workdir: str | Path,
        *,
        port: int = DEFAULT_PORT,
        default_limit: int = DEFAULT_LIMIT,
        trusted_operator_keys: list[str] | None = None,
        workspace_root: str | Path | None = None,
        evidence_head_witness: str | Path | None = None,
        trusted_evidence_witness_keys: list[str] | None = None,
    ):
        if not 0 <= port <= 65535:
            raise CommandCenterError("port must be between 0 and 65535")
        if not 0 <= default_limit <= MAX_LIMIT:
            raise CommandCenterError(f"default limit must be between 0 and {MAX_LIMIT}")
        self.command_core = CommandCore(
            workdir,
            trusted_operator_keys=trusted_operator_keys,
            workspace_root=workspace_root,
            evidence_head_witness=evidence_head_witness,
            trusted_evidence_witness_keys=trusted_evidence_witness_keys,
        )
        self.default_limit = default_limit
        super().__init__((LOOPBACK_HOST, port), CommandCenterRequestHandler)


class CommandCenterRequestHandler(BaseHTTPRequestHandler):
    """Serve packaged UI assets and one read-only JSON endpoint."""

    server: CommandCenterServer

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        self._route(include_body=True)

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib handler API
        self._route(include_body=False)

    def do_OPTIONS(self) -> None:  # noqa: N802 - stdlib handler API
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Allow", "GET, HEAD, OPTIONS")
        self._security_headers()
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        self._method_not_allowed()

    def do_PUT(self) -> None:  # noqa: N802 - stdlib handler API
        self._method_not_allowed()

    def do_PATCH(self) -> None:  # noqa: N802 - stdlib handler API
        self._method_not_allowed()

    def do_DELETE(self) -> None:  # noqa: N802 - stdlib handler API
        self._method_not_allowed()

    def log_message(self, format: str, *args: Any) -> None:
        # Keep local access logs useful while preventing control characters from
        # becoming terminal output through a crafted request.
        message = format % args
        cleaned = "".join(ch for ch in message if ch.isprintable())
        super().log_message("%s", cleaned)

    def _route(self, *, include_body: bool) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == "/api/snapshot":
            self._snapshot(parsed.query, include_body=include_body)
            return
        if parsed.path == "/api/health":
            self._json(
                HTTPStatus.OK,
                {"status": "ok", "mode": "read_only"},
                include_body=include_body,
            )
            return
        if parsed.path in _ASSETS:
            asset_name, content_type = _ASSETS[parsed.path]
            self._asset(asset_name, content_type, include_body=include_body)
            return
        self._json(
            HTTPStatus.NOT_FOUND,
            {"error": "not_found"},
            include_body=include_body,
        )

    def _snapshot(self, query: str, *, include_body: bool) -> None:
        try:
            # Python 3.10 treats an empty string as a malformed field under
            # strict parsing, while newer runtimes return an empty mapping.
            # Normalize only the no-query case; every supplied field remains
            # strict and bounded below.
            params = (
                parse_qs(query, keep_blank_values=True, strict_parsing=True)
                if query
                else {}
            )
            unknown = set(params) - {"limit", "request_id"}
            if unknown:
                names = ", ".join(sorted(unknown))
                raise ValueError(f"unknown query parameter: {names}")
            limit = _single_int(params, "limit", self.server.default_limit)
            if not 0 <= limit <= MAX_LIMIT:
                raise ValueError(f"limit must be between 0 and {MAX_LIMIT}")
            request_id = _single_text(params, "request_id", max_length=256)
            snapshot = self.server.command_core.snapshot(
                limit=limit,
                request_id=request_id,
            )
        except (ValueError, CommandError) as exc:
            status = (
                HTTPStatus.BAD_REQUEST
                if isinstance(exc, ValueError)
                else HTTPStatus.SERVICE_UNAVAILABLE
            )
            error_key = (
                "invalid_request"
                if status is HTTPStatus.BAD_REQUEST
                else "snapshot_unavailable"
            )
            self._json(
                status,
                {"error": error_key, "detail": str(exc)},
                include_body=include_body,
            )
            return
        self._json(HTTPStatus.OK, snapshot, include_body=include_body)

    def _asset(
        self,
        asset_name: str,
        content_type: str,
        *,
        include_body: bool,
    ) -> None:
        try:
            body = (
                files("defiant_agent_harness.command")
                .joinpath("ui", asset_name)
                .read_bytes()
            )
        except OSError:
            self._json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "asset_unavailable"},
                include_body=include_body,
            )
            return
        self._send(HTTPStatus.OK, body, content_type, include_body=include_body)

    def _json(
        self,
        status: HTTPStatus,
        payload: dict[str, Any],
        *,
        include_body: bool,
    ) -> None:
        body = json.dumps(payload, sort_keys=True, allow_nan=False).encode("utf-8")
        self._send(
            status,
            body,
            "application/json; charset=utf-8",
            include_body=include_body,
        )

    def _send(
        self,
        status: HTTPStatus,
        body: bytes,
        content_type: str,
        *,
        include_body: bool,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def _security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
        )
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")

    def _method_not_allowed(self) -> None:
        self.send_response(HTTPStatus.METHOD_NOT_ALLOWED)
        self.send_header("Allow", "GET, HEAD, OPTIONS")
        self.send_header("Content-Length", "0")
        self._security_headers()
        self.end_headers()


def _single_int(params: dict[str, list[str]], name: str, default: int) -> int:
    values = params.get(name)
    if values is None:
        return default
    if len(values) != 1:
        raise ValueError(f"{name} must appear once")
    try:
        return int(values[0])
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


def _single_text(
    params: dict[str, list[str]],
    name: str,
    *,
    max_length: int,
) -> str:
    values = params.get(name)
    if values is None:
        return ""
    if len(values) != 1:
        raise ValueError(f"{name} must appear once")
    value = values[0].strip()
    if len(value) > max_length:
        raise ValueError(f"{name} must not exceed {max_length} characters")
    return value


def command_center_url(server: CommandCenterServer) -> str:
    """Return the exact loopback URL assigned to a running server."""

    host, port = server.server_address[:2]
    return f"http://{host}:{port}/"
