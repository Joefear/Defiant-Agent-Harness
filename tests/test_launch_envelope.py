from __future__ import annotations

import json
import os
import sys
from io import StringIO
from pathlib import Path

import pytest
import yaml

import defiant_agent_harness.launch_envelope as launch_envelope_module
from defiant_agent_harness.authority_profile import AuthorityProfileError
from defiant_agent_harness.command.core import CommandCore
from defiant_agent_harness.launch_envelope import (
    LaunchEnvironmentConfig,
    LaunchEnvelopeAssurance,
    LaunchEnvelopeError,
    LaunchEnvelopeState,
    LaunchEnvelopeStateStore,
    build_launch_envelope,
)
from defiant_agent_harness.mcp.config import McpConfigError, load_proxy_config
from defiant_agent_harness.mcp.proxy import run_stdio_proxy
from defiant_agent_harness.state_integrity import StateIntegrityAuditor

EXECUTABLE = Path(sys.executable).resolve(strict=True)


def _platform_inherit() -> list[str]:
    return ["SystemRoot"] if "SystemRoot" in os.environ else []


def _config(
    path: Path,
    cwd: Path,
    *,
    inherit: list[str] | None = None,
    secret_env: list[str] | None = None,
    values: dict[str, str] | None = None,
    allow_unsafe: list[str] | None = None,
    command: list[str] | None = None,
) -> Path:
    body = {
        "server": {
            "name": "launch-test",
            "command": command or [str(EXECUTABLE), "-c", "pass"],
            "cwd": str(cwd),
            "launch_environment": {
                "inherit": inherit or [],
                "secret_env": secret_env or [],
                "set": values or {},
                "allow_unsafe": allow_unsafe or [],
            },
        },
        "tools": {"echo": {"side_effect": "none"}},
    }
    path.write_text(yaml.safe_dump(body, sort_keys=False), encoding="utf-8")
    return path


def _run(config_path: Path, state: Path, workspace: Path) -> None:
    run_stdio_proxy(
        load_proxy_config(config_path),
        workdir=state,
        user_id="test-user",
        workspace_id="test-workspace",
        workspace_root=workspace,
        client_input=StringIO(""),
        client_output=StringIO(),
    )


def test_restricted_envelope_passes_only_declared_variables(tmp_path, monkeypatch):
    monkeypatch.setenv("DAH_INHERITED", "inherited-value")
    monkeypatch.setenv("DAH_AMBIENT_ATTACK", "must-not-cross")
    config = LaunchEnvironmentConfig(
        inherit=("DAH_INHERITED",),
        values=(("DAH_LITERAL", "literal-value"),),
    )

    assurance = build_launch_envelope(
        config,
        cwd=tmp_path,
        workdir=tmp_path / "state",
    )

    assert assurance.mode == "restricted"
    assert assurance.environment == {
        "DAH_INHERITED": "inherited-value",
        "DAH_LITERAL": "literal-value",
    }
    assert assurance.variable_count == 2
    assert assurance.environment_hash is not None
    assert "DAH_AMBIENT_ATTACK" not in assurance.environment


def test_secret_values_are_required_but_excluded_from_authority_hash(
    tmp_path, monkeypatch
):
    config = LaunchEnvironmentConfig(secret_env=("DAH_SECRET",))
    monkeypatch.setenv("DAH_SECRET", "first-secret")
    first = build_launch_envelope(config, cwd=tmp_path, workdir=tmp_path / "state")
    monkeypatch.setenv("DAH_SECRET", "rotated-secret")
    second = build_launch_envelope(config, cwd=tmp_path, workdir=tmp_path / "state")

    assert first.authority_dict() == second.authority_dict()
    assert first.environment != second.environment
    assert "first-secret" not in json.dumps(first.authority_dict())
    monkeypatch.delenv("DAH_SECRET")
    with pytest.raises(LaunchEnvelopeError, match="not set"):
        build_launch_envelope(config, cwd=tmp_path, workdir=tmp_path / "state")
    monkeypatch.setenv("DAH_SECRET", "")
    with pytest.raises(LaunchEnvelopeError, match="is empty"):
        build_launch_envelope(config, cwd=tmp_path, workdir=tmp_path / "state")


def test_environment_manifest_is_canonical_and_assurance_validates_itself(tmp_path):
    first = build_launch_envelope(
        LaunchEnvironmentConfig(values=(("DAH_B", "2"), ("DAH_A", "1"))),
        cwd=tmp_path,
        workdir=tmp_path / "state",
    )
    second = build_launch_envelope(
        LaunchEnvironmentConfig(values=(("DAH_A", "1"), ("DAH_B", "2"))),
        cwd=tmp_path,
        workdir=tmp_path / "state",
    )
    assert first.authority_dict() == second.authority_dict()
    with pytest.raises(TypeError):
        first.environment["DAH_C"] = "3"

    with pytest.raises(LaunchEnvelopeError, match="variable count"):
        LaunchEnvelopeAssurance(
            "restricted",
            "sha256:" + "2" * 64,
            2,
            0,
            0,
            "sha256:" + "3" * 64,
            {"DAH_A": "1"},
            tmp_path,
            (0, 0),
        )


def test_loader_and_path_variables_require_exact_explicit_acknowledgement(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("PYTHONPATH", "attacker-controlled")
    config = LaunchEnvironmentConfig(inherit=("PYTHONPATH",))
    with pytest.raises(LaunchEnvelopeError, match="allow_unsafe"):
        build_launch_envelope(config, cwd=tmp_path, workdir=tmp_path / "state")

    allowed = LaunchEnvironmentConfig(
        inherit=("PYTHONPATH",), allow_unsafe=("PYTHONPATH",)
    )
    assurance = build_launch_envelope(allowed, cwd=tmp_path, workdir=tmp_path / "state")
    assert assurance.unsafe_count == 1

    with pytest.raises(LaunchEnvelopeError, match="non-sensitive"):
        LaunchEnvironmentConfig(inherit=("DAH_SAFE",), allow_unsafe=("DAH_SAFE",))


def test_restricted_mode_requires_explicit_safe_working_directory(tmp_path):
    config = LaunchEnvironmentConfig()
    with pytest.raises(LaunchEnvelopeError, match="explicit server.cwd"):
        build_launch_envelope(config, cwd=None, workdir=tmp_path / "state")

    state = tmp_path / "state"
    state.mkdir()
    with pytest.raises(LaunchEnvelopeError, match="outside mutable harness state"):
        build_launch_envelope(config, cwd=state, workdir=state)


def test_config_schema_is_strict_and_remote_transport_refuses_launch_settings(
    tmp_path,
):
    cwd = tmp_path / "workspace"
    cwd.mkdir()
    path = _config(
        tmp_path / "proxy.yaml",
        cwd,
        inherit=[*_platform_inherit(), "DAH_TOKEN"],
        secret_env=["DAH_SECRET"],
        values={"NODE_ENV": "production"},
    )
    config = load_proxy_config(path)
    assert config.launch_environment is not None
    assert config.launch_environment.secret_env == ("DAH_SECRET",)
    assert ("NODE_ENV", "production") in config.launch_environment.values

    remote = tmp_path / "remote.yaml"
    remote.write_text(
        """
server:
  name: remote
  url: https://mcp.example.com
  launch_environment: {inherit: []}
tools: {echo: {side_effect: none}}
""",
        encoding="utf-8",
    )
    with pytest.raises(McpConfigError, match="only valid with server.command"):
        load_proxy_config(remote)

    bad = tmp_path / "bad.yaml"
    bad.write_text(
        """
server:
  name: bad
  command: [python]
  launch_environment: {inherit: DAH_TOKEN}
tools: {echo: {side_effect: none}}
""",
        encoding="utf-8",
    )
    with pytest.raises(McpConfigError, match="list of strings"):
        load_proxy_config(bad)


def test_effective_environment_reaches_child_without_ambient_injection(
    tmp_path, monkeypatch
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    marker = tmp_path / "environment.json"
    monkeypatch.setenv("DAH_AMBIENT_ATTACK", "must-not-cross")
    script = (
        "import json,os,pathlib;"
        f"pathlib.Path({str(marker)!r}).write_text(json.dumps(dict(os.environ)))"
    )
    config_path = _config(
        tmp_path / "proxy.yaml",
        workspace,
        inherit=_platform_inherit(),
        values={"DAH_ALLOWED": "yes"},
        command=[str(EXECUTABLE), "-c", script],
    )

    _run(config_path, tmp_path / "state", workspace)

    child = json.loads(marker.read_text(encoding="utf-8"))
    assert child["DAH_ALLOWED"] == "yes"
    assert "DAH_AMBIENT_ATTACK" not in child


def test_nonsecret_environment_drift_requires_profile_rotation_before_spawn(
    tmp_path, monkeypatch
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config_path = _config(
        tmp_path / "proxy.yaml",
        workspace,
        inherit=[*_platform_inherit(), "DAH_DEPLOYMENT"],
    )
    state = tmp_path / "state"
    monkeypatch.setenv("DAH_DEPLOYMENT", "blue")
    _run(config_path, state, workspace)
    monkeypatch.setenv("DAH_DEPLOYMENT", "green")
    spawned = False

    def forbidden_start(self):
        nonlocal spawned
        spawned = True

    monkeypatch.setattr(
        "defiant_agent_harness.mcp.session.UpstreamSession.start", forbidden_start
    )
    with pytest.raises(AuthorityProfileError, match="does not match"):
        _run(config_path, state, workspace)
    assert spawned is False


def test_command_core_exposes_sanitized_launch_assurance(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config_path = _config(
        tmp_path / "proxy.yaml",
        workspace,
        inherit=_platform_inherit(),
        values={"DAH_VISIBLE_ONLY_TO_CHILD": "private-value"},
    )
    state = tmp_path / "state"
    _run(config_path, state, workspace)

    launch = CommandCore(state).snapshot()["launch_envelope"]
    serialized = json.dumps(launch)
    assert launch["state"] == "restricted"
    assert launch["verification"] == "verified"
    assert launch["variable_count"] == len(_platform_inherit()) + 1
    assert "DAH_VISIBLE_ONLY_TO_CHILD" not in serialized
    assert "private-value" not in serialized
    assert str(workspace) not in serialized
    durable = (state / "launch_envelope.json").read_text(encoding="utf-8")
    assert "DAH_VISIBLE_ONLY_TO_CHILD" not in durable
    assert "private-value" not in durable
    assert str(workspace) not in durable


def test_launch_state_conflict_lock_and_tampering_fail_closed(tmp_path):
    store = LaunchEnvelopeStateStore(tmp_path / "launch_envelope.json")
    profile = "sha256:" + "1" * 64
    first = LaunchEnvelopeAssurance(
        "restricted",
        "sha256:" + "2" * 64,
        1,
        0,
        0,
        "sha256:" + "3" * 64,
        {"DAH_VALUE": "one"},
        tmp_path,
        (0, 0),
    )
    changed = LaunchEnvelopeAssurance(
        "restricted",
        "sha256:" + "4" * 64,
        1,
        0,
        0,
        "sha256:" + "3" * 64,
        {"DAH_VALUE": "two"},
        tmp_path,
        (0, 0),
    )
    store.record(profile, first)
    with pytest.raises(LaunchEnvelopeError, match="conflicts"):
        store.record(profile, changed)

    store.path.with_name("launch_envelope.json.lock").write_text(
        "pid=attacker\n", encoding="utf-8"
    )
    with pytest.raises(LaunchEnvelopeError, match="locked"):
        store.record(profile, first)
    store.path.with_name("launch_envelope.json.lock").unlink()

    store.path.write_text("{}", encoding="utf-8")
    report = StateIntegrityAuditor(tmp_path).audit()
    assert report.safe_to_execute is False
    assert any(issue.code == "launch_envelope_state_invalid" for issue in report.issues)


def test_impossible_persisted_launch_mode_fails_closed(tmp_path):
    path = tmp_path / "launch_envelope.json"
    path.write_text(
        json.dumps(
            {
                "schema_name": "defiant.launch_envelope",
                "schema_version": "0.1.0",
                "profile_hash": "sha256:" + "1" * 64,
                "mode": "remote_not_applicable",
                "environment_hash": None,
                "variable_count": 1,
                "secret_count": 0,
                "unsafe_count": 0,
                "cwd_hash": None,
                "verified_at": "2026-08-22T12:00:00Z",
            }
        ),
        encoding="utf-8",
    )

    report = StateIntegrityAuditor(tmp_path).audit()
    assert report.safe_to_execute is False
    assert any(issue.code == "launch_envelope_state_invalid" for issue in report.issues)


def test_launch_state_store_owns_hostile_bounded_snapshot(tmp_path, monkeypatch):
    class HostileDict(dict):
        def __deepcopy__(self, memo):
            raise AssertionError("launch snapshot invoked deepcopy hook")

        def __iter__(self):
            raise AssertionError("launch snapshot invoked mapping iterator hook")

        def get(self, key, default=None):
            raise AssertionError("launch snapshot invoked mapping get hook")

        def items(self):
            raise AssertionError("launch snapshot invoked mapping items hook")

        def keys(self):
            raise AssertionError("launch snapshot invoked mapping keys hook")

    class HostileString(str):
        def __deepcopy__(self, memo):
            raise AssertionError("launch snapshot invoked scalar deepcopy hook")

        def __str__(self):
            raise AssertionError("launch snapshot invoked scalar rendering hook")

    path = tmp_path / "state" / "launch_envelope.json"
    store = LaunchEnvelopeStateStore(path)
    store.record(
        "sha256:" + "1" * 64,
        LaunchEnvelopeAssurance(
            "restricted",
            "sha256:" + "2" * 64,
            1,
            0,
            0,
            "sha256:" + "3" * 64,
            {"DAH_VALUE": "one"},
            tmp_path,
            (0, 0),
        ),
    )
    raw = json.loads(path.read_text(encoding="utf-8"))
    supplied = HostileDict(
        {
            key: HostileString(value) if type(value) is str else value
            for key, value in raw.items()
        }
    )
    observed = []

    def hostile_read(path, *, max_bytes=None):
        observed.append(max_bytes)
        return supplied

    monkeypatch.setattr(launch_envelope_module, "read_json", hostile_read)
    state = store.get()
    expected = state.to_dict()
    dict.__setitem__(supplied, "environment_hash", HostileString("sha256:" + "4" * 64))

    assert state.to_dict() == expected
    assert type(state.profile_hash) is str
    assert type(state.environment_hash) is str
    assert type(state.mode) is str
    assert type(state.cwd_hash) is str
    assert type(state.verified_at) is str
    assert observed == [launch_envelope_module._MAX_STATE_BYTES]


def test_launch_record_detaches_public_inputs_before_comparison_and_write(
    tmp_path, monkeypatch
):
    class HostileString(str):
        def __str__(self):
            raise AssertionError("launch record rendered caller scalar")

    profile = HostileString("sha256:" + "1" * 64)
    environment_hash = HostileString("sha256:" + "2" * 64)
    assurance = LaunchEnvelopeAssurance(
        HostileString("restricted"),
        environment_hash,
        1,
        0,
        0,
        HostileString("sha256:" + "3" * 64),
        {"DAH_VALUE": "one"},
        tmp_path,
        (0, 0),
    )
    original_write = launch_envelope_module.atomic_write_json
    observed = []

    def mutating_write(path, data, *, max_bytes=None):
        object.__setattr__(assurance, "environment_hash", "sha256:" + "4" * 64)
        observed.append(
            (
                max_bytes,
                type(data["profile_hash"]),
                type(data["mode"]),
                type(data["environment_hash"]),
            )
        )
        return original_write(path, data, max_bytes=max_bytes)

    monkeypatch.setattr(launch_envelope_module, "atomic_write_json", mutating_write)
    store = LaunchEnvelopeStateStore(tmp_path / "state" / "launch_envelope.json")
    state = store.record(profile, assurance)

    assert state.environment_hash == environment_hash
    assert store.get().environment_hash == environment_hash
    assert observed == [(launch_envelope_module._MAX_STATE_BYTES, str, str, str)]


def test_launch_state_rejects_noncanonical_input_without_secret_echo():
    class SecretValue:
        def __repr__(self):
            return "secret-launch-value"

    with pytest.raises(LaunchEnvelopeError) as failure:
        LaunchEnvelopeState.from_dict({"secret": SecretValue()})

    assert "secret-launch-value" not in str(failure.value)
    assert "SecretValue" not in str(failure.value)


def test_oversized_launch_state_fails_at_opened_stream_ceiling(tmp_path):
    path = tmp_path / "state" / "launch_envelope.json"
    path.parent.mkdir(mode=0o700)
    path.write_bytes(b" " * (launch_envelope_module._MAX_STATE_BYTES + 1))
    path.chmod(0o600)

    with pytest.raises(LaunchEnvelopeError, match="exceeds 65536 bytes"):
        LaunchEnvelopeStateStore(path).get()


def test_launch_state_refuses_unrecoverable_publication_without_replacement(
    tmp_path, monkeypatch
):
    path = tmp_path / "state" / "launch_envelope.json"
    store = LaunchEnvelopeStateStore(path)
    current = store.record(
        "sha256:" + "1" * 64,
        LaunchEnvelopeAssurance(
            "restricted",
            "sha256:" + "2" * 64,
            1,
            0,
            0,
            "sha256:" + "3" * 64,
            {"DAH_VALUE": "one"},
            tmp_path,
            (0, 0),
        ),
    )
    prior = path.read_bytes()
    original_limit = launch_envelope_module._MAX_STATE_BYTES
    monkeypatch.setattr(launch_envelope_module, "_MAX_STATE_BYTES", 1)

    with pytest.raises(LaunchEnvelopeError, match="bounded canonical state"):
        launch_envelope_module._write_state(path, current)

    assert path.read_bytes() == prior
    monkeypatch.setattr(launch_envelope_module, "_MAX_STATE_BYTES", original_limit)
    assert store.get() == current
