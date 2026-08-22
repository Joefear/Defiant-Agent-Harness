from __future__ import annotations

import hashlib
import json
import sys
from io import StringIO
from pathlib import Path

import pytest

from defiant_agent_harness.authority_profile import AuthorityProfileError
from defiant_agent_harness.command.core import CommandCore
from defiant_agent_harness.mcp.config import McpConfigError, load_proxy_config
from defiant_agent_harness.mcp.proxy import run_stdio_proxy
from defiant_agent_harness.runtime_artifacts import (
    RuntimeArtifactAssurance,
    RuntimeArtifactError,
    RuntimeArtifactPin,
    RuntimeArtifactStateStore,
    verify_runtime_artifacts,
)
from defiant_agent_harness.state_integrity import StateIntegrityAuditor


def _digest(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _pin(role: str, path: Path) -> RuntimeArtifactPin:
    return RuntimeArtifactPin(role, path, _digest(path))


def _config(path: Path, executable: Path, support: Path | None = None) -> Path:
    artifacts = [
        {
            "role": "executable",
            "path": executable.as_posix(),
            "sha256": _digest(executable),
        }
    ]
    command = [executable.as_posix(), "-c", "pass"]
    if support is not None:
        artifacts.append(
            {
                "role": "entrypoint",
                "path": support.as_posix(),
                "sha256": _digest(support),
            }
        )
    body = {
        "server": {
            "name": "pinned-test",
            "command": command,
            "artifact_integrity": {"required": True, "artifacts": artifacts},
        },
        "tools": {"echo": {"side_effect": "none"}},
    }
    import yaml

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


def test_bundle_is_order_independent_and_rewrites_to_pinned_executable(tmp_path):
    support = tmp_path / "server.py"
    support.write_text("print('safe')\n", encoding="utf-8")
    executable = Path(sys.executable)
    pins = (_pin("entrypoint", support), _pin("executable", executable))

    first = verify_runtime_artifacts(
        (sys.executable, str(support)), pins, workdir=tmp_path / "state"
    )
    second = verify_runtime_artifacts(
        (sys.executable, str(support)), reversed(pins), workdir=tmp_path / "state"
    )

    assert first.bundle_hash == second.bundle_hash
    assert first.command[0] == str(executable.resolve(strict=True))
    assert first.authority_dict() == {
        "mode": "required",
        "bundle_hash": first.bundle_hash,
        "artifact_count": 2,
        "executable_pinned": True,
    }


def test_digest_replacement_and_forged_identifiers_fail_closed(tmp_path):
    artifact = tmp_path / "server.py"
    artifact.write_text("safe\n", encoding="utf-8")
    pin = _pin("entrypoint", artifact)
    artifact.write_text("replaced\n", encoding="utf-8")

    with pytest.raises(RuntimeArtifactError, match="digest mismatch"):
        verify_runtime_artifacts(
            (sys.executable, str(artifact)),
            (_pin("executable", Path(sys.executable)), pin),
            workdir=tmp_path / "state",
        )
    with pytest.raises(RuntimeArtifactError, match="sha256 identifier"):
        RuntimeArtifactPin("executable", Path(sys.executable), "sha256:not-a-digest")


def test_artifacts_inside_mutable_harness_state_are_refused(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    artifact = state / "server.py"
    artifact.write_text("safe\n", encoding="utf-8")

    with pytest.raises(RuntimeArtifactError, match="outside mutable harness state"):
        verify_runtime_artifacts(
            (sys.executable, str(artifact)),
            (_pin("executable", Path(sys.executable)), _pin("entrypoint", artifact)),
            workdir=state,
        )


def test_command_must_resolve_to_the_exact_pinned_executable(tmp_path):
    support = tmp_path / "server.py"
    support.write_text("pass\n", encoding="utf-8")

    with pytest.raises(RuntimeArtifactError, match="does not resolve"):
        verify_runtime_artifacts(
            (str(support),),
            (_pin("executable", Path(sys.executable)),),
            workdir=tmp_path / "state",
        )


def test_two_roles_cannot_alias_the_same_canonical_artifact(tmp_path):
    executable = Path(sys.executable)
    with pytest.raises(RuntimeArtifactError, match="unique after canonical"):
        verify_runtime_artifacts(
            (sys.executable,),
            (_pin("executable", executable), _pin("entrypoint", executable)),
            workdir=tmp_path / "state",
        )


def test_symlinked_artifact_is_refused_when_supported(tmp_path):
    target = tmp_path / "target.py"
    target.write_text("pass\n", encoding="utf-8")
    link = tmp_path / "link.py"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(RuntimeArtifactError, match="must not be a symlink"):
        verify_runtime_artifacts(
            (sys.executable, str(link)),
            (_pin("executable", Path(sys.executable)), _pin("entrypoint", link)),
            workdir=tmp_path / "state",
        )


def test_config_requires_explicit_strict_shape_and_one_executable(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        """
server:
  name: bad
  command: [python]
  artifact_integrity:
    required: true
    artifacts: []
tools: {echo: {side_effect: none}}
""",
        encoding="utf-8",
    )
    with pytest.raises(McpConfigError, match="at least one artifact"):
        load_proxy_config(bad)

    remote = tmp_path / "remote.yaml"
    remote.write_text(
        f"""
server:
  name: remote
  url: https://mcp.example.com
  artifact_integrity:
    required: true
    artifacts:
      - role: executable
        path: {Path(sys.executable).as_posix()}
        sha256: {_digest(Path(sys.executable))}
tools: {{echo: {{side_effect: none}}}}
""",
        encoding="utf-8",
    )
    with pytest.raises(McpConfigError, match="only valid with server.command"):
        load_proxy_config(remote)


def test_pinned_startup_records_only_sanitized_read_only_assurance(tmp_path):
    config_path = _config(tmp_path / "proxy.yaml", Path(sys.executable))
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    _run(config_path, state, workspace)
    snapshot = CommandCore(state).snapshot()
    artifact_state = snapshot["runtime_artifacts"]

    assert artifact_state["state"] == "pinned"
    assert artifact_state["verification"] == "verified"
    assert artifact_state["artifact_count"] == 1
    serialized = json.dumps(artifact_state)
    assert str(Path(sys.executable)) not in serialized
    assert "artifacts" not in serialized


def test_changed_artifact_requires_profile_rotation_before_spawn(tmp_path, monkeypatch):
    support = tmp_path / "support.py"
    support.write_text("version = 1\n", encoding="utf-8")
    config_path = _config(
        tmp_path / "proxy.yaml", Path(sys.executable), support=support
    )
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _run(config_path, state, workspace)

    support.write_text("version = 2\n", encoding="utf-8")
    _config(config_path, Path(sys.executable), support=support)
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


def test_old_pin_rejects_replacement_before_state_changes(tmp_path):
    support = tmp_path / "support.py"
    support.write_text("version = 1\n", encoding="utf-8")
    config_path = _config(
        tmp_path / "proxy.yaml", Path(sys.executable), support=support
    )
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    support.write_text("attacker replacement\n", encoding="utf-8")

    with pytest.raises(RuntimeArtifactError, match="digest mismatch"):
        _run(config_path, state, workspace)
    assert not state.exists()


def test_artifact_state_cannot_change_under_the_same_profile(tmp_path):
    store = RuntimeArtifactStateStore(tmp_path / "runtime_artifacts.json")
    profile = "sha256:" + "1" * 64
    first = RuntimeArtifactAssurance(
        "required", "sha256:" + "2" * 64, 1, True, (sys.executable,)
    )
    changed = RuntimeArtifactAssurance(
        "required", "sha256:" + "3" * 64, 1, True, (sys.executable,)
    )
    store.record(profile, first)
    with pytest.raises(RuntimeArtifactError, match="conflicts"):
        store.record(profile, changed)


def test_artifact_state_writer_refuses_concurrent_or_crashed_lock(tmp_path):
    store = RuntimeArtifactStateStore(tmp_path / "runtime_artifacts.json")
    store.path.with_name("runtime_artifacts.json.lock").write_text(
        "pid=attacker\n", encoding="utf-8"
    )
    assurance = RuntimeArtifactAssurance(
        "required", "sha256:" + "2" * 64, 1, True, (sys.executable,)
    )

    with pytest.raises(RuntimeArtifactError, match="locked"):
        store.record("sha256:" + "1" * 64, assurance)


def test_tampered_artifact_assurance_is_a_critical_read_only_finding(tmp_path):
    path = tmp_path / "runtime_artifacts.json"
    path.write_text("{}", encoding="utf-8")

    report = StateIntegrityAuditor(tmp_path).audit()

    assert report.safe_to_execute is False
    assert report.stores["runtime_artifacts"]["state"] == "invalid"
    assert any(
        issue.code == "runtime_artifact_state_invalid" for issue in report.issues
    )
