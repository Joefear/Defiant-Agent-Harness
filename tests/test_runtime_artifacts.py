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
    RuntimeDependencyFilePin,
    RuntimeDependencyRoot,
    verify_runtime_artifacts,
)
from defiant_agent_harness.state_integrity import StateIntegrityAuditor

EXECUTABLE = Path(sys.executable).resolve(strict=True)


def _digest(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _pin(role: str, path: Path) -> RuntimeArtifactPin:
    return RuntimeArtifactPin(role, path, _digest(path))


def _root(path: Path) -> RuntimeDependencyRoot:
    files = tuple(
        RuntimeDependencyFilePin(
            file.relative_to(path).as_posix(),
            _digest(file),
        )
        for file in sorted(
            candidate for candidate in path.rglob("*") if candidate.is_file()
        )
    )
    return RuntimeDependencyRoot(path, files)


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


def _closed_config(path: Path, executable: Path, dependency_root: Path) -> Path:
    import yaml

    root = _root(dependency_root)
    body = {
        "server": {
            "name": "closed-test",
            "command": [executable.as_posix(), "-c", "pass"],
            "artifact_integrity": {
                "required": True,
                "artifacts": [
                    {
                        "role": "executable",
                        "path": executable.as_posix(),
                        "sha256": _digest(executable),
                    }
                ],
                "dependency_roots": [
                    {
                        "path": dependency_root.as_posix(),
                        "files": [
                            {"path": item.path, "sha256": item.sha256}
                            for item in root.files
                        ],
                    }
                ],
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


def test_bundle_is_order_independent_and_rewrites_to_pinned_executable(tmp_path):
    support = tmp_path / "server.py"
    support.write_text("print('safe')\n", encoding="utf-8")
    executable = EXECUTABLE
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
            (_pin("executable", EXECUTABLE), pin),
            workdir=tmp_path / "state",
        )
    with pytest.raises(RuntimeArtifactError, match="sha256 identifier"):
        RuntimeArtifactPin("executable", EXECUTABLE, "sha256:not-a-digest")


def test_artifacts_inside_mutable_harness_state_are_refused(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    artifact = state / "server.py"
    artifact.write_text("safe\n", encoding="utf-8")

    with pytest.raises(RuntimeArtifactError, match="outside mutable harness state"):
        verify_runtime_artifacts(
            (sys.executable, str(artifact)),
            (_pin("executable", EXECUTABLE), _pin("entrypoint", artifact)),
            workdir=state,
        )


def test_command_must_resolve_to_the_exact_pinned_executable(tmp_path):
    support = tmp_path / "server.py"
    support.write_text("pass\n", encoding="utf-8")

    with pytest.raises(RuntimeArtifactError, match="does not resolve"):
        verify_runtime_artifacts(
            (str(support),),
            (_pin("executable", EXECUTABLE),),
            workdir=tmp_path / "state",
        )


def test_two_roles_cannot_alias_the_same_canonical_artifact(tmp_path):
    executable = EXECUTABLE
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
            (_pin("executable", EXECUTABLE), _pin("entrypoint", link)),
            workdir=tmp_path / "state",
        )


def test_closed_dependency_bundle_is_deterministic_and_authority_bound(tmp_path):
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    (first_root / "pkg").mkdir(parents=True)
    second_root.mkdir()
    (first_root / "pkg" / "module.py").write_text("value = 1\n", encoding="utf-8")
    (first_root / "settings.json").write_text("{}\n", encoding="utf-8")
    (second_root / "plugin.py").write_text("enabled = True\n", encoding="utf-8")
    first = _root(first_root)
    reversed_first = RuntimeDependencyRoot(first.path, tuple(reversed(first.files)))
    pins = (_pin("executable", EXECUTABLE),)

    observed = verify_runtime_artifacts(
        (sys.executable,),
        pins,
        workdir=tmp_path / "state",
        dependency_roots=(first, _root(second_root)),
    )
    reordered = verify_runtime_artifacts(
        (sys.executable,),
        pins,
        workdir=tmp_path / "state",
        dependency_roots=(_root(second_root), reversed_first),
    )

    assert observed.bundle_hash == reordered.bundle_hash
    assert observed.authority_dict() == {
        "mode": "closed",
        "bundle_hash": observed.bundle_hash,
        "artifact_count": 4,
        "executable_pinned": True,
        "dependency_root_count": 2,
        "dependency_file_count": 3,
    }


@pytest.mark.parametrize("change", ["added", "missing", "changed"])
def test_closed_dependency_inventory_rejects_drift(tmp_path, change):
    root_path = tmp_path / "runtime"
    root_path.mkdir()
    dependency = root_path / "module.py"
    dependency.write_text("safe = True\n", encoding="utf-8")
    root = _root(root_path)
    if change == "added":
        (root_path / "injected.py").write_text("attacker = True\n", encoding="utf-8")
        match = "inventory mismatch"
    elif change == "missing":
        dependency.unlink()
        match = "inventory mismatch"
    else:
        dependency.write_text("safe = False\n", encoding="utf-8")
        match = "digest mismatch"

    with pytest.raises(RuntimeArtifactError, match=match):
        verify_runtime_artifacts(
            (sys.executable,),
            (_pin("executable", EXECUTABLE),),
            workdir=tmp_path / "state",
            dependency_roots=(root,),
        )


def test_closed_dependency_roots_reject_links_and_overlap(tmp_path):
    outer = tmp_path / "outer"
    inner = outer / "inner"
    inner.mkdir(parents=True)
    target = inner / "module.py"
    target.write_text("pass\n", encoding="utf-8")

    with pytest.raises(RuntimeArtifactError, match="must not overlap"):
        verify_runtime_artifacts(
            (sys.executable,),
            (_pin("executable", EXECUTABLE),),
            workdir=tmp_path / "state",
            dependency_roots=(_root(outer), _root(inner)),
        )

    link = outer / "alias.py"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    manifest = RuntimeDependencyRoot(
        outer,
        (
            RuntimeDependencyFilePin("inner/module.py", _digest(target)),
            RuntimeDependencyFilePin("alias.py", _digest(target)),
        ),
    )
    with pytest.raises(RuntimeArtifactError, match="must not contain links"):
        verify_runtime_artifacts(
            (sys.executable,),
            (_pin("executable", EXECUTABLE),),
            workdir=tmp_path / "state",
            dependency_roots=(manifest,),
        )


def test_dependency_manifest_paths_are_strict_and_portable():
    digest = "sha256:" + "1" * 64
    for path in (
        ".",
        "../escape.py",
        "/absolute.py",
        "pkg\\module.py",
        "./module.py",
        "bad\x00name.py",
    ):
        with pytest.raises(RuntimeArtifactError, match="dependency file path"):
            RuntimeDependencyFilePin(path, digest)


def test_closed_dependency_roots_reject_hard_links_when_supported(tmp_path):
    root_path = tmp_path / "runtime"
    root_path.mkdir()
    target = root_path / "module.py"
    target.write_text("safe = True\n", encoding="utf-8")
    alias = root_path / "alias.py"
    try:
        alias.hardlink_to(target)
    except OSError:
        pytest.skip("hard-link creation is unavailable")

    with pytest.raises(RuntimeArtifactError, match="must not contain hard links"):
        verify_runtime_artifacts(
            (sys.executable,),
            (_pin("executable", EXECUTABLE),),
            workdir=tmp_path / "state",
            dependency_roots=(_root(root_path),),
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
        path: {EXECUTABLE.as_posix()}
        sha256: {_digest(EXECUTABLE)}
tools: {{echo: {{side_effect: none}}}}
""",
        encoding="utf-8",
    )
    with pytest.raises(McpConfigError, match="only valid with server.command"):
        load_proxy_config(remote)


def test_dependency_root_config_rejects_unknown_and_noncanonical_fields(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        f"""
server:
  name: bad-closure
  command: [{EXECUTABLE.as_posix()}]
  artifact_integrity:
    required: true
    artifacts:
      - role: executable
        path: {EXECUTABLE.as_posix()}
        sha256: {_digest(EXECUTABLE)}
    dependency_roots:
      - path: runtime
        files:
          - path: ../escape.py
            sha256: {"sha256:" + "1" * 64}
            optional: true
tools: {{echo: {{side_effect: none}}}}
""",
        encoding="utf-8",
    )

    with pytest.raises(McpConfigError, match="unknown fields: optional"):
        load_proxy_config(bad)

    text = bad.read_text(encoding="utf-8").replace("            optional: true\n", "")
    bad.write_text(text, encoding="utf-8")
    with pytest.raises(McpConfigError, match="canonical and relative"):
        load_proxy_config(bad)


def test_pinned_startup_records_only_sanitized_read_only_assurance(tmp_path):
    config_path = _config(tmp_path / "proxy.yaml", EXECUTABLE)
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
    assert str(EXECUTABLE) not in serialized
    assert "artifacts" not in serialized


def test_closed_startup_projects_only_sanitized_counts(tmp_path):
    dependency_root = tmp_path / "runtime"
    dependency_root.mkdir()
    dependency = dependency_root / "module.py"
    dependency.write_text("safe = True\n", encoding="utf-8")
    config_path = _closed_config(tmp_path / "proxy.yaml", EXECUTABLE, dependency_root)
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    _run(config_path, state, workspace)
    artifact_state = CommandCore(state).snapshot()["runtime_artifacts"]

    assert artifact_state["state"] == "closed"
    assert artifact_state["verification"] == "verified"
    assert artifact_state["dependency_root_count"] == 1
    assert artifact_state["dependency_file_count"] == 1
    serialized = json.dumps(artifact_state)
    assert str(dependency_root) not in serialized
    assert "module.py" not in serialized
    assert _digest(dependency) not in serialized


def test_dependency_mutation_before_spawn_fails_closed(tmp_path, monkeypatch):
    dependency_root = tmp_path / "runtime"
    dependency_root.mkdir()
    dependency = dependency_root / "module.py"
    dependency.write_text("safe = True\n", encoding="utf-8")
    config_path = _closed_config(tmp_path / "proxy.yaml", EXECUTABLE, dependency_root)
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    spawned = False

    def forbidden_start(self):
        nonlocal spawned
        spawned = True

    original = verify_runtime_artifacts
    calls = 0

    def mutate_after_first_verification(*args, **kwargs):
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if calls == 1:
            dependency.write_text("safe = False\n", encoding="utf-8")
        return result

    monkeypatch.setattr(
        "defiant_agent_harness.mcp.proxy.verify_runtime_artifacts",
        mutate_after_first_verification,
    )
    monkeypatch.setattr(
        "defiant_agent_harness.mcp.session.UpstreamSession.start", forbidden_start
    )

    with pytest.raises(RuntimeArtifactError, match="digest mismatch"):
        _run(config_path, state, workspace)
    assert calls == 1
    assert spawned is False


def test_changed_artifact_requires_profile_rotation_before_spawn(tmp_path, monkeypatch):
    support = tmp_path / "support.py"
    support.write_text("version = 1\n", encoding="utf-8")
    config_path = _config(tmp_path / "proxy.yaml", EXECUTABLE, support=support)
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _run(config_path, state, workspace)

    support.write_text("version = 2\n", encoding="utf-8")
    _config(config_path, EXECUTABLE, support=support)
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
    config_path = _config(tmp_path / "proxy.yaml", EXECUTABLE, support=support)
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


def test_v1_artifact_state_remains_readable_and_upgrades_on_write(tmp_path):
    path = tmp_path / "runtime_artifacts.json"
    path.write_text(
        json.dumps(
            {
                "schema_name": "defiant.runtime_artifacts",
                "schema_version": "0.1.0",
                "profile_hash": "sha256:" + "1" * 64,
                "mode": "required",
                "bundle_hash": "sha256:" + "2" * 64,
                "artifact_count": 1,
                "executable_pinned": True,
                "verified_at": "2026-08-22T12:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    store = RuntimeArtifactStateStore(path)

    previous = store.get()
    assert previous is not None
    assert previous.dependency_root_count == 0
    store.record(
        "sha256:" + "1" * 64,
        RuntimeArtifactAssurance(
            "required", "sha256:" + "2" * 64, 1, True, (sys.executable,)
        ),
    )
    assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == "0.2.0"


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
