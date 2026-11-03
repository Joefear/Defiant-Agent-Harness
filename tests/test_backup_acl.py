"""S7 copies private ACL posture through real Windows security APIs."""

import os
import re

import pytest

from defiant_agent_harness.adapters.mock import MockAgentAdapter
from defiant_agent_harness.authority_profile import (
    AuthorityProfileError,
    AuthorityProfileStore,
)
from defiant_agent_harness.backup import snapshot, restore
from defiant_agent_harness.orchestrator.harness import build_harness
from defiant_agent_harness.runtime_lease import runtime_session
from defiant_agent_harness.state_integrity import StateIntegrityAuditor
from defiant_agent_harness.windows_acl import inspect_windows_private_acl
from test_windows_acl_native import (
    acl_path as acl_path,
    current_owner_creation as current_owner_creation,
)

pytestmark = pytest.mark.skipif(
    os.name != "nt", reason="requires real Windows security APIs and NTFS ACLs"
)


def test_private_acl_snapshot_and_restore_do_not_downgrade_original(
    tmp_path, acl_path, current_owner_creation
):
    state, workspace = tmp_path / "state", tmp_path / "workspace"
    state.mkdir()
    workspace.mkdir()
    original_acl = acl_path(state)
    with runtime_session(state):
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            require_windows_private_state_acl=True,
        )
    original = {p.name: p.read_bytes() for p in state.iterdir()}
    capture = snapshot(
        state,
        tmp_path / "snapshot",
        workspace=workspace,
        operator="operator",
        note="All writers stopped",
    )
    assert inspect_windows_private_acl(
        tmp_path / "snapshot", directory=True
    ).dacl_protected
    target = tmp_path / "restored"
    restore(
        state,
        tmp_path / "snapshot",
        target,
        expected_manifest_sha256=capture["manifest_sha256"],
        workspace=workspace,
        operator="operator",
        note="Stopped and retired original",
    )
    assert inspect_windows_private_acl(target, directory=True).dacl_protected
    for path in target.iterdir():
        assert inspect_windows_private_acl(path, directory=False).owner_current_user
    assert acl_path(state, write=False) == original_acl
    assert {p.name: p.read_bytes() for p in state.iterdir()} == original
    with pytest.raises(AuthorityProfileError, match="configured") as mismatch:
        build_harness(
            target,
            MockAgentAdapter(),
            workspace_root=workspace,
            require_windows_private_state_acl=True,
        )
    candidate = re.search(
        r"configured (sha256:[0-9a-f]{64})", str(mismatch.value)
    ).group(1)
    AuthorityProfileStore(target / "authority_profile.json").request_rotation(
        candidate,
        operator="operator",
        note="Activate restored private root",
        operator_trust=None,
    )
    build_harness(
        target,
        MockAgentAdapter(),
        workspace_root=workspace,
        require_windows_private_state_acl=True,
    )
    assert (
        StateIntegrityAuditor(target, workspace_root=workspace).audit().status
        == "healthy"
    )
