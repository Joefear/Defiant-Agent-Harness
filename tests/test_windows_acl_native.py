"""Real Windows ACL assurance; no replacement of the native inspection path.

PowerShell/.NET provisions operator-owned ACLs on disposable pytest paths only.
The production ctypes reader must independently inspect those filesystem objects.
Provisioning failures on Windows are failures, never reasons to skip.
"""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
from pathlib import Path

import pytest

from defiant_agent_harness.adapters.base import ToolCall
from defiant_agent_harness.adapters.mock import MockAgentAdapter
from defiant_agent_harness.command.core import CommandCore
from defiant_agent_harness.contracts import HarnessRequest
from defiant_agent_harness.orchestrator.harness import build_harness
from defiant_agent_harness.state_integrity import (
    StateIntegrityAuditor,
    StateIntegrityError,
)
from defiant_agent_harness.state_storage import (
    StateStorageError,
    prepare_state_storage,
)
from defiant_agent_harness.windows_acl import (
    WindowsAclError,
    inspect_windows_private_acl,
)

pytestmark = pytest.mark.skipif(
    os.name != "nt", reason="requires real Windows security APIs and NTFS ACLs"
)


@pytest.fixture
def current_owner_creation():
    """Select current-user creation ownership on a same-identity thread token.

    Hosted administrators can default new objects to the Administrators owner.
    Only a duplicate token's default owner changes, not its user or privileges,
    the process token, another thread, or machine policy. Never replace an
    existing impersonation context. Always revert before leaving this fixture.
    """
    from ctypes import wintypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)

    def api(library, name, arguments, result=wintypes.BOOL):
        function = getattr(library, name)
        function.argtypes = arguments
        function.restype = result
        return function

    handle = wintypes.HANDLE
    pointer = ctypes.POINTER(handle)
    close = api(kernel, "CloseHandle", [handle])
    current_thread = api(kernel, "GetCurrentThread", [], handle)
    current_process = api(kernel, "GetCurrentProcess", [], handle)
    open_thread = api(
        advapi, "OpenThreadToken", [handle, wintypes.DWORD, wintypes.BOOL, pointer]
    )
    open_process = api(advapi, "OpenProcessToken", [handle, wintypes.DWORD, pointer])
    duplicate = api(
        advapi,
        "DuplicateTokenEx",
        [handle, wintypes.DWORD, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, pointer],
    )
    get_info = api(
        advapi,
        "GetTokenInformation",
        [
            handle,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ],
    )
    set_info = api(
        advapi,
        "SetTokenInformation",
        [handle, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD],
    )
    impersonate = api(advapi, "ImpersonateLoggedOnUser", [handle])
    revert = api(advapi, "RevertToSelf", [])

    prior = handle()
    if open_thread(current_thread(), 0x0008, True, ctypes.byref(prior)):
        close(prior)
        pytest.fail("native owner fixture requires an unimpersonated test thread")
    assert ctypes.get_last_error() == 1008, ctypes.WinError()  # ERROR_NO_TOKEN
    primary = handle()
    owned = handle()
    active = False
    try:
        # QUERY | DUPLICATE; duplicate gets QUERY | ADJUST_DEFAULT | IMPERSONATE.
        assert open_process(current_process(), 0x000A, ctypes.byref(primary)), (
            ctypes.WinError()
        )
        assert duplicate(primary, 0x008C, None, 2, 2, ctypes.byref(owned)), (
            ctypes.WinError()
        )
        needed = wintypes.DWORD()
        get_info(primary, 1, None, 0, ctypes.byref(needed))  # TokenUser
        assert needed.value > 0, ctypes.WinError()
        user = ctypes.create_string_buffer(needed.value)
        assert get_info(primary, 1, user, needed, ctypes.byref(needed)), (
            ctypes.WinError()
        )
        # TOKEN_USER begins with its SID pointer; TOKEN_OWNER is one SID pointer.
        owner = ctypes.c_void_p.from_buffer_copy(user)
        assert set_info(owned, 4, ctypes.byref(owner), ctypes.sizeof(owner)), (
            ctypes.WinError()
        )
        assert impersonate(owned), ctypes.WinError()
        active = True
        yield
    finally:
        if active and not revert():
            pytest.exit(
                "cannot revert native owner fixture; terminating test run", returncode=1
            )
        if owned.value:
            close(owned)
        if primary.value:
            close(primary)


_ACL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$target = $env:DAH_TEST_ACL_PATH
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$directory = [System.IO.Directory]::Exists($target)
if ($env:DAH_TEST_ACL_WRITE -eq '1') {
    if ($directory) {
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
    } else {
        $acl = New-Object System.Security.AccessControl.FileSecurity
    }
    $protection = if ($env:DAH_TEST_ACL_PROTECTED -eq '1') { 'P' } else { '' }
    $inherit = if ($directory -and $env:DAH_TEST_ACL_INHERIT -eq '1') { 'OICI' } else { '' }
    $sddl = 'O:' + $sid + 'D:' + $protection + '(A;' + $inherit + ';FA;;;' + $sid + ')'
    if ($env:DAH_TEST_ACL_SYSTEM_ADMINS -eq '1') {
        $sddl += '(A;' + $inherit + ';FA;;;SY)(A;' + $inherit + ';FA;;;BA)'
    }
    if ($env:DAH_TEST_ACL_EVERYONE -eq '1') {
        $sddl += '(A;' + $inherit + ';FA;;;WD)'
    }
    # Do not request SACL writes: those require an unrelated auditing privilege.
    $acl.SetSecurityDescriptorSddlForm(
        $sddl, [System.Security.AccessControl.AccessControlSections]'Access,Owner')
    if ($directory) {
        [System.IO.Directory]::SetAccessControl($target, $acl)
    } else {
        [System.IO.File]::SetAccessControl($target, $acl)
    }
}
$observed = if ($directory) {
    [System.IO.Directory]::GetAccessControl($target)
} else {
    [System.IO.File]::GetAccessControl($target)
}
@{
    current_sid = $sid
    owner_sid = $observed.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    protected = $observed.AreAccessRulesProtected
    sddl = $observed.Sddl
} | ConvertTo-Json -Compress
"""


@pytest.fixture
def acl_path(tmp_path):
    """Restrict all test-only ACL writes to existing descendants of tmp_path."""
    boundary = tmp_path.resolve()

    def configure(
        path: Path,
        *,
        write: bool = True,
        protected: bool = True,
        inherit: bool = True,
        system_admins: bool = False,
        everyone: bool = False,
    ):
        target = path.resolve(strict=True)
        assert target != boundary and target.is_relative_to(boundary)
        env = dict(os.environ)
        env.update(
            DAH_TEST_ACL_PATH=str(target),
            DAH_TEST_ACL_WRITE=str(int(write)),
            DAH_TEST_ACL_PROTECTED=str(int(protected)),
            DAH_TEST_ACL_INHERIT=str(int(inherit)),
            DAH_TEST_ACL_SYSTEM_ADMINS=str(int(system_admins)),
            DAH_TEST_ACL_EVERYONE=str(int(everyone)),
        )
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                _ACL_SCRIPT,
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    return configure


@pytest.mark.parametrize("system_admins", [False, True])
def test_real_private_root_accepts_current_owner_and_protected_dacl(
    tmp_path, acl_path, system_admins
):
    state = tmp_path / "state"
    prepare_state_storage(state)  # Creation alone does not prove the strict contract.
    before = acl_path(state, system_admins=system_admins)
    assert before["owner_sid"] == before["current_sid"]
    assert before["protected"] is True

    observed = inspect_windows_private_acl(state, directory=True)
    assert observed.owner_current_user is True
    assert observed.dacl_protected is True
    assert observed.principal_count == (3 if system_admins else 1)
    assert observed.ace_count == (3 if system_admins else 1)
    assurance = prepare_state_storage(state, require_windows_private_acl=True)
    assert assurance.mode == "windows_private_acl"
    assert assurance.private_permissions is True
    assert acl_path(state, write=False) == before  # Inspection never repairs ACLs.


def test_real_child_file_inherits_private_acl(
    tmp_path, acl_path, current_owner_creation
):
    state = tmp_path / "state"
    prepare_state_storage(state)
    acl_path(state)
    child = state / "child.json"
    child.write_text("{}", encoding="utf-8")
    independent = acl_path(child, write=False)
    assert independent["owner_sid"] == independent["current_sid"]
    assert independent["protected"] is False
    observed = inspect_windows_private_acl(child, directory=False)
    assert observed.owner_current_user is True
    assert observed.dacl_protected is False
    assert observed.principal_count == 1


def test_real_ambient_child_owner_is_checked_without_repair(tmp_path, acl_path):
    # Do not normalize the creation token here: exercise the actual host default.
    state = tmp_path / "state"
    prepare_state_storage(state)
    acl_path(state)
    child = state / "ambient.json"
    child.write_text("{}", encoding="utf-8")
    before = acl_path(child, write=False)
    if before["owner_sid"] != before["current_sid"]:
        with pytest.raises(WindowsAclError, match="owned by the current user"):
            inspect_windows_private_acl(child, directory=False)
    else:
        assert inspect_windows_private_acl(child, directory=False).owner_current_user
    assert acl_path(child, write=False) == before


@pytest.mark.parametrize("directory", [True, False])
def test_real_everyone_full_control_is_refused(tmp_path, acl_path, directory):
    state = tmp_path / "state"
    prepare_state_storage(state)
    acl_path(state)
    target = state if directory else state / "child.json"
    if not directory:
        target.write_text("{}", encoding="utf-8")
    before = acl_path(target, everyone=True)
    with pytest.raises(WindowsAclError, match="unapproved principal"):
        inspect_windows_private_acl(target, directory=directory)
    assert acl_path(target, write=False) == before


def test_real_unprotected_root_is_refused(tmp_path, acl_path):
    # Inherit only private permissions, isolating protection from broad trustees.
    parent = tmp_path / "private-parent"
    prepare_state_storage(parent)
    acl_path(parent)
    state = parent / "state"
    prepare_state_storage(state)
    # Python 3.12.4+ handles mkdir(0o700) on Windows; explicitly provision this
    # negative posture instead of assuming mkdir leaves inheritance enabled.
    assert acl_path(state, protected=False)["protected"] is False
    with pytest.raises(WindowsAclError, match="disable inherited permissions"):
        inspect_windows_private_acl(state, directory=True)


def test_real_root_without_child_inheritance_is_refused(tmp_path, acl_path):
    state = tmp_path / "state"
    prepare_state_storage(state)
    acl_path(state, inherit=False)
    with pytest.raises(WindowsAclError, match="inherit"):
        inspect_windows_private_acl(state, directory=True)


def _state_bytes(state):
    return {path.name: path.read_bytes() for path in state.iterdir() if path.is_file()}


@pytest.mark.parametrize("drift_target", ["root", "budget.json"])
def test_real_acl_drift_blocks_execution_and_read_models_without_repair(
    tmp_path, acl_path, drift_target, current_owner_creation
):
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    prepare_state_storage(state)
    acl_path(state)
    harness = build_harness(
        state,
        MockAgentAdapter(),
        workspace_root=workspace,
        require_windows_private_state_acl=True,
    )
    core = CommandCore(state, workspace_root=workspace)
    healthy = core.snapshot()
    assert healthy["authoritative"] is True
    assert healthy["state_storage"]["state"] == "windows_private_acl"
    assert healthy["state_storage"]["private_permissions"] is True
    assert healthy["state_storage"]["files_checked"] >= 6

    target = state if drift_target == "root" else state / drift_target
    acl_before = acl_path(target, everyone=True)
    files_before = _state_bytes(state)
    report = StateIntegrityAuditor(state, workspace_root=workspace).audit()
    assert report.safe_to_execute is False
    assert any(issue.code == "state_storage_invalid" for issue in report.issues)
    snapshot = core.snapshot()
    assert snapshot["authoritative"] is False
    assert snapshot["state_storage"]["verification"] == "invalid"
    rendered = json.dumps(snapshot)
    assert "S-1-" not in rendered
    assert str(state) not in rendered
    assert json.dumps(str(state))[1:-1] not in rendered
    with pytest.raises(StateIntegrityError, match="state_storage_invalid"):
        harness.handle_call(
            ToolCall(name="read_file", arguments={"path": "workspace/a.txt"}),
            HarnessRequest(task="native ACL test", user_id="tester", workspace_id="ws"),
        )
    assert _state_bytes(state) == files_before
    assert acl_path(target, write=False) == acl_before


def test_real_broad_acl_refuses_strict_startup_before_state_creation(
    tmp_path, acl_path
):
    state = tmp_path / "state"
    prepare_state_storage(state)
    before = acl_path(state, everyone=True)
    with pytest.raises(StateStorageError, match="unapproved principal"):
        build_harness(state, MockAgentAdapter(), require_windows_private_state_acl=True)
    assert list(state.iterdir()) == []
    assert acl_path(state, write=False) == before
