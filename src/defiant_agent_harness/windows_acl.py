"""Fail-closed, read-only NTFS DACL assurance for Defiant state paths."""

from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


class WindowsAclError(RuntimeError):
    """A Windows state ACL could not be proven private."""


@dataclass(frozen=True)
class WindowsAce:
    ace_type: int
    flags: int
    mask: int
    sid: str


@dataclass(frozen=True)
class WindowsAclObservation:
    owner_current_user: bool
    dacl_protected: bool
    principal_count: int
    ace_count: int


_ACCESS_ALLOWED_ACE_TYPE = 0
_ACCESS_DENIED_ACE_TYPE = 1
_OBJECT_INHERIT_ACE = 0x01
_CONTAINER_INHERIT_ACE = 0x02
_INHERIT_ONLY_ACE = 0x08
_GENERIC_ALL = 0x10000000
_FILE_ALL_ACCESS = 0x001F01FF
_LOCAL_SYSTEM_SID = "S-1-5-18"
_BUILTIN_ADMINISTRATORS_SID = "S-1-5-32-544"


def inspect_windows_private_acl(
    path: str | Path,
    *,
    directory: bool,
) -> WindowsAclObservation:
    """Prove one Windows path has a conservative private owner/DACL posture."""

    if os.name != "nt":
        raise WindowsAclError("Windows private ACL assurance is unavailable")
    source = Path(path)
    try:
        before = os.lstat(source)
        owner_sid, protected, aces = _read_windows_acl(source)
        after = os.lstat(source)
    except WindowsAclError:
        raise
    except OSError as exc:
        raise WindowsAclError("cannot inspect Windows state ACL") from exc
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise WindowsAclError("state path changed during Windows ACL inspection")
    return evaluate_windows_private_acl(
        owner_sid=owner_sid,
        current_sid=_current_user_sid(),
        dacl_protected=protected,
        aces=aces,
        directory=directory,
    )


def evaluate_windows_private_acl(
    *,
    owner_sid: str,
    current_sid: str,
    dacl_protected: bool,
    aces: Iterable[WindowsAce],
    directory: bool,
) -> WindowsAclObservation:
    """Evaluate a normalized DACL without exposing trustee identities."""

    if not owner_sid or owner_sid != current_sid:
        raise WindowsAclError("Windows state path must be owned by the current user")
    if directory and not dacl_protected:
        raise WindowsAclError(
            "Windows state root DACL must disable inherited permissions"
        )

    allowed_sids = {
        current_sid,
        _LOCAL_SYSTEM_SID,
        _BUILTIN_ADMINISTRATORS_SID,
    }
    observed_allow_sids: set[str] = set()
    current_effective_mask = 0
    current_object_inherit_mask = 0
    current_container_inherit_mask = 0
    current_effective_deny_mask = 0
    current_object_inherit_deny_mask = 0
    current_container_inherit_deny_mask = 0
    count = 0
    for ace in aces:
        count += 1
        if (
            type(ace.ace_type) is not int
            or type(ace.flags) is not int
            or type(ace.mask) is not int
            or not 0 <= ace.ace_type <= 0xFF
            or not 0 <= ace.flags <= 0xFF
            or not 0 <= ace.mask <= 0xFFFFFFFF
            or not isinstance(ace.sid, str)
            or not ace.sid
        ):
            raise WindowsAclError("Windows state DACL contains an invalid ACE")
        if ace.ace_type == _ACCESS_DENIED_ACE_TYPE:
            if ace.sid == current_sid:
                if not ace.flags & _INHERIT_ONLY_ACE:
                    current_effective_deny_mask |= ace.mask
                if ace.flags & _OBJECT_INHERIT_ACE:
                    current_object_inherit_deny_mask |= ace.mask
                if ace.flags & _CONTAINER_INHERIT_ACE:
                    current_container_inherit_deny_mask |= ace.mask
            continue
        if ace.ace_type != _ACCESS_ALLOWED_ACE_TYPE:
            raise WindowsAclError("Windows state DACL contains an unsupported ACE type")
        if ace.sid not in allowed_sids:
            raise WindowsAclError(
                "Windows state DACL grants access to an unapproved principal"
            )
        observed_allow_sids.add(ace.sid)
        if ace.sid != current_sid:
            continue
        if not ace.flags & _INHERIT_ONLY_ACE:
            current_effective_mask |= ace.mask
        if ace.flags & _OBJECT_INHERIT_ACE:
            current_object_inherit_mask |= ace.mask
        if ace.flags & _CONTAINER_INHERIT_ACE:
            current_container_inherit_mask |= ace.mask

    if current_effective_deny_mask or not _grants_full_control(current_effective_mask):
        raise WindowsAclError(
            "Windows state DACL must grant the current user full control"
        )
    if directory and (
        current_object_inherit_deny_mask
        or current_container_inherit_deny_mask
        or not _grants_full_control(current_object_inherit_mask)
        or not _grants_full_control(current_container_inherit_mask)
    ):
        raise WindowsAclError(
            "Windows state root must inherit current-user full control to children"
        )
    return WindowsAclObservation(
        owner_current_user=True,
        dacl_protected=dacl_protected,
        principal_count=len(observed_allow_sids),
        ace_count=count,
    )


def _grants_full_control(mask: int) -> bool:
    return bool(mask & _GENERIC_ALL) or mask & _FILE_ALL_ACCESS == _FILE_ALL_ACCESS


def _read_windows_acl(path: Path) -> tuple[str, bool, tuple[WindowsAce, ...]]:
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()

    get_named = advapi32.GetNamedSecurityInfoW
    get_named.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    get_named.restype = wintypes.DWORD
    result = get_named(
        str(path),
        1,  # SE_FILE_OBJECT
        0x00000001
        | 0x00000004,  # OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if result != 0:
        raise WindowsAclError("cannot read Windows state security descriptor")
    try:
        if not owner.value:
            raise WindowsAclError("Windows state security descriptor has no owner")
        if not dacl.value:
            raise WindowsAclError("Windows state security descriptor has no safe DACL")
        protected = _dacl_is_protected(advapi32, descriptor)
        return (
            _sid_text(advapi32, kernel32, owner),
            protected,
            _acl_entries(
                advapi32,
                kernel32,
                dacl,
            ),
        )
    finally:
        if descriptor.value:
            _local_free(kernel32, descriptor)


def _dacl_is_protected(advapi32, descriptor: ctypes.c_void_p) -> bool:
    from ctypes import wintypes

    control = ctypes.c_ushort()
    revision = wintypes.DWORD()
    function = advapi32.GetSecurityDescriptorControl
    function.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ushort),
        ctypes.POINTER(wintypes.DWORD),
    ]
    function.restype = wintypes.BOOL
    if not function(descriptor, ctypes.byref(control), ctypes.byref(revision)):
        raise WindowsAclError("cannot inspect Windows DACL control flags")
    return bool(control.value & 0x1000)  # SE_DACL_PROTECTED


def _acl_entries(advapi32, kernel32, dacl: ctypes.c_void_p) -> tuple[WindowsAce, ...]:
    from ctypes import wintypes

    class AclHeader(ctypes.Structure):
        _fields_ = [
            ("AclRevision", ctypes.c_ubyte),
            ("Sbz1", ctypes.c_ubyte),
            ("AclSize", ctypes.c_ushort),
            ("AceCount", ctypes.c_ushort),
            ("Sbz2", ctypes.c_ushort),
        ]

    class AceHeader(ctypes.Structure):
        _fields_ = [
            ("AceType", ctypes.c_ubyte),
            ("AceFlags", ctypes.c_ubyte),
            ("AceSize", ctypes.c_ushort),
        ]

    get_ace = advapi32.GetAce
    get_ace.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    get_ace.restype = wintypes.BOOL
    is_valid_sid = advapi32.IsValidSid
    is_valid_sid.argtypes = [ctypes.c_void_p]
    is_valid_sid.restype = wintypes.BOOL
    get_length_sid = advapi32.GetLengthSid
    get_length_sid.argtypes = [ctypes.c_void_p]
    get_length_sid.restype = wintypes.DWORD

    acl = ctypes.cast(dacl, ctypes.POINTER(AclHeader)).contents
    entries: list[WindowsAce] = []
    for index in range(acl.AceCount):
        pointer = ctypes.c_void_p()
        if not get_ace(dacl, index, ctypes.byref(pointer)) or not pointer.value:
            raise WindowsAclError("cannot inspect Windows state DACL entry")
        header = ctypes.cast(pointer, ctypes.POINTER(AceHeader)).contents
        if header.AceSize < 8:
            raise WindowsAclError("Windows state DACL contains a malformed ACE")
        if header.AceType not in {
            _ACCESS_ALLOWED_ACE_TYPE,
            _ACCESS_DENIED_ACE_TYPE,
        }:
            entries.append(WindowsAce(header.AceType, header.AceFlags, 0, ""))
            continue
        sid_address = pointer.value + 8
        sid_pointer = ctypes.c_void_p(sid_address)
        if not is_valid_sid(sid_pointer):
            raise WindowsAclError("Windows state DACL contains an invalid SID")
        sid_length = get_length_sid(sid_pointer)
        if not sid_length or sid_length > header.AceSize - 8:
            raise WindowsAclError("Windows state DACL contains a malformed SID")
        mask = ctypes.c_uint32.from_address(pointer.value + 4).value
        entries.append(
            WindowsAce(
                header.AceType,
                header.AceFlags,
                mask,
                _sid_text(advapi32, kernel32, sid_pointer),
            )
        )
    return tuple(entries)


def _current_user_sid() -> str:
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class SidAndAttributes(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

    class TokenUser(ctypes.Structure):
        _fields_ = [("User", SidAndAttributes)]

    token = wintypes.HANDLE()
    open_token = advapi32.OpenProcessToken
    open_token.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    open_token.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    if not open_token(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise WindowsAclError("cannot open the current Windows process token")
    try:
        needed = wintypes.DWORD()
        get_info = advapi32.GetTokenInformation
        get_info.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        get_info.restype = wintypes.BOOL
        get_info(token, 1, None, 0, ctypes.byref(needed))  # TokenUser
        if not needed.value:
            raise WindowsAclError("cannot size the current Windows user token")
        buffer = ctypes.create_string_buffer(needed.value)
        if not get_info(
            token,
            1,
            buffer,
            needed.value,
            ctypes.byref(needed),
        ):
            raise WindowsAclError("cannot read the current Windows user token")
        sid = ctypes.cast(buffer, ctypes.POINTER(TokenUser)).contents.User.Sid
        if not sid:
            raise WindowsAclError("the current Windows user token has no SID")
        return _sid_text(advapi32, kernel32, ctypes.c_void_p(sid))
    finally:
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        close_handle(token)


def _sid_text(advapi32, kernel32, sid: ctypes.c_void_p) -> str:
    from ctypes import wintypes

    output = ctypes.c_void_p()
    function = advapi32.ConvertSidToStringSidW
    function.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    function.restype = wintypes.BOOL
    if not function(sid, ctypes.byref(output)) or not output.value:
        raise WindowsAclError("cannot normalize a Windows state trustee")
    try:
        value = ctypes.cast(output, ctypes.c_wchar_p).value
        if not value:
            raise WindowsAclError("cannot normalize a Windows state trustee")
        return value
    finally:
        _local_free(kernel32, output)


def _local_free(kernel32, pointer: ctypes.c_void_p) -> None:
    function = kernel32.LocalFree
    function.argtypes = [ctypes.c_void_p]
    function.restype = ctypes.c_void_p
    function(pointer)
