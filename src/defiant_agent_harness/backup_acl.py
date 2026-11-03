"""Preserve a verified Windows owner/DACL on a new, empty restore directory.

Never repair an existing state root. The caller owns the create-exclusive empty
destination; security is applied and rechecked before any state bytes are copied.
"""

import ctypes
import os

from .persistence import (
    PersistenceError,
    inspect_storage_root,
    require_storage_root_unchanged,
)
from .windows_acl import inspect_windows_private_acl


def preserve_private_directory_acl(source, target):
    if os.name != "nt":
        raise PersistenceError("Windows private ACL restore requires Windows")
    from ctypes import wintypes

    source_observation = inspect_storage_root(source)
    target_observation = inspect_storage_root(target)
    if (
        source_observation is None
        or target_observation is None
        or any(target.iterdir())
    ):
        raise PersistenceError(
            "ACL preservation requires an existing original and empty new candidate"
        )
    expected = inspect_windows_private_acl(source, directory=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    pointer = ctypes.POINTER(ctypes.c_void_p)
    get_named = advapi.GetNamedSecurityInfoW
    get_named.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        pointer,
        pointer,
        pointer,
        pointer,
        pointer,
    ]
    get_named.restype = wintypes.DWORD
    set_named = advapi.SetNamedSecurityInfoW
    set_named.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    set_named.restype = wintypes.DWORD
    local_free = kernel.LocalFree
    local_free.argtypes = [ctypes.c_void_p]
    local_free.restype = ctypes.c_void_p
    # OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, SE_FILE_OBJECT.
    result = get_named(
        str(source),
        1,
        5,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if result:
        raise PersistenceError("cannot read original Windows security descriptor")
    try:
        if not owner.value or not dacl.value:
            raise PersistenceError("original Windows descriptor is incomplete")
        require_storage_root_unchanged(source_observation)
        require_storage_root_unchanged(target_observation)
        # Preserve owner and exact ACL, explicitly protecting the new directory
        # from ambient parent inheritance. Existing source permissions never change.
        if set_named(str(target), 1, 5 | 0x80000000, owner, None, dacl, None):
            raise PersistenceError("cannot preserve private ACL on new candidate")
        if inspect_windows_private_acl(target, directory=True) != expected:
            raise PersistenceError(
                "new candidate did not retain the verified private ACL posture"
            )
        require_storage_root_unchanged(source_observation)
        require_storage_root_unchanged(target_observation)
    finally:
        if descriptor.value:
            local_free(descriptor)
