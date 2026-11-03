"""Lifetime exclusion between supported entry points and operator maintenance.

This is separate from the short authority transaction lock. It does not attest
that an external host tool stopped, fence an older binary, or lock another root.
"""

from contextlib import contextmanager
from functools import wraps
import os
from pathlib import Path
from threading import Lock

from .persistence import AuthorityTransactionLock, PersistenceError, inspect_state_file

LEASE_FILE = "runtime.lease"
INCOMPLETE_FILE = "restore_incomplete.json"
_LEASE_GUARD = Lock()
_LOCAL_LEASES = {}


def require_complete_restore(root):
    if os.path.lexists(Path(root) / INCOMPLETE_FILE):
        raise PersistenceError(
            "incomplete restore candidate; preserve it and refuse startup"
        )


@contextmanager
def runtime_session(root):
    require_complete_restore(root)
    key = os.path.normcase(os.path.abspath(root))
    with _LEASE_GUARD:
        local_lock = _LOCAL_LEASES.setdefault(key, Lock())
    # Unlike authority transactions, maintenance/lifetime ownership must not
    # reenter on the same thread and mistake a live runtime for quiescence.
    if not local_lock.acquire(blocking=False):
        raise PersistenceError("runtime or maintenance is busy for state directory")
    try:
        with AuthorityTransactionLock(Path(root) / LEASE_FILE).acquire():
            require_complete_restore(root)
            yield
    finally:
        local_lock.release()


def leased_runtime(root_argument):
    """Wrap keyword-only CLI/runner entry points, including upstream teardown."""

    def decorate(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            with runtime_session(kwargs[root_argument]):
                return function(*args, **kwargs)

        return wrapped

    return decorate


@contextmanager
def maintenance_session(root):
    root = Path(root)
    # Do not initialize an unknown/old root, even on a refusal path.
    for name in (LEASE_FILE, "authority.lock"):
        observed = inspect_state_file(root / name)
        if observed is None or observed.st_size != 1:
            raise PersistenceError(
                "maintenance requires an enrolled, stopped v0.101+ runtime"
            )
    with runtime_session(root):
        with AuthorityTransactionLock(root / "authority.lock").acquire():
            yield
