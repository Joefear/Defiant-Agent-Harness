from __future__ import annotations

import pytest

from defiant_agent_harness.windows_acl import (
    WindowsAce,
    WindowsAclError,
    evaluate_windows_private_acl,
)

CURRENT = "S-1-5-21-1000"
SYSTEM = "S-1-5-18"
ADMINISTRATORS = "S-1-5-32-544"
FOREIGN = "S-1-5-21-2000"
FULL = 0x001F01FF
INHERIT_TO_CHILDREN = 0x01 | 0x02


def _safe_aces(*extra: WindowsAce) -> tuple[WindowsAce, ...]:
    return (
        WindowsAce(0, INHERIT_TO_CHILDREN, FULL, CURRENT),
        WindowsAce(0, INHERIT_TO_CHILDREN, FULL, SYSTEM),
        WindowsAce(0, INHERIT_TO_CHILDREN, FULL, ADMINISTRATORS),
        *extra,
    )


def test_private_windows_acl_accepts_only_the_bounded_trustee_set():
    observation = evaluate_windows_private_acl(
        owner_sid=CURRENT,
        current_sid=CURRENT,
        dacl_protected=True,
        aces=_safe_aces(WindowsAce(1, 0, FULL, FOREIGN)),
        directory=True,
    )

    assert observation.owner_current_user is True
    assert observation.dacl_protected is True
    assert observation.principal_count == 3
    assert observation.ace_count == 4


@pytest.mark.parametrize(
    ("changes", "detail"),
    [
        ({"owner_sid": FOREIGN}, "owned by the current user"),
        ({"dacl_protected": False}, "disable inherited permissions"),
        (
            {"aces": _safe_aces(WindowsAce(0, 0, FULL, FOREIGN))},
            "unapproved principal",
        ),
        (
            {"aces": (WindowsAce(0, INHERIT_TO_CHILDREN, 0x1, CURRENT),)},
            "full control",
        ),
        (
            {"aces": (WindowsAce(0, 0, FULL, CURRENT),)},
            "inherit current-user full control",
        ),
        (
            {"aces": _safe_aces(WindowsAce(1, INHERIT_TO_CHILDREN, 0x2, CURRENT))},
            "full control",
        ),
        (
            {"aces": _safe_aces(WindowsAce(5, 0, FULL, CURRENT))},
            "unsupported ACE type",
        ),
    ],
)
def test_private_windows_acl_rejects_ambiguous_or_broad_posture(changes, detail):
    arguments = {
        "owner_sid": CURRENT,
        "current_sid": CURRENT,
        "dacl_protected": True,
        "aces": _safe_aces(),
        "directory": True,
        **changes,
    }
    with pytest.raises(WindowsAclError, match=detail):
        evaluate_windows_private_acl(**arguments)


def test_private_file_acl_does_not_require_a_protected_child_dacl():
    observation = evaluate_windows_private_acl(
        owner_sid=CURRENT,
        current_sid=CURRENT,
        dacl_protected=False,
        aces=(WindowsAce(0, 0, FULL, CURRENT),),
        directory=False,
    )

    assert observation.dacl_protected is False
    assert observation.principal_count == 1
