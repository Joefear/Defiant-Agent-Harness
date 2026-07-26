"""Defiant Agent Harness.

Control, approvals, budgets, memory discipline, and audit evidence for
business-grade AI agents.

The invariant the whole package exists to enforce:

    No side-effecting tool action executes unless it passed the policy
    decision path and produced an evidence record first.

Enforced at the registered tool boundary: tools reject execution without a
single-use, registry-signed CapabilityGrant tied to sealed authorization
evidence and the complete action.
"""

from .contracts import (
    CapabilityGrant,
    ContentRef,
    Decision,
    EvidenceRecord,
    GrantError,
    GuardrailDecision,
    HarnessRequest,
    ProposedAction,
    ResultStatus,
    Sensitivity,
    SideEffect,
    Trust,
)
from .orchestrator.harness import Harness, build_harness

__version__ = "0.2.0"

__all__ = [
    "CapabilityGrant",
    "ContentRef",
    "Decision",
    "EvidenceRecord",
    "GrantError",
    "GuardrailDecision",
    "Harness",
    "HarnessRequest",
    "ProposedAction",
    "ResultStatus",
    "Sensitivity",
    "SideEffect",
    "Trust",
    "build_harness",
]
