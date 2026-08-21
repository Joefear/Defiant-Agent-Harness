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
from .state_integrity import (
    IntegrityIssue,
    StateIntegrityAuditor,
    StateIntegrityError,
    StateIntegrityReport,
)

__version__ = "0.9.0"

__all__ = [
    "CapabilityGrant",
    "ContentRef",
    "Decision",
    "EvidenceRecord",
    "GrantError",
    "GuardrailDecision",
    "Harness",
    "HarnessRequest",
    "IntegrityIssue",
    "ProposedAction",
    "ResultStatus",
    "Sensitivity",
    "SideEffect",
    "StateIntegrityAuditor",
    "StateIntegrityError",
    "StateIntegrityReport",
    "Trust",
    "build_harness",
]
