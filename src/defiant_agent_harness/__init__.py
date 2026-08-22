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
from .authority_profile import (
    AuthorityProfileError,
    AuthorityProfileState,
    AuthorityProfileStore,
)
from .orchestrator.harness import (
    AuthorizationReconciliationOutcome,
    Harness,
    build_harness,
)
from .operator_identity import (
    AuthorizationReconciliationSubject,
    sign_authorization_reconciliation,
    sign_authority_profile_transition,
)
from .operator_trust_state import (
    OperatorTrustState,
    OperatorTrustStateError,
    OperatorTrustStateStore,
)
from .operation_journal import (
    ExecutionCompletionSubject,
    JournalOperation,
    OperationJournal,
    OperationJournalError,
)
from .persistence import AuthorityLockError, AuthorityTransactionLock
from .state_integrity import (
    IntegrityIssue,
    StateIntegrityAuditor,
    StateIntegrityError,
    StateIntegrityReport,
)
from .runtime_artifacts import (
    RuntimeArtifactAssurance,
    RuntimeArtifactError,
    RuntimeArtifactPin,
    RuntimeArtifactState,
    RuntimeArtifactStateStore,
)
from .launch_envelope import (
    LaunchEnvironmentConfig,
    LaunchEnvelopeAssurance,
    LaunchEnvelopeError,
    LaunchEnvelopeState,
    LaunchEnvelopeStateStore,
)
from .state_storage import (
    StateStorageAssurance,
    StateStorageError,
    StateStorageState,
    StateStorageStateStore,
)

__version__ = "0.18.0"

__all__ = [
    "CapabilityGrant",
    "AuthorizationReconciliationOutcome",
    "AuthorizationReconciliationSubject",
    "AuthorityLockError",
    "AuthorityProfileError",
    "AuthorityProfileState",
    "AuthorityProfileStore",
    "AuthorityTransactionLock",
    "ContentRef",
    "Decision",
    "EvidenceRecord",
    "ExecutionCompletionSubject",
    "GrantError",
    "GuardrailDecision",
    "Harness",
    "HarnessRequest",
    "IntegrityIssue",
    "LaunchEnvironmentConfig",
    "LaunchEnvelopeAssurance",
    "LaunchEnvelopeError",
    "LaunchEnvelopeState",
    "LaunchEnvelopeStateStore",
    "OperatorTrustState",
    "OperatorTrustStateError",
    "OperatorTrustStateStore",
    "JournalOperation",
    "OperationJournal",
    "OperationJournalError",
    "ProposedAction",
    "ResultStatus",
    "RuntimeArtifactAssurance",
    "RuntimeArtifactError",
    "RuntimeArtifactPin",
    "RuntimeArtifactState",
    "RuntimeArtifactStateStore",
    "Sensitivity",
    "SideEffect",
    "StateIntegrityAuditor",
    "StateIntegrityError",
    "StateIntegrityReport",
    "StateStorageAssurance",
    "StateStorageError",
    "StateStorageState",
    "StateStorageStateStore",
    "Trust",
    "build_harness",
    "sign_authorization_reconciliation",
    "sign_authority_profile_transition",
]
