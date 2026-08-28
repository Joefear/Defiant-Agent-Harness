const elements = {
  refresh: document.querySelector("#refresh-button"),
  filterForm: document.querySelector("#filter-form"),
  requestFilter: document.querySelector("#request-filter"),
  recordLimit: document.querySelector("#record-limit"),
  clearFilter: document.querySelector("#clear-filter"),
  syncState: document.querySelector("#sync-state"),
  syncLabel: document.querySelector("#sync-label"),
  errorBanner: document.querySelector("#error-banner"),
  errorDetail: document.querySelector("#error-detail"),
  stateIntegrityBanner: document.querySelector("#state-integrity-banner"),
  stateIntegrityTitle: document.querySelector("#state-integrity-title"),
  stateIntegrityDetail: document.querySelector("#state-integrity-detail"),
  reconciliationBanner: document.querySelector("#reconciliation-banner"),
  reconciliationDetail: document.querySelector("#reconciliation-detail"),
  integrityOrb: document.querySelector("#integrity-orb"),
  integrityTitle: document.querySelector("#integrity-title"),
  integrityDetail: document.querySelector("#integrity-detail"),
  updatedAt: document.querySelector("#updated-at"),
  recordCount: document.querySelector("#record-count"),
  requestCount: document.querySelector("#request-count"),
  approvalCount: document.querySelector("#approval-count"),
  approvalDetail: document.querySelector("#approval-detail"),
  availableBudget: document.querySelector("#available-budget"),
  budgetDetail: document.querySelector("#budget-detail"),
  profileGeneration: document.querySelector("#profile-generation"),
  profileDetail: document.querySelector("#profile-detail"),
  evidenceFilterBadge: document.querySelector("#evidence-filter-badge"),
  decisionBars: document.querySelector("#decision-bars"),
  withheldState: document.querySelector("#withheld-state"),
  decisionAllow: document.querySelector("#decision-allow"),
  decisionBlock: document.querySelector("#decision-block"),
  decisionApproval: document.querySelector("#decision-approval"),
  barAllow: document.querySelector("#bar-allow"),
  barBlock: document.querySelector("#bar-block"),
  barApproval: document.querySelector("#bar-approval"),
  evidenceCost: document.querySelector("#evidence-cost"),
  rulesetCount: document.querySelector("#ruleset-count"),
  latestEvent: document.querySelector("#latest-event"),
  budgetState: document.querySelector("#budget-state"),
  budgetAvailableDetail: document.querySelector("#budget-available-detail"),
  budgetBalance: document.querySelector("#budget-balance"),
  budgetReserved: document.querySelector("#budget-reserved"),
  budgetSpent: document.querySelector("#budget-spent"),
  budgetDrift: document.querySelector("#budget-drift"),
  approvalBadge: document.querySelector("#approval-badge"),
  approvalList: document.querySelector("#approval-list"),
  approvalsEmpty: document.querySelector("#approvals-empty"),
  activityCount: document.querySelector("#activity-count"),
  activityTableWrap: document.querySelector("#activity-table-wrap"),
  activityBody: document.querySelector("#activity-body"),
  activityEmpty: document.querySelector("#activity-empty"),
  resourceLimits: document.querySelector("#resource-limits"),
};

const compact = new Intl.NumberFormat(undefined, { notation: "compact" });
const integer = new Intl.NumberFormat();
const usd = new Intl.NumberFormat(undefined, {
  style: "currency",
  currency: "USD",
  maximumFractionDigits: 2,
});

const view = {
  requestId: "",
  limit: 25,
};

function money(value) {
  const amount = Number(value);
  return Number.isFinite(amount) ? usd.format(amount) : "—";
}

function label(value) {
  return String(value || "unknown")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function shortId(value) {
  const text = String(value || "—");
  return text.length > 20 ? `${text.slice(0, 12)}…${text.slice(-5)}` : text;
}

function time(value, includeDate = false) {
  if (!value) return "—";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.valueOf())) return "—";
  return parsed.toLocaleString([], includeDate
    ? { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }
    : { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function bytes(value) {
  const amount = Number(value);
  if (!Number.isFinite(amount) || amount < 0) return "—";
  if (amount % (1024 * 1024) === 0) {
    return `${integer.format(amount / (1024 * 1024))} MiB`;
  }
  return `${integer.format(amount)} bytes`;
}

function renderResourceLimits(limits, configuration) {
  if (!limits) {
    elements.resourceLimits.textContent = "Resource ceilings unavailable";
    return;
  }
  const details = [
    `Resource ceilings: tool call name ${integer.format(limits.tool_call_name_characters)} characters`,
    `tool call identifier ${integer.format(limits.tool_call_identifier_characters)} characters`,
    `tool call mapping ${integer.format(limits.tool_call_mapping_entries)} entries`,
    `tool call mapping sort work ${integer.format(limits.tool_call_mapping_sort_work_units)} units`,
    `tool call canonical input ${bytes(limits.tool_call_canonical_bytes)}`,
    `tool call depth ${integer.format(limits.tool_call_nesting_depth)}`,
    `tool call nodes ${integer.format(limits.tool_call_nodes)}`,
    `tool call number ${integer.format(limits.tool_call_number_characters)} characters`,
    `tool call scalar ${integer.format(limits.tool_call_scalar_characters)} characters`,
    `tool call escaped string ${bytes(limits.tool_call_string_token_bytes)}`,
    `action hash canonical input ${bytes(limits.action_hash_canonical_bytes)}`,
    `action hash mapping ${integer.format(limits.action_hash_mapping_entries)} entries`,
    `action hash mapping sort work ${integer.format(limits.action_hash_mapping_sort_work_units)} units`,
    `action hash depth ${integer.format(limits.action_hash_nesting_depth)}`,
    `action hash nodes ${integer.format(limits.action_hash_nodes)}`,
    `action hash number ${integer.format(limits.action_hash_number_characters)} characters`,
    `action hash scalar ${integer.format(limits.action_hash_scalar_characters)} characters`,
    `action hash escaped string ${bytes(limits.action_hash_string_token_bytes)}`,
    `tool result summary ${integer.format(limits.tool_result_summary_characters)} characters`,
    `tool result output ${bytes(limits.tool_result_output_canonical_bytes)}`,
    `tool result mapping ${integer.format(limits.tool_result_output_mapping_entries)} entries`,
    `tool result mapping sort work ${integer.format(limits.tool_result_output_mapping_sort_work_units)} units`,
    `tool result depth ${integer.format(limits.tool_result_output_nesting_depth)}`,
    `tool result nodes ${integer.format(limits.tool_result_output_nodes)}`,
    `tool result number ${integer.format(limits.tool_result_output_number_characters)} characters`,
    `tool result scalar ${integer.format(limits.tool_result_output_scalar_characters)} characters`,
    `tool result escaped string ${bytes(limits.tool_result_output_string_token_bytes)}`,
    `request task ${integer.format(limits.request_task_characters)} characters`,
    `request identifier ${integer.format(limits.request_identifier_characters)} characters`,
    `request allowed tools ${integer.format(limits.request_allowed_tool_count)} items`,
    `request allowed tool ${integer.format(limits.request_allowed_tool_characters)} characters`,
    `request text aggregate ${integer.format(limits.request_text_characters)} characters`,
    `provenance refs ${integer.format(limits.provenance_ref_count)}`,
    `provenance text item ${integer.format(limits.provenance_text_item_characters)} characters`,
    `provenance text aggregate ${integer.format(limits.provenance_text_characters)} characters`,
    `state ${bytes(limits.durable_json_bytes)}`,
    `evidence record ${bytes(limits.evidence_record_bytes)}`,
    `evidence export ${bytes(limits.evidence_export_bytes)}`,
    `MCP message ${bytes(limits.mcp_message_bytes)}`,
    `hook event ${bytes(limits.hook_event_bytes)}`,
    `hook execution state ${bytes(limits.hook_execution_state_bytes)}`,
    `approval state ${bytes(limits.approval_state_bytes)}`,
    `budget state ${bytes(limits.budget_state_bytes)}`,
    `operation journal ${bytes(limits.operation_journal_bytes)}`,
    `authority profile state ${bytes(limits.authority_profile_state_bytes)}`,
    `operator trust state ${bytes(limits.operator_trust_state_bytes)}`,
    `JSON depth ${integer.format(limits.json_nesting_depth)}`,
    `JSON lexical tokens ${integer.format(limits.json_lexical_tokens)}`,
    `JSON string token ${integer.format(limits.json_string_token_characters)} characters`,
    `JSON number token ${integer.format(limits.json_number_token_characters)} characters`,
    `MCP config ${bytes(limits.mcp_config_bytes)}`,
    `MCP config collection ${integer.format(limits.mcp_config_collection_items)} items`,
    `MCP dependency pins ${integer.format(limits.mcp_dependency_file_pins)}`,
    `MCP launch environment ${integer.format(limits.mcp_launch_environment_entries)} entries`,
    `policy pack ${bytes(limits.policy_pack_bytes)}`,
    `policy packs ${integer.format(limits.policy_pack_count)}`,
    `policy rules ${integer.format(limits.policy_rule_count)}`,
    `policy known tools ${integer.format(limits.policy_known_tool_count)}`,
    `policy rule field items ${integer.format(limits.policy_rule_field_items)}`,
    `policy rule list items ${integer.format(limits.policy_rule_list_items)}`,
    `policy text item ${integer.format(limits.policy_text_item_characters)} characters`,
    `policy text aggregate ${integer.format(limits.policy_text_characters)} characters`,
    `policy match payload depth ${integer.format(limits.policy_match_payload_nesting_depth)}`,
    `policy match payload nodes ${integer.format(limits.policy_match_payload_nodes)}`,
    `policy match payload ${integer.format(limits.policy_match_payload_characters)} characters`,
    `policy payload match work ${integer.format(limits.policy_payload_match_work_units)} units`,
    `policy match tool name ${integer.format(limits.policy_match_tool_name_characters)} characters`,
    `policy match target ${integer.format(limits.policy_match_target_characters)} characters`,
    `policy glob match work ${integer.format(limits.policy_glob_match_work_units)} units`,
    `policy context entries ${integer.format(limits.policy_context_entries)}`,
    `policy context key ${integer.format(limits.policy_context_key_characters)} characters`,
    `policy context value ${integer.format(limits.policy_context_value_characters)} characters`,
    `policy context aggregate ${integer.format(limits.policy_context_characters)} characters`,
    `trusted keys ${integer.format(limits.trusted_public_key_count)}`,
    `trusted key ${bytes(limits.trusted_public_key_bytes)}`,
    `trusted key set ${bytes(limits.trusted_public_key_set_bytes)}`,
    `YAML depth ${integer.format(limits.yaml_nesting_depth)}`,
    `YAML nodes ${integer.format(limits.yaml_nodes)}`,
  ];
  if (configuration) {
    const policyOwnership = configuration.validated_policy_snapshot_ownership
      ? "policy rules, known tools, and authority inputs retained from one detached bounded snapshot"
      : "policy snapshot ownership unverified";
    const policyRuntime = configuration.sealed_policy_runtime_state
      ? "policy runtime rules and tool patterns immutable with defensive authority projections"
      : "policy runtime seal unverified";
    const policyContext = configuration.validated_policy_context_snapshot
      ? "policy decision context bounded and retained from one exact string metadata snapshot"
      : "policy context snapshot unverified";
    const operationJournal = configuration.validated_operation_journal_snapshot
      ? "operation journal payload bounded, hashed from one exact snapshot, and sealed behind defensive projections"
      : "operation journal snapshot unverified";
    const nativeHookEvent = configuration.validated_native_hook_event_snapshot
      ? "native hook retry identity, authorization, targeting, payload, and completion derived from one bounded exact event snapshot"
      : "native hook event snapshot unverified";
    const authorityContinuity = configuration.sealed_authority_continuity_state
      ? "authority profile and operator trust state retained as sealed bounded snapshots with defensive projections and symmetric publication limits"
      : "authority continuity state seal unverified";
    const nativeHookCorrelation = configuration.sealed_native_hook_correlation_state
      ? "native hook authorization and completion correlation retained as sealed bounded snapshots with copy-on-write transitions"
      : "native hook correlation state seal unverified";
    const approvalRecordState = configuration.sealed_approval_record_state
      ? "approval records and held authority snapshots retained as sealed bounded state with copy-on-write lifecycle transitions"
      : "approval record state seal unverified";
    const budgetLedgerSnapshot = configuration.validated_budget_ledger_snapshot
      ? "budget validation and publication use detached bounded canonical ledger snapshots with symmetric I/O limits"
      : "budget ledger snapshot integrity unverified";
    details.push(
      `authority YAML ${label(configuration.yaml_parser_profile)} (aliases and duplicate keys refused; MCP collections bounded before transformation; policy text bounded before transformation; ${policyOwnership}; ${policyRuntime}; ${policyContext}; ${operationJournal}; ${nativeHookEvent}; ${authorityContinuity}; ${nativeHookCorrelation}; ${approvalRecordState}; ${budgetLedgerSnapshot}; canonical mapping key families and complete key tokens, size, sort work, values, strings, and numbers preflighted into a detached validated snapshot adopted directly by action, tool-call, and tool-result owners; request allowlist, request input, and action provenance collections snapshotted from built-in storage before validation; accepted scalar subclasses normalized to exact built-in values before ownership; policy decisions, capability grants, evidence records, and operation journals retain bounded exact built-in snapshots; governed request construction, tool-call translation, action hashing, tool-result capture, payload matching, glob matching, policy context, and journal publication bounded and fail-closed)`,
      `authority JSON ${label(configuration.json_parser_profile)} (strict UTF-8, bounded structure and scalars, duplicate keys and non-finite numbers refused)`,
    );
  }
  elements.resourceLimits.textContent = details.join(", ");
}

function tone(value) {
  if (String(value).startsWith("reconciliation_")) return "signal";
  if (["allow", "succeeded", "approved", "signed_trusted"].includes(value)) return "healthy";
  if (["block", "blocked", "failed", "rejected", "expired", "not_executed"].includes(value)) {
    return "danger";
  }
  if (["approval_required", "pending", "pending_approval", "executing"].includes(value)) {
    return "signal";
  }
  return "neutral";
}

function statusChip(value) {
  const chip = document.createElement("span");
  chip.className = "status-chip";
  chip.dataset.tone = tone(value);
  chip.textContent = label(value);
  return chip;
}

function setBar(element, value, total) {
  const width = total > 0 ? Math.max(2, (value / total) * 100) : 0;
  element.style.width = `${width}%`;
}

function renderIntegrity(snapshot) {
  const integrity = snapshot.evidence_integrity;
  elements.integrityOrb.classList.remove("is-loading", "is-broken");
  elements.integrityOrb.classList.toggle("is-broken", !integrity.ok);
  elements.integrityTitle.textContent = integrity.ok ? "Chain intact" : "Integrity alert";
  elements.integrityDetail.textContent = integrity.ok
    ? `${integer.format(integrity.count)} verified records`
    : integrity.detail;
  elements.updatedAt.textContent = time(snapshot.generated_at);
}

function renderStateIntegrity(integrity) {
  const critical = integrity.issue_counts.critical || 0;
  const warnings = integrity.issue_counts.warning || 0;
  const visible = integrity.status !== "healthy";
  elements.stateIntegrityBanner.hidden = !visible;
  elements.stateIntegrityBanner.classList.toggle(
    "is-warning",
    integrity.status === "recovery_required",
  );
  elements.stateIntegrityTitle.textContent = integrity.safe_to_execute
    ? "State recovery required."
    : "State integrity alert.";
  const journal = integrity.stores.operation_journal;
  elements.stateIntegrityDetail.textContent = integrity.safe_to_execute
    ? journal && journal.active
      ? `Prepared ${label(journal.kind)} operation ${shortId(journal.operation_id)} requires authority recovery. This dashboard remains read-only.`
      : `${integer.format(warnings)} recovery condition${warnings === 1 ? "" : "s"} detected. Inspect the read-only doctor report.`
    : `${integer.format(critical)} critical ${critical === 1 ? "inconsistency" : "inconsistencies"} detected. Authority-bearing operations are blocked.`;
}

function renderEvidence(evidence) {
  const available = evidence !== null;
  elements.decisionBars.hidden = !available;
  elements.withheldState.hidden = available;

  if (!available) {
    elements.recordCount.textContent = "—";
    elements.requestCount.textContent = "Totals withheld until integrity is restored";
    elements.evidenceCost.textContent = "—";
    elements.rulesetCount.textContent = "—";
    elements.latestEvent.textContent = "—";
    return;
  }

  elements.recordCount.textContent = compact.format(evidence.record_count);
  elements.requestCount.textContent = `${compact.format(evidence.request_count)} requests · ${compact.format(evidence.action_count)} actions`;
  elements.evidenceFilterBadge.textContent = evidence.filtered_request_id
    ? `Request ${shortId(evidence.filtered_request_id)}`
    : "All requests";

  const decisions = evidence.decisions;
  const allowed = decisions.allow || 0;
  const blocked = decisions.block || 0;
  const approval = decisions.approval_required || 0;
  const total = allowed + blocked + approval;
  elements.decisionAllow.textContent = integer.format(allowed);
  elements.decisionBlock.textContent = integer.format(blocked);
  elements.decisionApproval.textContent = integer.format(approval);
  setBar(elements.barAllow, allowed, total);
  setBar(elements.barBlock, blocked, total);
  setBar(elements.barApproval, approval, total);

  elements.evidenceCost.textContent = money(evidence.total_cost_usd);
  elements.rulesetCount.textContent = integer.format(evidence.ruleset_hashes.length);
  elements.latestEvent.textContent = time(evidence.latest_event_at, true);
}

function renderApprovals(approvals, operatorTrust, authorizationReconciliation) {
  const authorizationCount = authorizationReconciliation.required_count || 0;
  const queueCount = approvals.actionable_count + authorizationCount;
  elements.approvalCount.textContent = compact.format(queueCount);
  elements.approvalBadge.textContent = integer.format(queueCount);
  const approvalReconciliationCount = approvals.reconciliation_required_count || 0;
  const reconciliationCount = approvalReconciliationCount + authorizationCount;
  const trustDetail = operatorTrust.state === "ready"
    ? operatorTrust.verification === "verified"
      ? `Signed trust g${operatorTrust.generation}`
      : `Trust ${label(operatorTrust.verification)}`
    : "Operator trust not enrolled";
  const approvalDetail = reconciliationCount
    ? `${compact.format(reconciliationCount)} require reconciliation`
    : approvals.overdue_pending_count
      ? `${compact.format(approvals.overdue_pending_count)} overdue pending`
      : "No overdue pending approvals";
  elements.approvalDetail.textContent = `${approvalDetail} · ${trustDetail}`;
  elements.reconciliationBanner.hidden = reconciliationCount === 0;
  elements.reconciliationDetail.textContent = reconciliationCount
    ? `${integer.format(reconciliationCount)} uncertain execution${reconciliationCount === 1 ? "" : "s"} (${integer.format(approvalReconciliationCount)} approval, ${integer.format(authorizationCount)} approval-free) must be reconciled from the operator CLI. Command Center remains visibility-only.`
    : "";
  elements.approvalList.replaceChildren();
  elements.approvalsEmpty.hidden = queueCount > 0;

  for (const approval of approvals.actionable) {
    const item = document.createElement("article");
    item.className = "approval-item";
    item.classList.toggle("is-reconciliation-required", approval.reconciliation_required);
    const knownResultRecovery = approval.reconciliation_state === "known_result_recovery";

    const identity = document.createElement("div");
    const tool = document.createElement("strong");
    tool.textContent = approval.tool_name || "Unknown tool";
    const id = document.createElement("p");
    id.textContent = shortId(approval.approval_id);
    id.title = approval.approval_id;
    identity.append(tool, id);

    const status = document.createElement("div");
    const statusLabel = document.createElement("p");
    statusLabel.className = "approval-item-label";
    statusLabel.textContent = approval.reconciliation_required
      ? "Operator action"
      : knownResultRecovery
        ? "Automatic recovery"
        : "Status";
    status.append(
      statusLabel,
      statusChip(approval.reconciliation_required
        ? `reconciliation_${approval.reconciliation_state}`
        : knownResultRecovery
          ? approval.reconciliation_state
          : approval.status),
    );
    const operatorIdentity = approval.reconciliation_identity || approval.operator_identity;
    if (operatorIdentity && operatorIdentity.assurance !== "not_applicable") {
      const identityLabel = document.createElement("p");
      identityLabel.className = "operator-assurance";
      const operator = operatorIdentity.operator || "asserted operator";
      const key = operatorIdentity.key_id ? ` · ${shortId(operatorIdentity.key_id)}` : "";
      identityLabel.textContent = `${label(operatorIdentity.assurance)} · ${operator}${key}`;
      identityLabel.title = operatorIdentity.detail;
      status.append(identityLabel);
    }

    const request = document.createElement("div");
    const requestLabel = document.createElement("p");
    requestLabel.className = "approval-item-label";
    requestLabel.textContent = "Request / action";
    const requestValue = document.createElement("strong");
    requestValue.textContent = `${shortId(approval.request_id)} / ${shortId(approval.action_id)}`;
    request.append(requestLabel, requestValue);

    const expiry = document.createElement("div");
    const expiryLabel = document.createElement("p");
    expiryLabel.className = "approval-item-label";
    expiryLabel.textContent = "Expires";
    const expiryValue = document.createElement("strong");
    expiryValue.textContent = approval.expires_at ? time(approval.expires_at, true) : "No expiry";
    expiry.append(expiryLabel, expiryValue);

    item.append(identity, status, request, expiry);
    elements.approvalList.append(item);
  }

  for (const authorization of authorizationReconciliation.items || []) {
    const item = document.createElement("article");
    item.className = "approval-item is-reconciliation-required";

    const identity = document.createElement("div");
    const tool = document.createElement("strong");
    tool.textContent = authorization.tool_name || "Unknown tool";
    const id = document.createElement("p");
    id.textContent = shortId(authorization.authority_record_id);
    id.title = authorization.authority_record_id;
    identity.append(tool, id);

    const status = document.createElement("div");
    const statusLabel = document.createElement("p");
    statusLabel.className = "approval-item-label";
    statusLabel.textContent = "Operator action";
    status.append(statusLabel, statusChip("reconciliation_required"));

    const request = document.createElement("div");
    const requestLabel = document.createElement("p");
    requestLabel.className = "approval-item-label";
    requestLabel.textContent = "Request / action";
    const requestValue = document.createElement("strong");
    requestValue.textContent = `${shortId(authorization.request_id)} / ${shortId(authorization.action_id)}`;
    request.append(requestLabel, requestValue);

    const authorized = document.createElement("div");
    const authorizedLabel = document.createElement("p");
    authorizedLabel.className = "approval-item-label";
    authorizedLabel.textContent = "Authorized";
    const authorizedValue = document.createElement("strong");
    authorizedValue.textContent = time(authorization.authorized_at, true);
    authorized.append(authorizedLabel, authorizedValue);

    item.append(identity, status, request, authorized);
    elements.approvalList.append(item);
  }
}

function renderBudget(budget) {
  const ready = budget.state === "ready";
  const summary = budget.summary;
  const drift = budget.drift;
  elements.budgetState.textContent = ready
    ? "Ledger ready"
    : budget.state === "invalid"
      ? "State invalid"
      : "Not initialized";
  elements.availableBudget.textContent = ready ? money(summary.available_usd) : "Not set";
  elements.budgetDetail.textContent = ready
    ? `${money(summary.reserved_usd)} reserved`
    : "Ledger not initialized";
  elements.budgetAvailableDetail.textContent = money(summary.available_usd);
  elements.budgetBalance.textContent = money(summary.balance_usd);
  elements.budgetReserved.textContent = money(summary.reserved_usd);
  elements.budgetSpent.textContent = money(summary.total_spent_usd);
  elements.budgetDrift.textContent = `${money(drift.drift_usd)} · ${drift.drift_pct}%`;
}

function renderAuthorityProfile(
  profile,
  artifacts,
  launchEnvelope,
  stateStorage,
  controlPlaneIsolation,
  workspaceIntegrity,
  evidenceHead,
  evidenceWitness,
) {
  if (!profile || profile.state === "not_enrolled") {
    elements.profileGeneration.textContent = "—";
    elements.profileDetail.textContent = "Not enrolled";
    return;
  }
  elements.profileGeneration.textContent = `g${profile.generation}`;
  const hash = shortId(profile.profile_hash);
  const profileDetail = profile.rotation_required
    ? `Rotation required · ${label(profile.pending_assurance)} · ${shortId(profile.pending_profile_hash)}`
    : `${label(profile.verification)} · ${hash}`;
  const artifactDetail = artifacts && artifacts.state === "closed"
    ? `${integer.format(artifacts.dependency_file_count)} dependency files in ${integer.format(artifacts.dependency_root_count)} closed roots · ${shortId(artifacts.bundle_hash)}`
    : artifacts && artifacts.state === "pinned"
    ? `${integer.format(artifacts.artifact_count)} pinned · ${shortId(artifacts.bundle_hash)}`
    : artifacts
      ? label(artifacts.state)
      : "Not recorded";
  const launchDetail = launchEnvelope
    ? `${label(launchEnvelope.state)} · ${integer.format(launchEnvelope.variable_count || 0)} vars`
    : "Not recorded";
  const storageAclDetail = stateStorage?.acl_policy
    ? ` · protected ACL · ${integer.format(stateStorage.acl_principal_count || 0)} principals`
    : "";
  const storageDetail = stateStorage
    ? `${label(stateStorage.state)} · ${integer.format(stateStorage.files_checked || 0)} files${storageAclDetail}`
    : "Not recorded";
  const isolationDetail = controlPlaneIsolation
    ? `${label(controlPlaneIsolation.state)} · ${integer.format(controlPlaneIsolation.protected_root_count || 0)} roots · ${label(controlPlaneIsolation.relationship)}`
    : "Not recorded";
  const workspaceDetail = workspaceIntegrity
    ? `${label(workspaceIntegrity.state)} · ${label(workspaceIntegrity.verification)} · ${shortId(workspaceIntegrity.root_hash)}`
    : "Not recorded";
  const evidenceHeadDetail = evidenceHead
    ? `${label(evidenceHead.state)} · ${label(evidenceHead.verification)} · ${integer.format(evidenceHead.record_count || 0)} records`
    : "Not recorded";
  const evidenceWitnessLag = evidenceWitness?.max_unwitnessed_records == null
    ? "unbounded lag"
    : `${integer.format(evidenceWitness.unwitnessed_record_count || 0)}/${integer.format(evidenceWitness.max_unwitnessed_records)} unwitnessed`;
  const evidenceWitnessDetail = evidenceWitness
    ? `${label(evidenceWitness.state)} · ${label(evidenceWitness.verification)} · ${integer.format(evidenceWitness.witnessed_record_count || 0)} records · ${evidenceWitnessLag}`
    : "Not configured";
  elements.profileDetail.textContent = `${profileDetail} · Evidence head ${evidenceHeadDetail} · External witness ${evidenceWitnessDetail} · Workspace ${workspaceDetail} · Isolation ${isolationDetail} · Storage ${storageDetail} · Artifacts ${artifactDetail} · Launch ${launchDetail}`;
}

function renderActivity(activity) {
  elements.activityBody.replaceChildren();
  elements.activityCount.textContent = `${integer.format(activity.length)} records`;
  elements.activityTableWrap.hidden = activity.length === 0;
  elements.activityEmpty.hidden = activity.length > 0;

  for (const record of activity) {
    const row = document.createElement("tr");
    const timestamp = document.createElement("td");
    timestamp.textContent = time(record.timestamp, true);
    const tool = document.createElement("td");
    tool.textContent = record.tool_name || "—";
    const decision = document.createElement("td");
    decision.append(statusChip(record.decision));
    const result = document.createElement("td");
    result.append(statusChip(record.result_status));
    const identifiers = document.createElement("td");
    identifiers.className = "mono-pair";
    identifiers.textContent = `${shortId(record.request_id)} / ${shortId(record.action_id)}`;
    identifiers.title = `${record.request_id} / ${record.action_id}`;
    const cost = document.createElement("td");
    cost.className = "number-cell";
    cost.textContent = money(record.cost_usd);
    row.append(timestamp, tool, decision, result, identifiers, cost);
    elements.activityBody.append(row);
  }
}

function renderSnapshot(snapshot) {
  renderIntegrity(snapshot);
  renderStateIntegrity(snapshot.state_integrity);
  renderEvidence(snapshot.evidence);
  renderApprovals(
    snapshot.approvals,
    snapshot.operator_trust,
    snapshot.authorization_reconciliation,
  );
  renderBudget(snapshot.budget);
  renderResourceLimits(snapshot.resource_limits, snapshot.authority_configuration);
  renderAuthorityProfile(
    snapshot.authority_profile,
    snapshot.runtime_artifacts,
    snapshot.launch_envelope,
    snapshot.state_storage,
    snapshot.control_plane_isolation,
    snapshot.workspace_integrity,
    snapshot.evidence_head,
    snapshot.evidence_witness,
  );
  renderActivity(snapshot.recent_activity);
  elements.errorBanner.hidden = true;
}

function renderError(error) {
  elements.integrityOrb.classList.remove("is-loading");
  elements.integrityOrb.classList.add("is-broken");
  elements.integrityTitle.textContent = "Snapshot unavailable";
  elements.integrityDetail.textContent = "Command Core did not return a current view";
  elements.errorDetail.textContent = error.message;
  elements.errorBanner.hidden = false;
}

function snapshotUrl() {
  const params = new URLSearchParams({ limit: String(view.limit) });
  if (view.requestId) params.set("request_id", view.requestId);
  return `/api/snapshot?${params}`;
}

async function refresh() {
  elements.refresh.disabled = true;
  elements.refresh.textContent = "Refreshing…";
  elements.syncState.classList.remove("is-error");
  elements.syncState.classList.add("is-syncing");
  elements.syncLabel.textContent = "Reading Command Core";
  try {
    const response = await fetch(snapshotUrl(), {
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.detail || "Command Core did not return a snapshot");
    }
    renderSnapshot(payload);
    elements.syncLabel.textContent = view.requestId
      ? `Focused on ${shortId(view.requestId)}`
      : "Live local snapshot";
  } catch (error) {
    const safeError = error instanceof Error ? error : new Error("Unknown snapshot error");
    renderError(safeError);
    elements.syncState.classList.add("is-error");
    elements.syncLabel.textContent = "Snapshot error";
  } finally {
    elements.syncState.classList.remove("is-syncing");
    elements.refresh.disabled = false;
    elements.refresh.textContent = "Refresh now";
  }
}

elements.filterForm.addEventListener("submit", (event) => {
  event.preventDefault();
  view.requestId = elements.requestFilter.value.trim();
  view.limit = Number(elements.recordLimit.value);
  refresh();
});

elements.clearFilter.addEventListener("click", () => {
  elements.requestFilter.value = "";
  view.requestId = "";
  refresh();
});

elements.refresh.addEventListener("click", refresh);
window.setInterval(refresh, 15_000);
refresh();
