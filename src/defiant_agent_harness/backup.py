"""Bounded, operator-controlled snapshots and conservative separate-root restore.

No owning Harness is constructed here. Originals are read-only and retained.
New authority is activated separately through explicit profile rotation.
"""

from __future__ import annotations

import hashlib
import os
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from .approvals.store import ApprovalStore
from .contracts import utc_now
from .evidence.store import EvidenceStore, verify_evidence_records
from .money import money
from .hooks.state import HookExecutionStore
from .operator_identity import OperatorTrustPolicy
from .persistence import (
    PersistenceError,
    atomic_write_json,
    inspect_state_file,
    inspect_storage_root,
    open_state_file,
    read_json,
    require_storage_root_unchanged,
    sync_storage_directory,
)
from .runtime_lease import INCOMPLETE_FILE, LEASE_FILE, maintenance_session
from .state_integrity import StateIntegrityAuditor
from .state_storage import KNOWN_STATE_FILENAMES

SCHEMA = "defiant.snapshot.v1"
MANIFEST = "snapshot_manifest.json"
RECEIPT = "restore_receipt.json"
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
LOCKS = {"authority.lock", LEASE_FILE}
MANDATORY = {
    "approvals.json",
    "budget.json",
    "evidence.jsonl",
    "evidence_head.json",
    "authority_profile.json",
    "authority_publication.json",
    "authority_publication_continuity.json",
    "state_storage.json",
    "control_plane_isolation.json",
    "workspace_integrity.json",
    "evidence_witness_policy.json",
    "authority_publication_witness_policy.json",
}


class BackupError(PersistenceError):
    """The procedure cannot establish safe recovery; preserve the original."""


def _text(value, name):
    if type(value) is not str or not value.strip() or len(value) > 4096:
        raise BackupError(f"{name} requires non-empty text of at most 4096 characters")
    return value


def _digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _read(path, limit=MAX_FILE_BYTES):
    with open_state_file(path, "rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise BackupError("snapshot input exceeds the configured byte limit")
    return data


def _write_new(path, data):
    # All destinations are inside our create-exclusive private staging root.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _path(path):
    return Path(os.path.abspath(path))


def _separate(*paths):
    resolved = [p.resolve(strict=False) for p in paths]
    for index, first in enumerate(resolved):
        for second in resolved[index + 1 :]:
            if first == second or first in second.parents or second in first.parents:
                raise BackupError(
                    "state, workspace, snapshot and target must be separate roots"
                )


def _inventory(root, *, extra=()):
    observation = inspect_storage_root(root)
    if observation is None:
        raise BackupError("original or snapshot directory is missing")
    allowed = set(KNOWN_STATE_FILENAMES) | set(extra)
    names = set()
    with os.scandir(root) as entries:
        for entry in entries:
            if entry.name not in allowed or len(names) >= len(allowed):
                raise BackupError(
                    "interrupted or unrecognized state inventory; original preserved"
                )
            names.add(entry.name)
    if not MANDATORY <= names or names - allowed:
        raise BackupError(
            "incomplete, interrupted or unrecognized state inventory; original preserved"
        )
    for name in names:
        observed = inspect_state_file(root / name)
        if observed is None:
            raise BackupError("state file disappeared")
        if observed.st_size > MAX_FILE_BYTES:
            raise BackupError("snapshot input exceeds the configured byte limit")
    require_storage_root_unchanged(observation)
    return names, observation


def _files(root, names):
    result = {}
    total = 0
    for name in sorted(names - LOCKS):
        data = _read(root / name)
        total += len(data)
        if total > MAX_SNAPSHOT_BYTES:
            raise BackupError("snapshot exceeds total byte limit")
        result[name] = data
    return result


def _assess(root, workspace, trust, *, copied=False):
    report = StateIntegrityAuditor(
        root, operator_trust=trust, workspace_root=workspace
    ).audit()
    allowed = {"execution_recovery_required"}
    if copied:
        # Inspection only: never change runtime audit semantics or activate here.
        allowed.add("state_storage_root_mismatch")
        allowed.add("restore_incomplete")
    errors = [issue.code for issue in report.issues if issue.code not in allowed]
    if errors:
        raise BackupError("state is not restorable: " + ", ".join(sorted(set(errors))))
    if report.counts.get("active_journal_operations"):
        raise BackupError(
            "active operation journal must be preserved, not repaired by restore"
        )
    approvals = ApprovalStore(root / "approvals.json", operator_trust=trust)._read_all()
    if any(
        a.status == "executing" and a.reconciliation_outcome for a in approvals.values()
    ):
        raise BackupError(
            "interrupted operator reconciliation must be preserved, not restored"
        )
    for name in (
        "evidence_witness_policy.json",
        "authority_publication_witness_policy.json",
    ):
        if read_json(root / name).get("mode") == "required":
            raise BackupError(
                "required external witness cannot be migrated by S7 restore"
            )
    if (root / "hook_executions.json").exists():
        hooks = HookExecutionStore(root / "hook_executions.json")._read_all()
        # Conservative: an authorized correlation may represent a still-running
        # external host tool; a lease on the hook process cannot prove otherwise.
        if any(value.status == "authorized" for value in hooks.values()):
            raise BackupError(
                "outstanding native-hook authorization; establish outcome before snapshot/restore"
            )
    records = EvidenceStore.read_existing_records(root / "evidence.jsonl")
    if not verify_evidence_records(records).ok:
        raise BackupError("evidence chain is invalid")
    return records


def _trust(specs):
    return OperatorTrustPolicy.from_specs(specs) if specs else None


@contextmanager
def _staging(target, *, acl_source=None):
    if os.path.lexists(target):
        raise BackupError("destination must not exist")
    parent = target.parent.resolve(strict=True)
    temporary = parent / ("." + target.name + ".restore-" + uuid4().hex)
    temporary.mkdir(mode=0o700)
    sync_storage_directory(parent)
    if acl_source is not None:
        from .backup_acl import preserve_private_directory_acl

        preserve_private_directory_acl(acl_source, temporary)
    # Never remove a candidate on error. The marker blocks owning startup,
    # and the operator can preserve and investigate the partial copy.
    atomic_write_json(
        temporary / INCOMPLETE_FILE, {"schema": SCHEMA, "target": target.name}
    )
    yield temporary
    if os.path.lexists(target):
        raise BackupError("destination appeared during restore; candidate preserved")
    # Atomic directory rename publishes a complete candidate. A concurrent
    # operator replacing directories is outside the single-operator procedure.
    os.rename(temporary, target)
    sync_storage_directory(parent)


def _finish(temporary):
    (temporary / INCOMPLETE_FILE).unlink()
    sync_storage_directory(temporary)


def snapshot(root, output, *, workspace, operator, note, trusted_operator_keys=()):
    root, output, workspace = map(_path, (root, output, workspace))
    _text(operator, "operator")
    _text(note, "quiescence note")
    _separate(root, output)
    _separate(workspace, output)
    trust = _trust(trusted_operator_keys)
    with maintenance_session(root):
        names, observation = _inventory(root)
        files = _files(root, names)
        records = _assess(root, workspace, trust)
        manifest = {
            "schema": SCHEMA,
            "created_at": utc_now(),
            "operator": operator,
            "note": note,
            "source_root": str(observation.path),
            "source_identity": list(observation.identity),
            "source_storage": read_json(root / "state_storage.json")["root_hash"],
            "workspace": str(workspace.resolve()),
            "known_files": sorted(set(KNOWN_STATE_FILENAMES) - LOCKS),
            "files": {
                name: {"sha256": _digest(data), "bytes": len(data)}
                for name, data in files.items()
            },
            "evidence_count": len(records),
        }
        acl_source = (
            root
            if read_json(root / "state_storage.json")["mode"] == "windows_private_acl"
            else None
        )
        with _staging(output, acl_source=acl_source) as temporary:
            for name, data in files.items():
                _write_new(temporary / name, data)
            atomic_write_json(
                temporary / MANIFEST, manifest, max_bytes=MAX_MANIFEST_BYTES
            )
            _assess(temporary, workspace, trust, copied=True)
            require_storage_root_unchanged(observation)
            if _files(root, _inventory(root)[0]) != files:
                raise BackupError(
                    "original changed during snapshot; candidate preserved"
                )
            _finish(temporary)
            manifest_hash = _digest(_read(temporary / MANIFEST, MAX_MANIFEST_BYTES))
    return {
        "snapshot": str(output),
        "manifest_sha256": manifest_hash,
        "evidence_count": len(records),
    }


def _account(snapshot_root, original, before, after):
    if after[: len(before)] != before:
        raise BackupError("original evidence is not an exact extension of the snapshot")
    old = ApprovalStore(snapshot_root / "approvals.json")._read_all()
    live = ApprovalStore(original / "approvals.json")._read_all()
    if set(live) != set(old):
        raise BackupError("post-snapshot approval inventory cannot be imported safely")
    eligible = {
        a.action_id: a for a in old.values() if a.status in {"approved", "executing"}
    }
    for key, approval in old.items():
        latest = live[key]
        if approval.authorization_hash != latest.authorization_hash:
            raise BackupError("approval authority changed since snapshot")
        if approval.status == "pending" and latest.status not in {
            "pending",
            "rejected",
            "expired",
        }:
            raise BackupError(
                "post-snapshot approval decision requires unsupported authority import"
            )
        if (
            approval.status not in {"pending", "approved", "executing"}
            and approval.to_dict() != latest.to_dict()
        ):
            raise BackupError("terminal approval changed since snapshot")
    harmless = {"blocked", "rejected", "expired", "pending_approval"}
    for record in after[len(before) :]:
        if record.get("result_status") not in harmless:
            held = eligible.get(record.get("action_id"))
            if held is None or held.authorization_hash != record.get(
                "authorization_hash"
            ):
                raise BackupError(
                    "post-snapshot authorization cannot disappear; restore refused"
                )
    # Do not recreate less exposure than a known debit. Larger known costs need
    # an explicit future budget recovery protocol, not silent ledger rewriting.
    budget = read_json(original / "budget.json")
    debits = {}
    for entry in budget.get("entries", []):
        held = eligible.get(entry.get("action_id"))
        if held and entry.get("kind") == "debit":
            debits[held.action_id] = debits.get(held.action_id, money("0")) + money(
                entry["amount_usd"]
            )
        if held and debits.get(held.action_id, money("0")) > money(held.reserved_usd):
            raise BackupError(
                "known debit exceeds snapshot reservation; restore refused"
            )
    return sorted(a.approval_id for a in eligible.values())


def restore(
    root,
    source,
    target,
    *,
    expected_manifest_sha256,
    workspace,
    operator,
    note,
    trusted_operator_keys=(),
):
    root, source, target, workspace = map(_path, (root, source, target, workspace))
    _text(operator, "operator")
    _text(note, "quiescence and original-retirement note")
    _separate(root, source, target)
    _separate(workspace, source, target)
    trust = _trust(trusted_operator_keys)
    with maintenance_session(root):
        live_names, observation = _inventory(root)
        original_files = _files(root, live_names)
        after = _assess(root, workspace, trust)
        names, snapshot_observation = _inventory(source, extra=(MANIFEST,))
        manifest_bytes = _read(source / MANIFEST, MAX_MANIFEST_BYTES)
        if _digest(manifest_bytes) != expected_manifest_sha256:
            raise BackupError(
                "snapshot manifest does not match the independently retained digest"
            )
        manifest = read_json(source / MANIFEST, max_bytes=MAX_MANIFEST_BYTES)
        if type(manifest) is not dict:
            raise BackupError("snapshot manifest must be an object")
        if manifest.get("schema") != SCHEMA or manifest.get("known_files") != sorted(
            set(KNOWN_STATE_FILENAMES) - LOCKS
        ):
            raise BackupError("incompatible snapshot schema or inventory")
        if manifest.get("source_root") != str(observation.path) or manifest.get(
            "source_identity"
        ) != list(observation.identity):
            raise BackupError(
                "original identity no longer matches snapshot; accounting unavailable"
            )
        if manifest.get("workspace") != str(workspace.resolve()):
            raise BackupError("workspace differs from snapshot")
        files = _files(source, names - {MANIFEST})
        expected = {
            name: {"sha256": _digest(data), "bytes": len(data)}
            for name, data in files.items()
        }
        if expected != manifest.get("files"):
            raise BackupError("partial or modified snapshot")
        before = _assess(source, workspace, trust, copied=True)
        if len(before) != manifest.get("evidence_count"):
            raise BackupError("snapshot evidence count mismatch")
        for name in (
            "authority_profile.json",
            "operator_trust.json",
            "evidence_witness_policy.json",
            "authority_publication_witness_policy.json",
        ):
            if (name in live_names) != (name in files) or (
                name in files and _read(root / name) != files[name]
            ):
                raise BackupError(
                    "authority or trust changed since snapshot; restore refused"
                )
        # Host completions are not operator reconciliation. Do not roll their
        # correlation history back, even when all current events look terminal.
        if ("hook_executions.json" in live_names) != (
            "hook_executions.json" in files
        ) or (
            "hook_executions.json" in files
            and original_files["hook_executions.json"] != files["hook_executions.json"]
        ):
            raise BackupError(
                "hook correlation changed after snapshot; restore refused"
            )
        quarantined = _account(source, root, before, after)
        acl_source = (
            root
            if read_json(root / "state_storage.json")["mode"] == "windows_private_acl"
            else None
        )
        with _staging(target, acl_source=acl_source) as temporary:
            for name, data in files.items():
                _write_new(temporary / name, data)
            ApprovalStore(
                temporary / "approvals.json", operator_trust=trust
            ).quarantine_restored_approvals(quarantined)
            receipt = {
                "schema": "defiant.restore.v1",
                "operator": operator,
                "note": note,
                "restored_at": utc_now(),
                "manifest_sha256": expected_manifest_sha256,
                "original_evidence_count": len(after),
                "snapshot_evidence_count": len(before),
                "uncertain_approval_ids": quarantined,
                "activation": "explicit_profile_rotation_required",
            }
            # Receipt is diagnostic provenance, not a signature or execution grant.
            atomic_write_json(temporary / RECEIPT, receipt)
            _assess(temporary, workspace, trust, copied=True)
            require_storage_root_unchanged(observation)
            require_storage_root_unchanged(snapshot_observation)
            if _files(root, _inventory(root)[0]) != original_files:
                raise BackupError(
                    "original changed during restore; candidate preserved"
                )
            if (
                _files(source, _inventory(source, extra=(MANIFEST,))[0] - {MANIFEST})
                != files
            ):
                raise BackupError(
                    "snapshot changed during restore; candidate preserved"
                )
            if _read(source / MANIFEST, MAX_MANIFEST_BYTES) != manifest_bytes:
                raise BackupError("snapshot manifest changed during restore")
            _finish(temporary)
    return receipt | {"target": str(target), "original_preserved": True}
