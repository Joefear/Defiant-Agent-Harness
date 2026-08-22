"""Append-only, hash-chained, fail-closed JSONL evidence store."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from ..contracts import EvidenceRecord, sha256_of, utc_now
from ..persistence import (
    PersistenceError,
    exclusive_file_lock,
    inspect_state_file,
    open_state_file,
    prepare_storage_root,
    sync_storage_directory,
)
from .signing import EXPORT_SCHEMA, EXPORT_VERSION

GENESIS = "sha256:" + "0" * 64
_TERMINAL_RESULTS = {
    "succeeded",
    "failed",
    "blocked",
    "rejected",
    "expired",
    "not_executed",
}


class EvidenceError(RuntimeError):
    """Evidence cannot be trusted or durably extended."""


@dataclass
class ChainStatus:
    ok: bool
    count: int
    broken_at: int | None = None
    detail: str = ""


class EvidenceStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        try:
            root = prepare_storage_root(self.path.parent)
            if inspect_state_file(self.path) is None:
                with exclusive_file_lock(self.path):
                    if inspect_state_file(self.path) is None:
                        with open_state_file(self.path, "x", encoding="utf-8") as fh:
                            fh.flush()
                            os.fsync(fh.fileno())
                        sync_storage_directory(root.path)
        except (OSError, PersistenceError) as exc:
            raise EvidenceError(
                f"cannot initialize evidence store {self.path}: {exc}"
            ) from exc

    # -- write -------------------------------------------------------

    def head_hash(self) -> str:
        status = self.verify()
        if not status.ok:
            raise EvidenceError(status.detail)
        return self._head_hash_unchecked()

    def _head_hash_unchecked(self) -> str:
        last = None
        for last in self._raw():
            pass
        return last["record_hash"] if last else GENESIS

    def append(self, record: EvidenceRecord) -> EvidenceRecord:
        if record.record_hash:
            raise EvidenceError("refusing to append an already sealed record")
        try:
            with exclusive_file_lock(self.path):
                status = self._verify_unlocked()
                if not status.ok:
                    raise EvidenceError(
                        "refusing to append to broken evidence chain: " + status.detail
                    )
                record.seal(self._head_hash_unchecked())
                line = (
                    json.dumps(
                        record.to_dict(),
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    ).encode("utf-8")
                    + b"\n"
                )
                with open_state_file(self.path, "ab") as fh:
                    fh.write(line)
                    fh.flush()
                    os.fsync(fh.fileno())
        except PersistenceError as exc:
            raise EvidenceError(str(exc)) from exc
        except (OSError, TypeError, ValueError) as exc:
            raise EvidenceError(f"cannot append evidence safely: {exc}") from exc
        return record

    def append_idempotent(self, record: EvidenceRecord) -> EvidenceRecord:
        """Append or recognize an exact prepared record during recovery."""
        if record.record_hash:
            raise EvidenceError("prepared evidence record must not be sealed")
        expected = record.to_dict()
        try:
            with exclusive_file_lock(self.path):
                status = self._verify_unlocked()
                if not status.ok:
                    raise EvidenceError(
                        "refusing to append to broken evidence chain: " + status.detail
                    )
                for raw in self._raw():
                    if raw.get("record_id") != record.record_id:
                        continue
                    comparable = {
                        key: value
                        for key, value in raw.items()
                        if key not in {"previous_record_hash", "record_hash"}
                    }
                    expected_comparable = {
                        key: value
                        for key, value in expected.items()
                        if key not in {"previous_record_hash", "record_hash"}
                    }
                    if comparable != expected_comparable:
                        raise EvidenceError(
                            f"record {record.record_id} conflicts with journal"
                        )
                    return EvidenceRecord(**raw)
                record.seal(self._head_hash_unchecked())
                line = (
                    json.dumps(
                        record.to_dict(),
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    ).encode("utf-8")
                    + b"\n"
                )
                with open_state_file(self.path, "ab") as fh:
                    fh.write(line)
                    fh.flush()
                    os.fsync(fh.fileno())
        except PersistenceError as exc:
            raise EvidenceError(str(exc)) from exc
        except (OSError, TypeError, ValueError) as exc:
            raise EvidenceError(f"cannot append evidence safely: {exc}") from exc
        return record

    # -- read --------------------------------------------------------

    def _raw(self) -> Iterator[dict]:
        try:
            with open_state_file(self.path, "r", encoding="utf-8") as fh:
                for index, line in enumerate(fh):
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise EvidenceError(
                            f"record {index} is not valid JSON: {exc.msg}"
                        ) from exc
                    if not isinstance(record, dict):
                        raise EvidenceError(f"record {index} is not a JSON object")
                    yield record
        except (OSError, PersistenceError) as exc:
            raise EvidenceError(f"cannot read evidence store: {exc}") from exc

    def records(self) -> list[dict]:
        return list(self._raw())

    def open_authorizations(self) -> list[dict]:
        """Return sealed authorizations with no matching terminal evidence."""
        records = self.records()
        terminal_hashes = {
            record.get("authorization_hash")
            for record in records
            if record.get("result_status") in _TERMINAL_RESULTS
        }
        return [
            record
            for record in records
            if record.get("result_status") == "skipped"
            and record.get("authorization_hash") not in terminal_hashes
        ]

    def open_authorization(self, record_id: str) -> dict | None:
        return next(
            (
                record
                for record in self.open_authorizations()
                if record.get("record_id") == record_id
            ),
            None,
        )

    def by_request(self, request_id: str) -> list[dict]:
        return [
            record for record in self._raw() if record.get("request_id") == request_id
        ]

    def by_action(self, action_id: str) -> list[dict]:
        return [
            record for record in self._raw() if record.get("action_id") == action_id
        ]

    def get(self, record_id: str) -> dict | None:
        for record in self._raw():
            if record.get("record_id") == record_id:
                return record
        return None

    # -- verify ------------------------------------------------------

    def verify(self) -> ChainStatus:
        return self._verify_unlocked()

    def _verify_unlocked(self) -> ChainStatus:
        previous = GENESIS
        count = 0
        try:
            for index, record in enumerate(self._raw()):
                count = index + 1
                if record.get("previous_record_hash") != previous:
                    return ChainStatus(
                        False,
                        count,
                        index,
                        (
                            f"record {index} ({record.get('record_id')}) expected "
                            f"previous hash {previous} but carries "
                            f"{record.get('previous_record_hash')} -- a preceding "
                            "record was altered or removed"
                        ),
                    )
                body = {
                    key: value for key, value in record.items() if key != "record_hash"
                }
                recomputed = sha256_of(body)
                if recomputed != record.get("record_hash"):
                    return ChainStatus(
                        False,
                        count,
                        index,
                        (
                            f"record {index} ({record.get('record_id')}) content "
                            "does not match its own hash -- this record was altered "
                            "in place"
                        ),
                    )
                previous = record["record_hash"]
        except EvidenceError as exc:
            return ChainStatus(False, count, count, str(exc))
        return ChainStatus(True, count, detail="chain intact")

    # -- export ------------------------------------------------------

    def export_request(self, request_id: str) -> dict:
        try:
            with exclusive_file_lock(self.path):
                status = self._verify_unlocked()
                all_records = list(self._raw())
        except PersistenceError as exc:
            raise EvidenceError(str(exc)) from exc
        records = [
            record for record in all_records if record.get("request_id") == request_id
        ]
        return {
            "schema_name": EXPORT_SCHEMA,
            "schema_version": EXPORT_VERSION,
            "request_id": request_id,
            "exported_at": utc_now(),
            "record_count": len(records),
            "full_chain_record_count": status.count,
            "chain_head_hash": (
                all_records[-1]["record_hash"]
                if status.ok and all_records
                else GENESIS
                if status.ok
                else None
            ),
            "chain_status": status.__dict__,
            "records": records,
        }
