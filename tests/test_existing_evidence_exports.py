"""Exports require existing evidence and bind status to one locked capture."""

import json
from contextlib import contextmanager

import pytest

import defiant_agent_harness.evidence.store as store_module
from defiant_agent_harness.cli.main import main
from defiant_agent_harness.contracts import Decision, EvidenceRecord, ResultStatus
from defiant_agent_harness.evidence.store import GENESIS, EvidenceError, EvidenceStore
from defiant_agent_harness.persistence import PersistenceError, exclusive_file_lock


def _store(root):
    store = EvidenceStore(root / "evidence.jsonl")
    record = store.append(
        EvidenceRecord(
            request_id="req_export",
            action_id="act_export",
            tool_name="read_file",
            decision=Decision.BLOCK,
            result_status=ResultStatus.BLOCKED,
        )
    )
    return store, record


def _files(root):
    return {p.name: p.read_bytes() for p in root.iterdir()} if root.exists() else None


@pytest.mark.parametrize("state", ["missing_root", "missing_log", "deleted_log"])
@pytest.mark.parametrize("output_file", [False, True])
def test_cli_missing_evidence_has_no_output_or_initialization(
    tmp_path, capsys, state, output_file
):
    root = tmp_path / "state"
    if state == "missing_log":
        root.mkdir(mode=0o700)
    elif state == "deleted_log":
        store, _ = _store(root)
        store.path.unlink()
    before = _files(root)
    output = tmp_path / "export.json"
    args = ["--workdir", str(root), "export", "req_export"]
    if output_file:
        args += ["--output", str(output)]
    assert main(args) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err
    assert not output.exists()
    assert _files(root) == before


def test_existing_empty_store_can_be_exported_without_constructor(
    tmp_path, capsys, monkeypatch
):
    root = tmp_path / "state"
    EvidenceStore(root / "evidence.jsonl")
    before = _files(root)

    def forbid(*args, **kwargs):
        pytest.fail("export initialized a writable store")

    monkeypatch.setattr(EvidenceStore, "__init__", forbid)
    assert main(["--workdir", str(root), "export", "req_export"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["chain_status"]["ok"] is True
    assert document["records"] == []
    assert document["full_chain_record_count"] == 0
    assert document["chain_head_hash"] == GENESIS
    assert _files(root) == before


@pytest.mark.parametrize("api", ["instance", "existing"])
def test_export_verifies_and_selects_one_locked_capture(tmp_path, monkeypatch, api):
    store, record = _store(tmp_path / "state")
    reader = EvidenceStore.read_existing_records
    calls = []

    def capture_then_change(path):
        assert store.path.with_name("evidence.jsonl.lock").exists()
        calls.append(path)
        records = reader(path)
        store.path.write_bytes(b"{}\n")
        return records

    monkeypatch.setattr(
        EvidenceStore, "read_existing_records", staticmethod(capture_then_change)
    )
    document = (
        store.export_request(record.request_id)
        if api == "instance"
        else EvidenceStore.export_existing_request(store.path, record.request_id)
    )
    assert calls == [store.path]
    assert document["chain_status"]["ok"] is True
    assert document["full_chain_record_count"] == document["record_count"] == 1
    assert document["chain_head_hash"] == record.record_hash
    assert document["records"][0]["record_hash"] == record.record_hash
    assert store.path.read_bytes() == b"{}\n"
    assert not store.path.with_name("evidence.jsonl.lock").exists()


def test_existing_only_lock_never_creates_parent(tmp_path):
    root = tmp_path / "missing"
    with pytest.raises(PersistenceError, match="state directory does not exist"):
        with exclusive_file_lock(root / "evidence.jsonl", require_existing_root=True):
            pytest.fail("missing root was locked")
    assert not root.exists()


def test_export_root_deleted_after_precheck_is_not_recreated(tmp_path, monkeypatch):
    root = tmp_path / "state"
    store, record = _store(root)

    @contextmanager
    def delete_before_lock(path, *, require_existing_root=False):
        assert require_existing_root is True
        store.path.unlink()
        root.rmdir()
        with exclusive_file_lock(path, require_existing_root=require_existing_root):
            yield

    monkeypatch.setattr(store_module, "exclusive_file_lock", delete_before_lock)
    with pytest.raises(EvidenceError, match="state directory does not exist"):
        store.export_request(record.request_id)
    assert not root.exists()


def test_export_log_deleted_after_precheck_is_not_recreated(
    tmp_path, monkeypatch, capsys
):
    root = tmp_path / "state"
    store, record = _store(root)
    inspect = store_module.inspect_state_file

    def delete_after_check(path):
        observed = inspect(path)
        store.path.unlink()
        return observed

    monkeypatch.setattr(store_module, "inspect_state_file", delete_after_check)
    output = tmp_path / "export.json"
    assert (
        main(
            [
                "--workdir",
                str(root),
                "export",
                record.request_id,
                "--output",
                str(output),
            ]
        )
        == 1
    )
    assert capsys.readouterr().out == ""
    assert not output.exists()
    assert _files(root) == {}


@pytest.mark.parametrize("suffix", [b"not-json\n", b'{"x":1,"x":2}\n', b"[]\n"])
def test_malformed_tail_cannot_publish_partial_export(tmp_path, capsys, suffix):
    root = tmp_path / "state"
    store, record = _store(root)
    store.path.write_bytes(store.path.read_bytes() + suffix)
    before = _files(root)
    output = tmp_path / "export.json"
    assert (
        main(
            [
                "--workdir",
                str(root),
                "export",
                record.request_id,
                "--output",
                str(output),
            ]
        )
        == 1
    )
    assert capsys.readouterr().out == ""
    assert not output.exists()
    assert _files(root) == before


def test_stranded_lock_is_preserved_and_export_refused(tmp_path, capsys):
    root = tmp_path / "state"
    store, record = _store(root)
    store.path.with_name("evidence.jsonl.lock").write_bytes(b"pid=99999\n")
    before = _files(root)
    assert main(["--workdir", str(root), "export", record.request_id]) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and "state file is locked" in captured.err
    assert _files(root) == before
