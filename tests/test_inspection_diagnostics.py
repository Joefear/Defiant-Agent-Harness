"""Untrusted inspection diagnostics must remain bounded terminal text."""

import json

import pytest

import defiant_agent_harness.cli.main as cli_module
from defiant_agent_harness.cli.main import main
from defiant_agent_harness.contracts import Decision, EvidenceRecord, ResultStatus
from defiant_agent_harness.evidence.signing import EvidenceSigningError
from defiant_agent_harness.evidence.store import (
    EvidenceError,
    EvidenceStore,
    verify_evidence_records,
)


CONTROLS = [
    "\x1b[2J",
    "\x1b]0;forged title\x07",
    "\rforged",
    "\nchain intact",
    "\b",
    "\t",
    "\x7f",
    "\x9b31m",
    "\u202e",
    "\ud800",
]


def _store(root):
    store = EvidenceStore(root / "evidence.jsonl")
    record = store.append(
        EvidenceRecord(
            request_id="req_diagnostics",
            action_id="act_diagnostics",
            tool_name="read_file",
            decision=Decision.BLOCK,
            result_status=ResultStatus.BLOCKED,
        )
    )
    return store.path, record.to_dict()


def _replace(path, record):
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")


def _snapshot(root):
    return {
        str(path.relative_to(root)): (
            path.read_bytes() if path.is_file() else None,
            path.stat().st_mtime_ns,
            path.stat().st_mode,
        )
        for path in [root, *root.rglob("*")]
    }


def _plain(output):
    for color in (cli_module.RED, cli_module.GREEN, cli_module.RESET):
        output = output.replace(color, "")
    assert all(32 <= ord(char) < 127 or char == "\n" for char in output)
    return output


def _args(root, command):
    argument = {
        "history": [],
        "show": ["missing"],
        "verify": [],
        "export": ["req_diagnostics"],
    }[command]
    return ["--workdir", str(root), command, *argument]


@pytest.mark.parametrize("control", CONTROLS)
@pytest.mark.parametrize("field", ["record_id", "previous_record_hash"])
def test_verify_escapes_real_chain_failure(tmp_path, capsys, field, control):
    path, record = _store(tmp_path / "state")
    record[field] = control
    _replace(path, record)
    before = _snapshot(path.parent)
    raw_status = verify_evidence_records([record])
    assert not raw_status.ok and control in raw_status.detail
    assert main(_args(path.parent, "verify")) == 1
    captured = capsys.readouterr()
    output = _plain(captured.out)
    assert captured.err == ""
    assert len(output.splitlines()) == 2
    assert "CHAIN BROKEN" in output
    assert json.dumps(control)[1:-1] in output
    assert _snapshot(path.parent) == before


@pytest.mark.parametrize("command", ["history", "show", "verify"])
@pytest.mark.parametrize("control", CONTROLS)
def test_reader_errors_are_escaped(tmp_path, capsys, monkeypatch, command, control):
    root = tmp_path / "absent"

    def fail(*args, **kwargs):
        raise EvidenceError("cannot read evidence store: " + control)

    monkeypatch.setattr(EvidenceStore, "read_existing_records", staticmethod(fail))
    assert main(_args(root, command)) == 1
    captured = capsys.readouterr()
    output = _plain(captured.err)
    assert captured.out == "" and len(output.splitlines()) == 1
    assert json.dumps(control)[1:-1] in output
    assert not root.exists()


@pytest.mark.parametrize("error_type", [EvidenceError, EvidenceSigningError])
@pytest.mark.parametrize("control", CONTROLS)
def test_export_errors_are_escaped(tmp_path, capsys, monkeypatch, error_type, control):
    root = tmp_path / "absent"

    def fail(*args, **kwargs):
        raise error_type(control)

    monkeypatch.setattr(EvidenceStore, "export_existing_request", staticmethod(fail))
    assert main(_args(root, "export")) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert _plain(captured.err) == json.dumps(control)[1:-1] + "\n"
    assert not root.exists()


@pytest.mark.parametrize("control", CONTROLS)
def test_missing_record_id_is_escaped(tmp_path, capsys, control):
    path, _ = _store(tmp_path / "state")
    before = _snapshot(path.parent)
    assert main(["--workdir", str(path.parent), "show", control]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert _plain(captured.err) == "no record " + json.dumps(control)[1:-1] + "\n"
    assert _snapshot(path.parent) == before


@pytest.mark.parametrize("command", ["show", "verify"])
def test_oversized_diagnostic_is_bounded(tmp_path, capsys, command):
    path, record = _store(tmp_path / "state")
    record["record_id"] = "x" * 10000
    _replace(path, record)
    before = _snapshot(path.parent)
    args = ["--workdir", str(path.parent), command]
    if command == "show":
        args.append("y" * 10000)
    assert main(args) == 1
    captured = capsys.readouterr()
    output = _plain(captured.out + captured.err)
    assert len(output) < 1100 and "..." in output
    assert _snapshot(path.parent) == before


@pytest.mark.parametrize("command", ["history", "show", "verify", "export"])
def test_long_error_escaping_uses_only_bounded_prefix(
    tmp_path, capsys, monkeypatch, command
):
    def fail(*args, **kwargs):
        raise EvidenceError("\x1b" * 100000)

    method = (
        "export_existing_request" if command == "export" else "read_existing_records"
    )
    monkeypatch.setattr(EvidenceStore, method, staticmethod(fail))
    dumps = json.dumps
    sizes = []

    def bounded_dumps(value, *args, **kwargs):
        assert type(value) is str and len(value) <= 1024
        sizes.append(len(value))
        return dumps(value, *args, **kwargs)

    monkeypatch.setattr(cli_module.json, "dumps", bounded_dumps)
    assert main(_args(tmp_path / "absent", command)) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and sizes == [1024]
    assert len(_plain(captured.err)) == 1025
    assert captured.err.endswith("..." + cli_module.RESET + "\n")


@pytest.mark.parametrize("length", [1023, 1024, 1025])
def test_terminal_text_boundary(length):
    value = "x" * length
    output = cli_module._terminal_text(value)
    assert output == (value if length <= 1024 else "x" * 1021 + "...")


@pytest.mark.parametrize("command", ["show", "export"])
def test_json_output_stays_lossless(tmp_path, capsys, command):
    path, record = _store(tmp_path / "state")
    record["result_summary"] = "".join(CONTROLS) + "x" * 6000
    _replace(path, record)
    before = path.read_bytes()
    argument = record["record_id"] if command == "show" else record["request_id"]
    assert main(["--workdir", str(path.parent), command, argument]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    document = json.loads(_plain(captured.out))
    actual = document if command == "show" else document["records"][0]
    assert actual == record
    assert path.read_bytes() == before
    assert list(path.parent.iterdir()) == [path]


def test_export_output_path_is_escaped_without_changing_destination(tmp_path, capsys):
    path, record = _store(tmp_path / "state")
    destination = tmp_path / "export-\u202e.json"
    before = path.read_bytes()
    assert (
        main(
            [
                "--workdir",
                str(path.parent),
                "export",
                record["request_id"],
                "--output",
                str(destination),
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    assert captured.err == ""
    assert _plain(captured.out) == (
        "wrote evidence export " + json.dumps(str(destination))[1:-1] + "\n"
    )
    assert json.loads(destination.read_bytes())["records"] == [record]
    assert path.read_bytes() == before


def test_real_signing_failure_path_is_escaped(tmp_path, capsys):
    path, record = _store(tmp_path / "state")
    signing_key = tmp_path / "missing-\u202e.key"
    passphrase = tmp_path / "secret.txt"
    passphrase.write_text("test-only-passphrase", encoding="utf-8")
    before = path.read_bytes()
    assert (
        main(
            [
                "--workdir",
                str(path.parent),
                "export",
                record["request_id"],
                "--signing-key",
                str(signing_key),
                "--passphrase-file",
                str(passphrase),
                "--signer",
                "test operator",
                "--note",
                "test failure",
            ]
        )
        == 1
    )
    captured = capsys.readouterr()
    assert captured.out == "" and "\\u202e" in _plain(captured.err)
    assert path.read_bytes() == before


def test_plain_diagnostics_keep_exit_codes_and_wording(tmp_path, capsys):
    path, record = _store(tmp_path / "state")
    assert main(_args(path.parent, "verify")) == 0
    assert _plain(capsys.readouterr().out) == "chain intact  1 records\n"
    assert main(_args(path.parent, "show")) == 1
    assert capsys.readouterr().err == "no record missing\n"
    record["result_summary"] = "changed"
    _replace(path, record)
    status = verify_evidence_records([record])
    assert main(_args(path.parent, "verify")) == 1
    assert _plain(capsys.readouterr().out) == (
        "CHAIN BROKEN at record 0\n  " + status.detail + "\n"
    )
