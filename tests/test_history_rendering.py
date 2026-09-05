"""History output is validated and terminal-safe before any row is emitted."""

import json
from argparse import Namespace

import pytest

import defiant_agent_harness.cli.main as cli_module
from defiant_agent_harness.cli.main import cmd_history, main
from defiant_agent_harness.contracts import Decision, EvidenceRecord, ResultStatus
from defiant_agent_harness.evidence.store import EvidenceStore


FIELDS = [
    "timestamp",
    "tool_name",
    "decision",
    "result_status",
    "record_id",
    "request_id",
]


def _log(root, count=2):
    store = EvidenceStore(root / "evidence.jsonl")
    for index in range(count):
        store.append(
            EvidenceRecord(
                request_id=f"req_{index}",
                action_id=f"act_{index}",
                tool_name="read_file",
                decision=Decision.BLOCK,
                result_status=ResultStatus.BLOCKED,
            )
        )
    return store.path, store.records()


def _replace(path, records):
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("value", [None, [], {}, 17])
def test_bad_field_fails_without_partial_output(tmp_path, capsys, field, value):
    path, records = _log(tmp_path / "state")
    records[-1][field] = value
    _replace(path, records)
    before = path.read_bytes()
    assert main(["--workdir", str(path.parent), "history"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert f"invalid evidence history field: {field}" in captured.err
    assert path.read_bytes() == before
    assert list(path.parent.iterdir()) == [path]


@pytest.mark.parametrize(
    "options", [["--limit", "0"], ["--limit", "1"], ["--request", "req_1"]]
)
def test_filter_or_limit_cannot_hide_missing_field(tmp_path, capsys, options):
    path, records = _log(tmp_path / "state")
    del records[0]["timestamp"]
    _replace(path, records)
    assert main(["--workdir", str(path.parent), "history", *options]) == 1
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("field", FIELDS[:-1])
def test_terminal_controls_are_escaped(tmp_path, capsys, field):
    path, records = _log(tmp_path / "state", count=1)
    records[0][field] = "\x1b\r\n\t\x07\x9b\u202e"
    _replace(path, records)
    before = path.read_bytes()
    assert main(["--workdir", str(path.parent), "history"]) == 0
    output = capsys.readouterr().out
    for color in (
        cli_module.GREEN,
        cli_module.RED,
        cli_module.YELLOW,
        cli_module.DIM,
        cli_module.RESET,
    ):
        output = output.replace(color, "")
    assert "\\u001b" in output
    assert all(
        ord(char) < 128 and (char == "\n" or char.isprintable()) for char in output
    )
    assert len(output.splitlines()) == 5
    assert path.read_bytes() == before


@pytest.mark.parametrize("field", FIELDS[:-1])
def test_long_cells_have_bounded_display(tmp_path, capsys, field):
    path, records = _log(tmp_path / "state", count=1)
    records[0][field] = "x" * 1000
    _replace(path, records)
    assert main(["--workdir", str(path.parent), "history"]) == 0
    output = capsys.readouterr().out
    assert "x" * 81 not in output
    assert len(output) < 400


def test_cell_escaping_only_processes_bounded_prefixes(tmp_path, capsys, monkeypatch):
    path, records = _log(tmp_path / "state", count=1)
    records[0]["record_id"] = "x" * 10000
    _replace(path, records)
    dumps = json.dumps
    sizes = []

    def bounded_dumps(value, *args, **kwargs):
        assert isinstance(value, str) and len(value) <= 80
        sizes.append(len(value))
        return dumps(value, *args, **kwargs)

    monkeypatch.setattr(cli_module.json, "dumps", bounded_dumps)
    assert main(["--workdir", str(path.parent), "history"]) == 0
    assert 80 in sizes
    assert len(capsys.readouterr().out) < 400


def test_zero_limit_selects_no_rows_but_requires_readable_log(tmp_path, capsys):
    path, records = _log(tmp_path / "state")
    assert main(["--workdir", str(path.parent), "history", "--limit", "0"]) == 0
    output = capsys.readouterr().out
    assert "no evidence selected" in output
    assert all(r["record_id"] not in output for r in records)
    path.unlink()
    assert main(["--workdir", str(path.parent), "history", "--limit", "0"]) == 1
    assert capsys.readouterr().out == ""
    assert not path.exists()


def test_negative_cli_limit_rejected_before_read(tmp_path, monkeypatch, capsys):
    def forbid(*args, **kwargs):
        pytest.fail("invalid limit reached evidence reading")

    monkeypatch.setattr(EvidenceStore, "read_existing_records", forbid)
    with pytest.raises(SystemExit) as exc:
        main(["--workdir", str(tmp_path / "absent"), "history", "--limit", "-1"])
    assert exc.value.code == 2
    assert "non-negative integer" in capsys.readouterr().err


@pytest.mark.parametrize("limit", [-1, True, 1.5, "1"])
def test_direct_handler_rejects_invalid_limit_before_read(
    tmp_path, monkeypatch, capsys, limit
):
    def forbid(*args, **kwargs):
        pytest.fail("invalid limit reached evidence reading")

    monkeypatch.setattr(EvidenceStore, "read_existing_records", forbid)
    assert cmd_history(Namespace(workdir=tmp_path, request="", limit=limit)) == 1
    assert "non-negative integer" in capsys.readouterr().err


def test_positive_limit_and_request_filter_keep_latest_matches(tmp_path, capsys):
    path, records = _log(tmp_path / "state", count=3)
    records[0]["request_id"] = records[2]["request_id"] = "req_selected"
    _replace(path, records)
    assert (
        main(
            [
                "--workdir",
                str(path.parent),
                "history",
                "--limit",
                "1",
                "--request",
                "req_selected",
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert records[2]["record_id"] in output
    assert (
        records[0]["record_id"] not in output and records[1]["record_id"] not in output
    )
