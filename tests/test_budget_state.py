import pytest

import defiant_agent_harness.budgets.ledger as budget_module
from defiant_agent_harness.budgets.ledger import BudgetError, BudgetLedger
from defiant_agent_harness.persistence import atomic_write_json, read_json


class HostileText(str):
    def __str__(self):
        raise AssertionError("caller string hook invoked")

    def __len__(self):
        raise AssertionError("caller string length hook invoked")

    def strip(self, *args, **kwargs):
        raise AssertionError("caller string strip hook invoked")

    def replace(self, *args, **kwargs):
        raise AssertionError("caller string replace hook invoked")

    def __deepcopy__(self, memo):
        raise AssertionError("caller string copy hook invoked")


class HostileList(list):
    def __iter__(self):
        raise AssertionError("caller list iterator hook invoked")

    def __len__(self):
        raise AssertionError("caller list length hook invoked")

    def __getitem__(self, key):
        raise AssertionError("caller list item hook invoked")

    def __deepcopy__(self, memo):
        raise AssertionError("caller list copy hook invoked")


class HostileDict(dict):
    def __iter__(self):
        raise AssertionError("caller mapping iterator hook invoked")

    def __len__(self):
        raise AssertionError("caller mapping length hook invoked")

    def keys(self):
        raise AssertionError("caller mapping keys hook invoked")

    def items(self):
        raise AssertionError("caller mapping items hook invoked")

    def get(self, key, default=None):
        raise AssertionError("caller mapping get hook invoked")

    def __deepcopy__(self, memo):
        raise AssertionError("caller mapping copy hook invoked")


def _hostile_document(raw):
    hostile = HostileDict(raw)
    hostile["balance_usd"] = HostileText(raw["balance_usd"])
    hostile["entries"] = HostileList([HostileDict(entry) for entry in raw["entries"]])
    hostile["reservations"] = HostileDict(raw["reservations"])
    hostile["reconciliations"] = HostileDict(raw["reconciliations"])
    return hostile


def test_budget_reader_captures_hostile_state_without_caller_hooks(
    tmp_path, monkeypatch
):
    path = tmp_path / "budget.json"
    ledger = BudgetLedger(path, starting_balance_usd="10")
    ledger.grant("2", "baseline")
    raw = read_json(path)
    original_read = budget_module.read_json

    def hostile_read(source, *, max_bytes=None):
        assert source == path
        assert max_bytes == budget_module._MAX_STATE_BYTES
        return _hostile_document(raw)

    monkeypatch.setattr(budget_module, "read_json", hostile_read)

    restored = ledger._validated_read()

    assert restored == raw
    assert type(restored) is dict
    assert type(restored["entries"]) is list
    assert type(restored["entries"][0]["note"]) is str
    monkeypatch.setattr(budget_module, "read_json", original_read)


def test_budget_writer_captures_hostile_state_before_json_publication(tmp_path):
    path = tmp_path / "budget.json"
    ledger = BudgetLedger(path, starting_balance_usd="10")
    ledger.grant("2", "baseline")
    raw = read_json(path)

    ledger._write(_hostile_document(raw))

    assert read_json(path) == raw


def test_budget_public_inputs_and_attestation_are_detached_before_accounting(tmp_path):
    path = tmp_path / "budget.json"
    ledger = BudgetLedger(path, starting_balance_usd="10")
    note = HostileText("grant note")
    request_id = HostileText("req_budget")
    action_id = HostileText("act_budget")
    attestation = HostileDict(
        {
            "key_id": HostileText("operator-key"),
            "claims": HostileList([HostileText("reviewed")]),
        }
    )

    ledger.grant("1", note)
    ledger.reserve("3", request_id, action_id)
    result = ledger.reconcile_reservation(
        "3",
        request_id,
        action_id,
        HostileText("succeeded"),
        HostileText("operator-7"),
        HostileText("provider confirms execution"),
        authority_record_id=HostileText("evd_authority"),
        authority_record_hash=HostileText("sha256:authority"),
        attestation=attestation,
    )

    dict.__setitem__(attestation, "key_id", "caller-change")
    result["attestation"]["key_id"] = "projection-change"
    durable = ledger._validated_read()
    reconciliation = durable["reconciliations"]["act_budget"]
    assert reconciliation["attestation"]["key_id"] == "operator-key"
    assert reconciliation["attestation"]["claims"] == ["reviewed"]
    assert durable["entries"][0]["note"] == "grant note"


def test_budget_rejects_noncanonical_input_without_secret_echo(tmp_path):
    class SecretValue:
        def __str__(self):
            raise AssertionError("secret rendered")

        def __repr__(self):
            raise AssertionError("secret represented")

        def __deepcopy__(self, memo):
            raise AssertionError("secret copied")

    ledger = BudgetLedger(tmp_path / "budget.json", starting_balance_usd="10")
    raw = ledger._validated_read()
    raw["entries"].append({"secret": SecretValue()})

    with pytest.raises(
        BudgetError, match="exceeds bounded canonical contract"
    ) as failure:
        ledger._write(raw)

    assert "SecretValue" not in str(failure.value)


def test_budget_store_passes_one_explicit_ceiling_to_reads_and_writes(
    tmp_path, monkeypatch
):
    read_limits = []
    write_limits = []
    original_read = budget_module.read_json
    original_write = budget_module.atomic_write_json

    def observed_read(path, *, max_bytes=None):
        read_limits.append(max_bytes)
        return original_read(path, max_bytes=max_bytes)

    def observed_write(path, data, *, max_bytes=None):
        write_limits.append(max_bytes)
        return original_write(path, data, max_bytes=max_bytes)

    monkeypatch.setattr(budget_module, "read_json", observed_read)
    monkeypatch.setattr(budget_module, "atomic_write_json", observed_write)
    ledger = BudgetLedger(tmp_path / "budget.json", starting_balance_usd="10")
    ledger.grant("2")

    assert read_limits
    assert write_limits
    assert set(read_limits) == {budget_module._MAX_STATE_BYTES}
    assert set(write_limits) == {budget_module._MAX_STATE_BYTES}


def test_budget_report_projects_summary_and_drift_from_one_observation(
    tmp_path, monkeypatch
):
    ledger = BudgetLedger(tmp_path / "budget.json", starting_balance_usd="10")
    ledger.reserve("3", "req_report", "act_report")
    calls = 0
    original_read = ledger._validated_read

    def observed_read():
        nonlocal calls
        calls += 1
        return original_read()

    monkeypatch.setattr(ledger, "_validated_read", observed_read)

    report = ledger.report()

    assert calls == 1
    assert report["summary"]["reserved_usd"] == "3"
    assert report["drift"]["total_estimated_usd"] == "3"


def test_budget_store_refuses_oversized_update_without_replacing_prior_state(
    tmp_path, monkeypatch
):
    path = tmp_path / "budget.json"
    ledger = BudgetLedger(path, starting_balance_usd="10")
    prior = path.read_bytes()
    update = ledger._validated_read()
    update["entries"].append(
        {
            "kind": "grant",
            "amount_usd": "1",
            "balance_after_usd": "11",
            "request_id": "",
            "action_id": "",
            "note": "oversized",
            "at": "2026-08-28T12:00:00Z",
        }
    )
    original_limit = budget_module._MAX_STATE_BYTES
    monkeypatch.setattr(budget_module, "_MAX_STATE_BYTES", 1)

    with pytest.raises(BudgetError, match="exceeds"):
        ledger._write(update)

    assert path.read_bytes() == prior
    monkeypatch.setattr(budget_module, "_MAX_STATE_BYTES", original_limit)
    assert BudgetLedger(path).summary()["entry_count"] == 0


def test_budget_store_accepts_empty_legacy_v01_state(tmp_path):
    path = tmp_path / "budget.json"
    atomic_write_json(
        path,
        {
            "schema_version": "0.1.0",
            "balance_usd": "10",
            "total_spent_usd": "0",
            "total_estimated_usd": "0",
            "reservations": {},
            "entries": [],
        },
    )

    ledger = BudgetLedger(path)
    ledger.grant("2", "legacy continuation")

    restored = read_json(path)
    assert restored["schema_version"] == "0.1.0"
    assert restored["balance_usd"] == "12"
    assert restored["reconciliations"] == {}


def test_budget_store_rejects_unknown_schema(tmp_path):
    path = tmp_path / "budget.json"
    BudgetLedger(path, starting_balance_usd="10")
    raw = read_json(path)
    raw["schema_version"] = "99.0.0"
    atomic_write_json(path, raw)

    with pytest.raises(BudgetError, match="unsupported budget ledger schema"):
        BudgetLedger(path)
