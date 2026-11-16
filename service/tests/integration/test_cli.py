"""The `dataledger` command line, driven end to end against the test chain and API."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from dataledger import cli
from dataledger.client import ApiClient, ApiError

from .conftest import ANVIL_KEYS, Env

pytestmark = pytest.mark.chain
DATASETS = Path(__file__).resolve().parents[3] / "datasets"


class _KeepOpen(ApiClient):
    def close(self) -> None:  # the TestClient outlives each command
        pass


@pytest.fixture
def run(env: Env, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(cli, "get_settings", lambda: env.platform.settings)
    monkeypatch.setattr(cli, "_chain", lambda: env.chain)
    monkeypatch.setattr(cli, "_api", lambda account=None: _KeepOpen.wrap(env.api._http, account))
    runner = CliRunner()

    def invoke(*args: str, key: int | None = None) -> str:
        env_vars = {"DATALEDGER_PRIVATE_KEY": ANVIL_KEYS[key]} if key is not None else {}
        result = runner.invoke(cli.app, list(args), env=env_vars, catch_exceptions=False)
        assert result.exit_code == 0, result.output
        return result.output

    return invoke


def _json(output: str) -> dict:
    return json.loads(output[output.index("{") :])


OWNER, ANALYST, PARTNER, AUDITOR, STEWARD = 3, 4, 5, 2, 6


def test_publisher_consumer_and_auditor_commands(env: Env, run, tmp_path: Path):
    schema = DATASETS / "schemas" / "sales_orders.json"
    dataset = _json(run("register", "--schema", str(schema), "--classification", "confidential", key=OWNER))
    dataset_id = str(dataset["dataset_id"])
    csv = DATASETS / "sales_orders_2026-09.csv"
    published = _json(run("publish", "--dataset", dataset_id, "--file", str(csv), key=OWNER))
    assert published["version"] == 1
    env.sync()

    assert "added to stewards" in run("steward", dataset_id, env.steward.address, key=OWNER)
    request = _json(run("request-access", dataset_id, "Revenue forecasting", key=ANALYST))
    assert "approved" in run("approve", str(request["request_id"]), "--days", "7", key=OWNER)
    gasless = _json(run("request-access", dataset_id, "Partner settlement", "--gasless", key=PARTNER))
    assert gasless["relayed_by"] == env.gateway.address
    assert "rejected" in run("reject", str(gasless["request_id"]), "Not shared with partners", key=OWNER)

    out = tmp_path / "orders.csv"
    downloaded = _json(run("download", dataset_id, "1", "--out", str(out), key=ANALYST))
    assert out.read_bytes() == csv.read_bytes()
    assert downloaded["x-dl-access-tx"].startswith("0x")

    proof = _json(run("prove", dataset_id, "1", "3", key=ANALYST))
    proof_file = tmp_path / "proof.json"
    proof_file.write_text(json.dumps(proof), encoding="utf-8")
    assert _json(run("verify-record", str(proof_file)))["valid"] is True
    assert _json(run("verify-file", "--file", str(csv)))["result"] == "exact_match"

    assert "granted" in run("grant", dataset_id, env.partner.address, "Audit sample", "--days", "3", key=OWNER)
    assert "revoked" in run("revoke", dataset_id, env.partner.address, key=OWNER)

    run("grant", dataset_id, env.auditor.address, "Quality audit", "--days", "2", key=OWNER)
    env.sync()
    report = _json(run("quality", dataset_id, "1", key=AUDITOR))
    assert report["passed"] in (True, False)

    assert "deprecated" in run("status", dataset_id, "1", "--to", "deprecated", "--reason", "superseded", key=OWNER)
    assert _json(run("shred", dataset_id, "1", key=OWNER))["state"] == "shredded"


def test_operator_commands(env: Env, run):
    assert run("keygen", "--kid", "kek-2026-11").startswith("DATALEDGER_MASTER_KEYS=kek-2026-11:")
    assert "database at revision 0002" in run("db", "upgrade")
    assert run("db", "current").strip() == "0002"
    assert "cursor at block" in run("index", "--once")
    assert "re-wrapped 0 data keys" in run("rotate-keys")


def test_main_prints_one_line_errors(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    def fail() -> None:
        raise ApiError(403, "no active access grant for this dataset")

    monkeypatch.setattr(cli, "app", fail)
    with pytest.raises(SystemExit) as info:
        cli.main()
    assert info.value.code == 1
    assert "error: HTTP 403: no active access grant" in capsys.readouterr().err
