"""Spins up anvil, deploys fresh ledgers per test and wires the API through FastAPI's TestClient."""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from eth_account import Account
from eth_account.signers.local import LocalAccount
from fastapi.testclient import TestClient
from pydantic import SecretStr
from web3 import Web3

from dataledger.api import create_app
from dataledger.canonical import Column, Schema
from dataledger.chain import Chain, Classification, Deployment
from dataledger.client import ApiClient
from dataledger.config import Settings
from dataledger.crypto import KeyRing
from dataledger.platform import Platform
from dataledger.workflows import register_dataset

REPO = Path(__file__).resolve().parents[3]
ARTIFACTS = REPO / "contracts" / "out"

# Default anvil accounts (public development keys, never used outside a local chain).
ANVIL_KEYS = [
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
    "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
    "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
    "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
]

ORDERS_SCHEMA = Schema(
    name="sales_orders",
    description="Orders shipped to customers",
    owner_team="Sales operations",
    columns=(
        Column("order_id", "integer", required=True),
        Column("customer_id", "integer", required=True),
        Column("order_date", "date", required=True),
        Column("amount", "decimal", required=True),
        Column("status", "string"),
    ),
    primary_key=("order_id",),
)

ORDERS_CSV = (
    b"order_id,customer_id,order_date,amount,status\n"
    b"1001,7,2026-09-01,120.50,shipped\n"
    b"1002,8,2026-09-02,80,shipped\n"
    b"1003,7,2026-09-03,15.25,returned\n"
    b"1004,9,2026-09-04,640.00,shipped\n"
    b"1005,10,2026-09-05,42.10,pending\n"
)


def _anvil_binary() -> str | None:
    found = shutil.which("anvil")
    if found:
        return found
    for name in ("anvil.exe", "anvil"):
        candidate = Path.home() / ".foundry" / "bin" / name
        if candidate.exists():
            return str(candidate)
    return None


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def anvil_url() -> Iterator[str]:
    binary = _anvil_binary()
    if binary is None or not (ARTIFACTS / "DataRegistry.sol" / "DataRegistry.json").exists():
        pytest.skip("needs anvil on PATH and `forge build` in contracts/")
    port = _free_port()
    proc = subprocess.Popen(
        [binary, "--port", str(port), "--silent"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    url = f"http://127.0.0.1:{port}"
    w3 = Web3(Web3.HTTPProvider(url))
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            if w3.is_connected():
                break
        except Exception:  # noqa: S110 - anvil is still starting
            pass
        time.sleep(0.2)
    else:
        proc.kill()
        pytest.fail("anvil did not start")
    yield url
    proc.terminate()
    proc.wait(timeout=10)


def _artifact(name: str) -> tuple[list, str]:
    data = json.loads((ARTIFACTS / f"{name}.sol" / f"{name}.json").read_text(encoding="utf-8"))
    return data["abi"], data["bytecode"]["object"]


def deploy_ledgers(url: str, admin: LocalAccount, gateway: str, auditor: str, publishers: list[str]) -> Deployment:
    w3 = Web3(Web3.HTTPProvider(url))
    chain_id = w3.eth.chain_id
    start_block = w3.eth.block_number + 1

    def send(tx_fn) -> dict:
        tx = tx_fn.build_transaction(
            {"from": admin.address, "nonce": w3.eth.get_transaction_count(admin.address, "pending")}
        )
        receipt = w3.eth.wait_for_transaction_receipt(
            w3.eth.send_raw_transaction(admin.sign_transaction(tx).raw_transaction)
        )
        assert receipt["status"] == 1
        return receipt

    addresses = {}
    for name, args in (
        ("DataRegistry", lambda: [admin.address]),
        ("AccessLedger", lambda: [addresses["DataRegistry"], admin.address]),
        ("QualityLedger", lambda: [addresses["DataRegistry"], admin.address]),
    ):
        abi, bytecode = _artifact(name)
        receipt = send(w3.eth.contract(abi=abi, bytecode=bytecode).constructor(*args()))
        addresses[name] = receipt["contractAddress"]

    deployment = Deployment(
        chain_id=chain_id,
        data_registry=addresses["DataRegistry"],
        access_ledger=addresses["AccessLedger"],
        quality_ledger=addresses["QualityLedger"],
        start_block=start_block,
    )
    chain = Chain(url, deployment)
    chain.grant_role(admin, "AccessLedger", "GATEWAY_ROLE", gateway)
    chain.grant_role(admin, "QualityLedger", "AUDITOR_ROLE", auditor)
    for publisher in publishers:
        chain.grant_role(admin, "DataRegistry", "PUBLISHER_ROLE", publisher)
    return deployment


@dataclass
class Env:
    platform: Platform
    chain: Chain
    api: ApiClient
    admin: LocalAccount
    gateway: LocalAccount
    auditor: LocalAccount
    owner: LocalAccount
    analyst: LocalAccount
    partner: LocalAccount
    steward: LocalAccount
    tmp: Path

    def sync(self) -> None:
        self.platform.indexer.sync()

    def register_orders(self, classification: Classification = Classification.CONFIDENTIAL) -> int:
        return register_dataset(self.chain, self.api, self.owner, ORDERS_SCHEMA, classification)


@pytest.fixture
def env(anvil_url: str, tmp_path: Path) -> Iterator[Env]:
    accounts = [Account.from_key(k) for k in ANVIL_KEYS]
    admin, gateway, auditor, owner, analyst, partner, steward = accounts
    deployment = deploy_ledgers(anvil_url, admin, gateway.address, auditor.address, [owner.address])
    deployment_file = tmp_path / "deployment.json"
    deployment_file.write_text(json.dumps(deployment.to_dict()), encoding="utf-8")

    settings = Settings(
        rpc_url=anvil_url,
        deployment_file=deployment_file,
        database_url=f"sqlite:///{(tmp_path / 'dataledger.db').as_posix()}",
        object_store_dir=tmp_path / "objects",
        master_keys=SecretStr(KeyRing.generate_entry("k1")),
        gateway_private_key=SecretStr(ANVIL_KEYS[1]),
        _env_file=None,
    )
    platform = Platform.from_settings(settings)
    app = create_app(platform, start_indexer=False)
    with TestClient(app) as http:
        yield Env(
            platform=platform,
            chain=platform.chain,
            api=ApiClient.wrap(http),
            admin=admin,
            gateway=gateway,
            auditor=auditor,
            owner=owner,
            analyst=analyst,
            partner=partner,
            steward=steward,
            tmp=tmp_path,
        )
