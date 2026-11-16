"""1.1 gateway features against a real chain: gasless requests, smart accounts, batched grants, probes, metrics."""

from __future__ import annotations

import time

import pytest
from eth_account.messages import encode_typed_data

from dataledger.auth import eip712_digest, sign_headers
from dataledger.chain import Classification
from dataledger.client import ApiError
from dataledger.workflows import publish_version

from .conftest import ORDERS_CSV, Env, deploy_contract

pytestmark = pytest.mark.chain
DAY = 86_400


def _published(env: Env, classification: Classification = Classification.CONFIDENTIAL) -> int:
    dataset_id = env.register_orders(classification)
    publish_version(env.chain, env.api, env.owner, dataset_id, ORDERS_CSV, "orders.csv")
    env.sync()
    return dataset_id


def test_typed_data_matches_the_contract_digest(env: Env):
    dataset_id = _published(env)
    deadline = int(time.time()) + 600
    typed = env.chain.access_request_typed_data(dataset_id, env.analyst.address, "Churn model", 0, deadline)
    python_digest = eip712_digest(encode_typed_data(full_message=typed))
    assert python_digest == env.chain.hash_access_request(dataset_id, env.analyst.address, "Churn model", 0, deadline)


def test_gasless_request_is_relayed_indexed_and_usable(env: Env):
    dataset_id = _published(env)
    analyst = env.api.as_account(env.analyst)
    balance_before = env.chain.w3.eth.get_balance(env.analyst.address)

    result = analyst.request_access_gasless(dataset_id, "Churn model training")
    assert result["requester"] == env.analyst.address
    assert result["relayed_by"] == env.gateway.address
    assert env.chain.w3.eth.get_balance(env.analyst.address) == balance_before  # the analyst paid nothing
    assert env.chain.access_nonce(env.analyst.address) == 1

    env.sync()
    (request,) = env.api._request("GET", "/api/access-requests").json()
    assert request["request_id"] == result["request_id"]
    assert request["requester"] == env.analyst.address
    assert request["purpose"] == "Churn model training"
    assert "AccessRequestRelayed" in [e["event"] for e in env.api.audit(dataset_id)]

    env.chain.approve_request(env.owner, result["request_id"], 30 * DAY)
    data, _ = analyst.download(dataset_id, 1)
    assert data == ORDERS_CSV


def test_relay_refuses_tampered_expired_and_flooding_requests(env: Env):
    dataset_id = _published(env)
    http = env.api._http
    body = {"dataset_id": dataset_id, "requester": env.analyst.address, "purpose": "Forecasting"}
    typed = http.post("/api/relay/access-requests/prepare", json=body).json()
    signature = "0x" + bytes(env.analyst.sign_message(encode_typed_data(full_message=typed)).signature).hex()
    deadline = typed["message"]["deadline"]

    tampered = http.post(
        "/api/relay/access-requests",
        json={**body, "purpose": "Something else", "deadline": deadline, "signature": signature},
    )
    assert tampered.status_code == 400
    assert tampered.json()["error"] == "InvalidSignature"

    expired = http.post("/api/relay/access-requests", json={**body, "deadline": 1, "signature": signature})
    assert expired.status_code == 422

    env.platform.relay_limiter.per_hour = 1
    ok = http.post("/api/relay/access-requests", json={**body, "deadline": deadline, "signature": signature})
    assert ok.status_code == 201
    again = http.post("/api/relay/access-requests", json={**body, "deadline": deadline, "signature": signature})
    assert again.status_code == 429
    assert again.headers["retry-after"] == "3600"


def test_relay_can_be_switched_off(env: Env):
    dataset_id = _published(env)
    env.platform.settings.relay_enabled = False
    with pytest.raises(ApiError) as info:
        env.api.as_account(env.analyst).request_access_gasless(dataset_id, "Forecasting")
    assert info.value.status == 403


def test_smart_account_signs_api_calls_and_relayed_requests(env: Env):
    """An ERC-1271 wallet (owned by the partner key) asks for access gaslessly, then downloads."""
    dataset_id = _published(env)
    wallet = deploy_contract(env.url, env.admin, "SmartAccountMock", env.partner.address)
    http = env.api._http

    body = {"dataset_id": dataset_id, "requester": wallet, "purpose": "Partner settlement"}
    typed = http.post("/api/relay/access-requests/prepare", json=body).json()
    signature = "0x" + bytes(env.partner.sign_message(encode_typed_data(full_message=typed)).signature).hex()
    relayed = http.post(
        "/api/relay/access-requests",
        json={**body, "deadline": typed["message"]["deadline"], "signature": signature},
    )
    assert relayed.status_code == 201, relayed.text
    env.chain.approve_request(env.owner, relayed.json()["request_id"], 7 * DAY)

    path = f"/api/datasets/{dataset_id}/versions/1/download"
    domain = env.api.signing_domain()
    response = http.get(path, headers=sign_headers(env.partner, domain, "GET", path, on_behalf_of=wallet))
    assert response.status_code == 200, response.text
    assert response.content == ORDERS_CSV

    stranger = http.get(path, headers=sign_headers(env.steward, domain, "GET", path, on_behalf_of=wallet))
    assert stranger.status_code == 401


def test_batched_grants_keep_their_purpose_text(env: Env):
    dataset_id = _published(env)
    access = env.chain.access
    calls = [
        access.encode_abi("grantAccess", args=[dataset_id, account.address, 30 * DAY, "Month-end close"])
        for account in (env.analyst, env.partner)
    ]
    env.chain.transact(access.functions.multicall(calls), env.owner)
    env.sync()
    grants = {g["grantee"]: g for g in env.api.dataset(dataset_id)["grants"]}
    assert grants[env.analyst.address]["purpose"] == "Month-end close"
    assert grants[env.partner.address]["purpose"] == "Month-end close"


def test_probes_metrics_and_request_ids(env: Env):
    http = env.api._http
    assert http.get("/healthz").json() == {"status": "ok"}
    ready = http.get("/readyz")
    assert ready.status_code == 200
    assert ready.json() == {"ready": True, "checks": {"database": True, "chain": True}}

    dataset_id = _published(env, Classification.PUBLIC)
    env.api.as_account(env.analyst).download(dataset_id, 1)
    response = http.get("/metrics")
    assert response.headers["content-type"].startswith("text/plain")
    text = response.text
    assert 'dataledger_gateway_events_total{event="read_logged"} 1.0' in text
    assert 'dataledger_gateway_events_total{event="upload_staged"} 1.0' in text
    assert "dataledger_chain_up 1.0" in text
    assert "dataledger_indexer_lag_blocks" in text
    assert 'route="/api/datasets/{dataset_id}/versions/{version}/download"' in text
    assert http.get("/api/health", headers={"X-Request-ID": "trace-me"}).headers["x-request-id"] == "trace-me"


def test_auth_domain_is_published(env: Env):
    info = env.api._http.get("/api/auth/domain").json()
    assert info["domain"]["chainId"] == env.chain.deployment.chain_id
    assert info["domain"]["verifyingContract"] == env.chain.deployment.access_ledger
    assert info["primaryType"] == "Request"
    assert "Content-Digest" in info["headers"]
