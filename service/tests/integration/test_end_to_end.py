"""Full flows against a real chain: publish, gate, prove, verify, attest, withdraw and shred."""

from __future__ import annotations

import hashlib
import json

import pytest

from dataledger import db
from dataledger.canonical import Column, Schema
from dataledger.chain import ChainError, Classification, VersionStatus
from dataledger.client import ApiError
from dataledger.crypto import KeyRing
from dataledger.workflows import audit_quality, publish_version, register_dataset

from .conftest import ORDERS_CSV, ORDERS_SCHEMA, Env

pytestmark = pytest.mark.chain
DAY = 86_400


def publish_orders(env: Env, data: bytes = ORDERS_CSV, classification=Classification.CONFIDENTIAL):
    dataset_id = env.register_orders(classification)
    published = publish_version(env.chain, env.api, env.owner, dataset_id, data, "orders_2026-09.csv")
    env.sync()
    return dataset_id, published


def grant(env: Env, dataset_id: int, account, days: int = 30, purpose: str = "Monthly revenue reporting"):
    env.chain.grant_access(env.owner, dataset_id, account.address, days * DAY, purpose)


# ---------------------------------------------------------------------- publish + index


def test_publish_anchors_version_and_indexes_it(env: Env):
    dataset_id, published = publish_orders(env)
    on_chain = env.chain.get_version(dataset_id, published.version)
    assert on_chain["merkle_root"] == published.staged["merkle_root"]
    assert on_chain["content_hash"] == "0x" + hashlib.sha256(ORDERS_CSV).hexdigest()
    assert on_chain["record_count"] == 5

    detail = env.api.dataset(dataset_id)
    assert detail["name"] == "sales_orders"
    assert detail["classification_label"] == "Confidential"
    assert detail["schema"]["owner_team"] == "Sales operations"
    (version,) = detail["versions"]
    assert version["status_label"] == "Active"
    assert version["object"]["state"] == "anchored"
    assert version["schema_hash"] == "0x" + ORDERS_SCHEMA.schema_hash().hex()
    events = [e["event"] for e in env.api.audit(dataset_id)]
    assert {"DatasetRegistered", "VersionCommitted", "ObjectStaged"} <= set(events)

    stats = env.api.overview()["stats"]
    assert stats["datasets"] == 1
    assert stats["records_anchored"] == 5


def test_stored_object_is_encrypted_at_rest(env: Env):
    _, published = publish_orders(env)
    object_id = published.staged["object_id"]
    sealed = env.platform.store.get(object_id)
    assert b"shipped" not in sealed
    assert hashlib.sha256(sealed).hexdigest() == object_id


def test_upload_rules(env: Env):
    dataset_id = env.register_orders()
    with pytest.raises(ApiError) as denied:
        env.api.as_account(env.analyst).upload(dataset_id, ORDERS_CSV, "x.csv")
    assert denied.value.status == 403
    with pytest.raises(ApiError) as bad_header:
        env.api.as_account(env.owner).upload(dataset_id, b"order_id,amount\n1,2\n", "x.csv")
    assert bad_header.value.status == 422
    with pytest.raises(ApiError) as empty:
        env.api.as_account(env.owner).upload(dataset_id, b"order_id,customer_id,order_date,amount,status\n", "x.csv")
    assert empty.value.status == 422
    with pytest.raises(ApiError) as unsigned:
        env.api._request("POST", f"/api/datasets/{dataset_id}/objects", files={"file": ("x.csv", ORDERS_CSV)})
    assert unsigned.value.status == 401


def test_steward_can_publish(env: Env):
    dataset_id = env.register_orders()
    env.chain.set_steward(env.owner, dataset_id, env.steward.address, True)
    published = publish_version(env.chain, env.api, env.steward, dataset_id, ORDERS_CSV, "o.csv")
    env.sync()
    assert published.version == 1
    assert env.api.dataset(dataset_id)["stewards"] == [env.steward.address]


def test_mismatched_anchor_is_flagged(env: Env):
    dataset_id = env.register_orders()
    staged = env.api.as_account(env.owner).upload(dataset_id, ORDERS_CSV, "o.csv")
    env.chain.commit_version(
        env.owner,
        dataset_id,
        merkle_root="0x" + "ab" * 32,
        content_hash=staged["content_hash"],
        schema_hash=staged["schema_hash"],
        record_count=staged["record_count"],
        storage_uri=staged["storage_uri"],
    )
    env.sync()
    assert env.api.dataset(dataset_id)["versions"][0]["object"]["state"] == "mismatch"


# ---------------------------------------------------------------------- access control


def test_download_requires_grant_and_is_logged_on_chain(env: Env):
    dataset_id, published = publish_orders(env)
    analyst = env.api.as_account(env.analyst)
    with pytest.raises(ApiError) as denied:
        analyst.download(dataset_id, 1)
    assert denied.value.status == 403

    request_id = env.chain.request_access(env.analyst, dataset_id, "Monthly revenue reporting")
    env.chain.approve_request(env.owner, request_id, 30 * DAY)
    data, headers = analyst.download(dataset_id, 1)
    assert data == ORDERS_CSV
    assert headers["x-dl-content-hash"] == "0x" + hashlib.sha256(data).hexdigest()
    assert headers["x-dl-merkle-root"] == published.staged["merkle_root"]
    assert headers["x-dl-access-tx"].startswith("0x")

    env.sync()
    detail = env.api.dataset(dataset_id)
    assert detail["access_count"] == 1
    assert detail["recent_reads"][0]["accessor"] == env.analyst.address
    assert detail["recent_reads"][0]["receipt_hash"] == headers["x-dl-receipt"]
    (grant_row,) = detail["grants"]
    assert grant_row["purpose"] == "Monthly revenue reporting"
    assert grant_row["active"]
    assert detail["access_requests"][0]["status"] == "approved"

    env.chain.revoke_access(env.owner, dataset_id, env.analyst.address)
    with pytest.raises(ApiError) as revoked:
        analyst.download(dataset_id, 1)
    assert revoked.value.status == 403


def test_public_dataset_is_readable_by_any_signer(env: Env):
    dataset_id, _ = publish_orders(env, classification=Classification.PUBLIC)
    data, _ = env.api.as_account(env.partner).download(dataset_id, 1)
    assert data == ORDERS_CSV


def test_rejected_request_is_indexed_with_reason(env: Env):
    dataset_id, _ = publish_orders(env)
    request_id = env.chain.request_access(env.partner, dataset_id, "Lead enrichment")
    env.chain.reject_request(env.owner, request_id, "Customer data is not shared with partners")
    env.sync()
    (req,) = env.api.dataset(dataset_id)["access_requests"]
    assert req["status"] == "rejected"
    assert req["reason"] == "Customer data is not shared with partners"


def test_signed_request_cannot_be_replayed(env: Env):
    from dataledger.auth import sign_headers

    dataset_id, _ = publish_orders(env)
    path = f"/api/datasets/{dataset_id}/versions/1/download"
    headers = sign_headers(env.owner, "GET", path)
    http = env.api._http
    assert http.get(path, headers=headers).status_code == 200
    assert http.get(path, headers=headers).status_code == 401


# ---------------------------------------------------------------------- proofs + verification


def test_python_proofs_verify_on_chain(env: Env):
    dataset_id, _ = publish_orders(env)
    owner = env.api.as_account(env.owner)
    for index in range(5):
        proof = owner.record_proof(dataset_id, 1, index)
        assert env.chain.verify_record(dataset_id, 1, index, proof["canonical"].encode(), proof["proof"])
        assert env.chain.record_leaf(index, proof["canonical"].encode()).hex() == proof["leaf"][2:]
        assert env.api.verify_record(proof)["valid"] is True

    proof = owner.record_proof(dataset_id, 1, 3)
    tampered = {**proof, "canonical": proof["canonical"].replace("640", "64")}
    assert env.api.verify_record(tampered)["valid"] is False
    moved = {**proof, "index": 2}
    assert env.api.verify_record(moved)["valid"] is False
    via_record = {k: v for k, v in proof.items() if k != "canonical"}
    assert env.api.verify_record(via_record)["valid"] is True


def test_verify_file_levels(env: Env):
    dataset_id, _ = publish_orders(env)
    exact = env.api.verify_file(ORDERS_CSV)
    assert exact["result"] == "exact_match"
    assert (exact["dataset_id"], exact["version"]) == (dataset_id, 1)

    crlf = ORDERS_CSV.replace(b"\n", b"\r\n").replace(b"120.50", b"120.5")
    assert env.api.verify_file(crlf)["result"] == "unknown"
    assert env.api.verify_file(crlf, dataset_id, 1)["result"] == "records_match"

    tampered = ORDERS_CSV.replace(b"640.00", b"6400.00")
    result = env.api.verify_file(tampered, dataset_id, 1)
    assert result["result"] == "mismatch"
    assert result["merkle_root"] != result["anchored_merkle_root"]

    diff = env.api.as_account(env.owner).diff(dataset_id, 1, tampered + b"1006,11,2026-09-06,1,shipped\n")
    assert diff == {"identical": False, "changed_rows": [3], "changed_count": 1, "added": 1, "removed": 0}


def test_storage_tampering_is_detected(env: Env):
    dataset_id, published = publish_orders(env)
    object_id = published.staged["object_id"]
    path = env.platform.store._path(object_id)
    path.write_bytes(path.read_bytes()[:-1] + b"\x00")
    with pytest.raises(ApiError) as broken:
        env.api.as_account(env.owner).download(dataset_id, 1)
    assert broken.value.status == 409


# ---------------------------------------------------------------------- lineage + quality


def test_lineage_graph_spans_datasets(env: Env):
    orders_id, _ = publish_orders(env)
    revenue_schema = Schema(
        name="revenue_by_customer",
        columns=(Column("customer_id", "integer", required=True), Column("revenue", "decimal", required=True)),
        primary_key=("customer_id",),
    )
    revenue_id = register_dataset(env.chain, env.api, env.owner, revenue_schema, Classification.INTERNAL)
    publish_version(
        env.chain,
        env.api,
        env.owner,
        revenue_id,
        b"customer_id,revenue\n7,135.75\n8,80\n9,640\n10,42.10\n",
        "revenue.csv",
        parents=[(orders_id, 1)],
    )
    env.sync()

    graph = env.api.lineage(revenue_id)
    assert {n["id"] for n in graph["nodes"]} == {f"{orders_id}:1", f"{revenue_id}:1"}
    assert graph["edges"] == [{"from": f"{orders_id}:1", "to": f"{revenue_id}:1"}]
    upstream = env.api.dataset(orders_id)["versions"][0]["children"]
    assert upstream == [{"dataset_id": revenue_id, "version": 1, "name": "revenue_by_customer"}]

    with pytest.raises(ChainError, match="ParentNotUsable"):
        env.chain.commit_version(
            env.owner,
            revenue_id,
            merkle_root="0x" + "11" * 32,
            content_hash="0x" + "22" * 32,
            schema_hash=revenue_schema.schema_hash(),
            record_count=1,
            storage_uri="dl://objects/" + "0" * 64,
            parents=[(orders_id, 9)],
        )


def test_quality_attestation_flow(env: Env):
    bad = ORDERS_CSV + b"1006,,2026-09-06,10,shipped\n1001,7,2026-09-01,120.50,shipped\n"
    dataset_id, _ = publish_orders(env, data=bad)
    publish_version(env.chain, env.api, env.owner, dataset_id, ORDERS_CSV, "fixed.csv")
    grant(env, dataset_id, env.auditor, purpose="Independent quality review")

    failed = audit_quality(env.chain, env.api, env.auditor, dataset_id, 1)
    passed = audit_quality(env.chain, env.api, env.auditor, dataset_id, 2)
    assert failed["passed"] is False and failed["score_bps"] < 10_000
    assert passed["passed"] is True and passed["score_bps"] == 10_000

    env.sync()
    versions = {v["version"]: v for v in env.api.dataset(dataset_id)["versions"]}
    assert versions[1]["quality"]["passed"] == 0
    assert versions[2]["quality"]["passed"] == 1
    report = env.api.document(failed["report_hash"])["body"]
    assert report["merkle_root"] == versions[1]["merkle_root"]
    assert "shipped" not in json.dumps(report)

    with pytest.raises(ChainError, match="AlreadyAttested"):
        audit_quality(env.chain, env.api, env.auditor, dataset_id, 2)


def test_owner_cannot_attest_own_data(env: Env):
    dataset_id, _ = publish_orders(env)
    env.chain.grant_role(env.admin, "QualityLedger", "AUDITOR_ROLE", env.owner.address)
    with pytest.raises(ChainError, match="ConflictOfInterest"):
        audit_quality(env.chain, env.api, env.owner, dataset_id, 1)


# ---------------------------------------------------------------------- lifecycle + erasure


def test_withdraw_then_shred(env: Env):
    dataset_id, published = publish_orders(env)
    grant(env, dataset_id, env.analyst)
    proof = env.api.as_account(env.owner).record_proof(dataset_id, 1, 0)

    env.chain.set_version_status(env.owner, dataset_id, 1, VersionStatus.WITHDRAWN, "erasure request")
    with pytest.raises(ApiError) as gone:
        env.api.as_account(env.analyst).download(dataset_id, 1)
    assert gone.value.status == 410

    with pytest.raises(ApiError) as not_owner:
        env.api.as_account(env.analyst).shred(dataset_id, 1)
    assert not_owner.value.status == 403
    assert env.api.as_account(env.owner).shred(dataset_id, 1)["state"] == "shredded"
    assert not env.platform.store.exists(published.staged["object_id"])

    env.sync()
    version = env.api.dataset(dataset_id)["versions"][0]
    assert version["status_label"] == "Withdrawn"
    assert version["status_reason"] == "erasure request"
    assert version["object"]["state"] == "shredded"
    assert env.api.verify_record(proof)["valid"] is True
    assert env.api.verify_record(proof)["status"] == "Withdrawn"
    assert env.api.overview()["stats"]["shredded_objects"] == 1


def test_key_rotation_keeps_data_readable(env: Env):
    dataset_id, _ = publish_orders(env)
    old = env.platform.ring
    new_entry = KeyRing.generate_entry("k2")
    env.platform.ring = KeyRing({"k2": KeyRing.parse(new_entry).kek("k2"), "k1": old.kek("k1")}, active="k2")
    assert env.platform.rotate_keys() == 1
    with env.platform.engine.connect() as conn:
        assert conn.execute(db.objects.select()).mappings().one()["kek_id"] == "k2"
    env.platform.ring = KeyRing({"k2": env.platform.ring.kek("k2")}, active="k2")
    data, _ = env.api.as_account(env.owner).download(dataset_id, 1)
    assert data == ORDERS_CSV


# ---------------------------------------------------------------------- indexer


def test_indexer_rebuild_is_deterministic(env: Env):
    dataset_id, _ = publish_orders(env)
    grant(env, dataset_id, env.analyst)
    env.sync()
    before = env.api.dataset(dataset_id)
    env.platform.indexer.reset()
    env.sync()
    after = env.api.dataset(dataset_id)
    for key in ("versions", "grants", "stewards", "access_requests"):
        assert before[key] == after[key]


def test_indexer_recovers_from_reorg(env: Env):
    dataset_id, _ = publish_orders(env)
    w3 = env.chain.w3
    snapshot = w3.provider.make_request("evm_snapshot", [])["result"]
    publish_version(env.chain, env.api, env.owner, dataset_id, ORDERS_CSV + b"1006,1,2026-09-06,1,x\n", "v2.csv")
    env.sync()
    assert len(env.api.dataset(dataset_id)["versions"]) == 2

    w3.provider.make_request("evm_revert", [snapshot])
    for _ in range(3):
        w3.provider.make_request("evm_mine", [])
    env.sync()
    assert len(env.api.dataset(dataset_id)["versions"]) == 1
