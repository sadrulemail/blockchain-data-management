import json
from datetime import UTC, datetime, timedelta

import pytest
from eth_account import Account

from dataledger.auth import HEADER_ISSUED, AuthError, RequestVerifier, sign_headers
from dataledger.canonical import Column, Schema, parse_csv
from dataledger.quality import run_checks

SCHEMA = Schema(
    name="customers",
    columns=(
        Column("customer_id", "integer", required=True),
        Column("email", "string", required=True, pii=True),
        Column("signup_date", "date"),
    ),
    primary_key=("customer_id",),
)

ALICE = Account.from_key("0x" + "11" * 32)
BOB = Account.from_key("0x" + "22" * 32)


def test_clean_file_passes_with_full_score():
    data = b"customer_id,email,signup_date\n1,a@x.io,2026-01-02\n2,b@x.io,2026-02-03\n"
    report = run_checks(parse_csv(data, SCHEMA))
    assert report.passed
    assert report.score_bps == 10_000


def test_failures_are_reported_by_row_without_values():
    data = (
        b"customer_id,email,signup_date\n"
        b"1,secret@x.io,2026-01-02\n"
        b"1,other@x.io,not-a-date\n"
        b",missing@x.io,2026-01-02\n"
        b"1,secret@x.io,2026-01-02\n"
    )
    report = run_checks(parse_csv(data, SCHEMA))
    by_name = {(c.name, c.column): c for c in report.checks}
    assert not report.passed
    assert by_name[("required_value", "customer_id")].examples == [2]
    assert by_name[("type_conformance", "signup_date")].examples == [1]
    assert by_name[("primary_key_unique", "customer_id")].failures == 3
    assert by_name[("no_duplicate_records", None)].examples == [3]
    assert 0 < report.score_bps < 10_000

    document = json.dumps(report.to_document(dataset_id=1, version=1, content_hash="0x", merkle_root="0x"))
    assert "secret@x.io" not in document
    assert "missing@x.io" not in document


def test_signed_request_verifies_once():
    verifier = RequestVerifier(300)
    headers = sign_headers(ALICE, "GET", "/api/datasets/1/versions/1/download")
    assert verifier.verify("GET", "/api/datasets/1/versions/1/download", headers) == ALICE.address
    with pytest.raises(AuthError, match="nonce"):
        verifier.verify("GET", "/api/datasets/1/versions/1/download", headers)


def test_signature_is_bound_to_method_path_and_address():
    verifier = RequestVerifier(300)
    headers = sign_headers(ALICE, "GET", "/api/datasets/1/versions/1/download")
    with pytest.raises(AuthError):
        verifier.verify("GET", "/api/datasets/2/versions/1/download", dict(headers))
    with pytest.raises(AuthError):
        verifier.verify("POST", "/api/datasets/1/versions/1/download", dict(headers))
    with pytest.raises(AuthError, match="does not match"):
        verifier.verify("GET", "/api/datasets/1/versions/1/download", {**headers, "X-DL-Address": BOB.address})


def test_expired_and_malformed_requests_are_rejected():
    verifier = RequestVerifier(60)
    headers = sign_headers(ALICE, "GET", "/x")
    old = (datetime.now(UTC) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with pytest.raises(AuthError, match="expired"):
        verifier.verify("GET", "/x", {**headers, HEADER_ISSUED: old})
    with pytest.raises(AuthError, match="missing"):
        verifier.verify("GET", "/x", {})
    with pytest.raises(AuthError, match="malformed address"):
        verifier.verify("GET", "/x", {**headers, "X-DL-Address": "0x123"})
