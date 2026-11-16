import json

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
