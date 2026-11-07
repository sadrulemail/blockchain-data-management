import pytest
from eth_abi import encode
from eth_utils import keccak

from dataledger.canonical import Column, Schema, SchemaError, parse_csv, parse_value, record_leaf

ORDERS = Schema(
    name="sales_orders",
    columns=(
        Column("order_id", "integer", required=True),
        Column("order_date", "date", required=True),
        Column("amount", "decimal"),
        Column("paid", "boolean"),
        Column("note", "string"),
    ),
    primary_key=("order_id",),
    description="Orders",
)


@pytest.mark.parametrize(
    ("column_type", "raw", "expected", "ok"),
    [
        ("integer", "42", 42, True),
        ("integer", " +7 ", 7, True),
        ("integer", "1_000", "1_000", False),
        ("integer", "4.2", "4.2", False),
        ("decimal", "12.50", "12.5", True),
        ("decimal", "1e3", "1000", True),
        ("decimal", "-0.00", "0", True),
        ("decimal", "NaN", "NaN", False),
        ("decimal", "abc", "abc", False),
        ("date", "2026-09-30", "2026-09-30", True),
        ("date", "30/09/2026", "30/09/2026", False),
        ("timestamp", "2026-09-30T10:00:00Z", "2026-09-30T10:00:00+00:00", True),
        ("boolean", "Yes", True, True),
        ("boolean", "0", False, True),
        ("boolean", "maybe", "maybe", False),
        ("string", "  keep spaces ", "  keep spaces ", True),
        ("integer", "", None, True),
    ],
)
def test_parse_value_normalises(column_type, raw, expected, ok):
    assert parse_value(Column("c", column_type), raw) == (expected, ok)


def test_equivalent_rows_produce_identical_records():
    a = parse_csv(b"order_id,order_date,amount,paid,note\n1,2026-09-01,12.50,true,x\n", ORDERS)
    b = parse_csv(b"note,paid,amount,order_date,order_id\r\nx,yes,12.5,2026-09-01,01\r\n", ORDERS)
    assert a.records == b.records
    assert a.records[0] == b'{"amount":"12.5","note":"x","order_date":"2026-09-01","order_id":1,"paid":true}'


def test_parse_errors_are_collected_not_raised():
    parsed = parse_csv(b"order_id,order_date,amount,paid,note\nx,2026-13-01,1,true,\n", ORDERS)
    assert parsed.record_count == 1
    assert sorted(c for _, c in parsed.parse_errors) == ["order_date", "order_id"]


def test_header_must_match_schema():
    with pytest.raises(SchemaError, match="missing"):
        parse_csv(b"order_id,order_date\n1,2026-09-01\n", ORDERS)
    with pytest.raises(SchemaError, match="extra"):
        parse_csv(b"order_id,order_date,amount,paid,note,ssn\n", ORDERS)


def test_row_with_extra_cells_is_rejected():
    with pytest.raises(SchemaError, match="more cells"):
        parse_csv(b"order_id,order_date,amount,paid,note\n1,2026-09-01,1,true,x,extra\n", ORDERS)


def test_schema_hash_ignores_descriptions_but_not_structure():
    relabelled = Schema.from_dict({**ORDERS.to_dict(), "description": "changed", "tags": ["finance"]})
    assert relabelled.schema_hash() == ORDERS.schema_hash()
    changed = ORDERS.to_dict()
    changed["columns"][2]["type"] = "string"
    assert Schema.from_dict(changed).schema_hash() != ORDERS.schema_hash()


def test_schema_validation():
    with pytest.raises(SchemaError):
        Schema("x", ())
    with pytest.raises(SchemaError):
        Schema("x", (Column("a"), Column("a")))
    with pytest.raises(SchemaError):
        Schema("x", (Column("a"),), primary_key=("b",))
    with pytest.raises(SchemaError):
        Schema.from_dict({"name": "x"})


def test_record_leaf_matches_solidity_encoding():
    record = b'{"id":1}'
    assert record_leaf(7, record) == keccak(keccak(encode(["uint256", "bytes"], [7, record])))
