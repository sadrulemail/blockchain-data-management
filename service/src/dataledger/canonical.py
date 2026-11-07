"""Schemas, canonical record encoding and record leaves.

Every record is reduced to one canonical byte string before hashing, so the same logical row always produces
the same leaf: typed values are normalised (``12.50`` and ``12.5`` are the same decimal), keys are sorted and
JSON is written without whitespace. Values that do not parse keep their raw text, so any file can be anchored
and the quality checks report the bad cells.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Literal

from eth_abi import encode as abi_encode
from eth_utils import keccak

ColumnType = Literal["string", "integer", "decimal", "date", "timestamp", "boolean"]
COLUMN_TYPES: tuple[str, ...] = ("string", "integer", "decimal", "date", "timestamp", "boolean")
_TRUE = {"true", "t", "yes", "y", "1"}
_FALSE = {"false", "f", "no", "n", "0"}


class SchemaError(ValueError):
    """The file does not match the dataset schema (missing or extra columns)."""


@dataclass(frozen=True)
class Column:
    name: str
    type: ColumnType = "string"
    required: bool = False
    pii: bool = False
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type,
            "required": self.required,
            "pii": self.pii,
            "description": self.description,
        }


@dataclass(frozen=True)
class Schema:
    """Structure of a dataset plus descriptive metadata. Only the structure feeds the schema hash."""

    name: str
    columns: tuple[Column, ...]
    primary_key: tuple[str, ...] = ()
    description: str = ""
    owner_team: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        names = [c.name for c in self.columns]
        if not names:
            raise SchemaError("schema needs at least one column")
        if len(set(names)) != len(names):
            raise SchemaError("column names must be unique")
        for column in self.columns:
            if column.type not in COLUMN_TYPES:
                raise SchemaError(f"unknown type {column.type!r} for column {column.name!r}")
        missing = [k for k in self.primary_key if k not in names]
        if missing:
            raise SchemaError(f"primary key columns not in schema: {missing}")

    @property
    def column_names(self) -> list[str]:
        return [c.name for c in self.columns]

    def column(self, name: str) -> Column:
        for c in self.columns:
            if c.name == name:
                return c
        raise KeyError(name)

    def structure(self) -> dict[str, Any]:
        """Part of the schema that defines record layout; descriptions and tags are excluded."""
        return {
            "columns": [{"name": c.name, "type": c.type, "required": c.required} for c in self.columns],
            "primary_key": list(self.primary_key),
        }

    def schema_hash(self) -> bytes:
        return keccak(canonical_json(self.structure()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "owner_team": self.owner_team,
            "tags": list(self.tags),
            "primary_key": list(self.primary_key),
            "columns": [c.to_dict() for c in self.columns],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Schema:
        try:
            columns = tuple(
                Column(
                    name=c["name"],
                    type=c.get("type", "string"),
                    required=bool(c.get("required", False)),
                    pii=bool(c.get("pii", False)),
                    description=c.get("description", ""),
                )
                for c in data["columns"]
            )
            return cls(
                name=data["name"],
                columns=columns,
                primary_key=tuple(data.get("primary_key", ())),
                description=data.get("description", ""),
                owner_team=data.get("owner_team", ""),
                tags=tuple(data.get("tags", ())),
            )
        except (KeyError, TypeError) as exc:
            raise SchemaError(f"invalid schema document: {exc}") from exc

    @classmethod
    def from_file(cls, path: str | Path) -> Schema:
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def parse_value(column: Column, raw: str | None) -> tuple[Any, bool]:
    """Returns (normalised value, parsed ok). Empty cells become null; unparseable cells keep their raw text."""
    if raw is None or raw == "":
        return None, True
    text = raw.strip()
    try:
        match column.type:
            case "string":
                return raw, True
            case "integer":
                if not text.lstrip("+-").isdigit():
                    return raw, False
                return int(text), True
            case "decimal":
                d = Decimal(text)
                if not d.is_finite():
                    return raw, False
                normalised = format(d.normalize(), "f")
                return ("0" if normalised in ("-0", "0") else normalised), True
            case "date":
                return date.fromisoformat(text).isoformat(), True
            case "timestamp":
                return datetime.fromisoformat(text.replace("Z", "+00:00")).isoformat(), True
            case "boolean":
                lowered = text.lower()
                if lowered in _TRUE:
                    return True, True
                if lowered in _FALSE:
                    return False, True
                return raw, False
    except (InvalidOperation, ValueError):
        return raw, False
    return raw, False


@dataclass
class ParsedDataset:
    schema: Schema
    rows: list[dict[str, str]]
    records: list[bytes]
    parse_errors: list[tuple[int, str]]

    @property
    def record_count(self) -> int:
        return len(self.records)


def canonical_record(schema: Schema, row: dict[str, str | None]) -> tuple[bytes, list[str]]:
    values: dict[str, Any] = {}
    bad: list[str] = []
    for column in schema.columns:
        value, ok = parse_value(column, row.get(column.name))
        values[column.name] = value
        if not ok:
            bad.append(column.name)
    return canonical_json(values), bad


def parse_csv(data: bytes, schema: Schema) -> ParsedDataset:
    """Reads a UTF-8 CSV whose header must hold exactly the schema columns (in any order)."""
    text = data.decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(text, newline=""))
    header = reader.fieldnames or []
    expected = set(schema.column_names)
    missing = sorted(expected - set(header))
    extra = sorted(set(header) - expected)
    if missing or extra or len(header) != len(set(header)):
        raise SchemaError(f"header does not match schema {schema.name!r}: missing={missing} extra={extra}")

    rows: list[dict[str, str]] = []
    records: list[bytes] = []
    errors: list[tuple[int, str]] = []
    for index, row in enumerate(reader):
        if None in row:
            raise SchemaError(f"row {index} has more cells than the header")
        record, bad = canonical_record(schema, row)
        rows.append(row)
        records.append(record)
        errors.extend((index, column) for column in bad)
    return ParsedDataset(schema=schema, rows=rows, records=records, parse_errors=errors)


def record_leaf(index: int, record: bytes) -> bytes:
    """Same as DataRegistry.recordLeaf: keccak256(keccak256(abi.encode(uint256 index, bytes record)))."""
    return keccak(keccak(abi_encode(["uint256", "bytes"], [index, record])))
