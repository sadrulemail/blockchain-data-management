"""Data-quality checks run by an independent auditor before an on-chain attestation.

Reports list row positions only, never cell values, so a report can be published next to a confidential
dataset without leaking its content.
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .canonical import ParsedDataset

MAX_EXAMPLES = 10
CRITICAL = "critical"
WARNING = "warning"
_WEIGHTS = {CRITICAL: 3, WARNING: 1}


@dataclass
class CheckResult:
    name: str
    severity: str
    passed: bool
    failures: int = 0
    column: str | None = None
    examples: list[int] = field(default_factory=list)
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "column": self.column,
            "severity": self.severity,
            "passed": self.passed,
            "failures": self.failures,
            "example_rows": self.examples,
            "detail": self.detail,
        }


@dataclass
class QualityReport:
    checks: list[CheckResult]
    record_count: int

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.checks if c.severity == CRITICAL)

    @property
    def score_bps(self) -> int:
        total = sum(_WEIGHTS[c.severity] for c in self.checks)
        if total == 0:
            return 10_000
        earned = sum(_WEIGHTS[c.severity] for c in self.checks if c.passed)
        return round(10_000 * earned / total)

    def to_document(self, *, dataset_id: int, version: int, content_hash: str, merkle_root: str) -> dict:
        return {
            "kind": "quality_report",
            "dataset_id": dataset_id,
            "version": version,
            "content_hash": content_hash,
            "merkle_root": merkle_root,
            "record_count": self.record_count,
            "generated_at": int(time.time()),
            "score_bps": self.score_bps,
            "passed": self.passed,
            "checks": [c.to_dict() for c in self.checks],
        }


def _result(name: str, severity: str, rows: list[int], column: str | None = None, detail: str = ""):
    return CheckResult(
        name=name,
        severity=severity,
        passed=not rows,
        failures=len(rows),
        column=column,
        examples=rows[:MAX_EXAMPLES],
        detail=detail,
    )


def run_checks(parsed: ParsedDataset) -> QualityReport:
    schema = parsed.schema
    checks: list[CheckResult] = [
        CheckResult(
            name="not_empty",
            severity=CRITICAL,
            passed=parsed.record_count > 0,
            failures=0 if parsed.record_count else 1,
            detail=f"{parsed.record_count} records",
        )
    ]

    for column in schema.columns:
        if column.required:
            missing = [i for i, row in enumerate(parsed.rows) if (row.get(column.name) or "").strip() == ""]
            checks.append(_result("required_value", CRITICAL, missing, column.name))
        if column.type != "string":
            bad = sorted({i for i, col in parsed.parse_errors if col == column.name})
            checks.append(_result("type_conformance", CRITICAL, bad, column.name, f"expected {column.type}"))

    if schema.primary_key:
        keys = [tuple(row.get(k, "") for k in schema.primary_key) for row in parsed.rows]
        counts = Counter(keys)
        duplicate_rows = [i for i, key in enumerate(keys) if counts[key] > 1]
        checks.append(_result("primary_key_unique", CRITICAL, duplicate_rows, ",".join(schema.primary_key)))

    seen: dict[bytes, int] = {}
    repeated: list[int] = []
    for i, record in enumerate(parsed.records):
        if record in seen:
            repeated.append(i)
        else:
            seen[record] = i
    checks.append(_result("no_duplicate_records", WARNING, repeated))

    return QualityReport(checks=checks, record_count=parsed.record_count)
