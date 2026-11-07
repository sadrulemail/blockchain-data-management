"""Multi-step flows shared by the CLI and scripts: each pairs an API call with the matching chain transaction."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from eth_account.signers.local import LocalAccount

from .canonical import Schema, parse_csv
from .chain import Chain, Classification
from .client import ApiClient
from .quality import run_checks


@dataclass
class Published:
    dataset_id: int
    version: int
    staged: dict[str, Any]


def register_dataset(
    chain: Chain, api: ApiClient, owner: LocalAccount, schema: Schema, classification: Classification
) -> int:
    """Publishes the schema document, then registers the dataset on-chain pointing at it."""
    doc = api.as_account(owner).put_document("metadata", schema.to_dict())
    return chain.register_dataset(owner, schema.name, classification, schema.schema_hash(), doc["uri"])


def publish_version(
    chain: Chain,
    api: ApiClient,
    publisher: LocalAccount,
    dataset_id: int,
    data: bytes,
    file_name: str,
    parents: Sequence[tuple[int, int]] = (),
) -> Published:
    """Uploads the file (encrypted at rest by the gateway), then anchors its fingerprints on-chain."""
    staged = api.as_account(publisher).upload(dataset_id, data, file_name)
    version = chain.commit_version(
        publisher,
        dataset_id,
        merkle_root=staged["merkle_root"],
        content_hash=staged["content_hash"],
        schema_hash=staged["schema_hash"],
        record_count=staged["record_count"],
        storage_uri=staged["storage_uri"],
        parents=parents,
    )
    return Published(dataset_id, version, staged)


def audit_quality(chain: Chain, api: ApiClient, auditor: LocalAccount, dataset_id: int, version: int) -> dict[str, Any]:
    """Reads the version through the gateway, runs the checks locally, publishes the report and attests it."""
    client = api.as_account(auditor)
    data, headers = client.download(dataset_id, version)
    info = chain.get_version(dataset_id, version)
    schema_doc = headers.get("x-dl-schema-document")
    if schema_doc:
        schema = Schema.from_dict(client.document(schema_doc)["body"])
    else:
        schema = Schema.from_dict(client.dataset(dataset_id)["schema"])
    report = run_checks(parse_csv(data, schema))
    document = report.to_document(
        dataset_id=dataset_id,
        version=version,
        content_hash=info["content_hash"],
        merkle_root=info["merkle_root"],
    )
    stored = client.put_document("quality_report", document)
    chain.attest(
        auditor,
        dataset_id,
        version,
        score_bps=report.score_bps,
        passed=report.passed,
        report_hash=stored["hash"],
        report_uri=stored["uri"],
    )
    return {**document, "report_uri": stored["uri"], "report_hash": stored["hash"]}
