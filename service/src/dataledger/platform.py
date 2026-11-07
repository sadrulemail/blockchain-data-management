"""Service operations behind the API: documents, ingestion, gated reads, proofs, verification and erasure."""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Any

from eth_account import Account
from eth_account.signers.local import LocalAccount
from eth_utils import keccak, to_checksum_address
from sqlalchemy import Engine, select, update

from . import db
from .canonical import ParsedDataset, Schema, canonical_json, parse_csv, record_leaf
from .chain import Chain, ChainError, VersionStatus
from .config import Settings
from .crypto import DecryptionError, KeyRing, WrappedKey, decrypt_object, encrypt_object
from .indexer import Indexer
from .merkle import MerkleTree, diff_leaves
from .storage import (
    LocalObjectStore,
    ObjectNotFound,
    ObjectStore,
    StorageIntegrityError,
    object_uri,
    parse_object_uri,
)

log = logging.getLogger(__name__)

DOCUMENT_PREFIX = "dl://documents/"
DOCUMENT_KINDS = ("metadata", "quality_report")
MAX_DOCUMENT_BYTES = 256 * 1024


class NotFound(Exception):
    pass


class Forbidden(Exception):
    pass


class Gone(Exception):
    """The data was withdrawn or crypto-shredded."""


class IntegrityFailure(Exception):
    """Stored data no longer matches what is anchored on-chain."""


class InvalidInput(Exception):
    pass


def sha256_hex(data: bytes) -> str:
    return "0x" + hashlib.sha256(data).hexdigest()


def document_uri(doc_hash: str) -> str:
    return DOCUMENT_PREFIX + doc_hash


def parse_document_uri(uri: str) -> str:
    if not uri.startswith(DOCUMENT_PREFIX):
        raise InvalidInput(f"not a document URI: {uri!r}")
    return uri[len(DOCUMENT_PREFIX) :]


@dataclass
class VersionData:
    version: dict[str, Any]
    plaintext: bytes
    parsed: ParsedDataset
    tree: MerkleTree
    object_row: dict[str, Any]


class Platform:
    def __init__(
        self,
        settings: Settings,
        chain: Chain,
        engine: Engine,
        store: ObjectStore,
        ring: KeyRing,
        gateway: LocalAccount | None,
    ) -> None:
        self.settings = settings
        self.chain = chain
        self.engine = engine
        self.store = store
        self.ring = ring
        self.gateway = gateway
        self.indexer = Indexer(
            chain,
            engine,
            confirmations=settings.indexer_confirmations,
            batch_blocks=settings.indexer_batch_blocks,
        )

    @classmethod
    def from_settings(cls, settings: Settings) -> Platform:
        from .chain import Deployment

        deployment = Deployment.load(settings.deployment_file)
        chain = Chain(settings.rpc_url, deployment)
        engine = db.make_engine(settings.database_url)
        db.init_db(engine)
        ring = KeyRing.parse(settings.master_keys.get_secret_value())
        gateway = (
            Account.from_key(settings.gateway_private_key.get_secret_value()) if settings.gateway_private_key else None
        )
        return cls(settings, chain, engine, LocalObjectStore(settings.object_store_dir), ring, gateway)

    # ------------------------------------------------------------------ gateway audit

    def _audit(self, event: str, summary: str, *, dataset_id=None, version=None, actor=None, **details) -> None:
        with self.engine.begin() as conn:
            conn.execute(
                db.audit_events.insert().values(
                    source="gateway",
                    contract=None,
                    event=event,
                    dataset_id=dataset_id,
                    version=version,
                    actor=actor,
                    summary=summary,
                    details=json.dumps(details, sort_keys=True, default=str),
                    occurred_at=int(time.time()),
                )
            )

    # ------------------------------------------------------------------ documents

    def put_document(self, kind: str, body: dict[str, Any], created_by: str) -> dict[str, str]:
        if kind not in DOCUMENT_KINDS:
            raise InvalidInput(f"kind must be one of {DOCUMENT_KINDS}")
        raw = canonical_json(body)
        if len(raw) > MAX_DOCUMENT_BYTES:
            raise InvalidInput("document too large")
        if kind == "metadata":
            Schema.from_dict(body)  # validates
        doc_hash = "0x" + keccak(raw).hex()
        with self.engine.begin() as conn:
            conn.execute(
                db.dialect_insert(conn, db.documents)
                .values(
                    doc_hash=doc_hash,
                    kind=kind,
                    body=raw.decode("utf-8"),
                    created_by=to_checksum_address(created_by),
                    created_at=int(time.time()),
                )
                .on_conflict_do_nothing()
            )
        return {"hash": doc_hash, "uri": document_uri(doc_hash)}

    def get_document(self, doc_hash: str) -> dict[str, Any]:
        with self.engine.connect() as conn:
            row = conn.execute(select(db.documents).where(db.documents.c.doc_hash == doc_hash.lower())).first()
        if row is None:
            raise NotFound(f"document {doc_hash} not found")
        return {
            "hash": row.doc_hash,
            "kind": row.kind,
            "body": json.loads(row.body),
            "created_at": row.created_at,
        }

    def _schema_from_uri(self, metadata_uri: str) -> tuple[Schema, str]:
        doc_hash = parse_document_uri(metadata_uri)
        doc = self.get_document(doc_hash)
        return Schema.from_dict(doc["body"]), doc_hash

    # ------------------------------------------------------------------ ingestion

    def ingest(self, dataset_id: int, data: bytes, file_name: str, uploader: str) -> dict[str, Any]:
        """Validates a file against the dataset schema, seals and stores it, and returns the values to anchor."""
        if not self.chain.exists(dataset_id):
            raise NotFound(f"dataset {dataset_id} not found")
        if not self.chain.can_manage(dataset_id, uploader):
            raise Forbidden("only the dataset owner or a steward can upload versions")
        dataset = self.chain.get_dataset(dataset_id)
        if dataset["archived"]:
            raise InvalidInput("dataset is archived")
        schema, schema_doc = self._schema_from_uri(dataset["metadata_uri"])
        parsed = parse_csv(data, schema)
        if parsed.record_count == 0:
            raise InvalidInput("file has no records")

        tree = MerkleTree([record_leaf(i, r) for i, r in enumerate(parsed.records)])
        content_hash = sha256_hex(data)
        sealed, wrapped = encrypt_object(data, self.ring, aad=bytes.fromhex(content_hash[2:]))
        object_id = self.store.put(sealed)
        result = {
            "object_id": object_id,
            "storage_uri": object_uri(object_id),
            "content_hash": content_hash,
            "merkle_root": "0x" + tree.root.hex(),
            "schema_hash": "0x" + schema.schema_hash().hex(),
            "schema_document": schema_doc,
            "record_count": parsed.record_count,
            "size_bytes": len(data),
            "parse_errors": len(parsed.parse_errors),
        }
        with self.engine.begin() as conn:
            conn.execute(
                db.objects.insert().values(
                    object_id=object_id,
                    dataset_id=dataset_id,
                    content_hash=content_hash,
                    merkle_root=result["merkle_root"],
                    schema_hash=result["schema_hash"],
                    schema_document=schema_doc,
                    record_count=parsed.record_count,
                    size_bytes=len(data),
                    file_name=file_name[:255],
                    kek_id=wrapped.kek_id,
                    wrapped_key=wrapped.blob,
                    uploaded_by=to_checksum_address(uploader),
                    uploaded_at=int(time.time()),
                    state="staged",
                )
            )
        self._audit(
            "ObjectStaged",
            f"Encrypted upload staged for '{dataset['name']}' ({parsed.record_count:,} records)",
            dataset_id=dataset_id,
            actor=to_checksum_address(uploader),
            object_id=object_id,
            schema_document=schema_doc,
        )
        return result

    # ------------------------------------------------------------------ reads

    def _object_row(self, object_id: str) -> dict[str, Any]:
        with self.engine.connect() as conn:
            row = conn.execute(select(db.objects).where(db.objects.c.object_id == object_id)).mappings().first()
        if row is None:
            raise NotFound("stored object for this version is not held by this gateway")
        return dict(row)

    def _schema_for_object(self, row: dict[str, Any]) -> Schema:
        return Schema.from_dict(self.get_document(row["schema_document"])["body"])

    def require_access(self, dataset_id: int, account: str) -> None:
        if not self.chain.exists(dataset_id):
            raise NotFound(f"dataset {dataset_id} not found")
        if not self.chain.has_access(dataset_id, account):
            raise Forbidden("no active access grant for this dataset")

    def load_version(self, dataset_id: int, version: int) -> VersionData:
        try:
            info = self.chain.get_version(dataset_id, version)
        except ChainError as exc:
            raise NotFound(str(exc)) from exc
        if info["status"] == VersionStatus.WITHDRAWN:
            raise Gone("version was withdrawn by its owner")
        row = self._object_row(parse_object_uri(info["storage_uri"]))
        if row["state"] == "shredded" or row["wrapped_key"] is None:
            raise Gone("data key was destroyed (crypto-shredded); the content cannot be recovered")
        try:
            sealed = self.store.get(row["object_id"])
            plaintext = decrypt_object(
                sealed,
                WrappedKey(row["kek_id"], row["wrapped_key"]),
                self.ring,
                aad=bytes.fromhex(row["content_hash"][2:]),
            )
        except ObjectNotFound as exc:
            raise IntegrityFailure("sealed object is missing from storage") from exc
        except (StorageIntegrityError, DecryptionError) as exc:
            raise IntegrityFailure(str(exc)) from exc
        if sha256_hex(plaintext) != info["content_hash"]:
            raise IntegrityFailure("stored file does not match the on-chain fingerprint")
        parsed = parse_csv(plaintext, self._schema_for_object(row))
        tree = MerkleTree([record_leaf(i, r) for i, r in enumerate(parsed.records)])
        if "0x" + tree.root.hex() != info["merkle_root"]:
            raise IntegrityFailure("stored records do not match the on-chain Merkle root")
        return VersionData(info, plaintext, parsed, tree, row)

    def download(self, dataset_id: int, version: int, accessor: str) -> tuple[VersionData, str, str | None]:
        """Checks access on-chain, verifies the data, logs the read on-chain, then hands back the file."""
        self.require_access(dataset_id, accessor)
        data = self.load_version(dataset_id, version)
        receipt = (
            "0x" + keccak(f"{dataset_id}:{version}:{accessor}:{time.time_ns()}:{secrets.token_hex(8)}".encode()).hex()
        )
        tx_hash = None
        if self.gateway is not None:
            tx = self.chain.log_access(self.gateway, dataset_id, version, accessor, bytes.fromhex(receipt[2:]))
            tx_hash = "0x" + bytes(tx["transactionHash"]).hex()
        else:
            log.warning("no gateway key configured; read of %s v%s is not logged on-chain", dataset_id, version)
        return data, receipt, tx_hash

    def record_proof(self, dataset_id: int, version: int, index: int, accessor: str) -> dict[str, Any]:
        self.require_access(dataset_id, accessor)
        data = self.load_version(dataset_id, version)
        if not 0 <= index < data.parsed.record_count:
            raise NotFound(f"record {index} out of range")
        record = data.parsed.records[index]
        return {
            "dataset_id": dataset_id,
            "version": version,
            "index": index,
            "canonical": record.decode("utf-8"),
            "record": json.loads(record),
            "leaf": "0x" + record_leaf(index, record).hex(),
            "proof": ["0x" + p.hex() for p in data.tree.proof(index)],
            "merkle_root": data.version["merkle_root"],
        }

    def diff(self, dataset_id: int, version: int, candidate: bytes, accessor: str) -> dict[str, Any]:
        self.require_access(dataset_id, accessor)
        data = self.load_version(dataset_id, version)
        parsed = parse_csv(candidate, data.parsed.schema)
        result = diff_leaves(data.tree.leaves, [record_leaf(i, r) for i, r in enumerate(parsed.records)])
        return {
            "identical": result.identical,
            "changed_rows": result.changed[:500],
            "changed_count": len(result.changed),
            "added": result.added,
            "removed": result.removed,
        }

    # ------------------------------------------------------------------ public verification

    def verify_file(self, candidate: bytes, dataset_id: int | None, version: int | None) -> dict[str, Any]:
        content_hash = sha256_hex(candidate)
        located = self.chain.locate_content(content_hash)
        if located is not None:
            info = self.chain.get_version(*located)
            return {
                "result": "exact_match",
                "content_hash": content_hash,
                "dataset_id": located[0],
                "version": located[1],
                "status": info["status"].label,
                "record_count": info["record_count"],
                "merkle_root": info["merkle_root"],
            }
        if dataset_id is None or version is None:
            return {"result": "unknown", "content_hash": content_hash}

        try:
            info = self.chain.get_version(dataset_id, version)
        except ChainError as exc:
            raise NotFound(str(exc)) from exc
        try:
            schema = self._schema_for_object(self._object_row(parse_object_uri(info["storage_uri"])))
        except (NotFound, ValueError):
            schema, _ = self._schema_from_uri(self.chain.get_dataset(dataset_id)["metadata_uri"])
        parsed = parse_csv(candidate, schema)
        root = (
            "0x" + MerkleTree([record_leaf(i, r) for i, r in enumerate(parsed.records)]).root.hex()
            if parsed.records
            else None
        )
        same = root == info["merkle_root"] and parsed.record_count == info["record_count"]
        return {
            "result": "records_match" if same else "mismatch",
            "content_hash": content_hash,
            "anchored_content_hash": info["content_hash"],
            "dataset_id": dataset_id,
            "version": version,
            "status": info["status"].label,
            "merkle_root": root,
            "anchored_merkle_root": info["merkle_root"],
            "record_count": parsed.record_count,
            "anchored_record_count": info["record_count"],
        }

    def verify_record(
        self,
        dataset_id: int,
        version: int,
        index: int,
        canonical: str | None,
        record: dict[str, Any] | None,
        proof: list[str],
    ) -> dict[str, Any]:
        if canonical is None and record is None:
            raise InvalidInput("send either `canonical` or `record`")
        raw = canonical.encode("utf-8") if canonical is not None else canonical_json(record)
        try:
            valid = self.chain.verify_record(dataset_id, version, index, raw, proof)
            status = self.chain.version_status(dataset_id, version)
        except ChainError as exc:
            raise NotFound(str(exc)) from exc
        return {
            "valid": valid,
            "leaf": "0x" + record_leaf(index, raw).hex(),
            "status": status.label,
            "checked_on_chain": True,
        }

    # ------------------------------------------------------------------ erasure

    def shred(self, dataset_id: int, version: int, actor: str) -> dict[str, Any]:
        """Destroys the data key and ciphertext of a version. Hashes stay on-chain; content is unrecoverable."""
        if self.chain.dataset_owner(dataset_id) != to_checksum_address(actor):
            raise Forbidden("only the dataset owner can shred data")
        info = self.chain.get_version(dataset_id, version)
        row = self._object_row(parse_object_uri(info["storage_uri"]))
        if row["state"] == "shredded":
            raise Gone("already shredded")
        with self.engine.begin() as conn:
            conn.execute(
                update(db.objects)
                .where(db.objects.c.object_id == row["object_id"])
                .values(state="shredded", wrapped_key=None, kek_id=None, shredded_at=int(time.time()))
            )
        self.store.delete(row["object_id"])
        self._audit(
            "CryptoShredded",
            f"Data key and ciphertext of dataset {dataset_id} v{version} destroyed",
            dataset_id=dataset_id,
            version=version,
            actor=to_checksum_address(actor),
            object_id=row["object_id"],
        )
        return {
            "dataset_id": dataset_id,
            "version": version,
            "object_id": row["object_id"],
            "state": "shredded",
        }

    def rotate_keys(self) -> int:
        """Re-wraps every live data key under the active KEK. Returns how many keys moved."""
        moved = 0
        with self.engine.begin() as conn:
            rows = conn.execute(
                select(db.objects.c.object_id, db.objects.c.kek_id, db.objects.c.wrapped_key).where(
                    db.objects.c.wrapped_key.is_not(None) & (db.objects.c.kek_id != self.ring.active_id)
                )
            ).all()
            for row in rows:
                new = self.ring.rewrap(WrappedKey(row.kek_id, row.wrapped_key))
                conn.execute(
                    update(db.objects)
                    .where(db.objects.c.object_id == row.object_id)
                    .values(kek_id=new.kek_id, wrapped_key=new.blob)
                )
                moved += 1
        if moved:
            self._audit("KeysRotated", f"{moved} data keys re-wrapped under {self.ring.active_id}")
        return moved
