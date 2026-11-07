"""Event indexer: replays ledger events into SQL read models and a unified audit trail.

Logs are read in block ranges, applied in (block, log index) order and committed together with the cursor,
so a crash never leaves half a block applied. If the block under the cursor changes hash (a re-org), the
indexed tables are dropped and rebuilt from the deployment block.
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Callable
from typing import Any

from eth_utils import event_abi_to_log_topic
from sqlalchemy import Connection, Engine, delete, select, update
from web3.datastructures import AttributeDict
from web3.exceptions import BlockNotFound

from . import db
from .chain import Chain, Classification, VersionStatus
from .storage import parse_object_uri

log = logging.getLogger(__name__)

REQUEST_STATUS = {1: "pending", 2: "approved", 3: "rejected", 4: "cancelled"}


def _jsonable(value: Any) -> Any:
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (dict, AttributeDict)):
        return {k: _jsonable(v) for k, v in value.items()}
    return value


def _short(value: str) -> str:
    return f"{value[:6]}…{value[-4:]}" if isinstance(value, str) and len(value) > 12 else str(value)


class Indexer:
    def __init__(self, chain: Chain, engine: Engine, *, confirmations: int = 0, batch_blocks: int = 2_000):
        self.chain = chain
        self.engine = engine
        self.confirmations = confirmations
        self.batch_blocks = batch_blocks
        self._topics: dict[bytes, tuple[str, Any]] = {}
        for label, contract in chain.contracts.items():
            for item in contract.abi:
                if item.get("type") == "event":
                    self._topics[event_abi_to_log_topic(item)] = (
                        label,
                        getattr(contract.events, item["name"]),
                    )
        self._block_times: dict[int, int] = {}
        self._handlers: dict[str, Callable[[Connection, dict, dict], None]] = {
            "DatasetRegistered": self._on_dataset_registered,
            "VersionCommitted": self._on_version_committed,
            "LineageLinked": self._on_lineage_linked,
            "SchemaChanged": self._on_schema_changed,
            "VersionStatusChanged": self._on_version_status_changed,
            "StewardUpdated": self._on_steward_updated,
            "MetadataUpdated": self._on_metadata_updated,
            "ClassificationChanged": self._on_classification_changed,
            "DatasetArchived": self._on_dataset_archived,
            "OwnershipTransferStarted": self._on_ownership_started,
            "OwnershipTransferred": self._on_ownership_transferred,
            "AccessRequested": self._on_access_requested,
            "AccessRequestApproved": self._on_request_decided,
            "AccessRequestRejected": self._on_request_decided,
            "AccessRequestCancelled": self._on_request_decided,
            "AccessGranted": self._on_access_granted,
            "AccessRevoked": self._on_access_revoked,
            "DataAccessed": self._on_data_accessed,
            "QualityAttested": self._on_quality_attested,
        }

    # ------------------------------------------------------------------ cursor

    def _state(self, conn: Connection, key: str) -> str | None:
        return conn.execute(select(db.indexer_state.c.value).where(db.indexer_state.c.key == key)).scalar()

    def _set_state(self, conn: Connection, key: str, value: str) -> None:
        stmt = db.dialect_insert(conn, db.indexer_state).values(key=key, value=value)
        conn.execute(stmt.on_conflict_do_update(index_elements=["key"], set_={"value": value}))

    def cursor(self) -> int:
        with self.engine.connect() as conn:
            value = self._state(conn, "cursor_block")
        return int(value) if value is not None else self.chain.deployment.start_block - 1

    def reset(self) -> None:
        with self.engine.begin() as conn:
            for table in db.INDEXED_TABLES:
                conn.execute(delete(table))
            conn.execute(delete(db.audit_events).where(db.audit_events.c.source == "chain"))
            conn.execute(delete(db.indexer_state))
            conn.execute(
                update(db.objects)
                .where(db.objects.c.state.in_(["anchored", "mismatch"]))
                .values(state="staged", anchored_version=None)
            )
        self._block_times.clear()
        log.warning("indexer state reset; rebuilding from block %s", self.chain.deployment.start_block)

    def _reorged(self) -> bool:
        with self.engine.connect() as conn:
            block = self._state(conn, "cursor_block")
            stored_hash = self._state(conn, "cursor_hash")
        if block is None or stored_hash is None:
            return False
        try:
            current = self.chain.w3.eth.get_block(int(block))
        except BlockNotFound:
            return True
        return "0x" + bytes(current["hash"]).hex() != stored_hash

    # ------------------------------------------------------------------ sync

    def sync_once(self) -> int:
        """Applies the next batch of logs. Returns the number of logs applied."""
        if self._reorged():
            self.reset()
        head = self.chain.block_number - self.confirmations
        start = self.cursor() + 1
        if start > head:
            return 0
        end = min(head, start + self.batch_blocks - 1)
        logs = self.chain.w3.eth.get_logs(
            {
                "fromBlock": start,
                "toBlock": end,
                "address": [
                    self.chain.deployment.data_registry,
                    self.chain.deployment.access_ledger,
                    self.chain.deployment.quality_ledger,
                ],
            }
        )
        logs = sorted(logs, key=lambda entry: (entry["blockNumber"], entry["logIndex"]))
        end_hash = "0x" + bytes(self.chain.w3.eth.get_block(end)["hash"]).hex()
        with self.engine.begin() as conn:
            for entry in logs:
                self._apply(conn, entry)
            self._set_state(conn, "cursor_block", str(end))
            self._set_state(conn, "cursor_hash", end_hash)
        return len(logs)

    def sync(self) -> int:
        """Catches up to the chain head."""
        total = 0
        while True:
            applied = self.sync_once()
            total += applied
            if self.cursor() >= self.chain.block_number - self.confirmations:
                return total

    def run_forever(self, stop: threading.Event, poll_seconds: float = 1.0) -> None:
        backoff = poll_seconds
        while not stop.is_set():
            try:
                self.sync()
                backoff = poll_seconds
            except Exception:
                log.exception("indexer sync failed; retrying in %.1fs", backoff)
                backoff = min(backoff * 2, 30)
            stop.wait(backoff)

    def lag(self) -> int:
        return max(0, self.chain.block_number - self.cursor())

    # ------------------------------------------------------------------ dispatch

    def _block_time(self, number: int) -> int:
        if number not in self._block_times:
            self._block_times[number] = int(self.chain.w3.eth.get_block(number)["timestamp"])
        return self._block_times[number]

    def _apply(self, conn: Connection, entry: Any) -> None:
        topic = bytes(entry["topics"][0]) if entry["topics"] else b""
        match = self._topics.get(topic)
        if match is None:
            return
        contract, event = match
        decoded = event().process_log(entry)
        name = decoded["event"]
        args = dict(decoded["args"])
        meta = {
            "contract": contract,
            "event": name,
            "block_number": int(entry["blockNumber"]),
            "tx_hash": "0x" + bytes(entry["transactionHash"]).hex(),
            "log_index": int(entry["logIndex"]),
            "ts": self._block_time(int(entry["blockNumber"])),
        }
        handler = self._handlers.get(name)
        if handler:
            handler(conn, args, meta)
        else:
            self._audit(conn, meta, args, summary=self._generic_summary(name, args))

    def _audit(
        self,
        conn: Connection,
        meta: dict,
        args: dict,
        *,
        summary: str,
        dataset_id: int | None = None,
        version: int | None = None,
        actor: str | None = None,
    ) -> None:
        stmt = db.dialect_insert(conn, db.audit_events).values(
            source="chain",
            contract=meta["contract"],
            event=meta["event"],
            dataset_id=dataset_id,
            version=version,
            actor=actor,
            summary=summary,
            details=json.dumps(_jsonable(args), sort_keys=True),
            occurred_at=meta["ts"],
            block_number=meta["block_number"],
            tx_hash=meta["tx_hash"],
            log_index=meta["log_index"],
        )
        conn.execute(stmt.on_conflict_do_nothing())

    @staticmethod
    def _generic_summary(name: str, args: dict) -> str:
        if name in ("RoleGranted", "RoleRevoked"):
            verb = "granted to" if name == "RoleGranted" else "revoked from"
            return f"Role {_jsonable(args['role'])[:10]}… {verb} {_short(args['account'])}"
        if name in ("Paused", "Unpaused"):
            return f"Registry {name.lower()} by {_short(args.get('account', ''))}"
        return name

    def _dataset_name(self, conn: Connection, dataset_id: int) -> str:
        name = conn.execute(select(db.datasets.c.name).where(db.datasets.c.dataset_id == dataset_id)).scalar()
        return name or f"dataset {dataset_id}"

    # ------------------------------------------------------------------ registry handlers

    def _on_dataset_registered(self, conn: Connection, a: dict, m: dict) -> None:
        dataset_id = int(a["datasetId"])
        conn.execute(
            db.dialect_insert(conn, db.datasets)
            .values(
                dataset_id=dataset_id,
                name=a["name"],
                owner=a["owner"],
                classification=int(a["classification"]),
                schema_hash=_jsonable(a["schemaHash"]),
                metadata_uri=a["metadataURI"],
                archived=False,
                version_count=0,
                access_count=0,
                created_at=m["ts"],
                created_block=m["block_number"],
            )
            .on_conflict_do_nothing()
        )
        label = Classification(int(a["classification"])).label
        self._audit(conn, m, a, summary=f"Registered '{a['name']}' ({label})", dataset_id=dataset_id, actor=a["owner"])

    def _on_version_committed(self, conn: Connection, a: dict, m: dict) -> None:
        dataset_id, version = int(a["datasetId"]), int(a["version"])
        schema_hash = conn.execute(
            select(db.datasets.c.schema_hash).where(db.datasets.c.dataset_id == dataset_id)
        ).scalar()
        merkle_root = _jsonable(a["merkleRoot"])
        content_hash = _jsonable(a["contentHash"])
        conn.execute(
            db.dialect_insert(conn, db.versions)
            .values(
                dataset_id=dataset_id,
                version=version,
                merkle_root=merkle_root,
                content_hash=content_hash,
                schema_hash=schema_hash,
                record_count=int(a["recordCount"]),
                storage_uri=a["storageURI"],
                committer=a["committer"],
                status=int(VersionStatus.ACTIVE),
                committed_at=m["ts"],
                block_number=m["block_number"],
                tx_hash=m["tx_hash"],
            )
            .on_conflict_do_nothing()
        )
        conn.execute(update(db.datasets).where(db.datasets.c.dataset_id == dataset_id).values(version_count=version))
        self._link_object(conn, dataset_id, version, a, merkle_root, content_hash, schema_hash)
        self._audit(
            conn,
            m,
            a,
            summary=(
                f"v{version} of '{self._dataset_name(conn, dataset_id)}' anchored: "
                f"{int(a['recordCount']):,} records, root {merkle_root[:10]}…"
            ),
            dataset_id=dataset_id,
            version=version,
            actor=a["committer"],
        )

    def _link_object(self, conn, dataset_id, version, a, merkle_root, content_hash, schema_hash) -> None:
        try:
            object_id = parse_object_uri(a["storageURI"])
        except ValueError:
            return
        row = conn.execute(select(db.objects).where(db.objects.c.object_id == object_id)).mappings().first()
        if row is None or row["state"] == "shredded":
            return
        matches = (
            row["dataset_id"] == dataset_id
            and row["merkle_root"] == merkle_root
            and row["content_hash"] == content_hash
            and row["record_count"] == int(a["recordCount"])
            and (schema_hash is None or row["schema_hash"] == schema_hash)
        )
        conn.execute(
            update(db.objects)
            .where(db.objects.c.object_id == object_id)
            .values(state="anchored" if matches else "mismatch", anchored_version=version)
        )

    def _on_lineage_linked(self, conn: Connection, a: dict, m: dict) -> None:
        dataset_id, version = int(a["datasetId"]), int(a["version"])
        parent_id, parent_version = int(a["parentDatasetId"]), int(a["parentVersion"])
        conn.execute(
            db.dialect_insert(conn, db.lineage)
            .values(
                dataset_id=dataset_id,
                version=version,
                parent_dataset_id=parent_id,
                parent_version=parent_version,
            )
            .on_conflict_do_nothing()
        )
        self._audit(
            conn,
            m,
            a,
            summary=(
                f"'{self._dataset_name(conn, dataset_id)}' v{version} derived from "
                f"'{self._dataset_name(conn, parent_id)}' v{parent_version}"
            ),
            dataset_id=dataset_id,
            version=version,
        )

    def _on_schema_changed(self, conn: Connection, a: dict, m: dict) -> None:
        dataset_id = int(a["datasetId"])
        new_schema = _jsonable(a["newSchema"])
        conn.execute(update(db.datasets).where(db.datasets.c.dataset_id == dataset_id).values(schema_hash=new_schema))
        self._audit(
            conn,
            m,
            a,
            summary=f"Schema of '{self._dataset_name(conn, dataset_id)}' changed to {new_schema[:10]}…",
            dataset_id=dataset_id,
            version=int(a["version"]),
        )

    def _on_version_status_changed(self, conn: Connection, a: dict, m: dict) -> None:
        dataset_id, version = int(a["datasetId"]), int(a["version"])
        current = VersionStatus(int(a["current"]))
        conn.execute(
            update(db.versions)
            .where((db.versions.c.dataset_id == dataset_id) & (db.versions.c.version == version))
            .values(status=int(current), status_reason=a["reason"])
        )
        reason = f": {a['reason']}" if a["reason"] else ""
        self._audit(
            conn,
            m,
            a,
            summary=f"'{self._dataset_name(conn, dataset_id)}' v{version} marked {current.label}{reason}",
            dataset_id=dataset_id,
            version=version,
        )

    def _on_steward_updated(self, conn: Connection, a: dict, m: dict) -> None:
        dataset_id = int(a["datasetId"])
        stmt = db.dialect_insert(conn, db.stewards).values(
            dataset_id=dataset_id, account=a["account"], enabled=a["enabled"]
        )
        conn.execute(
            stmt.on_conflict_do_update(index_elements=["dataset_id", "account"], set_={"enabled": a["enabled"]})
        )
        verb = "added as" if a["enabled"] else "removed as"
        self._audit(
            conn,
            m,
            a,
            summary=f"{_short(a['account'])} {verb} steward of '{self._dataset_name(conn, dataset_id)}'",
            dataset_id=dataset_id,
            actor=a["account"],
        )

    def _on_metadata_updated(self, conn: Connection, a: dict, m: dict) -> None:
        dataset_id = int(a["datasetId"])
        conn.execute(
            update(db.datasets).where(db.datasets.c.dataset_id == dataset_id).values(metadata_uri=a["metadataURI"])
        )
        self._audit(
            conn,
            m,
            a,
            summary=f"Metadata of '{self._dataset_name(conn, dataset_id)}' updated",
            dataset_id=dataset_id,
        )

    def _on_classification_changed(self, conn: Connection, a: dict, m: dict) -> None:
        dataset_id = int(a["datasetId"])
        current = Classification(int(a["current"]))
        conn.execute(
            update(db.datasets).where(db.datasets.c.dataset_id == dataset_id).values(classification=int(current))
        )
        self._audit(
            conn,
            m,
            a,
            summary=f"'{self._dataset_name(conn, dataset_id)}' reclassified as {current.label}",
            dataset_id=dataset_id,
        )

    def _on_dataset_archived(self, conn: Connection, a: dict, m: dict) -> None:
        dataset_id = int(a["datasetId"])
        conn.execute(update(db.datasets).where(db.datasets.c.dataset_id == dataset_id).values(archived=True))
        self._audit(conn, m, a, summary=f"'{self._dataset_name(conn, dataset_id)}' archived", dataset_id=dataset_id)

    def _on_ownership_started(self, conn: Connection, a: dict, m: dict) -> None:
        dataset_id = int(a["datasetId"])
        conn.execute(
            update(db.datasets).where(db.datasets.c.dataset_id == dataset_id).values(pending_owner=a["newOwner"])
        )
        self._audit(
            conn,
            m,
            a,
            summary=f"Ownership of '{self._dataset_name(conn, dataset_id)}' offered to {_short(a['newOwner'])}",
            dataset_id=dataset_id,
            actor=a["currentOwner"],
        )

    def _on_ownership_transferred(self, conn: Connection, a: dict, m: dict) -> None:
        dataset_id = int(a["datasetId"])
        conn.execute(
            update(db.datasets)
            .where(db.datasets.c.dataset_id == dataset_id)
            .values(owner=a["newOwner"], pending_owner=None)
        )
        self._audit(
            conn,
            m,
            a,
            summary=f"'{self._dataset_name(conn, dataset_id)}' now owned by {_short(a['newOwner'])}",
            dataset_id=dataset_id,
            actor=a["newOwner"],
        )

    # ------------------------------------------------------------------ access handlers

    def _on_access_requested(self, conn: Connection, a: dict, m: dict) -> None:
        dataset_id = int(a["datasetId"])
        conn.execute(
            db.dialect_insert(conn, db.access_requests)
            .values(
                request_id=int(a["requestId"]),
                dataset_id=dataset_id,
                requester=a["requester"],
                purpose=a["purpose"],
                purpose_hash=_jsonable(a["purposeHash"]),
                status="pending",
                requested_at=m["ts"],
            )
            .on_conflict_do_nothing()
        )
        self._audit(
            conn,
            m,
            a,
            summary=(
                f"{_short(a['requester'])} requested access to '{self._dataset_name(conn, dataset_id)}': {a['purpose']}"
            ),
            dataset_id=dataset_id,
            actor=a["requester"],
        )

    def _on_request_decided(self, conn: Connection, a: dict, m: dict) -> None:
        request_id = int(a["requestId"])
        status = {
            "AccessRequestApproved": "approved",
            "AccessRequestRejected": "rejected",
            "AccessRequestCancelled": "cancelled",
        }[m["event"]]
        req = (
            conn.execute(select(db.access_requests).where(db.access_requests.c.request_id == request_id))
            .mappings()
            .first()
        )
        conn.execute(
            update(db.access_requests)
            .where(db.access_requests.c.request_id == request_id)
            .values(
                status=status,
                decided_by=a.get("approver") or (req["requester"] if req else None),
                decided_at=m["ts"],
                reason=a.get("reason"),
            )
        )
        dataset_id = req["dataset_id"] if req else None
        who = _short(req["requester"]) if req else f"request {request_id}"
        reason = f": {a['reason']}" if a.get("reason") else ""
        name = self._dataset_name(conn, dataset_id) if dataset_id else "?"
        self._audit(
            conn,
            m,
            a,
            summary=f"Access request #{request_id} from {who} to '{name}' {status}{reason}",
            dataset_id=dataset_id,
            actor=a.get("approver") or (req["requester"] if req else None),
        )

    def _purpose_text(self, conn: Connection, dataset_id: int, grantee: str, purpose_hash: str, tx_hash: str):
        text = conn.execute(
            select(db.access_requests.c.purpose)
            .where(
                (db.access_requests.c.dataset_id == dataset_id)
                & (db.access_requests.c.requester == grantee)
                & (db.access_requests.c.purpose_hash == purpose_hash)
            )
            .order_by(db.access_requests.c.request_id.desc())
        ).scalar()
        if text:
            return text
        try:
            tx = self.chain.w3.eth.get_transaction(tx_hash)
            fn, params = self.chain.access.decode_function_input(tx["input"])
            if fn.fn_name == "grantAccess":
                return params["purpose"]
        except Exception:  # noqa: S110 - purpose text is a convenience; the hash is authoritative
            pass
        return None

    def _on_access_granted(self, conn: Connection, a: dict, m: dict) -> None:
        dataset_id = int(a["datasetId"])
        purpose_hash = _jsonable(a["purposeHash"])
        purpose = self._purpose_text(conn, dataset_id, a["grantee"], purpose_hash, m["tx_hash"])
        values = {
            "granted_by": a["grantedBy"],
            "purpose_hash": purpose_hash,
            "purpose": purpose,
            "granted_at": m["ts"],
            "expires_at": int(a["expiresAt"]),
            "revoked": False,
        }
        stmt = db.dialect_insert(conn, db.grants).values(dataset_id=dataset_id, grantee=a["grantee"], **values)
        conn.execute(stmt.on_conflict_do_update(index_elements=["dataset_id", "grantee"], set_=values))
        days = max(1, round((int(a["expiresAt"]) - m["ts"]) / 86_400))
        self._audit(
            conn,
            m,
            a,
            summary=(
                f"{_short(a['grantee'])} granted access to '{self._dataset_name(conn, dataset_id)}' "
                f"for {days} days" + (f" ({purpose})" if purpose else "")
            ),
            dataset_id=dataset_id,
            actor=a["grantedBy"],
        )

    def _on_access_revoked(self, conn: Connection, a: dict, m: dict) -> None:
        dataset_id = int(a["datasetId"])
        conn.execute(
            update(db.grants)
            .where((db.grants.c.dataset_id == dataset_id) & (db.grants.c.grantee == a["grantee"]))
            .values(revoked=True)
        )
        self._audit(
            conn,
            m,
            a,
            summary=f"Access of {_short(a['grantee'])} to '{self._dataset_name(conn, dataset_id)}' revoked",
            dataset_id=dataset_id,
            actor=a["revokedBy"],
        )

    def _on_data_accessed(self, conn: Connection, a: dict, m: dict) -> None:
        dataset_id, version = int(a["datasetId"]), int(a["version"])
        conn.execute(
            db.access_log.insert().values(
                dataset_id=dataset_id,
                version=version,
                accessor=a["accessor"],
                receipt_hash=_jsonable(a["receiptHash"]),
                accessed_at=m["ts"],
                block_number=m["block_number"],
                tx_hash=m["tx_hash"],
            )
        )
        conn.execute(
            update(db.datasets)
            .where(db.datasets.c.dataset_id == dataset_id)
            .values(access_count=db.datasets.c.access_count + 1)
        )
        self._audit(
            conn,
            m,
            a,
            summary=f"'{self._dataset_name(conn, dataset_id)}' v{version} read by {_short(a['accessor'])}",
            dataset_id=dataset_id,
            version=version,
            actor=a["accessor"],
        )

    # ------------------------------------------------------------------ quality handler

    def _on_quality_attested(self, conn: Connection, a: dict, m: dict) -> None:
        dataset_id, version = int(a["datasetId"]), int(a["version"])
        conn.execute(
            db.dialect_insert(conn, db.attestations)
            .values(
                dataset_id=dataset_id,
                version=version,
                auditor=a["auditor"],
                score_bps=int(a["scoreBps"]),
                passed=bool(a["passed"]),
                report_hash=_jsonable(a["reportHash"]),
                report_uri=a["reportURI"],
                attested_at=m["ts"],
                tx_hash=m["tx_hash"],
            )
            .on_conflict_do_nothing()
        )
        verdict = "passed" if a["passed"] else "failed"
        self._audit(
            conn,
            m,
            a,
            summary=(
                f"Quality of '{self._dataset_name(conn, dataset_id)}' v{version} {verdict} "
                f"({int(a['scoreBps']) / 100:.1f}%)"
            ),
            dataset_id=dataset_id,
            version=version,
            actor=a["auditor"],
        )
