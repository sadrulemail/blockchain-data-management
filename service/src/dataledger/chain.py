"""Typed client for the three ledger contracts."""

from __future__ import annotations

import json
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from enum import IntEnum
from importlib import resources
from pathlib import Path
from typing import Any

from eth_abi import decode as abi_decode
from eth_account.signers.local import LocalAccount
from eth_utils import keccak, to_checksum_address
from web3 import Web3
from web3.contract.contract import ContractFunction
from web3.exceptions import ContractCustomError, ContractLogicError, ContractPanicError
from web3.logs import DISCARD
from web3.types import TxReceipt

CONTRACT_NAMES = ("DataRegistry", "AccessLedger", "QualityLedger")


class Classification(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def parse(cls, value: str | int) -> Classification:
        if isinstance(value, int) or str(value).isdigit():
            return cls(int(value))
        return cls[str(value).upper()]


class VersionStatus(IntEnum):
    NONE = 0
    ACTIVE = 1
    DEPRECATED = 2
    WITHDRAWN = 3

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def parse(cls, value: str | int) -> VersionStatus:
        if isinstance(value, int) or str(value).isdigit():
            return cls(int(value))
        return cls[str(value).upper()]


class ChainError(Exception):
    """A transaction or call reverted. ``error`` holds the custom error name when it could be decoded."""

    def __init__(self, message: str, error: str | None = None, args: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.error = error
        self.error_args = args or {}


def load_abi(name: str) -> list[dict[str, Any]]:
    return json.loads(resources.files("dataledger.abi").joinpath(f"{name}.json").read_text(encoding="utf-8"))


@dataclass(frozen=True)
class Deployment:
    chain_id: int
    data_registry: str
    access_ledger: str
    quality_ledger: str
    start_block: int

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Deployment:
        return cls(
            chain_id=int(data["chainId"]),
            data_registry=to_checksum_address(data["dataRegistry"]),
            access_ledger=to_checksum_address(data["accessLedger"]),
            quality_ledger=to_checksum_address(data["qualityLedger"]),
            start_block=int(data.get("startBlock", 0)),
        )

    @classmethod
    def load(cls, path: str | Path) -> Deployment:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"deployment file {p} not found; deploy the contracts first")
        return cls.from_dict(json.loads(p.read_text(encoding="utf-8")))

    def to_dict(self) -> dict[str, Any]:
        return {
            "chainId": self.chain_id,
            "dataRegistry": self.data_registry,
            "accessLedger": self.access_ledger,
            "qualityLedger": self.quality_ledger,
            "startBlock": self.start_block,
        }


def _hex(value: bytes) -> str:
    return "0x" + value.hex()


def _b32(value: bytes | str) -> bytes:
    if isinstance(value, str):
        value = bytes.fromhex(value.removeprefix("0x"))
    if len(value) != 32:
        raise ValueError("expected a 32-byte value")
    return value


class Chain:
    def __init__(self, rpc_url: str, deployment: Deployment, *, timeout: float = 30) -> None:
        self.w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": timeout}))
        self.deployment = deployment
        self.registry = self.w3.eth.contract(
            address=deployment.data_registry, abi=load_abi("DataRegistry"), decode_tuples=True
        )
        self.access = self.w3.eth.contract(
            address=deployment.access_ledger, abi=load_abi("AccessLedger"), decode_tuples=True
        )
        self.quality = self.w3.eth.contract(
            address=deployment.quality_ledger, abi=load_abi("QualityLedger"), decode_tuples=True
        )
        self._errors = self._error_table()
        self._tx_lock = threading.Lock()

    # ------------------------------------------------------------------ plumbing

    @property
    def contracts(self) -> dict[str, Any]:
        return {"DataRegistry": self.registry, "AccessLedger": self.access, "QualityLedger": self.quality}

    def _error_table(self) -> dict[bytes, tuple[str, list[str], list[str]]]:
        table: dict[bytes, tuple[str, list[str], list[str]]] = {}
        for contract in (self.registry, self.access, self.quality):
            for item in contract.abi:
                if item.get("type") != "error":
                    continue
                types = [i["type"] for i in item["inputs"]]
                selector = keccak(text=f"{item['name']}({','.join(types)})")[:4]
                table[selector] = (item["name"], [i["name"] for i in item["inputs"]], types)
        return table

    def decode_error(self, exc: Exception) -> ChainError:
        data = getattr(exc, "data", None)
        if isinstance(data, str) and data.startswith("0x") and len(data) >= 10:
            raw = bytes.fromhex(data[2:])
            entry = self._errors.get(raw[:4])
            if entry:
                name, names, types = entry
                values = abi_decode(types, raw[4:]) if types else ()
                args = {n: (_hex(v) if isinstance(v, bytes) else v) for n, v in zip(names, values, strict=True)}
                detail = ", ".join(f"{k}={v}" for k, v in args.items())
                return ChainError(f"{name}({detail})", name, args)
        return ChainError(str(exc))

    def call(self, fn: ContractFunction) -> Any:
        try:
            return fn.call()
        except (ContractCustomError, ContractLogicError, ContractPanicError) as exc:
            raise self.decode_error(exc) from exc

    def transact(self, fn: ContractFunction, account: LocalAccount) -> TxReceipt:
        with self._tx_lock:
            try:
                tx = fn.build_transaction(
                    {
                        "from": account.address,
                        "nonce": self.w3.eth.get_transaction_count(account.address, "pending"),
                        "chainId": self.deployment.chain_id,
                    }
                )
            except (ContractCustomError, ContractLogicError, ContractPanicError) as exc:
                raise self.decode_error(exc) from exc
            signed = account.sign_transaction(tx)
            tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        if receipt["status"] != 1:
            raise ChainError(f"transaction {_hex(tx_hash)} reverted")
        return receipt

    @property
    def block_number(self) -> int:
        return self.w3.eth.block_number

    # ------------------------------------------------------------------ registry writes

    def register_dataset(
        self,
        account: LocalAccount,
        name: str,
        classification: Classification,
        schema_hash: bytes,
        metadata_uri: str,
    ) -> int:
        receipt = self.transact(
            self.registry.functions.registerDataset(name, int(classification), _b32(schema_hash), metadata_uri),
            account,
        )
        (log,) = self.registry.events.DatasetRegistered().process_receipt(receipt, errors=DISCARD)
        return int(log["args"]["datasetId"])

    def commit_version(
        self,
        account: LocalAccount,
        dataset_id: int,
        *,
        merkle_root: bytes | str,
        content_hash: bytes | str,
        schema_hash: bytes | str,
        record_count: int,
        storage_uri: str,
        parents: Sequence[tuple[int, int]] = (),
    ) -> int:
        version_input = (_b32(merkle_root), _b32(content_hash), _b32(schema_hash), record_count, storage_uri)
        receipt = self.transact(
            self.registry.functions.commitVersion(dataset_id, version_input, [tuple(p) for p in parents]),
            account,
        )
        (log,) = self.registry.events.VersionCommitted().process_receipt(receipt, errors=DISCARD)
        return int(log["args"]["version"])

    def set_version_status(
        self, account: LocalAccount, dataset_id: int, version: int, status: VersionStatus, reason: str
    ) -> TxReceipt:
        return self.transact(
            self.registry.functions.setVersionStatus(dataset_id, version, int(status), reason), account
        )

    def set_steward(self, account: LocalAccount, dataset_id: int, steward: str, enabled: bool) -> TxReceipt:
        return self.transact(
            self.registry.functions.setSteward(dataset_id, to_checksum_address(steward), enabled), account
        )

    def update_metadata(self, account: LocalAccount, dataset_id: int, metadata_uri: str) -> TxReceipt:
        return self.transact(self.registry.functions.updateMetadata(dataset_id, metadata_uri), account)

    def grant_role(self, account: LocalAccount, contract: str, role: str, grantee: str) -> TxReceipt | None:
        target = self.contracts[contract]
        role_id = self.call(getattr(target.functions, role)())
        grantee = to_checksum_address(grantee)
        if self.call(target.functions.hasRole(role_id, grantee)):
            return None
        return self.transact(target.functions.grantRole(role_id, grantee), account)

    # ------------------------------------------------------------------ access writes

    def request_access(self, account: LocalAccount, dataset_id: int, purpose: str) -> int:
        receipt = self.transact(self.access.functions.requestAccess(dataset_id, purpose), account)
        (log,) = self.access.events.AccessRequested().process_receipt(receipt, errors=DISCARD)
        return int(log["args"]["requestId"])

    def approve_request(self, account: LocalAccount, request_id: int, duration_seconds: int) -> TxReceipt:
        return self.transact(self.access.functions.approveRequest(request_id, duration_seconds), account)

    def reject_request(self, account: LocalAccount, request_id: int, reason: str) -> TxReceipt:
        return self.transact(self.access.functions.rejectRequest(request_id, reason), account)

    def grant_access(
        self, account: LocalAccount, dataset_id: int, grantee: str, duration_seconds: int, purpose: str
    ) -> TxReceipt:
        return self.transact(
            self.access.functions.grantAccess(dataset_id, to_checksum_address(grantee), duration_seconds, purpose),
            account,
        )

    def revoke_access(self, account: LocalAccount, dataset_id: int, grantee: str) -> TxReceipt:
        return self.transact(self.access.functions.revokeAccess(dataset_id, to_checksum_address(grantee)), account)

    def log_access(
        self, gateway: LocalAccount, dataset_id: int, version: int, accessor: str, receipt_hash: bytes
    ) -> TxReceipt:
        return self.transact(
            self.access.functions.logAccess(dataset_id, version, to_checksum_address(accessor), _b32(receipt_hash)),
            gateway,
        )

    # ------------------------------------------------------------------ quality writes

    def attest(
        self,
        auditor: LocalAccount,
        dataset_id: int,
        version: int,
        *,
        score_bps: int,
        passed: bool,
        report_hash: bytes | str,
        report_uri: str,
    ) -> TxReceipt:
        return self.transact(
            self.quality.functions.attest(dataset_id, version, score_bps, passed, _b32(report_hash), report_uri),
            auditor,
        )

    # ------------------------------------------------------------------ reads

    def dataset_count(self) -> int:
        return int(self.call(self.registry.functions.datasetCount()))

    def get_dataset(self, dataset_id: int) -> dict[str, Any]:
        ds = self.call(self.registry.functions.getDataset(dataset_id))
        return {
            "dataset_id": dataset_id,
            "owner": ds.owner,
            "classification": Classification(ds.classification),
            "archived": ds.archived,
            "version_count": ds.versionCount,
            "created_at": ds.createdAt,
            "schema_hash": _hex(ds.schemaHash),
            "name": ds.name,
            "metadata_uri": ds.metadataURI,
        }

    def get_version(self, dataset_id: int, version: int) -> dict[str, Any]:
        v = self.call(self.registry.functions.getVersion(dataset_id, version))
        return {
            "dataset_id": dataset_id,
            "version": version,
            "merkle_root": _hex(v.merkleRoot),
            "content_hash": _hex(v.contentHash),
            "schema_hash": _hex(v.schemaHash),
            "record_count": v.recordCount,
            "committed_at": v.committedAt,
            "committer": v.committer,
            "status": VersionStatus(v.status),
            "storage_uri": v.storageURI,
        }

    def version_status(self, dataset_id: int, version: int) -> VersionStatus:
        return VersionStatus(self.call(self.registry.functions.versionStatus(dataset_id, version)))

    def can_manage(self, dataset_id: int, account: str) -> bool:
        return bool(self.call(self.registry.functions.canManage(dataset_id, to_checksum_address(account))))

    def dataset_owner(self, dataset_id: int) -> str:
        return self.call(self.registry.functions.datasetOwner(dataset_id))

    def exists(self, dataset_id: int) -> bool:
        return bool(self.call(self.registry.functions.exists(dataset_id)))

    def has_access(self, dataset_id: int, account: str) -> bool:
        return bool(self.call(self.access.functions.hasAccess(dataset_id, to_checksum_address(account))))

    def verify_record(
        self, dataset_id: int, version: int, index: int, record: bytes, proof: Sequence[bytes | str]
    ) -> bool:
        return bool(
            self.call(
                self.registry.functions.verifyRecord(dataset_id, version, index, record, [_b32(p) for p in proof])
            )
        )

    def locate_content(self, content_hash: bytes | str) -> tuple[int, int] | None:
        dataset_id, version = self.call(self.registry.functions.locateContent(_b32(content_hash)))
        return (int(dataset_id), int(version)) if dataset_id else None

    def record_leaf(self, index: int, record: bytes) -> bytes:
        return bytes(self.call(self.registry.functions.recordLeaf(index, record)))
