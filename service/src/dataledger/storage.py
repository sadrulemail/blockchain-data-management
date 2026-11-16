"""Content-addressed object store. An object id is the SHA-256 of the sealed bytes, so reads self-verify."""

from __future__ import annotations

import base64
import hashlib
import os
import re
from pathlib import Path
from typing import Any, Protocol

_OBJECT_ID = re.compile(r"^[0-9a-f]{64}$")
URI_PREFIX = "dl://objects/"


class ObjectNotFound(KeyError):
    pass


class StorageIntegrityError(Exception):
    """Stored bytes no longer hash to their object id."""


class ObjectStore(Protocol):
    def put(self, blob: bytes) -> str: ...
    def get(self, object_id: str) -> bytes: ...
    def delete(self, object_id: str) -> bool: ...
    def exists(self, object_id: str) -> bool: ...


def object_uri(object_id: str) -> str:
    return URI_PREFIX + object_id


def parse_object_uri(uri: str) -> str:
    if not uri.startswith(URI_PREFIX):
        raise ValueError(f"not an object URI: {uri!r}")
    object_id = uri[len(URI_PREFIX) :]
    if not _OBJECT_ID.match(object_id):
        raise ValueError(f"malformed object id in {uri!r}")
    return object_id


class LocalObjectStore:
    """Filesystem backend (``root/ab/cd/<id>``). Azure Blob, GCS or IPFS fit the same four methods."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, object_id: str) -> Path:
        if not _OBJECT_ID.match(object_id):
            raise ValueError(f"malformed object id {object_id!r}")
        return self.root / object_id[:2] / object_id[2:4] / object_id

    def put(self, blob: bytes) -> str:
        object_id = hashlib.sha256(blob).hexdigest()
        path = self._path(object_id)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(blob)
            os.replace(tmp, path)
        return object_id

    def get(self, object_id: str) -> bytes:
        path = self._path(object_id)
        if not path.exists():
            raise ObjectNotFound(object_id)
        blob = path.read_bytes()
        if hashlib.sha256(blob).hexdigest() != object_id:
            raise StorageIntegrityError(f"object {object_id} does not match its content address")
        return blob

    def delete(self, object_id: str) -> bool:
        path = self._path(object_id)
        if path.exists():
            path.unlink()
            return True
        return False

    def exists(self, object_id: str) -> bool:
        return self._path(object_id).exists()


class S3ObjectStore:
    """S3 or any S3-compatible service (MinIO, Ceph, R2, GCS interoperability). Keys are ``prefix/ab/cd/<id>``.

    Objects are already encrypted and content-addressed, so the bucket needs no extra trust: a changed object fails
    its hash check on read. Server-side encryption and versioning on the bucket are still recommended.
    """

    def __init__(self, bucket: str, prefix: str = "", client: Any = None, **client_kwargs: Any) -> None:
        if client is None:
            import boto3

            client = boto3.client("s3", **{k: v for k, v in client_kwargs.items() if v})
        self.client = client
        self.bucket = bucket
        self.prefix = prefix.strip("/")

    def _key(self, object_id: str) -> str:
        if not _OBJECT_ID.match(object_id):
            raise ValueError(f"malformed object id {object_id!r}")
        key = f"{object_id[:2]}/{object_id[2:4]}/{object_id}"
        return f"{self.prefix}/{key}" if self.prefix else key

    def _missing(self, exc: Exception) -> bool:
        code = str(getattr(exc, "response", {}).get("Error", {}).get("Code", ""))
        return code in {"404", "NoSuchKey", "NotFound"}

    def put(self, blob: bytes) -> str:
        object_id = hashlib.sha256(blob).hexdigest()
        if not self.exists(object_id):
            self.client.put_object(
                Bucket=self.bucket,
                Key=self._key(object_id),
                Body=blob,
                ContentType="application/octet-stream",
                ChecksumSHA256=base64.b64encode(bytes.fromhex(object_id)).decode(),
            )
        return object_id

    def get(self, object_id: str) -> bytes:
        try:
            response = self.client.get_object(Bucket=self.bucket, Key=self._key(object_id))
        except Exception as exc:
            if self._missing(exc):
                raise ObjectNotFound(object_id) from exc
            raise
        blob = response["Body"].read()
        if hashlib.sha256(blob).hexdigest() != object_id:
            raise StorageIntegrityError(f"object {object_id} does not match its content address")
        return blob

    def delete(self, object_id: str) -> bool:
        if not self.exists(object_id):
            return False
        self.client.delete_object(Bucket=self.bucket, Key=self._key(object_id))
        return True

    def exists(self, object_id: str) -> bool:
        try:
            self.client.head_object(Bucket=self.bucket, Key=self._key(object_id))
        except Exception as exc:
            if self._missing(exc):
                return False
            raise
        return True
