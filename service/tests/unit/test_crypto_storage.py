import hashlib

import pytest

from dataledger.crypto import DecryptionError, KeyRing, WrappedKey, decrypt_object, encrypt_object
from dataledger.storage import (
    LocalObjectStore,
    ObjectNotFound,
    StorageIntegrityError,
    object_uri,
    parse_object_uri,
)

AAD = hashlib.sha256(b"context").digest()


@pytest.fixture
def ring() -> KeyRing:
    return KeyRing.parse(KeyRing.generate_entry("k1"))


def test_round_trip(ring):
    sealed, wrapped = encrypt_object(b"order_id\n1\n", ring, AAD)
    assert b"order_id" not in sealed
    assert wrapped.kek_id == "k1"
    assert decrypt_object(sealed, wrapped, ring, AAD) == b"order_id\n1\n"


def test_tampered_ciphertext_is_rejected(ring):
    sealed, wrapped = encrypt_object(b"payload", ring, AAD)
    tampered = sealed[:-1] + bytes([sealed[-1] ^ 1])
    with pytest.raises(DecryptionError):
        decrypt_object(tampered, wrapped, ring, AAD)


def test_wrong_context_is_rejected(ring):
    sealed, wrapped = encrypt_object(b"payload", ring, AAD)
    with pytest.raises(DecryptionError):
        decrypt_object(sealed, wrapped, ring, b"other context")


def test_unknown_kek_and_corrupt_wrap(ring):
    sealed, wrapped = encrypt_object(b"payload", ring, AAD)
    with pytest.raises(DecryptionError):
        decrypt_object(sealed, WrappedKey("missing", wrapped.blob), ring, AAD)
    with pytest.raises(DecryptionError):
        decrypt_object(sealed, WrappedKey("k1", wrapped.blob[:-1] + b"\x00"), ring, AAD)
    with pytest.raises(DecryptionError):
        decrypt_object(b"XXXX" + sealed[4:], wrapped, ring, AAD)


def test_key_rotation_rewraps_without_touching_object(ring):
    sealed, wrapped = encrypt_object(b"payload", ring, AAD)
    rotated = KeyRing.parse(f"{KeyRing.generate_entry('k2')},{KeyRing.generate_entry('unused')}")
    combined = KeyRing({"k2": rotated.kek("k2"), "k1": ring.kek("k1")}, active="k2")
    moved = combined.rewrap(wrapped)
    assert moved.kek_id == "k2"
    assert decrypt_object(sealed, moved, combined, AAD) == b"payload"


@pytest.mark.parametrize("spec", ["", "nokey", ":abc", "k1:" + "QUJD"])
def test_key_ring_parse_errors(spec):
    with pytest.raises(ValueError):
        KeyRing.parse(spec)


def test_store_is_content_addressed(tmp_path):
    store = LocalObjectStore(tmp_path)
    object_id = store.put(b"sealed bytes")
    assert object_id == hashlib.sha256(b"sealed bytes").hexdigest()
    assert store.put(b"sealed bytes") == object_id
    assert store.get(object_id) == b"sealed bytes"
    assert parse_object_uri(object_uri(object_id)) == object_id


def test_store_detects_corruption_and_missing(tmp_path):
    store = LocalObjectStore(tmp_path)
    object_id = store.put(b"sealed bytes")
    path = tmp_path / object_id[:2] / object_id[2:4] / object_id
    path.write_bytes(b"changed")
    with pytest.raises(StorageIntegrityError):
        store.get(object_id)
    assert store.delete(object_id)
    with pytest.raises(ObjectNotFound):
        store.get(object_id)
    with pytest.raises(ValueError):
        store.get("../../etc/passwd")
    with pytest.raises(ValueError):
        parse_object_uri("s3://bucket/key")
