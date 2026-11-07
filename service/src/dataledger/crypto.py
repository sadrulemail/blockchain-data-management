"""Envelope encryption for stored dataset objects.

Each object gets its own 256-bit data key (DEK) and is sealed with AES-256-GCM. The DEK is wrapped by a key
encryption key (KEK) from the key ring; only the wrapped DEK is stored. Deleting the wrapped DEK makes the
object unreadable for good (crypto-shredding), which is how erasure works while hashes stay on-chain.
"""

from __future__ import annotations

import base64
import os
import secrets
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

OBJECT_MAGIC = b"DLO1"
NONCE_SIZE = 12


class DecryptionError(Exception):
    """Ciphertext, wrapped key or associated data did not authenticate."""


@dataclass(frozen=True)
class WrappedKey:
    kek_id: str
    blob: bytes  # nonce || AES-GCM(KEK, DEK)


class KeyRing:
    """Named KEKs. The first entry is the active key used for new objects; older ones stay for decryption."""

    def __init__(self, keys: dict[str, bytes], active: str) -> None:
        if active not in keys:
            raise ValueError("active key id is not in the key ring")
        for kid, key in keys.items():
            if len(key) != 32:
                raise ValueError(f"key {kid!r} must be 32 bytes")
        self._keys = dict(keys)
        self.active_id = active

    @classmethod
    def parse(cls, spec: str) -> KeyRing:
        """Parses ``kid:base64key[,kid:base64key...]``."""
        keys: dict[str, bytes] = {}
        order: list[str] = []
        for part in filter(None, (p.strip() for p in spec.split(","))):
            kid, sep, encoded = part.partition(":")
            if not sep or not kid:
                raise ValueError("key ring entries must look like kid:base64key")
            keys[kid] = base64.b64decode(encoded)
            order.append(kid)
        if not order:
            raise ValueError("key ring is empty; generate a key with `dataledger keygen`")
        return cls(keys, order[0])

    @staticmethod
    def generate_entry(kid: str | None = None) -> str:
        kid = kid or f"k{secrets.token_hex(3)}"
        return f"{kid}:{base64.b64encode(AESGCM.generate_key(bit_length=256)).decode()}"

    def kek(self, kid: str) -> bytes:
        try:
            return self._keys[kid]
        except KeyError as exc:
            raise DecryptionError(f"key {kid!r} is not in the key ring") from exc

    def wrap(self, dek: bytes) -> WrappedKey:
        nonce = os.urandom(NONCE_SIZE)
        sealed = AESGCM(self.kek(self.active_id)).encrypt(nonce, dek, self.active_id.encode())
        return WrappedKey(self.active_id, nonce + sealed)

    def unwrap(self, wrapped: WrappedKey) -> bytes:
        nonce, sealed = wrapped.blob[:NONCE_SIZE], wrapped.blob[NONCE_SIZE:]
        try:
            return AESGCM(self.kek(wrapped.kek_id)).decrypt(nonce, sealed, wrapped.kek_id.encode())
        except InvalidTag as exc:
            raise DecryptionError("wrapped data key failed authentication") from exc

    def rewrap(self, wrapped: WrappedKey) -> WrappedKey:
        """Re-seals a DEK under the active KEK (key rotation without touching the object)."""
        return self.wrap(self.unwrap(wrapped))


def encrypt_object(plaintext: bytes, ring: KeyRing, aad: bytes) -> tuple[bytes, WrappedKey]:
    dek = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, aad)
    return OBJECT_MAGIC + nonce + ciphertext, ring.wrap(dek)


def decrypt_object(blob: bytes, wrapped: WrappedKey, ring: KeyRing, aad: bytes) -> bytes:
    if not blob.startswith(OBJECT_MAGIC):
        raise DecryptionError("not a sealed object")
    body = blob[len(OBJECT_MAGIC) :]
    nonce, ciphertext = body[:NONCE_SIZE], body[NONCE_SIZE:]
    try:
        return AESGCM(ring.unwrap(wrapped)).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise DecryptionError("object failed authentication (tampered or wrong context)") from exc
