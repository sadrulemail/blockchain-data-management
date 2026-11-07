"""Wallet-signed API requests (EIP-191 personal_sign).

The caller signs a short text naming the HTTP method, path, its address, an issue time and a one-time nonce.
The server recovers the signer, checks freshness and refuses a nonce it has already seen. Access itself is
always decided on-chain, so the signature only proves *who* is asking.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_account.signers.local import LocalAccount
from eth_utils import is_address, to_checksum_address

HEADER_ADDRESS = "X-DL-Address"
HEADER_ISSUED = "X-DL-Issued"
HEADER_NONCE = "X-DL-Nonce"
HEADER_SIGNATURE = "X-DL-Signature"


class AuthError(Exception):
    pass


def signing_message(method: str, path: str, address: str, issued: str, nonce: str) -> str:
    return (
        "DataLedger signed request\n"
        f"Method: {method.upper()}\n"
        f"Path: {path}\n"
        f"Address: {to_checksum_address(address)}\n"
        f"Issued: {issued}\n"
        f"Nonce: {nonce}"
    )


def sign_headers(account: LocalAccount, method: str, path: str) -> dict[str, str]:
    issued = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce = secrets.token_hex(12)
    message = signing_message(method, path, account.address, issued, nonce)
    signature = account.sign_message(encode_defunct(text=message)).signature.hex()
    return {
        HEADER_ADDRESS: account.address,
        HEADER_ISSUED: issued,
        HEADER_NONCE: nonce,
        HEADER_SIGNATURE: signature if signature.startswith("0x") else "0x" + signature,
    }


@dataclass
class NonceCache:
    ttl_seconds: int

    def __post_init__(self) -> None:
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def claim(self, nonce: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if len(self._seen) > 10_000:
                self._seen = {n: exp for n, exp in self._seen.items() if exp > now}
            expiry = self._seen.get(nonce)
            if expiry is not None and expiry > now:
                return False
            self._seen[nonce] = now + self.ttl_seconds * 2
            return True


class RequestVerifier:
    def __init__(self, max_age_seconds: int = 300) -> None:
        self.max_age = max_age_seconds
        self.nonces = NonceCache(max_age_seconds)

    def verify(self, method: str, path: str, headers: dict[str, str]) -> str:
        """Returns the checksummed signer address or raises AuthError."""
        lowered = {k.lower(): v for k, v in headers.items()}
        try:
            address = lowered[HEADER_ADDRESS.lower()]
            issued = lowered[HEADER_ISSUED.lower()]
            nonce = lowered[HEADER_NONCE.lower()]
            signature = lowered[HEADER_SIGNATURE.lower()]
        except KeyError as exc:
            raise AuthError(f"missing signed-request header {exc.args[0]}") from exc
        if not is_address(address):
            raise AuthError("malformed address")
        if not 8 <= len(nonce) <= 64:
            raise AuthError("malformed nonce")

        try:
            issued_at = datetime.strptime(issued, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        except ValueError as exc:
            raise AuthError("issued must be UTC ISO-8601 like 2026-11-07T10:00:00Z") from exc
        age = abs((datetime.now(UTC) - issued_at).total_seconds())
        if age > self.max_age:
            raise AuthError("signed request expired")

        message = signing_message(method, path, address, issued, nonce)
        try:
            recovered = Account.recover_message(encode_defunct(text=message), signature=signature)
        except Exception as exc:
            raise AuthError("signature could not be recovered") from exc
        if recovered != to_checksum_address(address):
            raise AuthError("signature does not match address")
        if not self.nonces.claim(f"{recovered}:{nonce}"):
            raise AuthError("nonce already used")
        return recovered
