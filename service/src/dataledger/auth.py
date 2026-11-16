"""Wallet-signed API requests (EIP-712 typed data, ERC-1271 for smart accounts).

The caller signs a typed ``Request`` naming its address, the HTTP method and path, the SHA-256 digest of the body,
an issue time and a one-time nonce. The domain binds the signature to one chain and one deployment, so it cannot be
replayed against another network. Wallets show every field before signing (``eth_signTypedData_v4``).

The server recovers the signer, falls back to ERC-1271 ``isValidSignature`` when the address is a smart account
(Safe, passkey wallet, EIP-7702 delegate), checks freshness and refuses a nonce it has already seen. Access itself
is always decided on-chain: the signature only proves *who* is asking.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from eth_account import Account
from eth_account.messages import SignableMessage, encode_typed_data
from eth_account.signers.local import LocalAccount
from eth_utils import is_address, keccak, to_checksum_address

HEADER_ADDRESS = "X-DL-Address"
HEADER_ISSUED = "X-DL-Issued"
HEADER_NONCE = "X-DL-Nonce"
HEADER_SIGNATURE = "X-DL-Signature"
HEADER_DIGEST = "Content-Digest"

DOMAIN_NAME = "DataLedger API"
DOMAIN_VERSION = "1"

REQUEST_TYPES: dict[str, list[dict[str, str]]] = {
    "EIP712Domain": [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"},
        {"name": "verifyingContract", "type": "address"},
    ],
    "Request": [
        {"name": "account", "type": "address"},
        {"name": "method", "type": "string"},
        {"name": "path", "type": "string"},
        {"name": "contentDigest", "type": "bytes32"},
        {"name": "issuedAt", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ],
}

# ERC-1271 check: (account, digest, signature) -> bool. Injected so this module needs no chain connection.
SmartAccountCheck = Callable[[str, bytes, bytes], bool]


class AuthError(Exception):
    pass


@dataclass(frozen=True)
class SigningDomain:
    """EIP-712 domain of the API: the chain and the AccessLedger that the gateway enforces."""

    chain_id: int
    verifying_contract: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": DOMAIN_NAME,
            "version": DOMAIN_VERSION,
            "chainId": self.chain_id,
            "verifyingContract": to_checksum_address(self.verifying_contract),
        }


def body_digest(body: bytes) -> bytes:
    return hashlib.sha256(body).digest()


def format_content_digest(digest: bytes) -> str:
    """RFC 9530 ``Content-Digest`` header value."""
    return f"sha-256=:{base64.b64encode(digest).decode()}:"


def parse_content_digest(value: str) -> bytes:
    for item in value.split(","):
        algorithm, _, encoded = item.strip().partition("=")
        if algorithm.strip().lower() == "sha-256" and encoded.startswith(":") and encoded.endswith(":"):
            try:
                digest = base64.b64decode(encoded[1:-1], validate=True)
            except ValueError as exc:
                raise AuthError("malformed Content-Digest") from exc
            if len(digest) == 32:
                return digest
    raise AuthError("Content-Digest must carry a sha-256 value")


def typed_request(
    domain: SigningDomain, account: str, method: str, path: str, digest: bytes, issued_at: int, nonce: bytes
) -> dict[str, Any]:
    return {
        "types": REQUEST_TYPES,
        "primaryType": "Request",
        "domain": domain.as_dict(),
        "message": {
            "account": to_checksum_address(account),
            "method": method.upper(),
            "path": path,
            "contentDigest": digest,
            "issuedAt": issued_at,
            "nonce": nonce,
        },
    }


def eip712_digest(signable: SignableMessage) -> bytes:
    """The 32-byte hash a wallet signs, as ``isValidSignature`` receives it."""
    return keccak(b"\x19" + signable.version + signable.header + signable.body)


def sign_headers(
    account: LocalAccount,
    domain: SigningDomain,
    method: str,
    path: str,
    body: bytes = b"",
    *,
    on_behalf_of: str | None = None,
) -> dict[str, str]:
    """Headers for one signed request. `on_behalf_of` names a smart account whose owner key is `account`."""
    address = to_checksum_address(on_behalf_of) if on_behalf_of else account.address
    digest = body_digest(body)
    issued_at = int(time.time())
    nonce = secrets.token_bytes(32)
    message = typed_request(domain, address, method, path, digest, issued_at, nonce)
    signature = account.sign_message(encode_typed_data(full_message=message)).signature
    return {
        HEADER_ADDRESS: address,
        HEADER_ISSUED: str(issued_at),
        HEADER_NONCE: "0x" + nonce.hex(),
        HEADER_SIGNATURE: "0x" + bytes(signature).hex(),
        HEADER_DIGEST: format_content_digest(digest),
    }


@dataclass
class NonceCache:
    ttl_seconds: int
    max_entries: int = 100_000

    def __post_init__(self) -> None:
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def claim(self, nonce: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if len(self._seen) >= self.max_entries:
                self._seen = {n: exp for n, exp in self._seen.items() if exp > now}
                if len(self._seen) >= self.max_entries:
                    return False  # flooded: refuse rather than grow without bound
            expiry = self._seen.get(nonce)
            if expiry is not None and expiry > now:
                return False
            self._seen[nonce] = now + self.ttl_seconds * 2
            return True


def _hex_bytes(value: str, length: int, label: str) -> bytes:
    try:
        raw = bytes.fromhex(value.removeprefix("0x"))
    except ValueError as exc:
        raise AuthError(f"malformed {label}") from exc
    if length and len(raw) != length:
        raise AuthError(f"malformed {label}")
    return raw


class RequestVerifier:
    def __init__(
        self,
        domain: SigningDomain,
        max_age_seconds: int = 300,
        smart_account_check: SmartAccountCheck | None = None,
    ) -> None:
        self.domain = domain
        self.max_age = max_age_seconds
        self.nonces = NonceCache(max_age_seconds)
        self.smart_account_check = smart_account_check

    def verify(self, method: str, path: str, headers: Mapping[str, str], body_sha256: bytes) -> str:
        """Returns the checksummed signer address or raises AuthError.

        ``body_sha256`` is the digest of the bytes the server actually received, not the header value.
        """
        lowered = {k.lower(): v for k, v in headers.items()}
        try:
            address = lowered[HEADER_ADDRESS.lower()]
            issued = lowered[HEADER_ISSUED.lower()]
            nonce_hex = lowered[HEADER_NONCE.lower()]
            signature_hex = lowered[HEADER_SIGNATURE.lower()]
            digest_header = lowered[HEADER_DIGEST.lower()]
        except KeyError as exc:
            raise AuthError(f"missing signed-request header {exc.args[0]}") from exc
        if not is_address(address):
            raise AuthError("malformed address")
        nonce = _hex_bytes(nonce_hex, 32, "nonce")
        signature = _hex_bytes(signature_hex, 0, "signature")
        if parse_content_digest(digest_header) != body_sha256:
            raise AuthError("Content-Digest does not match the request body")
        if not issued.isdigit():
            raise AuthError("issued must be unix seconds")
        if abs(time.time() - int(issued)) > self.max_age:
            raise AuthError("signed request expired")

        account = to_checksum_address(address)
        signable = encode_typed_data(
            full_message=typed_request(self.domain, account, method, path, body_sha256, int(issued), nonce)
        )
        if not self._valid(account, signable, signature):
            raise AuthError("signature does not match address")
        if not self.nonces.claim(f"{account}:{nonce.hex()}"):
            raise AuthError("nonce already used")
        return account

    def _valid(self, account: str, signable: SignableMessage, signature: bytes) -> bool:
        try:
            if Account.recover_message(signable, signature=signature) == account:
                return True
        except Exception:  # noqa: S110 - not a 65-byte ECDSA signature; may still be a smart-account signature
            pass
        if self.smart_account_check is None:
            return False
        try:
            return self.smart_account_check(account, eip712_digest(signable), signature)
        except Exception:
            return False
