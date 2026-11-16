"""EIP-712 signed requests: binding, freshness, replay, body integrity and smart-account fallback."""

import time

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data

from dataledger.auth import (
    HEADER_ADDRESS,
    HEADER_DIGEST,
    HEADER_ISSUED,
    AuthError,
    NonceCache,
    RequestVerifier,
    SigningDomain,
    body_digest,
    eip712_digest,
    format_content_digest,
    parse_content_digest,
    sign_headers,
    typed_request,
)

ALICE = Account.from_key("0x" + "11" * 32)
BOB = Account.from_key("0x" + "22" * 32)
DOMAIN = SigningDomain(31337, "0x5FbDB2315678afecb367f032d93F642f64180aa3")
PATH = "/api/datasets/1/versions/1/download"


def _verify(verifier: RequestVerifier, headers: dict, method: str = "GET", path: str = PATH, body: bytes = b""):
    return verifier.verify(method, path, headers, body_digest(body))


def test_signed_request_verifies_once():
    verifier = RequestVerifier(DOMAIN)
    headers = sign_headers(ALICE, DOMAIN, "GET", PATH)
    assert _verify(verifier, headers) == ALICE.address
    with pytest.raises(AuthError, match="nonce"):
        _verify(verifier, headers)


def test_signature_is_bound_to_method_path_and_address():
    verifier = RequestVerifier(DOMAIN)
    headers = sign_headers(ALICE, DOMAIN, "GET", PATH)
    with pytest.raises(AuthError):
        _verify(verifier, headers, path="/api/datasets/2/versions/1/download")
    with pytest.raises(AuthError):
        _verify(verifier, headers, method="POST")
    with pytest.raises(AuthError, match="does not match"):
        _verify(verifier, {**headers, HEADER_ADDRESS: BOB.address})


def test_signature_is_bound_to_chain_and_deployment():
    headers = sign_headers(ALICE, DOMAIN, "GET", PATH)
    other_chain = RequestVerifier(SigningDomain(1, DOMAIN.verifying_contract))
    other_deployment = RequestVerifier(SigningDomain(31337, "0x" + "ab" * 20))
    for verifier in (other_chain, other_deployment):
        with pytest.raises(AuthError, match="does not match"):
            _verify(verifier, dict(headers))


def test_body_is_covered_by_the_signature():
    verifier = RequestVerifier(DOMAIN)
    body = b'{"kind":"metadata","body":{}}'
    headers = sign_headers(ALICE, DOMAIN, "POST", "/api/documents", body)
    with pytest.raises(AuthError, match="Content-Digest does not match"):
        _verify(verifier, dict(headers), "POST", "/api/documents", body + b" ")
    forged = {**headers, HEADER_DIGEST: format_content_digest(body_digest(b"other"))}
    with pytest.raises(AuthError, match="Content-Digest does not match"):
        _verify(verifier, forged, "POST", "/api/documents", b"other" + b"x")
    with pytest.raises(AuthError, match="does not match address"):
        _verify(verifier, forged, "POST", "/api/documents", b"other")
    assert _verify(verifier, headers, "POST", "/api/documents", body) == ALICE.address


def test_expired_and_malformed_requests_are_rejected():
    verifier = RequestVerifier(DOMAIN, max_age_seconds=60)
    headers = sign_headers(ALICE, DOMAIN, "GET", "/x")
    with pytest.raises(AuthError, match="expired"):
        _verify(verifier, {**headers, HEADER_ISSUED: str(int(time.time()) - 300)}, path="/x")
    with pytest.raises(AuthError, match="unix seconds"):
        _verify(verifier, {**headers, HEADER_ISSUED: "2026-11-16T10:00:00Z"}, path="/x")
    with pytest.raises(AuthError, match="missing"):
        _verify(verifier, {}, path="/x")
    with pytest.raises(AuthError, match="malformed address"):
        _verify(verifier, {**headers, HEADER_ADDRESS: "0x123"}, path="/x")
    with pytest.raises(AuthError, match="malformed nonce"):
        _verify(verifier, {**headers, "X-DL-Nonce": "0x1234"}, path="/x")
    with pytest.raises(AuthError, match="malformed signature"):
        _verify(verifier, {**headers, "X-DL-Signature": "0xzz"}, path="/x")


def test_header_names_are_case_insensitive():
    verifier = RequestVerifier(DOMAIN)
    headers = {k.lower(): v for k, v in sign_headers(ALICE, DOMAIN, "GET", PATH).items()}
    assert _verify(verifier, headers) == ALICE.address


def test_smart_account_signatures_go_through_erc1271():
    wallet = "0x" + "c0" * 20
    seen: list[tuple[str, bytes, bytes]] = []

    def erc1271(account: str, digest: bytes, signature: bytes) -> bool:
        seen.append((account, digest, signature))
        return Account._recover_hash(digest, signature=signature) == ALICE.address

    verifier = RequestVerifier(DOMAIN, smart_account_check=erc1271)
    # The owner key signs for the wallet address, as a Safe or an EIP-7702 delegate would accept.
    message = typed_request(DOMAIN, wallet, "GET", PATH, body_digest(b""), int(time.time()), b"\x01" * 32)
    signable = encode_typed_data(full_message=message)
    signature = ALICE.sign_message(signable).signature
    headers = {
        HEADER_ADDRESS: wallet,
        HEADER_ISSUED: str(message["message"]["issuedAt"]),
        "X-DL-Nonce": "0x" + "01" * 32,
        "X-DL-Signature": "0x" + bytes(signature).hex(),
        HEADER_DIGEST: format_content_digest(body_digest(b"")),
    }
    assert _verify(verifier, headers).lower() == wallet
    assert seen[0][1] == eip712_digest(signable)

    rejecting = RequestVerifier(DOMAIN, smart_account_check=lambda *_: False)
    with pytest.raises(AuthError, match="does not match"):
        _verify(rejecting, {**headers, "X-DL-Nonce": "0x" + "02" * 32})
    failing = RequestVerifier(DOMAIN, smart_account_check=lambda *_: 1 / 0)
    with pytest.raises(AuthError, match="does not match"):
        _verify(failing, {**headers, "X-DL-Nonce": "0x" + "03" * 32})


def test_content_digest_header_format():
    digest = body_digest(b"hello")
    value = format_content_digest(digest)
    assert value == "sha-256=:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=:"
    assert parse_content_digest(f"sha-512=:AAAA:, {value}") == digest
    for bad in ("sha-256=abc", "md5=:AAAA:", "sha-256=:not base64!:"):
        with pytest.raises(AuthError):
            parse_content_digest(bad)


def test_nonce_cache_refuses_when_flooded():
    cache = NonceCache(ttl_seconds=60, max_entries=3)
    assert all(cache.claim(f"n{i}") for i in range(3))
    assert not cache.claim("n3")
    assert not cache.claim("n0")
