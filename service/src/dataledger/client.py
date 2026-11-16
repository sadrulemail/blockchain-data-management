"""HTTP client for the DataLedger API with wallet-signed requests."""

from __future__ import annotations

import time
from typing import Any

import httpx
from eth_account.messages import encode_typed_data
from eth_account.signers.local import LocalAccount

from .auth import SigningDomain, sign_headers


class ApiError(Exception):
    def __init__(self, status: int, detail: Any) -> None:
        super().__init__(f"HTTP {status}: {detail}")
        self.status = status
        self.detail = detail


class ApiClient:
    def __init__(
        self,
        base_url: str,
        account: LocalAccount | None = None,
        *,
        timeout: float = 120,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.account = account
        self._domain: SigningDomain | None = None
        self._http = httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout, transport=transport)

    @classmethod
    def wrap(cls, http: httpx.Client, account: LocalAccount | None = None) -> ApiClient:
        """Uses an existing httpx client (for example a FastAPI TestClient)."""
        client = cls.__new__(cls)
        client.account = account
        client._domain = None
        client._http = http
        return client

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> ApiClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def as_account(self, account: LocalAccount) -> ApiClient:
        client = ApiClient.wrap(self._http, account)
        client._domain = self._domain
        return client

    def signing_domain(self) -> SigningDomain:
        """EIP-712 domain published by the gateway (cached)."""
        if self._domain is None:
            data = self._request("GET", "/api/auth/domain").json()["domain"]
            self._domain = SigningDomain(int(data["chainId"]), data["verifyingContract"])
        return self._domain

    def _request(self, method: str, path: str, *, signed: bool = False, **kwargs: Any) -> httpx.Response:
        request = self._http.build_request(method, path, **kwargs)
        if signed:
            if self.account is None:
                raise ValueError("this call needs a signing account")
            body = request.read()  # the exact bytes that go on the wire, multipart boundary included
            request.headers.update(sign_headers(self.account, self.signing_domain(), method, request.url.path, body))
        response = self._http.send(request)
        if response.status_code >= 400:
            try:
                detail = response.json().get("detail")
            except ValueError:
                detail = response.text
            raise ApiError(response.status_code, detail)
        return response

    # ------------------------------------------------------------------ reads

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/api/health").json()

    def overview(self) -> dict[str, Any]:
        return self._request("GET", "/api/overview").json()

    def datasets(self) -> list[dict[str, Any]]:
        return self._request("GET", "/api/datasets").json()

    def dataset(self, dataset_id: int) -> dict[str, Any]:
        return self._request("GET", f"/api/datasets/{dataset_id}").json()

    def lineage(self, dataset_id: int | None = None, version: int | None = None) -> dict[str, Any]:
        params = {k: v for k, v in {"dataset_id": dataset_id, "version": version}.items() if v is not None}
        return self._request("GET", "/api/lineage", params=params).json()

    def audit(self, dataset_id: int | None = None, limit: int = 100) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"limit": limit}
        if dataset_id is not None:
            params["dataset_id"] = dataset_id
        return self._request("GET", "/api/audit", params=params).json()

    def document(self, doc_hash: str) -> dict[str, Any]:
        return self._request("GET", f"/api/documents/{doc_hash}").json()

    def wait_for_block(self, block: int, timeout: float = 30) -> None:
        """Blocks until the indexer has processed `block`."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.health()["indexed_block"] >= block:
                return
            time.sleep(0.25)
        raise TimeoutError(f"indexer did not reach block {block} within {timeout}s")

    # ------------------------------------------------------------------ signed

    def put_document(self, kind: str, body: dict[str, Any]) -> dict[str, str]:
        return self._request("POST", "/api/documents", signed=True, json={"kind": kind, "body": body}).json()

    def upload(self, dataset_id: int, data: bytes, file_name: str) -> dict[str, Any]:
        files = {"file": (file_name, data, "text/csv")}
        return self._request("POST", f"/api/datasets/{dataset_id}/objects", signed=True, files=files).json()

    def download(self, dataset_id: int, version: int) -> tuple[bytes, dict[str, str]]:
        response = self._request("GET", f"/api/datasets/{dataset_id}/versions/{version}/download", signed=True)
        return response.content, {k.lower(): v for k, v in response.headers.items() if k.lower().startswith("x-dl")}

    def record_proof(self, dataset_id: int, version: int, index: int) -> dict[str, Any]:
        path = f"/api/datasets/{dataset_id}/versions/{version}/records/{index}"
        return self._request("GET", path, signed=True).json()

    def diff(self, dataset_id: int, version: int, data: bytes) -> dict[str, Any]:
        files = {"file": ("candidate.csv", data, "text/csv")}
        path = f"/api/datasets/{dataset_id}/versions/{version}/diff"
        return self._request("POST", path, signed=True, files=files).json()

    def shred(self, dataset_id: int, version: int) -> dict[str, Any]:
        return self._request("POST", f"/api/datasets/{dataset_id}/versions/{version}/shred", signed=True).json()

    # ------------------------------------------------------------------ gasless access requests

    def request_access_gasless(self, dataset_id: int, purpose: str) -> dict[str, Any]:
        """Signs an EIP-712 access request locally and has the gateway submit it; the signer pays no gas."""
        if self.account is None:
            raise ValueError("this call needs a signing account")
        body = {"dataset_id": dataset_id, "requester": self.account.address, "purpose": purpose}
        typed = self._request("POST", "/api/relay/access-requests/prepare", json=body).json()
        message = typed.get("message", {})
        expected = (dataset_id, self.account.address.lower(), purpose)
        if (
            typed.get("primaryType") != "AccessRequest"
            or (
                message.get("datasetId"),
                str(message.get("requester", "")).lower(),
                message.get("purpose"),
            )
            != expected
        ):
            raise ApiError(502, "gateway returned typed data that does not match the request; not signing")
        signature = self.account.sign_message(encode_typed_data(full_message=typed)).signature
        submit = {**body, "deadline": typed["message"]["deadline"], "signature": "0x" + bytes(signature).hex()}
        return self._request("POST", "/api/relay/access-requests", json=submit).json()

    # ------------------------------------------------------------------ public verification

    def verify_file(self, data: bytes, dataset_id: int | None = None, version: int | None = None) -> dict:
        form = {k: str(v) for k, v in {"dataset_id": dataset_id, "version": version}.items() if v is not None}
        files = {"file": ("candidate.csv", data, "text/csv")}
        return self._request("POST", "/api/verify/file", data=form, files=files).json()

    def verify_record(self, proof: dict[str, Any]) -> dict[str, Any]:
        body = {k: proof[k] for k in ("dataset_id", "version", "index", "proof")}
        body["canonical"] = proof.get("canonical")
        if body["canonical"] is None:
            body["record"] = proof["record"]
        return self._request("POST", "/api/verify/record", json=body).json()
