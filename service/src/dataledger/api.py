"""HTTP API and web console."""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from importlib import resources
from pathlib import Path
from typing import Annotated, Any

from eth_utils import is_address, to_checksum_address
from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import text
from starlette.concurrency import run_in_threadpool

from . import __version__, queries
from .auth import REQUEST_TYPES, AuthError, RequestVerifier, SigningDomain
from .canonical import SchemaError
from .chain import ChainError
from .config import Settings, get_settings
from .observability import Metrics, RequestContextMiddleware, SecurityHeadersMiddleware, configure_tracing
from .platform import Forbidden, Gone, IntegrityFailure, InvalidInput, NotFound, Platform, RateLimited

log = logging.getLogger(__name__)


class DocumentIn(BaseModel):
    kind: str = Field(pattern="^(metadata|quality_report)$")
    body: dict[str, Any]


class RecordCheck(BaseModel):
    dataset_id: int = Field(ge=1)
    version: int = Field(ge=1)
    index: int = Field(ge=0)
    canonical: str | None = None
    record: dict[str, Any] | None = None
    proof: list[str] = Field(default_factory=list, max_length=64)


def _address(value: str) -> str:
    if not is_address(value):
        raise ValueError("not an address")
    return to_checksum_address(value)


class RelayPrepare(BaseModel):
    dataset_id: int = Field(ge=1)
    requester: str
    purpose: str = Field(min_length=1, max_length=1_000)

    @field_validator("requester")
    @classmethod
    def _checksum(cls, value: str) -> str:
        return _address(value)


class RelaySubmit(RelayPrepare):
    deadline: int = Field(ge=0)
    signature: str = Field(pattern="^0x[0-9a-fA-F]+$", max_length=4_096)


def get_platform(request: Request) -> Platform:
    return request.app.state.platform


def get_signer(request: Request) -> str:
    hasher = request.scope.get("state", {}).get("body_hasher")
    digest = hasher.digest() if hasher is not None else hashlib.sha256(b"").digest()
    try:
        return request.app.state.verifier.verify(request.method, request.url.path, request.headers, digest)
    except AuthError as exc:
        request.app.state.metrics.gateway_events.labels("auth_failed").inc()
        raise HTTPException(status_code=401, detail=str(exc)) from exc


P = Annotated[Platform, Depends(get_platform)]
Signer = Annotated[str, Depends(get_signer)]


def create_app(platform: Platform | None = None, *, start_indexer: bool | None = None) -> FastAPI:
    settings: Settings = platform.settings if platform else get_settings()
    run_indexer = settings.run_indexer if start_indexer is None else start_indexer
    metrics = Metrics()
    max_upload = settings.max_upload_mb * 1024 * 1024

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        p = platform or Platform.from_settings(settings)
        app.state.platform = p
        app.state.verifier = RequestVerifier(
            SigningDomain(p.chain.deployment.chain_id, p.chain.deployment.access_ledger),
            settings.auth_max_age_seconds,
            smart_account_check=p.chain.is_valid_smart_account_signature,
        )
        p.on_event = lambda event: metrics.gateway_events.labels(event).inc()
        metrics.observe_platform(p)
        stop = threading.Event()
        worker = None
        if run_indexer:
            worker = threading.Thread(
                target=p.indexer.run_forever, args=(stop, settings.indexer_poll_seconds), name="indexer", daemon=True
            )
            worker.start()
        yield
        stop.set()
        if worker:
            worker.join(timeout=5)

    app = FastAPI(
        title="DataLedger API",
        version=__version__,
        description=(
            "Blockchain-anchored data management: registry, lineage, access control and verification. "
            "Signed endpoints take EIP-712 typed-data signatures; see `GET /api/auth/domain`."
        ),
        lifespan=lifespan,
    )
    app.state.metrics = metrics

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_methods=["GET", "POST"],
            allow_headers=["*"],
            expose_headers=["X-Request-ID", "X-DL-Content-Hash", "X-DL-Merkle-Root", "X-DL-Receipt", "X-DL-Access-Tx"],
        )
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.hsts)
    app.add_middleware(RequestContextMiddleware, metrics=metrics)
    configure_tracing(app)

    def _error(status: int, exc: Exception, **extra: Any) -> JSONResponse:
        return JSONResponse(status_code=status, content={"detail": str(exc), **extra})

    @app.exception_handler(NotFound)
    async def _not_found(_: Request, exc: NotFound) -> JSONResponse:
        return _error(404, exc)

    @app.exception_handler(Forbidden)
    async def _forbidden(_: Request, exc: Forbidden) -> JSONResponse:
        return _error(403, exc)

    @app.exception_handler(Gone)
    async def _gone(_: Request, exc: Gone) -> JSONResponse:
        return _error(410, exc)

    @app.exception_handler(RateLimited)
    async def _limited(_: Request, exc: RateLimited) -> JSONResponse:
        return JSONResponse(status_code=429, content={"detail": str(exc)}, headers={"Retry-After": "3600"})

    @app.exception_handler(IntegrityFailure)
    async def _integrity(_: Request, exc: IntegrityFailure) -> JSONResponse:
        log.error("integrity failure: %s", exc)
        metrics.gateway_events.labels("integrity_failure").inc()
        return _error(409, exc, integrity=False)

    @app.exception_handler(InvalidInput)
    @app.exception_handler(SchemaError)
    async def _invalid(_: Request, exc: Exception) -> JSONResponse:
        return _error(422, exc)

    @app.exception_handler(ChainError)
    async def _chain(_: Request, exc: ChainError) -> JSONResponse:
        return _error(400, exc, error=exc.error)

    async def read_upload(upload: UploadFile) -> bytes:
        data = await upload.read(max_upload + 1)
        if len(data) > max_upload:
            raise HTTPException(status_code=413, detail=f"file larger than {settings.max_upload_mb} MB")
        return data

    # ------------------------------------------------------------------ operations

    @app.get("/healthz", tags=["operations"], include_in_schema=False)
    def healthz() -> dict[str, str]:
        """Liveness: the process answers."""
        return {"status": "ok"}

    @app.get("/readyz", tags=["operations"], include_in_schema=False)
    def readyz(p: P) -> JSONResponse:
        """Readiness: the database answers and the RPC endpoint serves the expected chain and contracts."""
        checks: dict[str, bool] = {}
        try:
            with p.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            checks["database"] = True
        except Exception:
            checks["database"] = False
        try:
            checks["chain"] = p.chain.is_ready()
        except Exception:
            checks["chain"] = False
        ready = all(checks.values())
        return JSONResponse(status_code=200 if ready else 503, content={"ready": ready, "checks": checks})

    if settings.metrics_enabled:

        @app.get("/metrics", tags=["operations"], include_in_schema=False)
        def prometheus() -> PlainTextResponse:
            return PlainTextResponse(generate_latest(metrics.registry), media_type=CONTENT_TYPE_LATEST)

    # ------------------------------------------------------------------ platform

    @app.get("/api/health", tags=["platform"])
    def health(p: P) -> dict[str, Any]:
        head = p.chain.block_number
        cursor = p.indexer.cursor()
        return {
            "status": "ok",
            "version": __version__,
            "chain_id": p.chain.deployment.chain_id,
            "head_block": head,
            "indexed_block": cursor,
            "indexer_lag": max(0, head - cursor),
            "gateway": p.gateway.address if p.gateway else None,
            "relay": bool(p.gateway and p.settings.relay_enabled),
            "contracts": p.chain.deployment.to_dict(),
        }

    @app.get("/api/auth/domain", tags=["platform"])
    def auth_domain(request: Request) -> dict[str, Any]:
        """EIP-712 domain and types for signed requests, so wallets and clients can build the typed data."""
        verifier: RequestVerifier = request.app.state.verifier
        return {
            "domain": verifier.domain.as_dict(),
            "types": REQUEST_TYPES,
            "primaryType": "Request",
            "max_age_seconds": verifier.max_age,
            "headers": ["X-DL-Address", "X-DL-Issued", "X-DL-Nonce", "X-DL-Signature", "Content-Digest"],
        }

    @app.get("/api/directory", tags=["platform"])
    def directory(p: P) -> dict[str, str]:
        """Display names for known accounts (off-chain convenience; never used for access decisions)."""
        path = p.settings.directory_file
        if path is None or not Path(path).exists():
            return {}
        return {to_checksum_address(k): str(v) for k, v in json.loads(Path(path).read_text(encoding="utf-8")).items()}

    @app.get("/api/overview", tags=["platform"])
    def overview(p: P) -> dict[str, Any]:
        return queries.overview(p.engine)

    @app.get("/api/audit", tags=["platform"])
    def audit(
        p: P,
        dataset_id: int | None = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        before_id: int | None = None,
    ) -> list[dict[str, Any]]:
        return queries.audit(p.engine, dataset_id=dataset_id, limit=limit, before_id=before_id)

    @app.get("/api/lineage", tags=["catalog"])
    def lineage(p: P, dataset_id: int | None = None, version: int | None = None) -> dict[str, Any]:
        return queries.lineage_graph(p.engine, dataset_id, version)

    # ------------------------------------------------------------------ catalog

    @app.get("/api/datasets", tags=["catalog"])
    def datasets(p: P) -> list[dict[str, Any]]:
        return queries.list_datasets(p.engine)

    @app.get("/api/datasets/{dataset_id}", tags=["catalog"])
    def dataset(p: P, dataset_id: int) -> dict[str, Any]:
        detail = queries.dataset_detail(p.engine, dataset_id)
        if detail is None:
            raise NotFound(f"dataset {dataset_id} not indexed")
        try:
            detail["schema"] = p.get_document(detail["metadata_uri"].rsplit("/", 1)[-1])["body"]
        except NotFound:
            detail["schema"] = None
        return detail

    @app.get("/api/access-requests", tags=["access"])
    def access_requests(p: P, status: str | None = None) -> list[dict[str, Any]]:
        return queries.access_requests(p.engine, status)

    @app.post("/api/relay/access-requests/prepare", tags=["access"])
    def relay_prepare(p: P, body: RelayPrepare) -> dict[str, Any]:
        """Typed data a consumer signs (`eth_signTypedData_v4`) to ask for access without paying gas."""
        return p.prepare_access_request(body.dataset_id, body.requester, body.purpose)

    @app.post("/api/relay/access-requests", tags=["access"], status_code=201)
    def relay_submit(p: P, body: RelaySubmit) -> dict[str, Any]:
        """The gateway submits the signed request on-chain and pays the gas. The contract checks the signature."""
        return p.relay_access_request(body.dataset_id, body.requester, body.purpose, body.deadline, body.signature)

    @app.get("/api/documents/{doc_hash}", tags=["documents"])
    def get_document(p: P, doc_hash: str) -> dict[str, Any]:
        return p.get_document(doc_hash)

    @app.post("/api/documents", tags=["documents"], status_code=201)
    def put_document(p: P, who: Signer, doc: DocumentIn) -> dict[str, str]:
        return p.put_document(doc.kind, doc.body, who)

    # ------------------------------------------------------------------ data plane (signed)

    @app.post("/api/datasets/{dataset_id}/objects", tags=["data"], status_code=201)
    async def upload(p: P, who: Signer, dataset_id: int, file: Annotated[UploadFile, File()]) -> dict[str, Any]:
        data = await read_upload(file)
        return await run_in_threadpool(p.ingest, dataset_id, data, file.filename or "upload.csv", who)

    @app.get("/api/datasets/{dataset_id}/versions/{version}/download", tags=["data"])
    def download(p: P, who: Signer, dataset_id: int, version: int) -> Response:
        data, receipt, tx_hash = p.download(dataset_id, version, who)
        headers = {
            "Content-Disposition": f'attachment; filename="{data.object_row["file_name"]}"',
            "X-DL-Content-Hash": data.version["content_hash"],
            "X-DL-Merkle-Root": data.version["merkle_root"],
            "X-DL-Receipt": receipt,
            "X-DL-Schema-Document": data.object_row["schema_document"],
        }
        if tx_hash:
            headers["X-DL-Access-Tx"] = tx_hash
        return Response(content=data.plaintext, media_type="text/csv", headers=headers)

    @app.get("/api/datasets/{dataset_id}/versions/{version}/records/{index}", tags=["data"])
    def record_proof(p: P, who: Signer, dataset_id: int, version: int, index: int) -> dict[str, Any]:
        return p.record_proof(dataset_id, version, index, who)

    @app.post("/api/datasets/{dataset_id}/versions/{version}/diff", tags=["data"])
    async def diff(
        p: P, who: Signer, dataset_id: int, version: int, file: Annotated[UploadFile, File()]
    ) -> dict[str, Any]:
        data = await read_upload(file)
        return await run_in_threadpool(p.diff, dataset_id, version, data, who)

    @app.post("/api/datasets/{dataset_id}/versions/{version}/shred", tags=["data"])
    def shred(p: P, who: Signer, dataset_id: int, version: int) -> dict[str, Any]:
        return p.shred(dataset_id, version, who)

    # ------------------------------------------------------------------ public verification

    @app.post("/api/verify/file", tags=["verify"])
    async def verify_file(
        p: P,
        file: Annotated[UploadFile, File()],
        dataset_id: Annotated[int | None, Form()] = None,
        version: Annotated[int | None, Form()] = None,
    ) -> dict[str, Any]:
        data = await read_upload(file)
        return await run_in_threadpool(p.verify_file, data, dataset_id, version)

    @app.post("/api/verify/record", tags=["verify"])
    def verify_record(p: P, body: RecordCheck) -> dict[str, Any]:
        return p.verify_record(body.dataset_id, body.version, body.index, body.canonical, body.record, body.proof)

    web_root = resources.files("dataledger").joinpath("web")
    app.mount("/", StaticFiles(directory=str(web_root), html=True), name="console")
    return app
