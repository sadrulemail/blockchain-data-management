"""HTTP API and web console."""

from __future__ import annotations

import json
import logging
import threading
from contextlib import asynccontextmanager
from importlib import resources
from pathlib import Path
from typing import Annotated, Any

from eth_utils import to_checksum_address
from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from . import __version__, queries
from .auth import AuthError, RequestVerifier
from .canonical import SchemaError
from .chain import ChainError
from .config import Settings, get_settings
from .platform import Forbidden, Gone, IntegrityFailure, InvalidInput, NotFound, Platform

log = logging.getLogger(__name__)
MAX_UPLOAD_BYTES = 50 * 1024 * 1024


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


def get_platform(request: Request) -> Platform:
    return request.app.state.platform


def get_signer(request: Request) -> str:
    try:
        return request.app.state.verifier.verify(request.method, request.url.path, dict(request.headers))
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


P = Annotated[Platform, Depends(get_platform)]
Signer = Annotated[str, Depends(get_signer)]


def create_app(platform: Platform | None = None, *, start_indexer: bool = True) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        settings: Settings = platform.settings if platform else get_settings()
        app.state.platform = platform or Platform.from_settings(settings)
        app.state.verifier = RequestVerifier(settings.auth_max_age_seconds)
        stop = threading.Event()
        worker = None
        if start_indexer:
            worker = threading.Thread(
                target=app.state.platform.indexer.run_forever,
                args=(stop, settings.indexer_poll_seconds),
                name="indexer",
                daemon=True,
            )
            worker.start()
        yield
        stop.set()
        if worker:
            worker.join(timeout=5)

    app = FastAPI(
        title="DataLedger API",
        version=__version__,
        description="Blockchain-anchored data management: registry, lineage, access control and verification.",
        lifespan=lifespan,
    )

    @app.exception_handler(NotFound)
    async def _not_found(_: Request, exc: NotFound):
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(Forbidden)
    async def _forbidden(_: Request, exc: Forbidden):
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(Gone)
    async def _gone(_: Request, exc: Gone):
        return JSONResponse(status_code=410, content={"detail": str(exc)})

    @app.exception_handler(IntegrityFailure)
    async def _integrity(_: Request, exc: IntegrityFailure):
        log.error("integrity failure: %s", exc)
        return JSONResponse(status_code=409, content={"detail": str(exc), "integrity": False})

    @app.exception_handler(InvalidInput)
    @app.exception_handler(SchemaError)
    async def _invalid(_: Request, exc: Exception):
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(ChainError)
    async def _chain(_: Request, exc: ChainError):
        return JSONResponse(status_code=400, content={"detail": str(exc), "error": exc.error})

    async def read_upload(upload: UploadFile) -> bytes:
        data = await upload.read(MAX_UPLOAD_BYTES + 1)
        if len(data) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="file larger than 50 MB")
        return data

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
            "contracts": p.chain.deployment.to_dict(),
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


def run() -> None:  # pragma: no cover - uvicorn entry
    import uvicorn

    uvicorn.run("dataledger.api:create_app", factory=True, host="127.0.0.1", port=8000)
