"""Command line for publishers, consumers, auditors and operators."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Annotated

import typer
from eth_account import Account
from eth_account.signers.local import LocalAccount

from .canonical import Schema
from .chain import Chain, ChainError, Classification, Deployment, VersionStatus
from .client import ApiClient, ApiError
from .config import get_settings
from .crypto import KeyRing
from .workflows import audit_quality, publish_version, register_dataset

app = typer.Typer(help="DataLedger: blockchain-anchored data management.", no_args_is_help=True)

KeyEnv = Annotated[str, typer.Option("--key-env", help="Environment variable that holds the signer's private key.")]
DAY = 86_400


def _account(key_env: str) -> LocalAccount:
    key = os.environ.get(key_env)
    if not key:
        raise typer.BadParameter(f"set {key_env} to the signer's private key")
    return Account.from_key(key)


def _chain() -> Chain:
    s = get_settings()
    return Chain(s.rpc_url, Deployment.load(s.deployment_file))


def _api(account: LocalAccount | None = None) -> ApiClient:
    return ApiClient(get_settings().api_url, account)


def _print(data: object) -> None:
    typer.echo(json.dumps(data, indent=2, default=str))


def _parse_parent(value: str) -> tuple[int, int]:
    dataset, sep, version = value.partition(":")
    if not sep or not dataset.isdigit() or not version.isdigit():
        raise typer.BadParameter("parents look like DATASET:VERSION, e.g. 2:1")
    return int(dataset), int(version)


# ---------------------------------------------------------------------- operator


@app.command()
def serve(
    host: str = "127.0.0.1",
    port: int = 8000,
    indexer: Annotated[bool, typer.Option(help="Run the event indexer in the same process.")] = True,
) -> None:
    """Run the API, the web console and (by default) the indexer."""
    import uvicorn

    from .api import create_app

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    uvicorn.run(create_app(start_indexer=indexer), host=host, port=port)


@app.command()
def index(once: bool = False) -> None:
    """Run the event indexer on its own (for split deployments)."""
    import threading

    from .platform import Platform

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    platform = Platform.from_settings(get_settings())
    if once:
        typer.echo(f"applied {platform.indexer.sync()} events; cursor at block {platform.indexer.cursor()}")
        return
    platform.indexer.run_forever(threading.Event(), get_settings().indexer_poll_seconds)


@app.command()
def keygen(kid: str = "") -> None:
    """Print a new key-encryption key entry for DATALEDGER_MASTER_KEYS."""
    typer.echo(f"DATALEDGER_MASTER_KEYS={KeyRing.generate_entry(kid or None)}")


@app.command("rotate-keys")
def rotate_keys() -> None:
    """Re-wrap every data key under the first (active) entry of DATALEDGER_MASTER_KEYS."""
    from .platform import Platform

    moved = Platform.from_settings(get_settings()).rotate_keys()
    typer.echo(f"re-wrapped {moved} data keys")


# ---------------------------------------------------------------------- publisher


@app.command()
def register(
    schema: Annotated[Path, typer.Option(exists=True, help="Schema JSON file.")],
    classification: Annotated[str, typer.Option(help="public | internal | confidential | restricted")] = "internal",
    key_env: KeyEnv = "DATALEDGER_PRIVATE_KEY",
) -> None:
    """Register a dataset owned by the signer."""
    owner = _account(key_env)
    with _api(owner) as api:
        dataset_id = register_dataset(
            _chain(), api, owner, Schema.from_file(schema), Classification.parse(classification)
        )
    _print({"dataset_id": dataset_id})


@app.command()
def publish(
    dataset: Annotated[int, typer.Option(help="Dataset id.")],
    file: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
    parent: Annotated[list[str] | None, typer.Option(help="Upstream version DATASET:VERSION (repeatable).")] = None,
    key_env: KeyEnv = "DATALEDGER_PRIVATE_KEY",
) -> None:
    """Upload a CSV and anchor it as the next version."""
    signer = _account(key_env)
    parents = [_parse_parent(p) for p in parent or []]
    with _api(signer) as api:
        result = publish_version(_chain(), api, signer, dataset, file.read_bytes(), file.name, parents)
    _print({"dataset_id": result.dataset_id, "version": result.version, **result.staged})


@app.command()
def status(
    dataset: int,
    version: int,
    to: Annotated[str, typer.Option(help="deprecated | withdrawn")],
    reason: str = "",
    key_env: KeyEnv = "DATALEDGER_PRIVATE_KEY",
) -> None:
    """Deprecate or withdraw a version."""
    _chain().set_version_status(_account(key_env), dataset, version, VersionStatus.parse(to), reason)
    typer.echo(f"dataset {dataset} v{version} -> {to}")


@app.command()
def steward(dataset: int, account: str, remove: bool = False, key_env: KeyEnv = "DATALEDGER_PRIVATE_KEY") -> None:
    """Add or remove a steward (owner only)."""
    _chain().set_steward(_account(key_env), dataset, account, not remove)
    typer.echo(f"{account} {'removed from' if remove else 'added to'} stewards of dataset {dataset}")


@app.command()
def grant(
    dataset: int,
    to: str,
    purpose: str,
    days: int = 30,
    key_env: KeyEnv = "DATALEDGER_PRIVATE_KEY",
) -> None:
    """Grant time-boxed access directly."""
    _chain().grant_access(_account(key_env), dataset, to, days * DAY, purpose)
    typer.echo(f"granted {to} access to dataset {dataset} for {days} days")


@app.command()
def revoke(dataset: int, account: str, key_env: KeyEnv = "DATALEDGER_PRIVATE_KEY") -> None:
    """Revoke a grant."""
    _chain().revoke_access(_account(key_env), dataset, account)
    typer.echo(f"revoked {account} on dataset {dataset}")


@app.command()
def approve(request: int, days: int = 30, key_env: KeyEnv = "DATALEDGER_PRIVATE_KEY") -> None:
    """Approve an access request."""
    _chain().approve_request(_account(key_env), request, days * DAY)
    typer.echo(f"request {request} approved for {days} days")


@app.command()
def reject(request: int, reason: str, key_env: KeyEnv = "DATALEDGER_PRIVATE_KEY") -> None:
    """Reject an access request."""
    _chain().reject_request(_account(key_env), request, reason)
    typer.echo(f"request {request} rejected")


@app.command()
def shred(
    dataset: int, version: int, reason: str = "erasure request", key_env: KeyEnv = "DATALEDGER_PRIVATE_KEY"
) -> None:
    """Withdraw a version on-chain and destroy its data key (owner only)."""
    signer = _account(key_env)
    chain = _chain()
    if chain.version_status(dataset, version) != VersionStatus.WITHDRAWN:
        chain.set_version_status(signer, dataset, version, VersionStatus.WITHDRAWN, reason)
    with _api(signer) as api:
        _print(api.shred(dataset, version))


# ---------------------------------------------------------------------- consumer


@app.command("request-access")
def request_access(dataset: int, purpose: str, key_env: KeyEnv = "DATALEDGER_PRIVATE_KEY") -> None:
    """Ask the dataset owner for access, stating the purpose."""
    request_id = _chain().request_access(_account(key_env), dataset, purpose)
    _print({"request_id": request_id})


@app.command()
def download(
    dataset: int,
    version: int,
    out: Annotated[Path, typer.Option(help="Where to write the file.")],
    key_env: KeyEnv = "DATALEDGER_PRIVATE_KEY",
) -> None:
    """Download a version; the read is logged on-chain before data is returned."""
    with _api(_account(key_env)) as api:
        data, headers = api.download(dataset, version)
    out.write_bytes(data)
    _print({"written": str(out), "bytes": len(data), **headers})


@app.command()
def prove(dataset: int, version: int, row: int, key_env: KeyEnv = "DATALEDGER_PRIVATE_KEY") -> None:
    """Fetch one record with its Merkle proof."""
    with _api(_account(key_env)) as api:
        _print(api.record_proof(dataset, version, row))


@app.command("verify-file")
def verify_file(
    file: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
    dataset: int | None = None,
    version: int | None = None,
) -> None:
    """Check a file against the chain (public, no signature needed)."""
    with _api() as api:
        _print(api.verify_file(file.read_bytes(), dataset, version))


@app.command("verify-record")
def verify_record(proof_file: Annotated[Path, typer.Argument(exists=True)]) -> None:
    """Check a saved record proof on-chain (public)."""
    with _api() as api:
        _print(api.verify_record(json.loads(proof_file.read_text(encoding="utf-8"))))


# ---------------------------------------------------------------------- auditor


@app.command()
def quality(dataset: int, version: int, key_env: KeyEnv = "DATALEDGER_PRIVATE_KEY") -> None:
    """Run the quality checks on a version and attest the result on-chain (auditor role)."""
    auditor = _account(key_env)
    with _api(auditor) as api:
        report = audit_quality(_chain(), api, auditor, dataset, version)
    _print({k: report[k] for k in ("dataset_id", "version", "score_bps", "passed", "report_uri")})


def main() -> None:
    """Console entry point: prints chain and API errors as one line instead of a traceback."""
    try:
        app()
    except (ApiError, ChainError) as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise SystemExit(1) from None


if __name__ == "__main__":  # pragma: no cover
    main()
