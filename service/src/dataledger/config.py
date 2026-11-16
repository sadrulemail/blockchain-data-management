"""Runtime settings, read from ``DATALEDGER_*`` environment variables or a local ``.env`` file."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DATALEDGER_", env_file=".env", extra="ignore")

    # Chain
    rpc_url: str = "http://127.0.0.1:8545"
    deployment_file: Path = Path("../contracts/deployments/31337.json")
    gateway_private_key: SecretStr | None = None

    # Read models. SQLite for a laptop, PostgreSQL (postgresql+psycopg://...) anywhere else.
    database_url: str = "sqlite:///./var/dataledger.db"
    auto_migrate: bool = True  # run Alembic migrations on start; turn off when a migrate job owns the schema

    # Object store
    object_store: Literal["local", "s3"] = "local"
    object_store_dir: Path = Path("./var/objects")
    s3_bucket: str = ""
    s3_prefix: str = "objects"
    s3_endpoint_url: str | None = None  # S3-compatible services (MinIO, Ceph, R2)
    s3_region: str | None = None

    # Envelope encryption: key-encryption keys `kid:base64key`, newest first.
    master_keys: SecretStr = SecretStr("")

    # API
    api_url: str = "http://127.0.0.1:8000"
    directory_file: Path | None = None  # optional JSON {address: label} shown in the console
    auth_max_age_seconds: int = Field(default=300, ge=10, le=3_600)
    cors_origins: Annotated[list[str], NoDecode] = []
    hsts: bool = False  # set behind TLS
    relay_enabled: bool = True  # gateway pays gas for EIP-712 signed access requests
    relay_max_per_hour: int = Field(default=60, ge=0)  # per requester address
    max_upload_mb: int = Field(default=50, ge=1, le=2_048)

    # Indexer
    run_indexer: bool = True  # run inside the API process; set false when `dataledger index` runs separately
    indexer_poll_seconds: float = 1.0
    indexer_confirmations: int = 0
    indexer_batch_blocks: int = 2_000

    # Operations
    log_level: str = "INFO"
    log_format: Literal["text", "json"] = "text"
    metrics_enabled: bool = True

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [o.strip() for o in value.split(",") if o.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
