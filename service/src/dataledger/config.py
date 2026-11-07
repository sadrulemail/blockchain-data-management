"""Runtime settings, read from ``DATALEDGER_*`` environment variables or a local ``.env`` file."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DATALEDGER_", env_file=".env", extra="ignore")

    rpc_url: str = "http://127.0.0.1:8545"
    deployment_file: Path = Path("../contracts/deployments/31337.json")
    database_url: str = "sqlite:///./var/dataledger.db"
    object_store_dir: Path = Path("./var/objects")
    master_keys: SecretStr = SecretStr("")
    gateway_private_key: SecretStr | None = None

    api_url: str = "http://127.0.0.1:8000"
    directory_file: Path | None = None  # optional JSON {address: label} shown in the console
    auth_max_age_seconds: int = 300

    indexer_poll_seconds: float = 1.0
    indexer_confirmations: int = 0
    indexer_batch_blocks: int = 2_000


@lru_cache
def get_settings() -> Settings:
    return Settings()
