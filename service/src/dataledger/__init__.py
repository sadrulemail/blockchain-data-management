"""Off-chain service of the blockchain data management platform."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("dataledger")  # single source of truth: [project].version in pyproject.toml
except PackageNotFoundError:  # pragma: no cover - running from a source tree without installing
    __version__ = "0.0.0+unknown"
