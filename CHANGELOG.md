# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-11-16

### Contracts
- Added `AccessLedger.requestAccessWithSig`: consumers sign an EIP-712 access request off-chain and anyone can
  relay it, so asking for access needs no gas. Smart-account signatures are checked with ERC-1271. Added
  `hashAccessRequest`, `nonces` and the ERC-5267 `eip712Domain`.
- All three ledgers use `AccessControlDefaultAdminRules`: one admin, handed over in two steps after a delay.
  Constructors take the delay; `Deploy.s.sol` reads `ADMIN_TRANSFER_DELAY` and can start the hand-over to
  `FINAL_ADMIN_ADDRESS` (a multisig or timelock).
- `DataRegistry` and `AccessLedger` support `multicall`.
- Solidity 0.8.38 on the Prague EVM, OpenZeppelin 5.7, forge-std 1.17. Lineage linking moved to a private helper.
- Slither runs with no findings; a gas snapshot covers every unit test; testnet RPC aliases and Etherscan V2
  verification for Sepolia, Base, Arbitrum, Optimism and Polygon Amoy.

### Service
- API requests are signed as EIP-712 typed data bound to the chain and deployment, and cover an RFC 9530
  `Content-Digest` of the body. ERC-1271 smart accounts can sign. `GET /api/auth/domain` publishes the domain.
- Gasless relay: `POST /api/relay/access-requests/prepare` and `POST /api/relay/access-requests`, rate limited per
  account. `dataledger request-access --gasless`.
- PostgreSQL support with Alembic migrations (`dataledger db upgrade`, `db current`); 1.0.0 databases are stamped
  and upgraded in place. Migrations take a PostgreSQL advisory lock so several pods can start together.
- S3-compatible object store (`DATALEDGER_OBJECT_STORE=s3`).
- The indexer runs as its own process (`dataledger index --metrics-port`), stops cleanly on SIGTERM and needs no
  encryption keys. The indexer reads grant purposes from `multicall` batches.
- Prometheus metrics at `/metrics`, JSON logs with request ids, OpenTelemetry traces (`otel` extra), `/healthz` and
  `/readyz`, security headers and a Content-Security-Policy for the console, optional CORS and HSTS.
- Python 3.14 (3.12+ supported), web3.py 8, FastAPI 0.163, SQLAlchemy 2.1. mypy and branch coverage gates.
- Fixed: on PostgreSQL, `records_anchored` in the overview came back as a decimal.
- The API reports the version from the package metadata (`/api/health`, OpenAPI), not a hard-coded string.

### Delivery
- Images are built for linux/amd64 and linux/arm64 with SBOM and provenance attestations (`docker-bake.hcl`),
  from digest-pinned bases (Python 3.14 on Debian trixie, Foundry 1.9.0). The service image has a health check.
- Compose stack: PostgreSQL, a migration job, separate API and indexer, read-only non-root containers without
  capabilities, ports bound to localhost, and an `observability` profile with Prometheus and a Grafana dashboard.
- Helm chart in `deploy/helm/dataledger` with a values schema, probes, PDB, HPA, ServiceMonitor and NetworkPolicy.
- `Makefile` with every quality gate (`make check`), pre-commit hooks, `.editorconfig`.

### Upgrading
- Contracts changed: deploy them again and point the service at the new `deployments/<chainId>.json`.
- Docker Compose: `docker compose down -v`, then `docker compose up -d`.

## [1.0.0] - 2026-11-07

First release: DataRegistry, AccessLedger and QualityLedger; the Python data service with anchoring, envelope
encryption and crypto-shredding, the access gateway, record proofs, verification, the event indexer, the web
console and the CLI; reference datasets and the governance scenario; Docker images and a compose stack.

[1.1.0]: https://github.com/sadrulemail/blockchain-data-management/compare/d0b5150...main
[1.0.0]: https://github.com/sadrulemail/blockchain-data-management/commit/d0b5150
