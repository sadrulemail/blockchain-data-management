# Contributing

## Setup

```bash
git clone --recurse-submodules https://github.com/sadrulemail/blockchain-data-management.git
```

```bash
cd blockchain-data-management && make install
```

You need [Foundry](https://book.getfoundry.sh/getting-started/installation), [uv](https://docs.astral.sh/uv/) and
Docker. Install the commit hooks once:

```bash
uvx pre-commit install
```

## Working on a change

- `make test` runs the contract and service suites; the end-to-end tests start their own anvil.
- `make check` runs every gate: formatting, linters, mypy, ABI drift, tests with coverage, gas snapshot,
  Slither and the Helm chart. A change is ready when it passes.
- `make test-postgres` repeats the end-to-end suite on PostgreSQL 18.

When you change a contract, run `make abi` and commit the updated ABIs in `service/src/dataledger/abi/`, and
`make gas` when gas use changes on purpose.

When you change a table in `service/src/dataledger/db.py`, add an Alembic revision:

```bash
cd service && uv run alembic -c src/dataledger/migrations/alembic.ini revision --autogenerate -m "describe it"
```

A test fails when the revisions and the table definitions drift apart.

## Style

- Solidity: `forge fmt`, custom errors, an event for every state change, NatSpec on public functions.
- Python: ruff (lint and format, 120 columns), type hints checked by mypy.
- Commits: short imperative subject lines ("Add S3 object store"), one topic per commit.
- Record user-facing changes in [CHANGELOG.md](CHANGELOG.md).

## Releasing

1. Bump `version` in `service/pyproject.toml`, `VERSION` in `docker-bake.hcl`, `version` and `appVersion` in the
   chart, and the image tag default in `docker-compose.yml`.
2. Move the changelog entries under the new version.
3. `make check`, then `make release-images` to build and push both platforms with SBOM and provenance.
