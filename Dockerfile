# syntax=docker/dockerfile:1.7
#
# Two images from one file:
#   docker build --target contracts --build-arg VERSION=1.0.0 -t sadrulemail/dataledger-contracts:1.0.0 .
#   docker build --target service   --build-arg VERSION=1.0.0 -t sadrulemail/dataledger:1.0.0 .
#
# docker-compose.yml wires them into a local chain, the contract deployment and the data service.

ARG FOUNDRY_IMAGE=ghcr.io/foundry-rs/foundry:v1.5.1
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.11.26
ARG PYTHON_IMAGE=python:3.12-slim-bookworm

FROM ${UV_IMAGE} AS uv

# ------------------------------------------------------------------------------------------------ contracts
# Foundry toolchain with the compiled ledgers. `chain` runs anvil, `deploy` deploys to RPC_URL.
FROM ${FOUNDRY_IMAGE} AS contracts
ARG VERSION=dev
LABEL org.opencontainers.image.title="dataledger-contracts" \
      org.opencontainers.image.description="DataRegistry, AccessLedger and QualityLedger with the Foundry toolchain: run a local chain or deploy the ledgers" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.authors="Sadrul" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/sadrulemail/blockchain-data-management"

USER root
# Named volumes copy a directory's ownership only when it has content, hence the .keep files.
RUN mkdir -p /app/deployments /data && touch /app/deployments/.keep /data/.keep \
 && chown -R foundry:foundry /app /data
COPY --chmod=755 docker/contracts-entrypoint.sh /usr/local/bin/entrypoint
USER foundry
WORKDIR /app
COPY --chown=foundry:foundry contracts/ ./
RUN forge build

EXPOSE 8545
ENTRYPOINT ["entrypoint"]
CMD ["chain"]

# ------------------------------------------------------------------------------------------------ service build
FROM ${PYTHON_IMAGE} AS service-build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /src
COPY service/pyproject.toml service/uv.lock service/.python-version ./
RUN --mount=type=cache,target=/root/.cache/uv uv sync --locked --no-dev --no-install-project
COPY service/src ./src
RUN --mount=type=cache,target=/root/.cache/uv uv sync --locked --no-dev --no-editable

# ------------------------------------------------------------------------------------------------ service
# API gateway, event indexer, web console and CLI.
FROM ${PYTHON_IMAGE} AS service
ARG VERSION=dev
LABEL org.opencontainers.image.title="dataledger" \
      org.opencontainers.image.description="DataLedger data service: anchoring, encryption, event indexer, signed-request API gateway, web console and CLI" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.authors="Sadrul" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/sadrulemail/blockchain-data-management"

RUN useradd --system --uid 10001 --user-group --create-home --home-dir /home/dataledger dataledger \
 && mkdir -p /data /deployments \
 && touch /data/.keep \
 && chown -R dataledger:dataledger /data
COPY --from=service-build /opt/venv /opt/venv
COPY datasets/ /app/datasets/
COPY scripts/load_reference_data.py /app/scripts/
COPY --chmod=755 docker/service-entrypoint.sh /usr/local/bin/entrypoint

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    DATALEDGER_DEPLOYMENT_FILE=/deployments/31337.json \
    DATALEDGER_DATABASE_URL=sqlite:////data/dataledger.db \
    DATALEDGER_OBJECT_STORE_DIR=/data/objects \
    DATALEDGER_DIRECTORY_FILE=/app/datasets/directory.json

WORKDIR /app
USER dataledger
EXPOSE 8000
ENTRYPOINT ["entrypoint"]
CMD ["dataledger", "serve", "--host", "0.0.0.0", "--port", "8000"]
