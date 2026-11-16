# syntax=docker/dockerfile:1.12
#
# Two images from one file, for linux/amd64 and linux/arm64:
#   docker buildx build --target contracts -t sadrulemail/dataledger-contracts:1.1.0 .
#   docker buildx build --target service   -t sadrulemail/dataledger:1.1.0 .
# `make images` builds both for both platforms with an SBOM and provenance attestation.
#
# Base images are pinned by digest; bump the tag and the digest together.

ARG FOUNDRY_IMAGE=ghcr.io/foundry-rs/foundry:v1.9.0@sha256:3a392c18f9b16e665e932de159fb6fa9ed972c4b4352f2f76a1a8c7ca9b57d39
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.13.8@sha256:5cc1805e2426484abca4ad46ea783bab281fdb225fd82d8ce6d66a81254bac85
ARG PYTHON_IMAGE=python:3.14-slim-trixie@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f

FROM ${UV_IMAGE} AS uv

# ------------------------------------------------------------------------------------------------ contracts
# Foundry toolchain with the compiled ledgers. `chain` runs anvil, `deploy` deploys to RPC_URL.
FROM ${FOUNDRY_IMAGE} AS contracts
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
LABEL org.opencontainers.image.title="dataledger-contracts" \
      org.opencontainers.image.description="DataRegistry, AccessLedger and QualityLedger with the Foundry toolchain: run a local chain or deploy the ledgers" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
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
RUN forge build --skip test

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
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --all-extras --no-install-project
COPY service/src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --all-extras --no-editable

# ------------------------------------------------------------------------------------------------ service
# API gateway, event indexer, migrations, web console and CLI.
FROM ${PYTHON_IMAGE} AS service
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
LABEL org.opencontainers.image.title="dataledger" \
      org.opencontainers.image.description="DataLedger data service: anchoring, encryption, event indexer, EIP-712 signed-request API gateway, web console and CLI" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
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
    PYTHONDONTWRITEBYTECODE=1 \
    DATALEDGER_DEPLOYMENT_FILE=/deployments/31337.json \
    DATALEDGER_DATABASE_URL=sqlite:////data/dataledger.db \
    DATALEDGER_OBJECT_STORE_DIR=/data/objects \
    DATALEDGER_DIRECTORY_FILE=/app/datasets/directory.json \
    DATALEDGER_LOG_FORMAT=json

WORKDIR /app
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]
ENTRYPOINT ["entrypoint"]
CMD ["dataledger", "serve", "--host", "0.0.0.0", "--port", "8000"]
