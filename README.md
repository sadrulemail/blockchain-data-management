# Blockchain Data Management

**DataLedger** is a data-management platform that uses a blockchain as a shared, tamper-evident control plane for
enterprise datasets. The data itself never goes on-chain: files stay off-chain, encrypted per object. What the chain
holds is everything you need to *trust* the data: fingerprints of every version, record-level Merkle roots, lineage
between datasets, purpose-bound access grants, a log of every read, and independent data-quality attestations.

![Overview](docs/screenshots/overview.png)

| | |
|---|---|
| **Smart contracts** | Solidity 0.8.38 (Prague EVM), OpenZeppelin 5.7, Foundry 1.9: 3 contracts, 85 tests (unit, fuzz, invariant, cross-language golden vector), 100% line and branch coverage, no Slither findings |
| **Data service** | Python 3.14, FastAPI, web3.py 8, SQLAlchemy 2.1 with Alembic migrations: ingestion, envelope encryption, access gateway, public verification |
| **Wallets** | EIP-712 typed-data signatures for API calls and access requests, ERC-1271 smart accounts (Safe, passkey wallets, EIP-7702 delegates), gasless access requests relayed by the gateway |
| **Indexer** | Event-sourced read models in PostgreSQL 18 (SQLite on a laptop), rebuilt from chain logs, re-org aware, runs as its own process |
| **Storage** | AES-256-GCM with a key per object, on any S3-compatible bucket or a volume; crypto-shredding for erasure |
| **Console** | Dependency-free web console: catalogue, versions, lineage graph, access, audit trail, verification |
| **Operations** | Prometheus metrics and a Grafana dashboard, JSON logs with request ids, OpenTelemetry traces, liveness and readiness probes |
| **Delivery** | Docker images for linux/amd64 and linux/arm64 with SBOM and provenance, a hardened Docker Compose stack, a Helm chart for Kubernetes |
| **Quality gates** | 196 automated tests across both languages, end-to-end runs against a real chain on SQLite and PostgreSQL, one `make check` |

---

## Contents

1. [Why a blockchain for data management](#why-a-blockchain-for-data-management)
2. [Core concepts](#core-concepts)
3. [Architecture](#architecture)
4. [Key flows](#key-flows)
5. [Smart contracts](#smart-contracts)
6. [Data service and API](#data-service-and-api)
7. [Reference scenario](#reference-scenario)
8. [Screens](#screens)
9. [Run with Docker](#run-with-docker)
10. [Deploy to Kubernetes](#deploy-to-kubernetes)
11. [Operations](#operations)
12. [Run it locally](#run-it-locally)
13. [Quality gates](#quality-gates)
14. [Design decisions and trade-offs](#design-decisions-and-trade-offs)
15. [Taking it to production](#taking-it-to-production)
16. [Project structure](#project-structure)

---

## Why a blockchain for data management

When data moves between teams, business units or companies, the hard questions are not about storage. They are
about trust:

- *Is the file I received exactly what the producer published, or was it edited along the way?*
- *Which upstream data was this report built from, and is any of it now known to be bad?*
- *Who has read this dataset, under which approval, and for what purpose?*
- *Did anyone independent check the quality before we used it?*

A conventional database can store the answers, but whoever administers that database can also rewrite them. A
blockchain changes the trust model: the records are append-only, replicated, time-stamped by consensus, and the
rules that govern them (who may publish, who may grant access, what a valid lineage link is) are enforced by code
that every party can read. No single administrator, including the platform operator, can quietly change history.

The design principle is a strict split between what the ledger is good at and what it is not:

| On-chain (public, permanent, small) | Off-chain (private, erasable, large) |
|---|---|
| Dataset registry, owners, stewards, classification | The data files themselves, encrypted at rest |
| Per version: Merkle root, SHA-256 fingerprint, record count, schema hash, storage pointer | Schema documents and quality reports (content-addressed, hash anchored on-chain) |
| Lineage links between versions | Data keys, wrapped by a key-encryption key |
| Access requests, purpose hashes, grants with expiry, revocations | Address-book labels shown in the console |
| One event per read, with a receipt hash | SQL read models rebuilt from chain events |
| Quality attestations: auditor, score, verdict, report hash | |

Personal data never touches the chain. That keeps the ledger small and cheap, and it is what makes the right to
erasure possible (see [crypto-shredding](#8-privacy-and-the-right-to-erasure)).

---

## Core concepts

### 1. Anchoring: commit to the data without publishing it

When a version is published, the service computes two commitments and the owner anchors them on-chain in one
transaction:

- **File fingerprint**: `SHA-256(file bytes)`. Anyone holding the exact file can prove it is the published one.
- **Merkle root over records**: every row is turned into a *canonical record*, hashed into a leaf, and the leaves
  are folded into a binary Merkle tree. The 32-byte root commits to every record and its position.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/diagrams/merkle-tree-dark.png">
  <img src="docs/diagrams/merkle-tree.png" width="953" alt="Merkle tree: five records are hashed into leaves, paired level by level, and the root is stored in DataRegistry">
</picture>

**Canonical records.** Two files can hold the same data and still differ byte for byte (`12.50` vs `12.5`,
column order, CRLF vs LF, a leading zero in an id). Before hashing, every row is normalised against the dataset
schema: integers and decimals are parsed and written in one form, dates and timestamps are written in ISO-8601,
booleans become `true`/`false`, keys are sorted and JSON is written without whitespace. Cells that do not parse
keep their raw text, so any file can be anchored and the quality checks report the bad cells.

**Leaf design.** `leaf = keccak256(keccak256(abi.encode(index, recordBytes)))`.
Encoding the position binds each record to its row, so a valid record cannot be replayed at another index.
Hashing twice means a leaf can never be confused with an internal 64-byte node (second-preimage protection).
Pairs are hashed in sorted order, which is the convention used by OpenZeppelin's `MerkleProof`, so the contract
verifies proofs with audited library code. The Python and Solidity implementations share a golden test vector.

### 2. Record-level proofs

A consumer can prove that *one row* belongs to a published version without revealing any other row. The proof
is the list of sibling hashes from the leaf to the root: for the 1,500-row orders extract that is 11 hashes. The
contract checks it in a `view` call (`DataRegistry.verifyRecord`), so verification is free and needs no
account. An auditor, regulator or counterparty can check a single invoice line against the anchored version.

### 3. Verification levels

Uploading a file to the public verify endpoint (no account needed) returns one of four answers:

| Result | Meaning |
|---|---|
| `exact_match` | The SHA-256 of the file is anchored; the response says which dataset version it is. |
| `records_match` | The bytes differ (formatting) but every canonical record matches the version's Merkle root. |
| `mismatch` | The records do not reproduce the anchored root: the data was changed. |
| `unknown` | The fingerprint is not anchored and no version was named to compare against. |

Callers with access can also ask for a **row-level diff** that names the exact rows that changed, were added or
were removed, by comparing leaves with the anchored tree.

### 4. Versions and lifecycle

Versions are immutable. A correction is a new version, never an edit. Each version carries its own schema hash
(schema evolution is visible on-chain through `SchemaChanged`) and moves through a one-way lifecycle:

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/diagrams/version-lifecycle-dark.png">
  <img src="docs/diagrams/version-lifecycle.png" width="275" alt="Version lifecycle: Active becomes Deprecated when superseded; Active or Deprecated can be Withdrawn, which is final">
</picture>

*Deprecated* versions are still served and still valid as lineage parents. *Withdrawn* versions are never served
again by the gateway and can no longer be used as parents or attested. Datasets can be archived (closed for new
versions while old ones stay verifiable), reclassified, and handed to a new owner through a two-step transfer.

### 5. Lineage

When a version is committed it names the exact upstream versions it was built from (up to 16). The contract
rejects parents that do not exist, are withdrawn, or are listed twice, so the lineage graph on-chain is always
closed and well-formed (an invariant checked by fuzzing). Because parents are *versions* rather than datasets,
lineage answers precise questions: if a customer extract is withdrawn after an erasure request, the console shows
exactly which downstream versions were derived from it.

### 6. Consent and access control

Every dataset has a classification: `Public`, `Internal`, `Confidential` or `Restricted`. Public data is
readable by anyone who signs a request. For everything else:

1. A consumer calls `requestAccess` with a stated purpose. The purpose text is emitted in the event and its
   keccak hash is stored, so the approval is bound to that purpose. A consumer without gas signs the same request
   as EIP-712 typed data instead, and the gateway submits it with `requestAccessWithSig`; the contract checks the
   signature itself (ECDSA for wallets, ERC-1271 for smart accounts), so the gateway cannot forge a request.
2. The owner or a steward approves with a duration (at most 365 days) or rejects with a reason.
3. Grants can be revoked by the owner or renounced by the grantee at any time.

The data gateway enforces this at read time. For every download it checks `hasAccess` **live on-chain** (not
from a cache), verifies the stored file against the anchored fingerprint and Merkle root, and then calls
`AccessLedger.logAccess`, which rechecks access inside the contract and emits `DataAccessed` with a receipt hash.
Only after that transaction succeeds does data leave the gateway. A bug or a compromised gateway cannot read data
silently: every read either leaves evidence on-chain or does not happen.

### 7. Independent data-quality attestations

An auditor (`AUDITOR_ROLE`) reads a version through the gateway like any consumer, runs the checks locally
(required values, type conformance, primary-key uniqueness, duplicate records), publishes the report as a
content-addressed document and signs `QualityLedger.attest` with the score and the report hash. Two rules keep
attestations meaningful: an auditor cannot attest a dataset it owns or stewards (`ConflictOfInterest`), and each
auditor attests a version once. Reports list row positions only, never cell values, so a report can be shared
next to a confidential dataset.

### 8. Privacy and the right to erasure

Blockchains are immutable and privacy laws grant a right to erasure. The platform reconciles the two with
**envelope encryption and crypto-shredding**:

- Each stored object is sealed with its own random 256-bit data key (AES-256-GCM). The ciphertext is bound to the
  file fingerprint as associated data, so a sealed object cannot be swapped for another.
- The data key is wrapped by a key-encryption key from a key ring (named keys, newest first). Rotation re-wraps
  data keys without touching the objects (`dataledger rotate-keys`).
- Erasure: the owner withdraws the version on-chain and the gateway destroys the wrapped data key and the
  ciphertext. What remains on-chain is a set of hashes that can no longer be linked to any recoverable content.
  The withdrawal reason and the off-chain shred event stay in the audit trail.

Objects are content-addressed by the SHA-256 of their sealed bytes, so storage corruption is detected on every
read, before decryption.

### 9. Event sourcing

The SQL database behind the API is a *projection* of chain events, not a source of truth. The indexer reads logs
in block ranges, applies them in `(block, logIndex)` order and commits each batch together with its cursor, so a
crash never leaves half a block applied. It stores the hash of the last processed block; if that block is
replaced (a chain re-organisation), the read models are dropped and rebuilt from the deployment block. A
configurable confirmation depth trades freshness for stability on public networks.

### 10. Trust model

| Threat | What stops it |
|---|---|
| A file is edited after publication | Fingerprint and Merkle root on-chain; `verify/file` and record proofs detect any change |
| Stored ciphertext is corrupted or swapped | Content addressing (SHA-256 of sealed bytes) and AES-GCM authentication bound to the fingerprint |
| The gateway serves data without permission | `logAccess` rechecks access in the contract and reverts; every served read has a chain event |
| An administrator rewrites the audit trail | Events are on-chain; the SQL trail can be rebuilt from logs and compared |
| A record is moved to another row | Leaves encode the row position |
| A leaf is forged from internal nodes | Double-hashed leaves |
| A data owner rubber-stamps their own quality | `ConflictOfInterest` in `QualityLedger` |
| A signed API request is replayed or altered | The EIP-712 signature covers method, path, body digest, time and a one-time nonce, in a domain bound to the chain and the deployment; nonces are remembered for the validity window |
| A relayed access request is forged or replayed | The requester's signature is checked in the contract, with a per-account nonce and a deadline |
| An admin key is mistyped, lost or stolen | The admin role has one holder and moves in two steps, after a delay (2 days by default) |
| Personal data must be erased | Nothing personal is on-chain; crypto-shredding destroys the only key |

---

## Architecture

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/diagrams/architecture-dark.png">
  <img src="docs/diagrams/architecture.png" width="1385" alt="Architecture: publishers, consumers, auditors and verifiers use signed transactions to the contracts and signed requests to the Python data service, which keeps read models in PostgreSQL, objects in S3 and exposes metrics to Prometheus">
</picture>

Writes that change governance state (registering, committing, granting, attesting) are signed by the actor's own
wallet and go straight to the chain. The service never holds those keys. It holds one key of its own, the
gateway key, whose only powers are to log reads and to submit access requests that consumers signed themselves.
The API and the indexer are separate processes that share the PostgreSQL read models, so the API scales
horizontally while exactly one indexer applies chain events.

---

## Key flows

### Publishing a version

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/diagrams/publish-flow-dark.png">
  <img src="docs/diagrams/publish-flow.png" width="1686" alt="Publishing a version: upload to the gateway, schema parse, Merkle tree and SHA-256, encrypted storage, commitVersion on-chain, then indexing">
</picture>

### Reading data under a grant

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/diagrams/read-flow-dark.png">
  <img src="docs/diagrams/read-flow.png" width="1166" alt="Reading under a grant: request and approval on AccessLedger, signed download, live access check, integrity checks and an on-chain read log">
</picture>

### Verifying a single record

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/diagrams/record-proof-dark.png">
  <img src="docs/diagrams/record-proof.png" width="1300" alt="Verifying a single record: the consumer receives a record and its Merkle proof, and anyone checks it with DataRegistry.verifyRecord">
</picture>

---

## Smart contracts

All three contracts use OpenZeppelin `AccessControlDefaultAdminRules`: the admin role has a single holder and
changes hands in two steps after a delay, so a mistyped address or a stolen key cannot take over at once. They use
custom errors and emit an event for every state change. `DataRegistry` is also `Pausable` for emergencies, and
`DataRegistry` and `AccessLedger` support `multicall` to batch several calls in one transaction. The contracts are
deliberately not upgradeable; see [design decisions](#design-decisions-and-trade-offs).

### DataRegistry

| Function | Who | Purpose |
|---|---|---|
| `registerDataset(name, classification, schemaHash, metadataURI)` | `PUBLISHER_ROLE` | Creates a dataset owned by the caller |
| `commitVersion(id, {merkleRoot, contentHash, schemaHash, recordCount, storageURI}, parents[])` | owner, steward | Anchors an immutable version with lineage |
| `setVersionStatus(id, version, status, reason)` | owner, steward | Active → Deprecated → Withdrawn |
| `setSteward`, `setClassification`, `archiveDataset` | owner | Governance of a dataset |
| `updateMetadata` | owner, steward | Points at a new metadata document |
| `transferDatasetOwnership` / `acceptDatasetOwnership` | owner / new owner | Two-step hand-over |
| `verifyRecord(id, version, index, record, proof)` | anyone (view) | Record inclusion proof |
| `locateContent(contentHash)` | anyone (view) | Which version first anchored this file |
| `pause` / `unpause` | `PAUSER_ROLE` | Emergency stop for writes |

Events: `DatasetRegistered`, `VersionCommitted`, `LineageLinked`, `SchemaChanged`, `VersionStatusChanged`,
`StewardUpdated`, `MetadataUpdated`, `ClassificationChanged`, `DatasetArchived`, `OwnershipTransferStarted`,
`OwnershipTransferred`.

### AccessLedger

| Function | Who | Purpose |
|---|---|---|
| `requestAccess(id, purpose)` | anyone | Opens one pending request per dataset and requester |
| `requestAccessWithSig(id, requester, purpose, deadline, signature)` | anyone (a relayer) | Opens a request the requester signed off-chain (EIP-712; ERC-1271 for smart accounts) |
| `hashAccessRequest(...)`, `nonces(account)`, `eip712Domain()` | anyone (view) | The digest to sign, the next nonce and the signing domain (ERC-5267) |
| `approveRequest(requestId, duration)` / `rejectRequest(requestId, reason)` | owner, steward | Decide a request |
| `cancelRequest(requestId)` | requester | Withdraw a pending request |
| `grantAccess(id, grantee, duration, purpose)` / `revokeAccess(id, grantee)` | owner, steward | Direct grants |
| `renounceAccess(id)` | grantee | Give up a grant early |
| `logAccess(id, version, accessor, receiptHash)` | `GATEWAY_ROLE` | Rechecks access, refuses withdrawn versions, emits `DataAccessed` |
| `hasAccess(id, account)` | anyone (view) | Public, owner, steward, or a live unrevoked grant |
| `multicall(calls)` | anyone | Batches calls, such as grants to several teams, in one transaction |

### QualityLedger

| Function | Who | Purpose |
|---|---|---|
| `attest(id, version, scoreBps, passed, reportHash, reportURI)` | `AUDITOR_ROLE`, not a manager of the dataset | One attestation per auditor and version |
| `qualitySummary(id, version)` | anyone (view) | Count, passes and lowest score |

### Gas profile

Measured with `forge test --gas-report` (Prague EVM). Verification calls are `view` and cost nothing when called
off-chain. `contracts/.gas-snapshot` records the gas of every unit test, and `make gas-check` fails when a change
moves it.

| Operation | Gas |
|---|---|
| `registerDataset` | ~166k |
| `commitVersion` (no parents / with lineage links) | ~220k / up to ~342k |
| `requestAccess` / `requestAccessWithSig` (paid by the relayer) | ~145k / ~186k |
| `grantAccess` | ~103k |
| `logAccess` (one read) | ~31k–68k |
| `attest` | ~155k (first attestation) |
| `verifyRecord` | ~9k–10k, free as a view call |

A version costs the same whether the file has ten rows or ten million: only the root goes on-chain.

---

## Data service and API

The Python package `dataledger` (in `service/`) contains:

| Module | Responsibility |
|---|---|
| `canonical.py` | Schemas, typed normalisation, canonical JSON records, record leaves |
| `merkle.py` | Merkle tree, proofs and leaf-level diffs, compatible with OpenZeppelin `MerkleProof` |
| `crypto.py` | Key ring, AES-256-GCM envelope encryption, key rotation |
| `storage.py` | Content-addressed object store: S3-compatible buckets or a local volume (the same four methods fit Azure Blob or IPFS) |
| `chain.py` | Typed contract client, transaction sending, custom-error decoding |
| `indexer.py` | Event indexer with cursor, batch commits and re-org recovery |
| `platform.py` | Gateway operations: ingest, gated reads, proofs, diffs, verification, crypto-shredding |
| `quality.py` | Data-quality checks and reports without cell values |
| `auth.py` | EIP-712 signed requests: body digest, freshness window, nonce replay protection, ERC-1271 for smart accounts |
| `db.py`, `migrations/` | Table definitions and Alembic revisions; `dataledger db upgrade` |
| `observability.py` | JSON logs with request ids, Prometheus metrics, security headers, OpenTelemetry |
| `api.py` | FastAPI app (OpenAPI docs at `/docs`), probes, metrics, the gasless relay and the web console |
| `cli.py` | `dataledger` command line for every role |

### Endpoints

| Method and path | Auth | Description |
|---|---|---|
| `GET /healthz`, `GET /readyz` | public | Liveness; readiness checks the database, the chain id and the contract code |
| `GET /metrics` | public | Prometheus metrics |
| `GET /api/health` | public | Chain id, head and indexed block, gateway address, contract addresses |
| `GET /api/auth/domain` | public | EIP-712 domain and types for signed requests |
| `GET /api/overview` | public | Platform statistics and recent activity |
| `GET /api/datasets`, `GET /api/datasets/{id}` | public | Catalogue and dataset detail (versions, lineage, grants, requests, reads, quality, schema) |
| `GET /api/lineage?dataset_id=&version=` | public | Lineage graph, optionally focused on a dataset |
| `GET /api/audit?dataset_id=` | public | Unified audit trail (chain events and gateway actions) |
| `GET /api/access-requests` | public | All access requests |
| `POST /api/relay/access-requests/prepare` | public | Typed data a consumer signs to ask for access without gas |
| `POST /api/relay/access-requests` | signature in the body | The gateway submits the signed request and pays the gas (rate limited per account) |
| `GET /api/documents/{hash}`, `POST /api/documents` | public / signed | Content-addressed schema and report documents |
| `POST /api/datasets/{id}/objects` | signed, owner or steward | Stage an encrypted upload, returns values to anchor |
| `GET /api/datasets/{id}/versions/{v}/download` | signed, access | Verified, logged download |
| `GET /api/datasets/{id}/versions/{v}/records/{i}` | signed, access | Canonical record and Merkle proof |
| `POST /api/datasets/{id}/versions/{v}/diff` | signed, access | Row-level differences against the anchored version |
| `POST /api/datasets/{id}/versions/{v}/shred` | signed, owner | Destroy the data key and ciphertext |
| `POST /api/verify/file` | public | Exact match, records match, mismatch or unknown |
| `POST /api/verify/record` | public | On-chain record proof check |

**Signed requests.** The caller signs an EIP-712 `Request` with `eth_signTypedData_v4`, so a wallet shows every
field before signing. The domain names the chain and the AccessLedger address, so a signature cannot be replayed
against another network or deployment:

```text
Request(address account, string method, string path, bytes32 contentDigest, uint256 issuedAt, bytes32 nonce)
```

The request carries `X-DL-Address`, `X-DL-Issued`, `X-DL-Nonce`, `X-DL-Signature` and an RFC 9530
`Content-Digest` of the body. The gateway hashes the body as it arrives and refuses a digest that does not match,
so an upload cannot be swapped in transit. Smart-account signatures are checked with ERC-1271 `isValidSignature`.

The signature proves who is asking. Whether they may read is always decided by the contracts.

---

## Reference scenario

`scripts/load_reference_data.py` drives the running platform through a full governance cycle with seven roles
(each a separate wallet): platform admin, data gateway, quality auditor, sales operations, finance analytics, a
data engineer and an external partner analyst. The reference datasets in `datasets/` are generated
deterministically by `scripts/generate_datasets.py`.

1. **Registration.** Sales operations registers `crm_customers` (Confidential, contains contact e-mails),
   `sales_orders` (Internal) and `product_catalog` (Public), and makes the data engineer a steward of
   `sales_orders`.
2. **A flawed extract.** The September orders extract (721 rows) is published. It has three missing customer ids
   and one double-booked order.
3. **The fix.** The corrected October extract (1,500 rows) is published as v2 and v1 is deprecated.
4. **Access with purpose.** Finance analytics requests access to orders and customers for the monthly close;
   sales approves 90-day grants. Finance reads all three inputs through the gateway, and every read is a chain
   event.
5. **A derived dataset with lineage.** Finance builds `revenue_by_region` (net revenue by month, region and
   category) and commits it with three parents: orders v2, customers v1, catalog v1.
6. **Independent quality audit.** The auditor gets review grants, reads each version and attests:
   orders v1 **fails at 84.8%**, every other version passes at 100%.
7. **Partner sharing.** The partner analyst signs two access requests off-chain and the gateway relays them,
   so the partner pays no gas. The aggregate is shared for go-to-market planning and read; the request for
   customer contacts is rejected with a reason on-chain.
8. **Right to erasure.** Customer 5017 asks to be forgotten: customers v2 is published without them, v1 is
   withdrawn with the reason on-chain and then crypto-shredded. The lineage graph still shows that revenue v1 was
   built from the withdrawn version.

End state: 4 datasets, 6 versions, 2,784 records anchored, 3 lineage links, 6 active grants, 9 reads logged
on-chain, 5 quality attestations, 1 object crypto-shredded.

---

## Screens

| Dataset versions | Lineage |
|---|---|
| ![Versions](docs/screenshots/dataset-versions.png) | ![Lineage](docs/screenshots/lineage.png) |
| **Access grants and requests** | **Audit trail** |
| ![Dataset access](docs/screenshots/dataset-access.png) | ![Audit trail](docs/screenshots/audit-trail.png) |
| **Catalogue** | **Access requests** |
| ![Datasets](docs/screenshots/datasets.png) | ![Access](docs/screenshots/access.png) |

**Verification.** Left: a received copy of the orders file in which one unit price was quietly changed; the
recomputed Merkle root does not match the anchored one. Right: a record proof produced with `dataledger prove`
checked against the contract.

![Verify](docs/screenshots/verify.png)

---

## Run with Docker

The platform is published as two images on Docker Hub, for linux/amd64 and linux/arm64, with an SBOM and build
provenance attached (tags `1.1.0` and `latest`):

| Image | Contents |
|---|---|
| [`sadrulemail/dataledger`](https://hub.docker.com/r/sadrulemail/dataledger) | Data service: API gateway, event indexer, migrations, web console and CLI, plus the reference datasets |
| [`sadrulemail/dataledger-contracts`](https://hub.docker.com/r/sadrulemail/dataledger-contracts) | The three ledgers compiled with Foundry: runs a local chain (`chain`) or deploys to any RPC endpoint (`deploy`) |

[`docker-compose.yml`](docker-compose.yml) is all you need. It starts a local chain and PostgreSQL, deploys the
ledgers and migrates the schema once, then starts the API and the indexer:

```bash
docker compose up -d --wait
```

| Service | Role |
|---|---|
| `chain` | anvil on `127.0.0.1:8545`, state kept in a volume |
| `deploy` | one-shot: deploys the ledgers and grants the roles, skipped when they already exist |
| `postgres` | PostgreSQL 18 for the read models |
| `migrate` | one-shot: `dataledger db upgrade` |
| `api` | gateway API and console on `127.0.0.1:8000` |
| `indexer` | applies chain events to the read models; metrics on port 9100 |

Play the reference scenario (optional), then open the console at <http://localhost:8000>:

```bash
docker compose --profile reference-data run --rm reference-data
```

Add Prometheus on <http://localhost:9090> and Grafana on <http://localhost:3000> (see [Operations](#operations)):

```bash
docker compose --profile observability up -d
```

The CLI runs inside the service container:

```bash
docker compose exec api dataledger verify-file --file /app/datasets/sales_orders_2026-10.csv
```

Stop the stack and delete every volume:

```bash
docker compose down -v
```

- **Hardened by default.** Ports bind to 127.0.0.1 (set `DATALEDGER_BIND=0.0.0.0` to open them), service
  containers run read-only as a non-root user with every Linux capability dropped and `no-new-privileges`, and
  each service has a health check and a memory limit.
- **State survives restarts.** The chain, database and objects live in volumes and the deploy step is skipped when
  the ledgers exist, so `docker compose down` followed by `up` brings back the same chain and data.
- **Upgrading from 1.0.0.** 1.1.0 deploys new contracts and moves the read models to PostgreSQL. Reset a 1.0.0
  stack with `docker compose down -v` before `docker compose up -d`.
- **Keys.** Without `DATALEDGER_MASTER_KEYS`, the service generates a key ring and keeps it in its data volume.
  That is convenient on a laptop, but anyone holding the volume then holds both the ciphertext and the key.
  Anywhere else, inject the keys from a secret store, either as `DATALEDGER_MASTER_KEYS` or as a mounted file
  named in `DATALEDGER_MASTER_KEYS_FILE`.
- **Other chains.** Run the contracts image with `deploy`, set `RPC_URL` and `DEPLOYER_PRIVATE_KEY`, and mount
  `/app/deployments` to collect `<chainId>.json`. Set `FINAL_ADMIN_ADDRESS` to hand the admin role to a multisig
  or timelock. Point the service's `DATALEDGER_DEPLOYMENT_FILE` at the JSON file.
- **Building from source.** `docker compose build`, or `make images` ([`docker-bake.hcl`](docker-bake.hcl) builds
  both images for both platforms with SBOM and provenance attestations).

---

## Deploy to Kubernetes

[`deploy/helm/dataledger`](deploy/helm/dataledger) is a Helm chart for the off-chain half. It expects a chain with
the ledgers deployed, PostgreSQL, and an S3-compatible bucket (or a volume for a single replica):

```bash
helm install dataledger deploy/helm/dataledger -n dataledger --create-namespace \
  --set chain.rpcUrl=https://sepolia.base.org \
  --set-json 'chain.deployment={"chainId":84532,"startBlock":0,"dataRegistry":"0x...","accessLedger":"0x...","qualityLedger":"0x..."}' \
  --set secrets.existingSecret=dataledger-runtime \
  --set objectStore.s3.bucket=dataledger-objects --set objectStore.s3.region=eu-west-1
```

| Resource | Details |
|---|---|
| API `Deployment` | Two replicas by default, spread across nodes, `startupProbe`/`livenessProbe` on `/healthz` and `readinessProbe` on `/readyz`; optional HPA and a PodDisruptionBudget |
| Indexer `Deployment` | One replica with the `Recreate` strategy, so two indexers never write at once |
| Migrations | An init container runs `dataledger db upgrade` in every pod; a PostgreSQL advisory lock lets one run at a time |
| Configuration | The deployment addresses in a ConfigMap; the database URL, key ring and gateway key from a Secret (`secrets.existingSecret` fits External Secrets or Sealed Secrets) |
| Security | Non-root uid 10001, read-only root filesystem, all capabilities dropped, `RuntimeDefault` seccomp, no service-account token |
| Optional | Ingress with TLS and HSTS, `ServiceMonitor` for the Prometheus Operator, `NetworkPolicy` |

`values.schema.json` rejects malformed values (such as a bad contract address), and the chart refuses settings
that cannot work, such as several replicas on a single-node volume. `make helm-lint` lints the chart with two
value profiles in [`ci/`](deploy/helm/dataledger/ci).

---

## Operations

![Grafana dashboard](docs/screenshots/grafana.png)

- **Metrics.** The API serves Prometheus metrics at `/metrics` and the indexer on its own port
  (`dataledger index --metrics-port 9100`): requests and latency by route template, chain head, indexed block
  and lag, and gateway events (staged uploads, reads logged on-chain, record proofs, relayed requests,
  crypto-shreds, rejected signatures, integrity failures). The compose `observability` profile provisions
  Prometheus and the Grafana dashboard above.
- **Logs.** One JSON object per line (`DATALEDGER_LOG_FORMAT=json`, the image default) with the request id of the
  call that caused it. Callers can send `X-Request-ID`; every response returns it.
- **Traces.** With the `otel` extra installed (it is in the image), setting `OTEL_EXPORTER_OTLP_ENDPOINT` sends
  OpenTelemetry traces of every request to any OTLP collector.
- **Probes.** `/healthz` answers while the process runs; `/readyz` returns 503 until the database answers and the
  RPC endpoint serves the expected chain with the registry deployed.
- **Headers.** Every response carries `nosniff`, `no-referrer` and frame protection; the console adds a strict
  Content-Security-Policy, API responses are `no-store`, and `DATALEDGER_HSTS=true` adds HSTS behind TLS.

---

## Run it locally

### Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation) (`forge`, `anvil`)
- [uv](https://docs.astral.sh/uv/), which fetches Python 3.14 (3.12 and 3.13 work too)
- Docker, for the PostgreSQL test run and the chart checks
- `make` (optional): `make help` lists every task, and `make check` runs every quality gate

### 1. Contracts

```bash
git clone --recurse-submodules https://github.com/sadrulemail/blockchain-data-management.git
```

```bash
cd blockchain-data-management/contracts && forge build && forge test
```

### 2. Local chain and deployment

Start a local chain in its own terminal:

```bash
anvil
```

Deploy the three ledgers and grant the operating roles (the keys and addresses are anvil's public development
accounts):

```bash
GATEWAY_ADDRESS=0x70997970C51812dc3A010C7d01b50e0d17dc79C8 \
AUDITOR_ADDRESS=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC \
PUBLISHER_ADDRESSES=0x90F79bf6EB2c4f870365E785982E1f101E93b906,0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65 \
forge script script/Deploy.s.sol --rpc-url anvil --broadcast \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
```

This writes `contracts/deployments/31337.json`, which the service reads.

### 3. Service

```bash
cd ../service && uv sync --all-extras && cp .env.example .env
```

Generate a key-encryption key and put the printed line into `.env`:

```bash
uv run dataledger keygen --kid kek-1
```

Start the API, indexer and console in its own terminal:

```bash
uv run dataledger serve
```

### 4. Load the reference scenario

```bash
uv run python ../scripts/load_reference_data.py
```

Open the console at <http://127.0.0.1:8000> and the OpenAPI reference at <http://127.0.0.1:8000/docs>.

### 5. Use the CLI

Each command signs with the key in `DATALEDGER_PRIVATE_KEY` (or `--key-env NAME`).

```bash
export DATALEDGER_PRIVATE_KEY=0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a
```

```bash
uv run dataledger prove 2 2 41 > proof.json && uv run dataledger verify-record proof.json
```

```bash
uv run dataledger verify-file --file ../datasets/sales_orders_2026-10.csv
```

| Command | Role | What it does |
|---|---|---|
| `register --schema s.json --classification confidential` | publisher | Publishes the schema document and registers the dataset |
| `publish --dataset 2 --file f.csv [--parent 1:1]` | owner, steward | Uploads, then anchors the version with lineage |
| `status 2 1 --to deprecated --reason "..."` | owner, steward | Lifecycle change |
| `steward 2 0xabc...` / `grant 2 0xabc... "purpose" --days 30` / `revoke` | owner | Stewardship and grants |
| `request-access 2 "purpose" [--gasless]` / `approve 1 --days 90` / `reject 1 "reason"` | consumer / owner | Request flow; `--gasless` signs EIP-712 and lets the gateway pay |
| `download 2 2 --out f.csv` / `prove 2 2 41` | consumer | Logged download, record proof |
| `verify-file --file f.csv [--dataset 2 --version 2]` / `verify-record proof.json` | anyone | Public verification |
| `quality 2 2` | auditor | Reads, checks, publishes the report and attests on-chain |
| `shred 1 1 --reason "erasure request"` | owner | Withdraws on-chain and destroys the data key |
| `serve [--no-indexer]`, `index [--once] [--metrics-port 9100]`, `db upgrade`, `db current`, `keygen`, `rotate-keys` | operator | Run and maintain the service |

---

## Quality gates

`make check` runs every gate below; [pre-commit](.pre-commit-config.yaml) runs the fast ones on each commit.

| Gate | Count | What it covers |
|---|---|---|
| Contract unit tests | 76 | Every function, role check, custom error and event, status transitions, ownership and admin hand-over, pause, signed requests (EOA and ERC-1271), batching, deploy script |
| Contract fuzz tests | 5 × 1,000 runs | Proofs accepted for every record, rejected when tampered or moved; grant expiry; only the real signer can open a signed request |
| Contract invariants | 3 × 128 runs × 64 calls | Counters match commits, lineage graph always closed, withdrawn is final |
| Golden vectors | 2 | Same records give the same Merkle root in Solidity and Python; the Python EIP-712 digest equals `hashAccessRequest` |
| Static analysis | 0 findings | Slither (every detector, two reviewed suppressions with reasons) and `forge lint` |
| Gas snapshot | 76 entries | `forge snapshot --check` fails when gas use changes unnoticed |
| Python unit tests | 81 | Canonicalisation, Merkle trees, encryption, storage (filesystem and S3), EIP-712 signing and replay, migrations, logging, metrics and security headers |
| End-to-end tests | 30 | Real anvil chain per test: publish, gated reads, proofs, verification, diffs, tampering, lineage, attestations, erasure, key rotation, re-org recovery, gasless relay, smart-account signatures, batched grants, probes, metrics and every CLI command |
| End-to-end on PostgreSQL | 30 | The same suite against PostgreSQL 18 (`make test-postgres`) |
| Types and style | | mypy, ruff (lint and format), `forge fmt` |
| Helm chart | 2 profiles | `helm lint --strict` and kubeconform against the Kubernetes 1.34 schemas |

Contract coverage is 100% of lines, statements, branches and functions (`forge coverage`). Python coverage is
89% with branch coverage, and the suite fails below 85%.

```bash
make check
```

---

## Design decisions and trade-offs

The main decisions are written up as [architecture decision records](docs/adr/README.md), with the options
considered for each.

**Hashes on-chain, data off-chain.** Storing data on a chain is expensive, public to every node, and impossible
to delete. Anchoring a 32-byte root gives the same tamper evidence at a fixed cost per version.

**Merkle root per version rather than a transaction per record.** One transaction anchors any number of rows,
while still allowing proofs for single rows. The trade-off is that a proof needs the full version to build, which
the gateway has.

**A gateway that enforces on-chain rules, rather than keys handed out on-chain.** Encrypting data to each
grantee's key would remove the gateway from the read path but makes revocation meaningless (a grantee keeps
what they decrypted) and makes erasure impossible. A gateway that checks grants live and logs every read keeps
revocation and erasure real, and `logAccess` rechecks access inside the contract so the gateway cannot bypass
the rules without leaving evidence.

**Logging every read on-chain.** It costs one small transaction per read (~31k gas). For high-volume reads the
same design can batch receipts into a Merkle root per interval and anchor that instead.

**Purpose hashes.** Purposes are bound to grants by hash. Request purposes are emitted in full so reviewers can
read them, and direct-grant purposes travel in the transaction calldata; nothing personal belongs in a purpose.

**Event-sourced SQL.** The chain is the source of truth, the database is a fast, disposable view. PostgreSQL
holds it in every shared deployment and SQLite on a laptop; the SQL layer is SQLAlchemy Core with dialect-aware
upserts, and the schema evolves through Alembic revisions that a test compares with the table definitions.

**Indexer as its own process.** Applying events is a single-writer job, while the API is stateless and scales
out. Splitting them lets the API run several replicas and lets the indexer restart without dropping requests.

**EIP-712 rather than plain-text signatures.** Typed data shows the user exactly what they sign, binds the
signature to one chain and one deployment, and covers the body digest. It is also what smart-account wallets
verify through ERC-1271, so Safe and passkey wallets can use the API.

**Gasless requests through the gateway.** Asking for access should not need a funded wallet. The consumer signs,
the gateway pays, and the contract still checks the consumer's signature, so relaying adds no trust in the
gateway. Each account can have a limited number of requests relayed per hour, and a bad signature fails gas
estimation before anything is sent.

**Immutable contracts, guarded admin.** The ledgers are not behind upgradeable proxies: an upgrade key could
rewrite the rules that make the history trustworthy. New rules mean new contracts and a new deployment. What can
change, the admin role, moves only in two steps with a delay, ideally to a multisig or timelock.

**Any EVM chain.** The contracts use no chain-specific features. The same code runs on a consortium network
(Hyperledger Besu, Quorum), a public L2, or a public testnet, depending on who must be able to verify.

---

## Taking it to production

Already in place: PostgreSQL with migrations, S3 storage, a separate indexer with confirmations, metrics, probes,
hardened images and the Helm chart. What remains depends on the environment:

- Key-encryption keys and the gateway signer in a KMS or HSM; the chart reads them from a Secret that an External
  Secrets operator can fill.
- `FINAL_ADMIN_ADDRESS` set to a multisig or timelock at deployment, and `PAUSER_ROLE` held separately.
- `chain.confirmations` matched to the finality of the target chain.
- A funded, monitored gateway wallet, with rate limits or an allow-list at the ingress for the relay endpoint.
- Batched read receipts for high-volume datasets.
- Per-version salts for datasets with low-entropy rows, so record hashes cannot be guessed.
- An external audit before mainnet; Slither already runs in `make check`.

---

## Project structure

```text
blockchain-data-management/
├── Makefile                      every task and quality gate (`make help`)
├── Dockerfile                    service and contracts images (one target each)
├── docker-bake.hcl               multi-platform builds with SBOM and provenance
├── docker-compose.yml            chain, deployment, PostgreSQL, migrations, API, indexer, observability
├── docker/                       image entry points, Prometheus and Grafana provisioning
├── deploy/helm/dataledger/       Helm chart for Kubernetes
├── contracts/                    Foundry project
│   ├── src/
│   │   ├── DataRegistry.sol      datasets, versions, lineage, record proofs
│   │   ├── AccessLedger.sol      requests (direct and EIP-712 signed), grants, read log
│   │   ├── QualityLedger.sol     independent attestations
│   │   └── interfaces/IDataRegistry.sol
│   ├── script/Deploy.s.sol       deploy, grant roles, start the admin hand-over, write deployments/<chainId>.json
│   ├── test/                     unit, fuzz, invariant and deploy tests
│   ├── .gas-snapshot             gas per unit test
│   └── slither.config.json
├── service/                      Python data service (uv project)
│   ├── src/dataledger/           API, indexer, crypto, Merkle, storage, observability, CLI, console, ABIs
│   │   └── migrations/           Alembic revisions
│   └── tests/                    unit tests and end-to-end tests against anvil
├── datasets/                     reference CSVs, schema documents, address book
├── scripts/
│   ├── generate_datasets.py      deterministic reference data
│   ├── load_reference_data.py    full governance cycle against a running platform
│   ├── export_abi.py             copy ABIs from the Foundry build into the service
│   ├── capture_screenshots.py    console and Grafana screenshots for this README
│   └── render_diagrams.py        README diagrams from docs/diagrams/*.mmd
└── docs/
    ├── adr/                      architecture decision records
    ├── diagrams/                 Mermaid sources and rendered light/dark PNGs
    └── screenshots/
```

See also [CHANGELOG](CHANGELOG.md), [SECURITY](SECURITY.md) and [CONTRIBUTING](CONTRIBUTING.md).

## License

MIT, see [LICENSE](LICENSE).
