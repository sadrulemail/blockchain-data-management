# 0005. Event-sourced read models on PostgreSQL, single indexer

- Status: Accepted
- Date: 2026-11-16

## Context

The console and API need fast queries over datasets, versions, grants and the audit trail. Chain calls are too
slow for that, and 1.0.0 kept the read models in SQLite inside the API process, which limits it to one replica.

## Decision

Read models are a projection of chain events in PostgreSQL (SQLite stays for laptops), versioned with Alembic.
One indexer process applies events in block order and commits each batch with its cursor; it rebuilds from the
deployment block when the block hash under the cursor changes (a re-org). API replicas only read the projection
and write their own object and document rows.

## Options considered

- **Query the chain directly:** always fresh, but slow and expensive for lists and joins.
- **A hosted indexer (The Graph, Ponder, Envio):** less code, but another service to run or pay for, and the
  service still needs its own tables for objects and documents.
- **Own indexer into PostgreSQL (chosen):** one database for both, transactional cursor, simple to operate.

## Consequences

The indexer is a single writer (the Helm chart runs it with the `Recreate` strategy). Migrations run before the
API and indexer start, under a PostgreSQL advisory lock. The database can always be dropped and rebuilt from the
chain.
