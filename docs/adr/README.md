# Architecture decision records

Each record states one decision, the options considered and what follows from it. New decisions get the next
number; a decision that is replaced is marked *Superseded* with a link to its successor.

| # | Decision | Status |
|---|---|---|
| [0001](0001-anchor-commitments-not-data.md) | Anchor commitments on-chain, keep data off-chain | Accepted |
| [0002](0002-gateway-enforces-on-chain-access.md) | A gateway enforces on-chain access and logs every read | Accepted |
| [0003](0003-immutable-ledgers-with-guarded-admin.md) | Immutable ledgers with a two-step, delayed admin | Accepted |
| [0004](0004-eip712-signatures-and-gasless-requests.md) | EIP-712 signatures and gasless access requests | Accepted |
| [0005](0005-event-sourced-read-models-on-postgresql.md) | Event-sourced read models on PostgreSQL, single indexer | Accepted |
