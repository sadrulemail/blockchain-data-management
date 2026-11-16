# 0001. Anchor commitments on-chain, keep data off-chain

- Status: Accepted
- Date: 2026-11-07

## Context

Datasets range from kilobytes to gigabytes and may contain personal data. A chain is replicated to every node,
costs gas per byte and can never forget anything.

## Decision

Each version anchors a Merkle root over canonical records, a SHA-256 fingerprint of the file, the record count,
a schema hash and a storage pointer. Files stay off-chain, encrypted with a key per object.

## Options considered

- **Data on-chain:** simple verification, but unaffordable at scale, public to every node and impossible to erase.
- **A transaction per record:** row-level evidence, but the cost grows with the row count.
- **One Merkle root per version (chosen):** constant cost per version, proofs for single rows, nothing personal
  on-chain.

## Consequences

Any party can prove a file or a single record against the chain. Building a proof needs the whole version, which
the gateway holds. Erasure works by destroying the object key (crypto-shredding) while the hashes remain.
