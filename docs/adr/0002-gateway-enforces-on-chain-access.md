# 0002. A gateway enforces on-chain access and logs every read

- Status: Accepted
- Date: 2026-11-07

## Context

Access grants are recorded on-chain, but the data is off-chain. Something has to apply the grants when data is
served.

## Decision

A data gateway serves every read. It checks `hasAccess` live on-chain, verifies the stored object against the
anchored fingerprint and root, and calls `AccessLedger.logAccess`, which rechecks access inside the contract and
emits `DataAccessed`, before any data leaves.

## Options considered

- **Encrypt to the key of each grantee:** no gateway in the read path, but revocation is meaningless once a
  grantee has decrypted, and erasure becomes impossible.
- **Gateway with an off-chain policy store:** fast, but the operator could change the rules unseen.
- **Gateway enforcing on-chain rules (chosen):** revocation and erasure stay real; a faulty gateway cannot read
  silently, because every served read is a chain event.

## Consequences

One small transaction per read (~31k gas). For high volumes, receipts can be batched into a Merkle root per
interval. The gateway key can only log reads and relay signed requests.
