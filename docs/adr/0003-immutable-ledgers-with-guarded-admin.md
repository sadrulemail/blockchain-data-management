# 0003. Immutable ledgers with a two-step, delayed admin

- Status: Accepted
- Date: 2026-11-16

## Context

The value of the ledgers is that nobody, including the operator, can rewrite the rules or the history. Clients
also ask how the system is governed and how it changes over time.

## Decision

The contracts are deployed without upgradeable proxies. Roles are managed with OpenZeppelin
`AccessControlDefaultAdminRules`: a single admin, handed over in two steps after a delay (2 days by default). The
deploy script can start the hand-over to a multisig or timelock (`FINAL_ADMIN_ADDRESS`).

## Options considered

- **UUPS or transparent proxies:** fixes without redeploying, but whoever holds the upgrade key can change any
  rule, which undermines the trust model.
- **Plain `AccessControl`:** flexible, but a mistyped or stolen admin key takes effect at once.
- **Immutable contracts with a guarded admin (chosen):** the rules are fixed; role changes are visible on-chain
  and can be cancelled during the delay.

## Consequences

A change to the rules means new contracts and a new deployment; the indexer and service follow the deployment
file. Operating roles (publisher, gateway, auditor, pauser) can still be granted and revoked by the admin.
