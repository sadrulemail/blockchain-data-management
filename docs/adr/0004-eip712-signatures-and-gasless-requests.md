# 0004. EIP-712 signatures and gasless access requests

- Status: Accepted (replaces the EIP-191 request signatures of 1.0.0)
- Date: 2026-11-16

## Context

1.0.0 signed API requests with EIP-191 plain text. Wallets showed an opaque message, the signature was not tied
to a chain or a deployment, the body was not covered, and smart-account wallets could not take part. Consumers
also needed gas to ask for access.

## Decision

- API requests are signed as EIP-712 typed data in a domain naming the chain and the AccessLedger, covering the
  method, path, an RFC 9530 body digest, the issue time and a nonce. ERC-1271 is the fallback for smart accounts.
- Consumers can sign an `AccessRequest` (EIP-712) and the gateway relays it with
  `AccessLedger.requestAccessWithSig`. The contract verifies the signature with OpenZeppelin `SignatureChecker`,
  with a nonce per account and a deadline.

## Options considered

- **Keep EIP-191:** simplest, but weaker binding and poor wallet display.
- **ERC-2771 meta-transactions through a trusted forwarder:** generic, but every contract would trust the
  forwarder for `msg.sender`.
- **ERC-4337 paymaster:** suits smart accounts, but needs bundler and paymaster infrastructure for one action.
- **Function-specific EIP-712 signatures (chosen):** no trusted forwarder; the contract checks the requester.

## Consequences

The gateway pays gas for relayed requests, so relaying is rate limited per account and can be switched off.
Clients fetch the domain from `GET /api/auth/domain` and the typed data from the prepare endpoint.
