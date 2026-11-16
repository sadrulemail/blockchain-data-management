# Security

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](https://github.com/sadrulemail/blockchain-data-management/security/advisories/new)
rather than in a public issue. Include the affected component (contracts, service, images or chart), the version
or commit, and the steps to reproduce. You can expect an acknowledgement within three working days.

## Supported versions

| Version | Supported |
|---|---|
| 1.1.x | Yes |
| 1.0.x | No: upgrade to 1.1 |

## Scope and assumptions

- **Contracts.** The ledgers are not upgradeable. They are covered by unit, fuzz and invariant tests at 100%
  coverage and by Slither, but have not had an external audit. Do not use them on mainnet without one.
- **Keys in the compose stack.** `docker-compose.yml`, `service/.env.example` and the tests use anvil's public
  development accounts. They only hold value on a local chain and must never be used anywhere else.
- **Key ring.** Without `DATALEDGER_MASTER_KEYS`, the image generates a key ring in its data volume for local use.
  In any shared environment, supply keys from a secret manager so they never sit next to the ciphertext.
- **Gateway key.** The gateway key can log reads and pays gas for relayed access requests. Keep it in a KMS or
  HSM, fund it with a limited balance and monitor it. The per-account relay limit does not stop requests signed
  by many fresh keys; add rate limits or an allow-list at the ingress where that matters.
- **Signed requests.** Signatures are valid for `DATALEDGER_AUTH_MAX_AGE_SECONDS` (300 s) and nonces are kept in
  memory per API process. Replicas behind a load balancer each keep their own nonce cache, so a captured request
  could be replayed once per replica within that window; TLS between client and gateway prevents the capture.
- **Personal data** must never be written on-chain, including in access-request purposes, which are public.

## Hardening already in place

Non-root, read-only containers with every capability dropped; digest-pinned base images; SBOM and provenance on
published images; a Content-Security-Policy on the console; `no-store` on API responses; probes and resource
limits; EIP-712 signatures bound to the chain, the deployment and the request body; two-step admin hand-over on
every contract.
