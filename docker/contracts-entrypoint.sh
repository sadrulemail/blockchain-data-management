#!/bin/sh
# Contracts image entry point.
#   chain [anvil flags]   run a local chain on :8545, state kept in /data across restarts
#   deploy [forge flags]  deploy the ledgers to RPC_URL with DEPLOYER_PRIVATE_KEY (skipped if already deployed)
#   anything else         run as a command (forge, cast, anvil, sh)
set -eu

case "${1:-}" in
  chain)
    shift
    exec anvil --host 0.0.0.0 --port 8545 --state /data/anvil-state.json --state-interval 5 "$@"
    ;;
  deploy)
    shift
    : "${RPC_URL:?set RPC_URL to the chain endpoint}"
    : "${DEPLOYER_PRIVATE_KEY:?set DEPLOYER_PRIVATE_KEY to the admin key}"
    chain_id=$(cast chain-id --rpc-url "$RPC_URL")
    file="deployments/${chain_id}.json"
    if [ -f "$file" ]; then
      registry=$(sed -n 's/.*"dataRegistry": *"\(0x[0-9a-fA-F]*\)".*/\1/p' "$file")
      if [ -n "$registry" ] && [ "$(cast code "$registry" --rpc-url "$RPC_URL")" != "0x" ]; then
        echo "ledgers already deployed on chain ${chain_id}: ${file}"
        cat "$file"
        exit 0
      fi
    fi
    forge script script/Deploy.s.sol --rpc-url "$RPC_URL" --private-key "$DEPLOYER_PRIVATE_KEY" --broadcast "$@"
    cat "$file"
    ;;
  *)
    exec "$@"
    ;;
esac
