#!/bin/sh
# Service image entry point: resolves the key-encryption keys, then runs the command.
#   docker run sadrulemail/dataledger keygen         CLI subcommands work without the `dataledger` prefix
#   DATALEDGER_MASTER_KEYS or DATALEDGER_MASTER_KEYS_FILE (a mounted secret) supplies the key ring
set -eu

if [ $# -eq 0 ] || ! command -v "$1" >/dev/null 2>&1; then
  set -- dataledger "$@"
fi

if [ -z "${DATALEDGER_MASTER_KEYS:-}" ] && [ -n "${DATALEDGER_MASTER_KEYS_FILE:-}" ]; then
  DATALEDGER_MASTER_KEYS=$(cat "$DATALEDGER_MASTER_KEYS_FILE")
  export DATALEDGER_MASTER_KEYS
fi

# The server needs a key ring. Without one, keep a generated ring in the data volume so a local stack works out
# of the box; anywhere else, inject the keys from a secret store so they never sit next to the ciphertext.
case "${1:-} ${2:-}" in
  "dataledger serve" | "dataledger index" | "dataledger rotate-keys")
    if [ -z "${DATALEDGER_MASTER_KEYS:-}" ]; then
      ring=/data/master-keys
      if [ ! -s "$ring" ]; then
        (umask 077 && dataledger keygen --kid "kek-$(date +%Y-%m)" | sed 's/^DATALEDGER_MASTER_KEYS=//' > "$ring")
        echo "entrypoint: no DATALEDGER_MASTER_KEYS given; generated a key ring in $ring for local use" >&2
      fi
      DATALEDGER_MASTER_KEYS=$(cat "$ring")
      export DATALEDGER_MASTER_KEYS
    fi
    ;;
esac

exec "$@"
