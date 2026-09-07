#!/usr/bin/env bash
# Manage the bridge allowlists (allowed tokens + allowed chain pairs) and read
# transaction history, all via the sig-store HTTP API. The DB is the source of
# truth; this is just curl with friendly subcommands.
#
# Usage:
#   scripts/testing/allowlist.sh tokens                              # list allowed tokens
#   scripts/testing/allowlist.sh add-token <chainId> <token> [sym]   # allow a token
#   scripts/testing/allowlist.sh del-token <chainId> <token>         # remove a token
#   scripts/testing/allowlist.sh chains                              # list allowed pairs
#   scripts/testing/allowlist.sh add-chain <from> <to>               # allow a chain pair
#   scripts/testing/allowlist.sh del-chain <from> <to>               # remove a chain pair
#   scripts/testing/allowlist.sh history                             # transaction history
#   scripts/testing/allowlist.sh seed                                # local-dev defaults
#
# Env: SIG_STORE=http://127.0.0.1:8080 (override to point elsewhere).
#      SIG_STORE_ADMIN_TOKEN=...  bearer token with the `admin` scope (L-5).
#      SIG_STORE_TOKEN=...        legacy all-scopes fallback.
set -euo pipefail
SIG_STORE="${SIG_STORE:-http://127.0.0.1:8080}"

# Forward the bearer token on every call when one is configured (the sig-store
# requires it unless it's running in open dev mode).
AUTH=()
# Allowlist mutations need the `admin` scope; fall back to the legacy secret.
#
# NAMED `AUTH_TOKEN`, not `TOKEN`. These were once the same variable, which was
# harmless only while the store ran unauthenticated: the moment a credential is
# present — now the default, since the store refuses to serve open — the bearer
# string survived into the ERC-20 slot below and `seed` allowlisted the SECRET
# as a token address. That fails silently: the command reports success, the real
# TestToken is never allowlisted, and validators withhold signatures for it.
AUTH_TOKEN="${SIG_STORE_ADMIN_TOKEN:-${SIG_STORE_TOKEN:-}}"
if [ -n "$AUTH_TOKEN" ]; then
  AUTH=(-H "authorization: Bearer ${AUTH_TOKEN}")
fi

# The ERC-20 `seed` allowlists. Prefer the address the running stack actually
# deployed; fall back to the deterministic local anvil one (account #0 deploys
# TestToken first).
if [ -z "${TOKEN:-}" ] && [ -f "${RUN_DIR:-/tmp/bridge-run}/addresses.env" ]; then
  # shellcheck disable=SC1090
  . "${RUN_DIR:-/tmp/bridge-run}/addresses.env"
  TOKEN="${TOKEN_TST_1337:-}"
fi
TOKEN="${TOKEN:-0x5FbDB2315678afecb367f032d93F642f64180aa3}"
CHAIN_A="${CHAIN_A:-1337}"
CHAIN_B="${CHAIN_B:-1338}"

j() { if command -v jq >/dev/null 2>&1; then jq .; else cat; fi; }

cmd="${1:-}"; shift || true
case "$cmd" in
  tokens)  curl -fsS "${AUTH[@]}" "$SIG_STORE/allowed/tokens" | j ;;
  chains)  curl -fsS "${AUTH[@]}" "$SIG_STORE/allowed/chains" | j ;;
  history) curl -fsS "${AUTH[@]}" "$SIG_STORE/history" | j ;;

  add-token)
    chain="$1"; token="$2"; sym="${3:-}"
    if [ -n "$sym" ]; then symval="\"$sym\""; else symval=null; fi
    curl -fsS "${AUTH[@]}" -X POST "$SIG_STORE/allowed/tokens" -H 'content-type: application/json' \
      -d "{\"chain_id\":$chain,\"token\":\"$token\",\"symbol\":$symval}" | j ;;
  del-token)
    chain="$1"; token="$2"
    curl -fsS "${AUTH[@]}" -X DELETE "$SIG_STORE/allowed/tokens/$chain/$token" -o /dev/null -w "%{http_code}\n" ;;

  add-chain)
    from="$1"; to="$2"
    curl -fsS "${AUTH[@]}" -X POST "$SIG_STORE/allowed/chains" -H 'content-type: application/json' \
      -d "{\"chain_id_from\":$from,\"chain_id_to\":$to}" | j ;;
  del-chain)
    from="$1"; to="$2"
    curl -fsS "${AUTH[@]}" -X DELETE "$SIG_STORE/allowed/chains/$from/$to" -o /dev/null -w "%{http_code}\n" ;;

  seed)
    # Whitelist the local TestToken on both chains and both directions.
    curl -fsS "${AUTH[@]}" -X POST "$SIG_STORE/allowed/tokens" -H 'content-type: application/json' \
      -d "{\"chain_id\":$CHAIN_A,\"token\":\"$TOKEN\",\"symbol\":\"TST\"}" >/dev/null
    curl -fsS "${AUTH[@]}" -X POST "$SIG_STORE/allowed/tokens" -H 'content-type: application/json' \
      -d "{\"chain_id\":$CHAIN_B,\"token\":\"$TOKEN\",\"symbol\":\"TST\"}" >/dev/null
    curl -fsS "${AUTH[@]}" -X POST "$SIG_STORE/allowed/chains" -H 'content-type: application/json' \
      -d "{\"chain_id_from\":$CHAIN_A,\"chain_id_to\":$CHAIN_B}" >/dev/null
    curl -fsS "${AUTH[@]}" -X POST "$SIG_STORE/allowed/chains" -H 'content-type: application/json' \
      -d "{\"chain_id_from\":$CHAIN_B,\"chain_id_to\":$CHAIN_A}" >/dev/null
    echo "seeded: TestToken on $CHAIN_A and $CHAIN_B; chain pairs $CHAIN_A<->$CHAIN_B"
    curl -fsS "${AUTH[@]}" "$SIG_STORE/allowed/tokens" | j ;;

  *)
    echo "usage: $0 {tokens|add-token|del-token|chains|add-chain|del-chain|history|seed}" >&2
    exit 2 ;;
esac
