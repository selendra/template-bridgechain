#!/usr/bin/env bash
# Launch the bridge backend (graphql-api) + frontend (vite dev) as detached
# services that survive past this shell, then verify both are up.
#
# Best-effort extra: if foundry is available, spin up a local anvil (chain 1337
# on :8545), deploy + seed a same-chain SwapPool, mint demo balances to anvil
# account 0, and start the API with `--swap` so the Swap view is live. Import
# account 0 (0xf39F…2266, key 0xac09…ff80) into MetaMask and pick "Anvil A" to
# actually swap. If foundry isn't installed this block is skipped and the bridge
# UI still runs.
set -euo pipefail

# Native Linux node (nvm). Pick the newest installed version rather than pinning
# one: a hardcoded path silently vanishes on the next `nvm install`, and then
# PATH falls back to whatever `node` the shell has — often none at all, which
# surfaces as a confusing "command not found" deep inside the run. Same
# auto-detect idiom as scripts/run.sh.
NODE_BIN="${NODE_BIN:-$(ls -d "$HOME"/.nvm/versions/node/*/bin 2>/dev/null | sort -V | tail -1 || true)}"
export PATH="${NODE_BIN:+$NODE_BIN:}$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTRACTS="$ROOT/contracts"
LOG=/tmp/bridge-run
mkdir -p "$LOG"

RPC=http://127.0.0.1:8545
CHAIN=1337
KEY0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
ACCT0=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266

# Free the ports if a previous run is still holding them.
fuser -k 8088/tcp 5173/tcp 8545/tcp 2>/dev/null || true
sleep 0.5

# --- optional: local anvil + SwapPool so the Swap view has live data ---
SWAP_ARG=""
if command -v anvil >/dev/null 2>&1 && command -v forge >/dev/null 2>&1; then
  echo "=== starting anvil ($CHAIN) + deploying SwapPool ==="
  setsid bash -c "exec anvil --chain-id $CHAIN --port 8545 --silent" >"$LOG/anvil.log" 2>&1 < /dev/null &
  disown || true
  for _ in $(seq 1 50); do cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 0.2; done

  if ( cd "$CONTRACTS" && forge script script/DeploySwap.s.sol:DeploySwap \
         --rpc-url "$RPC" --private-key "$KEY0" --broadcast >"$LOG/swap-deploy.log" 2>&1 ); then
    source "$CONTRACTS/fixtures/swap-deploy.env"
    # Mint demo balances to account 0 so the connected wallet has something to swap.
    for pair in "$WETH:10000000000000000000" "$TT:250000000000000000000000" "$STABLE:5000000000"; do
      cast send "${pair%%:*}" "mint(address,uint256)" "$ACCT0" "${pair##*:}" \
        --rpc-url "$RPC" --private-key "$KEY0" >/dev/null 2>&1 || true
    done
    SWAP_ARG="--swap $CHAIN=$RPC,$SWAP_POOL"
    echo "  SwapPool=$SWAP_POOL (stable=$STABLE WETH=$WETH TT=$TT)"
  else
    echo "  !! swap deploy failed — Swap view will be empty (see $LOG/swap-deploy.log)"
  fi
else
  echo "=== foundry not found — skipping local SwapPool (Swap view will be empty) ==="
fi

# --- backend: GraphQL API over the existing signature store ---
cd "$ROOT"
setsid bash -c "exec ./target/debug/graphql-api --bind 127.0.0.1:8088 --dir sig-store-data --threshold 2 --chains-file chains.json $SWAP_ARG" \
  >"$LOG/api.log" 2>&1 < /dev/null &
disown || true

# --- frontend: Vite dev server (proxies /graphql -> 127.0.0.1:8088) ---
cd "$ROOT/frontend"
[ -d node_modules ] || bun install
setsid bash -c 'exec bunx vite --host 0.0.0.0 --port 5173 --strictPort' \
  >"$LOG/web.log" 2>&1 < /dev/null &
disown || true

# --- wait for health ---
for _ in $(seq 1 40); do curl -s http://127.0.0.1:8088/health >/dev/null 2>&1 && break; sleep 0.25; done
for _ in $(seq 1 80); do curl -s http://127.0.0.1:5173/         >/dev/null 2>&1 && break; sleep 0.25; done

echo "=== backend /health ==="
curl -s http://127.0.0.1:8088/health; echo
echo "=== frontend index.html ==="
curl -s http://127.0.0.1:5173/ | grep -oE 'id="root"|/src/main.tsx' | sort -u
echo "=== stats via dev proxy ==="
curl -s http://127.0.0.1:5173/graphql -H 'content-type: application/json' \
  --data '{"query":"{ stats { total signed ready threshold } }"}'; echo
if [ -n "$SWAP_ARG" ]; then
  echo "=== swapPool($CHAIN) via dev proxy ==="
  curl -s http://127.0.0.1:5173/graphql -H 'content-type: application/json' \
    --data "{\"query\":\"{ swapPool(chainId:$CHAIN){ address stable tokens{ symbol reserve isStable } } }\"}"; echo
fi
echo "=== running pids ==="
pgrep -af 'anvil|graphql-api|vite' | grep -v pgrep || true
