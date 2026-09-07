#!/usr/bin/env bash
# Launch the FULL live bridge stack as detached services that survive past this
# shell, so you can bridge from the browser (Bridge tab) end-to-end:
#
#   anvil A (1337) + anvil B (1338)
#   deploy Gate + TestToken on each, wire validators/threshold/liquidity
#   sig-store + 2 validators (threshold 2) + keeper
#   graphql-api  --store-url <live store>  --gate <dest>  --allow-mutations
#   vite dev server, seeded with the freshly deployed addresses
#
# After this, import anvil account 0 into MetaMask and bridge from the UI.
# Re-running redeploys cleanly. Stop everything with:
#   fuser -k 8545/tcp 8546/tcp 8080/tcp 8088/tcp 5173/tcp ; pkill -f 'anvil --chain-id'
#   docker rm -f bridge-pg-live
set -euo pipefail

# Native Linux node (nvm). Pick the newest installed version rather than pinning
# one: a hardcoded path silently vanishes on the next `nvm install`, and then
# PATH falls back to whatever `node` the shell has — often none at all, which
# surfaces as a confusing "command not found" deep inside the run. Same
# auto-detect idiom as scripts/run.sh.
NODE_BIN="${NODE_BIN:-$(ls -d "$HOME"/.nvm/versions/node/*/bin 2>/dev/null | sort -V | tail -1 || true)}"
export PATH="${NODE_BIN:+$NODE_BIN:}$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"
source "$(dirname "${BASH_SOURCE[0]}")/_deploy_gate.sh"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTRACTS="$ROOT/contracts"
WEB="$ROOT/frontend"
LOG=/tmp/bridge-run
mkdir -p "$LOG"

# Postgres-backed sig-store (the file-per-id store was retired). Runs in Docker.
PG_NAME=bridge-pg-live
PG_PORT=5433
DATABASE_URL="postgres://bridge:bridge@127.0.0.1:${PG_PORT}/bridge?sslmode=disable"
# Wipe scan cursors — a reset chain restarts at block 0, so stale resume points
# would make validators skip the new events. Matches both -A.json and -B.json.
rm -f "$ROOT"/.live-val*-state*.json

# Well-known public anvil dev keys (test-only; never use on a real network).
ACC0=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
KEY0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
V1=0x70997970C51812dc3A010C7d01b50e0d17dc79C8;  V1K=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
V2=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC;  V2K=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
KEEPER_KEY=0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a

SRC_RPC=http://127.0.0.1:8545; SRC_CHAIN=1337
DST_RPC=http://127.0.0.1:8546; DST_CHAIN=1338
STORE_URL=http://127.0.0.1:8080
GQL_BIND=127.0.0.1:8088
MINT=1000000000000000000000000   # 1,000,000e18

deployed_to() { grep deployedTo | grep -oE '0x[0-9a-fA-F]{40}' | head -1; }

# Run a long-lived service detached from this shell so it survives the tool call.
spawn() { setsid bash -c "exec $1" >"$LOG/$2" 2>&1 < /dev/null & disown || true; }

echo "=== kill prior run (services don't all hold ports, so pkill by name too) ==="
fuser -k 8545/tcp 8546/tcp 8080/tcp 8088/tcp 5173/tcp 2>/dev/null || true
pkill -f 'anvil --chain-id' 2>/dev/null || true
pkill -f 'target/debug/validator'  2>/dev/null || true
pkill -f 'target/debug/keeper'     2>/dev/null || true
pkill -f 'target/debug/sig-store'  2>/dev/null || true
pkill -f 'target/debug/graphql-api' 2>/dev/null || true
docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
sleep 1.5

echo "=== build rust services ==="
( cd "$ROOT" && cargo build -p validator -p keeper -p sig-store -p graphql-api >/dev/null 2>&1 )

echo "=== boot anvil A (1337) + B (1338) ==="
spawn "anvil --chain-id $SRC_CHAIN --port 8545 --host 127.0.0.1" anvil-src.log
spawn "anvil --chain-id $DST_CHAIN --port 8546 --host 127.0.0.1" anvil-dst.log
for url in $SRC_RPC $DST_RPC; do
  for _ in $(seq 1 60); do cast chain-id --rpc-url "$url" >/dev/null 2>&1 && break; sleep 0.2; done
done

echo "=== deploy gates + tokens (2 validators, threshold 2) ==="
( cd "$CONTRACTS" && forge build >/dev/null )
cd "$CONTRACTS"
TOKEN_SRC=$(forge create src/TestToken.sol:TestToken --rpc-url "$SRC_RPC" --private-key $KEY0 --broadcast --json --constructor-args Test TST 2>/dev/null | deployed_to)
# Gate is UUPS: implementation + GateProxy running initialize(). See _deploy_gate.sh.
GATE_SRC=$(deploy_gate "$SRC_RPC" "$KEY0" "[$V1,$V2]" 2)
TOKEN_DST=$(forge create src/TestToken.sol:TestToken --rpc-url "$DST_RPC" --private-key $KEY0 --broadcast --json --constructor-args Test TST 2>/dev/null | deployed_to)
GATE_DST=$(deploy_gate "$DST_RPC" "$KEY0" "[$V1,$V2]" 2)

echo "    TOKEN_SRC=$TOKEN_SRC  GATE_SRC=$GATE_SRC"
echo "    TOKEN_DST=$TOKEN_DST  GATE_DST=$GATE_DST"

echo "=== fund both chains for BIDIRECTIONAL bridging (A<->B) ==="
# debridgeId = keccak(originChainId padded to 32 bytes || originToken). Each
# destination gate maps the *origin* asset's id to its own local token.
PREFIX_A=$(printf '%064x' $SRC_CHAIN); DEBRIDGE_A=$(cast keccak "0x${PREFIX_A}${TOKEN_SRC#0x}")
PREFIX_B=$(printf '%064x' $DST_CHAIN); DEBRIDGE_B=$(cast keccak "0x${PREFIX_B}${TOKEN_DST#0x}")

# account0 holds spendable tokens on BOTH chains (bridge from either side).
cast send "$TOKEN_SRC" "mint(address,uint256)" $ACC0 $MINT --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null
cast send "$TOKEN_DST" "mint(address,uint256)" $ACC0 $MINT --rpc-url $DST_RPC --private-key $KEY0 >/dev/null

# Each gate needs liquidity to PAY OUT inbound claims:
#   gate B pays A->B claims;  gate A pays B->A claims.
cast send "$TOKEN_DST" "mint(address,uint256)" "$GATE_DST" $MINT --rpc-url $DST_RPC --private-key $KEY0 >/dev/null
cast send "$TOKEN_SRC" "mint(address,uint256)" "$GATE_SRC" $MINT --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null

# Register the inbound asset on each destination gate.
cast send "$GATE_DST" "setLocalToken(bytes32,address)" "$DEBRIDGE_A" "$TOKEN_DST" --rpc-url $DST_RPC --private-key $KEY0 >/dev/null
cast send "$GATE_SRC" "setLocalToken(bytes32,address)" "$DEBRIDGE_B" "$TOKEN_SRC" --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null

echo "=== start Postgres in Docker ($PG_NAME on :$PG_PORT) ==="
docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
docker run -d --name "$PG_NAME" \
  -e POSTGRES_USER=bridge -e POSTGRES_PASSWORD=bridge -e POSTGRES_DB=bridge \
  -p ${PG_PORT}:5432 postgres:16-alpine >/dev/null
for _ in $(seq 1 60); do docker exec "$PG_NAME" pg_isready -U bridge -d bridge >/dev/null 2>&1 && break; sleep 0.5; done

echo "=== boot Postgres-backed sig-store + 2 validators + keeper ==="
# sig-store retries the DB connection, so it tolerates Postgres still warming up.
# --allow-unauthenticated: local demo on 127.0.0.1, no tokens to distribute.
# The binary now refuses to serve an open store without being told to.
SIG_STORE_BIND=127.0.0.1:8080 DATABASE_URL="$DATABASE_URL" SIG_STORE_ALLOW_UNAUTHENTICATED=1 spawn "$ROOT/target/debug/sig-store" sig-store.log
for _ in $(seq 1 40); do curl -s "$STORE_URL/health" >/dev/null 2>&1 && break; sleep 0.25; done

# Each validator watches BOTH gates ([[sources]]), so either direction is signed.
# $1 cfg path  $2 signer key  $3 state-file prefix
write_vcfg() { cat > "$1" <<CFG
[[sources]]
chain_id = $SRC_CHAIN
rpcs = ["$SRC_RPC"]
gate = "$GATE_SRC"
start_block = 0
block_confirmation = 0
allow_zero_confirmation = true   # anvil is instant-final; a real chain MUST set block_confirmation
poll_interval_ms = 300
max_block_range = 1000
state_file = "$3-A.json"

[[sources]]
chain_id = $DST_CHAIN
rpcs = ["$DST_RPC"]
gate = "$GATE_DST"
start_block = 0
block_confirmation = 0
allow_zero_confirmation = true   # anvil is instant-final; a real chain MUST set block_confirmation
poll_interval_ms = 300
max_block_range = 1000
state_file = "$3-B.json"

[signer]
private_key = "$2"

[store]
url = "$STORE_URL"
CFG
}
write_vcfg "$ROOT/.live-val1.toml" "$V1K" "$ROOT/.live-val1-state"
write_vcfg "$ROOT/.live-val2.toml" "$V2K" "$ROOT/.live-val2-state"

# One keeper claims on BOTH chains ([[targets]]).
cat > "$LOG/.live-keeper.toml" <<CFG
[[targets]]
chain_id = $SRC_CHAIN
rpc = "$SRC_RPC"
gate = "$GATE_SRC"
poll_interval_ms = 300

[[targets]]
chain_id = $DST_CHAIN
rpc = "$DST_RPC"
gate = "$GATE_DST"
poll_interval_ms = 300

[keeper]
private_key = "$KEEPER_KEY"

[store]
url = "$STORE_URL"
CFG
spawn "$ROOT/target/debug/validator $ROOT/.live-val1.toml" val1.log
spawn "$ROOT/target/debug/validator $ROOT/.live-val2.toml" val2.log
spawn "$ROOT/target/debug/keeper    $LOG/.live-keeper.toml" keeper.log

echo "=== boot graphql-api (live store + BOTH gates + mutations) ==="
spawn "$ROOT/target/debug/graphql-api --bind $GQL_BIND --store-url $STORE_URL --threshold 2 --gate $SRC_CHAIN=$SRC_RPC,$GATE_SRC --gate $DST_CHAIN=$DST_RPC,$GATE_DST --allow-mutations" graphql-api.log
for _ in $(seq 1 40); do curl -s "http://$GQL_BIND/health" >/dev/null 2>&1 && break; sleep 0.25; done

echo "=== seed the frontend with the deployed addresses (frontend/.env.local) ==="
cat > "$WEB/.env.local" <<ENV
VITE_BRIDGE_CHAINS=[{"chainId":$SRC_CHAIN,"name":"Anvil A","rpcUrl":"$SRC_RPC","gate":"$GATE_SRC","token":"$TOKEN_SRC"},{"chainId":$DST_CHAIN,"name":"Anvil B","rpcUrl":"$DST_RPC","gate":"$GATE_DST","token":"$TOKEN_DST"}]
ENV

echo "=== boot vite dev server ==="
( cd "$WEB" && spawn "bunx vite --host 127.0.0.1 --port 5173 --strictPort" web.log )
for _ in $(seq 1 80); do curl -s "http://127.0.0.1:5173/" >/dev/null 2>&1 && break; sleep 0.3; done

echo
echo "=== health ==="
echo "anvil A : $(cast chain-id --rpc-url $SRC_RPC 2>/dev/null)"
echo "anvil B : $(cast chain-id --rpc-url $DST_RPC 2>/dev/null)"
echo "sig-store: $(curl -s $STORE_URL/health)"
echo "graphql  : $(curl -s http://$GQL_BIND/health)"
echo "frontend : $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5173/)"
echo
echo "=== bridge config (also seeded into the UI) ==="
echo "  SOURCE  chain $SRC_CHAIN  RPC $SRC_RPC"
echo "    gate  $GATE_SRC"
echo "    token $TOKEN_SRC   (account0 holds 1,000,000 TST)"
echo "  DEST    chain $DST_CHAIN  RPC $DST_RPC"
echo "    gate  $GATE_DST"
echo "    token $TOKEN_DST"
echo
echo "Open http://localhost:5173 -> Bridge. In MetaMask add networks 1337/1338"
echo "(RPCs above) and import account0 key:"
echo "  $KEY0"
