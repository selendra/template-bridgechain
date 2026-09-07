#!/usr/bin/env bash
# End-to-end test of the Postgres-backed sig-store + allowlists.
#
# Brings up the WHOLE stack in one shot (Postgres in Docker, two anvil chains,
# one validator threshold-1, one keeper, the Postgres-backed sig-store) and
# proves:
#   CHECK 1  allowlisted token bridges 1337->1338 and lands in transaction
#            history as status=claimed with a claim_tx.
#   CHECK 2  a NON-allowlisted token is BLOCKED: the validator withholds its
#            signature (no record, no claim) — funds lock on source, nothing
#            is attested or executed on the target.
#   CHECK 3  after the operator adds that token to the allowlist (live, no
#            restart), a fresh transfer of it now bridges and is claimed.
#   CHECK 4  a NON-allowlisted CHAIN pair is BLOCKED the same way.
#
# Run from anywhere:  bash scripts/testing/db-e2e.sh
set -euo pipefail
export PATH="$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"
source "$(dirname "${BASH_SOURCE[0]}")/_deploy_gate.sh"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTRACTS="$ROOT/contracts"
LOGS="$ROOT/.e2e-logs"
mkdir -p "$LOGS"
rm -f "$LOGS"/db-*.json "$LOGS"/db-*.log

PG_NAME=bridge-pg-e2e
PG_PORT=5433
DATABASE_URL="postgres://bridge:bridge@127.0.0.1:${PG_PORT}/bridge?sslmode=disable"

# anvil default accounts: [0] deployer/sender, [1] validator, [4] keeper, [6] receiver
ACC0=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
KEY0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
V1=0x70997970C51812dc3A010C7d01b50e0d17dc79C8; V1K=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
KEEPER_KEY=0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a
RECEIVER=0x976EA74026E726554dB657fA54763abd0C3a0aa9

SRC_RPC=http://127.0.0.1:8545
DST_RPC=http://127.0.0.1:8546
SRC_CHAIN=1337
DST_CHAIN=1338
OTHER_CHAIN=9999          # a chain pair we never allowlist (for CHECK 4)
STORE_URL=http://127.0.0.1:8080
AMOUNT=100000000000000000000   # 100e18

declare -a PIDS=()
track() { PIDS+=("$1"); }
cleanup() {
  echo "--- cleaning up ---"
  for p in "${PIDS[@]:-}"; do [[ -n "${p:-}" ]] && kill "$p" 2>/dev/null || true; done
  pkill -f "anvil --chain-id" 2>/dev/null || true
  docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

deployed_to() { grep deployedTo | grep -oE '0x[0-9a-fA-F]{40}' | head -1; }
bal() { cast call "$1" "balanceOf(address)(uint256)" "$2" --rpc-url "$3" | awk '{print $1}'; }
debridge_id() { local chain=$1 token=$2; cast keccak "0x$(printf '%064x' "$chain")${token#0x}"; }
fail() {
  echo "❌ FAIL: $1"
  echo "--- validator.log (tail) ---"; tail -25 "$LOGS/db-validator.log" 2>/dev/null || true
  echo "--- keeper.log (tail) ---";    tail -15 "$LOGS/db-keeper.log" 2>/dev/null || true
  echo "--- sig-store.log (tail) ---"; tail -15 "$LOGS/db-sig-store.log" 2>/dev/null || true
  exit 1
}

# --- JSON helpers over the sig-store HTTP API (python3 is always present) ----
hist_status_for() { # $1=debridge_id -> newest matching status, or NONE
  curl -fsS "$STORE_URL/history" | python3 -c "import sys,json;d=json.load(sys.stdin);m=[r for r in d if r['debridge_id'].lower()=='${1,,}'];print(m[0]['status'] if m else 'NONE')"
}
hist_claimtx_for() {
  curl -fsS "$STORE_URL/history" | python3 -c "import sys,json;d=json.load(sys.stdin);m=[r for r in d if r['debridge_id'].lower()=='${1,,}'];print(m[0].get('claim_tx') or 'NONE')"
}
subs_count_for() { # $1=debridge_id -> number of submission records with that token
  curl -fsS "$STORE_URL/submissions" | python3 -c "import sys,json;d=json.load(sys.stdin);print(sum(1 for r in d if r['debridge_id'].lower()=='${1,,}'))"
}
wait_status() { # $1=debridge_id $2=want  -> 0 once history reaches that status
  for i in $(seq 1 80); do [[ "$(hist_status_for "$1")" == "$2" ]] && return 0; sleep 0.25; done; return 1
}

echo "=== building binaries ==="
( cd "$ROOT" && cargo build -p validator -p keeper -p sig-store >/dev/null 2>&1 ) || fail "cargo build failed"

echo "=== starting Postgres in Docker ($PG_NAME on :$PG_PORT) ==="
docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
docker run -d --name "$PG_NAME" \
  -e POSTGRES_USER=bridge -e POSTGRES_PASSWORD=bridge -e POSTGRES_DB=bridge \
  -p ${PG_PORT}:5432 postgres:16-alpine >/dev/null
for i in $(seq 1 60); do
  docker exec "$PG_NAME" pg_isready -U bridge -d bridge >/dev/null 2>&1 && break
  sleep 0.5
  [[ $i == 60 ]] && fail "Postgres did not become ready"
done
echo "✅ Postgres ready"

echo "=== starting anvil chains ==="
pkill -f "anvil --chain-id" 2>/dev/null || true; sleep 1
anvil --chain-id $SRC_CHAIN --port 8545 >"$LOGS/db-anvil-src.log" 2>&1 & track $!
anvil --chain-id $DST_CHAIN --port 8546 >"$LOGS/db-anvil-dst.log" 2>&1 & track $!
for url in $SRC_RPC $DST_RPC; do
  for i in $(seq 1 50); do cast chain-id --rpc-url "$url" >/dev/null 2>&1 && break; sleep 0.2; done
done

cd "$CONTRACTS"
forge build >/dev/null
echo "=== deploying (1 validator, threshold 1); GOOD + BAD token on each chain ==="
TOKEN_GOOD=$(forge create src/TestToken.sol:TestToken  --rpc-url "$SRC_RPC" --private-key $KEY0 --broadcast --json --constructor-args Good GOOD 2>/dev/null | deployed_to)
TOKEN_BAD=$( forge create src/TestToken.sol:TestToken  --rpc-url "$SRC_RPC" --private-key $KEY0 --broadcast --json --constructor-args Bad  BAD  2>/dev/null | deployed_to)
# Gate is UUPS: implementation + GateProxy running initialize(). See _deploy_gate.sh.
GATE_SRC=$(  deploy_gate "$SRC_RPC" "$KEY0" "[$V1]" 1)
TOKEN_GOOD_DST=$(forge create src/TestToken.sol:TestToken --rpc-url "$DST_RPC" --private-key $KEY0 --broadcast --json --constructor-args Good GOOD 2>/dev/null | deployed_to)
TOKEN_BAD_DST=$( forge create src/TestToken.sol:TestToken --rpc-url "$DST_RPC" --private-key $KEY0 --broadcast --json --constructor-args Bad  BAD  2>/dev/null | deployed_to)
GATE_DST=$(  deploy_gate "$DST_RPC" "$KEY0" "[$V1]" 1)
echo "  src: good=$TOKEN_GOOD bad=$TOKEN_BAD gate=$GATE_SRC"
echo "  dst: good=$TOKEN_GOOD_DST bad=$TOKEN_BAD_DST gate=$GATE_DST"

DID_GOOD=$(debridge_id $SRC_CHAIN $TOKEN_GOOD)
DID_BAD=$(debridge_id $SRC_CHAIN $TOKEN_BAD)

# Source: give acc0 spendable balance; approve the gate. Bad token is sent twice
# (once while blocked, once after it's allowlisted) so fund 3x to be safe.
FUND=3000000000000000000000   # 3000e18
for t in "$TOKEN_GOOD" "$TOKEN_BAD"; do
  cast send "$t" "mint(address,uint256)" $ACC0 $FUND --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null
  cast send "$t" "approve(address,uint256)" "$GATE_SRC" $FUND --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null
done
# Target: pre-fund the gate with liquidity and register the local token per debridgeId,
# so the ONLY thing that can stop a claim is the allowlist (not missing liquidity).
cast send "$TOKEN_GOOD_DST" "mint(address,uint256)" "$GATE_DST" 1000000000000000000000 --rpc-url $DST_RPC --private-key $KEY0 >/dev/null
cast send "$TOKEN_BAD_DST"  "mint(address,uint256)" "$GATE_DST" 1000000000000000000000 --rpc-url $DST_RPC --private-key $KEY0 >/dev/null
cast send "$GATE_DST" "setLocalToken(bytes32,address)" "$DID_GOOD" "$TOKEN_GOOD_DST" --rpc-url $DST_RPC --private-key $KEY0 >/dev/null
cast send "$GATE_DST" "setLocalToken(bytes32,address)" "$DID_BAD"  "$TOKEN_BAD_DST"  --rpc-url $DST_RPC --private-key $KEY0 >/dev/null

echo "=== starting Postgres-backed sig-store ($STORE_URL) ==="
# --allow-unauthenticated: local demo on 127.0.0.1, no tokens to distribute.
# The binary now refuses to serve an open store without being told to.
#
# Keep this comment ABOVE the assignments: a comment line after a `\` swallows
# the continuation, so the env prefix never reaches the command and sig-store
# starts with no DATABASE_URL.
SIG_STORE_BIND=127.0.0.1:8080 DATABASE_URL="$DATABASE_URL" \
  "$ROOT/target/debug/sig-store" --allow-unauthenticated >"$LOGS/db-sig-store.log" 2>&1 & track $!
for i in $(seq 1 60); do curl -s "$STORE_URL/health" >/dev/null 2>&1 && break; sleep 0.25; done
curl -s "$STORE_URL/health" | grep -q ok || fail "sig-store did not come up (check DATABASE_URL / migrations)"
echo "✅ sig-store healthy (connected to Postgres, schema applied)"

echo "=== seeding allowlist: GOOD token + chain pair $SRC_CHAIN->$DST_CHAIN only ==="
SIG_STORE="$STORE_URL" TOKEN="$TOKEN_GOOD" CHAIN_A=$SRC_CHAIN CHAIN_B=$DST_CHAIN \
  bash "$ROOT/scripts/testing/allowlist.sh" add-token $SRC_CHAIN "$TOKEN_GOOD" GOOD >/dev/null
curl -fsS -X POST "$STORE_URL/allowed/chains" -H 'content-type: application/json' \
  -d "{\"chain_id_from\":$SRC_CHAIN,\"chain_id_to\":$DST_CHAIN}" >/dev/null
echo "  allowed tokens:"; curl -fsS "$STORE_URL/allowed/tokens"

# config: single validator + keeper, both pointed at the Postgres-backed sig-store
cat > "$LOGS/db-validator.toml" <<EOF
[source]
chain_id = $SRC_CHAIN
rpcs = ["$SRC_RPC"]
gate = "$GATE_SRC"
start_block = 0
block_confirmation = 0
allow_zero_confirmation = true   # anvil is instant-final; a real chain MUST set block_confirmation
poll_interval_ms = 300
max_block_range = 1000
state_file = "$LOGS/db-val-state.json"

[signer]
private_key = "$V1K"

[store]
url = "$STORE_URL"
EOF
cat > "$LOGS/db-keeper.toml" <<EOF
[target]
chain_id = $DST_CHAIN
rpc = "$DST_RPC"
gate = "$GATE_DST"
poll_interval_ms = 300

[keeper]
private_key = "$KEEPER_KEY"

[store]
url = "$STORE_URL"
EOF

echo "=== starting validator + keeper ==="
"$ROOT/target/debug/validator" "$LOGS/db-validator.toml" >"$LOGS/db-validator.log" 2>&1 & track $!
"$ROOT/target/debug/keeper"    "$LOGS/db-keeper.toml"    >"$LOGS/db-keeper.log"    2>&1 & track $!
sleep 1

send() { # $1=token $2=chainTo
  cast send "$GATE_SRC" "send(address,uint256,uint256,bytes,bytes)" \
    "$1" $AMOUNT "$2" "$RECEIVER" "0x" --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null
}

echo
echo "########## CHECK 1: allowlisted token bridges + lands in history ##########"
send "$TOKEN_GOOD" $DST_CHAIN
wait_status "$DID_GOOD" claimed || fail "allowlisted GOOD transfer never reached status=claimed"
TX=$(hist_claimtx_for "$DID_GOOD")
GOOD_BAL=$(bal "$TOKEN_GOOD_DST" "$RECEIVER" "$DST_RPC")
echo "  history: status=claimed claim_tx=$TX  receiver good-bal=$GOOD_BAL"
[[ "$TX" == 0x* ]]          || fail "history claim_tx for GOOD missing"
[[ "$GOOD_BAL" == "$AMOUNT" ]] || fail "receiver was not paid the GOOD amount"
echo "✅ GOOD token bridged 100, history shows status=claimed with a claim_tx"

echo
echo "########## CHECK 2: NON-allowlisted token is blocked (no signature, no claim) ##########"
GOOD_DEBRIDGE_SUBS=$(subs_count_for "$DID_GOOD")
send "$TOKEN_BAD" $DST_CHAIN
sleep 4   # give the validator time to see + (refuse to) sign it
BAD_SUBS=$(subs_count_for "$DID_BAD")
BAD_BAL=$(bal "$TOKEN_BAD_DST" "$RECEIVER" "$DST_RPC")
BLOCKED_LOG=$(grep -c "BLOCKED by allowlist" "$LOGS/db-validator.log" || true)
echo "  bad-token records in store=$BAD_SUBS  receiver bad-bal=$BAD_BAL  validator BLOCKED logs=$BLOCKED_LOG"
[[ "$BAD_SUBS" == "0" ]] || fail "a record was created for the non-allowlisted token (validator should withhold)"
[[ "$BAD_BAL" == "0" ]]  || fail "non-allowlisted token was paid out on target"
[[ "$BLOCKED_LOG" -ge 1 ]] || fail "validator did not log 'BLOCKED by allowlist'"
echo "✅ non-allowlisted token attested by nobody → no record, no claim (funds lock on source)"

echo
echo "########## CHECK 3: allowlist the token (live) → next transfer bridges ##########"
SIG_STORE="$STORE_URL" bash "$ROOT/scripts/testing/allowlist.sh" add-token $SRC_CHAIN "$TOKEN_BAD" BAD >/dev/null
echo "  added BAD token to allowlist; sending again"
send "$TOKEN_BAD" $DST_CHAIN
wait_status "$DID_BAD" claimed || fail "token did not bridge after being allowlisted"
echo "  receiver bad-bal=$(bal "$TOKEN_BAD_DST" "$RECEIVER" "$DST_RPC")  history status=claimed"
[[ "$(bal "$TOKEN_BAD_DST" "$RECEIVER" "$DST_RPC")" == "$AMOUNT" ]] || fail "receiver not paid after allowlisting"
echo "✅ once allowlisted, the same token bridges and is claimed (live refresh, no restart)"

echo
echo "########## CHECK 4: non-allowlisted CHAIN pair is blocked ##########"
# GOOD token is allowed, but only for $SRC_CHAIN->$DST_CHAIN. Send it to $OTHER_CHAIN.
BLOCK_BEFORE=$(grep -c "BLOCKED by allowlist" "$LOGS/db-validator.log" || true)
send "$TOKEN_GOOD" $OTHER_CHAIN
sleep 4
BLOCK_AFTER=$(grep -c "BLOCKED by allowlist" "$LOGS/db-validator.log" || true)
echo "  validator BLOCKED logs: before=$BLOCK_BEFORE after=$BLOCK_AFTER"
[[ "$BLOCK_AFTER" -gt "$BLOCK_BEFORE" ]] || fail "transfer to non-allowlisted chain $OTHER_CHAIN was not blocked"
echo "✅ allowed token to a non-allowlisted chain pair → blocked"

echo
echo "================= DB E2E RESULT ================="
echo "✅ Postgres-backed sig-store works end to end:"
echo "   • transaction history persisted in Postgres (status signed→claimed + claim_tx)"
echo "   • token allowlist enforced at the validator (and keeper)"
echo "   • chain-pair allowlist enforced"
echo "   • allowlist edits apply live (no restart)"
echo "--- final transaction history ---"
curl -fsS "$STORE_URL/history" | python3 -m json.tool
echo "================================================="
