#!/usr/bin/env bash
# Phase 7 — N validators + threshold, via the HTTP sig-store.
#
# Real trust model: 3 independent validators (own keys), target gate threshold=2,
# all posting to the sig-store service; the keeper claims only with >= 2 sigs.
#
# Demonstrates:
#   * sig-store HTTP service (POST/GET signatures)
#   * 2-of-3 happy path: receiver paid
#   * 1-of-3 SAFETY: a single signature never executes (keeper waits)
#   * recovery: a 2nd validator comes back online -> threshold met -> claim
#
# Run from anywhere:  bash scripts/testing/phase7.sh
set -euo pipefail

export PATH="$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"
source "$(dirname "${BASH_SOURCE[0]}")/_deploy_gate.sh"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTRACTS="$ROOT/contracts"
LOGS="$ROOT/.e2e-logs"
mkdir -p "$LOGS"
rm -f "$LOGS"/val*-p7-state.json

# Postgres-backed sig-store (the file-per-id store was retired). Runs in Docker.
PG_NAME=bridge-pg-p7
PG_PORT=5433
DATABASE_URL="postgres://bridge:bridge@127.0.0.1:${PG_PORT}/bridge?sslmode=disable"

# anvil default accounts: [0] deployer/sender, [1..3] validators, [4] keeper, [6] receiver
ACC0=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
KEY0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
V1=0x70997970C51812dc3A010C7d01b50e0d17dc79C8;  V1K=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
V2=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC;  V2K=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
V3=0x90F79bf6EB2c4f870365E785982E1f101E93b906;  V3K=0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6
KEEPER_KEY=0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a
RECEIVER=0x976EA74026E726554dB657fA54763abd0C3a0aa9

SRC_RPC=http://127.0.0.1:8545
DST_RPC=http://127.0.0.1:8546
SRC_CHAIN=1337
DST_CHAIN=1338
STORE_URL=http://127.0.0.1:8080
AMOUNT=100000000000000000000      # 100e18
TWICE=200000000000000000000

declare -a PIDS=()
track() { PIDS+=("$1"); }
cleanup() {
  echo "--- cleaning up ---"
  for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done
  pkill -f "anvil --chain-id" 2>/dev/null || true
  docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

deployed_to() { grep deployedTo | grep -oE '0x[0-9a-fA-F]{40}' | head -1; }
bal() { cast call "$1" "balanceOf(address)(uint256)" "$2" --rpc-url "$3" | awk '{print $1}'; }
fail() { echo "❌ FAIL: $1"; echo "--- sig-store.log ---"; tail -15 "$LOGS/sig-store.log" 2>/dev/null || true;
         echo "--- keeper.log ---"; tail -15 "$LOGS/keeper-p7.log" 2>/dev/null || true; exit 1; }

start_validator() { # $1=cfg $2=logname  -> sets LAST_PID
  "$ROOT/target/debug/validator" "$1" >"$LOGS/$2.log" 2>&1 &
  LAST_PID=$!
}

echo "=== building binaries ==="
( cd "$ROOT" && cargo build -p validator -p keeper -p sig-store >/dev/null 2>&1 )

echo "=== starting anvil chains ==="
pkill -f "anvil --chain-id" 2>/dev/null || true; sleep 1
anvil --chain-id $SRC_CHAIN --port 8545 >"$LOGS/anvil-src-p7.log" 2>&1 & track $!
anvil --chain-id $DST_CHAIN --port 8546 >"$LOGS/anvil-dst-p7.log" 2>&1 & track $!
for url in $SRC_RPC $DST_RPC; do
  for i in $(seq 1 50); do cast chain-id --rpc-url "$url" >/dev/null 2>&1 && break; sleep 0.2; done
done

cd "$CONTRACTS"
forge build >/dev/null
echo "=== deploying (3 validators, threshold 2) ==="
TOKEN_SRC=$(forge create src/TestToken.sol:TestToken --rpc-url "$SRC_RPC" --private-key $KEY0 --broadcast --json --constructor-args Test TST 2>/dev/null | deployed_to)
# Gate is UUPS: implementation + GateProxy running initialize(). See _deploy_gate.sh.
GATE_SRC=$(deploy_gate "$SRC_RPC" "$KEY0" "[$V1,$V2,$V3]" 2)
TOKEN_DST=$(forge create src/TestToken.sol:TestToken --rpc-url "$DST_RPC" --private-key $KEY0 --broadcast --json --constructor-args Test TST 2>/dev/null | deployed_to)
GATE_DST=$(deploy_gate "$DST_RPC" "$KEY0" "[$V1,$V2,$V3]" 2)
echo "  src: token=$TOKEN_SRC gate=$GATE_SRC"
echo "  dst: token=$TOKEN_DST gate=$GATE_DST"

PREFIX=$(printf '%064x' $SRC_CHAIN)
DEBRIDGE_ID=$(cast keccak "0x${PREFIX}${TOKEN_SRC#0x}")

cast send "$TOKEN_SRC" "mint(address,uint256)" $ACC0 $TWICE --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null
cast send "$TOKEN_SRC" "approve(address,uint256)" "$GATE_SRC" $TWICE --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null
cast send "$TOKEN_DST" "mint(address,uint256)" "$GATE_DST" $TWICE --rpc-url $DST_RPC --private-key $KEY0 >/dev/null
cast send "$GATE_DST" "setLocalToken(bytes32,address)" "$DEBRIDGE_ID" "$TOKEN_DST" --rpc-url $DST_RPC --private-key $KEY0 >/dev/null

echo "=== starting Postgres in Docker ($PG_NAME on :$PG_PORT) ==="
docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
docker run -d --name "$PG_NAME" \
  -e POSTGRES_USER=bridge -e POSTGRES_PASSWORD=bridge -e POSTGRES_DB=bridge \
  -p ${PG_PORT}:5432 postgres:16-alpine >/dev/null
for i in $(seq 1 60); do
  docker exec "$PG_NAME" pg_isready -U bridge -d bridge >/dev/null 2>&1 && break
  sleep 0.5; [[ $i == 60 ]] && fail "Postgres did not become ready"
done
echo "✅ Postgres ready"

echo "=== starting Postgres-backed sig-store ($STORE_URL) ==="
# --allow-unauthenticated: local demo on 127.0.0.1, no tokens to distribute.
# The binary now refuses to serve an open store without being told to.
SIG_STORE_BIND=127.0.0.1:8080 DATABASE_URL="$DATABASE_URL" "$ROOT/target/debug/sig-store" --allow-unauthenticated >"$LOGS/sig-store.log" 2>&1 & track $!
for i in $(seq 1 60); do curl -s "$STORE_URL/health" >/dev/null 2>&1 && break; sleep 0.25; done
curl -s "$STORE_URL/health" | grep -q ok || fail "sig-store did not come up"
echo "✅ sig-store healthy"

write_vcfg() { # $1=path $2=key $3=statefile
  cat > "$1" <<EOF
[source]
chain_id = $SRC_CHAIN
rpcs = ["$SRC_RPC"]
gate = "$GATE_SRC"
start_block = 0
block_confirmation = 0
allow_zero_confirmation = true   # anvil is instant-final; a real chain MUST set block_confirmation
poll_interval_ms = 300
max_block_range = 1000
state_file = "$3"

[signer]
private_key = "$2"

[store]
url = "$STORE_URL"
EOF
}
write_vcfg "$ROOT/val1-p7.toml" "$V1K" "$LOGS/val1-p7-state.json"
write_vcfg "$ROOT/val2-p7.toml" "$V2K" "$LOGS/val2-p7-state.json"
write_vcfg "$ROOT/val3-p7.toml" "$V3K" "$LOGS/val3-p7-state.json"

cat > "$LOGS/keeper-p7.toml" <<EOF
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

echo "=== starting 3 validators + keeper ==="
start_validator "$ROOT/val1-p7.toml" val1-p7; V1_PID=$LAST_PID; track $V1_PID
start_validator "$ROOT/val2-p7.toml" val2-p7; V2_PID=$LAST_PID; track $V2_PID
start_validator "$ROOT/val3-p7.toml" val3-p7; V3_PID=$LAST_PID; track $V3_PID
"$ROOT/target/debug/keeper" "$LOGS/keeper-p7.toml" >"$LOGS/keeper-p7.log" 2>&1 & KEEPER_PID=$!; track $KEEPER_PID
sleep 1

send_one() {
  cast send "$GATE_SRC" "send(address,uint256,uint256,bytes,bytes)" \
    "$TOKEN_SRC" $AMOUNT $DST_CHAIN "$RECEIVER" "0x" \
    --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null
}
# submissionId of the record with the given decimal nonce (via the HTTP API)
sub_for_nonce() { curl -fsS "$STORE_URL/submissions" | python3 -c "import sys,json;d=json.load(sys.stdin);m=[r for r in d if r['nonce']==$1];print(m[0]['submission_id'] if m else '')"; }
# signature count for a submissionId
sig_count_id() { curl -fsS "$STORE_URL/submissions" | python3 -c "import sys,json;d=json.load(sys.stdin);m=[r for r in d if r['submission_id'].lower()=='${1,,}'];print(len(m[0]['signatures']) if m else 0)"; }

echo
echo "########## CHECK 1: 2-of-3 happy path ##########"
send_one    # nonce 0
PAID=0
for i in $(seq 1 80); do [[ "$(bal "$TOKEN_DST" "$RECEIVER" "$DST_RPC")" == "$AMOUNT" ]] && { PAID=1; break; }; sleep 0.25; done
[[ "$PAID" == "1" ]] || fail "receiver not paid by threshold-2 claim"
SUB0=$(sub_for_nonce 0)
N0=$(sig_count_id "$SUB0")
echo "  nonce-0 record $SUB0 has $N0 signatures (>=2 needed)"
[[ "$N0" -ge 2 ]] || fail "expected >=2 signatures for nonce 0"
echo "✅ 2-of-3 transfer paid receiver $AMOUNT"

echo
echo "########## CHECK 2: 1-of-3 must NOT execute (safety) ##########"
kill "$V2_PID" "$V3_PID" 2>/dev/null || true
wait "$V2_PID" 2>/dev/null || true; wait "$V3_PID" 2>/dev/null || true
echo "  stopped V2 and V3; only V1 online"
send_one    # nonce 1, only V1 will sign
sleep 3
SUB1=$(sub_for_nonce 1)
[[ -n "$SUB1" ]] || fail "no record created for nonce 1"
N1=$(sig_count_id "$SUB1")
EXECD1=$(cast call "$GATE_DST" 'executed(bytes32)(bool)' "$SUB1" --rpc-url $DST_RPC)
CUR_BAL=$(bal "$TOKEN_DST" "$RECEIVER" "$DST_RPC")
echo "  nonce-1 sigs=$N1  executed=$EXECD1  receiver=$CUR_BAL"
[[ "$N1" == "1" ]] || fail "expected exactly 1 signature with only V1 online (got $N1)"
[[ "$EXECD1" == "false" ]] || fail "claim executed with only 1 signature — THRESHOLD VIOLATED"
[[ "$CUR_BAL" == "$AMOUNT" ]] || fail "receiver balance changed below threshold"
echo "✅ below threshold: 1 signature, no claim (executed=false, balance unchanged)"

echo
echo "########## CHECK 3: recovery — V2 back online -> 2-of-3 -> claim ##########"
start_validator "$ROOT/val2-p7.toml" val2b-p7; V2_PID=$LAST_PID; track $V2_PID
echo "  restarted V2; waiting for threshold + claim"
PAID2=0
for i in $(seq 1 100); do [[ "$(bal "$TOKEN_DST" "$RECEIVER" "$DST_RPC")" == "$TWICE" ]] && { PAID2=1; break; }; sleep 0.25; done
EXECD1=$(cast call "$GATE_DST" 'executed(bytes32)(bool)' "$SUB1" --rpc-url $DST_RPC)
echo "  nonce-1 sigs=$(sig_count_id "$SUB1")  executed=$EXECD1  receiver=$(bal "$TOKEN_DST" "$RECEIVER" "$DST_RPC")"
[[ "$PAID2" == "1" && "$EXECD1" == "true" ]] || fail "recovery did not reach threshold/claim"
echo "✅ recovered: 2nd signature arrived, claim executed, receiver paid $TWICE total"

echo
echo "================= PHASE 7 RESULT ================="
echo "✅ Checkpoint 7 PASS:"
echo "   • HTTP sig-store mediates 3 independent validators"
echo "   • 2-of-3 threshold transfer succeeds"
echo "   • 1-of-3 fails safe (no execution below threshold)"
echo "   • recovery to 2-of-3 completes the claim"
echo "================================================="
echo "logs in $LOGS/ (sig-store.log, val{1,2,3}-p7.log, keeper-p7.log)"
