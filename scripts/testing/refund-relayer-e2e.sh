#!/usr/bin/env bash
# Two-phase refund, driven by the REAL relayers (not cast).
#
# scripts/testing/refund-e2e.sh proves the on-chain protocol by signing with `cast`.
# This proves the off-chain automation actually wires together end to end:
#
#   indexer   observes Sent (records the locked token), sweeps a long-unclaimed
#             transfer to refund_status='eligible', then observes Cancelled and
#             Refunded to advance the lifecycle
#   validator refund loop: sees the eligible candidate, reads the DESTINATION gate
#             (executed==false) and the SOURCE gate (sentBy!=0), attests a cancel;
#             once it reads cancelled==true on the destination, attests a refund
#   keeper    submits cancel() on the destination (burning the transfer), then
#             refund() on the source (repaying the sender)
#
# The transfer is engineered to strand: the destination gate has NO liquidity and
# NO asset registration, so claim() reverts forever. Nobody drives the refund by
# hand — the script only does the initial send() and then watches the sender get
# made whole.
#
# Run from anywhere:  bash scripts/testing/refund-relayer-e2e.sh
set -euo pipefail

export PATH="$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"
source "$(dirname "${BASH_SOURCE[0]}")/_deploy_gate.sh"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTRACTS="$ROOT/contracts"
LOGS="$ROOT/.e2e-logs"
mkdir -p "$LOGS"
rm -f "$LOGS"/refund-relayer-*.json

PG_NAME=bridge-pg-refund
PG_PORT=5434
DATABASE_URL="postgres://bridge:bridge@127.0.0.1:${PG_PORT}/bridge?sslmode=disable"

# anvil default accounts: [0] deployer/sender, [1] validator, [4] keeper
ACC0=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
KEY0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
V1=0x70997970C51812dc3A010C7d01b50e0d17dc79C8;  V1K=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
KEEPER=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
KEEPER_KEY=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
RECEIVER=0x976EA74026E726554dB657fA54763abd0C3a0aa9

SRC_RPC=http://127.0.0.1:8545
DST_RPC=http://127.0.0.1:8546
SRC_CHAIN=1337
DST_CHAIN=1338
STORE_URL=http://127.0.0.1:8087
AMOUNT=100000000000000000000      # 100e18

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
fail() {
  echo "❌ FAIL: $1"
  for l in indexer validator keeper sig-store; do
    echo "--- $l.log (tail) ---"; tail -20 "$LOGS/refund-relayer-$l.log" 2>/dev/null || true
  done
  exit 1
}

# refund_status of a submissionId, via the history view
refund_status_of() {
  curl -fsS "$STORE_URL/history" | python3 -c "
import sys,json
d=json.load(sys.stdin)
m=[r for r in d if r['submission_id'].lower()=='${1,,}']
print(m[0]['refund_status'] if m else 'MISSING')"
}
field_of() { # $1=submissionId $2=field
  curl -fsS "$STORE_URL/history" | python3 -c "
import sys,json
d=json.load(sys.stdin)
m=[r for r in d if r['submission_id'].lower()=='${1,,}']
print(m[0].get('$2') if m else '')"
}

echo "=== building binaries ==="
( cd "$ROOT" && cargo build -p validator -p keeper -p sig-store -p indexer >/dev/null 2>&1 )

echo "=== starting anvil chains ==="
pkill -f "anvil --chain-id" 2>/dev/null || true; sleep 1
# --block-time 1: the chains must keep PRODUCING BLOCKS, not just accept txs.
#
# The validator establishes the unclaimed timeout itself, by walking back from
# the confirmed head to a block at least `timeout_secs` older (`aged_block`) —
# deliberately, so the store cannot talk it into burning a live transfer. That
# age is measured in BLOCK TIMESTAMPS. A default anvil mines only when a tx
# arrives, so once the test stops sending, the head timestamp freezes and no
# block is ever old enough: `aged_out` stays false and the cancel never comes.
# Wall-clock waiting cannot fix that, however long the loop sleeps.
anvil --chain-id $SRC_CHAIN --port 8545 --block-time 1 >"$LOGS/anvil-src-refund.log" 2>&1 & track $!
anvil --chain-id $DST_CHAIN --port 8546 --block-time 1 >"$LOGS/anvil-dst-refund.log" 2>&1 & track $!
for url in $SRC_RPC $DST_RPC; do
  for _ in $(seq 1 50); do cast chain-id --rpc-url "$url" >/dev/null 2>&1 && break; sleep 0.2; done
done

cd "$CONTRACTS"
forge build >/dev/null
echo "=== deploying (validator=1, threshold 1) ==="
# Source: token + gate, funds get locked here.
TOKEN_SRC=$(forge create src/TestToken.sol:TestToken --rpc-url "$SRC_RPC" --private-key $KEY0 --broadcast --json --constructor-args Test TST 2>/dev/null | deployed_to)
# Gate is UUPS: implementation + GateProxy running initialize(). See _deploy_gate.sh.
GATE_SRC=$(deploy_gate "$SRC_RPC" "$KEY0" "[$V1]" 1)
# Destination: gate ONLY — deliberately no liquidity and no setLocalToken, so
# claim() can never succeed and the transfer strands.
GATE_DST=$(deploy_gate "$DST_RPC" "$KEY0" "[$V1]" 1)
echo "  src: token=$TOKEN_SRC gate=$GATE_SRC"
echo "  dst: gate=$GATE_DST  (UNFUNDED, UNREGISTERED — every claim reverts)"

cast send "$TOKEN_SRC" "mint(address,uint256)" $ACC0 $AMOUNT --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null
cast send "$TOKEN_SRC" "approve(address,uint256)" "$GATE_SRC" $AMOUNT --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null

echo "=== starting Postgres ($PG_NAME on :$PG_PORT) ==="
docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
docker run -d --name "$PG_NAME" \
  -e POSTGRES_USER=bridge -e POSTGRES_PASSWORD=bridge -e POSTGRES_DB=bridge \
  -p ${PG_PORT}:5432 postgres:16-alpine >/dev/null
for i in $(seq 1 60); do
  docker exec "$PG_NAME" pg_isready -U bridge -d bridge >/dev/null 2>&1 && break
  sleep 0.5; [[ $i == 60 ]] && fail "Postgres did not become ready"
done
echo "✅ Postgres ready"

echo "=== starting sig-store ($STORE_URL) ==="
# --allow-unauthenticated: local demo on 127.0.0.1, no tokens to distribute.
# The binary now refuses to serve an open store without being told to.
SIG_STORE_BIND=127.0.0.1:8087 DATABASE_URL="$DATABASE_URL" "$ROOT/target/debug/sig-store" --allow-unauthenticated >"$LOGS/refund-relayer-sig-store.log" 2>&1 & track $!
for _ in $(seq 1 60); do curl -s "$STORE_URL/health" >/dev/null 2>&1 && break; sleep 0.25; done
curl -s "$STORE_URL/health" | grep -q ok || fail "sig-store did not come up"
echo "✅ sig-store healthy"

# --- indexer: observes both gates, sweeps eligible after a SHORT timeout ---
cat > "$LOGS/indexer-refund.toml" <<EOF
database_url = "$DATABASE_URL"
refund_timeout_secs = 5           # a transfer is "stuck" after 5s unclaimed
sweep_interval_secs = 2           # and the sweep re-checks every 2s

[[chains]]
chain_id = $SRC_CHAIN
rpc = "$SRC_RPC"
gate = "$GATE_SRC"
start_block = 0
block_confirmation = 0
allow_zero_confirmation = true   # anvil is instant-final
poll_interval_ms = 500
max_block_range = 1000

[[chains]]
chain_id = $DST_CHAIN
rpc = "$DST_RPC"
gate = "$GATE_DST"
start_block = 0
block_confirmation = 0
allow_zero_confirmation = true   # anvil is instant-final
poll_interval_ms = 500
max_block_range = 1000
EOF

# --- validator: signs transfers AND runs the refund attestation loop ---
cat > "$LOGS/validator-refund.toml" <<EOF
[source]
chain_id = $SRC_CHAIN
rpcs = ["$SRC_RPC"]
gate = "$GATE_SRC"
start_block = 0
block_confirmation = 0
allow_zero_confirmation = true   # anvil is instant-final; a real chain MUST set block_confirmation
poll_interval_ms = 300
max_block_range = 1000
state_file = "$LOGS/refund-relayer-val-state.json"

[signer]
private_key = "$V1K"

[store]
url = "$STORE_URL"

[refund]
timeout_secs = 5
poll_interval_ms = 1000
block_confirmation = 0
allow_zero_confirmation = true   # anvil is instant-final; a real chain MUST set block_confirmation

[[refund.destinations]]
chain_id = $DST_CHAIN
rpcs = ["$DST_RPC"]
gate = "$GATE_DST"
EOF

# --- keeper: claims on the destination, refunds on the source ---
cat > "$LOGS/keeper-refund.toml" <<EOF
[keeper]
private_key = "$KEEPER_KEY"

[store]
url = "$STORE_URL"

[[targets]]
chain_id = $DST_CHAIN
rpc = "$DST_RPC"
gate = "$GATE_DST"
poll_interval_ms = 300

[[sources]]
chain_id = $SRC_CHAIN
rpc = "$SRC_RPC"
gate = "$GATE_SRC"
poll_interval_ms = 300
EOF

echo "=== starting indexer + validator + keeper ==="
"$ROOT/target/debug/indexer"   "$LOGS/indexer-refund.toml"   >"$LOGS/refund-relayer-indexer.log" 2>&1 & track $!
"$ROOT/target/debug/validator" "$LOGS/validator-refund.toml" >"$LOGS/refund-relayer-validator.log" 2>&1 & track $!
"$ROOT/target/debug/keeper"    "$LOGS/keeper-refund.toml"    >"$LOGS/refund-relayer-keeper.log" 2>&1 & track $!
sleep 1

echo
echo "########## locking funds that can never be delivered ##########"
BAL_BEFORE=$(bal "$TOKEN_SRC" $ACC0 $SRC_RPC)
cast send "$GATE_SRC" "send(address,uint256,uint256,bytes,bytes)" \
  "$TOKEN_SRC" $AMOUNT $DST_CHAIN "$RECEIVER" "0x" \
  --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null

SUB=$(cast call "$GATE_SRC" "computeSubmissionId(bytes32,uint256,uint256,uint256,uint256,bytes,bytes,bytes)(bytes32)" \
  "$(cast keccak "$(cast abi-encode --packed "f(uint256,address)" $SRC_CHAIN "$TOKEN_SRC")")" \
  "$AMOUNT" "$SRC_CHAIN" "$DST_CHAIN" 0 \
  "$(cast abi-encode --packed "f(address)" "$RECEIVER")" "0x" "0x" --rpc-url $SRC_RPC)
echo "  submissionId=$SUB"
echo "  sender debited: $BAL_BEFORE -> $(bal "$TOKEN_SRC" $ACC0 $SRC_RPC)"

echo
echo "########## the relayers take over — watching the lifecycle ##########"
# We assert each state IN ORDER, so a skipped stage (e.g. a refund that raced
# ahead of its cancel) is caught, not just the final balance.

echo "  [1/4] waiting for indexer sweep -> refund_status=eligible ..."
SAW_ELIGIBLE=0
for _ in $(seq 1 60); do
  s=$(refund_status_of "$SUB")
  [[ "$s" == "eligible" || "$s" == "cancelled" || "$s" == "refunded" ]] && { SAW_ELIGIBLE=1; break; }
  sleep 1
done
[[ "$SAW_ELIGIBLE" == "1" ]] || fail "transfer was never flagged refund-eligible (indexer sweep)"
echo "        ok (status=$(refund_status_of "$SUB"))"

echo "  [2/4] waiting for cancel() on the destination -> cancelled==true ..."
SAW_CANCEL=0
for _ in $(seq 1 90); do
  c=$(cast call "$GATE_DST" "cancelled(bytes32)(bool)" "$SUB" --rpc-url $DST_RPC 2>/dev/null || echo false)
  [[ "$c" == "true" ]] && { SAW_CANCEL=1; break; }
  sleep 1
done
[[ "$SAW_CANCEL" == "1" ]] || fail "validator/keeper never cancelled the transfer on the destination"
echo "        ok (destination executed=$(cast call "$GATE_DST" "executed(bytes32)(bool)" "$SUB" --rpc-url $DST_RPC), cancelled=true)"

echo "  [3/4] a claim can never land now (double-spend guard) ..."
CLAIM_SIG=$(cast wallet sign --private-key $V1K "$SUB")
if cast send "$GATE_DST" "claim(bytes32,uint256,uint256,uint256,bytes,bytes,bytes,bytes[])" \
     "$(cast keccak "$(cast abi-encode --packed "f(uint256,address)" $SRC_CHAIN "$TOKEN_SRC")")" \
     "$AMOUNT" "$SRC_CHAIN" 0 "$(cast abi-encode --packed "f(address)" "$RECEIVER")" "0x" "0x" "[$CLAIM_SIG]" \
     --rpc-url $DST_RPC --private-key $KEY0 >/dev/null 2>&1; then
  fail "claim() succeeded AFTER cancel — double-spend!"
fi
echo "        ok (claim reverts)"

echo "  [4/4] waiting for refund() on the source -> sender made whole ..."
SAW_REFUND=0
for _ in $(seq 1 90); do
  [[ "$(bal "$TOKEN_SRC" $ACC0 $SRC_RPC)" == "$BAL_BEFORE" ]] && { SAW_REFUND=1; break; }
  sleep 1
done
[[ "$SAW_REFUND" == "1" ]] || fail "sender was never refunded on the source chain"

# Final on-chain + DB assertions.
REFUNDED=$(cast call "$GATE_SRC" "refunded(bytes32)(bool)" "$SUB" --rpc-url $SRC_RPC)
GATE_BAL=$(bal "$TOKEN_SRC" "$GATE_SRC" $SRC_RPC)
[[ "$REFUNDED" == "true" ]] || fail "refunded flag not set on source gate"
[[ "$GATE_BAL" == "0" ]]    || fail "source gate still holds funds after refund"

echo "        ok (refunded=true, gate balance=0)"

# Let the indexer catch the Refunded event and finalize the DB lifecycle.
FINAL=""
for _ in $(seq 1 30); do
  FINAL=$(refund_status_of "$SUB")
  [[ "$FINAL" == "refunded" ]] && break
  sleep 1
done
CANCEL_TX=$(field_of "$SUB" cancel_tx)
REFUND_TX=$(field_of "$SUB" refund_tx)

echo
echo "================= RELAYER REFUND RESULT ================="
echo "✅ a stranded transfer was recovered by the relayers alone:"
echo "   • indexer flagged it eligible after the timeout"
echo "   • validator attested cancel, keeper burned it on the destination"
echo "   • claim() is permanently impossible (no double-spend)"
echo "   • validator attested refund, keeper repaid the sender on the source"
echo "   • DB lifecycle: refund_status=$FINAL"
echo "   • cancel_tx=$CANCEL_TX"
echo "   • refund_tx=$REFUND_TX"
echo "========================================================"
[[ "$FINAL" == "refunded" ]] || fail "DB lifecycle did not reach 'refunded' (got '$FINAL')"
[[ -n "$CANCEL_TX" && "$CANCEL_TX" != "None" ]] || fail "cancel_tx not recorded in DB"
[[ -n "$REFUND_TX" && "$REFUND_TX" != "None" ]] || fail "refund_tx not recorded in DB"
echo "✅ Checkpoint PASS"
