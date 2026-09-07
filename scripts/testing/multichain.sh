#!/usr/bin/env bash
# Multi-destination demo — one source chain (A) bridging to TWO targets (B, C)
# served by a SINGLE keeper configured with two [[targets]] blocks.
#
# Boots three anvil chains, deploys Gate+TestToken on each, runs one validator
# (watching A) and one multi-target keeper, then sends A->B and A->C and asserts
# BOTH receivers are paid on their respective chains.
#
# Run from anywhere:  bash scripts/testing/multichain.sh
set -euo pipefail

export PATH="$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"
source "$(dirname "${BASH_SOURCE[0]}")/_deploy_gate.sh"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTRACTS="$ROOT/contracts"
STORE="$ROOT/sig-store-data"
LOGS="$ROOT/.e2e-logs"
mkdir -p "$LOGS"
rm -rf "$STORE"; mkdir -p "$STORE"

# --- anvil default accounts ---
ACC0=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
KEY0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
VALIDATOR=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
VALIDATOR_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
KEEPER_KEY=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
RECEIVER_B=0x90F79bf6EB2c4f870365E785982E1f101E93b906
RECEIVER_C=0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65

SRC_RPC=http://127.0.0.1:8545
B_RPC=http://127.0.0.1:8546
C_RPC=http://127.0.0.1:8547
SRC_CHAIN=1337
B_CHAIN=1338
C_CHAIN=1339
AMOUNT=100000000000000000000   # 100e18

cleanup() {
  echo "--- cleaning up ---"
  for p in VALIDATOR_PID KEEPER_PID ANVIL_S_PID ANVIL_B_PID ANVIL_C_PID; do
    [[ -n "${!p:-}" ]] && kill "${!p}" 2>/dev/null || true
  done
}
trap cleanup EXIT

deployed_to() { grep deployedTo | grep -oE '0x[0-9a-fA-F]{40}' | head -1; }

echo "=== building rust binaries ==="
( cd "$ROOT" && cargo build -p validator -p keeper >/dev/null 2>&1 )

echo "=== killing stale anvil ==="
pkill -f "anvil --chain-id" 2>/dev/null || true
sleep 1

echo "=== starting anvil chains (A=$SRC_CHAIN, B=$B_CHAIN, C=$C_CHAIN) ==="
anvil --chain-id $SRC_CHAIN --port 8545 >"$LOGS/anvil-A.log" 2>&1 &
ANVIL_S_PID=$!
anvil --chain-id $B_CHAIN --port 8546 >"$LOGS/anvil-B.log" 2>&1 &
ANVIL_B_PID=$!
anvil --chain-id $C_CHAIN --port 8547 >"$LOGS/anvil-C.log" 2>&1 &
ANVIL_C_PID=$!

for url in $SRC_RPC $B_RPC $C_RPC; do
  for i in $(seq 1 50); do
    if cast chain-id --rpc-url "$url" >/dev/null 2>&1; then break; fi
    sleep 0.2
  done
done
echo "  A=$(cast chain-id --rpc-url $SRC_RPC) B=$(cast chain-id --rpc-url $B_RPC) C=$(cast chain-id --rpc-url $C_RPC)"

cd "$CONTRACTS"
forge build >/dev/null

deploy_one() {  # $1 = rpc, $2 = label, $3 = "TOKEN"|"GATE"
  local rpc=$1 label=$2 kind=$3 out addr
  # Gate is UUPS — an implementation plus a GateProxy that runs
  # initialize(). The old single `forge create Gate --constructor-args`
  # form no longer compiles against it. See _deploy_gate.sh.
  if [[ "$kind" == "GATE" ]]; then
    deploy_gate "$rpc" "$KEY0" "[$VALIDATOR]" 1
    return
  fi
  if [[ "$kind" == "TOKEN" ]]; then
    out=$(forge create src/TestToken.sol:TestToken --rpc-url "$rpc" --private-key $KEY0 \
          --broadcast --json --constructor-args Test TST 2>"$LOGS/deploy-$label-err.log")
  fi
  echo "$out" > "$LOGS/deploy-$label.log"
  addr=$(echo "$out" | deployed_to || true)
  if [[ -z "$addr" ]]; then
    echo "!! deploy $label failed; raw output:" >&2
    cat "$LOGS/deploy-$label.log" >&2; cat "$LOGS/deploy-$label-err.log" >&2
    exit 1
  fi
  echo "$addr"
}

echo "=== deploying on source A ($SRC_CHAIN) ==="
TOKEN_SRC=$(deploy_one "$SRC_RPC" A-token TOKEN)
GATE_SRC=$(deploy_one "$SRC_RPC" A-gate GATE)
echo "  token=$TOKEN_SRC gate=$GATE_SRC"

echo "=== deploying on target B ($B_CHAIN) ==="
TOKEN_B=$(deploy_one "$B_RPC" B-token TOKEN)
GATE_B=$(deploy_one "$B_RPC" B-gate GATE)
echo "  token=$TOKEN_B gate=$GATE_B"

echo "=== deploying on target C ($C_CHAIN) ==="
TOKEN_C=$(deploy_one "$C_RPC" C-token TOKEN)
GATE_C=$(deploy_one "$C_RPC" C-gate GATE)
echo "  token=$TOKEN_C gate=$GATE_C"

# debridgeId = keccak256(abi.encodePacked(uint256 SRC_CHAIN, address TOKEN_SRC))
PREFIX=$(printf '%064x' $SRC_CHAIN)
DEBRIDGE_ID=$(cast keccak "0x${PREFIX}${TOKEN_SRC#0x}")
echo "  debridgeId=$DEBRIDGE_ID"

echo "=== source setup: mint + approve (enough for two sends) ==="
TOTAL=200000000000000000000  # 200e18
cast send "$TOKEN_SRC" "mint(address,uint256)" $ACC0 $TOTAL --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null
cast send "$TOKEN_SRC" "approve(address,uint256)" "$GATE_SRC" $TOTAL --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null

echo "=== target setup: fund gate liquidity + register asset on B and C ==="
cast send "$TOKEN_B" "mint(address,uint256)" "$GATE_B" $AMOUNT --rpc-url $B_RPC --private-key $KEY0 >/dev/null
cast send "$GATE_B" "setLocalToken(bytes32,address)" "$DEBRIDGE_ID" "$TOKEN_B" --rpc-url $B_RPC --private-key $KEY0 >/dev/null
cast send "$TOKEN_C" "mint(address,uint256)" "$GATE_C" $AMOUNT --rpc-url $C_RPC --private-key $KEY0 >/dev/null
cast send "$GATE_C" "setLocalToken(bytes32,address)" "$DEBRIDGE_ID" "$TOKEN_C" --rpc-url $C_RPC --private-key $KEY0 >/dev/null

echo "=== writing configs ==="
rm -f "$LOGS/validator-state.json"
cat > "$LOGS/validator.toml" <<EOF
[source]
chain_id = $SRC_CHAIN
rpc = "$SRC_RPC"
gate = "$GATE_SRC"
start_block = 0
block_confirmation = 0
allow_zero_confirmation = true   # anvil is instant-final; a real chain MUST set block_confirmation
poll_interval_ms = 500
max_block_range = 1000
state_file = "$LOGS/validator-state.json"

[signer]
private_key = "$VALIDATOR_KEY"

[store]
dir = "$STORE"
EOF

# ONE keeper, TWO destinations.
cat > "$LOGS/keeper.toml" <<EOF
[[targets]]
chain_id = $B_CHAIN
rpc = "$B_RPC"
gate = "$GATE_B"
poll_interval_ms = 500

[[targets]]
chain_id = $C_CHAIN
rpc = "$C_RPC"
gate = "$GATE_C"
poll_interval_ms = 500

[keeper]
private_key = "$KEEPER_KEY"

[store]
dir = "$STORE"
EOF

echo "=== starting validator + multi-target keeper ==="
"$ROOT/target/debug/validator" "$LOGS/validator.toml" >"$LOGS/validator.log" 2>&1 &
VALIDATOR_PID=$!
"$ROOT/target/debug/keeper" "$LOGS/keeper.toml" >"$LOGS/keeper.log" 2>&1 &
KEEPER_PID=$!
sleep 1

echo "=== send() 100 TST: A($SRC_CHAIN) -> B($B_CHAIN) ==="
cast send "$GATE_SRC" "send(address,uint256,uint256,bytes,bytes)" \
  "$TOKEN_SRC" $AMOUNT $B_CHAIN "$RECEIVER_B" "0x" \
  --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null

echo "=== send() 100 TST: A($SRC_CHAIN) -> C($C_CHAIN) ==="
cast send "$GATE_SRC" "send(address,uint256,uint256,bytes,bytes)" \
  "$TOKEN_SRC" $AMOUNT $C_CHAIN "$RECEIVER_C" "0x" \
  --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null

wait_paid() {  # $1 rpc, $2 token, $3 receiver -> echoes balance, returns 0 if paid
  local rpc=$1 token=$2 rcv=$3 bal
  for i in $(seq 1 60); do
    bal=$(cast call "$token" "balanceOf(address)(uint256)" "$rcv" --rpc-url $rpc | awk '{print $1}')
    if [[ "$bal" != "0" ]]; then echo "$bal"; return 0; fi
    sleep 0.5
  done
  echo "$bal"; return 1
}

echo "=== waiting for both receivers to be paid ==="
BAL_B=$(wait_paid "$B_RPC" "$TOKEN_B" "$RECEIVER_B") && OK_B=1 || OK_B=0
BAL_C=$(wait_paid "$C_RPC" "$TOKEN_C" "$RECEIVER_C") && OK_C=1 || OK_C=0

echo
echo "================= RESULT ================="
echo "  B receiver balance: $BAL_B (expected $AMOUNT)"
echo "  C receiver balance: $BAL_C (expected $AMOUNT)"
if [[ "$OK_B" == "1" && "$BAL_B" == "$AMOUNT" && "$OK_C" == "1" && "$BAL_C" == "$AMOUNT" ]]; then
  echo "✅ PASS: one source bridged to TWO chains via a single multi-target keeper"
else
  echo "❌ FAIL"
  echo "--- validator.log ---"; tail -20 "$LOGS/validator.log" || true
  echo "--- keeper.log ---"; tail -30 "$LOGS/keeper.log" || true
  exit 1
fi
echo "=========================================="
