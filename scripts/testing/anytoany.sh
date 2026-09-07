#!/usr/bin/env bash
# Any-direction demo — prove B->A and C->A (the reverse of multichain.sh).
#
# Three chains A/B/C. To watch every source we run ONE validator PER source
# chain (each with its own state file, all writing the shared sig-store) and ONE
# multi-target keeper (targets A, B, C). Then we send B->A and C->A and assert
# both receivers are paid on A. Demonstrates the topology is symmetric: any chain
# can be a source as long as a validator watches it.
#
# Run from anywhere:  bash scripts/testing/anytoany.sh
set -euo pipefail

export PATH="$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"
source "$(dirname "${BASH_SOURCE[0]}")/_deploy_gate.sh"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTRACTS="$ROOT/contracts"
STORE="$ROOT/sig-store-data"
LOGS="$ROOT/.e2e-logs"
mkdir -p "$LOGS"
rm -rf "$STORE"; mkdir -p "$STORE"

ACC0=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
KEY0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
VALIDATOR=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
VALIDATOR_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
KEEPER_KEY=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
RCV_FROM_B=0x90F79bf6EB2c4f870365E785982E1f101E93b906
RCV_FROM_C=0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65

A_RPC=http://127.0.0.1:8545
B_RPC=http://127.0.0.1:8546
C_RPC=http://127.0.0.1:8547
A_CHAIN=1337
B_CHAIN=1338
C_CHAIN=1339
AMOUNT=100000000000000000000   # 100e18

cleanup() {
  echo "--- cleaning up ---"
  for p in VAL_A_PID VAL_B_PID VAL_C_PID KEEPER_PID ANVIL_A_PID ANVIL_B_PID ANVIL_C_PID; do
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

echo "=== starting anvil chains (A=$A_CHAIN, B=$B_CHAIN, C=$C_CHAIN) ==="
anvil --chain-id $A_CHAIN --port 8545 >"$LOGS/anvil-A.log" 2>&1 &
ANVIL_A_PID=$!
anvil --chain-id $B_CHAIN --port 8546 >"$LOGS/anvil-B.log" 2>&1 &
ANVIL_B_PID=$!
anvil --chain-id $C_CHAIN --port 8547 >"$LOGS/anvil-C.log" 2>&1 &
ANVIL_C_PID=$!

for url in $A_RPC $B_RPC $C_RPC; do
  for i in $(seq 1 50); do
    if cast chain-id --rpc-url "$url" >/dev/null 2>&1; then break; fi
    sleep 0.2
  done
done
echo "  A=$(cast chain-id --rpc-url $A_RPC) B=$(cast chain-id --rpc-url $B_RPC) C=$(cast chain-id --rpc-url $C_RPC)"

cd "$CONTRACTS"
forge build >/dev/null

deploy_one() {  # $1 rpc, $2 label, $3 TOKEN|GATE
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
    echo "!! deploy $label failed:" >&2; cat "$LOGS/deploy-$label.log" "$LOGS/deploy-$label-err.log" >&2; exit 1
  fi
  echo "$addr"
}

echo "=== deploying gates+tokens on A, B, C ==="
TOKEN_A=$(deploy_one "$A_RPC" A-token TOKEN); GATE_A=$(deploy_one "$A_RPC" A-gate GATE)
TOKEN_B=$(deploy_one "$B_RPC" B-token TOKEN); GATE_B=$(deploy_one "$B_RPC" B-gate GATE)
TOKEN_C=$(deploy_one "$C_RPC" C-token TOKEN); GATE_C=$(deploy_one "$C_RPC" C-gate GATE)
echo "  A: token=$TOKEN_A gate=$GATE_A"
echo "  B: token=$TOKEN_B gate=$GATE_B"
echo "  C: token=$TOKEN_C gate=$GATE_C"

# debridgeId is keyed by the SOURCE chain + SOURCE token.
PRE_B=$(printf '%064x' $B_CHAIN); DEBRIDGE_B=$(cast keccak "0x${PRE_B}${TOKEN_B#0x}")
PRE_C=$(printf '%064x' $C_CHAIN); DEBRIDGE_C=$(cast keccak "0x${PRE_C}${TOKEN_C#0x}")
echo "  debridgeId(B-asset)=$DEBRIDGE_B"
echo "  debridgeId(C-asset)=$DEBRIDGE_C"

echo "=== source setup on B and C (mint+approve) ==="
cast send "$TOKEN_B" "mint(address,uint256)" $ACC0 $AMOUNT --rpc-url $B_RPC --private-key $KEY0 >/dev/null
cast send "$TOKEN_B" "approve(address,uint256)" "$GATE_B" $AMOUNT --rpc-url $B_RPC --private-key $KEY0 >/dev/null
cast send "$TOKEN_C" "mint(address,uint256)" $ACC0 $AMOUNT --rpc-url $C_RPC --private-key $KEY0 >/dev/null
cast send "$TOKEN_C" "approve(address,uint256)" "$GATE_C" $AMOUNT --rpc-url $C_RPC --private-key $KEY0 >/dev/null

echo "=== target setup on A: fund liquidity + register BOTH inbound assets ==="
TOTAL=200000000000000000000
cast send "$TOKEN_A" "mint(address,uint256)" "$GATE_A" $TOTAL --rpc-url $A_RPC --private-key $KEY0 >/dev/null
cast send "$GATE_A" "setLocalToken(bytes32,address)" "$DEBRIDGE_B" "$TOKEN_A" --rpc-url $A_RPC --private-key $KEY0 >/dev/null
cast send "$GATE_A" "setLocalToken(bytes32,address)" "$DEBRIDGE_C" "$TOKEN_A" --rpc-url $A_RPC --private-key $KEY0 >/dev/null

echo "=== writing configs: one validator per source (B, C) + one keeper -> A ==="
rm -f "$LOGS"/val-*-state.json
write_validator() {  # $1 path, $2 chain, $3 rpc, $4 gate, $5 statefile
  cat > "$1" <<EOF
[source]
chain_id = $2
rpc = "$3"
gate = "$4"
start_block = 0
block_confirmation = 0
allow_zero_confirmation = true   # anvil is instant-final; a real chain MUST set block_confirmation
poll_interval_ms = 500
max_block_range = 1000
state_file = "$5"

[signer]
private_key = "$VALIDATOR_KEY"

[store]
dir = "$STORE"
EOF
}
write_validator "$LOGS/validator-B.toml" $B_CHAIN "$B_RPC" "$GATE_B" "$LOGS/val-B-state.json"
write_validator "$LOGS/validator-C.toml" $C_CHAIN "$C_RPC" "$GATE_C" "$LOGS/val-C-state.json"

cat > "$LOGS/keeper.toml" <<EOF
[[targets]]
chain_id = $A_CHAIN
rpc = "$A_RPC"
gate = "$GATE_A"
poll_interval_ms = 500

[keeper]
private_key = "$KEEPER_KEY"

[store]
dir = "$STORE"
EOF

echo "=== starting 2 validators (B, C) + 1 keeper (->A) ==="
"$ROOT/target/debug/validator" "$LOGS/validator-B.toml" >"$LOGS/val-B.log" 2>&1 &
VAL_B_PID=$!
"$ROOT/target/debug/validator" "$LOGS/validator-C.toml" >"$LOGS/val-C.log" 2>&1 &
VAL_C_PID=$!
"$ROOT/target/debug/keeper" "$LOGS/keeper.toml" >"$LOGS/keeper.log" 2>&1 &
KEEPER_PID=$!
sleep 1

echo "=== send() 100 TST: B($B_CHAIN) -> A($A_CHAIN) ==="
cast send "$GATE_B" "send(address,uint256,uint256,bytes,bytes)" \
  "$TOKEN_B" $AMOUNT $A_CHAIN "$RCV_FROM_B" "0x" --rpc-url $B_RPC --private-key $KEY0 >/dev/null

echo "=== send() 100 TST: C($C_CHAIN) -> A($A_CHAIN) ==="
cast send "$GATE_C" "send(address,uint256,uint256,bytes,bytes)" \
  "$TOKEN_C" $AMOUNT $A_CHAIN "$RCV_FROM_C" "0x" --rpc-url $C_RPC --private-key $KEY0 >/dev/null

wait_paid() {  # $1 rpc, $2 token, $3 receiver
  local rpc=$1 token=$2 rcv=$3 bal
  for i in $(seq 1 60); do
    bal=$(cast call "$token" "balanceOf(address)(uint256)" "$rcv" --rpc-url $rpc | awk '{print $1}')
    if [[ "$bal" != "0" ]]; then echo "$bal"; return 0; fi
    sleep 0.5
  done
  echo "$bal"; return 1
}

echo "=== waiting for both receivers to be paid on A ==="
BAL_FROM_B=$(wait_paid "$A_RPC" "$TOKEN_A" "$RCV_FROM_B") && OK_B=1 || OK_B=0
BAL_FROM_C=$(wait_paid "$A_RPC" "$TOKEN_A" "$RCV_FROM_C") && OK_C=1 || OK_C=0

echo
echo "================= RESULT ================="
echo "  A receiver (from B): $BAL_FROM_B (expected $AMOUNT)"
echo "  A receiver (from C): $BAL_FROM_C (expected $AMOUNT)"
if [[ "$OK_B" == "1" && "$BAL_FROM_B" == "$AMOUNT" && "$OK_C" == "1" && "$BAL_FROM_C" == "$AMOUNT" ]]; then
  echo "✅ PASS: B->A and C->A both delivered (per-source validators + multi-target keeper)"
else
  echo "❌ FAIL"
  echo "--- val-B.log ---"; tail -20 "$LOGS/val-B.log" || true
  echo "--- val-C.log ---"; tail -20 "$LOGS/val-C.log" || true
  echo "--- keeper.log ---"; tail -30 "$LOGS/keeper.log" || true
  exit 1
fi
echo "=========================================="
