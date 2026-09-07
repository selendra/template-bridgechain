#!/usr/bin/env bash
# Fault-isolation demo (security fix M1) — one multi-source validator watches B
# and C; we KILL chain C's RPC mid-flight, then prove B->A still works and the
# validator process survives. Pre-fix, C's RPC error propagated through the
# JoinSet and exited the whole validator, silently stopping B too.
#
# Run from anywhere:  bash scripts/testing/resilience.sh
set -euo pipefail

export PATH="$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"
source "$(dirname "${BASH_SOURCE[0]}")/_deploy_gate.sh"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTRACTS="$ROOT/contracts"
STORE="$ROOT/sig-store-data"
LOGS="$ROOT/.e2e-logs"
mkdir -p "$LOGS"; rm -rf "$STORE"; mkdir -p "$STORE"

ACC0=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
KEY0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
VALIDATOR=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
VALIDATOR_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
KEEPER_KEY=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
RCV_FROM_B=0x90F79bf6EB2c4f870365E785982E1f101E93b906

A_RPC=http://127.0.0.1:8545
B_RPC=http://127.0.0.1:8546
C_RPC=http://127.0.0.1:8547
A_CHAIN=1337; B_CHAIN=1338; C_CHAIN=1339
API=127.0.0.1:9097
AMOUNT=100000000000000000000

cleanup() {
  echo "--- cleaning up ---"
  for p in VAL_PID KEEPER_PID ANVIL_A_PID ANVIL_B_PID ANVIL_C_PID; do
    [[ -n "${!p:-}" ]] && kill "${!p}" 2>/dev/null || true
  done
}
trap cleanup EXIT

deployed_to() { grep deployedTo | grep -oE '0x[0-9a-fA-F]{40}' | head -1; }
fail() { echo "❌ FAIL: $1"; echo "--- val log ---"; tail -30 "$LOGS/val-res.log" || true; exit 1; }

echo "=== build + boot 3 anvils ==="
( cd "$ROOT" && cargo build -p validator -p keeper >/dev/null 2>&1 )
pkill -f "anvil --chain-id" 2>/dev/null || true; sleep 1
anvil --chain-id $A_CHAIN --port 8545 >"$LOGS/anvil-A.log" 2>&1 & ANVIL_A_PID=$!
anvil --chain-id $B_CHAIN --port 8546 >"$LOGS/anvil-B.log" 2>&1 & ANVIL_B_PID=$!
anvil --chain-id $C_CHAIN --port 8547 >"$LOGS/anvil-C.log" 2>&1 & ANVIL_C_PID=$!
for url in $A_RPC $B_RPC $C_RPC; do
  for i in $(seq 1 50); do cast chain-id --rpc-url "$url" >/dev/null 2>&1 && break; sleep 0.2; done
done

cd "$CONTRACTS"; forge build >/dev/null
deploy_one() {
  local rpc=$1 label=$2 kind=$3 out addr
  # Gate is UUPS: implementation + GateProxy running initialize(). See _deploy_gate.sh.
  if [[ "$kind" == "GATE" ]]; then
    deploy_gate "$rpc" "$KEY0" "[$VALIDATOR]" 1
    return
  fi
  out=$(forge create src/TestToken.sol:TestToken --rpc-url "$rpc" --private-key $KEY0 --broadcast --json --constructor-args Test TST 2>/dev/null)
  addr=$(echo "$out" | deployed_to || true); [[ -n "$addr" ]] || { echo "deploy $label failed" >&2; exit 1; }; echo "$addr"
}

echo "=== deploy A, B, C ==="
TOKEN_A=$(deploy_one "$A_RPC" A-token TOKEN); GATE_A=$(deploy_one "$A_RPC" A-gate GATE)
TOKEN_B=$(deploy_one "$B_RPC" B-token TOKEN); GATE_B=$(deploy_one "$B_RPC" B-gate GATE)
TOKEN_C=$(deploy_one "$C_RPC" C-token TOKEN); GATE_C=$(deploy_one "$C_RPC" C-gate GATE)

PRE_B=$(printf '%064x' $B_CHAIN); DEBRIDGE_B=$(cast keccak "0x${PRE_B}${TOKEN_B#0x}")
cast send "$TOKEN_B" "mint(address,uint256)" $ACC0 $AMOUNT --rpc-url $B_RPC --private-key $KEY0 >/dev/null
cast send "$TOKEN_B" "approve(address,uint256)" "$GATE_B" $AMOUNT --rpc-url $B_RPC --private-key $KEY0 >/dev/null
cast send "$TOKEN_A" "mint(address,uint256)" "$GATE_A" $AMOUNT --rpc-url $A_RPC --private-key $KEY0 >/dev/null
cast send "$GATE_A" "setLocalToken(bytes32,address)" "$DEBRIDGE_B" "$TOKEN_A" --rpc-url $A_RPC --private-key $KEY0 >/dev/null

echo "=== ONE validator watching B+C; keeper -> A ==="
rm -f "$LOGS"/res-*-state.json
cat > "$LOGS/validator.toml" <<EOF
[[sources]]
chain_id = $B_CHAIN
rpc = "$B_RPC"
gate = "$GATE_B"
block_confirmation = 0
allow_zero_confirmation = true   # anvil is instant-final; a real chain MUST set block_confirmation
poll_interval_ms = 500
state_file = "$LOGS/res-B-state.json"

[[sources]]
chain_id = $C_CHAIN
rpc = "$C_RPC"
gate = "$GATE_C"
block_confirmation = 0
allow_zero_confirmation = true   # anvil is instant-final; a real chain MUST set block_confirmation
poll_interval_ms = 500
state_file = "$LOGS/res-C-state.json"

[signer]
private_key = "$VALIDATOR_KEY"

[store]
dir = "$STORE"

[api]
bind = "$API"
# allow_unauthenticated: this harness drives pause/resume/rescan itself on
# 127.0.0.1 with no token to distribute. The validator now leaves those routes
# UNMOUNTED unless a token is set or this says otherwise.
allow_unauthenticated = true
EOF
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

"$ROOT/target/debug/validator" "$LOGS/validator.toml" >"$LOGS/val-res.log" 2>&1 & VAL_PID=$!
"$ROOT/target/debug/keeper" "$LOGS/keeper.toml" >"$LOGS/keeper.log" 2>&1 & KEEPER_PID=$!
for i in $(seq 1 40); do curl -s "http://$API/status" >/dev/null 2>&1 && break; sleep 0.25; done

echo
echo "########## FAULT INJECTION: kill chain C's RPC ##########"
kill "$ANVIL_C_PID" 2>/dev/null || true; ANVIL_C_PID=""
sleep 2   # let the validator's C-loop hit the dead RPC a few times

echo "=== checking validator is still alive after C died ==="
kill -0 "$VAL_PID" 2>/dev/null || fail "validator process DIED when chain C went down (M1 not fixed)"
echo "✅ validator still running"
grep -q "get_block_number failed; retrying" "$LOGS/val-res.log" \
  && echo "✅ C-loop is retrying (not propagating)" \
  || echo "  (note: retry log line not seen yet — C loop may poll slower)"

echo "=== B->A while C is DOWN ==="
cast send "$GATE_B" "send(address,uint256,uint256,bytes,bytes)" \
  "$TOKEN_B" $AMOUNT $A_CHAIN "$RCV_FROM_B" "0x" --rpc-url $B_RPC --private-key $KEY0 >/dev/null

PAID=0
for i in $(seq 1 60); do
  BAL=$(cast call "$TOKEN_A" "balanceOf(address)(uint256)" "$RCV_FROM_B" --rpc-url $A_RPC | awk '{print $1}')
  [[ "$BAL" != "0" ]] && { PAID=1; break; }; sleep 0.5
done

echo "=== validator API still responsive for the healthy chain B ==="
curl -s "http://$API/status/$B_CHAIN" >/dev/null 2>&1 && echo "✅ /status/$B_CHAIN responds" || fail "API unresponsive"

echo
echo "================= RESULT ================="
echo "  B receiver on A: $BAL (expected $AMOUNT)"
if [[ "$PAID" == "1" && "$BAL" == "$AMOUNT" ]]; then
  echo "✅ PASS: chain C's outage did NOT stop B->A (fault isolated, M1 fixed)"
else
  fail "B->A did not complete while C was down"
fi
echo "=========================================="
