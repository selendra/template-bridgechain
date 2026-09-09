#!/usr/bin/env bash
# Phase F — cross-chain swap end-to-end over TWO local anvil chains.
#
# Proves the SwapRouter composition on real chains, with no changes to Gate or
# SwapPool:
#   @chain A  routerA.swapAndBridge(WETH -> ... -> chain B, want TT):
#               WETH --poolA--> stable, then Gate.send(stable) with the swap
#               intent (TT, receiver, minOut) in autoParams.data.
#   off-chain the validator would sign the Sent; here we sign the submissionId
#   directly with the validator key (single validator, threshold 1) — the same
#   digest the Gate verifies.
#   @chain B  routerB.claimAndFinalize(...):
#               Gate.claim releases the stable to routerB, then
#               stable --poolB--> TT is delivered to the final receiver.
#
# The destination router recomputes the submissionId from the passed fields, so
# any mismatch in our reconstructed autoParams makes claim() revert — the test
# self-validates the encoding.
#
# Run from anywhere:  bash scripts/testing/xswap.sh
set -euo pipefail

export PATH="$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTRACTS="$ROOT/contracts"
LOGS="$ROOT/.xswap-logs"
mkdir -p "$LOGS"

# --- anvil default accounts ---
ACC0=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
KEY0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
VALIDATOR=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
VALIDATOR_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
USER=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
USER_KEY=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
FINAL_RECEIVER=0x90F79bf6EB2c4f870365E785982E1f101E93b906

SRC_RPC=http://127.0.0.1:8545
DST_RPC=http://127.0.0.1:8546
CHAIN_A=1337
CHAIN_B=1338

AMOUNT_IN=1000000000000000000       # 1 WETH (18 dec)
WETH_PRICE=3180000000000000000000   # 3180e18
TT_PRICE=2000000000000000000        # 2e18

FAIL=0
check() { if [[ "$2" == "$3" ]]; then echo "  ✅ $1: $2"; else echo "  ❌ $1: got $2 want $3"; FAIL=1; fi; }

cleanup() {
  echo "--- cleaning up ---"
  [[ -n "${ANVIL1_PID:-}" ]] && kill "$ANVIL1_PID" 2>/dev/null || true
  [[ -n "${ANVIL2_PID:-}" ]] && kill "$ANVIL2_PID" 2>/dev/null || true
}
trap cleanup EXIT

# strip any "[..]"/scientific suffix cast appends to numeric output
num() { awk '{print $1}'; }

echo "=== building contracts ==="
cd "$CONTRACTS"
forge build >/dev/null

echo "=== killing stale anvil ==="
pkill -f "anvil --chain-id" 2>/dev/null || true
sleep 1

echo "=== starting anvil chains ($CHAIN_A, $CHAIN_B) ==="
anvil --chain-id $CHAIN_A --port 8545 >"$LOGS/anvil-a.log" 2>&1 & ANVIL1_PID=$!
anvil --chain-id $CHAIN_B --port 8546 >"$LOGS/anvil-b.log" 2>&1 & ANVIL2_PID=$!
for url in $SRC_RPC $DST_RPC; do
  for i in $(seq 1 50); do cast chain-id --rpc-url "$url" >/dev/null 2>&1 && break; sleep 0.2; done
done
echo "  A=$(cast chain-id --rpc-url $SRC_RPC)  B=$(cast chain-id --rpc-url $DST_RPC)"

echo "=== deploy chain A (alt = WETH @3180) ==="
VALIDATOR=$VALIDATOR ALT_PRICE=$WETH_PRICE ALT_SYMBOL=WETH \
  forge script script/DeployXSwap.s.sol:DeployXSwap \
  --rpc-url "$SRC_RPC" --private-key $KEY0 --broadcast \
  >"$LOGS/deploy-a.log" 2>&1 || { echo "!! deploy A failed"; tail -30 "$LOGS/deploy-a.log"; exit 1; }
source "$CONTRACTS/fixtures/xswap-$CHAIN_A.env"
STABLE_A=$STABLE; WETH=$ALT; POOL_A=$POOL; GATE_A=$GATE; ROUTER_A=$ROUTER
echo "  stableA=$STABLE_A WETH=$WETH poolA=$POOL_A gateA=$GATE_A routerA=$ROUTER_A"

echo "=== deploy chain B (alt = TT @2) ==="
VALIDATOR=$VALIDATOR ALT_PRICE=$TT_PRICE ALT_SYMBOL=TT \
  forge script script/DeployXSwap.s.sol:DeployXSwap \
  --rpc-url "$DST_RPC" --private-key $KEY0 --broadcast \
  >"$LOGS/deploy-b.log" 2>&1 || { echo "!! deploy B failed"; tail -30 "$LOGS/deploy-b.log"; exit 1; }
source "$CONTRACTS/fixtures/xswap-$CHAIN_B.env"
STABLE_B=$STABLE; TT=$ALT; POOL_B=$POOL; GATE_B=$GATE; ROUTER_B=$ROUTER
echo "  stableB=$STABLE_B TT=$TT poolB=$POOL_B gateB=$GATE_B routerB=$ROUTER_B"

echo "=== wire corridor A<->B ==="
# M-3: each gate must list the peer before `send` (and so swapAndBridge) works.
cast send "$GATE_A" "setSupportedChain(uint256,bool)" $CHAIN_B true --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null
cast send "$GATE_B" "setSupportedChain(uint256,bool)" $CHAIN_A true --rpc-url $DST_RPC --private-key $KEY0 >/dev/null
cast send "$ROUTER_A" "setRemoteRouter(uint256,bytes)" $CHAIN_B "$ROUTER_B" --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null
cast send "$ROUTER_B" "setRemoteRouter(uint256,bytes)" $CHAIN_A "$ROUTER_A" --rpc-url $DST_RPC --private-key $KEY0 >/dev/null

# The stable bridges A->B as (native chain A, stableA) -> local stableB.
PREFIX=$(printf '%064x' $CHAIN_A)
DEBRIDGE_ID=$(cast keccak "0x${PREFIX}${STABLE_A#0x}")
echo "  debridgeId(stable A->B)=$DEBRIDGE_ID"
cast send "$GATE_B" "setLocalToken(bytes32,address)" "$DEBRIDGE_ID" "$STABLE_B" --rpc-url $DST_RPC --private-key $KEY0 >/dev/null
# H-1: wiring done — seal both gates before funding, as production does.
cast send "$GATE_A" "seal()" --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null
cast send "$GATE_B" "seal()" --rpc-url $DST_RPC --private-key $KEY0 >/dev/null
# pre-fund gate B with target-side stable liquidity for the claim
cast send "$STABLE_B" "mint(address,uint256)" "$GATE_B" 10000000000000 --rpc-url $DST_RPC --private-key $KEY0 >/dev/null

echo
echo "=== chain A: swapAndBridge 1 WETH -> (bridge) -> TT@B for $FINAL_RECEIVER ==="
cast send "$WETH" "mint(address,uint256)" "$USER" $AMOUNT_IN --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null
cast send "$WETH" "approve(address,uint256)" "$ROUTER_A" $AMOUNT_IN --rpc-url $SRC_RPC --private-key $USER_KEY >/dev/null

# the stable this produces (WETH->stable, pegged): 3180.000000 (6 dec)
STABLE_OUT=$(cast call "$POOL_A" "quote(address,address,uint256)(uint256)" "$WETH" "$STABLE_A" $AMOUNT_IN --rpc-url $SRC_RPC | num)
echo "  stable bridged = $STABLE_OUT"
check "bridged stable (3180e6)" "$STABLE_OUT" "3180000000"

cast send "$ROUTER_A" "swapAndBridge(address,uint256,uint256,uint256,address,address,uint256)" \
  "$WETH" $AMOUNT_IN 0 $CHAIN_B "$TT" "$FINAL_RECEIVER" 0 \
  --rpc-url $SRC_RPC --private-key $USER_KEY >/dev/null
echo "  gateA now locks stable: $(cast call $STABLE_A 'balanceOf(address)(uint256)' $GATE_A --rpc-url $SRC_RPC | num)"

echo
echo "=== reconstruct the transfer + sign the submissionId ==="
NONCE=0
# intent = abi.encode(finalToken, finalReceiver, finalMinOut)
INTENT=$(cast abi-encode "f(address,address,uint256)" "$TT" "$FINAL_RECEIVER" 0)
# autoParams = abi.encode(Gate.AutoParamsTo{0,0, fallback=finalReceiver(20b), data=intent})
AUTOPARAMS=$(cast abi-encode "f((uint256,uint256,bytes,bytes))" "(0,0,$FINAL_RECEIVER,$INTENT)")
# gate injects nativeSender = abi.encodePacked(msg.sender) = routerA (20 bytes)
NATIVE_SENDER=$ROUTER_A
RECEIVER=$ROUTER_B  # the peer router the stable was bridged to

SUB_ID=$(cast call "$GATE_A" \
  "computeSubmissionId(bytes32,uint256,uint256,uint256,uint256,bytes,bytes,bytes)(bytes32)" \
  "$DEBRIDGE_ID" $STABLE_OUT $CHAIN_A $CHAIN_B $NONCE "$RECEIVER" "$AUTOPARAMS" "$NATIVE_SENDER" \
  --rpc-url $SRC_RPC)
echo "  submissionId = $SUB_ID"

# sign the raw 32-byte id (cast applies the EIP-191 prefix the Gate expects)
SIG=$(cast wallet sign --private-key $VALIDATOR_KEY "$SUB_ID")
echo "  validator sig = ${SIG:0:20}..."

echo
echo "=== chain B: claimAndFinalize (Gate.claim + stable->TT swap) ==="
EXPECTED_TT=$(cast call "$POOL_B" "quote(address,address,uint256)(uint256)" "$STABLE_B" "$TT" $STABLE_OUT --rpc-url $DST_RPC | num)
echo "  expected TT out = $EXPECTED_TT"
check "dest quote (1590e18)" "$EXPECTED_TT" "1590000000000000000000"

cast send "$ROUTER_B" \
  "claimAndFinalize(bytes32,uint256,uint256,uint256,bytes,bytes,bytes,bytes[])" \
  "$DEBRIDGE_ID" $STABLE_OUT $CHAIN_A $NONCE "$RECEIVER" "$AUTOPARAMS" "$NATIVE_SENDER" "[$SIG]" \
  --rpc-url $DST_RPC --private-key $KEY0 >"$LOGS/claim.log" 2>&1 \
  || { echo "  ❌ claimAndFinalize reverted"; tail -20 "$LOGS/claim.log"; exit 1; }

echo
echo "=== assertions ==="
GOT_TT=$(cast call "$TT" "balanceOf(address)(uint256)" "$FINAL_RECEIVER" --rpc-url $DST_RPC | num)
check "final receiver TT balance" "$GOT_TT" "$EXPECTED_TT"
EXECD=$(cast call "$GATE_B" "executed(bytes32)(bool)" "$SUB_ID" --rpc-url $DST_RPC)
check "gateB.executed[id]" "$EXECD" "true"
FINALIZED=$(cast call "$ROUTER_B" "finalized(bytes32)(bool)" "$SUB_ID" --rpc-url $DST_RPC)
check "routerB.finalized[id]" "$FINALIZED" "true"
ROUTER_RESIDUAL=$(cast call "$STABLE_B" "balanceOf(address)(uint256)" "$ROUTER_B" --rpc-url $DST_RPC | num)
check "routerB residual stable" "$ROUTER_RESIDUAL" "0"

echo
echo "================= RESULT ================="
if [[ "$FAIL" == "0" ]]; then
  echo "✅ Phase F PASS: WETH@$CHAIN_A -> TT@$CHAIN_B delivered $GOT_TT TT cross-chain"
else
  echo "❌ FAIL — see $LOGS/"
  exit 1
fi
echo "=========================================="
