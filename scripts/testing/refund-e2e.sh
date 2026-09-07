#!/usr/bin/env bash
# Two-phase refund, end to end across two local chains.
#
# The scenario is a transfer that can never be delivered: the destination gate
# is deliberately left with NO liquidity and NO asset registration, so `claim()`
# would revert forever and the user's funds would otherwise be locked on the
# source chain permanently.
#
# It then drives the refund the way the protocol does:
#
#   1. validators attest a CANCEL (destination still shows executed == false)
#   2. `cancel()` burns the transfer on the destination — claim() is now
#      permanently impossible, which is what makes the refund safe
#   3. validators observe `cancelled == true` and attest a REFUND
#   4. `refund()` returns the locked funds to the original sender on the source
#
# and asserts the properties that matter:
#   * the sender is made whole, exactly once
#   * a claim AFTER the cancel reverts (no double-spend)
#   * a second refund reverts
#   * a refund for a submissionId this gate never sent reverts
#   * transfer signatures are NOT accepted as cancel/refund authorisations
#
# Signatures are produced with `cast wallet sign` rather than by running the
# validator, so the script tests the on-chain protocol directly and stays
# independent of relayer timing. scripts/testing/phase7.sh covers the relayer path.
#
# Run from anywhere:  bash scripts/testing/refund-e2e.sh
set -euo pipefail

export PATH="$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"
source "$(dirname "${BASH_SOURCE[0]}")/_deploy_gate.sh"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTRACTS="$ROOT/contracts"
LOGS="$ROOT/.refund-e2e-logs"
mkdir -p "$LOGS"

# --- anvil default accounts ---
ACC0=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
KEY0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
V1=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
V1_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
RECEIVER=0x90F79bf6EB2c4f870365E785982E1f101E93b906

SRC_RPC=http://127.0.0.1:8545
DST_RPC=http://127.0.0.1:8546
SRC_CHAIN=1337
DST_CHAIN=1338
AMOUNT=100000000000000000000   # 100e18

# BridgeHash domain prefixes — MUST match contracts/src/BridgeHash.sol.
CANCEL_PREFIX=2
REFUND_PREFIX=3

PASS=0
FAIL=0

cleanup() {
  echo "--- cleaning up ---"
  [[ -n "${ANVIL1_PID:-}" ]] && kill "$ANVIL1_PID" 2>/dev/null || true
  [[ -n "${ANVIL2_PID:-}" ]] && kill "$ANVIL2_PID" 2>/dev/null || true
}
trap cleanup EXIT

ok()   { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
check(){ if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (got $2, want $3)"; fi; }

# assert a call reverts
reverts() { # $1 = label, rest = command
  local label=$1; shift
  if "$@" >/dev/null 2>&1; then bad "$label (expected revert, but it succeeded)"
  else ok "$label"; fi
}

deployed_to() { grep deployedTo | grep -oE '0x[0-9a-fA-F]{40}' | head -1; }

echo "=== killing stale anvil ==="
pkill -f "anvil --chain-id" 2>/dev/null || true
sleep 1

echo "=== starting anvil chains ==="
anvil --chain-id $SRC_CHAIN --port 8545 >"$LOGS/anvil-src.log" 2>&1 &
ANVIL1_PID=$!
anvil --chain-id $DST_CHAIN --port 8546 >"$LOGS/anvil-dst.log" 2>&1 &
ANVIL2_PID=$!

for url in $SRC_RPC $DST_RPC; do
  for _ in $(seq 1 50); do
    if cast chain-id --rpc-url "$url" >/dev/null 2>&1; then break; fi
    sleep 0.2
  done
done

cd "$CONTRACTS"
forge build >/dev/null

deploy() { # $1 = rpc, $2 = label, $3 = TOKEN|GATE
  local rpc=$1 label=$2 kind=$3 out addr
  # Gate is UUPS — an implementation plus a GateProxy that runs
  # initialize(). The old single `forge create Gate --constructor-args`
  # form no longer compiles against it. See _deploy_gate.sh.
  if [[ "$kind" == "GATE" ]]; then
    deploy_gate "$rpc" "$KEY0" "[$V1]" 1
    return
  fi
  if [[ "$kind" == "TOKEN" ]]; then
    out=$(forge create src/TestToken.sol:TestToken --rpc-url "$rpc" --private-key $KEY0 \
          --broadcast --json --constructor-args Test TST 2>"$LOGS/deploy-$label-err.log")
  fi
  echo "$out" > "$LOGS/deploy-$label.log"
  addr=$(echo "$out" | deployed_to || true)
  if [[ -z "$addr" ]]; then
    echo "!! deploy $label failed" >&2; cat "$LOGS/deploy-$label"*.log >&2; exit 1
  fi
  echo "$addr"
}

echo "=== deploying ==="
TOKEN_SRC=$(deploy "$SRC_RPC" src-token TOKEN)
GATE_SRC=$(deploy "$SRC_RPC" src-gate GATE)
# A second, unrelated ERC-20 on the SOURCE chain, used only to prove refund()
# rejects an asset that doesn't hash to the transfer's debridgeId.
#
# It has to be a real third deployment: both chains are driven by the same
# deployer account, so contracts share nonces and the dst gate lands on the
# SAME address as the src token. Reusing an address from the other chain as the
# "wrong" token silently tests nothing.
OTHER_TOKEN=$(deploy "$SRC_RPC" src-other-token TOKEN)
GATE_DST=$(deploy "$DST_RPC" dst-gate GATE)
echo "  src: token=$TOKEN_SRC gate=$GATE_SRC other=$OTHER_TOKEN"
echo "  dst: gate=$GATE_DST  (deliberately UNFUNDED and UNREGISTERED)"

if [[ "${OTHER_TOKEN,,}" == "${TOKEN_SRC,,}" ]]; then
  echo "!! the wrong-token fixture collides with the real token; the test would be vacuous" >&2
  exit 1
fi

echo "=== locking funds on the source ==="
cast send "$TOKEN_SRC" "mint(address,uint256)" "$ACC0" "$AMOUNT" \
  --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null
cast send "$TOKEN_SRC" "approve(address,uint256)" "$GATE_SRC" "$AMOUNT" \
  --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null

BAL_BEFORE=$(cast call "$TOKEN_SRC" "balanceOf(address)(uint256)" "$ACC0" --rpc-url $SRC_RPC | awk '{print $1}')

RECEIVER_BYTES=$(cast abi-encode "f(address)" "$RECEIVER" | sed 's/^0x0\{24\}/0x/')
cast send "$GATE_SRC" "send(address,uint256,uint256,bytes,bytes)" \
  "$TOKEN_SRC" "$AMOUNT" "$DST_CHAIN" "$RECEIVER_BYTES" "0x" \
  --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null

DEBRIDGE_ID=$(cast keccak "$(cast abi-encode --packed "f(uint256,address)" "$SRC_CHAIN" "$TOKEN_SRC")")
NONCE=0

# The gate's own deployment generation. Read it off the gate rather than
# assuming: it is the second field of the preimage, so a local derivation that
# omits it produces an id that matches nothing (which is exactly how this test
# started failing when bridgeDomain was introduced).
GATE_DOMAIN=$(cast call "$GATE_SRC" "bridgeDomain()(bytes32)" --rpc-url $SRC_RPC)

# submissionId = keccak(prefix(1), bridgeDomain, debridgeId, chainFrom, chainTo,
#                       amount, receiver, nonce)   -- see BridgeHash.packedSubmission
SUBMISSION_ID=$(cast keccak "$(cast abi-encode --packed \
  "f(uint256,bytes32,bytes32,uint256,uint256,uint256,bytes,uint256)" \
  1 "$GATE_DOMAIN" "$DEBRIDGE_ID" "$SRC_CHAIN" "$DST_CHAIN" "$AMOUNT" "$RECEIVER_BYTES" "$NONCE")")

ONCHAIN_ID=$(cast call "$GATE_SRC" "computeSubmissionId(bytes32,uint256,uint256,uint256,uint256,bytes,bytes,bytes)(bytes32)" \
  "$DEBRIDGE_ID" "$AMOUNT" "$SRC_CHAIN" "$DST_CHAIN" "$NONCE" "$RECEIVER_BYTES" "0x" "0x" --rpc-url $SRC_RPC)
check "locally-derived submissionId matches the gate's" "$SUBMISSION_ID" "$ONCHAIN_ID"

SENT_BY=$(cast call "$GATE_SRC" "sentBy(bytes32)(address)" "$SUBMISSION_ID" --rpc-url $SRC_RPC)
check "gate recorded the sender at lock time" "${SENT_BY,,}" "${ACC0,,}"

# The two attestation digests, domain-separated from the submissionId.
CANCEL_ID=$(cast keccak "$(cast abi-encode --packed "f(uint256,bytes32)" $CANCEL_PREFIX "$SUBMISSION_ID")")
REFUND_ID=$(cast keccak "$(cast abi-encode --packed "f(uint256,bytes32)" $REFUND_PREFIX "$SUBMISSION_ID")")

# `cast wallet sign` produces the EIP-191 eth_sign signature the Gate verifies.
SIG_TRANSFER=$(cast wallet sign --private-key $V1_KEY "$SUBMISSION_ID")
SIG_CANCEL=$(cast wallet sign --private-key $V1_KEY "$CANCEL_ID")
SIG_REFUND=$(cast wallet sign --private-key $V1_KEY "$REFUND_ID")

echo
echo "=== domain separation: a transfer signature must authorise nothing else ==="
reverts "cancel() rejects a replayed transfer signature" \
  cast send "$GATE_DST" "cancel(bytes32,uint256,uint256,uint256,bytes,bytes,bytes,bytes[])" \
    "$DEBRIDGE_ID" "$AMOUNT" "$SRC_CHAIN" "$NONCE" "$RECEIVER_BYTES" "0x" "0x" "[$SIG_TRANSFER]" \
    --rpc-url $DST_RPC --private-key $KEY0
reverts "refund() rejects a replayed transfer signature" \
  cast send "$GATE_SRC" "refund(address,bytes32,uint256,uint256,uint256,bytes,bytes,bytes,bytes[])" \
    "$TOKEN_SRC" "$DEBRIDGE_ID" "$AMOUNT" "$DST_CHAIN" "$NONCE" "$RECEIVER_BYTES" "0x" "0x" "[$SIG_TRANSFER]" \
    --rpc-url $SRC_RPC --private-key $KEY0
reverts "refund() rejects a cancel attestation" \
  cast send "$GATE_SRC" "refund(address,bytes32,uint256,uint256,uint256,bytes,bytes,bytes,bytes[])" \
    "$TOKEN_SRC" "$DEBRIDGE_ID" "$AMOUNT" "$DST_CHAIN" "$NONCE" "$RECEIVER_BYTES" "0x" "0x" "[$SIG_CANCEL]" \
    --rpc-url $SRC_RPC --private-key $KEY0

echo
echo "=== the gate must not refund what it never sent ==="
GHOST_NONCE=99
GHOST_ID=$(cast keccak "$(cast abi-encode --packed \
  "f(uint256,bytes32,bytes32,uint256,uint256,uint256,bytes,uint256)" \
  1 "$GATE_DOMAIN" "$DEBRIDGE_ID" "$SRC_CHAIN" "$DST_CHAIN" "$AMOUNT" "$RECEIVER_BYTES" "$GHOST_NONCE")")
GHOST_REFUND_ID=$(cast keccak "$(cast abi-encode --packed "f(uint256,bytes32)" $REFUND_PREFIX "$GHOST_ID")")
GHOST_SIG=$(cast wallet sign --private-key $V1_KEY "$GHOST_REFUND_ID")
reverts "refund() of a never-sent submissionId reverts (NotSent)" \
  cast send "$GATE_SRC" "refund(address,bytes32,uint256,uint256,uint256,bytes,bytes,bytes,bytes[])" \
    "$TOKEN_SRC" "$DEBRIDGE_ID" "$AMOUNT" "$DST_CHAIN" "$GHOST_NONCE" "$RECEIVER_BYTES" "0x" "0x" "[$GHOST_SIG]" \
    --rpc-url $SRC_RPC --private-key $KEY0

echo
echo "=== phase 1: burn the transfer on the destination ==="
cast send "$GATE_DST" "cancel(bytes32,uint256,uint256,uint256,bytes,bytes,bytes,bytes[])" \
  "$DEBRIDGE_ID" "$AMOUNT" "$SRC_CHAIN" "$NONCE" "$RECEIVER_BYTES" "0x" "0x" "[$SIG_CANCEL]" \
  --rpc-url $DST_RPC --private-key $KEY0 >/dev/null

EXECUTED=$(cast call "$GATE_DST" "executed(bytes32)(bool)" "$SUBMISSION_ID" --rpc-url $DST_RPC)
CANCELLED=$(cast call "$GATE_DST" "cancelled(bytes32)(bool)" "$SUBMISSION_ID" --rpc-url $DST_RPC)
check "destination marks it executed" "$EXECUTED" "true"
check "destination marks it cancelled" "$CANCELLED" "true"

# THE double-spend guard: the transfer signatures are still perfectly valid, but
# the destination is burned, so they can never release funds there again.
reverts "claim() after cancel reverts (no double-spend)" \
  cast send "$GATE_DST" "claim(bytes32,uint256,uint256,uint256,bytes,bytes,bytes,bytes[])" \
    "$DEBRIDGE_ID" "$AMOUNT" "$SRC_CHAIN" "$NONCE" "$RECEIVER_BYTES" "0x" "0x" "[$SIG_TRANSFER]" \
    --rpc-url $DST_RPC --private-key $KEY0
reverts "cancel() replay reverts" \
  cast send "$GATE_DST" "cancel(bytes32,uint256,uint256,uint256,bytes,bytes,bytes,bytes[])" \
    "$DEBRIDGE_ID" "$AMOUNT" "$SRC_CHAIN" "$NONCE" "$RECEIVER_BYTES" "0x" "0x" "[$SIG_CANCEL]" \
    --rpc-url $DST_RPC --private-key $KEY0

echo
echo "=== phase 2: return the funds on the source ==="
reverts "refund() with the wrong token reverts (TokenMismatch)" \
  cast send "$GATE_SRC" "refund(address,bytes32,uint256,uint256,uint256,bytes,bytes,bytes,bytes[])" \
    "$OTHER_TOKEN" "$DEBRIDGE_ID" "$AMOUNT" "$DST_CHAIN" "$NONCE" "$RECEIVER_BYTES" "0x" "0x" "[$SIG_REFUND]" \
    --rpc-url $SRC_RPC --private-key $KEY0

cast send "$GATE_SRC" "refund(address,bytes32,uint256,uint256,uint256,bytes,bytes,bytes,bytes[])" \
  "$TOKEN_SRC" "$DEBRIDGE_ID" "$AMOUNT" "$DST_CHAIN" "$NONCE" "$RECEIVER_BYTES" "0x" "0x" "[$SIG_REFUND]" \
  --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null

BAL_AFTER=$(cast call "$TOKEN_SRC" "balanceOf(address)(uint256)" "$ACC0" --rpc-url $SRC_RPC | awk '{print $1}')
GATE_BAL=$(cast call "$TOKEN_SRC" "balanceOf(address)(uint256)" "$GATE_SRC" --rpc-url $SRC_RPC | awk '{print $1}')
REFUNDED=$(cast call "$GATE_SRC" "refunded(bytes32)(bool)" "$SUBMISSION_ID" --rpc-url $SRC_RPC)
SENT_BY_AFTER=$(cast call "$GATE_SRC" "sentBy(bytes32)(address)" "$SUBMISSION_ID" --rpc-url $SRC_RPC)

check "sender made whole" "$BAL_AFTER" "$BAL_BEFORE"
check "source gate no longer holds the funds" "$GATE_BAL" "0"
check "refunded flag set" "$REFUNDED" "true"
check "sentBy cleared" "${SENT_BY_AFTER,,}" "0x0000000000000000000000000000000000000000"

reverts "refund() replay reverts (AlreadyRefunded)" \
  cast send "$GATE_SRC" "refund(address,bytes32,uint256,uint256,uint256,bytes,bytes,bytes,bytes[])" \
    "$TOKEN_SRC" "$DEBRIDGE_ID" "$AMOUNT" "$DST_CHAIN" "$NONCE" "$RECEIVER_BYTES" "0x" "0x" "[$SIG_REFUND]" \
    --rpc-url $SRC_RPC --private-key $KEY0

echo
echo "======================================"
echo "  passed: $PASS   failed: $FAIL"
echo "======================================"
[[ $FAIL -eq 0 ]] || exit 1
