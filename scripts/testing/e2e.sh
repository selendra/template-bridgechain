#!/usr/bin/env bash
# Phase 5 — first end-to-end transfer across two local chains.
#
# Boots two anvil chains, deploys Gate+TestToken on both, runs the Rust
# validator + keeper, performs a send() on the source chain, and asserts the
# receiver is paid on the target chain (and that a replayed claim reverts).
#
# Run from anywhere:  bash scripts/testing/e2e.sh
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
KEEPER=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
KEEPER_KEY=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
RECEIVER=0x90F79bf6EB2c4f870365E785982E1f101E93b906

SRC_RPC=http://127.0.0.1:8545
DST_RPC=http://127.0.0.1:8546
SRC_CHAIN=1337
DST_CHAIN=1338
AMOUNT=100000000000000000000   # 100e18

cleanup() {
  echo "--- cleaning up ---"
  [[ -n "${VALIDATOR_PID:-}" ]] && kill "$VALIDATOR_PID" 2>/dev/null || true
  [[ -n "${KEEPER_PID:-}" ]] && kill "$KEEPER_PID" 2>/dev/null || true
  [[ -n "${ANVIL1_PID:-}" ]] && kill "$ANVIL1_PID" 2>/dev/null || true
  [[ -n "${ANVIL2_PID:-}" ]] && kill "$ANVIL2_PID" 2>/dev/null || true
}
trap cleanup EXIT

deployed_to() { grep deployedTo | grep -oE '0x[0-9a-fA-F]{40}' | head -1; }

echo "=== building rust binaries ==="
( cd "$ROOT" && cargo build -p validator -p keeper >/dev/null 2>&1 )

echo "=== killing stale anvil ==="
pkill -f "anvil --chain-id" 2>/dev/null || true
sleep 1

echo "=== starting anvil chains ==="
anvil --chain-id $SRC_CHAIN --port 8545 >"$LOGS/anvil-src.log" 2>&1 &
ANVIL1_PID=$!
anvil --chain-id $DST_CHAIN --port 8546 >"$LOGS/anvil-dst.log" 2>&1 &
ANVIL2_PID=$!

# wait for RPCs
for url in $SRC_RPC $DST_RPC; do
  for i in $(seq 1 50); do
    if cast chain-id --rpc-url "$url" >/dev/null 2>&1; then break; fi
    sleep 0.2
  done
done
echo "src chainId: $(cast chain-id --rpc-url $SRC_RPC)"
echo "dst chainId: $(cast chain-id --rpc-url $DST_RPC)"

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
    cat "$LOGS/deploy-$label.log" >&2
    cat "$LOGS/deploy-$label-err.log" >&2
    exit 1
  fi
  echo "$addr"
}

echo "=== deploying on source ($SRC_CHAIN) ==="
TOKEN_SRC=$(deploy_one "$SRC_RPC" src-token TOKEN)
GATE_SRC=$(deploy_one "$SRC_RPC" src-gate GATE)
echo "  token=$TOKEN_SRC gate=$GATE_SRC"

echo "=== deploying on target ($DST_CHAIN) ==="
TOKEN_DST=$(deploy_one "$DST_RPC" dst-token TOKEN)
GATE_DST=$(deploy_one "$DST_RPC" dst-gate GATE)
echo "  token=$TOKEN_DST gate=$GATE_DST"

# debridgeId = keccak256(abi.encodePacked(uint256 SRC_CHAIN, address TOKEN_SRC))
PREFIX=$(printf '%064x' $SRC_CHAIN)
DEBRIDGE_ID=$(cast keccak "0x${PREFIX}${TOKEN_SRC#0x}")
echo "  debridgeId=$DEBRIDGE_ID"

echo "=== source setup: mint + approve ==="
cast send "$TOKEN_SRC" "mint(address,uint256)" $ACC0 $AMOUNT --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null
cast send "$TOKEN_SRC" "approve(address,uint256)" "$GATE_SRC" $AMOUNT --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null

echo "=== target setup: fund gate liquidity + register asset ==="
cast send "$TOKEN_DST" "mint(address,uint256)" "$GATE_DST" $AMOUNT --rpc-url $DST_RPC --private-key $KEY0 >/dev/null
cast send "$GATE_DST" "setLocalToken(bytes32,address)" "$DEBRIDGE_ID" "$TOKEN_DST" --rpc-url $DST_RPC --private-key $KEY0 >/dev/null

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

cat > "$LOGS/keeper.toml" <<EOF
[target]
chain_id = $DST_CHAIN
rpc = "$DST_RPC"
gate = "$GATE_DST"
poll_interval_ms = 500

[keeper]
private_key = "$KEEPER_KEY"

[store]
dir = "$STORE"
EOF

# The validator starts FIRST and alone. The keeper is held back until after the
# junk-signature injection below, so the reproduction is deterministic rather
# than a race against the keeper's 500ms poll.
echo "=== starting validator ==="
"$ROOT/target/debug/validator" "$LOGS/validator.toml" >"$LOGS/validator.log" 2>&1 &
VALIDATOR_PID=$!
sleep 1

echo "=== send() 100 TST: $SRC_CHAIN -> $DST_CHAIN ==="
cast send "$GATE_SRC" "send(address,uint256,uint256,bytes,bytes)" \
  "$TOKEN_SRC" $AMOUNT $DST_CHAIN "$RECEIVER" "0x" \
  --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null
echo "  sent. gate(src) now holds: $(cast call $TOKEN_SRC 'balanceOf(address)(uint256)' $GATE_SRC --rpc-url $SRC_RPC)"

# ---------------------------------------------------------------------------
# Finding H-1 regression — junk signatures must not deny the claim path.
#
# The signature store authenticates only that a signature recovers to its CLAIMED
# signer; it does not check validator membership. So anyone who can write to it
# can deposit structurally valid signatures from throwaway keys.
#
# The keeper used to count only validators toward quorum but then forward the
# record's ENTIRE signature list as calldata. `Gate._verifySignatures` rejects any
# array longer than `validatorCount`, so a couple of junk signatures made every
# submission revert TooManySignatures — forever, because the off-chain quorum
# still read as satisfied and the tick just retried. The transfer became
# permanently unclaimable.
#
# This gate has ONE validator, so two injected signatures are more than enough.
# ---------------------------------------------------------------------------
echo "=== injecting junk signatures (H-1 regression) ==="
REC=""
for i in $(seq 1 60); do
  REC=$(ls "$STORE"/*.json 2>/dev/null | head -1 || true)
  [[ -n "$REC" ]] && break
  sleep 0.5
done
[[ -n "$REC" ]] || { echo "FAIL: validator never wrote a record to $STORE"; exit 1; }

SUBMISSION_ID="0x$(basename "$REC" .json)"
echo "  record: $SUBMISSION_ID"

# Two throwaway keys sign the same submissionId. These are real EIP-191
# signatures over the raw 32-byte id — exactly the shape the store accepts —
# they simply are not from validators.
for JUNK_KEY in \
  0x1111111111111111111111111111111111111111111111111111111111111111 \
  0x2222222222222222222222222222222222222222222222222222222222222222
do
  JUNK_ADDR=$(cast wallet address --private-key "$JUNK_KEY")
  JUNK_SIG=$(cast wallet sign --private-key "$JUNK_KEY" "$SUBMISSION_ID")
  python3 - "$REC" "$JUNK_ADDR" "$JUNK_SIG" <<'PY'
import json, sys
path, signer, signature = sys.argv[1], sys.argv[2], sys.argv[3]
rec = json.load(open(path))
rec.setdefault("signatures", []).append({"signer": signer, "signature": signature})
json.dump(rec, open(path, "w"), indent=2)
PY
  echo "  injected non-validator signature from $JUNK_ADDR"
done

SIG_COUNT=$(python3 -c "import json,sys;print(len(json.load(open(sys.argv[1]))['signatures']))" "$REC")
VCOUNT=$(cast call "$GATE_DST" "validatorCount()(uint256)" --rpc-url $DST_RPC | awk '{print $1}')
echo "  store now holds $SIG_COUNT signatures against a gate with validatorCount=$VCOUNT"
if (( SIG_COUNT <= VCOUNT )); then
  echo "FAIL: premise broken — need more stored signatures than validatorCount to reproduce H-1"
  exit 1
fi

echo "=== starting keeper (must claim despite the junk) ==="
"$ROOT/target/debug/keeper" "$LOGS/keeper.toml" >"$LOGS/keeper.log" 2>&1 &
KEEPER_PID=$!

echo "=== waiting for receiver to be paid on target ==="
PAID=0
for i in $(seq 1 60); do
  BAL=$(cast call "$TOKEN_DST" "balanceOf(address)(uint256)" "$RECEIVER" --rpc-url $DST_RPC | awk '{print $1}')
  if [[ "$BAL" != "0" ]]; then PAID=1; break; fi
  sleep 0.5
done

BAL=$(cast call "$TOKEN_DST" "balanceOf(address)(uint256)" "$RECEIVER" --rpc-url $DST_RPC | awk '{print $1}')
echo "  receiver balance on target: $BAL"

echo
echo "================= RESULT ================="
if [[ "$PAID" == "1" && "$BAL" == "$AMOUNT" ]]; then
  echo "✅ Checkpoint 5 PASS: receiver received $BAL (expected $AMOUNT)"
else
  echo "❌ FAIL: receiver balance=$BAL expected=$AMOUNT"
  echo "--- validator.log ---"; tail -20 "$LOGS/validator.log" || true
  echo "--- keeper.log ---"; tail -20 "$LOGS/keeper.log" || true
  exit 1
fi

# replay guard end-to-end: the store file is named after the submissionId
SUB_FILE=$(ls "$STORE"/*.json 2>/dev/null | head -1 || true)
if [[ -n "$SUB_FILE" ]]; then
  SUB_ID="0x$(basename "$SUB_FILE" .json)"
  EXECD=$(cast call "$GATE_DST" 'executed(bytes32)(bool)' "$SUB_ID" --rpc-url $DST_RPC)
  echo "submissionId   : $SUB_ID"
  echo "executed[id]   : $EXECD  (replay guard set on target)"
  if [[ "$EXECD" == "true" ]]; then
    echo "✅ replay guard holds end-to-end"
  fi
fi
echo "=========================================="
echo "validator + keeper logs in $LOGS/"
