#!/usr/bin/env bash
# Deploy + wire the gates for the docker-compose stack.
#
# Run on the HOST against the compose anvils (published on localhost:8545/8546)
# AFTER `docker compose up -d anvil-src anvil-dst`. Because anvil account #0
# deploys TestToken (nonce 0) then Gate (nonce 1) on a fresh chain, the addresses
# are deterministic and already baked into docker/configs/*.toml:
#   token = 0x5FbDB2315678afecb367f032d93F642f64180aa3
#   gate  = 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
set -euo pipefail
export PATH="$HOME/.foundry/bin:$PATH"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACTS="$ROOT/contracts"

KEY0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
ACC0=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
V1=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
V2=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
V3=0x90F79bf6EB2c4f870365E785982E1f101E93b906

SRC_RPC=http://127.0.0.1:8545
DST_RPC=http://127.0.0.1:8546
SRC_CHAIN=1337
DST_CHAIN=1338
AMOUNT=100000000000000000000

EXPECT_TOKEN=0x5FbDB2315678afecb367f032d93F642f64180aa3
EXPECT_GATE=0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512

deployed_to() { grep deployedTo | grep -oE '0x[0-9a-fA-F]{40}' | head -1; }

cd "$CONTRACTS"
forge build >/dev/null

for spec in "src:$SRC_RPC" "dst:$DST_RPC"; do
  label=${spec%%:*}; rpc=${spec#*:}
  echo "=== deploying on $label ($rpc) ==="
  tok=$(forge create src/TestToken.sol:TestToken --rpc-url "$rpc" --private-key $KEY0 \
        --broadcast --json --constructor-args Test TST 2>/dev/null | deployed_to)
  gate=$(forge create src/Gate.sol:Gate --rpc-url "$rpc" --private-key $KEY0 \
        --broadcast --json --constructor-args "[$V1,$V2,$V3]" 2 2>/dev/null | deployed_to)
  echo "  token=$tok gate=$gate"
  [[ "$tok" == "$EXPECT_TOKEN" && "$gate" == "$EXPECT_GATE" ]] \
    || { echo "!! addresses differ from the baked configs — was the chain fresh?"; exit 1; }
done

DEBRIDGE_ID=$(cast keccak "0x$(printf '%064x' $SRC_CHAIN)${EXPECT_TOKEN#0x}")
echo "=== wiring ==="
# source: give the sender funds + approve the gate
cast send "$EXPECT_TOKEN" "mint(address,uint256)" $ACC0 $AMOUNT --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null
cast send "$EXPECT_TOKEN" "approve(address,uint256)" "$EXPECT_GATE" $AMOUNT --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null
# target: fund gate liquidity + register the asset
cast send "$EXPECT_TOKEN" "mint(address,uint256)" "$EXPECT_GATE" $AMOUNT --rpc-url $DST_RPC --private-key $KEY0 >/dev/null
cast send "$EXPECT_GATE" "setLocalToken(bytes32,address)" "$DEBRIDGE_ID" "$EXPECT_TOKEN" --rpc-url $DST_RPC --private-key $KEY0 >/dev/null
# M-3: `send` refuses a destination the owner has not listed.
cast send "$EXPECT_GATE" "setSupportedChain(uint256,bool)" $DST_CHAIN true --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null
cast send "$EXPECT_GATE" "setSupportedChain(uint256,bool)" $SRC_CHAIN true --rpc-url $DST_RPC --private-key $KEY0 >/dev/null

echo "✅ deployed + wired. debridgeId=$DEBRIDGE_ID"
echo "Now: docker compose up -d validator1 validator2 validator3 keeper"
echo "Then send a transfer (100 TST, 1337 -> 1338):"
echo "  cast send $EXPECT_GATE 'send(address,uint256,uint256,bytes,bytes)' \\"
echo "    $EXPECT_TOKEN $AMOUNT 1338 0x976EA74026E726554dB657fA54763abd0C3a0aa9 0x \\"
echo "    --rpc-url $SRC_RPC --private-key $KEY0"
