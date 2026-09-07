#!/usr/bin/env bash
# Fire one B->A transfer and confirm it EXECUTES on chain A (the direction that
# previously stalled). Sends from account0 on B, receiver gets TOKEN on A.
set -euo pipefail
export PATH="$HOME/.foundry/bin:$PATH"

B_RPC=http://127.0.0.1:8546   # source = chain B (1338)
A_RPC=http://127.0.0.1:8545   # dest   = chain A (1337)
KEY0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
source "$(dirname "${BASH_SOURCE[0]}")/_addresses.sh"
RCV=0x976EA74026E726554dB657fA54763abd0C3a0aa9
AMT=100000000000000000000

before=$(cast call "$TOKEN" "balanceOf(address)(uint256)" "$RCV" --rpc-url "$A_RPC" | awk '{print $1}')
echo "receiver TOKEN on A before: $before"

cast send "$TOKEN" "approve(address,uint256)" "$GATE" "$AMT" --rpc-url "$B_RPC" --private-key "$KEY0" >/dev/null
cast send "$GATE" "send(address,uint256,uint256,bytes,bytes)" "$TOKEN" "$AMT" 1337 "$RCV" "0x" --rpc-url "$B_RPC" --private-key "$KEY0" >/dev/null
echo "sent B->A (100 TST), waiting for the keeper to claim on A..."

for _ in $(seq 1 40); do
  now=$(cast call "$TOKEN" "balanceOf(address)(uint256)" "$RCV" --rpc-url "$A_RPC" | awk '{print $1}')
  if [ "$now" != "$before" ]; then
    echo "receiver TOKEN on A after : $now"
    Q='{"query":"{ submissions(filter:{chainIdFrom:1338, chainIdTo:1337}) { status executed meetsThreshold } }"}'
    echo "graphql: $(curl -s http://127.0.0.1:5173/graphql -H 'content-type: application/json' --data "$Q")"
    echo "RESULT: B->A EXECUTED, receiver credited on A ✅"
    exit 0
  fi
  sleep 0.5
done
echo "RESULT: receiver balance on A did not increase in time" >&2
exit 1
