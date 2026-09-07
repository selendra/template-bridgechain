#!/usr/bin/env bash
# Fire one A->B transfer through the live stack and watch graphql-api report it
# go READY -> EXECUTED (proves validators + keeper are actually running).
set -euo pipefail
export PATH="$HOME/.foundry/bin:$PATH"

SRC_RPC=http://127.0.0.1:8545
KEY0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
source "$(dirname "${BASH_SOURCE[0]}")/_addresses.sh"
RCV=0x976EA74026E726554dB657fA54763abd0C3a0aa9
AMT=100000000000000000000

cast send "$TOKEN" "approve(address,uint256)" "$GATE" "$AMT" --rpc-url "$SRC_RPC" --private-key "$KEY0" >/dev/null
cast send "$GATE" "send(address,uint256,uint256,bytes,bytes)" "$TOKEN" "$AMT" 1338 "$RCV" "0x" --rpc-url "$SRC_RPC" --private-key "$KEY0" >/dev/null
echo "sent A->B (100 TST), polling graphql via the dev proxy..."

Q='{"query":"{ stats { total ready } submissions { status meetsThreshold executed } }"}'
for _ in $(seq 1 40); do
  OUT=$(curl -s http://127.0.0.1:5173/graphql -H 'content-type: application/json' --data "$Q")
  if echo "$OUT" | grep -q '"status":"EXECUTED"'; then
    echo "$OUT"
    echo "RESULT: EXECUTED ✅"
    exit 0
  fi
  sleep 0.5
done
echo "last response: $OUT"
echo "RESULT: did not reach EXECUTED in time" >&2
exit 1
