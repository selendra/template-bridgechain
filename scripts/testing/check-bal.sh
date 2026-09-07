#!/usr/bin/env bash
set -euo pipefail
export PATH="$HOME/.foundry/bin:$PATH"
source "$(dirname "${BASH_SOURCE[0]}")/_addresses.sh"
ACC0=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
for pair in "A http://127.0.0.1:8545" "B http://127.0.0.1:8546"; do
  set -- $pair; LABEL=$1; RPC=$2
  echo "--- chain $LABEL ($RPC) ---"
  echo "  chain-id     : $(cast chain-id --rpc-url "$RPC" 2>/dev/null || echo DOWN)"
  echo "  token symbol : $(cast call "$TOKEN" 'symbol()(string)' --rpc-url "$RPC" 2>/dev/null || echo none)"
  echo "  acc0 TST     : $(cast call "$TOKEN" 'balanceOf(address)(uint256)' "$ACC0" --rpc-url "$RPC" 2>/dev/null || echo err)"
  echo "  gate TST     : $(cast call "$TOKEN" 'balanceOf(address)(uint256)' "$GATE" --rpc-url "$RPC" 2>/dev/null || echo err)"
  echo "  acc0 ETH     : $(cast balance "$ACC0" --rpc-url "$RPC" 2>/dev/null || echo err)"
done
