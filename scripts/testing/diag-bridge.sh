#!/usr/bin/env bash
# Diagnose where tokens actually land. Bridge to a FRESH receiver in each
# direction and print sender + receiver balances on both sides, so we can tell
# an on-chain (backend) problem from a wallet-display (frontend/MetaMask) one.
set -euo pipefail
export PATH="$HOME/.foundry/bin:$PATH"

A_RPC=http://127.0.0.1:8545   # chain 1337
B_RPC=http://127.0.0.1:8546   # chain 1338
KEY0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
ACC0=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
source "$(dirname "${BASH_SOURCE[0]}")/_addresses.sh"
AMT=100000000000000000000   # 100e18

# two brand-new receivers (no prior balance anywhere)
RCV_B=0x00000000000000000000000000000000000000A1   # gets A->B payout on B
RCV_A=0x00000000000000000000000000000000000000B2   # gets B->A payout on A

bal() { cast call "$TOKEN" "balanceOf(address)(uint256)" "$1" --rpc-url "$2" | awk '{print $1}'; }
wait_bal() { # addr rpc expected
  for _ in $(seq 1 40); do [ "$(bal "$1" "$2")" = "$3" ] && return 0; sleep 0.5; done; return 1; }

echo "############ A -> B (receiver $RCV_B) ############"
echo "before: acc0 on A=$(bal $ACC0 $A_RPC)  receiver on B=$(bal $RCV_B $B_RPC)"
cast send "$TOKEN" "approve(address,uint256)" "$GATE" "$AMT" --rpc-url "$A_RPC" --private-key "$KEY0" >/dev/null
cast send "$GATE" "send(address,uint256,uint256,bytes,bytes)" "$TOKEN" "$AMT" 1338 "$RCV_B" "0x" --rpc-url "$A_RPC" --private-key "$KEY0" >/dev/null
if wait_bal "$RCV_B" "$B_RPC" "$AMT"; then echo "after : receiver on B=$(bal $RCV_B $B_RPC)  -> CREDITED ✅"
else echo "after : receiver on B=$(bal $RCV_B $B_RPC)  -> NOT credited ❌"; fi
echo "        acc0 on A=$(bal $ACC0 $A_RPC) (reduced by 100)"

echo
echo "############ B -> A (receiver $RCV_A) ############"
echo "before: acc0 on B=$(bal $ACC0 $B_RPC)  receiver on A=$(bal $RCV_A $A_RPC)"
cast send "$TOKEN" "approve(address,uint256)" "$GATE" "$AMT" --rpc-url "$B_RPC" --private-key "$KEY0" >/dev/null
cast send "$GATE" "send(address,uint256,uint256,bytes,bytes)" "$TOKEN" "$AMT" 1337 "$RCV_A" "0x" --rpc-url "$B_RPC" --private-key "$KEY0" >/dev/null
if wait_bal "$RCV_A" "$A_RPC" "$AMT"; then echo "after : receiver on A=$(bal $RCV_A $A_RPC)  -> CREDITED ✅"
else echo "after : receiver on A=$(bal $RCV_A $A_RPC)  -> NOT credited ❌"; fi
echo "        acc0 on B=$(bal $ACC0 $B_RPC) (reduced by 100)"
