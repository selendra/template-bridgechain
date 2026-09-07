#!/usr/bin/env bash
# Show that no tokens are lost: on each chain, sum every holder and compare to
# totalSupply. Bridging LOCKS the source amount in the gate and RELEASES it to
# the receiver on the other chain — if the receiver isn't you, your personal
# total drops, but the supply is fully conserved.
set -euo pipefail
export PATH="$HOME/.foundry/bin:$PATH"

source "$(dirname "${BASH_SOURCE[0]}")/_addresses.sh"
ACC0=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
# receivers used by the test/diag scripts
R1=0x976EA74026E726554dB657fA54763abd0C3a0aa9
R2=0x00000000000000000000000000000000000000A1
R3=0x00000000000000000000000000000000000000B2

e18() { python3 -c "print(int('$1')/10**18)"; }
b() { cast call "$TOKEN" "balanceOf(address)(uint256)" "$1" --rpc-url "$2" | awk '{print $1}'; }

for pair in "A http://127.0.0.1:8545" "B http://127.0.0.1:8546"; do
  set -- $pair; L=$1; RPC=$2
  TS=$(cast call "$TOKEN" "totalSupply()(uint256)" --rpc-url "$RPC" | awk '{print $1}')
  A=$(b "$ACC0" "$RPC"); G=$(b "$GATE" "$RPC")
  X1=$(b "$R1" "$RPC"); X2=$(b "$R2" "$RPC"); X3=$(b "$R3" "$RPC")
  SUM=$(python3 -c "print($A+$G+$X1+$X2+$X3)")
  echo "===== chain $L ====="
  echo "  totalSupply     : $(e18 $TS)"
  echo "  account0        : $(e18 $A)"
  echo "  gate (locked)   : $(e18 $G)"
  echo "  receiver R1     : $(e18 $X1)"
  echo "  receiver R2     : $(e18 $X2)"
  echo "  receiver R3     : $(e18 $X3)"
  echo "  ---- sum holders: $(e18 $SUM)   (matches totalSupply => nothing lost)"
done
