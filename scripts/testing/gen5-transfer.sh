#!/usr/bin/env bash
# gen5-transfer.sh — a real round-trip transfer through the live Generation-5
# mesh, asserting each stage rather than just the final balance.
#
#   bash scripts/testing/gen5-transfer.sh
#
# Credentials and addresses come from scripts/gen5.config.local and
# $RUN_DIR/addresses.env; nothing secret is passed on a command line.
#
# A fresh receiver per direction, derived from the clock, so a re-run can never
# read a previous run's balance and call it a pass.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
export PATH="$HOME/.foundry/bin:$PATH"

CFG="${1:-scripts/gen5.config.local}"
# shellcheck disable=SC1090
source "$CFG"
RUN_DIR="${RUN_DIR:-/tmp/bridge-gen5}"
# shellcheck disable=SC1091
source "$RUN_DIR/addresses.env"
GQL="http://${BIND_HOST:-127.0.0.1}:${GQL_PORT:-8088}/graphql"

rpc_for() { local want=$1 e c n r; for e in "${CHAINS[@]}"; do IFS='|' read -r c n r _ <<<"$e"; [[ "${c// /}" == "$want" ]] && { printf '%s' "${r// /}"; return; }; done; }
SEP_RPC=$(rpc_for 11155111); HOO_RPC=$(rpc_for 560048)
SEP_G=$CHAIN_11155111_GATE;  HOO_G=$CHAIN_560048_GATE
SEP_T=$TOKEN_TST_11155111;   HOO_T=$TOKEN_TST_560048

AMT=${AMT:-2000000000000000000}   # 2 TST
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

leg() { # name  src_rpc src_gate src_token  dst_rpc dst_token  dst_chain  receiver
  local name=$1 srpc=$2 sgate=$3 stok=$4 drpc=$5 dtok=$6 dchain=$7 rcv=$8
  printf '\n\033[1;36m=== %s ===\033[0m\n' "$name"
  local before after
  before=$(cast call "$dtok" 'balanceOf(address)(uint256)' "$rcv" --rpc-url "$drpc" | awk '{print $1}')
  [[ "$before" == "0" ]] || fail "receiver $rcv is not fresh (holds $before)"
  echo "  receiver $rcv starts at 0"

  cast send "$stok" "approve(address,uint256)" "$sgate" "$AMT" \
    --rpc-url "$srpc" --private-key "$DEPLOYER_KEY" >/dev/null
  cast send "$sgate" "send(address,uint256,uint256,bytes,bytes)" "$stok" "$AMT" "$dchain" "$rcv" "0x" \
    --rpc-url "$srpc" --private-key "$DEPLOYER_KEY" --json \
    | sed -n 's/.*"transactionHash": *"\([^"]*\)".*/  sent, tx \1/p'
  echo "  waiting: $SOURCE_BLOCK_CONFIRMATION confirmations, then quorum, then the claim"

  local i sigs
  for i in $(seq 1 60); do
    after=$(cast call "$dtok" 'balanceOf(address)(uint256)' "$rcv" --rpc-url "$drpc" | awk '{print $1}')
    if [[ "$after" == "$AMT" ]]; then echo "  [$((i*10))s] CREDITED $after"; break; fi
    sigs=$(curl -s -X POST "$GQL" -H 'content-type: application/json' \
      --data '{"query":"{ submissions { signatureCount status } }"}' \
      | grep -o '"status":"[A-Z]*"' | sort | uniq -c | tr -d '\n' || true)
    echo "  [$((i*10))s] ${sigs:-no records yet}"
    sleep 10
  done
  [[ "$after" == "$AMT" ]] || fail "$name never credited (receiver holds $after, want $AMT)"
}

STAMP=$(printf '%08x' $(( $(date +%s) & 0xffffffff )))
leg "Sepolia -> Hoodi" "$SEP_RPC" "$SEP_G" "$SEP_T" "$HOO_RPC" "$HOO_T" 560048   "0x11111111${STAMP}111111111111111111111111"
leg "Hoodi -> Sepolia" "$HOO_RPC" "$HOO_G" "$HOO_T" "$SEP_RPC" "$SEP_T" 11155111 "0x22222222${STAMP}222222222222222222222222"

printf '\n\033[1;36m=== every record reached a terminal, signed state ===\033[0m\n'
OUT=$(curl -s -X POST "$GQL" -H 'content-type: application/json' \
  --data '{"query":"{ submissions { chainIdFrom chainIdTo signatureCount meetsThreshold status executed } }"}')
echo "$OUT"
echo "$OUT" | grep -q '"status":"PENDING"' && fail "a transfer is still PENDING"
[[ "$(echo "$OUT" | grep -o '"executed":true' | wc -l)" -ge 2 ]] || fail "fewer than 2 executed transfers"
echo "$OUT" | grep -q '"meetsThreshold":false' && fail "a record is below quorum"

printf '\n\033[32mPASS: both directions settled on live testnets through the Gen-5 gates\033[0m\n'
