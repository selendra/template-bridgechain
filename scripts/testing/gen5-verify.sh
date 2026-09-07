#!/usr/bin/env bash
# gen5-verify.sh — assert the live Generation-5 mesh is what it claims to be.
#
#   bash scripts/testing/gen5-verify.sh
#
# Reads endpoints and addresses from scripts/gen5.config.local and
# $RUN_DIR/addresses.env, so no credential is ever passed on a command line.
#
# What it checks, and why each one is worth checking:
#   * GOVERNANCE_DELAY answers          -> these gates run the AUDITED code, not
#                                          the pre-audit implementation Gen 4 has
#   * bridgeDomain matches the config   -> the mesh agrees on its generation, and
#                                          is distinct from Gen 4's
#   * both gates share ONE domain       -> the two sides compute the same ids
#   * threshold / validator set         -> quorum is what the config asked for
#   * destination liquidity + tokenOf   -> a claim can actually pay out
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

GEN4_DOMAIN=0x619244a655e7383c05da63e9d66080952fcfe4fc48b40c61f566996006848055
pass=0 fail=0
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; fail=$((fail+1)); }
check(){ if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (got $2, want $3)"; fi; }

rpc_for() { local want=$1 e c n r; for e in "${CHAINS[@]}"; do IFS='|' read -r c n r _ <<<"$e"; [[ "${c// /}" == "$want" ]] && { printf '%s' "${r// /}"; return; }; done; }

echo "Generation 5 — live mesh verification"
echo "domain (config): $BRIDGE_DOMAIN"
echo

declare -A GATE=( [11155111]="$CHAIN_11155111_GATE" [560048]="$CHAIN_560048_GATE" )
declare -A TOKEN=( [11155111]="$TOKEN_TST_11155111" [560048]="$TOKEN_TST_560048" )
declare -A NAME=( [11155111]="Sepolia" [560048]="Hoodi" )

for cid in 11155111 560048; do
  URL=$(rpc_for "$cid"); G=${GATE[$cid]}; T=${TOKEN[$cid]}
  echo "--- ${NAME[$cid]} ($cid)  gate $G ---"

  # The audited implementation exposes GOVERNANCE_DELAY; the pre-audit one reverts.
  if gd=$(cast call "$G" 'GOVERNANCE_DELAY()(uint256)' --rpc-url "$URL" 2>/dev/null); then
    check "runs the audited implementation (GOVERNANCE_DELAY=48h)" "${gd%% *}" "172800"
  else
    bad "runs the audited implementation — GOVERNANCE_DELAY reverted (pre-audit code)"
  fi

  d=$(cast call "$G" 'bridgeDomain()(bytes32)' --rpc-url "$URL" | awk '{print $1}')
  check "bridgeDomain matches the config" "$d" "$BRIDGE_DOMAIN"
  if [[ "$d" == "$GEN4_DOMAIN" ]]; then bad "domain is Gen 4's — signatures would replay across generations"; else ok "domain is distinct from Gen 4's"; fi

  check "threshold" "$(cast call "$G" 'threshold()(uint256)' --rpc-url "$URL" | awk '{print $1}')" "$THRESHOLD"
  check "validatorCount" "$(cast call "$G" 'validatorCount()(uint256)' --rpc-url "$URL" | awk '{print $1}')" "${#VALIDATOR_KEYS[@]}"
  check "upgrade is NOT pre-scheduled on a fresh gate" \
        "$(cast call "$G" 'upgradeReadyAt(address)(uint256)' "$G" --rpc-url "$URL" | awk '{print $1}')" "0"

  # A destination can only pay out if the incoming debridgeId maps to a local
  # token AND the gate holds enough of it.
  other=$([[ "$cid" == 11155111 ]] && echo 560048 || echo 11155111)
  did=$(cast keccak "$(cast abi-encode --packed 'f(uint256,address)' "$other" "${TOKEN[$other]}")")
  mapped=$(cast call "$G" 'tokenOf(bytes32)(address)' "$did" --rpc-url "$URL" | awk '{print $1}')
  check "incoming ${NAME[$other]} asset maps to the local token" "${mapped,,}" "${T,,}"
  liq=$(cast call "$T" 'balanceOf(address)(uint256)' "$G" --rpc-url "$URL" | awk '{print $1}')
  if [[ "${liq%%[^0-9]*}" -gt 0 ]] 2>/dev/null; then ok "holds claim liquidity ($liq)"; else bad "no claim liquidity"; fi
  echo
done

# One mesh means one domain on every gate.
d1=$(cast call "${GATE[11155111]}" 'bridgeDomain()(bytes32)' --rpc-url "$(rpc_for 11155111)" | awk '{print $1}')
d2=$(cast call "${GATE[560048]}"   'bridgeDomain()(bytes32)' --rpc-url "$(rpc_for 560048)"   | awk '{print $1}')
check "both gates share ONE domain" "$d1" "$d2"

echo
printf 'RESULT: %d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
