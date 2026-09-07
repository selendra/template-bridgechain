#!/usr/bin/env bash
# Resolve the LIVE stack's deployed addresses. Sourced by the diagnostic and
# send scripts in this directory.
#
# WHY THIS EXISTS. These scripts used to pin `GATE=0xe7f1725E…` as a literal —
# the address anvil hands the Gate under one particular deploy ordering. Two
# things break that:
#
#   * Gate moved behind `GateProxy` (UUPS). `0xe7f1725E…` is now the
#     IMPLEMENTATION, and the implementation has no storage: calls against it
#     revert or, worse, read zeroed state. The address to talk to is the proxy.
#   * Any change to deploy order shifts every subsequent address.
#
# Both fail *silently-ish* — you get a revert with no hint that the constant is
# simply pointing at the wrong contract. So read the addresses `scripts/run.sh`
# actually wrote instead of restating them here.
#
# Sets: GATE_A GATE_B TOKEN_A TOKEN_B TOKEN GATE SWAP_POOL BRIDGE_DOMAIN
# Honours: RUN_DIR (default /tmp/bridge-run), CHAIN_A/CHAIN_B, ASSET.

RUN_DIR="${RUN_DIR:-/tmp/bridge-run}"
CHAIN_A="${CHAIN_A:-1337}"
CHAIN_B="${CHAIN_B:-1338}"
ASSET="${ASSET:-TST}"

_addr_env="$RUN_DIR/addresses.env"
if [[ ! -f "$_addr_env" ]]; then
  echo "ERROR: $_addr_env not found — is the stack up? (bash scripts/run.sh)" >&2
  return 1 2>/dev/null || exit 1
fi
# shellcheck disable=SC1090
source "$_addr_env"

_need() {  # _need VARNAME  -> echoes its value, or dies naming what is missing
  local v="${!1:-}"
  [[ -n "$v" ]] || { echo "ERROR: $1 is not set in $_addr_env" >&2; return 1; }
  printf '%s' "$v"
}

GATE_A="$(_need "CHAIN_${CHAIN_A}_GATE")"   || return 1 2>/dev/null || exit 1
GATE_B="$(_need "CHAIN_${CHAIN_B}_GATE")"   || return 1 2>/dev/null || exit 1
TOKEN_A="$(_need "TOKEN_${ASSET}_${CHAIN_A}")" || return 1 2>/dev/null || exit 1
TOKEN_B="$(_need "TOKEN_${ASSET}_${CHAIN_B}")" || return 1 2>/dev/null || exit 1

# Most of these scripts predate multi-chain address divergence and use one
# `TOKEN`/`GATE` for both sides. That is only correct while the two deploys
# landed on the same address (deterministic nonce ordering on a fresh anvil
# pair). Say so out loud rather than reporting a confusing balance if it ever
# stops being true.
if [[ "$TOKEN_A" != "$TOKEN_B" ]]; then
  echo "NOTE: $ASSET differs per chain (A=$TOKEN_A B=$TOKEN_B); use TOKEN_A/TOKEN_B" >&2
fi
if [[ "$GATE_A" != "$GATE_B" ]]; then
  echo "NOTE: gate differs per chain (A=$GATE_A B=$GATE_B); use GATE_A/GATE_B" >&2
fi
TOKEN="$TOKEN_A"
GATE="$GATE_A"
