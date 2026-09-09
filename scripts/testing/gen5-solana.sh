#!/usr/bin/env bash
# gen5-solana.sh — bring the Solana devnet leg into Generation 5.
#
#   bash scripts/testing/gen5-solana.sh deploy     # publish the program (~1.6 SOL)
#   bash scripts/testing/gen5-solana.sh configure  # init + corridors + asset
#   bash scripts/testing/gen5-solana.sh show       # read back the config PDA
#   bash scripts/testing/gen5-solana.sh check      # verify it agrees with the EVM mesh
#
# WHY A NEW PROGRAM AND NOT AN UPGRADE. The gate's `bridge_domain` lives in the
# Config PDA and is written once, by `Init`; there is no instruction to change it
# and `process_init` refuses a second call. The PDA is derived from the program
# id, so the only way to get a config carrying Gen 5's domain is a new program
# id. The CODE is unchanged — every audited fix was Solidity — so this is a fresh
# identity for the same bytecode, not a bug fix.
#
# WHY IT MATTERS. Every submissionId hashes the domain. While the Solana gate
# holds Gen 4's, the EVM side and the Solana side compute DIFFERENT ids for the
# same transfer, so a claim can never reach quorum and an EVM->Solana transfer
# locks on the source forever.
#
# Credentials come from scripts/solana-devnet.config.local and the Gen-5 EVM
# addresses from $RUN_DIR/addresses.env. Nothing secret is passed on a command
# line.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
export PATH="$HOME/.local/share/solana/install/active_release/bin:$HOME/.foundry/bin:$PATH"

# shellcheck disable=SC1090
source scripts/solana-devnet.config.local   # SOLANA_RPC, payer, chain id
# shellcheck disable=SC1090
source scripts/gen5.config.local            # BRIDGE_DOMAIN, VALIDATOR_KEYS, THRESHOLD, RUN_DIR

SO=crates/solana-gate/target/deploy/solana_gate.so
PROGRAM_KP=.solana/gen5/program-keypair.json
PAYER="$SOLANA_PAYER_KEYPAIR"
ADMIN="$ROOT/crates/solana-relayer/target/debug/gate-admin"
RUN_DIR="${RUN_DIR:-/tmp/bridge-gen5}"

[[ "$BRIDGE_DOMAIN" =~ ^0x[0-9a-fA-F]{64}$ ]] || { echo "bad BRIDGE_DOMAIN" >&2; exit 1; }
[[ -f "$PROGRAM_KP" ]] || { echo "missing $PROGRAM_KP" >&2; exit 1; }
PID=$(solana-keygen pubkey "$PROGRAM_KP")
PAYER_PUB=$(solana-keygen pubkey "$PAYER")

say()  { printf '\n\033[1;36m=== %s ===\033[0m\n' "$*"; }
need() { [[ -n "$2" ]] || { echo "could not determine $1" >&2; exit 1; }; }
admin(){ "$ADMIN" --rpc "$SOLANA_RPC" --keypair "$PAYER" --program "$PID" "$@"; }

# The validator set MUST equal the EVM one: one quorum attests for both VMs, so a
# mismatch means Solana-origin transfers can never reach EVM threshold.
vaddrs() { local k; for k in "${VALIDATOR_KEYS[@]}"; do cast wallet address --private-key "$k"; done; }

# `show` prints "vault authority: <pubkey>". Match space OR underscore — an
# earlier version of this script assumed the underscore, produced an empty vault,
# and would have failed halfway through configure.
vault_authority() { admin show | sed -n 's/.*vault[ _]authority[: ]*\([1-9A-HJ-NP-Za-km-z]\{32,44\}\).*/\1/p' | head -1; }

case "${1:-}" in
deploy)
  [[ -f "$SO" ]] || { echo "missing $SO — run scripts/testing/build-solana.sh gate" >&2; exit 1; }
  say "deploying solana-gate to devnet"
  echo "  program id : $PID"
  echo "  payer      : $PAYER_PUB  ($(solana balance "$PAYER_PUB" --url "$SOLANA_RPC"))"
  echo "  artifact   : $SO ($(stat -c%s "$SO") bytes)"
  solana program deploy "$SO" \
    --program-id "$PROGRAM_KP" --keypair "$PAYER" \
    --upgrade-authority "$PAYER" --url "$SOLANA_RPC"
  echo "  balance after: $(solana balance "$PAYER_PUB" --url "$SOLANA_RPC")"
  ;;

configure)
  [[ -x "$ADMIN" ]] || { echo "build it: (cd crates/solana-relayer && cargo build --bin gate-admin)" >&2; exit 1; }
  # shellcheck disable=SC1091
  source "$RUN_DIR/addresses.env"
  SEP_TOKEN="${TOKEN_TST_11155111:?Gen-5 Sepolia token missing from $RUN_DIR/addresses.env}"
  DID=$(cast keccak "$(cast abi-encode --packed 'f(uint256,address)' 11155111 "$SEP_TOKEN")")

  say "init config PDA (domain ${BRIDGE_DOMAIN:0:14}…, threshold $THRESHOLD)"
  vargs=(); while read -r a; do vargs+=(--validator "$a"); done < <(vaddrs)
  admin init --chain-id "$SOLANA_CHAIN_ID" --threshold "$THRESHOLD" \
             --bridge-domain "$BRIDGE_DOMAIN" "${vargs[@]}"

  say "register corridors"
  for c in 11155111 560048; do admin register-corridor --chain-id-to "$c"; done

  say "create the mirrored SPL asset"
  AUTH=$(vault_authority); need "vault authority" "$AUTH"
  echo "  vault authority PDA : $AUTH"
  # 6 decimals, matching the previous generation's mirrored asset.
  MINT=$(spl-token create-token --decimals 6 --url "$SOLANA_RPC" --fee-payer "$PAYER" \
           --mint-authority "$PAYER_PUB" | sed -n 's/^Address: *//p' | head -1)
  need "mint" "$MINT"; echo "  mint                : $MINT"
  # Owned by the PDA, with no delegate and no close authority — process_register_asset
  # rejects a vault anyone else could move (M-6). A fresh ATA satisfies all three.
  VAULT=$(spl-token create-account "$MINT" --owner "$AUTH" --url "$SOLANA_RPC" --fee-payer "$PAYER" \
           | sed -n 's/^Creating account *//p' | head -1)
  need "vault token account" "$VAULT"; echo "  vault               : $VAULT"
  spl-token mint "$MINT" 1000000 "$VAULT" --url "$SOLANA_RPC" --fee-payer "$PAYER" >/dev/null
  echo "  minted 1,000,000 units of claim liquidity"

  say "register asset (debridgeId $DID)"
  admin register-asset --debridge-id "$DID" --mint "$MINT" --vault "$VAULT"

  say "register the RETURN path on the EVM side"
  # Without this, Solana->EVM is one-way-broken and nothing says so loudly.
  # `run.sh` wires setLocalToken only between the EVM chains it knows about;
  # Solana lives in a different config, so its corridor's return leg is never
  # registered. A Solana-origin claim then hits `UnknownAsset` — and the keeper
  # skips it SILENTLY (it treats tokenOf==0 as a stranded transfer and declines
  # to hammer the RPC), so the symptom is a transfer stuck at READY forever with
  # nothing in any log.
  #
  # The debridgeId is Sepolia's own, because that is the asset identity the
  # Solana gate has registered and will emit on `send`.
  bash -c 'source scripts/gen5.config.local >/dev/null 2>&1
    source "'"$RUN_DIR"'/addresses.env"
    rpc(){ local w=$1 e c n r; for e in "${CHAINS[@]}"; do IFS="|" read -r c n r _ <<<"$e"; [ "${c// /}" = "$w" ] && { printf "%s" "${r// /}"; return; }; done; }
    # M-3: every EVM gate must list the Solana chain id before an EVM->Solana
    # `send` is accepted (run.config: EXTRA_SUPPORTED_CHAINS=('"$SOLANA_CHAIN_ID"')).
    for c in 11155111 560048; do
      g="CHAIN_${c}_GATE"; g="${!g:-}"; [ -n "$g" ] || continue
      ok=$(cast call "$g" "supportedChain(uint256)(bool)" '"$SOLANA_CHAIN_ID"' --rpc-url "$(rpc "$c")" 2>/dev/null || echo false)
      if [ "$ok" != "true" ]; then
        cast send "$g" "setSupportedChain(uint256,bool)" '"$SOLANA_CHAIN_ID"' true --rpc-url "$(rpc "$c")" --private-key "$DEPLOYER_KEY" >/dev/null
        echo "  chain $c gate: send -> Solana enabled"
      fi
    done
    cur=$(cast call "$CHAIN_11155111_GATE" "tokenOf(bytes32)(address)" "'"$DID"'" --rpc-url "$(rpc 11155111)")
    if [ "${cur,,}" = "0x0000000000000000000000000000000000000000" ]; then
      # H-1: on a sealed gate this is a governance action, not an instant call.
      sealed=$(cast call "$CHAIN_11155111_GATE" "isSealed()(bool)" --rpc-url "$(rpc 11155111)" 2>/dev/null || echo false)
      if [ "$sealed" = "true" ]; then
        aid=$(cast call "$CHAIN_11155111_GATE" "setLocalTokenActionId(bytes32,address)(bytes32)" "'"$DID"'" "$TOKEN_TST_11155111" --rpc-url "$(rpc 11155111)")
        echo "  !! Sepolia gate is SEALED — register the return path through governance:"
        echo "     cast send $CHAIN_11155111_GATE '"'"'scheduleGovernance(bytes32)'"'"' $aid --rpc-url <sepolia> --private-key <owner>"
        echo "     # after 48h (within 7d):"
        echo "     cast send $CHAIN_11155111_GATE '"'"'setLocalToken(bytes32,address)'"'"' '"$DID"' $TOKEN_TST_11155111 --rpc-url <sepolia> --private-key <owner>"
        echo "     (or add \"11155111|'"$DID"'|$TOKEN_TST_11155111\" to EXTRA_LOCAL_TOKENS before the next run.sh deploy)"
      else
        cast send "$CHAIN_11155111_GATE" "setLocalToken(bytes32,address)" "'"$DID"'" "$TOKEN_TST_11155111" \
          --rpc-url "$(rpc 11155111)" --private-key "$DEPLOYER_KEY" >/dev/null
        echo "  Sepolia gate: tokenOf set -> $TOKEN_TST_11155111"
      fi
    else
      echo "  Sepolia gate: already mapped -> $cur"
    fi'

  # NOTE ON RECEIVERS. A Solana->EVM `send` must carry a 20-BYTE receiver: the
  # EVM gate's `_toAddress` requires exactly 20 and reverts BadReceiver on a
  # 32-byte left-padded address. The keeper pre-filters those at DEBUG, so a
  # wrong-width receiver also strands silently. EVM->Solana is the mirror image:
  # the receiver there is the 32-byte SPL TOKEN ACCOUNT, not a wallet.

  say "record these in scripts/solana-devnet.config.local"
  echo "  SOLANA_PROGRAM_ID=\"$PID\""
  echo "  mint  $MINT"
  echo "  vault $VAULT"
  echo "  debridgeId $DID   (mirrors Sepolia $SEP_TOKEN)"
  echo
  echo "Then re-point the relayer at \$SOLANA_PROGRAM_ID and run: $0 check"
  ;;

show)  admin show ;;

check)
  say "does the Solana gate agree with the Gen-5 EVM mesh?"
  out=$(admin show)
  dom=$(sed -n 's/.*bridge domain[: ]*\(0x[0-9a-fA-F]\{64\}\).*/\1/p' <<<"$out" | head -1)
  thr=$(sed -n 's/.*threshold *: *\([0-9]\+\).*/\1/p' <<<"$out" | head -1)
  fail=0
  if [[ "$dom" == "$BRIDGE_DOMAIN" ]]; then
    printf '  \033[32mPASS\033[0m  bridge domain matches the EVM mesh\n'
  else
    printf '  \033[31mFAIL\033[0m  bridge domain %s != EVM %s\n' "$dom" "$BRIDGE_DOMAIN"; fail=1
  fi
  [[ "$thr" == "$THRESHOLD" ]] \
    && printf '  \033[32mPASS\033[0m  threshold %s\n' "$thr" \
    || { printf '  \033[31mFAIL\033[0m  threshold %s != %s\n' "$thr" "$THRESHOLD"; fail=1; }
  while read -r a; do
    grep -qi "${a#0x}" <<<"$out" \
      && printf '  \033[32mPASS\033[0m  validator %s present\n' "$a" \
      || { printf '  \033[31mFAIL\033[0m  validator %s missing\n' "$a"; fail=1; }
  done < <(vaddrs)
  for c in 11155111 560048; do
    grep -q "chain $c" <<<"$out" \
      && printf '  \033[32mPASS\033[0m  corridor -> %s registered\n' "$c" \
      || { printf '  \033[31mFAIL\033[0m  corridor -> %s missing\n' "$c"; fail=1; }
  done
  echo
  [[ "$fail" -eq 0 ]] && echo "Solana leg is IN the Gen-5 mesh" || { echo "Solana leg is OUT of the Gen-5 mesh"; exit 1; }
  ;;

*) echo "usage: $0 {deploy|configure|show|check}" >&2; exit 1 ;;
esac
