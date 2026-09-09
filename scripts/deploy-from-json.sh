#!/usr/bin/env bash
# deploy-from-json.sh — deploy the bridge contracts from a JSON config.
#
#   bash scripts/deploy-from-json.sh [config.json] [--dry-run] [--no-config-update] [--redeploy]
#                                    [--allow-local-profile-on-chain]
#
# Default config: config/deploy.config.json  (see config/README.md for the field
# reference). Two profiles:
#
#   "local"       forge-create path: Gate implementation + GateProxy, TestTokens
#                 for assets marked "auto", corridor registration + mint
#                 liquidity. The deployer stays the gate owner.
#   "production"  runs contracts/script/DeployProd.s.sol, which enforces >=3
#                 validators, a strict-majority threshold, a guardian, and hands
#                 ownership to a multisig (two-step). No tokens are deployed.
#
# The `local` profile is REFUSED on any chain id outside DEV_CHAIN_IDS below
# (M-12: it ships threshold-1 gates owned by a hot key with no guardian) unless
# --allow-local-profile-on-chain is passed explicitly.
#
# Gate wiring, both profiles, while the deployer is still the (transient) owner
# — i.e. before the multisig's acceptOwnership():
#   setSupportedChain(peer, true) for every peer -> setLocalToken for every
#   inbound corridor -> seal()  (gate.seal, default true; irreversible).
# Anything the deployer cannot send (a gate it no longer owns, a corridor on an
# already-sealed gate) is written to `governance_calls` in the output file for
# the owner to execute — including the scheduleGovernance step a sealed gate
# needs first. Production asserts isSealed and every supportedChain at the end.
#
# Writes every address it produced to `output.file`, and (unless
# --no-config-update) patches gate/token/pool addresses straight into the
# bridge runtime config named by `output.update_bridge_config`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACTS="$ROOT/contracts"
CONFIG="config/deploy.config.json"
DRY_RUN=false
UPDATE_CFG=true
REDEPLOY=false
ALLOW_LOCAL_ON_CHAIN=false

# Chain ids the `local` profile may touch (M-12). One list, one place: anvil /
# hardhat defaults, the ports-as-chain-ids convention the launchers here use, and
# the well-known public testnets. Anything else is presumed to carry real value.
#   31337 anvil/hardhat, 1337-1339 run.config, 11155111 Sepolia, 560048 Hoodi,
#   17000 Holesky, 84532 Base Sepolia, 421614 Arbitrum Sepolia, 11155420 OP
#   Sepolia, 80002 Polygon Amoy, 97 BSC testnet, 43113 Fuji, 1313161555 Aurora
#   testnet, 1953 Selendra testnet
DEV_CHAIN_IDS=(31337 31338 31339 1337 1338 1339 11155111 560048 17000 84532 421614 11155420 80002 97 43113 1313161555 1953)
is_dev_chain() { local c; for c in "${DEV_CHAIN_IDS[@]}"; do [[ "$1" == "$c" ]] && return 0; done; return 1; }

for arg in "$@"; do
  case "$arg" in
    --dry-run)          DRY_RUN=true ;;
    --redeploy)         REDEPLOY=true ;;
    --no-config-update) UPDATE_CFG=false ;;
    --allow-local-profile-on-chain) ALLOW_LOCAL_ON_CHAIN=true ;;
    -h|--help)          sed -n '2,25p' "$0"; exit 0 ;;
    -*)                 echo "unknown flag: $arg" >&2; exit 1 ;;
    *)                  CONFIG="$arg" ;;
  esac
done
[[ "$CONFIG" = /* ]] || CONFIG="$ROOT/$CONFIG"
[[ -f "$CONFIG" ]] || { echo "config not found: $CONFIG" >&2; exit 1; }

say()  { printf '\n\033[1;36m=== %s ===\033[0m\n' "$*"; }
info() { printf '  %s\n' "$*"; }
warn() { printf '\033[1;33m  ! %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' not found on PATH (needed for: $2)"; }

need jq    "reading the JSON config"
need forge "contract deploys"
need cast  "chain reads/writes"

j()  { jq -r "$1" "$CONFIG"; }
jr() { jq -r "$1 // empty" "$CONFIG"; }

# --- config ----------------------------------------------------------------
NAME="$(j '.name')"
PROFILE="$(j '.profile')"
[[ "$PROFILE" == "local" || "$PROFILE" == "production" ]] || die "profile must be \"local\" or \"production\" (got: $PROFILE)"
THRESHOLD="$(j '.gate.threshold')"
mapfile -t VALIDATORS < <(j '.gate.validators[]')
GUARDIAN="$(jr '.gate.guardian')"
OWNER="$(jr '.gate.owner')"
BRIDGE_DOMAIN="$(j '.gate.bridge_domain')"
OUT_FILE="$(jr '.output.file')"; OUT_FILE="${OUT_FILE:-config/deployments/$NAME.json}"
[[ "$OUT_FILE" = /* ]] || OUT_FILE="$ROOT/$OUT_FILE"
BRIDGE_CFG="$(jr '.output.update_bridge_config')"
[[ -n "$BRIDGE_CFG" && "$BRIDGE_CFG" != /* ]] && BRIDGE_CFG="$ROOT/$BRIDGE_CFG"

(( ${#VALIDATORS[@]} >= 1 )) || die "gate.validators is empty"
(( THRESHOLD >= 1 && THRESHOLD <= ${#VALIDATORS[@]} )) || die "gate.threshold must be 1..${#VALIDATORS[@]}"
for v in "${VALIDATORS[@]}"; do [[ "$v" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "not an address: gate.validators[] = $v"; done
# Duplicates would silently shrink the quorum: the Gate constructor dedupes, so
# [A,B,B] with threshold 2 ships a 2-of-2 gate, one key short of what was signed off.
dupes="$(printf '%s\n' "${VALIDATORS[@]}" | tr 'A-F' 'a-f' | sort | uniq -d)"
[[ -z "$dupes" ]] || die "duplicate validator address: $dupes"

# --- profile policy --------------------------------------------------------
SEAL="$(j 'if .gate.seal == null then true else .gate.seal end')"
mapfile -t EXTRA_PEERS < <(j '.gate.extra_supported_chains[]?')
if [[ "$PROFILE" == "production" ]]; then
  [[ "$SEAL" == "true" ]] || die "production must seal the gates (gate.seal = false is a dev-only setting)"
  (( ${#VALIDATORS[@]} >= 3 )) || die "production needs >= 3 validators (DeployProd rejects fewer)"
  (( THRESHOLD >= 2 && THRESHOLD * 2 > ${#VALIDATORS[@]} )) || die "production needs a strict-majority threshold (> ${#VALIDATORS[@]}/2, and >= 2)"
  [[ "$GUARDIAN" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "production needs gate.guardian"
  [[ "$OWNER"    =~ ^0x[0-9a-fA-F]{40}$ ]] || die "production needs gate.owner (the multisig)"
  [[ "${GUARDIAN,,}" != "${OWNER,,}" ]] || die "gate.guardian must differ from gate.owner"
  [[ "$BRIDGE_DOMAIN" == "auto" ]] && die "production must PIN gate.bridge_domain (0x + 64 hex) — 'auto' would mint a new one on every run"
  [[ "$(jq -r '[.assets[]?.deployments[]? | select(.address == "auto")] | length' "$CONFIG")" == "0" ]] \
    || die "production cannot deploy TestTokens: replace every asset address \"auto\" with the real ERC-20"
  [[ "$(jq -r '[.assets[]? | select(.test_liquidity.enabled == true)] | length' "$CONFIG")" == "0" ]] \
    || die "production cannot mint test liquidity: set assets[].test_liquidity.enabled = false"
fi

# Every gate in one mesh generation shares ONE domain, and a NEW generation needs
# a NEW one — that is what stops the previous deployment's validator signatures
# from replaying against these fresh gates.
if [[ "$BRIDGE_DOMAIN" == "auto" ]]; then
  BRIDGE_DOMAIN="$(cast keccak "$(printf 'selendra-bridge|%s|%s|%s|%s' \
    "$NAME" "$(IFS=,; echo "${VALIDATORS[*]}")" "$THRESHOLD" "$(date +%s)-$$")")"
  info "generated bridge_domain=$BRIDGE_DOMAIN (pin it in the config to reuse)"
fi
[[ "$BRIDGE_DOMAIN" =~ ^0x[0-9a-fA-F]{64}$ ]] || die "gate.bridge_domain must be 0x + 64 hex chars"
[[ "$BRIDGE_DOMAIN" =~ ^0x0{64}$ ]] && die "gate.bridge_domain must not be zero (Gate rejects it)"

# --- deployer auth (private key / env var / encrypted keystore) -------------
AUTH=()
DEPLOYER_KEY="$(jr '.deployer.private_key')"
DEPLOYER_KEY_ENV="$(jr '.deployer.private_key_env')"
KEYSTORE="$(jr '.deployer.keystore')"
KEYSTORE_PASS_FILE="$(jr '.deployer.keystore_password_file')"
if [[ -n "$KEYSTORE" ]]; then
  [[ -f "$KEYSTORE" ]] || die "deployer.keystore not found: $KEYSTORE"
  AUTH=(--keystore "$KEYSTORE")
  [[ -n "$KEYSTORE_PASS_FILE" ]] && AUTH+=(--password-file "$KEYSTORE_PASS_FILE")
  DEPLOYER_ADDR="$(cast wallet address --keystore "$KEYSTORE" ${KEYSTORE_PASS_FILE:+--password-file "$KEYSTORE_PASS_FILE"})"
elif [[ -n "$DEPLOYER_KEY_ENV" ]]; then
  key="${!DEPLOYER_KEY_ENV:-}"
  [[ -n "$key" ]] || die "deployer.private_key_env=$DEPLOYER_KEY_ENV is set in the config but that env var is empty"
  AUTH=(--private-key "$key")
  DEPLOYER_ADDR="$(cast wallet address --private-key "$key")"
elif [[ -n "$DEPLOYER_KEY" ]]; then
  [[ "$PROFILE" == "local" ]] && : || warn "profile=production with an INLINE deployer key — prefer deployer.keystore"
  AUTH=(--private-key "$DEPLOYER_KEY")
  DEPLOYER_ADDR="$(cast wallet address --private-key "$DEPLOYER_KEY")"
else
  die "no deployer key: set deployer.keystore (preferred), deployer.private_key_env, or deployer.private_key"
fi

mapfile -t CHAIN_IDS < <(j '.chains[] | select(.enabled != false) | .chain_id')
(( ${#CHAIN_IDS[@]} >= 1 )) || die "no enabled chains in .chains"
if [[ "$PROFILE" == "local" ]]; then
  # A local-profile gate is a threshold-1 (possibly) gate owned by the deployer's
  # hot key with no guardian. On a chain with real value that is a live bridge
  # one leaked key away from empty — and Gen-5 WAS deployed this way (M-12).
  for cid in "${CHAIN_IDS[@]}"; do
    is_dev_chain "$cid" && continue
    $ALLOW_LOCAL_ON_CHAIN || die "profile \"local\" on chain $cid, which is not in DEV_CHAIN_IDS (${DEV_CHAIN_IDS[*]}). Use profile \"production\" (guardian, multisig owner, strict-majority quorum), or pass --allow-local-profile-on-chain if you really mean to run a hot-key gate there."
    warn "profile \"local\" on non-dev chain $cid — allowed by --allow-local-profile-on-chain; the gate owner will be the deployer hot key"
  done
fi
# `join` on numbers is a jq type error, and an `&&` tail here would be the
# script's exit status under `set -e` when nothing is skipped.
skipped="$(j '[.chains[] | select(.enabled == false) | .chain_id | tostring] | join(", ")')"
if [[ -n "$skipped" ]]; then warn "skipping disabled chain(s): $skipped"; fi

say "deploy plan: $NAME (profile=$PROFILE)"
info "deployer : $DEPLOYER_ADDR"
info "gate     : ${#VALIDATORS[@]} validators, threshold $THRESHOLD"
info "domain   : $BRIDGE_DOMAIN"
info "chains   : $(IFS=,; echo "${CHAIN_IDS[*]}")"
info "assets   : $(j '[.assets[]?.symbol] | join(", ") | if . == "" then "none" else . end')"
$DRY_RUN && { echo; info "--dry-run: nothing was sent"; exit 0; }

# --- helpers ---------------------------------------------------------------
deployed_to() { grep deployedTo | grep -oE '0x[0-9a-fA-F]{40}' | head -1; }
fc()    { ( cd "$CONTRACTS" && forge create "$1" --rpc-url "$2" "${AUTH[@]}" --broadcast --json "${@:3}" ) | deployed_to; }
csend() { cast send "$1" "$2" "${@:3}" "${AUTH[@]}" >/dev/null; }
debridge_id() { printf '0x%064x%s\n' "$1" "${2#0x}" | xargs cast keccak; }   # keccak(packed(uint256,address))
scaled()      { local whole="$1" dec="$2"; [[ "$whole" =~ ^[0-9]+$ ]] || die "amount must be a whole number: $whole"
                printf '%s%s\n' "$whole" "$(printf '0%.0s' $(seq 1 "$dec"))"; }

RUN_LOG_DIR="$(dirname "$OUT_FILE")/logs"
mkdir -p "$RUN_LOG_DIR"

say "building contracts"
( cd "$CONTRACTS" && forge build >/dev/null ) || die "forge build failed"

# --- chains: verify RPC, record floor block, deploy gates -------------------
declare -A GATE IMPL FLOOR RPC CNAME
for cid in "${CHAIN_IDS[@]}"; do
  RPC[$cid]="$(j ".chains[] | select(.chain_id == $cid) | .rpc_url")"
  CNAME[$cid]="$(j ".chains[] | select(.chain_id == $cid) | .name")"
  got="$(cast chain-id --rpc-url "${RPC[$cid]}" 2>/dev/null)" || die "RPC unreachable: ${RPC[$cid]}"
  [[ "$got" == "$cid" ]] || die "${RPC[$cid]} reports chainId $got, config says $cid"
  FLOOR[$cid]="$(cast block-number --rpc-url "${RPC[$cid]}")"
done

say "deploying gates"
for cid in "${CHAIN_IDS[@]}"; do
  deploy_gate="$(j ".chains[] | select(.chain_id == $cid) | .deploy_gate")"
  existing="$(jq -r ".chains[] | select(.chain_id == $cid) | .gate // empty" "$CONFIG")"
  # A gate already in the record is reused for the same reason a token is: a
  # fresh gate restarts its nonces and strands every transfer in flight.
  if [[ "$deploy_gate" == "true" ]] && ! $REDEPLOY && [[ -f "$OUT_FILE" ]]; then
    prev_gate="$(jq -r --argjson c "$cid" '.chains[]? | select(.chain_id == $c) | .gate // empty' "$OUT_FILE")"
    if [[ "$prev_gate" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
      GATE[$cid]="$prev_gate"
      info "${CNAME[$cid]} ($cid) gate=$prev_gate (from $(basename "$OUT_FILE"); --redeploy to replace)"
      continue
    fi
  fi
  if [[ "$deploy_gate" != "true" ]]; then
    [[ "$existing" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "chain $cid has deploy_gate=false but no gate address"
    GATE[$cid]="$existing"; info "${CNAME[$cid]} ($cid) reusing gate ${GATE[$cid]}"; continue
  fi

  if [[ "$PROFILE" == "production" ]]; then
    # DeployProd asserts every policy invariant on-chain and reverts the whole
    # deployment if one is off; it also appoints the guardian and starts the
    # ownership handover to the multisig.
    log="$RUN_LOG_DIR/deploy-prod-$cid.log"
    # Subshell + "${AUTH[@]}" rather than `bash -c "... ${AUTH[*]}"`: the array
    # form keeps a keystore path with spaces intact and never re-splits the key.
    ( cd "$CONTRACTS" \
      && EXPECTED_CHAIN_ID="$cid" \
         VALIDATORS="$(IFS=,; echo "${VALIDATORS[*]}")" \
         THRESHOLD="$THRESHOLD" GUARDIAN="$GUARDIAN" OWNER="$OWNER" BRIDGE_DOMAIN="$BRIDGE_DOMAIN" \
         forge script script/DeployProd.s.sol:DeployProd \
           --rpc-url "${RPC[$cid]}" "${AUTH[@]}" --broadcast ) >"$log" 2>&1 \
      || { tail -30 "$log"; die "DeployProd failed on chain $cid (log: $log)"; }
    GATE[$cid]="$(grep -A0 'Gate deployed' "$log" | grep -oE '0x[0-9a-fA-F]{40}' | head -1)"
    [[ "${GATE[$cid]}" =~ ^0x ]] || { cat "$log"; die "could not read the deployed gate address on chain $cid"; }
    info "${CNAME[$cid]} ($cid) gate=${GATE[$cid]}  (guardian set, ownership pending $OWNER)"
  else
    # UUPS: an implementation (never initialized) + the proxy that IS the gate.
    # initialize runs inside the proxy constructor, so no uninitialized proxy
    # ever exists on-chain for someone else to claim.
    initdata="$(cast calldata 'initialize(address[],uint256,bytes32)' "[$(IFS=,; echo "${VALIDATORS[*]}")]" "$THRESHOLD" "$BRIDGE_DOMAIN")"
    IMPL[$cid]="$(fc src/Gate.sol:Gate "${RPC[$cid]}")"
    [[ "${IMPL[$cid]}" =~ ^0x ]] || die "gate implementation deploy failed on chain $cid"
    GATE[$cid]="$(fc src/GateProxy.sol:GateProxy "${RPC[$cid]}" --constructor-args "${IMPL[$cid]}" "$initdata")"
    [[ "${GATE[$cid]}" =~ ^0x ]] || die "gate proxy deploy failed on chain $cid"
    info "${CNAME[$cid]} ($cid) gate=${GATE[$cid]} (implementation ${IMPL[$cid]})"
  fi
done

# --- assets: resolve/deploy tokens -----------------------------------------
declare -A TOKEN          # "SYM|chain_id" -> address
declare -A ASSET_CHAINS   # "SYM" -> "cid cid"
mapfile -t SYMS < <(j '.assets[]?.symbol')
if (( ${#SYMS[@]} )); then
  say "resolving asset tokens"
  for sym in "${SYMS[@]}"; do
    tname="$(j ".assets[] | select(.symbol == \"$sym\") | .name")"
    for cid in $(j ".assets[] | select(.symbol == \"$sym\") | .deployments[].chain_id"); do
      if [[ -z "${RPC[$cid]:-}" ]]; then
        jq -e --argjson c "$cid" '[.chains[] | select(.chain_id == $c and .enabled == false)] | length > 0' "$CONFIG" >/dev/null \
          && { info "$sym on chain $cid skipped (chain disabled)"; continue; }
        die "asset $sym lists chain $cid, which is not in .chains"
      fi
      addr="$(j ".assets[] | select(.symbol == \"$sym\") | .deployments[] | select(.chain_id == $cid) | .address")"
      if [[ "$addr" == "auto" ]]; then
        # "auto" means "deploy if we do not already have one" — NOT "deploy
        # again". A second run that mints a fresh token silently rewires the
        # whole mesh to it and orphans the liquidity in the old one, which is
        # exactly the failure the bash launcher's config warns about in prose.
        # The previous run's record is the memory that makes re-running safe.
        prev=""
        if ! $REDEPLOY && [[ -f "$OUT_FILE" ]]; then
          prev="$(jq -r --argjson c "$cid" --arg s "$sym" \
            '.chains[]? | select(.chain_id == $c) | .tokens[$s] // empty' "$OUT_FILE")"
        fi
        if [[ -n "$prev" ]]; then
          addr="$prev"
          info "$sym @ $cid = $addr (from $(basename "$OUT_FILE"); --redeploy to replace)"
        else
          addr="$(fc src/TestToken.sol:TestToken "${RPC[$cid]}" --constructor-args "$tname" "$sym")"
          [[ "$addr" =~ ^0x ]] || die "TestToken deploy failed: $sym on chain $cid"
        fi
      else
        [[ "$addr" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "asset $sym on chain $cid: '$addr' is neither \"auto\" nor an address"
        code="$(cast code "$addr" --rpc-url "${RPC[$cid]}" 2>/dev/null || echo 0x)"
        [[ "$code" != "0x" && -n "$code" ]] || die "asset $sym on chain $cid: no contract code at $addr"
      fi
      TOKEN["$sym|$cid"]="$addr"
      ASSET_CHAINS[$sym]="${ASSET_CHAINS[$sym]:-} $cid"
      info "$sym @ $cid = $addr"
    done
  done
fi

# --- gate wiring (audit round 4: M-3 supportedChain, H-1 seal) --------------
#
# The deployer is the gate's owner until the multisig calls acceptOwnership()
# (two-step), so the wiring below is sent directly in BOTH profiles. What the
# deployer cannot send — a gate someone else already owns, a corridor on a gate
# that is already sealed — becomes a `governance_calls` entry for the owner.
CORRIDOR_CALLS='[]'
gate_owner()       { cast call "$1" 'owner()(address)' --rpc-url "$2" 2>/dev/null || echo ""; }
gate_owned_by_us() { [[ "$(gate_owner "$1" "$2" | tr 'A-F' 'a-f')" == "${DEPLOYER_ADDR,,}" ]]; }
gate_sealed()      { [[ "$(cast call "$1" 'isSealed()(bool)' --rpc-url "$2" 2>/dev/null || echo false)" == "true" ]]; }
chain_supported()  { [[ "$(cast call "$1" 'supportedChain(uint256)(bool)' "$3" --rpc-url "$2" 2>/dev/null || echo false)" == "true" ]]; }
gov_call() {  # chain_id to data note
  CORRIDOR_CALLS="$(jq -c --argjson c "$1" --arg to "$2" --arg d "$3" --arg n "$4" \
    '. + [{chain_id: $c, to: $to, data: $d, note: $n}]' <<<"$CORRIDOR_CALLS")"
}
peers_of() {  # chain_id -> every chain id its gate may `send` to
  local me="$1" c
  for c in "${CHAIN_IDS[@]}"; do [[ "$c" == "$me" ]] || echo "$c"; done
  [[ "$(j '.solana.enabled // false')" == "true" ]] && j '.solana.chain_id'
  for c in "${EXTRA_PEERS[@]:-}"; do [[ -n "$c" ]] && echo "$c"; done
}
# setLocalToken is WRITE-ONCE (in-flight claims bind only the debridgeId, so
# repointing a live corridor would release the wrong asset): an existing mapping
# is left alone. On a SEALED gate a new corridor needs scheduleGovernance first,
# so both calls are emitted for the owner, in order.
register_corridor() {  # chain_id debridgeId localToken note
  local cid="$1" did="$2" tok="$3" note="$4" cur data aid
  cur="$(cast call "${GATE[$cid]}" 'tokenOf(bytes32)(address)' "$did" --rpc-url "${RPC[$cid]}" 2>/dev/null || echo "")"
  if [[ -n "$cur" && ! "$cur" =~ ^0x0{40}$ ]]; then info "chain $cid: $note already registered ($cur)"; return; fi
  data="$(cast calldata 'setLocalToken(bytes32,address)' "$did" "$tok")"
  if gate_owned_by_us "${GATE[$cid]}" "${RPC[$cid]}" && ! gate_sealed "${GATE[$cid]}" "${RPC[$cid]}"; then
    csend "${GATE[$cid]}" 'setLocalToken(bytes32,address)' "$did" "$tok" --rpc-url "${RPC[$cid]}"
    info "chain $cid: $note  ($did)"
  else
    if gate_sealed "${GATE[$cid]}" "${RPC[$cid]}"; then
      aid="$(cast call "${GATE[$cid]}" 'setLocalTokenActionId(bytes32,address)(bytes32)' "$did" "$tok" --rpc-url "${RPC[$cid]}")"
      gov_call "$cid" "${GATE[$cid]}" "$(cast calldata 'scheduleGovernance(bytes32)' "$aid")" "1/2 schedule: $note (sealed gate; wait GOVERNANCE_DELAY, then 2/2 within SCHEDULE_GRACE)"
      gov_call "$cid" "${GATE[$cid]}" "$data" "2/2 $note"
    else
      gov_call "$cid" "${GATE[$cid]}" "$data" "$note"
    fi
    warn "chain $cid: $note NOT sent (owner $(gate_owner "${GATE[$cid]}" "${RPC[$cid]}"), sealed=$(gate_sealed "${GATE[$cid]}" "${RPC[$cid]}" && echo true || echo false)) — written to governance_calls"
  fi
}

say "listing destinations (setSupportedChain)"
for cid in "${CHAIN_IDS[@]}"; do
  for peer in $(peers_of "$cid"); do
    chain_supported "${GATE[$cid]}" "${RPC[$cid]}" "$peer" && continue
    data="$(cast calldata 'setSupportedChain(uint256,bool)' "$peer" true)"
    if gate_owned_by_us "${GATE[$cid]}" "${RPC[$cid]}"; then
      csend "${GATE[$cid]}" 'setSupportedChain(uint256,bool)' "$peer" true --rpc-url "${RPC[$cid]}"
      info "chain $cid: send -> $peer enabled"
    else
      gov_call "$cid" "${GATE[$cid]}" "$data" "setSupportedChain($peer, true)"
      warn "chain $cid: not the gate owner — setSupportedChain($peer) written to governance_calls"
    fi
  done
done

# --- corridors: setLocalToken (write-once, owner-only) ----------------------
for sym in "${SYMS[@]:-}"; do
  [[ -z "${sym:-}" ]] && continue
  [[ "$(j ".assets[] | select(.symbol == \"$sym\") | .register_corridors")" == "true" ]] || continue
  read -ra chs <<<"${ASSET_CHAINS[$sym]}"
  (( ${#chs[@]} >= 2 )) || { warn "$sym lives on <2 chains — nothing to bridge"; continue; }
  say "registering $sym corridors (${#chs[@]} chains, full mesh)"
  for cid in "${chs[@]}"; do
    for ocid in "${chs[@]}"; do
      [[ "$ocid" == "$cid" ]] && continue
      did="$(debridge_id "$ocid" "${TOKEN[$sym|$ocid]}")"
      register_corridor "$cid" "$did" "${TOKEN[$sym|$cid]}" "register $sym inbound from chain $ocid"
    done
  done
done

# --- test liquidity (local only) -------------------------------------------
for sym in "${SYMS[@]:-}"; do
  [[ -z "${sym:-}" ]] && continue
  [[ "$(j ".assets[] | select(.symbol == \"$sym\") | .test_liquidity.enabled")" == "true" ]] || continue
  dec="$(j ".assets[] | select(.symbol == \"$sym\") | .decimals")"
  to_dep="$(j ".assets[] | select(.symbol == \"$sym\") | .test_liquidity.mint_to_deployer")"
  to_gate="$(j ".assets[] | select(.symbol == \"$sym\") | .test_liquidity.mint_to_gate")"
  say "minting $sym test liquidity"
  for cid in ${ASSET_CHAINS[$sym]}; do
    tok="${TOKEN[$sym|$cid]}"
    [[ "$to_dep"  == "0" ]] || csend "$tok" 'mint(address,uint256)' "$DEPLOYER_ADDR" "$(scaled "$to_dep" "$dec")"  --rpc-url "${RPC[$cid]}"
    [[ "$to_gate" == "0" ]] || csend "$tok" 'mint(address,uint256)' "${GATE[$cid]}"  "$(scaled "$to_gate" "$dec")" --rpc-url "${RPC[$cid]}"
    info "chain $cid: $to_dep to deployer, $to_gate to gate"
  done
done

# --- SwapPools ---------------------------------------------------------------
#
# Two shapes, because they answer different questions:
#
#   pools[]  ONE pool per chain over the assets this config already deploys, so
#            every bridged token is also swappable on the chain it lands on. The
#            pool's `stable` is its pricing hub (priced at 1.0 by construction);
#            everything else is listed against it.
#   deploy   the demo script (contracts/script/DeploySwap.s.sol), which brings its
#            own unrestricted-mint tokens. Local bring-up only.
SWAP_POOL=""; SWAP_JSON='null'; SWAP_POOLS='[]'
DEV_BPS="$(jr '.swap.deviation_bps')"; DEV_BPS="${DEV_BPS:-1000}"
if [[ "$(j '.swap.enabled')" == "true" ]] && [[ "$(j '[.swap.pools[]?] | length')" != "0" ]]; then
  say "deploying SwapPools (one per chain, over the bridged assets)"
  for cid in $(j '.swap.pools[].chain_id'); do
    if [[ -z "${RPC[$cid]:-}" ]]; then
      jq -e --argjson c "$cid" '[.chains[] | select(.chain_id == $c and .enabled == false)] | length > 0' "$CONFIG" >/dev/null \
        && { info "pool on chain $cid skipped (chain disabled)"; continue; }
      die "swap.pools lists chain $cid, which is not in .chains"
    fi
    pjson=".swap.pools[] | select(.chain_id == $cid)"
    stable_sym="$(j "($pjson).stable")"
    stable_tok="${TOKEN[$stable_sym|$cid]:-}"
    [[ -n "$stable_tok" ]] || die "swap pool on chain $cid names stable '$stable_sym', which is not an asset on that chain"

    existing="$(jq -r "($pjson).pool // empty" "$CONFIG")"
    if [[ -z "$existing" ]] && ! $REDEPLOY && [[ -f "$OUT_FILE" ]]; then
      existing="$(jq -r --argjson c "$cid" '.swap_pools[]? | select(.chain_id == $c) | .pool // empty' "$OUT_FILE")"
    fi
    if [[ -n "$existing" ]]; then
      pool="$existing"; from_block="$(jq -r "($pjson).from_block // 0" "$CONFIG")"
      info "chain $cid reusing pool $pool"
    else
      from_block="${FLOOR[$cid]}"
      pool="$(fc src/SwapPool.sol:SwapPool "${RPC[$cid]}" --constructor-args "$stable_tok" "$DEV_BPS")"
      [[ "$pool" =~ ^0x ]] || die "SwapPool deploy failed on chain $cid"
      info "chain $cid pool=$pool (hub $stable_sym $stable_tok)"
    fi

    listed="$(jq -c -n --arg s "$stable_sym" --arg a "$stable_tok" '[{symbol:$s, address:$a, price:"1"}]')"
    for sym in $(j "($pjson).list[]?.symbol"); do
      tok="${TOKEN[$sym|$cid]:-}"
      [[ -n "$tok" ]] || die "swap pool on chain $cid lists '$sym', which is not an asset on that chain"
      price="$(j "($pjson).list[] | select(.symbol == \"$sym\") | .price")"
      # Prices are quoted in WHOLE units of the hub and scaled by PRICE_ONE
      # (1e18) here — the pool's own fixed-point base, independent of either
      # token's decimals.
      price_wei="$(scaled "$price" 18)"
      if [[ -n "$existing" ]]; then
        info "  (reused pool) leaving $sym listing alone"
      else
        csend "$pool" 'listToken(address,uint256)' "$tok" "$price_wei" --rpc-url "${RPC[$cid]}"
        info "  listed $sym at $price $stable_sym"
      fi
      listed="$(jq -c --arg s "$sym" --arg a "$tok" --arg p "$price" '. + [{symbol:$s, address:$a, price:$p}]' <<<"$listed")"
    done

    # Reserves. A pool with no reserve of the OUT token quotes fine and then
    # reverts on the swap, which reads as a broken UI rather than an unfunded
    # pool — so seed both sides.
    for sym in $(j "($pjson).seed | keys[]?"); do
      tok="${TOKEN[$sym|$cid]:-}"
      [[ -n "$tok" ]] || die "swap pool on chain $cid seeds '$sym', which is not an asset on that chain"
      whole="$(j "($pjson).seed.$sym")"
      dec="$(j ".assets[] | select(.symbol == \"$sym\") | .decimals")"
      amt="$(scaled "$whole" "$dec")"
      [[ "$(j "($pjson).mint_seed // false")" == "true" ]] && \
        csend "$tok" 'mint(address,uint256)' "$DEPLOYER_ADDR" "$amt" --rpc-url "${RPC[$cid]}"
      csend "$tok" 'approve(address,uint256)' "$pool" "$amt" --rpc-url "${RPC[$cid]}"
      csend "$pool" 'seedLiquidity(address,uint256)' "$tok" "$amt" --rpc-url "${RPC[$cid]}"
      info "  seeded $whole $sym"
    done

    SWAP_POOLS="$(jq -c --argjson c "$cid" --arg p "$pool" --argjson fb "$from_block" --argjson t "$listed" \
      '. + [{chain_id:$c, pool:$p, from_block:$fb, tokens:$t}]' <<<"$SWAP_POOLS")"
  done
elif [[ "$(j '.swap.enabled')" == "true" ]]; then
  SWAP_POOL="$(jr '.swap.pool')"; SWAP_CHAIN="$(jr '.swap.chain_id')"
  [[ -n "${RPC[$SWAP_CHAIN]:-}" ]] || die "swap.chain_id=$SWAP_CHAIN is not in .chains"
  if [[ "$(j '.swap.deploy')" == "true" ]]; then
    [[ "$PROFILE" == "local" ]] || die "swap.deploy=true is local-only (DeploySwap mints unrestricted test tokens)"
    say "deploying SwapPool on chain $SWAP_CHAIN"
    ( cd "$CONTRACTS" && forge script script/DeploySwap.s.sol:DeploySwap --rpc-url "${RPC[$SWAP_CHAIN]}" "${AUTH[@]}" --broadcast >/dev/null ) \
      || die "DeploySwap failed"
    # shellcheck disable=SC1091
    source "$CONTRACTS/fixtures/swap-deploy.env"   # SWAP_POOL, STABLE, WETH, TT
    info "pool=$SWAP_POOL stable=$STABLE weth=$WETH tt=$TT"
    # The pool's token list is discovered by replaying its TokenListed logs, so a
    # scan floor AFTER those listings reports a pool with zero tokens — and a
    # floor of 0 is worse: on a live chain it is a genesis-to-tip filter that
    # hosted RPCs reject outright. Pin it to the height captured before the deploy.
    SWAP_JSON="$(jq -n --argjson c "$SWAP_CHAIN" --arg p "$SWAP_POOL" --arg s "$STABLE" --arg w "$WETH" --arg t "$TT" \
      --argjson fb "${FLOOR[$SWAP_CHAIN]}" '{chain_id:$c, pool:$p, from_block:$fb, stable:$s, weth:$w, tt:$t}')"
  else
    [[ "$SWAP_POOL" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "swap.enabled with deploy=false needs swap.pool (or swap.pools)"
    # Reusing a pool: its listings predate this run, so keep whatever floor the
    # runtime config already carries rather than inventing one.
    SWAP_JSON="$(jq -n --argjson c "$SWAP_CHAIN" --arg p "$SWAP_POOL" '{chain_id:$c, pool:$p, from_block:null}')"
  fi
fi

# --- Solana leg: program, gate config, corridors, assets --------------------
#
# A different VM, a different toolchain and a different process. What ties it to
# the EVM gates is exactly two values: the SAME validator set and the SAME
# bridge_domain — the domain is hashed into every submissionId on both VMs, so a
# mismatch means no id ever agrees and nothing bridges (loudly, not silently).
SOLANA_JSON='null'
if [[ "$(j '.solana.enabled // false')" == "true" ]]; then
  SOL_CHAIN_ID="$(j '.solana.chain_id')"
  SOL_RPC="$(j '.solana.rpc')"
  for cid in "${CHAIN_IDS[@]}"; do
    [[ "$cid" == "$SOL_CHAIN_ID" ]] && die "solana.chain_id $SOL_CHAIN_ID collides with an EVM chain in .chains"
  done

  # The solana CLI is not usually on PATH; fall back to the standard install dir.
  command -v solana >/dev/null 2>&1 || export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
  need solana "the Solana program deploy"

  GATE_ADMIN="$(jr '.solana.gate_admin_bin')"; GATE_ADMIN="${GATE_ADMIN:-crates/solana-relayer/target/debug/gate-admin}"
  [[ "$GATE_ADMIN" = /* ]] || GATE_ADMIN="$ROOT/$GATE_ADMIN"
  if [[ ! -x "$GATE_ADMIN" ]]; then
    [[ "$(j '.solana.build')" == "true" ]] || die "no gate-admin at $GATE_ADMIN (set solana.build = true, or point solana.gate_admin_bin at your build)"
    # Its own cargo project: solana-client pins zeroize <1.4, alloy needs ^1.5,
    # so no EVM-side crate can host this tool.
    ( cd "$ROOT" && cargo build --manifest-path crates/solana-relayer/Cargo.toml --bin gate-admin ) || die "building gate-admin failed"
  fi

  PAYER="$(j '.solana.payer_keypair')"; [[ "$PAYER" = /* ]] || PAYER="$ROOT/$PAYER"
  [[ -f "$PAYER" ]] || die "solana.payer_keypair not found: $PAYER"
  PAYER_PUBKEY="$(solana address --keypair "$PAYER")"

  say "solana leg ($(j '.solana.cluster'), chain id $SOL_CHAIN_ID)"
  info "payer   : $PAYER_PUBKEY  ($(solana balance --keypair "$PAYER" --url "$SOL_RPC" 2>/dev/null || echo 'balance unknown'))"

  # --- program ---
  if [[ "$(j '.solana.program.deploy')" == "true" ]]; then
    so="$(j '.solana.program.so_path')"; [[ "$so" = /* ]] || so="$ROOT/$so"
    [[ -f "$so" ]] || die "program binary not found: $so (build it with scripts/testing/build-solana.sh)"
    out="$RUN_LOG_DIR/solana-deploy.json"
    # --use-rpc sends the write transactions over JSON-RPC instead of straight to
    # the leader's TPU. The TPU path needs gossip reachability, which a hosted
    # endpoint or a containerised validator does not give you — it fails with
    # "Failed find any cluster node info for upcoming leaders" after a 20s stall.
    rpc_flag=(); [[ "$(j '.solana.program.use_rpc')" != "false" ]] && rpc_flag=(--use-rpc)
    solana program deploy "$so" --url "$SOL_RPC" --keypair "$PAYER" "${rpc_flag[@]}" --output json > "$out" \
      || { cat "$out"; die "solana program deploy failed"; }
    SOL_PROGRAM="$(jq -r '.programId' "$out")"
    info "program : $SOL_PROGRAM (deployed)"
  else
    SOL_PROGRAM="$(jr '.solana.program.program_id')"
    [[ -n "$SOL_PROGRAM" ]] || die "solana.program.deploy = false needs solana.program.program_id"
    info "program : $SOL_PROGRAM (existing)"
  fi

  ga() { "$GATE_ADMIN" --rpc "$SOL_RPC" --keypair "$PAYER" --program "$SOL_PROGRAM" "$@"; }
  # A freshly deployed program is not instantly visible at the commitment the
  # admin client reads at: the first instruction after a deploy fails with
  # "invalid account data" while the ProgramData account is still settling.
  # Retry rather than make every operator hit that once and guess.
  ga_retry() {
    local out attempt
    for attempt in 1 2 3 4 5; do
      if out="$(ga "$@" 2>&1)"; then return 0; fi
      sleep 3
    done
    echo "$out" >&2
    return 1
  }

  # Wait for the program account itself before touching it at all.
  for _ in $(seq 1 20); do
    solana program show "$SOL_PROGRAM" --url "$SOL_RPC" >/dev/null 2>&1 && break
    sleep 2
  done

  # --- production policy for the Solana leg (M-12) ---------------------------
  #
  # `init` must be signed by the program's UPGRADE AUTHORITY, and the signer
  # becomes the gate owner FOR GOOD: there is no ownership-transfer instruction
  # on this side (unlike the EVM gate's two-step handover). Owner actions that
  # widen trust — `set-validator` (add), `set-threshold` (lower) — now sit behind
  # a 48h `schedule-governance` (H-2), but the owner key itself is whatever paid
  # for `init`. So production requires that key to be NAMED in the config as the
  # multisig-controlled owner (`solana.init.owner`), to MATCH the payer, and to
  # come with a guardian; anything else is a hot-key gate and is refused.
  guardian="$(jr '.solana.init.guardian')"
  SOL_OWNER="$(jr '.solana.init.owner')"
  if [[ "$PROFILE" == "production" ]]; then
    [[ -n "$guardian" ]]  || die "production needs solana.init.guardian — the Solana gate's stop button (pause-only, may be hot)"
    [[ -n "$SOL_OWNER" ]] || die "production needs solana.init.owner: the multisig-controlled key that will own the Solana gate. It MUST be the key in solana.payer_keypair — the init signer is the owner and cannot be changed later"
    [[ "$SOL_OWNER" == "$PAYER_PUBKEY" ]] || die "solana.init.owner ($SOL_OWNER) is not the payer ($PAYER_PUBKEY). The Solana gate has no ownership transfer: whoever signs init owns it. Point solana.payer_keypair at the multisig-controlled key, or hold the deploy"
    [[ "$guardian" != "$SOL_OWNER" ]] || die "solana.init.guardian must differ from solana.init.owner"
  elif [[ -z "$SOL_OWNER" ]]; then
    warn "solana.init.owner unset: the Solana gate owner will be the deploy payer $PAYER_PUBKEY (fine on devnet; production refuses this)"
  fi

  # --- init (idempotent: the program refuses a second init, so read first) ---
  show="$(ga show 2>&1)" || { echo "$show"; die "gate-admin show failed"; }
  if grep -q "NOT INITIALIZED" <<<"$show"; then
    [[ "$(j '.solana.init.run')" == "true" ]] || die "the gate program is not initialized and solana.init.run = false"
    vargs=(); for v in "${VALIDATORS[@]}"; do vargs+=(--validator "$v"); done
    ga_retry init --chain-id "$SOL_CHAIN_ID" --threshold "$THRESHOLD" "${vargs[@]}" \
       --bridge-domain "$BRIDGE_DOMAIN" \
       --max-validators "$(j '.solana.init.max_validators')" \
       --max-corridors "$(j '.solana.init.max_corridors')" \
       ${guardian:+--guardian "$guardian"} >/dev/null || die "gate-admin init failed"
    info "init    : $THRESHOLD-of-${#VALIDATORS[@]}, owner $PAYER_PUBKEY${guardian:+, guardian $guardian}"
    show="$(ga show 2>&1)"
  else
    info "init    : already initialized (leaving it alone)"
  fi

  # Whoever `show` reports as owner is who governs this gate, for its lifetime.
  # A program from an earlier run that some other key initialised is exactly the
  # case this catches: nothing here can fix it, so say so before anything else
  # is registered against it.
  on_chain_owner="$(sed -n 's/^  owner *: *//p' <<<"$show" | head -1)"
  if [[ -n "$SOL_OWNER" && -n "$on_chain_owner" && "$on_chain_owner" != "$SOL_OWNER" ]]; then
    msg="the Solana gate's on-chain owner is $on_chain_owner, but solana.init.owner says $SOL_OWNER — there is no owner-transfer instruction, so that key governs validators/threshold (48h schedule) and pause (instant) for good"
    if [[ "$PROFILE" == "production" ]]; then die "$msg. Deploy a fresh program with the right payer."; else warn "$msg"; fi
  fi
  # Post-deploy governance on this gate (validator add / threshold lower):
  #   gate-admin schedule-governance <action-id>   # the id set-validator/set-threshold print
  #   (wait GOVERNANCE_DELAY, 48h)  gate-admin set-validator … / set-threshold …
  #   gate-admin governance-status | cancel-governance <action-id>   (guardian may cancel)
  # And move the program's UPGRADE AUTHORITY behind the same multisig/timelock:
  #   solana program set-upgrade-authority <program> --new-upgrade-authority <multisig>
  if [[ "$PROFILE" == "production" ]]; then
    upgrade_auth="$(solana program show "$SOL_PROGRAM" --url "$SOL_RPC" 2>/dev/null | sed -n 's/^Authority: *//p' | head -1)"
    [[ -z "$upgrade_auth" || "$upgrade_auth" == "$PAYER_PUBKEY" ]] \
      && warn "the program's upgrade authority is the deploy payer ($upgrade_auth). The program cannot delay its own upgrade: move it behind the multisig/timelock — solana program set-upgrade-authority $SOL_PROGRAM --new-upgrade-authority <multisig>"
  fi

  # An existing program from an EARLIER generation is the failure this catches:
  # its domain is baked in at init and can never be mutated, so it would sign
  # ids the EVM gates of this mesh reject — and the only symptom is transfers
  # that never claim.
  on_chain_domain="$(grep -oE 'bridge domain: 0x[0-9a-fA-F]{64}' <<<"$show" | grep -oE '0x[0-9a-fA-F]{64}' || true)"
  if [[ -n "$on_chain_domain" && "${on_chain_domain,,}" != "${BRIDGE_DOMAIN,,}" ]]; then
    die "the Solana gate's bridge_domain is $on_chain_domain but this deployment's is $BRIDGE_DOMAIN — that program belongs to a different generation and no submissionId would ever agree. Deploy a fresh program, or pin gate.bridge_domain to the on-chain value."
  fi

  # --- corridors: every EVM chain this mesh can send to ---
  SOL_CORRIDORS='[]'
  if [[ "$(j '.solana.register_corridors')" == "true" ]]; then
    for cid in "${CHAIN_IDS[@]}"; do
      # `send` refuses any chain_id_to that governance has not registered here
      # (H-3), and the instruction is idempotent, so re-running is free.
      ga_retry register-corridor --chain-id-to "$cid" >/dev/null || die "register-corridor $cid failed"
      SOL_CORRIDORS="$(jq -c --argjson c "$cid" '. + [$c]' <<<"$SOL_CORRIDORS")"
      info "corridor: -> chain $cid"
    done
  fi

  # --- assets: bind each corridor's debridgeId to the SPL mint + vault ---
  #
  # One registration per SOURCE chain, exactly as the EVM side needs one
  # setLocalToken per corridor: a claim commits only to the debridgeId, and the
  # id differs per origin chain. The mint and vault are supplied, never created
  # here — the vault must already be an SPL account owned by the program's
  # vault_authority PDA with no delegate or close authority.
  SOL_ASSETS='[]'
  for sym in $(j '.solana.assets[]?.symbol'); do
    mint="$(jr ".solana.assets[] | select(.symbol == \"$sym\") | .mint")"
    vault="$(jr ".solana.assets[] | select(.symbol == \"$sym\") | .vault")"
    [[ -n "$mint" && -n "$vault" ]] || { warn "solana asset $sym has no mint/vault — skipped (create them first, then re-run)"; continue; }
    from="$(jq -c ".solana.assets[] | select(.symbol == \"$sym\") | .from_chains" "$CONFIG")"
    ids='[]'
    for cid in ${ASSET_CHAINS[$sym]:-}; do
      if [[ "$from" != '"all"' ]]; then
        jq -e --argjson c "$cid" 'index($c) != null' <<<"$from" >/dev/null || continue
      fi
      did="$(debridge_id "$cid" "${TOKEN[$sym|$cid]}")"
      ga_retry register-asset --debridge-id "$did" --mint "$mint" --vault "$vault" >/dev/null \
        || die "register-asset $sym (from chain $cid) failed"
      info "asset   : $sym from chain $cid -> mint $mint"
      ids="$(jq -c --arg d "$did" --argjson c "$cid" '. + [{from_chain: $c, debridge_id: $d}]' <<<"$ids")"
    done
    # A Solana-NATIVE asset has no EVM-derived id, so the operator names one; it
    # is then registered on the EVM gates the same way any inbound corridor is.
    native_did="$(jr ".solana.assets[] | select(.symbol == \"$sym\") | .debridge_id")"
    if [[ -n "$native_did" ]]; then
      ga_retry register-asset --debridge-id "$native_did" --mint "$mint" --vault "$vault" >/dev/null \
        || die "register-asset $sym (solana-native id) failed"
      for cid in ${ASSET_CHAINS[$sym]:-}; do
        register_corridor "$cid" "$native_did" "${TOKEN[$sym|$cid]}" "register $sym inbound from Solana"
      done
      ids="$(jq -c --arg d "$native_did" '. + [{from_chain: "solana", debridge_id: $d}]' <<<"$ids")"
    fi
    SOL_ASSETS="$(jq -c --arg s "$sym" --arg m "$mint" --arg v "$vault" --argjson ids "$ids" \
      '. + [{symbol: $s, mint: $m, vault: $v, registrations: $ids}]' <<<"$SOL_ASSETS")"
  done

  # --- the Solana swap pool (a SEPARATE program from the gate) ---------------
  #
  # Separate on purpose, exactly as `SwapPool.sol` is a separate contract from
  # `Gate.sol`: the gate holds bridge liquidity, and a bug in swap pricing must
  # not be able to reach it.
  SOL_SWAP_JSON='null'
  if [[ "$(j '.solana.swap.enabled // false')" == "true" ]]; then
    SWAP_ADMIN="$(jr '.solana.swap.swap_admin_bin')"
    SWAP_ADMIN="${SWAP_ADMIN:-crates/solana-relayer/target/debug/swap-admin}"
    [[ "$SWAP_ADMIN" = /* ]] || SWAP_ADMIN="$ROOT/$SWAP_ADMIN"
    [[ -x "$SWAP_ADMIN" ]] || die "no swap-admin at $SWAP_ADMIN (cargo build --manifest-path crates/solana-relayer/Cargo.toml --bin swap-admin)"

    say "solana swap pool"
    if [[ "$(j '.solana.swap.deploy')" == "true" ]]; then
      so="$(j '.solana.swap.so_path')"; [[ "$so" = /* ]] || so="$ROOT/$so"
      [[ -f "$so" ]] || die "swap program binary not found: $so (bash scripts/testing/build-solana.sh swap)"
      out="$RUN_LOG_DIR/solana-swap-deploy.json"
      rpc_flag=(); [[ "$(j '.solana.swap.use_rpc')" != "false" ]] && rpc_flag=(--use-rpc)
      solana program deploy "$so" --url "$SOL_RPC" --keypair "$PAYER" "${rpc_flag[@]}" --output json > "$out" \
        || { cat "$out"; die "solana swap program deploy failed"; }
      SWAP_PROGRAM="$(jq -r '.programId' "$out")"
      info "program : $SWAP_PROGRAM (deployed)"
    else
      SWAP_PROGRAM="$(jr '.solana.swap.program_id')"
      [[ -n "$SWAP_PROGRAM" ]] || die "solana.swap.deploy = false needs solana.swap.program_id"
      info "program : $SWAP_PROGRAM (existing)"
    fi

    sa() { "$SWAP_ADMIN" --rpc "$SOL_RPC" --keypair "$PAYER" --program "$SWAP_PROGRAM" "$@"; }
    sa_retry() {
      local out attempt
      for attempt in 1 2 3 4 5; do
        if out="$(sa "$@" 2>&1)"; then return 0; fi
        sleep 3
      done
      echo "$out" >&2
      return 1
    }
    for _ in $(seq 1 20); do
      solana program show "$SWAP_PROGRAM" --url "$SOL_RPC" >/dev/null 2>&1 && break
      sleep 2
    done

    hub_sym="$(j '.solana.swap.hub')"
    hub_mint="$(jr ".solana.assets[] | select(.symbol == \"$hub_sym\") | .mint")"
    hub_vault="$(jr ".solana.assets[] | select(.symbol == \"$hub_sym\") | .swap_vault")"
    [[ -n "$hub_mint" && -n "$hub_vault" ]] \
      || die "solana.swap.hub is '$hub_sym', but that asset has no mint/swap_vault"

    # Idempotent: an initialized pool is left alone, the same way the gate is.
    if sa show 2>&1 | grep -q "NOT INITIALIZED"; then
      sa_retry init --hub-mint "$hub_mint" --hub-vault "$hub_vault" \
        --fee-bps "$(j '.solana.swap.fee_bps')" \
        --deviation-bps "$(j '.solana.swap.deviation_bps')" \
        --min-price-interval "$(j '.solana.swap.min_price_interval')" >/dev/null \
        || die "swap-admin init failed"
      info "init    : hub $hub_sym at 1.0, fee $(j '.solana.swap.fee_bps') bps"
    else
      info "init    : already initialized (leaving it alone)"
    fi

    SOL_SWAP_TOKENS="$(jq -c -n --arg s "$hub_sym" --arg m "$hub_mint" '[{symbol:$s, mint:$m, price:"1"}]')"
    for sym in $(j '.solana.swap.list[]?.symbol'); do
      mint="$(jr ".solana.assets[] | select(.symbol == \"$sym\") | .mint")"
      vault="$(jr ".solana.assets[] | select(.symbol == \"$sym\") | .swap_vault")"
      [[ -n "$mint" && -n "$vault" ]] || die "swap lists '$sym', which has no mint/swap_vault in solana.assets"
      price="$(j ".solana.swap.list[] | select(.symbol == \"$sym\") | .price")"
      # Prices are quoted in WHOLE hub units and scaled by PRICE_ONE (1e18) —
      # the pool's fixed point, independent of either mint's decimals.
      price_scaled="$(scaled "$price" 18)"
      if sa show --mint "$mint" 2>&1 | grep -q "NOT LISTED"; then
        sa_retry list-token --mint "$mint" --vault "$vault" --price "$price_scaled" >/dev/null \
          || die "swap-admin list-token $sym failed"
        info "listed  : $sym at $price $hub_sym"
      else
        info "listed  : $sym already listed (price left alone)"
      fi
      SOL_SWAP_TOKENS="$(jq -c --arg s "$sym" --arg m "$mint" --arg p "$price" \
        '. + [{symbol:$s, mint:$m, price:$p}]' <<<"$SOL_SWAP_TOKENS")"
    done

    # Reserves. A pool with no reserve of the OUT token quotes fine and then
    # fails the swap on its own lock, which reads as a broken UI.
    for sym in $(j '.solana.swap.seed | keys[]?'); do
      mint="$(jr ".solana.assets[] | select(.symbol == \"$sym\") | .mint")"
      from="$(jr ".solana.assets[] | select(.symbol == \"$sym\") | .seed_from")"
      amount="$(j ".solana.swap.seed.$sym")"
      if [[ -z "$from" ]]; then
        warn "no seed_from token account for $sym — reserve left as is"
        continue
      fi
      sa_retry seed --mint "$mint" --amount "$amount" --from "$from" >/dev/null \
        || die "swap-admin seed $sym failed"
      info "seeded  : $amount $sym"
    done

    SOL_SWAP_JSON="$(jq -n --arg prog "$SWAP_PROGRAM" --argjson tokens "$SOL_SWAP_TOKENS" \
      '{program_id:$prog, tokens:$tokens}')"
  fi

  SOLANA_JSON="$(jq -n --argjson cid "$SOL_CHAIN_ID" --arg rpc "$SOL_RPC" --arg prog "$SOL_PROGRAM" \
    --arg owner "$PAYER_PUBKEY" --argjson cor "$SOL_CORRIDORS" --argjson assets "$SOL_ASSETS" \
    --argjson swap "$SOL_SWAP_JSON" \
    '{chain_id:$cid, rpc:$rpc, program_id:$prog, owner:$owner, corridors:$cor, assets:$assets,
      swap:$swap}')"
fi

# --- seal (H-1) — the LAST wiring step ---------------------------------------
#
# Irreversible. Afterwards every NEW corridor is scheduleGovernance + 48h, which
# is what stops a stolen owner key from registering a worthless token behind a
# real corridor and draining the pot in one block. Sits after the Solana leg
# because that leg registers the Solana-native return corridors on the EVM gates.
if [[ "$SEAL" == "true" ]]; then
  say "sealing gates"
  for cid in "${CHAIN_IDS[@]}"; do
    if gate_sealed "${GATE[$cid]}" "${RPC[$cid]}"; then info "chain $cid: already sealed"; continue; fi
    if gate_owned_by_us "${GATE[$cid]}" "${RPC[$cid]}"; then
      csend "${GATE[$cid]}" 'seal()' --rpc-url "${RPC[$cid]}"
      info "chain $cid: sealed"
    else
      gov_call "$cid" "${GATE[$cid]}" "$(cast calldata 'seal()')" "seal() — LAST, after every corridor above"
      warn "chain $cid: not the gate owner — seal() written to governance_calls"
    fi
  done
else
  warn "gate.seal = false: the gates stay in their setup phase (setLocalToken instant). Dev only."
fi

# --- assert the wiring -------------------------------------------------------
# Production: hard. A gate that is unsealed or missing a peer must not be
# reported as deployed — that is precisely the state the multisig would fund.
say "verifying gate wiring"
wiring_ok=true
for cid in "${CHAIN_IDS[@]}"; do
  for peer in $(peers_of "$cid"); do
    chain_supported "${GATE[$cid]}" "${RPC[$cid]}" "$peer" \
      || { wiring_ok=false; warn "chain $cid gate ${GATE[$cid]}: supportedChain($peer) is false"; }
  done
  if [[ "$SEAL" == "true" ]] && ! gate_sealed "${GATE[$cid]}" "${RPC[$cid]}"; then
    wiring_ok=false; warn "chain $cid gate ${GATE[$cid]}: NOT sealed"
  fi
  info "chain $cid: owner $(gate_owner "${GATE[$cid]}" "${RPC[$cid]}") sealed=$(gate_sealed "${GATE[$cid]}" "${RPC[$cid]}" && echo true || echo false)"
done
if ! $wiring_ok; then
  if [[ "$PROFILE" == "production" ]]; then
    # Still write the record first, so the governance_calls are not lost.
    WIRING_FAILED=true
  else
    warn "wiring incomplete — see governance_calls in $OUT_FILE"
  fi
fi

# --- record ----------------------------------------------------------------
say "writing $OUT_FILE"
mkdir -p "$(dirname "$OUT_FILE")"
chains_json='[]'
for cid in "${CHAIN_IDS[@]}"; do
  toks='{}'
  for sym in "${SYMS[@]:-}"; do
    [[ -n "${TOKEN[$sym|$cid]:-}" ]] || continue
    toks="$(jq -c --arg s "$sym" --arg a "${TOKEN[$sym|$cid]}" '. + {($s): $a}' <<<"$toks")"
  done
  chains_json="$(jq -c --argjson cid "$cid" --arg name "${CNAME[$cid]}" --arg rpc "${RPC[$cid]}" \
    --arg gate "${GATE[$cid]}" --arg impl "${IMPL[$cid]:-}" --argjson floor "${FLOOR[$cid]}" --argjson toks "$toks" \
    '. + [{chain_id:$cid, name:$name, rpc_url:$rpc, gate:$gate, gate_implementation:(if $impl == "" then null else $impl end), deploy_block:$floor, tokens:$toks}]' \
    <<<"$chains_json")"
done
jq -n --arg name "$NAME" --arg profile "$PROFILE" --arg domain "$BRIDGE_DOMAIN" \
      --arg deployer "$DEPLOYER_ADDR" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --argjson vals "$(printf '%s\n' "${VALIDATORS[@]}" | jq -R . | jq -s .)" \
      --argjson th "$THRESHOLD" --argjson chains "$chains_json" --argjson swap "$SWAP_JSON" \
      --argjson gov "$CORRIDOR_CALLS" --argjson solana "$SOLANA_JSON" --argjson pools "$SWAP_POOLS" \
  '{name:$name, profile:$profile, deployed_at:$at, deployer:$deployer, bridge_domain:$domain,
    validators:$vals, threshold:$th, chains:$chains, swap:$swap, swap_pools:$pools,
    solana:$solana, governance_calls:$gov}' > "$OUT_FILE"

# --- patch the runtime config ----------------------------------------------
if $UPDATE_CFG && [[ -n "$BRIDGE_CFG" ]]; then
  [[ -f "$BRIDGE_CFG" ]] || die "output.update_bridge_config points at a missing file: $BRIDGE_CFG"
  say "updating $BRIDGE_CFG"
  tmp="$(mktemp)"
  jq --slurpfile d "$OUT_FILE" '
    ($d[0]) as $dep
    | .threshold = $dep.threshold
    | .chains = [ .chains[] as $c
        | ($dep.chains[] | select(.chain_id == $c.chain_id)) as $x
        | if $x == null then $c else
            $c + { gate: $x.gate,
                   start_block: $x.deploy_block,
                   tokens: ($x.tokens | to_entries | map({symbol: .key, address: .value})) }
          end ]
    | if $dep.solana != null
      then .solana = ((.solana // {}) + { enabled: true, chain_id: $dep.solana.chain_id,
                                          rpc: $dep.solana.rpc, program_id: $dep.solana.program_id })
         | .solana.tokens = [ $dep.solana.assets[] | {symbol, mint} ]
         # The Solana pool is served through the same `graphql.swaps` list as the
         # EVM ones; the API tells the two apart by the address form (base58 vs
         # 0x), so nothing else in the config has to say which VM it is.
         | if $dep.solana.swap != null
           then .solana.swap = { program_id: $dep.solana.swap.program_id,
                                 tokens: $dep.solana.swap.tokens }
              | .graphql.swaps = ((.graphql.swaps // []) | map(select(.chain_id != $dep.solana.chain_id)))
                                 + [{ chain_id: $dep.solana.chain_id,
                                      pool: $dep.solana.swap.program_id,
                                      from_block: 0 }]
           else . end
      else . end
    | if ($dep.swap_pools | length) > 0
      # Replace only the entries this deployment covers. A wholesale assignment
      # drops pools it knows nothing about — notably the Solana one, which is
      # registered by the solana branch above and would silently vanish here.
      then .graphql.swaps =
             ((.graphql.swaps // [])
              | map(select(.chain_id as $c | ($dep.swap_pools | map(.chain_id) | index($c)) == null)))
             + [ $dep.swap_pools[] | {chain_id, pool, from_block} ]
         | .graphql.swap = null
         | .chains = [ .chains[] as $c
             | ($dep.swap_pools[] | select(.chain_id == $c.chain_id)) as $sp
             | if $sp == null then $c else $c + {pool: $sp.pool} end ]
      elif $dep.swap != null
      then .graphql.swap = { enabled: true, chain_id: $dep.swap.chain_id, pool: $dep.swap.pool,
                             from_block: ($dep.swap.from_block // .graphql.swap.from_block // 0) }
         | .chains = [ .chains[] | if .chain_id == $dep.swap.chain_id then .pool = $dep.swap.pool else . end ]
      else . end
  ' "$BRIDGE_CFG" > "$tmp" && mv "$tmp" "$BRIDGE_CFG"
  info "gate + token + start_block addresses written into the runtime config"
fi

if [[ "${WIRING_FAILED:-false}" == "true" ]]; then
  die "production gate wiring is incomplete (unsealed gate or missing supportedChain — see above). The record and governance_calls are in $OUT_FILE; do NOT fund these gates until every check passes."
fi

say "done"
info "addresses : $OUT_FILE"
info "domain    : $BRIDGE_DOMAIN  (every gate in this mesh generation shares it)"
[[ "$PROFILE" == "production" ]] && {
  info "next      : the multisig $OWNER must call acceptOwnership() on every gate"
  [[ "$CORRIDOR_CALLS" != "[]" ]] && info "            then execute .governance_calls from $OUT_FILE (in order)"
}
info "run       : bash scripts/bridge-from-json.sh ${BRIDGE_CFG:-config/bridge.config.json}"
