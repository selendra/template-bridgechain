#!/usr/bin/env bash
# bridge-from-json.sh — run the bridge mesh (N chains, M validators, K keepers)
# from a single JSON config.
#
#   bash scripts/bridge-from-json.sh [config.json]                  # generate + start
#   bash scripts/bridge-from-json.sh [config.json] --generate-only  # just write the TOMLs
#   bash scripts/bridge-from-json.sh [config.json] --stop           # tear the stack down
#   bash scripts/bridge-from-json.sh [config.json] --status         # what is alive
#   bash scripts/bridge-from-json.sh [config.json] --compose        # emit a docker stack
#
# Default config: config/bridge.config.json (field reference: config/README.md).
# Every chain listed bridges to every other one (full mesh, both directions);
# each validator watches all the chains it is given as sources and attests
# refunds on all destinations, and each keeper delivers claims on its targets.
#
# The generated validator/keeper/indexer TOMLs land in runtime.run_dir, so you
# can inspect exactly what each process was handed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="config/bridge.config.json"
MODE=start

for arg in "$@"; do
  case "$arg" in
    --generate-only) MODE=generate ;;
    --compose)       MODE=compose ;;
    --stop)          MODE=stop ;;
    --status)        MODE=status ;;
    -h|--help)       sed -n '2,18p' "$0"; exit 0 ;;
    -*)              echo "unknown flag: $arg" >&2; exit 1 ;;
    *)               CONFIG="$arg" ;;
  esac
done
[[ "$CONFIG" = /* ]] || CONFIG="$ROOT/$CONFIG"
[[ -f "$CONFIG" ]] || { echo "config not found: $CONFIG" >&2; exit 1; }

say()  { printf '\n\033[1;36m=== %s ===\033[0m\n' "$*"; }
info() { printf '  %s\n' "$*"; }
warn() { printf '\033[1;33m  ! %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' not found on PATH (needed for: $2)"; }
need jq "reading the JSON config"

j()  { jq -r "$1" "$CONFIG"; }
jr() { jq -r "$1 // empty" "$CONFIG"; }

NAME="$(j '.name')"
# Not /tmp (M-11): the generated TOMLs carry private keys and the validator
# cursors live here; systemd-tmpfiles sweeps /tmp daily. Same root as run.sh.
RUN_DIR="$(jr '.runtime.run_dir')"
RUN_DIR="${RUN_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/selendra-bridge/$NAME}"
[[ "$RUN_DIR" = /* ]] || RUN_DIR="$ROOT/$RUN_DIR"
BIN_DIR="$(jr '.runtime.bin_dir')"; BIN_DIR="${BIN_DIR:-target/debug}"
[[ "$BIN_DIR" = /* ]] || BIN_DIR="$ROOT/$BIN_DIR"
LOG_LEVEL="$(jr '.runtime.log_level')"; LOG_LEVEL="${LOG_LEVEL:-info}"
PIDS="$RUN_DIR/pids"

pg_enabled() { [[ "$(j '.database.docker.enabled')" == "true" ]]; }
PG_NAME="$(jr '.database.docker.container')"; PG_NAME="${PG_NAME:-bridge-json-pg}"

# --- stop / status ---------------------------------------------------------
if [[ "$MODE" == "stop" ]]; then
  say "stopping $NAME"
  if [[ -f "$PIDS" ]]; then
    # pid first, then a match pattern: `setsid` may fork, in which case the
    # recorded pid is the wrapper and the service itself outlives the kill.
    while IFS=$'\t' read -r pid name pattern; do
      [[ -n "${pid:-}" ]] || continue
      kill "$pid" 2>/dev/null || true
      [[ -n "${pattern:-}" ]] && pkill -f -- "$pattern" 2>/dev/null || true
      info "stopped $name"
    done < "$PIDS"
    sleep 1
    while IFS=$'\t' read -r pid _ pattern; do
      kill -9 "$pid" 2>/dev/null || true
      [[ -n "${pattern:-}" ]] && pkill -9 -f -- "$pattern" 2>/dev/null || true
    done < "$PIDS"
    rm -f "$PIDS"
  else
    info "no pid file at $PIDS"
  fi
  # The Postgres VOLUME is kept: it holds signatures, transfer history and the
  # indexer cursors. Validators resume from file cursors and never re-sign blocks
  # they already scanned, so wiping it strands anything in flight. Remove it by
  # hand (`docker volume rm …`) only when a clean slate is really what you want.
  if pg_enabled && command -v docker >/dev/null 2>&1; then
    docker rm -f "$PG_NAME" >/dev/null 2>&1 && info "removed container $PG_NAME (volume kept)" || true
  fi
  exit 0
fi
if [[ "$MODE" == "status" ]]; then
  say "$NAME"
  [[ -f "$PIDS" ]] || { info "not running (no $PIDS)"; exit 0; }
  while IFS=$'\t' read -r pid name pattern; do
    if kill -0 "$pid" 2>/dev/null || pgrep -f -- "$pattern" >/dev/null 2>&1
    then printf '  %-22s up   (pid %s)\n' "$name" "$pid"
    else printf '  %-22s DOWN (pid %s)\n' "$name" "$pid"; fi
  done < "$PIDS"
  exit 0
fi

# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------
rand_token() { openssl rand -hex 32 2>/dev/null || head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

say "validating $CONFIG"
# per-chain field with fallback to .defaults
cf() { # $1 chain_id, $2 field
  local v; v="$(jq -r ".chains[] | select(.chain_id == $1) | .$2 // empty" "$CONFIG")"
  [[ -n "$v" && "$v" != "null" ]] && { echo "$v"; return; }
  jq -r ".defaults.$2 // empty" "$CONFIG"
}
cbool() { # $1 chain_id, $2 field — false is a real value, so `// empty` is wrong here
  local v; v="$(jq -r ".chains[] | select(.chain_id == $1) | .$2" "$CONFIG")"
  [[ "$v" == "null" ]] && v="$(jq -r ".defaults.$2 // false" "$CONFIG")"
  echo "$v"
}
# "all" or [id, id] -> chain ids, intersected with a role (source/destination)
select_chains() { # $1 jq path to the selector, $2 role field
  local sel; sel="$(jq -c "$1" "$CONFIG")"
  for cid in "${CHAIN_IDS[@]}"; do
    [[ "$(cbool "$cid" "$2")" == "false" ]] && continue
    if [[ "$sel" == '"all"' || "$sel" == "null" ]]; then echo "$cid"
    else jq -e --argjson c "$cid" 'index($c) != null' <<<"$sel" >/dev/null && echo "$cid"; fi
  done
}
# [signer] / [keeper] body from a JSON signer object
emit_signer() { # $1 jq path
  local any=false k
  for k in private_key private_key_env keystore keystore_password keystore_password_env keystore_password_file; do
    local v; v="$(jq -r "$1.$k // empty" "$CONFIG")"
    [[ -n "$v" ]] || continue
    echo "$k = \"$v\""; any=true
  done
  $any || die "signer at $1 has no key source (private_key / private_key_env / keystore)"
}

THRESHOLD="$(j '.threshold')"
mapfile -t CHAIN_IDS < <(j '.chains[] | select(.enabled != false) | .chain_id')
(( ${#CHAIN_IDS[@]} >= 1 )) || die ".chains is empty"
(( ${#CHAIN_IDS[@]} >= 2 )) || warn "only one chain configured — nothing to bridge to"
[[ "$(printf '%s\n' "${CHAIN_IDS[@]}" | sort | uniq -d)" == "" ]] || die "duplicate chain_id in .chains"

dup_names="$(j '[.validators[]?.name] + [.keepers[]?.name] | group_by(.) | map(select(length > 1) | .[0]) | join(", ")')"
[[ -z "$dup_names" ]] || die "duplicate validator/keeper name: $dup_names (names key the generated configs)"

VAL_COUNT="$(j '[.validators[] | select(.enabled != false)] | length')"
(( VAL_COUNT >= 1 )) || die "no enabled validators"
(( THRESHOLD >= 1 && THRESHOLD <= VAL_COUNT )) || die "threshold ($THRESHOLD) must be 1..$VAL_COUNT (enabled validators)"
(( THRESHOLD * 2 > VAL_COUNT )) || warn "threshold $THRESHOLD of $VAL_COUNT is not a strict majority"

for cid in "${CHAIN_IDS[@]}"; do
  gate="$(jr ".chains[] | select(.chain_id == $cid) | .gate")"
  [[ "$gate" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "chain $cid has no gate address — run scripts/deploy-from-json.sh first"
  [[ "$gate" =~ ^0x0{40}$ ]] && die "chain $cid gate is the zero address — run scripts/deploy-from-json.sh first"
  # Fail closed exactly where the Rust services do, but with the chain named up
  # front instead of after half the stack is already running. Signing an event at
  # the chain tip lets a reorg erase the deposit after the destination paid out.
  bc="$(cf "$cid" block_confirmation)"; bc="${bc:-0}"
  az="$(cbool "$cid" allow_zero_confirmation)"
  if [[ "$bc" == "0" && "$az" != "true" ]]; then
    die "chain $cid: block_confirmation = 0 without allow_zero_confirmation. Set a finality buffer above the chain's reorg depth, or opt in ONLY for an instant-final dev chain (anvil)."
  fi
done

SOLANA_ON="$(j '.solana.enabled // false')"
if [[ "$SOLANA_ON" == "true" ]]; then
  SOL_CHAIN_ID="$(j '.solana.chain_id')"
  SOL_PROGRAM="$(jr '.solana.program_id')"
  SOL_COMMITMENT="$(j '.solana.commitment')"
  SOL_BIN="$(jr '.solana.bin')"; SOL_BIN="${SOL_BIN:-crates/solana-relayer/target/debug/solana-relayer}"
  [[ "$SOL_BIN" = /* ]] || SOL_BIN="$ROOT/$SOL_BIN"
  [[ -n "$SOL_PROGRAM" ]] || die "solana.enabled but no solana.program_id — run scripts/deploy-from-json.sh first"

  # Solana's finality control is the COMMITMENT level, not a block count. Signing
  # a Sent that a fork later discards is the same double-spend the EVM side's
  # block_confirmation defends against, so fail closed here exactly as the
  # relayer does — just earlier, and by name.
  case "$SOL_COMMITMENT" in
    finalized) ;;
    confirmed|processed)
      [[ "$(j '.solana.allow_unfinalized')" == "true" ]] \
        || die "solana.commitment = \"$SOL_COMMITMENT\" can be rolled back by a fork, so the relayer would sign a Sent whose deposit never settles. Use \"finalized\", or set solana.allow_unfinalized = true ONLY for a local test validator." ;;
    *) die "unknown solana.commitment: $SOL_COMMITMENT" ;;
  esac

  SOL_COUNT="$(j '[.solana.relayers[] | select(.enabled != false)] | length')"
  # Solana `Sent` events are signed ONLY by relayers — the EVM validators never
  # scan Solana — so a gate with threshold T needs at least T relayers, each
  # holding a DISTINCT validator key. Run fewer and Solana-origin transfers stall
  # below quorum, silently.
  (( SOL_COUNT >= THRESHOLD )) || die "solana.relayers has $SOL_COUNT enabled, threshold is $THRESHOLD — Solana-origin transfers would never reach quorum (the EVM validators do not scan Solana)"
  dup_keys="$(j '[.solana.relayers[] | select(.enabled != false) | (.signer.private_key_env // .signer.private_key)] | group_by(.) | map(select(length > 1) | .[0]) | length')"
  [[ "$dup_keys" == "0" ]] || die "two solana.relayers share a signing key — the quorum would count one key twice"
  deliverers="$(j '[.solana.relayers[] | select(.enabled != false and .deliver == true)] | length')"
  (( deliverers <= 1 )) || warn "$deliverers relayers have deliver = true; they submit the same claims from different payers and will race"
  (( deliverers >= 1 )) || warn "no relayer has deliver = true — nothing delivers EVM->Solana claims (signing still works)"
  for kp in $(j '.solana.relayers[] | select(.enabled != false and .deliver == true) | .payer_keypair // empty'); do
    [[ "$kp" = /* ]] || kp="$ROOT/$kp"
    [[ -f "$kp" ]] || die "relayer payer_keypair not found: $kp"
  done
fi

STORE_URL="$(jr '.sig_store.url')"; STORE_URL="${STORE_URL:-http://127.0.0.1:8080}"
STORE_BIND="$(jr '.sig_store.bind')"; STORE_BIND="${STORE_BIND:-127.0.0.1:8080}"
TOKENS_ENV="$RUN_DIR/tokens.env"
prev_token() { [[ -f "$TOKENS_ENV" ]] && sed -n "s/^$1=//p" "$TOKENS_ENV" | head -1 || true; }

# Postgres credentials (M-10). With the container managed here, the password is
# whatever `database.docker.password` says — and when that is null, a RANDOM one
# per run dir, kept in tokens.env (0600) so restarts keep matching the volume,
# and `database.url` is DERIVED from it (a configured url with a stale password
# is exactly the "works once, then auth fails" trap). A configured password wins.
DATABASE_URL="$(jr '.database.url')"
PG_PASSWORD=""
if pg_enabled && [[ "$MODE" != "compose" ]]; then
  PG_USER="$(j '.database.docker.user')"; PG_DB="$(j '.database.docker.db')"; PG_PORT="$(j '.database.docker.port')"
  PG_PASSWORD="$(jr '.database.docker.password')"
  if [[ -z "$PG_PASSWORD" ]]; then
    PG_PASSWORD="$(prev_token PG_PASSWORD)"
    [[ -n "$PG_PASSWORD" ]] || PG_PASSWORD="$(rand_token)"
    DATABASE_URL="postgres://$PG_USER:$PG_PASSWORD@127.0.0.1:$PG_PORT/$PG_DB?sslmode=disable"
  else
    [[ "$PG_PASSWORD" != "bridge" ]] || warn "database.docker.password is the well-known default \"bridge\" — set it to null to get a generated one"
    [[ -n "$DATABASE_URL" ]] || DATABASE_URL="postgres://$PG_USER:$PG_PASSWORD@127.0.0.1:$PG_PORT/$PG_DB?sslmode=disable"
  fi
fi
[[ -n "$DATABASE_URL" || "$MODE" == "compose" ]] || die ".database.url is required when database.docker.enabled = false (the sig-store and indexer are Postgres-backed)"

export RUST_LOG="$LOG_LEVEL"
export DATABASE_URL

# Where the generated TOMLs LAND (CFG_DIR) is not the same question as what the
# paths INSIDE them point at (STATE_DIR, KEYS_DIR) — under compose the files are
# written on the host and read from inside a container.
CFG_DIR="$RUN_DIR"; STATE_DIR="$RUN_DIR"; KEYS_DIR=""
if [[ "$MODE" == "compose" ]]; then
  COMPOSE_DIR="$ROOT/docker/$NAME"
  CFG_DIR="$COMPOSE_DIR/configs"; STATE_DIR="/data"; KEYS_DIR="/keys"
  STORE_URL="http://sig-store:8080"
  # The password stays in the compose .env, never in a generated config.
  DATABASE_URL="postgres://$(j '.database.docker.user'):\${POSTGRES_PASSWORD}@postgres:5432/$(j '.database.docker.db')"
fi

# ---------------------------------------------------------------------------
# generate configs
# ---------------------------------------------------------------------------
# File modes BEFORE the first write (M-11): every TOML below carries a
# private_key, and they used to land 0644 because the umask was set only after
# the whole generation pass.
#   host run : 0600 files in a 0700 run dir (nothing but this user reads them);
#   compose  : the files must be readable by the container's unprivileged uid,
#              so they stay 0644 and the STACK DIRECTORY is 0700 instead — a
#              bind mount is resolved by the daemon, other host users are
#              stopped at the directory.
if [[ "$MODE" == "compose" ]]; then
  install -d -m 700 "$COMPOSE_DIR"
  umask 022
  mkdir -p "$CFG_DIR"
else
  umask 077
  mkdir -p "$RUN_DIR"; chmod 700 "$RUN_DIR"
  # anything an older version of this script left world-readable
  find "$RUN_DIR" -maxdepth 1 -type f \( -name '*.toml' -o -name '*.env' -o -name 'chains.json' \) -exec chmod 600 {} + 2>/dev/null || true
fi
say "generating configs in $CFG_DIR"

REFUND_ON="$(j '.refund.enabled')"
mapfile -t REFUND_DESTS < <(select_chains '.refund.destinations' destination)

VAL_FILES=() VAL_NAMES=()
for idx in $(j '[.validators[] | select(.enabled != false)] | to_entries[].key'); do
  vpath=".validators[] | select(.enabled != false)"
  vname="$(jq -r "[$vpath] | .[$idx].name" "$CONFIG")"
  vjson=".validators[] | select(.name == \"$vname\")"
  cfg="$CFG_DIR/validator-$vname.toml"
  {
    for cid in $(select_chains "$(printf '(%s).sources' "$vjson")" source); do
      rpcs="$(jq -c ".chains[] | select(.chain_id == $cid) | .rpcs" "$CONFIG")"
      echo "[[sources]]"
      echo "chain_id = $cid"
      echo "rpcs = $rpcs"
      echo "gate = \"$(cf "$cid" gate)\""
      echo "start_block = $(cf "$cid" start_block)"
      echo "block_confirmation = $(cf "$cid" block_confirmation)"
      echo "allow_zero_confirmation = $(cbool "$cid" allow_zero_confirmation)"
      echo "poll_interval_ms = $(cf "$cid" poll_interval_ms)"
      cu="$(cf "$cid" catchup_poll_interval_ms)"
      [[ -n "$cu" ]] && echo "catchup_poll_interval_ms = $cu"
      echo "max_block_range = $(cf "$cid" max_block_range)"
      echo "state_file = \"$STATE_DIR/validator-$vname-$cid.json\""
      echo
    done
    echo "[signer]"
    emit_signer "($vjson).signer"
    echo
    echo "[store]"
    echo "url = \"$STORE_URL\""
    if [[ "$(jq -r "($vjson).api.enabled // false" "$CONFIG")" == "true" ]]; then
      echo
      echo "[api]"
      echo "bind = \"$(jq -r "($vjson).api.bind" "$CONFIG")\""
      tok="$(jq -r "($vjson).api.token // empty" "$CONFIG")"
      if [[ -n "$tok" ]]; then
        echo "token = \"$tok\""
      elif [[ "$(jq -r "($vjson).api.allow_unauthenticated // false" "$CONFIG")" == "true" ]]; then
        # Opt-in only. Without a token (and without this) the validator serves
        # read-only /status and leaves pause/resume/rescan unmounted, because an
        # open halt button is a one-request denial of service on the signer set.
        echo "allow_unauthenticated = true"
      fi
    fi
    if [[ "$REFUND_ON" == "true" ]]; then
      # No [refund] block => this validator never votes on cancels/refunds, and
      # stranded transfers stay stranded. That is the safe default: a node that
      # cannot read the destination chain must not have an opinion on delivery.
      echo
      echo "[refund]"
      echo "timeout_secs = $(j '.refund.timeout_secs')"
      echo "poll_interval_ms = $(j '.refund.poll_interval_ms')"
      echo "block_confirmation = $(j '.refund.block_confirmation')"
      echo "allow_zero_confirmation = $(j '.refund.allow_zero_confirmation')"
      for cid in "${REFUND_DESTS[@]}"; do
        echo
        echo "[[refund.destinations]]"
        echo "chain_id = $cid"
        echo "rpcs = $(jq -c ".chains[] | select(.chain_id == $cid) | .rpcs" "$CONFIG")"
        echo "gate = \"$(cf "$cid" gate)\""
      done
    fi
  } > "$cfg"
  VAL_FILES+=("$cfg"); VAL_NAMES+=("$vname")
  info "validator $vname -> $cfg"
done

KEEP_FILES=() KEEP_NAMES=()
for idx in $(j '[.keepers[] | select(.enabled != false)] | to_entries[].key'); do
  kname="$(jq -r "[.keepers[] | select(.enabled != false)] | .[$idx].name" "$CONFIG")"
  kjson=".keepers[] | select(.name == \"$kname\")"
  poll="$(jq -r "($kjson).poll_interval_ms // 1000" "$CONFIG")"
  cfg="$CFG_DIR/keeper-$kname.toml"
  {
    for cid in $(select_chains "$(printf '(%s).targets' "$kjson")" destination); do
      echo "[[targets]]"
      echo "chain_id = $cid"
      echo "rpc = \"$(jq -r ".chains[] | select(.chain_id == $cid) | .rpcs[0]" "$CONFIG")\""
      echo "gate = \"$(cf "$cid" gate)\""
      echo "poll_interval_ms = $poll"
      echo
    done
    echo "[keeper]"
    emit_signer "($kjson).signer"
    echo
    echo "[store]"
    echo "url = \"$STORE_URL\""
    if [[ "$REFUND_ON" == "true" ]]; then
      # Refunds pay out where the funds were LOCKED, i.e. on the source chain —
      # hence their own blocks, separate from the claim targets.
      for cid in $(select_chains "$(printf '(%s).refund_sources' "$kjson")" source); do
        echo
        echo "[[sources]]"
        echo "chain_id = $cid"
        echo "rpc = \"$(jq -r ".chains[] | select(.chain_id == $cid) | .rpcs[0]" "$CONFIG")\""
        echo "gate = \"$(cf "$cid" gate)\""
        echo "poll_interval_ms = $poll"
      done
    fi
  } > "$cfg"
  KEEP_FILES+=("$cfg"); KEEP_NAMES+=("$kname")
  info "keeper $kname -> $cfg"
done
(( ${#KEEP_FILES[@]} >= 1 )) || warn "no enabled keepers — signatures will collect but nothing will claim on-chain"

SOL_FILES=() SOL_NAMES=()
if [[ "$SOLANA_ON" == "true" ]]; then
  for idx in $(j '[.solana.relayers[] | select(.enabled != false)] | to_entries[].key'); do
    rname="$(jq -r "[.solana.relayers[] | select(.enabled != false)] | .[$idx].name" "$CONFIG")"
    rjson=".solana.relayers[] | select(.name == \"$rname\")"
    cfg="$CFG_DIR/solana-relayer-$rname.toml"
    {
      echo "[source]"
      echo "chain_id = $SOL_CHAIN_ID"
      echo "rpc = \"$(j '.solana.rpc')\""
      echo "program_id = \"$SOL_PROGRAM\""
      echo "commitment = \"$SOL_COMMITMENT\""
      echo "allow_unfinalized = $(j '.solana.allow_unfinalized')"
      echo "poll_interval_ms = $(j '.solana.poll_interval_ms')"
      echo "max_batch = $(j '.solana.max_batch')"
      # Its own cursor file: two relayers sharing one would resume from each
      # other's position and skip signatures neither has signed.
      echo "state_file = \"$STATE_DIR/solana-relayer-$rname-state.json\""
      echo
      echo "[signer]"
      # secp256k1, and the SAME key this validator uses on the EVM side: one
      # validator set attests for both VMs. No keystore support here — the
      # relayer only reads `private_key` / `private_key_env`.
      kenv="$(jq -r "($rjson).signer.private_key_env // empty" "$CONFIG")"
      key="$(jq -r "($rjson).signer.private_key // empty" "$CONFIG")"
      if [[ -n "$kenv" ]]; then echo "private_key_env = \"$kenv\""
      elif [[ -n "$key" ]]; then echo "private_key = \"$key\""
      else die "solana relayer $rname has no signing key"; fi
      echo
      echo "[store]"
      echo "url = \"$STORE_URL\""
      echo "token_env = \"SIG_STORE_VALIDATOR_TOKEN\""
      if [[ "$REFUND_ON" == "true" ]]; then
        # The refund attester's on-chain sources (M-13): without this block the
        # relayer votes REFUND but never CANCEL, so a stranded EVM->Solana
        # transfer is never released. It re-derives the transfer's age from the
        # SOURCE gate at an aged block and reads `executed`/`cancelled` on the
        # DESTINATION gate — one [[refund.evm]] per EVM gate, so every corridor
        # end is covered. Same timeout as the validators (one policy, one number).
        # `rpc_env` (never `rpc`): a keyed url stays in the environment, not in
        # the file. The variables are exported at spawn (host) or passed through
        # the service environment (compose).
        rbc="$(jr '.refund.block_confirmation')"; [[ "$rbc" =~ ^[0-9]+$ ]] || rbc=0
        # The relayer refuses 0 (a reorg after a signed refund is a double-spend).
        # On an instant-final anvil 1 is the honest minimum.
        (( rbc >= 1 )) || rbc=1
        echo
        echo "[refund]"
        echo "timeout_secs = $(j '.refund.timeout_secs')"
        for cid in "${CHAIN_IDS[@]}"; do
          echo
          echo "[[refund.evm]]"
          echo "chain_id = $cid"
          echo "gate = \"$(cf "$cid" gate)\""
          echo "rpc_env = \"RPC_$cid\""
          echo "block_confirmation = $rbc"
        done
      fi
      if [[ "$(jq -r "($rjson).deliver // false" "$CONFIG")" == "true" ]]; then
        # The claim-submitting half (EVM -> Solana). Absent => this process only
        # SIGNS, which is a valid split: a validator need not be a keeper.
        kp="$(jq -r "($rjson).payer_keypair" "$CONFIG")"
        if [[ -n "$KEYS_DIR" ]]; then kp="$KEYS_DIR/$(basename "$kp")"
        elif [[ "$kp" != /* ]]; then kp="$ROOT/$kp"; fi
        echo
        echo "[target]"
        echo "payer_keypair = \"$kp\""
        echo "poll_interval_ms = $(jq -r "($rjson).poll_interval_ms // 2000" "$CONFIG")"
      fi
    } > "$cfg"
    SOL_FILES+=("$cfg"); SOL_NAMES+=("$rname")
    info "solana relayer $rname -> $cfg"
  done
fi

IDX_CFG=""
if [[ "$(j '.indexer.enabled')" == "true" ]]; then
  IDX_CFG="$CFG_DIR/indexer.toml"
  {
    # `database_url` in the file beats the DATABASE_URL env var, so under compose
    # it is omitted deliberately: the credential belongs in the environment.
    [[ "$MODE" == "compose" ]] || echo "database_url = \"$DATABASE_URL\""
    echo "refund_timeout_secs = $(j '.indexer.refund_timeout_secs')"
    echo "sweep_interval_secs = $(j '.indexer.sweep_interval_secs')"
    for cid in $(select_chains '.indexer.chains' source); do
      echo
      echo "[[chains]]"
      echo "chain_id = $cid"
      echo "rpc = \"$(jq -r ".chains[] | select(.chain_id == $cid) | .rpcs[0]" "$CONFIG")\""
      echo "gate = \"$(cf "$cid" gate)\""
      pool="$(jr ".chains[] | select(.chain_id == $cid) | .pool")"; [[ -n "$pool" ]] && echo "pool = \"$pool\""
      router="$(jr ".chains[] | select(.chain_id == $cid) | .router")"; [[ -n "$router" ]] && echo "router = \"$router\""
      echo "start_block = $(cf "$cid" start_block)"
      echo "block_confirmation = $(cf "$cid" block_confirmation)"
      echo "allow_zero_confirmation = $(cbool "$cid" allow_zero_confirmation)"
      echo "poll_interval_ms = $(cf "$cid" poll_interval_ms)"
      cu="$(cf "$cid" catchup_poll_interval_ms)"
      [[ -n "$cu" ]] && echo "catchup_poll_interval_ms = $cu"
      echo "max_block_range = $(cf "$cid" max_block_range)"
    done
  } > "$IDX_CFG"
  info "indexer -> $IDX_CFG"
fi

# registry the graphql API serves to the UI
#
# `rpc_url` is the SERVER-SIDE endpoint (rpcs[0], may carry a key) — the API uses
# it for `executed()` reads and never serves it. `public_rpc_url` is the only
# url a browser ever sees (H-4): `chains[].public_rpc` when set; a loopback
# rpcs[0] is its own public url; anything else is served as null (the UI falls
# back to the wallet's provider) and warned about here, once, by name.
is_local_rpc() { [[ "$1" =~ ^https?://(127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0)(:[0-9]+)?(/.*)?$ ]]; }
for cid in "${CHAIN_IDS[@]}"; do
  pub="$(jr ".chains[] | select(.chain_id == $cid) | .public_rpc")"
  prim="$(jq -r ".chains[] | select(.chain_id == $cid) | .rpcs[0]" "$CONFIG")"
  [[ -n "$pub" ]] || is_local_rpc "$prim" \
    || warn "chain $cid has no public_rpc — the UI gets rpcUrl=null for it (rpcs[0] is never served to browsers)"
done
# The swap pools ride in the registry too (`swap_pool`, read over the entry's
# own rpc_url) — `graphql.swaps[]` (multi-chain) or the older `graphql.swap`
# (single pool). The pool's `from_block` must be at or before its deployment:
# its token list is discovered by replaying TokenListed logs. `max_block_range`
# is that chain's own getLogs cap — a fast chain throttled to another endpoint's
# cap produces blocks faster than its listing history can be replayed.
REG_JSON="$CFG_DIR/chains.json"
jq '
  def is_local: test("^https?://(127\\.0\\.0\\.1|localhost|\\[::1\\]|0\\.0\\.0\\.0)(:[0-9]+)?(/.*)?$");
  (.defaults.max_block_range // 1000) as $dmbr
  | ([.graphql.swaps[]?] + (if (.graphql.swap.enabled // false) then [.graphql.swap] else [] end)) as $pools
  | [ .chains[] | select(.enabled != false) | . as $ch
    | ($pools | map(select(.chain_id == $ch.chain_id)) | .[0]) as $sp
    | {chain_id, name, rpc_url: .rpcs[0], gate,
       token: ((.tokens // [])[0].address // null),
       tokens: (.tokens // []),
       router}
      + (if (.public_rpc // "") != "" then {public_rpc_url: .public_rpc}
         elif (.rpcs[0] | is_local) then {public_rpc_url: .rpcs[0]}
         else {} end)
      + (if ($sp != null and ($sp.pool // "") != "")
         then {swap_pool: {address: $sp.pool, from_block: ($sp.from_block // 0),
                           max_block_range: ($ch.max_block_range // $dmbr)}}
         else {} end) ]' "$CONFIG" > "$REG_JSON"
if [[ "$SOLANA_ON" == "true" ]]; then
  # The Solana gate is a registry entry like any other: `gate` is the base58
  # program id (the API routes on address form: 0x = EVM, base58 = Solana),
  # `rpc_url` the server-side endpoint it reads the gate and pool through, and
  # `public_rpc_url` the browser-safe one (`solana.public_rpc`; a loopback rpc
  # is its own). That is what lets the UI read a corridor's nonce and vault to
  # build a `send` out of Solana — and it is why the row is always present when
  # the leg is enabled: `include_in_registry` no longer gates it (the API needs
  # the row to reach the program at all).
  [[ "$(j '.solana.include_in_registry')" == "true" ]] \
    || info "solana.include_in_registry is false but the row is required for the API to read the gate — listed anyway"
  sol_pub="$(jr '.solana.public_rpc')"
  [[ -n "$sol_pub" ]] || { is_local_rpc "$(j '.solana.rpc')" && sol_pub="$(j '.solana.rpc')"; } \
    || warn "solana has no public_rpc — the UI gets rpcUrl=null for it (solana.rpc is never served to browsers)"
  tmp="$(mktemp)"
  jq --slurpfile c <(jq '{solana, graphql}' "$CONFIG") --arg pub "$sol_pub" --arg prog "$SOL_PROGRAM" '
    ($c[0].graphql.swaps // [] | map(select(.chain_id == $c[0].solana.chain_id)) | .[0].pool // "") as $sp
    | . + [{ chain_id: $c[0].solana.chain_id, name: $c[0].solana.name,
             rpc_url: $c[0].solana.rpc, gate: $prog,
             token: ($c[0].solana.tokens[0].mint // null),
             tokens: [$c[0].solana.tokens[] | select(.mint != null) | {symbol, address: .mint}],
             router: null }
           + (if $pub != "" then {public_rpc_url: $pub} else {} end)
           + (if $sp != "" then {swap_pool: $sp} else {} end)]' \
    "$REG_JSON" > "$tmp" && mv "$tmp" "$REG_JSON"
fi
# `mktemp` creates 0600 and `mv` carries that mode over — which makes the
# registry unreadable to the container uid under compose, where the file is
# bind-mounted rather than read by this user. (It holds no secrets beyond
# rpc_url, which the configs/ directory protects the same way as the TOMLs.)
[[ "$MODE" == "compose" ]] && chmod 644 "$REG_JSON"
info "registry -> $REG_JSON"

if [[ "$MODE" == "compose" ]]; then
  say "writing the docker stack to $COMPOSE_DIR"
  yml="$COMPOSE_DIR/docker-compose.yml"

  # The relayer's payer keypair is typically 0600 and owned by the operator,
  # while the container runs as an unprivileged uid of its own — a direct bind
  # mount is unreadable to it. Stage a copy the container CAN read, and protect
  # it with the directory instead: 0700 here blocks other host users, and a bind
  # mount is resolved by the daemon, so the container still reads the file.
  # (The same reasoning covers configs/, which hold validator private keys.)
  chmod 700 "$COMPOSE_DIR"
  if (( ${#SOL_FILES[@]} )); then
    # 0755 on the directory itself: a DIRECTORY bind mount keeps its own mode
    # inside the container, so 0700 here would stop the container uid at the
    # traversal even with a readable file inside. Other host users are still
    # blocked — they cannot traverse the 0700 stack directory above it.
    mkdir -p "$COMPOSE_DIR/keys"; chmod 755 "$COMPOSE_DIR/keys"
    for kp in $(j '.solana.relayers[] | select(.enabled != false and .deliver == true) | .payer_keypair // empty'); do
      [[ "$kp" = /* ]] || kp="$ROOT/$kp"
      install -m 0644 "$kp" "$COMPOSE_DIR/keys/$(basename "$kp")"
      info "staged $(basename "$kp") -> keys/ (readable by the container uid)"
    done
  fi
  # Every service is built from the repo root, so the context is two levels up.
  CTX="../.."

  svc_deps=""    # accumulated depends_on for graphql (it must not start first)
  {
    printf '# GENERATED by scripts/bridge-from-json.sh --compose from %s\n' "$(basename "$CONFIG")"
    printf '# Regenerate after any config change; hand edits are overwritten.\n#\n'
    printf '#   cp .env.example .env && edit it   (tokens + Postgres password)\n'
    printf '#   docker compose up -d --build\n#\n'
    printf '# The configs in ./configs are generated too, and they carry the validator\n'
    printf '# and keeper PRIVATE KEYS — treat this directory as secret material.\n\n'
    printf 'x-restart: &restart\n  restart: unless-stopped\n\nservices:\n'

    # --- postgres ---
    printf '  postgres:\n    image: %s\n    <<: *restart\n' "$(j '.database.docker.image')"
    printf '    environment:\n'
    printf '      POSTGRES_USER: %s\n' "$(j '.database.docker.user')"
    printf '      POSTGRES_PASSWORD: "${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD}"\n'
    printf '      POSTGRES_DB: %s\n' "$(j '.database.docker.db')"
    printf '    volumes: ["pgdata:/var/lib/postgresql/data"]\n'
    printf '    healthcheck:\n      test: ["CMD-SHELL", "pg_isready -U %s -d %s"]\n' \
      "$(j '.database.docker.user')" "$(j '.database.docker.db')"
    printf '      interval: 3s\n      timeout: 3s\n      retries: 30\n\n'

    # --- sig-store ---
    printf '  sig-store:\n    build: { context: %s, dockerfile: Dockerfile }\n    <<: *restart\n' "$CTX"
    printf '    command: ["sig-store", "--bind", "0.0.0.0:8080"]\n    environment:\n'
    printf '      DATABASE_URL: "%s"\n' "$DATABASE_URL"
    for role in VALIDATOR KEEPER READER ADMIN; do
      printf '      SIG_STORE_%s_TOKEN: "${SIG_STORE_%s_TOKEN:?set SIG_STORE_%s_TOKEN}"\n' "$role" "$role" "$role"
    done
    printf '    depends_on:\n      postgres: { condition: service_healthy }\n'
    printf '    healthcheck:\n      test: ["CMD", "curl", "-fsS", "http://localhost:8080/health"]\n'
    printf '      interval: 5s\n      timeout: 3s\n      retries: 30\n\n'

    # --- validators ---
    for n in "${VAL_NAMES[@]}"; do
      printf '  validator-%s:\n    build: { context: %s, dockerfile: Dockerfile }\n    <<: *restart\n' "$n" "$CTX"
      printf '    command: ["validator", "/configs/validator-%s.toml"]\n' "$n"
      printf '    environment:\n      SIG_STORE_VALIDATOR_TOKEN: "${SIG_STORE_VALIDATOR_TOKEN:?set SIG_STORE_VALIDATOR_TOKEN}"\n'
      # Its own volume: the cursor file is per validator, and sharing one would
      # make each resume from the other's position.
      printf '    volumes:\n      - ./configs:/configs:ro\n      - validator-%s-state:/data\n' "$n"
      printf '    depends_on:\n      sig-store: { condition: service_healthy }\n\n'
    done

    # --- keepers ---
    for n in "${KEEP_NAMES[@]}"; do
      printf '  keeper-%s:\n    build: { context: %s, dockerfile: Dockerfile }\n    <<: *restart\n' "$n" "$CTX"
      printf '    command: ["keeper", "/configs/keeper-%s.toml"]\n' "$n"
      printf '    environment:\n      SIG_STORE_KEEPER_TOKEN: "${SIG_STORE_KEEPER_TOKEN:?set SIG_STORE_KEEPER_TOKEN}"\n'
      printf '    volumes: ["./configs:/configs:ro"]\n'
      printf '    depends_on:\n      sig-store: { condition: service_healthy }\n\n'
    done

    # --- solana relayers ---
    for i in "${!SOL_NAMES[@]}"; do
      n="${SOL_NAMES[$i]}"
      printf '  solana-relayer-%s:\n    build: { context: %s, dockerfile: docker/Dockerfile.relayer }\n    <<: *restart\n' "$n" "$CTX"
      printf '    command: ["solana-relayer", "/configs/solana-relayer-%s.toml"]\n' "$n"
      printf '    environment:\n      SIG_STORE_VALIDATOR_TOKEN: "${SIG_STORE_VALIDATOR_TOKEN:?set SIG_STORE_VALIDATOR_TOKEN}"\n'
      # the [[refund.evm]] readers resolve their urls from RPC_<chain> (rpc_env)
      for cid in "${CHAIN_IDS[@]}"; do
        printf '      RPC_%s: "${RPC_%s:?set RPC_%s in .env}"\n' "$cid" "$cid" "$cid"
      done
      printf '    volumes:\n      - ./configs:/configs:ro\n      - ./keys:/keys:ro\n      - solana-%s-state:/data\n' "$n"
      printf '    depends_on:\n      sig-store: { condition: service_healthy }\n\n'
    done

    # --- indexer ---
    if [[ -n "$IDX_CFG" ]]; then
      printf '  indexer:\n    build: { context: %s, dockerfile: Dockerfile }\n    <<: *restart\n' "$CTX"
      printf '    command: ["indexer", "/configs/indexer.toml"]\n'
      printf '    environment:\n      DATABASE_URL: "%s"\n' "$DATABASE_URL"
      printf '    volumes: ["./configs:/configs:ro"]\n'
      # Behind sig-store, not just postgres: both run the same idempotent
      # migration, and two simultaneous first-creates race on pg_type.
      printf '    depends_on:\n      sig-store: { condition: service_healthy }\n      postgres: { condition: service_healthy }\n\n'
    fi

    # --- graphql-api ---
    printf '  graphql-api:\n    build: { context: %s, dockerfile: Dockerfile }\n    <<: *restart\n' "$CTX"
    printf '    command:\n'
    printf '      - "graphql-api"\n      - "--bind"\n      - "0.0.0.0:8088"\n'
    printf '      - "--store-url"\n      - "http://sig-store:8080"\n'
    printf '      - "--threshold"\n      - "%s"\n' "$THRESHOLD"
    printf '      - "--chains-file"\n      - "/configs/chains.json"\n'
    [[ "$(j '.graphql.allow_mutations')" == "true" ]] && printf '      - "--allow-mutations"\n'
    # No `--gate` / `--swap`: every gate (EVM and Solana) and every swap pool is
    # in /configs/chains.json, read over that entry's rpc_url. No RPC url is
    # ever written into this file (H-4: it was committed with a live key once).
    # Read-only credential, and its only one: this is the service that faces the
    # internet, so it holds nothing that can write and no database URL at all.
    printf '    environment:\n      SIG_STORE_READER_TOKEN: "${SIG_STORE_READER_TOKEN:?set SIG_STORE_READER_TOKEN}"\n'
    printf '      GRAPHQL_MAX_BLOCK_RANGE: "%s"\n' "$(j '.defaults.max_block_range')"
    printf '    volumes: ["./configs:/configs:ro"]\n'
    printf '    depends_on:\n      sig-store: { condition: service_healthy }\n'
    printf '    healthcheck:\n      test: ["CMD", "curl", "-fsS", "http://localhost:8088/health"]\n'
    printf '      interval: 5s\n      timeout: 3s\n      retries: 30\n\n'

    # --- frontend ---
    if [[ "$(j '.frontend.enabled // false')" == "true" ]]; then
      printf '  frontend:\n    build: { context: %s, dockerfile: docker/Dockerfile.frontend }\n    <<: *restart\n' "$CTX"
      # nginx proxies /graphql and /health to graphql-api, so the browser talks
      # to the API same-origin and no API port needs publishing.
      printf '    ports: ["%s:8080"]\n' "$(j '.frontend.port')"
      printf '    depends_on:\n      graphql-api: { condition: service_healthy }\n\n'
    fi

    printf 'volumes:\n  pgdata:\n'
    for n in "${VAL_NAMES[@]}"; do printf '  validator-%s-state:\n' "$n"; done
    for n in "${SOL_NAMES[@]}"; do printf '  solana-%s-state:\n' "$n"; done
  } > "$yml"

  # Two files on purpose. `.env` carries REAL secrets and is gitignored;
  # `.env.example` is the committable template and holds none, so a checked-in
  # example can never become the credentials someone actually runs with.
  #
  # The RPC urls live in .env too (H-4): compose resolves the `${RPC_<chain>}`
  # references above from it, so the keyed urls never appear in the compose
  # file. Secrets already in an existing .env are KEPT (regenerating must not
  # rotate the Postgres password out from under a live volume); the RPC lines
  # are refreshed from the config on every run.
  {
    echo "# Template. Every secret must be a fresh random value:  openssl rand -hex 32"
    echo "# One token per role, so a leak from one component cannot act as another."
    echo "POSTGRES_PASSWORD="
    for role in VALIDATOR KEEPER READER ADMIN; do echo "SIG_STORE_${role}_TOKEN="; done
    echo "# EVM RPC endpoints for the relayers' [[refund.evm]] readers (rpc_env); may carry provider keys"
    for cid in "${CHAIN_IDS[@]}"; do echo "RPC_$cid="; done
  } > "$COMPOSE_DIR/.env.example"
  env_prev() { [[ -f "$COMPOSE_DIR/.env" ]] && sed -n "s/^$1=//p" "$COMPOSE_DIR/.env" | head -1 || true; }
  kept=false; [[ -f "$COMPOSE_DIR/.env" ]] && kept=true
  umask 077
  tmp_env="$(mktemp)"
  {
    echo "# Generated by $(basename "$0") — gitignored, do not commit."
    echo "# Secrets are kept across regenerations; RPC lines follow the config."
    for k in POSTGRES_PASSWORD SIG_STORE_VALIDATOR_TOKEN SIG_STORE_KEEPER_TOKEN SIG_STORE_READER_TOKEN SIG_STORE_ADMIN_TOKEN; do
      v="$(env_prev "$k")"; [[ -n "$v" ]] || v="$(rand_token)"
      echo "$k=$v"
    done
    for cid in "${CHAIN_IDS[@]}"; do
      echo "RPC_$cid=$(jq -r ".chains[] | select(.chain_id == $cid) | .rpcs[0]" "$CONFIG")"
    done
  } > "$tmp_env"
  mv "$tmp_env" "$COMPOSE_DIR/.env"; chmod 600 "$COMPOSE_DIR/.env"
  if $kept; then info "secrets      : $COMPOSE_DIR/.env secrets kept, RPC lines refreshed"
  else info "secrets      : $COMPOSE_DIR/.env written (fresh random values)"; fi

  info "compose file : $yml"
  info "configs      : $CFG_DIR ($(ls "$CFG_DIR" | wc -l) files, they hold PRIVATE KEYS)"
  echo
  info "  cd $COMPOSE_DIR && docker compose up -d --build"
  exit 0
fi

[[ "$MODE" == "generate" ]] && { say "generated (not started)"; exit 0; }

# ---------------------------------------------------------------------------
# start
# ---------------------------------------------------------------------------
spawn() { # $1 command, $2 log name, $3 display name, $4 pattern that matches only this process
  setsid bash -c "exec $1" >"$RUN_DIR/$2" 2>&1 </dev/null &
  local pid=$!
  disown || true
  printf '%s\t%s\t%s\n' "$pid" "$3" "$4" >> "$PIDS"
}

if [[ -f "$PIDS" ]]; then
  say "stopping the previous run"
  bash "$0" "$CONFIG" --stop >/dev/null 2>&1 || true
  sleep 1
fi
: > "$PIDS"

if [[ "$(j '.runtime.build')" == "true" ]]; then
  say "building rust services"
  pkgs=(-p sig-store -p validator -p keeper -p graphql-api)
  [[ -n "$IDX_CFG" ]] && pkgs+=(-p indexer)
  ( cd "$ROOT" && cargo build "${pkgs[@]}" ) || die "cargo build failed"
fi
for b in sig-store validator keeper graphql-api; do
  [[ -x "$BIN_DIR/$b" ]] || die "missing binary $BIN_DIR/$b (set runtime.build = true, or point runtime.bin_dir at your release build)"
done

if pg_enabled; then
  need docker "the Postgres-backed sig-store"
  say "starting Postgres ($PG_NAME)"
  PG_PORT="$(j '.database.docker.port')"; PG_VOL="$(j '.database.docker.volume')"
  docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
  docker volume create "$PG_VOL" >/dev/null 2>&1 || true
  # Loopback only (M-10): a docker `-p` publish bypasses ufw, and this database
  # is the bridge's memory — signatures, refund state, allowlists, cursors.
  docker run -d --name "$PG_NAME" \
    -e POSTGRES_USER="$PG_USER" \
    -e POSTGRES_PASSWORD="$PG_PASSWORD" \
    -e POSTGRES_DB="$PG_DB" \
    -v "$PG_VOL:/var/lib/postgresql/data" -p "127.0.0.1:$PG_PORT:5432" \
    "$(j '.database.docker.image')" >/dev/null || die "could not start $PG_NAME"
  ok=false
  for _ in $(seq 1 60); do docker exec "$PG_NAME" pg_isready -U "$PG_USER" >/dev/null 2>&1 && { ok=true; break; }; sleep 0.5; done
  $ok || die "Postgres did not become ready"
  # POSTGRES_PASSWORD only applies when the volume is first initialised; a volume
  # from an earlier run keeps its old one. Set it explicitly over the container's
  # local socket so the generated/configured password always matches the volume.
  docker exec "$PG_NAME" psql -q -U "$PG_USER" -d "$PG_DB" \
    -c "ALTER USER \"$PG_USER\" WITH PASSWORD '$PG_PASSWORD';" >/dev/null 2>&1 \
    || warn "could not set the Postgres password on the existing volume"
  info "Postgres ready on 127.0.0.1:$PG_PORT (password in $TOKENS_ENV)"
fi

# Scoped sig-store credentials. With none set the store starts UNAUTHENTICATED:
# signatures, claim status and the allowlist all become writable by anything that
# can reach the port. One token per role, so a leak from one component cannot act
# as another.
gen_if_unset="$(j '.sig_store.tokens.generate_if_unset')"
for role in VALIDATOR KEEPER READER ADMIN; do
  lower="$(tr 'A-Z' 'a-z' <<<"$role")"
  val="$(jr ".sig_store.tokens.$lower")"
  if [[ -z "$val" ]]; then
    # The store FAILS CLOSED with no token configured (it refuses to bind unless
    # started with --allow-unauthenticated), so this is a startup failure, not a
    # silently open store.
    [[ "$gen_if_unset" == "true" ]] || warn "sig_store.tokens.$lower unset and generate_if_unset=false — the store will refuse to start without every role's token"
    [[ "$gen_if_unset" == "true" ]] && val="$(rand_token)"
  fi
  export "SIG_STORE_${role}_TOKEN=$val"
done
{ for role in VALIDATOR KEEPER READER ADMIN; do
    v="SIG_STORE_${role}_TOKEN"; echo "$v=${!v}"
  done
  [[ -n "$PG_PASSWORD" ]] && echo "PG_PASSWORD=$PG_PASSWORD"
} > "$TOKENS_ENV"
chmod 600 "$TOKENS_ENV"

if [[ "$(j '.sig_store.enabled')" == "true" ]]; then
  say "starting sig-store ($STORE_URL)"
  # --bind on the command line (not the env var) so the process line identifies
  # THIS stack: the stop fallback matches on it, and a second stack on another
  # port is left alone. Tokens stay in the environment — a command line is
  # world-readable in /proc.
  spawn "$BIN_DIR/sig-store --bind $STORE_BIND" sig-store.log sig-store "sig-store --bind $STORE_BIND"
  ok=false
  for _ in $(seq 1 80); do curl -s "$STORE_URL/health" 2>/dev/null | grep -q ok && { ok=true; break; }; sleep 0.25; done
  $ok || die "sig-store did not come up (see $RUN_DIR/sig-store.log)"
  info "healthy; tokens in $RUN_DIR/tokens.env"
fi

say "starting ${#VAL_FILES[@]} validator(s)"
for i in "${!VAL_FILES[@]}"; do
  spawn "$BIN_DIR/validator ${VAL_FILES[$i]}" "validator-${VAL_NAMES[$i]}.log" "validator-${VAL_NAMES[$i]}" "${VAL_FILES[$i]}"
  info "${VAL_NAMES[$i]}"
done

say "starting ${#KEEP_FILES[@]} keeper(s)"
for i in "${!KEEP_FILES[@]}"; do
  spawn "$BIN_DIR/keeper ${KEEP_FILES[$i]}" "keeper-${KEEP_NAMES[$i]}.log" "keeper-${KEEP_NAMES[$i]}" "${KEEP_FILES[$i]}"
  info "${KEEP_NAMES[$i]}"
done

if (( ${#SOL_FILES[@]} )); then
  say "starting ${#SOL_FILES[@]} solana relayer(s)"
  if [[ "$(j '.solana.build')" == "true" ]]; then
    # Its own cargo project on purpose: solana-client pins zeroize <1.4 and alloy
    # needs ^1.5, so the relayer cannot live in the workspace with the EVM services.
    ( cd "$ROOT" && cargo build --manifest-path crates/solana-relayer/Cargo.toml --bin solana-relayer ) \
      || die "building solana-relayer failed"
  fi
  [[ -x "$SOL_BIN" ]] || die "missing $SOL_BIN (set solana.build = true, or point solana.bin at your build)"
  # The relayer's [[refund.evm]] readers take their urls from RPC_<chain_id>
  # (`rpc_env`), so a keyed url is in this process environment, not in a file.
  for cid in "${CHAIN_IDS[@]}"; do
    export "RPC_$cid=$(jq -r ".chains[] | select(.chain_id == $cid) | .rpcs[0]" "$CONFIG")"
  done
  for i in "${!SOL_FILES[@]}"; do
    spawn "$SOL_BIN ${SOL_FILES[$i]}" "solana-relayer-${SOL_NAMES[$i]}.log" "solana-relayer-${SOL_NAMES[$i]}" "${SOL_FILES[$i]}"
    info "${SOL_NAMES[$i]}"
  done
fi

if [[ -n "$IDX_CFG" ]]; then
  say "starting indexer"
  spawn "$BIN_DIR/indexer $IDX_CFG" indexer.log indexer "$IDX_CFG"
fi

if [[ "$(j '.graphql.enabled')" == "true" ]]; then
  GQL_BIND="$(j '.graphql.bind')"
  say "starting graphql-api ($GQL_BIND)"
  args=(--bind "$GQL_BIND" --store-url "$STORE_URL" --threshold "$THRESHOLD" --chains-file "$REG_JSON")
  [[ "$(j '.graphql.allow_mutations')" == "true" ]] && args+=(--allow-mutations)
  # No `--gate` / `--swap`: every gate (EVM by 0x address, Solana by base58
  # program id) and every swap pool (`swap_pool`) is in the 0600 registry file
  # and read over that entry's rpc_url, so no (possibly keyed) url ever sits on
  # a world-readable command line.
  # No --db-url: graphql-api reads history through the sig-store on its reader
  # token. It is the only service meant to face the internet, so it holds no
  # database credential of its own.
  export GRAPHQL_MAX_BLOCK_RANGE="$(j '.defaults.max_block_range')"
  spawn "$BIN_DIR/graphql-api ${args[*]}" graphql-api.log graphql-api "$REG_JSON"
  ok=false
  for _ in $(seq 1 80); do curl -s "http://$GQL_BIND/health" >/dev/null 2>&1 && { ok=true; break; }; sleep 0.25; done
  $ok || die "graphql-api did not come up (see $RUN_DIR/graphql-api.log)"
  info "healthy"
fi

if [[ "$(j '.frontend.enabled // false')" == "true" ]]; then
  FE_DIR="$(jr '.frontend.dir')"; FE_DIR="${FE_DIR:-frontend}"
  [[ "$FE_DIR" = /* ]] || FE_DIR="$ROOT/$FE_DIR"
  FE_HOST="$(jr '.frontend.host')"; FE_HOST="${FE_HOST:-127.0.0.1}"
  FE_PORT="$(jr '.frontend.port')"; FE_PORT="${FE_PORT:-5173}"
  say "starting frontend (vite on :$FE_PORT)"
  # nvm installs are not on a non-login shell's PATH, so find the newest one
  # rather than failing on a node that is installed and simply not visible here.
  FE_NODE_BIN="$(jr '.frontend.node_bin')"
  if [[ -z "$FE_NODE_BIN" ]] && ! command -v node >/dev/null 2>&1; then
    FE_NODE_BIN="$(ls -d "$HOME"/.nvm/versions/node/*/bin 2>/dev/null | sort -V | tail -1 || true)"
  fi
  [[ -n "$FE_NODE_BIN" ]] && export PATH="$FE_NODE_BIN:$PATH"
  need node "the frontend"; need npm "the frontend"
  if [[ ! -d "$FE_DIR/node_modules" ]]; then
    [[ "$(j '.frontend.install')" == "true" ]] || die "no $FE_DIR/node_modules and frontend.install = false"
    ( cd "$FE_DIR" && npm install --no-audit --no-fund ) || die "npm install failed"
  fi
  # The UI talks to the API through vite's proxy, so it needs no CORS and no
  # public API port — the same wiring scripts/run.sh uses.
  export VITE_PROXY_TARGET="http://$(j '.graphql.bind')"
  ( cd "$FE_DIR" && spawn "npx vite --host $FE_HOST --port $FE_PORT --strictPort" web.log frontend "vite --host $FE_HOST --port $FE_PORT" )
  ok=false
  for _ in $(seq 1 80); do curl -s "http://127.0.0.1:$FE_PORT/" >/dev/null 2>&1 && { ok=true; break; }; sleep 0.3; done
  $ok && info "http://$FE_HOST:$FE_PORT" || warn "vite did not answer yet (see $RUN_DIR/web.log)"
fi

say "$NAME is up"
for cid in "${CHAIN_IDS[@]}"; do
  printf '  %-14s %s  gate %s\n' "$(jq -r ".chains[] | select(.chain_id == $cid) | .name" "$CONFIG")" \
    "$(jq -r ".chains[] | select(.chain_id == $cid) | .rpcs[0]" "$CONFIG")" "$(cf "$cid" gate)"
done
printf '  %-14s %s\n' "validators" "${VAL_NAMES[*]} (threshold $THRESHOLD)"
printf '  %-14s %s\n' "keepers"    "${KEEP_NAMES[*]:-none}"
[[ "$SOLANA_ON" == "true" ]] && printf '  %-14s %s  program %s (%s relayers, commitment %s)\n' \
  "$(j '.solana.name')" "$(j '.solana.rpc')" "$SOL_PROGRAM" "${#SOL_FILES[@]}" "$SOL_COMMITMENT"
printf '  %-14s %s\n' "sig-store"  "$STORE_URL"
[[ "$(j '.graphql.enabled')" == "true" ]] && printf '  %-14s http://%s  (GraphiQL at /)\n' "graphql" "$(j '.graphql.bind')"
[[ "$(j '.frontend.enabled // false')" == "true" ]] && printf '  %-14s http://%s:%s\n' "frontend" "$(j '.frontend.host')" "$(j '.frontend.port')"
echo
info "logs:   $RUN_DIR/*.log"
info "status: bash scripts/bridge-from-json.sh $CONFIG --status"
info "stop:   bash scripts/bridge-from-json.sh $CONFIG --stop"
