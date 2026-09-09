#!/usr/bin/env bash
# stop.sh — tear down everything scripts/run.sh started, using the same config
# (for the run dir and the Postgres container name).
#
#   bash scripts/stop.sh [config-file] [--wipe] [--force]
#
#   default   kills ONLY the processes run.sh recorded in $RUN_DIR/pids/ — each
#             pidfile is written by the service itself at exec time, and the
#             process is checked against its recorded command line before the
#             signal is sent, so a recycled pid is never hit.
#   --force   additionally falls back to the old pattern kills (`anvil
#             --chain-id`, `vite`, target/debug/<service>) and frees the
#             configured ports with fuser. Those patterns match ANY such process
#             on the machine, including ones that are not ours (audit round 4,
#             LOW) — hence opt-in, for when the pidfiles are gone.
#   --wipe    also deletes the Postgres data volume. Without it, history survives.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$ROOT/scripts/run.config"
WIPE=false; FORCE=false
for a in "$@"; do
  case "$a" in
    --wipe)  WIPE=true ;;
    --force) FORCE=true ;;
    -*)      echo "unknown flag: $a" >&2; exit 1 ;;
    *)       CONFIG="$a" ;;
  esac
done
# shellcheck disable=SC1090
[[ -f "$CONFIG" ]] && source "$CONFIG"

# defaults in case the config is missing a field (must match run.sh)
STORE_PORT="${STORE_PORT:-8080}"
GQL_PORT="${GQL_PORT:-8088}"
WEB_PORT="${WEB_PORT:-5173}"
PG_NAME="${PG_NAME:-bridge-run-pg}"
PG_DOCKER="${PG_DOCKER:-true}"
RUN_DIR="${RUN_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/selendra-bridge/run}"

echo "=== stopping bridge stack ==="

# --- 1. the recorded processes ------------------------------------------------
# Each service was started as its own session (setsid), so its pid is also its
# process-group id: `kill -- -pid` takes the service AND anything it forked
# (`npx vite` -> node, cargo-run wrappers) without touching anything else.
alive() { kill -0 "$1" 2>/dev/null; }
ours() {  # $1 pid, $2 recorded command — does /proc say this pid is still that process?
  # Any meaningful token of the recorded command must appear in the live command
  # line — not just the first word: `npx vite …` runs as `npm exec vite …`, and a
  # shell wrapper may have re-exec'd under a different name. A recycled pid
  # running something unrelated matches none of them.
  local live tok
  [[ -r "/proc/$1/cmdline" ]] || return 1
  live="$(tr '\0' ' ' <"/proc/$1/cmdline")"
  for tok in $2; do
    [[ "$tok" == -* || ${#tok} -lt 4 ]] && continue
    grep -qF -- "$(basename "$tok")" <<<"$live" && return 0
  done
  return 1
}
stopped=0; stale=0
shopt -s nullglob
for pidfile in "$RUN_DIR"/pids/*.pid; do
  name="$(basename "$pidfile" .pid)"
  pid="$(tr -dc '0-9' <"$pidfile")"
  cmd="$(cat "$RUN_DIR/pids/$name.cmd" 2>/dev/null || echo "$name")"
  if [[ -n "$pid" ]] && alive "$pid" && ours "$pid" "$cmd"; then
    kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null
    for _ in $(seq 1 20); do alive "$pid" || break; sleep 0.1; done
    alive "$pid" && { kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null; }
    echo "  stopped $name (pid $pid)"
    stopped=$((stopped+1))
  elif [[ -n "$pid" ]] && alive "$pid"; then
    echo "  ! $name: pid $pid is alive but is not '$cmd' (pid reused?) — left alone"
    stale=$((stale+1))
  else
    stale=$((stale+1))
  fi
  rm -f "$pidfile" "$RUN_DIR/pids/$name.cmd"
done
shopt -u nullglob
(( stopped > 0 )) || echo "  no recorded processes to stop (pid dir: $RUN_DIR/pids)"

# --- 2. the pattern fallback (opt-in) ------------------------------------------
ports=( "$STORE_PORT" "$GQL_PORT" "$WEB_PORT" )
for entry in "${CHAINS[@]:-}"; do
  [[ -z "$entry" ]] && continue
  IFS='|' read -r _ _ rpc _ <<<"$entry"
  rpc="${rpc// /}"
  [[ -n "$rpc" ]] && ports+=( "${rpc##*:}" )
done
if $FORCE; then
  echo "  --force: pattern + port fallback"
  fuser -k "${ports[@]/%//tcp}" 2>/dev/null || true
  for p in 'anvil --chain-id' 'target/debug/sig-store' 'target/debug/validator' \
           'target/debug/keeper' 'target/debug/indexer' 'target/debug/graphql-api' \
           'vite'; do
    pkill -f "$p" 2>/dev/null || true
  done
else
  busy=()
  for port in "${ports[@]}"; do
    fuser "$port/tcp" >/dev/null 2>&1 && busy+=("$port")
  done
  if (( ${#busy[@]} )); then
    echo "  ! ports still in use: ${busy[*]} — not ours by the pidfiles. If they are leftovers"
    echo "    from an older run (no pidfiles), re-run with --force."
  fi
fi

# --- 3. Postgres -----------------------------------------------------------------
if [[ "$PG_DOCKER" == "true" ]] && command -v docker >/dev/null 2>&1; then
  # Remove the CONTAINER (it holds the port) but keep its named volume, so
  # transfer history, refund state and indexer cursors survive a restart. Pass
  # --wipe to drop the data too.
  docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
  if [[ "$WIPE" == "true" ]]; then
    docker volume rm "${PG_NAME}-data" >/dev/null 2>&1 || true
    echo "  wiped Postgres volume ${PG_NAME}-data"
  fi
fi

if [[ "$WIPE" == "true" ]]; then
  echo "  stopped ($stopped process(es); $PG_NAME and its data removed)"
else
  echo "  stopped ($stopped process(es); $PG_NAME removed, data volume ${PG_NAME}-data KEPT)"
fi
