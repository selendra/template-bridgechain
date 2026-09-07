#!/usr/bin/env bash
# End-to-end smoke test for the React dashboard (frontend/). Proves the whole
# wiring works without a browser:
#   1. boot graphql-api against a seeded dir store
#   2. boot the Vite dev server (which proxies /graphql -> the API)
#   3. fetch the dashboard's index.html (the SPA is served)
#   4. issue the exact stats/submissions/by-id queries the app sends, THROUGH the
#      dev-server proxy, and assert the shapes the UI relies on come back
#
# Run from anywhere:  bash scripts/testing/web-smoke.sh
set -euo pipefail

# Native Linux node (nvm). Pick the newest installed version rather than pinning
# one: a hardcoded path silently vanishes on the next `nvm install`, and then
# PATH falls back to whatever `node` the shell has — often none at all, which
# surfaces as a confusing "command not found" deep inside the run. Same
# auto-detect idiom as scripts/run.sh.
NODE_BIN="${NODE_BIN:-$(ls -d "$HOME"/.nvm/versions/node/*/bin 2>/dev/null | sort -V | tail -1 || true)}"
export PATH="${NODE_BIN:+$NODE_BIN:}$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WEB="$ROOT/frontend"
API_BIND=127.0.0.1:8093
WEB_PORT=5199
BASE="$(mktemp -d)"
STORE="$BASE/store"; mkdir -p "$STORE"

API_PID=""; WEB_PID=""
cleanup() {
  # `bunx vite` is a SHELL -> bunx -> node chain, so killing the pid we backgrounded
  # reaps the wrapper and orphans the node process actually holding $WEB_PORT.
  # A leaked server is worse than an untidy one here: the next run's `--strictPort`
  # vite exits, curl still gets an answer from the STALE server, and the suite
  # reports on a proxy pointed somewhere else entirely. So kill the process GROUP
  # (see the setsid below), then make sure the port is really free.
  [[ -n "$WEB_PID" ]] && kill -- -"$WEB_PID" 2>/dev/null || true
  [[ -n "$API_PID" ]] && kill "$API_PID" 2>/dev/null || true
  command -v fuser >/dev/null 2>&1 && fuser -k "$WEB_PORT/tcp" 2>/dev/null || true
  rm -rf "$BASE"
}
trap cleanup EXIT

# Refuse to run against someone else's server. Without this the suite silently
# grades a process it did not start (and did not seed).
if curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$WEB_PORT/" 2>/dev/null; then
  echo "❌ port $WEB_PORT is already serving — stop it first (this test must own it)" >&2
  exit 1
fi

fail() {
  echo "❌ FAIL: $1"
  echo "--- api log ---"; tail -20 "$BASE/api.log" 2>/dev/null || true
  echo "--- web log ---"; tail -20 "$BASE/web.log" 2>/dev/null || true
  exit 1
}

# POST a GraphQL query through the Vite dev proxy (same path the browser uses).
gql() {
  curl -s "http://127.0.0.1:$WEB_PORT/graphql" -H 'content-type: application/json' \
    --data "$(printf '{"query":%s}' "$(printf '%s' "$1" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')")"
}

echo "=== build graphql-api ==="
( cd "$ROOT" && cargo build -p graphql-api >/dev/null 2>&1 ) || fail "cargo build failed"

echo "=== seed store with two records (one ready @ threshold 2, one pending) ==="
ID_READY="$(printf 'a%.0s' {1..63})1"
ID_PEND="$(printf 'b%.0s' {1..63})2"
cat > "$STORE/$ID_READY.json" <<EOF
{"submission_id":"0x$ID_READY","debridge_id":"0x$(printf 'c%.0s' {1..63})3","amount":"100000000000000000000","chain_id_from":1337,"chain_id_to":1338,"nonce":0,"receiver":"0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","auto_params":"0x","native_sender":"0x","signatures":[{"signer":"0x1111111111111111111111111111111111111111","signature":"0xaa"},{"signer":"0x2222222222222222222222222222222222222222","signature":"0xbb"}]}
EOF
cat > "$STORE/$ID_PEND.json" <<EOF
{"submission_id":"0x$ID_PEND","debridge_id":"0x$(printf 'd%.0s' {1..63})4","amount":"5000000000000000000","chain_id_from":1338,"chain_id_to":1337,"nonce":7,"receiver":"0x000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","auto_params":"0x","native_sender":"0x","signatures":[{"signer":"0x3333333333333333333333333333333333333333","signature":"0xcc"}]}
EOF

echo "=== boot graphql-api --dir (threshold 2) ==="
"$ROOT/target/debug/graphql-api" --bind "$API_BIND" --dir "$STORE" --threshold 2 >"$BASE/api.log" 2>&1 & API_PID=$!
for i in $(seq 1 40); do curl -s "http://$API_BIND/health" >/dev/null 2>&1 && break; sleep 0.2; done
curl -s "http://$API_BIND/health" | grep -q ok || fail "graphql-api did not come up"

echo "=== install web deps (if needed) ==="
[[ -d "$WEB/node_modules/vite" ]] || ( cd "$WEB" && bun install >/dev/null 2>&1 ) || fail "bun install failed"

echo "=== boot vite dev server (proxy -> $API_BIND) ==="
# VITE_PROXY_TARGET is the name vite.config.ts actually reads. This used to
# say GRAPHQL_API_URL, which vite ignores — so the proxy fell back to its
# default :8088 and this "hermetic" test quietly queried whatever stack was
# already running, seeded store and all assertions notwithstanding.
# setsid puts vite in its own process group so cleanup can kill the whole
# chain (bunx + node), not just the wrapper.
setsid bash -c "cd '$WEB' && VITE_PROXY_TARGET='http://$API_BIND' exec bunx vite --port $WEB_PORT --strictPort" >"$BASE/web.log" 2>&1 & WEB_PID=$!
for i in $(seq 1 60); do curl -s "http://127.0.0.1:$WEB_PORT/" >/dev/null 2>&1 && break; sleep 0.3; done

echo
echo "########## 1. SPA index.html is served ##########"
HTML=$(curl -s "http://127.0.0.1:$WEB_PORT/")
echo "$HTML" | grep -q 'id="root"' || fail "dashboard index.html not served"
echo "$HTML" | grep -q '/src/main.tsx' || fail "entry script missing from index.html"
echo "✅ index.html served with #root + entry script"

echo
echo "########## 2. stats query through the proxy ##########"
OUT=$(gql 'query { stats { total signed ready threshold routes { chainIdFrom chainIdTo count } } }')
echo "$OUT"
echo "$OUT" | grep -q '"total":2' || fail "stats.total != 2"
echo "$OUT" | grep -q '"ready":1'  || fail "stats.ready != 1 (one record meets threshold 2)"
echo "$OUT" | grep -q '"threshold":2' || fail "stats.threshold != 2"
echo "✅ stats: total=2 ready=1 threshold=2, routes present"

echo
echo "########## 3. submissions query (exact UI field set) ##########"
OUT=$(gql 'query { submissions { submissionId chainIdFrom chainIdTo nonce amount receiver signatureCount meetsThreshold status executed signatures { signer signature } } }')
echo "$OUT" | head -c 400; echo
echo "$OUT" | grep -q "\"0x$ID_READY\"" || fail "ready record missing from submissions"
echo "$OUT" | grep -q '"status":"READY"' || fail "ready record not reported READY"
echo "$OUT" | grep -q '"status":"PENDING"' || fail "pending record not reported PENDING"
echo "$OUT" | grep -q '"meetsThreshold":true' || fail "meetsThreshold:true missing"
echo "$OUT" | grep -q '"executed":null' || fail "executed should be null without a --gate"
echo "✅ submissions: READY + PENDING statuses, meetsThreshold, executed=null (no gate)"

echo
echo "########## 4. filtered submissions (chainIdTo:1338) ##########"
OUT=$(gql 'query { submissions(filter:{chainIdTo:1338}) { submissionId chainIdTo } }')
echo "$OUT"
echo "$OUT" | grep -q "\"0x$ID_READY\"" || fail "filter dropped the matching record"
echo "$OUT" | grep -q "\"0x$ID_PEND\"" && fail "filter leaked a non-matching record"
echo "✅ filter chainIdTo:1338 returns only the matching route"

echo
echo "########## 5. by-id lookup: hit, miss, malformed ##########"
OUT=$(gql "query { submission(submissionId:\"0x$ID_READY\") { amount status } }")
echo "$OUT" | grep -q '"amount":"100000000000000000000"' || fail "by-id hit failed"
MISS=$(gql "query { submission(submissionId:\"0x$(printf 'f%.0s' {1..64})\") { amount } }")
echo "$MISS" | grep -q '"submission":null' || fail "absent id should resolve null"
BAD=$(gql 'query { submission(submissionId:"../leak") { amount } }')
echo "$BAD" | grep -qi '32-byte hex hash' || fail "malformed id should return a validation error"
echo "✅ by-id: hit returns record, absent->null, malformed->validation error"

echo
echo "================= RESULT ================="
echo "✅ PASS: dashboard is served and all UI queries resolve through the dev proxy"
echo "=========================================="
