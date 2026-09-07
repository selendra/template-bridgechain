#!/usr/bin/env bash
# Live integration test for the GraphQL API against a REAL running bridge.
#
# Boots anvil A+B, the HTTP sig-store, 2 validators (threshold 2) and the keeper,
# then points graphql-api at the live sig-store (--store-url, the REMOTE backend).
# Sends two real A->B transfers and proves graphql-api reflects the genuine,
# validator-signed records: stats, filters, by-id, and meetsThreshold all track
# live state. Also checks read-only mode, GraphiQL, health, and bad-query handling.
#
# Run from anywhere:  bash scripts/testing/graphql-live.sh
set -euo pipefail

export PATH="$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"
source "$(dirname "${BASH_SOURCE[0]}")/_deploy_gate.sh"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTRACTS="$ROOT/contracts"
LOGS="$ROOT/.e2e-logs"
mkdir -p "$LOGS"
rm -f "$LOGS"/val*-gql-state.json

# Postgres-backed sig-store (the file-per-id store was retired). Runs in Docker.
PG_NAME=bridge-pg-gql
PG_PORT=5433
DATABASE_URL="postgres://bridge:bridge@127.0.0.1:${PG_PORT}/bridge?sslmode=disable"

ACC0=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
KEY0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
V1=0x70997970C51812dc3A010C7d01b50e0d17dc79C8;  V1K=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
V2=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC;  V2K=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
KEEPER_KEY=0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a
RECEIVER=0x976EA74026E726554dB657fA54763abd0C3a0aa9

SRC_RPC=http://127.0.0.1:8545
DST_RPC=http://127.0.0.1:8546
SRC_CHAIN=1337; DST_CHAIN=1338
STORE_URL=http://127.0.0.1:8080
GQL_BIND=127.0.0.1:8088;  GQL=http://$GQL_BIND/graphql
RO_BIND=127.0.0.1:8089;   RO=http://$RO_BIND/graphql   # read-only instance
AMOUNT=100000000000000000000
THRESHOLD=2

declare -a PIDS=()
track() { PIDS+=("$1"); }
cleanup() {
  echo "--- cleaning up ---"
  for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done
  pkill -f "anvil --chain-id" 2>/dev/null || true
  docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

deployed_to() { grep deployedTo | grep -oE '0x[0-9a-fA-F]{40}' | head -1; }
bal() { cast call "$1" "balanceOf(address)(uint256)" "$2" --rpc-url "$3" | awk '{print $1}'; }
gqlq() { curl -s "$1" -H 'content-type: application/json' \
          --data "$(printf '{"query":%s}' "$(printf '%s' "$2" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')")"; }
field() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
fail() { echo "❌ FAIL: $1"; echo "--- graphql.log ---"; tail -20 "$LOGS/graphql-live.log" 2>/dev/null || true;
         echo "--- sig-store.log ---"; tail -10 "$LOGS/sig-store-gql.log" 2>/dev/null || true; exit 1; }

echo "=== build ==="
( cd "$ROOT" && cargo build -p validator -p keeper -p sig-store -p graphql-api >/dev/null 2>&1 )

echo "=== boot anvil A+B ==="
pkill -f "anvil --chain-id" 2>/dev/null || true; sleep 1
anvil --chain-id $SRC_CHAIN --port 8545 >"$LOGS/anvil-src-gql.log" 2>&1 & track $!
anvil --chain-id $DST_CHAIN --port 8546 >"$LOGS/anvil-dst-gql.log" 2>&1 & track $!
for url in $SRC_RPC $DST_RPC; do
  for i in $(seq 1 50); do cast chain-id --rpc-url "$url" >/dev/null 2>&1 && break; sleep 0.2; done
done

cd "$CONTRACTS"; forge build >/dev/null
echo "=== deploy (2 validators, threshold $THRESHOLD) ==="
TOKEN_SRC=$(forge create src/TestToken.sol:TestToken --rpc-url "$SRC_RPC" --private-key $KEY0 --broadcast --json --constructor-args Test TST 2>/dev/null | deployed_to)
# Gate is UUPS: implementation + GateProxy running initialize(). See _deploy_gate.sh.
GATE_SRC=$(deploy_gate "$SRC_RPC" "$KEY0" "[$V1,$V2]" "$THRESHOLD")
TOKEN_DST=$(forge create src/TestToken.sol:TestToken --rpc-url "$DST_RPC" --private-key $KEY0 --broadcast --json --constructor-args Test TST 2>/dev/null | deployed_to)
GATE_DST=$(deploy_gate "$DST_RPC" "$KEY0" "[$V1,$V2]" "$THRESHOLD")

PREFIX=$(printf '%064x' $SRC_CHAIN); DEBRIDGE_ID=$(cast keccak "0x${PREFIX}${TOKEN_SRC#0x}")
cast send "$TOKEN_SRC" "mint(address,uint256)" $ACC0 900000000000000000000 --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null
cast send "$TOKEN_SRC" "approve(address,uint256)" "$GATE_SRC" 900000000000000000000 --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null
cast send "$TOKEN_DST" "mint(address,uint256)" "$GATE_DST" 900000000000000000000 --rpc-url $DST_RPC --private-key $KEY0 >/dev/null
cast send "$GATE_DST" "setLocalToken(bytes32,address)" "$DEBRIDGE_ID" "$TOKEN_DST" --rpc-url $DST_RPC --private-key $KEY0 >/dev/null

echo "=== start Postgres in Docker ($PG_NAME on :$PG_PORT) ==="
docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
docker run -d --name "$PG_NAME" \
  -e POSTGRES_USER=bridge -e POSTGRES_PASSWORD=bridge -e POSTGRES_DB=bridge \
  -p ${PG_PORT}:5432 postgres:16-alpine >/dev/null
for i in $(seq 1 60); do
  docker exec "$PG_NAME" pg_isready -U bridge -d bridge >/dev/null 2>&1 && break
  sleep 0.5; [[ $i == 60 ]] && fail "Postgres did not become ready"
done

echo "=== boot Postgres-backed sig-store + validators + keeper ==="
# --allow-unauthenticated: local demo on 127.0.0.1, no tokens to distribute.
# The binary now refuses to serve an open store without being told to.
SIG_STORE_BIND=127.0.0.1:8080 DATABASE_URL="$DATABASE_URL" "$ROOT/target/debug/sig-store" --allow-unauthenticated >"$LOGS/sig-store-gql.log" 2>&1 & track $!
for i in $(seq 1 60); do curl -s "$STORE_URL/health" >/dev/null 2>&1 && break; sleep 0.25; done
curl -s "$STORE_URL/health" | grep -q ok || fail "sig-store did not come up"

write_vcfg() { cat > "$1" <<EOF
[source]
chain_id = $SRC_CHAIN
rpcs = ["$SRC_RPC"]
gate = "$GATE_SRC"
start_block = 0
block_confirmation = 0
allow_zero_confirmation = true   # anvil is instant-final; a real chain MUST set block_confirmation
poll_interval_ms = 300
max_block_range = 1000
state_file = "$3"

[signer]
private_key = "$2"

[store]
url = "$STORE_URL"
EOF
}
write_vcfg "$ROOT/val1-gql.toml" "$V1K" "$LOGS/val1-gql-state.json"
write_vcfg "$ROOT/val2-gql.toml" "$V2K" "$LOGS/val2-gql-state.json"
cat > "$LOGS/keeper-gql.toml" <<EOF
[target]
chain_id = $DST_CHAIN
rpc = "$DST_RPC"
gate = "$GATE_DST"
poll_interval_ms = 300

[keeper]
private_key = "$KEEPER_KEY"

[store]
url = "$STORE_URL"
EOF
"$ROOT/target/debug/validator" "$ROOT/val1-gql.toml" >"$LOGS/val1-gql.log" 2>&1 & track $!
"$ROOT/target/debug/validator" "$ROOT/val2-gql.toml" >"$LOGS/val2-gql.log" 2>&1 & track $!
"$ROOT/target/debug/keeper"    "$LOGS/keeper-gql.toml" >"$LOGS/keeper-gql.log" 2>&1 & track $!
sleep 1

echo "=== boot graphql-api against the LIVE sig-store (remote backend) ==="
# Main instance knows the destination gate, so it can report on-chain executed/status.
"$ROOT/target/debug/graphql-api" --bind "$GQL_BIND" --store-url "$STORE_URL" --threshold $THRESHOLD \
  --gate "$DST_CHAIN=$DST_RPC,$GATE_DST" --allow-mutations \
  >"$LOGS/graphql-live.log" 2>&1 & track $!
# a second instance in default READ-ONLY mode (no --allow-mutations, no --gate)
"$ROOT/target/debug/graphql-api" --bind "$RO_BIND" --store-url "$STORE_URL" --threshold $THRESHOLD \
  >"$LOGS/graphql-ro.log" 2>&1 & track $!
for i in $(seq 1 40); do curl -s "http://$GQL_BIND/health" >/dev/null 2>&1 && break; sleep 0.25; done
curl -s "http://$GQL_BIND/health" | grep -q ok || fail "graphql-api did not come up"
curl -s "http://$RO_BIND/health"  | grep -q ok || fail "read-only graphql-api did not come up"
echo "✅ both API instances up"

echo
echo "########## send two real A->B transfers ##########"
send_one() { cast send "$GATE_SRC" "send(address,uint256,uint256,bytes,bytes)" \
  "$TOKEN_SRC" $AMOUNT $DST_CHAIN "$RECEIVER" "0x" --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null; }
send_one   # nonce 0
send_one   # nonce 1

echo "=== wait until graphql-api sees 2 ready records (via the remote backend) ==="
READY=0
for i in $(seq 1 80); do
  OUT=$(gqlq "$GQL" 'query { stats { total ready } }')
  T=$(echo "$OUT" | field 'd["data"]["stats"]["total"]' 2>/dev/null || echo x)
  R=$(echo "$OUT" | field 'd["data"]["stats"]["ready"]' 2>/dev/null || echo x)
  [[ "$T" == "2" && "$R" == "2" ]] && { READY=1; break; }
  sleep 0.5
done
[[ "$READY" == "1" ]] || fail "graphql-api never reported 2 ready records (got total=$T ready=$R)"
echo "✅ stats via remote backend: total=2 ready=2"

echo
echo "=== CHECK: receiver actually paid on-chain (sanity that records are real) ==="
PAID=0
for i in $(seq 1 60); do
  [[ "$(bal "$TOKEN_DST" "$RECEIVER" "$DST_RPC")" == "200000000000000000000" ]] && { PAID=1; break; }
  sleep 0.5
done
[[ "$PAID" == "1" ]] || fail "receiver not paid 2x — records aren't from a real claim (got $(bal "$TOKEN_DST" "$RECEIVER" "$DST_RPC"))"
echo "✅ receiver paid 200e18 (records reflect genuine claims)"

echo
echo "=== CHECK: on-chain status — the API now distinguishes READY from EXECUTED ==="
# This is the fix: ready (sigs collected) != executed (claimed on-chain). The API
# reads the destination gate's executed(submissionId), so a consumer asks the API
# for the truth instead of polling the chain blind.
EX=0
for i in $(seq 1 40); do
  OUT=$(gqlq "$GQL" 'query { submissions(filter:{chainIdTo:1338}) { executed status } }')
  ALLEXEC=$(echo "$OUT" | field 'all(s["executed"] is True and s["status"]=="EXECUTED" for s in d["data"]["submissions"])' 2>/dev/null || echo False)
  [[ "$ALLEXEC" == "True" ]] && { EX=1; break; }
  sleep 0.5
done
echo "$OUT"
[[ "$EX" == "1" ]] || fail "API never reported executed=true / status=EXECUTED for the claimed transfers"
echo "✅ main instance: executed=true, status=EXECUTED (matches the on-chain claim)"

echo
echo "=== CHECK: instance WITHOUT --gate reports executed=null, status=READY ==="
OUT=$(gqlq "$RO" 'query { submissions(filter:{chainIdTo:1338}) { executed status meetsThreshold } }')
echo "$OUT"
[[ "$(echo "$OUT" | field 'all(s["executed"] is None for s in d["data"]["submissions"])')" == "True" ]] || fail "no-gate instance should report executed=null"
[[ "$(echo "$OUT" | field 'all(s["status"]=="READY" for s in d["data"]["submissions"])')" == "True" ]] || fail "no-gate instance should fall back to status=READY"
echo "✅ no-gate instance: executed=null, status=READY (no on-chain RPC -> falls back to signatures)"

echo
echo "=== CHECK: submissions(filter A->B) returns 2, each with 2 sigs + meetsThreshold ==="
OUT=$(gqlq "$GQL" 'query { submissions(filter:{chainIdFrom:1337, chainIdTo:1338}) { submissionId signatureCount meetsThreshold chainIdFrom chainIdTo nonce } }')
echo "$OUT"
[[ "$(echo "$OUT" | field 'len(d["data"]["submissions"])')" == "2" ]] || fail "expected 2 A->B submissions"
[[ "$(echo "$OUT" | field 'all(s["signatureCount"]==2 for s in d["data"]["submissions"])')" == "True" ]] || fail "each record should carry 2 signatures"
[[ "$(echo "$OUT" | field 'all(s["meetsThreshold"] for s in d["data"]["submissions"])')" == "True" ]] || fail "all should meet threshold"
[[ "$(echo "$OUT" | field 'sorted(s["nonce"] for s in d["data"]["submissions"])')" == "[0, 1]" ]] || fail "expected nonces 0 and 1"
echo "✅ 2 records, 2 sigs each, meetsThreshold=true, nonces [0,1]"

echo
echo "=== CHECK: submission(by real id) round-trips through remote GET /submissions/:id ==="
SID=$(echo "$OUT" | field 'd["data"]["submissions"][0]["submissionId"]')
OUT2=$(gqlq "$GQL" "query { submission(submissionId:\"$SID\") { submissionId signatureCount chainIdTo } }")
[[ "$(echo "$OUT2" | field 'd["data"]["submission"]["submissionId"]')" == "$SID" ]] || fail "by-id mismatch for $SID"
[[ "$(echo "$OUT2" | field 'd["data"]["submission"]["chainIdTo"]')" == "1338" ]] || fail "by-id wrong chainIdTo"
# well-formed but absent id -> null
ABSENT="0x$(printf 'f%.0s' {1..64})"
OUT3=$(gqlq "$GQL" "query { submission(submissionId:\"$ABSENT\") { submissionId } }")
[[ "$(echo "$OUT3" | field 'd["data"]["submission"]')" == "None" ]] || fail "absent id should be null"
# malformed id -> validation error (never a backend lookup)
OUT4=$(gqlq "$GQL" 'query { submission(submissionId:"0x00") { submissionId } }')
echo "$OUT4" | grep -qi '32-byte hex hash' || fail "malformed id should be rejected with a validation error"
echo "✅ by-id round-trips ($SID), absent -> null, malformed -> error"

echo
echo "=== CHECK: filters that should match nothing ==="
OUT=$(gqlq "$GQL" 'query { submissions(filter:{chainIdTo:9999}) { submissionId } }')
[[ "$(echo "$OUT" | field 'len(d["data"]["submissions"])')" == "0" ]] || fail "chainIdTo=9999 should match nothing"
OUT=$(gqlq "$GQL" 'query { submissions(filter:{minSignatures:99}) { submissionId } }')
[[ "$(echo "$OUT" | field 'len(d["data"]["submissions"])')" == "0" ]] || fail "minSignatures=99 should match nothing"
echo "✅ empty-result filters return []"

echo
echo "=== CHECK: read-only instance refuses the mutation ==="
OUT=$(gqlq "$RO" 'mutation { submitSignature(input:{submissionId:"0x00", debridgeId:"0x00", amount:"1", chainIdFrom:1, chainIdTo:2, nonce:0, receiver:"0x00", autoParams:"0x", nativeSender:"0x", signer:"0x00", signature:"0x00"}) { submissionId } }')
echo "$OUT"
echo "$OUT" | grep -qi 'error' || fail "read-only instance should reject mutations"
[[ "$(echo "$OUT" | field 'd.get("data")' 2>/dev/null || echo None)" == "None" ]] || fail "read-only mutation must not return data"
# and the read-only instance still serves queries fine
[[ "$(gqlq "$RO" 'query { stats { total } }' | field 'd["data"]["stats"]["total"]')" == "2" ]] || fail "read-only instance can't query"
echo "✅ read-only mode: mutation refused, queries still work"

echo
echo "=== CHECK: GraphiQL served at / and a malformed query fails gracefully ==="
curl -s "http://$GQL_BIND/" | grep -qi 'graphiql' || fail "GraphiQL not served at /"
BAD=$(gqlq "$GQL" 'query { thisFieldDoesNotExist }')
echo "$BAD" | grep -qi 'error' || fail "unknown field should return a GraphQL error"
[[ "$(curl -s -o /dev/null -w '%{http_code}' "http://$GQL_BIND/health")" == "200" ]] || fail "health not 200"
echo "✅ GraphiQL at /, bad query -> graceful error, /health 200"

echo
echo "================= RESULT ================="
echo "✅ PASS: graphql-api works end-to-end over the LIVE sig-store (remote backend):"
echo "   • reflects genuine validator-signed records (stats/filters/by-id)"
echo "   • meetsThreshold/ready track real 2-of-2 claims (receiver paid 200e18)"
echo "   • read-only mode refuses mutations but serves queries"
echo "   • GraphiQL + health + graceful errors on bad input"
echo "=========================================="
