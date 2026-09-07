#!/usr/bin/env bash
# Smoke test for the GraphQL API. Boots graphql-api over a dir-backed store seeded
# with a couple of records, then exercises every query (submissions + filters,
# submission-by-id, stats) and the submitSignature mutation's trust boundary.
#
# Self-contained: no anvil needed (the read path never touches a chain). Uses a
# real signed record so the mutation's signature check has something valid to add.
#
# Run from anywhere:  bash scripts/testing/graphql.sh
set -euo pipefail

export PATH="$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOGS="$ROOT/.e2e-logs"; mkdir -p "$LOGS"
STORE="$(mktemp -d)"
BIND=127.0.0.1:8088
URL="http://$BIND/graphql"
THRESHOLD=2

cleanup() { [[ -n "${API_PID:-}" ]] && kill "$API_PID" 2>/dev/null || true; rm -rf "$STORE"; }
trap cleanup EXIT

# A tiny GraphQL POST helper: gql '<query>' -> raw JSON response.
gql() { curl -s "$URL" -H 'content-type: application/json' \
          --data "$(printf '{"query":%s}' "$(printf '%s' "$1" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')")"; }
field() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
fail() { echo "❌ FAIL: $1"; echo "--- api log ---"; tail -20 "$LOGS/graphql.log" || true; exit 1; }

echo "=== build ==="
( cd "$ROOT" && cargo build -p graphql-api >/dev/null 2>&1 )

echo "=== seed store: two A->B records + one A->C record ==="
# Two records destined for chain 1338 (one with 2 sigs => ready, one with 1 => not),
# and one for chain 1339 with 0 sigs. submissionIds are arbitrary for the READ path.
write_rec() { # id from to nonce nsigs
  local sigs="[]"
  [[ "$5" == "1" ]] && sigs='[{"signer":"0xaaaa000000000000000000000000000000000001","signature":"0x01"}]'
  [[ "$5" == "2" ]] && sigs='[{"signer":"0xaaaa000000000000000000000000000000000001","signature":"0x01"},{"signer":"0xbbbb000000000000000000000000000000000002","signature":"0x02"}]'
  cat > "$STORE/$1.json" <<EOF
{"submission_id":"0x$1","debridge_id":"0xdead","amount":"100","chain_id_from":$2,"chain_id_to":$3,"nonce":$4,"receiver":"0xcccc000000000000000000000000000000000003","auto_params":"0x","native_sender":"0x","signatures":$sigs}
EOF
}
# Real 32-byte submissionIds (64 hex digits) — the store validates this shape.
A1="$(printf 'a%.0s' {1..63})1"   # ready, A->B
A2="$(printf 'a%.0s' {1..63})2"   # signed, not ready, A->B
B1="$(printf 'b%.0s' {1..63})1"   # unsigned, A->C
ABSENT="$(printf 'f%.0s' {1..64})" # well-formed but not in the store
write_rec "$A1" 1337 1338 0 2   # ready
write_rec "$A2" 1337 1338 1 1   # signed, not ready
write_rec "$B1" 1337 1339 0 0   # unsigned, A->C

echo "=== boot graphql-api (--dir, threshold=$THRESHOLD) ==="
"$ROOT/target/debug/graphql-api" --bind "$BIND" --dir "$STORE" --threshold $THRESHOLD --allow-mutations \
  >"$LOGS/graphql.log" 2>&1 & API_PID=$!
for i in $(seq 1 40); do curl -s "http://$BIND/health" >/dev/null 2>&1 && break; sleep 0.25; done
curl -s "http://$BIND/health" | grep -q ok || fail "API never came up"
echo "✅ API up"

echo
echo "=== Q1: stats ==="
OUT=$(gql 'query { stats { total signed ready threshold routes { chainIdFrom chainIdTo count } } }')
echo "$OUT"
[[ "$(echo "$OUT" | field 'd["data"]["stats"]["total"]')"  == "3" ]] || fail "stats.total != 3"
[[ "$(echo "$OUT" | field 'd["data"]["stats"]["signed"]')" == "2" ]] || fail "stats.signed != 2"
[[ "$(echo "$OUT" | field 'd["data"]["stats"]["ready"]')"  == "1" ]] || fail "stats.ready != 1"
echo "✅ stats: total=3 signed=2 ready=1"

echo
echo "=== Q2: submissions filtered to A->B, ready only ==="
OUT=$(gql 'query { submissions(filter:{chainIdTo:1338, ready:true}) { submissionId signatureCount meetsThreshold } }')
echo "$OUT"
[[ "$(echo "$OUT" | field 'len(d["data"]["submissions"])')" == "1" ]] || fail "expected exactly 1 ready A->B record"
[[ "$(echo "$OUT" | field 'd["data"]["submissions"][0]["submissionId"]')" == "0x$A1" ]] || fail "wrong record returned"
[[ "$(echo "$OUT" | field 'd["data"]["submissions"][0]["meetsThreshold"]')" == "True" ]] || fail "meetsThreshold should be true"
echo "✅ filter chainIdTo=1338 + ready=true -> just one record"

echo
echo "=== Q3: submission(by id) — known, absent, and malformed ==="
OUT=$(gql "query { submission(submissionId:\"0x$B1\") { chainIdTo signatureCount } }")
[[ "$(echo "$OUT" | field 'd["data"]["submission"]["chainIdTo"]')" == "1339" ]] || fail "by-id lookup wrong"
# well-formed but not present -> null (not found)
OUT=$(gql "query { submission(submissionId:\"0x$ABSENT\") { submissionId } }")
[[ "$(echo "$OUT" | field 'd["data"]["submission"]')" == "None" ]] || fail "absent id should be null"
# malformed (not a 32-byte hash) -> validation error, never a filesystem lookup
OUT=$(gql 'query { submission(submissionId:"0xnope") { submissionId } }')
echo "$OUT" | grep -qi '32-byte hex hash' || fail "malformed id should be rejected with a validation error"
echo "✅ by-id: record for known, null for absent, error for malformed"

echo
echo "=== Q4: mutation trust boundary rejects a forged record ==="
# Well-formed fields, but submissionId is NOT keccak(params) => the id<->params
# binding must reject it (IdMismatch), proving the write path runs the same
# trust boundary as the sig-store, not just shape validation.
SID="0x$(printf '0%.0s' {1..63})1"          # 32-byte hash, value 1
DID="0x$(printf 'de%.0s' {1..32})"          # 32-byte hash, all 0xde
DOM="0x$(printf 'a1%.0s' {1..32})"          # 32-byte deployment domain
# bridgeDomain is a REQUIRED input field (it is part of the submissionId
# preimage). Omitting it makes the server reject at schema validation, BEFORE
# the trust boundary runs — which is how this assertion silently went vacuous:
# it saw "rejected" and passed without ever exercising the id<->params check.
# Supply a well-formed value so the rejection has to come from the recompute.
OUT=$(gql "mutation { submitSignature(input:{submissionId:\"$SID\", bridgeDomain:\"$DOM\", debridgeId:\"$DID\", amount:\"100\", chainIdFrom:1337, chainIdTo:1338, nonce:9, receiver:\"0xcccc000000000000000000000000000000000003\", autoParams:\"0x\", nativeSender:\"0x\", signer:\"0xaaaa000000000000000000000000000000000001\", signature:\"0x01\"}) { submissionId } }")
echo "$OUT"
echo "$OUT" | grep -qi 'does not match\|recomputed' || fail "mutation should have rejected on id<->params mismatch"
echo "$OUT" | grep -qi 'is required but not provided' && fail "rejected at schema validation, not at the trust boundary"
echo "✅ mutation rejected: submissionId != keccak(params) (id<->params binding holds)"

echo
echo "=== Q5: bridgeDomain is part of the id preimage, not optional decoration ==="
# Same record, domain omitted -> the schema itself must refuse it. This pins the
# field as required, so the check above can never silently go vacuous again.
OUT=$(gql "mutation { submitSignature(input:{submissionId:\"$SID\", debridgeId:\"$DID\", amount:\"100\", chainIdFrom:1337, chainIdTo:1338, nonce:9, receiver:\"0xcccc000000000000000000000000000000000003\", autoParams:\"0x\", nativeSender:\"0x\", signer:\"0xaaaa000000000000000000000000000000000001\", signature:\"0x01\"}) { submissionId } }")
echo "$OUT" | grep -qi 'bridgeDomain' || fail "omitting bridgeDomain should be refused by the schema"
echo "✅ bridgeDomain is required by the schema"

echo
echo "================= RESULT ================="
echo "✅ PASS: GraphQL API serves stats/filters/by-id and enforces the write trust boundary"
echo "=========================================="
