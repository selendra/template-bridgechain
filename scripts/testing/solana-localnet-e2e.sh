#!/usr/bin/env bash
# Real EVM -> Solana claim on a LOCAL Solana validator (Docker).
#
# Prereqs (one-time):
#   * a solana-test-validator container listening on 127.0.0.1:8899, e.g.:
#       docker run -d --name solana-node -p 8899:8899 -p 8900:8900 \
#         solanalabs/solana:v1.18.26 solana-test-validator --ledger /tmp/ledger --quiet
#   * the BPF program built:  bash scripts/testing/build-solana.sh
#   * the WSL Solana CLI + a native (nvm) node toolchain installed.
#
# This deploys solana_gate.so, then drives tools/localnet/claim.mjs: create an SPL
# mint + program-owned vault + receiver account, Init the gate with 3 EVM
# validators (threshold 2), and submit a Claim carrying 2 real validator
# signatures — asserting the SPL is released on-chain and a replay is rejected.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SOLANA_BIN="$HOME/.local/share/solana/install/active_release/bin"
NODE_BIN="${NODE_BIN:-$(ls -d "$HOME"/.nvm/versions/node/*/bin 2>/dev/null | sort -V | tail -1 || true)}"
export PATH="$SOLANA_BIN:$NODE_BIN:$HOME/.cargo/bin:$PATH"
RPC="http://127.0.0.1:8899"

echo "== validator =="
solana config set --url "$RPC" >/dev/null
for i in $(seq 1 30); do solana cluster-version --url "$RPC" >/dev/null 2>&1 && break || sleep 2; done
solana cluster-version --url "$RPC"

echo "== payer =="
KEY="$HOME/.config/solana/id.json"
[ -f "$KEY" ] || solana-keygen new --no-bip39-passphrase --silent --outfile "$KEY"
for i in 1 2 3 4 5; do solana airdrop 100 >/dev/null 2>&1 && break || sleep 2; done
echo "payer $(solana address) balance $(solana balance)"

echo "== deploy =="
solana program deploy "$ROOT/crates/solana-gate/target/deploy/solana_gate.so" --output json > /tmp/deploy.json
PROGRAM_ID="$(python3 -c 'import json;print(json.load(open("/tmp/deploy.json"))["programId"])')"
echo "programId $PROGRAM_ID"

echo "== build ix helper =="
( cd "$ROOT" && cargo build -p bridge-solana --example gen_claim_ix --offline >/dev/null 2>&1 )

echo "== localnet deps =="
[ -d "$ROOT/tools/localnet/node_modules" ] || ( cd "$ROOT/tools/localnet" && bun install >/dev/null 2>&1 )

echo "== run claim =="
node "$ROOT/tools/localnet/claim.mjs" "$PROGRAM_ID" "$ROOT/target/debug/examples/gen_claim_ix" "$KEY"
