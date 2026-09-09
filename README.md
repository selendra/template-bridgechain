# EVM ↔ EVM + EVM ↔ Solana Bridge

An external-validator bridge built per [`docs/history/bridge-build-plan.md`](docs/history/bridge-build-plan.md),
modeled on [deBridge's `DeBridgeGate`](https://github.com/debridge-finance/debridge-contracts-v1/tree/main/contracts/transfers).
On-chain gate in **Solidity**; off-chain validator + keeper + sig-store in **Rust**.

Start with [`docs/architecture.md`](docs/architecture.md) — it describes the system
as built, from the sources.

## Quick start — run the whole stack

One config file, one command. Brings up two chains, deploys + wires the gates
(and a SwapPool), and starts Postgres + sig-store + validators + keeper +
indexer + refund loop + the GraphQL backend + the React frontend:

```bash
bash scripts/run.sh          # edit scripts/run.config first to taste
# open http://localhost:5173   (Bridge + Swap views, live)
bash scripts/stop.sh         # tear it all down
```

Everything is driven by [`scripts/run.config`](scripts/run.config): chains and
RPCs (local anvil or your own), validator keys + threshold, ports, and feature
toggles (`ENABLE_SWAP` / `ENABLE_INDEXER` / `ENABLE_REFUND`). Point it at an
existing deployment with `LOCAL_ANVIL=false` / `DEPLOY=false` and the `*_ADDR`
fields. Generated per-service configs, pidfiles, logs and the run's secrets
(`tokens.env`: sig-store tokens + the random Postgres password) land in
`RUN_DIR` (default `~/.local/state/selendra-bridge/run`, 0700). Re-running is
idempotent (it stops the previous run first; `stop.sh` kills only the pids it
recorded — `--force` for the old pattern kills). Every gate is wired
`setSupportedChain` -> `setLocalToken` -> `seal()` and verified before the
services start; `EXTRA_SUPPORTED_CHAINS` lists destinations outside the mesh
(the Solana gate), `PUBLIC_RPCS` names the browser-safe RPC the UI is served
(the keyed one never is). The MetaMask network details are printed at the end;
the deployer key is not.

> `scripts/testing/` holds the phase/e2e demos (`e2e.sh`, `phase7.sh`,
> `refund-relayer-e2e.sh`, …); `scripts/run.sh` is the everyday launcher.

### JSON configs (deploy and run, separately)

The same stack, driven by JSON instead of one bash config, with deployment split
from operation — so you can redeploy without restarting, or restart without
redeploying:

```bash
bash scripts/deploy-from-json.sh config/deploy.config.json   # gates, tokens, corridors
bash scripts/bridge-from-json.sh config/bridge.config.json   # validators, keeper, indexer, API
```

The deploy step writes every address it produced into `config/deployments/` and
patches them into the runtime config, so no addresses are copied by hand. A
`production` profile enforces the real safety parameters (≥ 3 validators, a
strict-majority threshold, a guardian, ownership to a multisig, every gate
sealed with every peer listed); the `local` profile is refused on any chain id
outside the dev/testnet allowlist in the script. The Solana leg
is covered too — its own `solana` block in each file deploys/initializes the gate
program and runs the relayers, sharing the EVM validator set and `bridge_domain`.
Field reference: [`config/README.md`](config/README.md).

```
.
├── contracts/                # Foundry: Gate, BridgeHash, SwapPool, SwapRouter + tests
│   └── fixtures/             # submissionId fixtures shared with Rust (Phase 3)
├── crates/
│   ├── bridge-core/          # the SACRED hashing (submissionId) + store + Gate ABI bindings
│   ├── bridge-db/            # Postgres source of truth (history + allowlists), sqlx
│   ├── bridge-solana/        # host-side Solana model: hash, verify, gate, relayer adapters
│   ├── validator/            # scan → recompute → sign → store
│   ├── keeper/               # collect ≥ threshold sigs → submit claim / cancel / refund
│   ├── sig-store/            # Phase 7: HTTP signature store (axum)
│   ├── indexer/              # on-chain events → DB; the only writer of refund_status
│   ├── graphql-api/          # read API the frontend talks to
│   └── solana-gate/          # deployable BPF program; EXCLUDED from the workspace
├── frontend/                 # React 18 + Vite + TypeScript dashboard
├── docker/                   # Phase 7: compose configs + host deploy helper
├── Dockerfile                # builds validator/keeper/sig-store
├── docker-compose.yml        # sig-store + 3 validators + keeper + postgres + 2 anvils
├── scripts/testing/          # e2e and integration scripts (run from anywhere)
│   ├── e2e.sh                # Phase 5: 2 anvils, deploy, run validator+keeper, assert a transfer
│   ├── phase6.sh             # Phase 6: failover, resume, operator API, nonce sequencing
│   └── phase7.sh             # Phase 7: 3 validators, threshold 2, sig-store, safety + recovery
└── docs/                     # cross-cutting docs; component READMEs live with their code
```

## Architecture in one paragraph

`send()` locks an ERC-20 on the source gate and emits `Sent(submissionId, …)`. The
**validator** scans the source chain at `latest - block_confirmation`, independently
recomputes the `submissionId` (`bridge-core`, byte-identical to `BridgeHash.sol`)
under the `bridgeDomain` it reads from the gate itself, checks the nonce is
sequential for that corridor, and — only on an exact match — signs the EIP-191
digest and writes the signature to the store. The **keeper** reads the store,
discards any signature whose signer is not in the gate's current validator set,
and once ≥ threshold survive submits `claim()` to the target gate, which re-derives
the `submissionId`, verifies the signatures against its validator set, guards
against replay (`executed[]`), and releases funds.

Validators never talk to each other — the store is the only thing they share, and
it is untrusted infrastructure: it re-verifies everything it is handed, and the
Gate verifies it all again on-chain. See [`docs/architecture.md`](docs/architecture.md)
§4.2–4.4 for how the validator and keeper work, and §4.7 (with
[`docs/operations.md`](docs/operations.md) §5) for running them on separate machines.

## The sacred hash

`submissionId = keccak256(abi.encodePacked(SUBMISSION_PREFIX, bridgeDomain,
debridgeId, chainIdFrom, chainIdTo, amount, receiver, nonce))` (with an auto-params
tail when an execution payload is attached). `bridgeDomain` binds the id to one
deployment generation: without it an id commits only to (asset, chain pair, amount,
receiver, nonce) and never to the gates themselves, so a previous deployment's
quorum signatures stay valid against a freshly deployed gate on the same chain pair
— which also restarts `nonceTo` at 0. It is defined once in
`contracts/src/BridgeHash.sol` and reproduced in `crates/bridge-core/src/lib.rs`.
Phase 3 locks the two together:

```bash
cd contracts && forge test --match-contract GenFixtures   # Solidity writes fixtures
cd ..        && cargo test -p bridge-core                  # Rust must reproduce them
```

## Governance is delayed, in both directions that grant power

The Gate is UUPS behind a proxy, and an implementation swap waits out
`UPGRADE_DELAY` (48 h) after `scheduleUpgrade`. The same delay covers the two
changes that buy the same power without touching the code — **adding a
validator** and **lowering the threshold** — because an owner who could do those
in one transaction could sign a claim for every corridor and empty the gate with
no notice at all, which made the upgrade timelock decorative.

Removing a validator, raising the threshold, `pause()` and cancelling a queued
action all stay immediate: every direction that shrinks an attacker's reach is
what incident response needs, and only granting power waits. See
[`docs/operations.md`](docs/operations.md) §9 for the rotation runbook and the one
case (`validatorCount == threshold`) that needs planning.

## Run the tests

```bash
# contracts (Phases 1–3): send, claim security suite, hash fixtures
cd contracts && forge test -vv

# cross-language hash equivalence (Phase 3)
cargo test -p bridge-core
```

## Run the end-to-end transfer (Phase 5)

Requires `forge`/`anvil`/`cast` (Foundry) and `cargo` on PATH.

```bash
bash scripts/testing/e2e.sh
```

It starts two local chains (1337 @ :8545, 1338 @ :8546), deploys `Gate`+`TestToken`
on both, pre-funds the target gate and registers the asset, runs the Rust validator
and keeper, performs `send()` of 100 TST on 1337, and asserts the receiver is paid
100 TST on 1338 and that the replay guard (`executed[submissionId]`) is set. Logs
land in `.e2e-logs/`.

## Hardened validator (Phase 6)

The validator is now the real node, not a prototype:

- **Multi-RPC failover** (`provider::Failover`) — an ordered list of endpoints; every
  call tries the active one and rotates to the next on error. A `chainId` guard drops
  endpoints reporting the wrong network at startup.
- **Finality buffer** — only processes blocks up to `latest - block_confirmation`.
- **Resumable cursor** (`state::Runtime`) — `{last_block, nonces}` is persisted to a
  JSON state file (atomic temp-then-rename). On restart it resumes from `last_block + 1`
  without re-signing or skipping events.
- **Sequential-nonce enforcement** — per `chainIdTo`, a gap (`MISSED_NONCE`) or replay
  (`DUPLICATED_NONCE`) **pauses** the scanner instead of signing. An `submissionId`
  mismatch (lying RPC) also pauses. Decision logic is unit-tested (`cargo test -p validator`).
- **Operator API** (`api`, optional `[api]` block) — `GET /status`,
  `POST /pause`, `POST /resume`, `POST /rescan {"from_block":N}`.

Demonstrate every mechanism end-to-end:

```bash
bash scripts/testing/phase6.sh
```

## N validators + threshold (Phase 7)

The trust model is now real: **multiple independent validators**, each with its own
key, all POSTing to the **`sig-store` HTTP service**; the keeper submits `claim()`
only once **≥ threshold distinct** signatures exist. The Gate enforces the threshold
on-chain (signatures sorted ascending by signer, deduped).

`sig-store` (axum) keeps the same `SubmissionRecord` shape as the file store and is
backed by a directory on disk:

```
GET  /health
POST /submissions        # upsert a record + signature; dedupe by signer
GET  /submissions        # all records (keeper polls)
GET  /submissions/:id    # one record
```

Validator/keeper pick the backend in `[store]`: `dir = "…"` (local file) **or**
`url = "http://sig-store:8080"` (HTTP). Demonstrate 3 validators / threshold 2,
the 1-of-3 safety case, and recovery:

```bash
bash scripts/testing/phase7.sh
```

## Docker

For a **distributed production deployment** — each component on its own machine —
see [`docker/production/`](docker/production/README.md): one compose stack per
role, with the secret-distribution table and cross-machine wiring.

The single-host stack below is for local development.

## Docker (Phase 7)

The off-chain stack is dockerized — `sig-store` + 3 validators + 1 keeper, plus two
anvil chains for local bring-up. Gate addresses in `docker/configs/*.toml` are
anvil's deterministic deploy addresses, so deployment is reproducible:

```bash
docker compose up -d anvil-src anvil-dst sig-store
bash docker/deploy.sh                                  # deploy + wire both chains
docker compose up -d validator1 validator2 validator3 keeper
```

> Not exercised in the WSL dev box used to build this (Docker Desktop WSL
> integration was off); `scripts/testing/phase7.sh` covers the same topology with local
> processes.

## Config

`validator.toml` / `keeper.toml` are generated by the scripts. Shapes:

```toml
# validator.toml
[[sources]]  chain_id, gate, start_block, block_confirmation, poll_interval_ms, max_block_range
             rpc = "http://…"                 # single endpoint (back-compat), OR
             rpcs = ["http://…", "http://…"]  # ordered failover list
             state_file = "validator-state.json"   # resumable cursor + nonce state
             catchup_poll_interval_ms = 50    # optional; only while behind — see ops §3.2
[signer]     # how this node holds its signing key — see "Key custody" below
[store]      dir = "…"   OR   url = "http://sig-store:8080"
[api]        bind = "127.0.0.1:9090"   # optional operator API
[refund]     timeout_secs, poll_interval_ms, block_confirmation
             # + one [[refund.destinations]] per chain this node can verify.
             # Omit the whole block and this validator never attests refunds.

# keeper.toml
[[targets]]  chain_id, rpc, gate, poll_interval_ms   # claims + cancels, on the DESTINATION
[[sources]]  chain_id, rpc, gate, poll_interval_ms   # refunds, where funds were locked
[keeper]     # funded gas-payer key — same custody options as [signer]
[store]      dir = "…"   OR   url = "http://sig-store:8080"
```

Both are repeatable: one validator process can watch several source chains, and one
keeper can deliver to several destinations. The singular `[source]` / `[target]`
forms still load and are folded into the lists. A keeper with no `[[sources]]` never
submits a refund; a validator with no `[refund]` block never attests one.

### Key custody

No single key can move funds on-chain — `claim()` needs a threshold of *distinct*
validator signatures. That only holds if each relayer guards its own key well, so
`[signer]` (validator) and `[keeper]` (gas payer) both accept, in order of
preference — **exactly one** source:

```toml
[signer]
# 1. Encrypted keystore (Web3 Secret Storage / `cast wallet`) — recommended.
keystore = "/run/secrets/validator-keystore.json"
keystore_password_file = "/run/secrets/keystore-password"   # OR
keystore_password_env  = "KEYSTORE_PASSWORD"                # OR (dev) keystore_password = "…"

# 2. Raw key via env var — keeps the secret out of the file (Docker/systemd secret).
private_key_env = "VALIDATOR_PRIVATE_KEY"

# 3. Raw key inline — DEV ONLY (logged as a warning; a leaked config is a leaked key).
private_key = "0x…"
```

Setting more than one source (or a keystore without a password) is rejected at
startup. Secrets are redacted from any debug output of the config.

## EVM ↔ Solana (Phase 8)

The bridge is no longer EVM-only. The protocol is chain-agnostic: the sacred
keccak `submissionId` and the EIP-191 secp256k1 validator signatures only need a
keccak and a secp256k1-recover primitive to verify — and Solana has both
(`keccak` and `secp256k1_recover` syscalls). So **the same validator set, with the
same keys, signs for both VMs** — no new signing path, no new trust assumption.

What changed:

- **`Gate.sol`** `send()` now accepts a **32-byte** receiver (a Solana pubkey /
  SPL token account) as well as a 20-byte EVM address, so an EVM→Solana transfer
  can be initiated. Any other width is still rejected.
- **`crates/bridge-solana`** — the Solana side, host-testable and alloy-free:
  `hash` (keccak `submissionId`, byte-identical to `BridgeHash.sol`), `verify`
  (`secp256k1_recover` + the ascending-signer threshold rule from
  `_verifySignatures`), the `SolanaGate` send/claim state machine, the Borsh
  instruction wire format, and the off-chain relayer adapters (scan a `Sent`
  program log; encode a `claim` instruction).
- **`crates/solana-gate`** — the deployable native Solana program: a
  syscall-based reimplementation of the above, built with `cargo build-sbf` (out
  of the host workspace; see its README).

Solana's chain id is `7565164` (deBridge's value, also used in the hash fixtures).

Verify the whole thing — no Solana runtime needed:

```bash
bash scripts/testing/solana-e2e.sh
```

It runs (1) the Foundry test for the 32-byte send path, (2) the cross-chain hash
+ signature equivalence (`bridge-solana` reproduces every fixture id and accepts
real validator signatures), and (3) a both-direction end-to-end simulation driven
by real validator signatures: EVM→Solana claim releases SPL under a 2-of-3
threshold (replay-blocked, below-threshold refused), and a Solana→Send is scanned,
independently recomputed, and its signatures pass the EVM gate's verification.

### On a real Solana validator (Docker)

The program has also been built and run against a **live local validator** —
proving the `secp256k1_recover` / `keccak` path works on-chain, not just in the
host reproduction:

```bash
# 1. local validator
docker run -d --name solana-node -p 8899:8899 -p 8900:8900 \
  solanalabs/solana:v1.18.26 solana-test-validator --ledger /tmp/ledger --quiet
# 2. build the BPF program (handles the toolchain/edition2024 dep pinning)
bash scripts/testing/build-solana.sh
# 3. deploy + drive a real EVM->Solana claim
bash scripts/testing/solana-localnet-e2e.sh
```

Step 3 deploys `solana_gate.so`, creates an SPL mint + a program-owned vault +
a receiver account, `Init`s the gate with the 3 EVM validators (threshold 2), and
submits a `Claim` carrying **2 real validator signatures**. It asserts, on-chain:
the SPL is released to the receiver, a replay is rejected, and a **1-of-3
(below-threshold) claim is refused** — no funds move without quorum. The
signatures are the exact EIP-191 secp256k1 signatures the EVM validators produce.

## Refunds — two-phase, cancel then repay

A transfer can strand: the destination gate may hold no liquidity for the asset,
the corridor may be de-listed after the funds were locked, or the target chain
may be down long enough that nobody claims. The locked funds must be
recoverable — but a refund that simply waits out a timeout is a **double-spend**:
the transfer's validator signatures still exist, so a keeper can `claim()` on the
destination in the very window the source pays the refund.

So the refund is ordered, and the ordering is enforced on-chain rather than by
any timing assumption:

```
chain B (destination)   cancel(id, cancelSigs)
                          -> executed[id] = true, cancelled[id] = true
                          -> emits Cancelled; claim(id) now reverts, forever
                                 |
                                 |  validators observe Cancelled on-chain
                                 v
chain A (source)        refund(id, refundSigs)
                          -> pays sentBy[id] (recorded at lock time)
                          -> emits Refunded
```

If a keeper delivers first, `cancel` reverts with `AlreadyExecuted` and no refund
is ever authorised. There is no interleaving that pays out twice.

**Three independent quorums.** `BridgeHash` derives `cancelId` and `refundId`
under distinct domain prefixes, so a validator's transfer signature — which
authorises *paying a transfer out* — can never be replayed to burn it or claw it
back. The store enforces the same split off-chain: attestations are verified
against their own digest, never merely against the submissionId.

**Why `sentBy`.** `nativeSender` is only folded into the submissionId when
`autoParams` is non-empty, so for a plain transfer the sender is **not** bound by
the hash and calldata could name anyone. `send()` therefore records
`sentBy[submissionId] = msg.sender`, which is both the authoritative refund
recipient and the proof that this gate really locked these funds — without it a
validator quorum could authorise a refund for a transfer that never happened
here.

**What the validators check** before attesting, all from on-chain reads at a
confirmed block (`crates/validator/src/refund.rs`):

| | condition | consequence |
|---|---|---|
| cancel | destination `executed == false` | never burn a delivered transfer |
| cancel | source `sentBy != 0` | never vote on a transfer this gate didn't send |
| refund | destination `cancelled == true` | the burn must already be on-chain |
| both | corridor's *both* ends configured | never trust the store for delivery |

The store's `refund_status`/timeout only **nominates** candidates; it authorises
nothing, so a wrong timestamp there costs at most a wasted look. Enable the loop
with a `[refund]` block on the validator and `[[sources]]` on the keeper (see
`docker/configs/`); omit them and the node simply never votes.

> **Honest limit:** the source gate cannot read the destination, so `refund()`
> does not itself verify the cancel — a valid refund quorum pays out regardless.
> What guarantees the ordering is that the quorum never *forms* until the burn is
> an observed on-chain fact. That is the same trust assumption the bridge already
> makes for `Sent`, but it means the validators' attestation rule is load-bearing,
> not a convenience.

Verify it:

```bash
cd contracts && forge test --match-contract Refund -vv   # security suite
bash scripts/testing/refund-e2e.sh                               # two live chains
```

## What's next (per the build plan)

- **P8+** deploy `solana-gate` to a **localnet** ✓ (done — `scripts/testing/build-solana.sh`
  + `scripts/testing/solana-localnet-e2e.sh`); next, a public **devnet** deploy and wiring
  the live validator/keeper to a Solana RPC (scan program logs / submit claims).
- **Refunds** on Solana — `crates/solana-gate` has no `cancel`/`refund` yet, so
  an EVM→Solana transfer still cannot be refunded (the EVM↔EVM path can).
- **P8** asset registry + wrapped-token minting (`deployId`).
- **P9** testnet soak, chaos, audit.
