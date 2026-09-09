# Operations

How to run the stack, configure a node, hold the keys, and deploy.

This document is written from the code.
Where it and the sources disagree, the sources are right and this is a bug.
Read [`architecture.md`](./architecture.md) first if you have not; this one assumes you know what the processes do.

---

## 1. The processes

Eight crates, five of them binaries.

| Binary | What it needs | What breaks without it |
| --- | --- | --- |
| `sig-store` | Postgres (or a directory) | Nothing works. It is the bulletin board every other process reads. |
| `validator` | source RPC, a signing key, the store | No transfer is ever attested. One per independent operator. |
| `keeper` | target RPC, a funded key, the store | Nothing is ever submitted on-chain. Anyone can run one; it is permissionless. |
| `indexer` | Postgres, RPC per chain | History, stuck detection, and **the entire refund lifecycle**. It is the only writer of `refund_status`. |
| `graphql-api` | the store (read scope only) | The frontend has no backend. Holds no database credential: history comes back through the sig-store. |

The dependency that catches people out is the refund one.
A refund needs the indexer running, because the keeper's refund loop only ever sees candidates the store has already nominated, and the sweep that nominates them (`bridge_db::Db::sweep_refund_eligible`) is called from the indexer and nowhere else.

`Dockerfile` builds all five binaries and `docker-compose.yml` deploys all of them, so the shipped stack advances refunds and serves the frontend on its own.

The processes coordinate only through the sig-store — there are no direct connections between them, and in particular validators have no peers. Section 5 covers spreading them across machines; `architecture.md` §4.7 covers why that topology is safe.
Note that `graphql-api` is the one service with no `DATABASE_URL`: it reads the indexer's history over the sig-store's read scope, not from Postgres, so do not hand it a database URL when running it by hand either.

---

## 2. Running it locally

### 2.1 The scripted way

`scripts/testing/` holds the end-to-end harnesses.
They boot their own anvil chains, deploy, wire, run the Rust processes, and assert an outcome.
Each resolves its own root, so they run from anywhere.

They need Foundry (`forge`, `anvil`, `cast`) and `cargo` on `PATH`.

```bash
bash scripts/testing/e2e.sh          # one transfer across two chains, end to end
bash scripts/testing/phase6.sh       # failover, resume, operator API, nonce sequencing
bash scripts/testing/phase7.sh       # 3 validators, threshold 2, sig-store, recovery
bash scripts/testing/refund-e2e.sh   # the two-phase cancel-then-refund protocol
bash scripts/testing/db-e2e.sh       # allowlists and history against Postgres
```

Start with `e2e.sh`.
If it passes, the toolchain is sound and the rest will run.

Two scripts do not currently work, for reasons unrelated to paths.
`build-solana.sh` calls `scripts/testing/_detect_ed2024.py`, and `solana-localnet-e2e.sh` needs `tools/localnet/`.
Both were deleted in commit `525b109` and neither has been restored.

### 2.2 The compose way

```bash
docker compose up -d anvil-src anvil-dst postgres sig-store
bash docker/deploy.sh                                   # deploy + wire both chains
docker compose up -d validator1 validator2 validator3 keeper
```

`docker/deploy.sh` deploys `TestToken` then `Gate` from anvil account 0 on a fresh chain, so the addresses are deterministic and already baked into `docker/configs/*.toml`.
It asserts that the deployed addresses match the baked ones and refuses to continue if they do not, which is the check that catches a non-fresh chain.

Then send a transfer:

```bash
cast send 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512 \
  'send(address,uint256,uint256,bytes,bytes)' \
  0x5FbDB2315678afecb367f032d93F642f64180aa3 100000000000000000000 1338 \
  0x976EA74026E726554dB657fA54763abd0C3a0aa9 0x \
  --rpc-url http://127.0.0.1:8545 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
```

Override the shared sig-store secret, which defaults to `dev-local-bridge-token`:

```bash
SIG_STORE_TOKEN=$(openssl rand -hex 32) docker compose up -d
```

`SIG_STORE_TOKEN` is the legacy all-scopes secret: whoever holds it can read, sign, relay and edit the allowlist, and the service logs a warning when it is set. It is fine for a throwaway local stack. For anything else, give each service the narrowest one instead — `SIG_STORE_VALIDATOR_TOKEN`, `SIG_STORE_KEEPER_TOKEN`, `SIG_STORE_READER_TOKEN`, `SIG_STORE_ADMIN_TOKEN` — so a leak from one component cannot write on behalf of the others. `scripts/bridge-from-json.sh` generates the four separately when `sig_store.tokens.generate_if_unset` is set.

### 2.3 Frontend

```bash
bash scripts/testing/run-dev.sh      # graphql-api + vite, detached
```

In dev, `vite.config.ts` proxies `/graphql` and `/health` to the API.
In production the frontend must be served same-origin with the API, or built with `VITE_API` pointing at it.
There is no production serving story in compose.

---

## 3. Configuring a validator

Reference: `crates/validator/src/config.rs`.
Working examples: `docker/configs/val1.toml`.

```toml
[[sources]]                        # repeatable; one block per chain to watch
chain_id         = 1337
rpcs             = ["http://rpc-a", "http://rpc-b"]   # ordered failover list
gate             = "0x…"
start_block      = 0
block_confirmation = 12            # SEE BELOW
poll_interval_ms = 1000
max_block_range  = 1000
state_file       = "/data/val1-state.json"

[signer]                           # see section 6
keystore = "/run/secrets/validator-keystore.json"
keystore_password_file = "/run/secrets/keystore-password"

[store]
url = "http://sig-store:8080"      # or dir = "…" for a local file store

[api]                              # optional operator API
bind  = "127.0.0.1:9090"
token = "…"                        # or the VALIDATOR_API_TOKEN env var

[refund]                           # optional; omit and this node never attests refunds
timeout_secs     = 3600
poll_interval_ms = 15000
block_confirmation = 64            # SEE BELOW
[[refund.destinations]]
chain_id = 1338
rpcs     = ["http://rpc-dst"]
gate     = "0x…"
```

What `Config::load` rejects at startup, so you find out immediately rather than in production:

- no `[[sources]]` at all
- two sources with the same `chain_id`, or sharing a `state_file` (two scan loops would clobber one cursor)
- a `[refund]` block with no destinations, or duplicate destination chain ids
- `[refund] block_confirmation = 0` without `allow_zero_confirmation = true`
- a `[refund]` block with a file-backed `[store]`, because the unclaimed-timeout gate lives in the DB-backed sweep and the file store does not have one

### 3.1 The two finality buffers

There are two `block_confirmation` settings. Both are now enforced the same way: `Config::load` refuses to start at `0` unless you set `allow_zero_confirmation = true` alongside it, and both structs carry `#[serde(deny_unknown_fields)]`, so a misspelled opt-in (`allow_zero_confirmations`, with the trailing `s`) is a startup error rather than a silently-ignored no-op that leaves the buffer at zero.

**`[[sources]] block_confirmation`** bounds how close to the tip you will *sign*.
Signing a `Sent` event at the chain tip lets a source reorg erase the deposit *after* validators have signed and the keeper has already released destination liquidity — a double-spend of bridge funds.
Set it above the source chain's maximum reorg depth.

**`[refund] block_confirmation`** bounds how close to the tip you will *attest a refund*.
A refund on the source chain is irreversible and is authorised solely on having read `cancelled == true` on the destination.
If that read is at the chain tip and the destination later reorgs the cancel away, the original claim signatures become live again, and the transfer is paid on the destination *and* refunded on the source.
Set it above the **destination** chain's maximum reorg depth.

`allow_zero_confirmation = true` is only ever correct on an instant-finality dev chain such as anvil. Never set it against a real network.

### 3.2 Catch-up pacing

`catchup_poll_interval_ms` is optional and applies only while a scanner is **behind** — when the last range hit `max_block_range` and confirmed history is still unread. It defaults to `poll_interval_ms`, which is the conservative choice.

The arithmetic that matters is `blocks/s = max_block_range ÷ poll_interval`. On a fast chain behind a capped `eth_getLogs`, recovering from a few hours of downtime can take longer than the downtime did, and reading back-to-back is what fixes that.

But how fast a scanner *may* read is a property of the **endpoint**, not of the backlog. On a shared rate-limited provider, back-to-back reads consume the compute budget that the GraphQL API's pool reads and the indexer are also drawing on, and the symptom is 429s across unrelated services rather than a slow validator. Lower it only for an endpoint you know can take it — your own node, or a public RPC with a generous cap — and leave it unset everywhere else.

### 3.3 Operator API

```
GET  /status
POST /pause
POST /resume
POST /rescan {"from_block": N}
```

Each optionally scoped to one chain. The token comes from `[api] token` or the `VALIDATOR_API_TOKEN` env var.

**With neither set, `/pause`, `/resume` and `/rescan` are not mounted at all** — the process serves read-only `/status` and logs why. `pause` takes a validator out of quorum and survives a restart, so an open halt button is a one-request denial of service against the signer set; a missing secret mount used to be indistinguishable from a correct deployment except in the log. For local dev, `allow_unauthenticated = true` in the `[api]` block restores the old behaviour explicitly.

The scanner pauses itself on a nonce gap, a nonce replay, or a `submissionId` mismatch — each of which means an RPC is lying or events were missed.
A pause is a real safety stop and needs a human to look before `/resume`.

**The pause survives a restart.** `Runtime.paused` and its reason are serialized to `state_file`, and a validator that comes up paused logs a warning naming the reason. Restarting is not a way to clear the condition — diagnose it, then `/resume`.

---

## 4. Configuring a keeper

Reference: `crates/keeper/src/config.rs`.

```toml
[[targets]]                        # repeatable; claims + cancels, on the DESTINATION
chain_id         = 1338
rpc              = "http://rpc-dst"
gate             = "0x…"
poll_interval_ms = 1000

[[sources]]                        # repeatable; refunds, on the chain funds were locked on
chain_id         = 1337
rpc              = "http://rpc-src"
gate             = "0x…"
poll_interval_ms = 1000

[keeper]                           # the funded gas-payer key; same shape as [signer], see section 6
keystore = "/run/secrets/keeper-keystore.json"
keystore_password_file = "/run/secrets/keystore-password"

[store]
url = "http://sig-store:8080"
```

What `Config::load` rejects at startup:

- no `[[targets]]` at all (a legacy single `[target]` is folded into the list)
- two `[[targets]]`, or two `[[sources]]`, naming the same `chain_id` — two loops on one chain would submit from the same account and contend on its nonce
- any unknown field, in either block

Three things to know when running one:

- **Targets and sources are different lists.** Claims and cancels happen on the destination; refunds happen where the funds were locked. A keeper with only `[[targets]]` never submits a refund, and nothing warns you at runtime — the transfers simply sit in the candidate list.
- **The key must stay funded on every listed chain.** A claim loop whose account is out of gas logs `claim failed` each tick and delivers nothing.
- **A chain in both lists gets a startup warning.** The two loops share one account and can briefly contend on its nonce under load. It is self-healing, but for a busy bidirectional corridor run the two roles as separate processes, or give them separate accounts.

Running more than one keeper is safe and is the normal way to get redundancy: each `try_*` re-reads on-chain state first, so the loser of a race sees `executed == true` and does nothing.

---

## 5. Running validators on separate machines

A real deployment puts each validator on hardware its operator controls. Nothing about the process changes when you do — validators have no peer connections to configure, because they have no peers. See `architecture.md` §4.7 for why the topology is hub-and-spoke and why the hub is not trusted.

**Ready-made stacks: [`docker/production/`](../docker/production/README.md)** — one compose file per machine role (store, indexer, validator, keeper, api, solana-relayer), with `.env` and config templates, TLS termination, and a `preflight.sh` for the keystore-permission trap. This section explains the requirements; that directory implements them, and [`RUNBOOK.md`](../docker/production/RUNBOOK.md) covers running and troubleshooting each stack individually.

### 5.1 What actually changes

On each validator host, point the store at the shared sig-store and hand it the sign-scope credential:

```toml
[store]
url = "https://sig-store.internal.example.com"    # was http://127.0.0.1:8080
```

```bash
export SIG_STORE_VALIDATOR_TOKEN=…                # read by StoreBackend::remote_for_role
```

On the sig-store host, bind publicly and open the port:

```json
"sig_store": {
  "bind": "0.0.0.0:8080",
  "url":  "https://sig-store.internal.example.com"
}
```

HTTPS works without a code change — the workspace `reqwest` keeps its default features, so native-tls is compiled in. That is the whole configuration difference.

### 5.2 What you must get right

**The link must be encrypted.** `sig-store` is plain axum HTTP with bearer tokens; it terminates no TLS of its own. A token crossing the public internet in cleartext is a stolen sign credential. Put it behind nginx or Caddy with a certificate, or run the validators into it over WireGuard. Do not expose `0.0.0.0:8080` directly.

**Each validator needs genuinely independent RPCs.** This is the one that quietly destroys the security model. Three validators reading Sepolia through the same provider key are not three independent observers — they are one observer signing three times, and a provider that serves a wrong log makes all three sign it. The threshold then counts signatures, not independent confirmations. Independent providers per operator is the point of separate machines at all; run your own node where the corridor's value justifies it.

**Each needs its own key and its own `state_file`.** `Config::load` enforces uniqueness of `state_file` *within* one process, but nothing stops two hosts from mounting the same path off shared storage. Keep state local to the machine.

**Set `block_confirmation` per chain, per operator.** It is not a fleet-wide constant. A validator on a slower or less trusted RPC should sit further from the tip; nothing forces operators to agree, and a more conservative one simply signs later.

**Clock skew does not matter, and should not.** The refund loop derives transfer age from block timestamps read off the chain, never from the host's wall clock (`validator/src/refund.rs:117`). Do not add a wall-clock-based timeout on top of it.

### 5.3 The credential gap to close first

`crates/sig-store/src/main.rs` exposes a single `--validator-token` / `SIG_STORE_VALIDATOR_TOKEN`, so today every validator shares one sign credential. `Auth` itself is a `HashMap<String, HashSet<Scope>>` and already supports many tokens per scope — making the flag repeatable gives each operator a credential you can revoke individually.

Until that lands, understand what one leaked token does and does not buy an attacker. It does **not** let them forge signatures: `Db::upsert_signature` ecrecovers every signature and `Gate._verifySignatures` counts only keys in the on-chain validator set. It does let them write to the store unattributably and spam it, and it means revoking one operator's access means rotating the token for everyone.

### 5.4 Checking that a remote validator is actually working

```bash
curl -s https://sig-store.example.com/health                      # no auth required
curl -s -H "Authorization: Bearer $SIG_STORE_READER_TOKEN" \
     https://sig-store.example.com/submissions | jq '.[0].signatures'
```

The signer addresses in that array are the ground truth for who is participating. A validator that is running, unpaused, and caught up but whose address never appears is not reaching the store — check the token and the URL before suspecting the scanner.

Then, on the validator host:

```bash
curl -s -H "Authorization: Bearer $VALIDATOR_API_TOKEN" http://127.0.0.1:9090/status
```

`paused` with a reason means a real safety stop that survived a restart, not a transient error. Read §3.3 before resuming it.

---

## 6. Key custody

Reference: `crates/bridge-core/src/signer.rs`.
The same `[signer]` / `[keeper]` shape applies to both node types.

The bridge's safety rests on validators holding *distinct, well-guarded* keys.
The Gate needs a threshold of them, so no single key is ever enough, but that only holds if each operator guards its own.
A raw key in a TOML turns "leak the config" into "leak the key".

Exactly one key source must be set.
Both zero and more than one fail loudly at startup.

```toml
[signer]
# 1. Encrypted keystore (Web3 Secret Storage / `cast wallet`). Recommended.
keystore = "/run/secrets/validator-keystore.json"
keystore_password_file = "/run/secrets/keystore-password"   # OR
keystore_password_env  = "KEYSTORE_PASSWORD"                # OR (dev) keystore_password = "…"

# 2. Raw key via env var. Keeps the secret out of the file (Docker/systemd secret).
private_key_env = "VALIDATOR_PRIVATE_KEY"

# 3. Raw key inline. DEV ONLY; logged as a warning at startup.
private_key = "0x…"
```

Secrets are redacted from the config's debug output.

Other secrets in the system:

| Secret | Where it comes from | Notes |
| --- | --- | --- |
| sig-store bearer tokens | `SIG_STORE_{VALIDATOR,KEEPER,READER,ADMIN}_TOKEN` | One per role (scoped). The store **fails closed**: with none configured it refuses to bind unless started with `--allow-unauthenticated`, the explicit dev opt-out. Both launchers generate a random token per role per run into `RUN_DIR/tokens.env` (0600); the compose generator writes them to the stack's gitignored `.env`. |
| Postgres password | `PG_PASSWORD` (run.config) / `database.docker.password` (bridge.config.json) | Random per run dir when unset, persisted in `RUN_DIR/tokens.env` and re-applied to the volume on every start; `DATABASE_URL` is derived from it. The container is bound to `127.0.0.1` only (M-10). |
| validator operator API token | `[api] token` or `VALIDATOR_API_TOKEN` | Unset means `/pause`, `/resume`, and `/rescan` are unauthenticated. |
| Postgres URL | `DATABASE_URL` or config | `sig-store` and `indexer` only. `graphql-api` deliberately has none — it is the internet-facing service, and a direct connection would sit outside the scope model in `bridge_core::auth`. |

`docker/configs/*.toml` carry inline private keys.
They are anvil's well-known development keys, so nothing there is at risk today, and `.dockerignore` excludes them from the Docker build context — as it does every generated stack (`docker/*/configs`, `.env`, `keys`), `.solana/`, `config/deployments/`, the `*.local` configs and the root-level `*.toml` the test suites write, so `COPY . .` in the builder stage cannot bake a real key into an image layer.
The pattern is still the one to break before a real key goes anywhere near it.

**RPC urls are secrets too.** A hosted provider's url *is* its API key. Both launchers therefore keep the url the services dial (`rpc_url` / `rpcs[0]`) separate from the one the GraphQL API may hand to browsers (`public_rpc_url`, from `PUBLIC_RPCS[chain]` in `run.config` or `chains[].public_rpc` in `bridge.config.json`). The API serves only the public one — `null` when there is none, and the UI then reads through the wallet's provider — and `--production` refuses to start a registry with a chain missing it. The generated compose file references RPC urls as `${RPC_<chain>}` variables resolved from the stack's gitignored `.env`; `docker/*/docker-compose.yml` is gitignored since the H-4 leak, and the leaked key (`alch_0…`) must be treated as burned and rotated at the provider.

---

## 7. Deploy checklist

The production deploy path is `scripts/deploy-from-json.sh` with `"profile": "production"`, which runs `contracts/script/DeployProd.s.sol`: it asserts `EXPECTED_CHAIN_ID == block.chainid`, ≥ 3 validators with a strict-majority threshold, appoints the guardian, and starts the two-step ownership handover to the multisig — then the script lists every peer chain (`setSupportedChain`), registers every corridor (`setLocalToken`), calls `seal()`, and refuses to report success unless every gate is sealed and every peer listed. `DeploySwap.s.sol` / `DeployXSwap.s.sol` remain local demos (threshold-1 gates, unrestricted-mint tokens) and `docker/deploy.sh` is anvil-specific.
The `local` profile refuses any chain id outside the dev/testnet allowlist in the script unless `--allow-local-profile-on-chain` is passed (M-12).

This is the checklist those scripts encode. Every line is an assertion to make *after* deploying, not a step to trust.

**Gate, per chain**

1. `owner` is the intended cold key, and `pendingOwner` is zero.
   Ownership transfer is two-step; an unaccepted transfer leaves the old owner in control.
2. `isValidator[v]` is true for exactly the intended set, and false for everything else.
   Enumerate it; do not assume the constructor argument was right.
3. `threshold` is the intended value and is greater than 1.
   A threshold of 1 means a single signature releases funds.
4. **`guardian` is set and is not `address(0)`.**
   `DeployProd` calls `setGuardian` and reverts if it is zero or equal to the owner; the `local` profile leaves it optional, which is one reason that profile is refused on real chains.
   The guardian can pause but never unpause and never move funds, so it is safe to hold hot.
   Without it, the only key that can stop the bridge in an incident is the owner key, which is the one you most want to keep cold.
5. `paused` is false.
6. `supportedChain[chainId]` is true for every chain this gate may `send` to, and false for everything else.
   `send` reverts `UnsupportedChain` otherwise (M-3), so a missing peer is a dead corridor; a spurious one lets users lock funds towards a chain with no gate.
7. `tokenOf[debridgeId]` is set for every asset the gate must pay out, and the gate holds liquidity in each.
   A transfer to an unregistered asset cannot be claimed.
8. **`isSealed()` is true**, and it became true *before* the gate was funded.
   Sealing ends the setup phase: from then on a new corridor needs `scheduleGovernance(setLocalTokenActionId(debridgeId, token))`, the 48 h `GOVERNANCE_DELAY`, and execution within the 7-day `SCHEDULE_GRACE`. That delay is what stops a stolen owner key from pointing a real corridor at a worthless token and draining the pot in one block (H-1). An unsealed gate holding funds is that drain waiting.

**SwapPool, per chain, if deployed**

7. `oracle` is the intended key and is separate from `owner`.
8. `maxPriceDeviationBps` is set, and you understand that it is a per-call cap with no time gate, so N calls in one block walk the price N times (M5).
9. `stable` is the intended token and its price is `PRICE_ONE`.

**Off-chain**

10. Each validator has a distinct key, and no two validators share a `state_file`.
    The compose stack mounts one `val-state` volume across all three; the paths inside it differ, which is safe today and one typo away from two validators sharing a nonce cursor.
11. `block_confirmation` is set explicitly on every source and every refund destination, above that chain's reorg depth.
    Remember the source-chain one is unvalidated.
12. `SIG_STORE_TOKEN` is a real secret, not the compose default.
13. `indexer` is running, or refunds silently do not exist.
14. `refund_timeout_secs` on the indexer matches `[refund] timeout_secs` on the validators.
    The indexer's value is the one that gates anything; the validator's is advisory and exists so the intended window is visible in one place.

**Verify the deploy end to end before announcing it.**
Send a dust transfer through the corridor and watch it claim.
Then strand one deliberately, on an unregistered asset, and watch it cancel and refund.
The refund path is the one that is easiest to ship broken, because nothing about a working transfer exercises it.

---

## 8. Incident response

**Stop the bleeding.**
`pause()` on the Gate, callable by owner or guardian.
`unpause()` is owner-only, deliberately, so a compromised guardian can cause a denial of service and nothing worse.

Know what pausing stops.
`whenNotPaused` guards `send`, `claim` and `cancel` — but **not** `refund`.
A refund only returns already-locked funds to the address that locked them, and only after validators have attested a destination burn, so it can create no new exposure and stays open during a pause.
A `cancel` is frozen, though, so a transfer that is not already burned on the destination cannot begin recovery until you unpause.

Pausing the **SwapPool** is a separate decision with its own consequence: cross-chain swaps in flight cannot complete their destination leg, so `SwapRouter.finalize` defers them (see §9) rather than settling. If the pause outlasts `FALLBACK_GRACE`, those users receive the carrier stable instead of the token they asked for.

**Stop a validator signing.**
`POST /pause` on its operator API, or stop the process.
Signatures already in the store stay there; pausing prevents new ones.

**A validator paused itself.**
Read the log for `MISSED_NONCE`, `DUPLICATED_NONCE`, or a `submissionId` mismatch.
All three mean an RPC is lying or events were missed.
Find out which before resuming, and use `POST /rescan {"from_block": N}` rather than restarting the process, because a restart clears the pause flag without clearing the cause.

**A transfer is stuck.**
Check `status` in the DB.
A reverted `claim()` is *not* recorded as claimed — the keeper's `confirm` helper refuses to report a mined-but-reverted transaction as success, precisely so a failed claim cannot exclude the transfer from the refund sweep.

If a transfer has a full quorum and still will not claim, check the signature encodings. The store now stores every signature in the low-`s` / `v ∈ {27,28}` form the Gate accepts, and the keeper re-normalises anything older on the way out, but a store restored from a pre-fix backup that is read by a pre-fix keeper will produce `ECDSAInvalidSignatureS` on every attempt.

---

## 9. Security parameters and their delays

These are the knobs whose values *are* security properties. None of them is a latency setting.

| Parameter | Where | Default | What it bounds |
|---|---|---|---|
| `UPGRADE_DELAY` | `Gate` (constant) | 48 h | Notice before a new implementation can be installed |
| `GOVERNANCE_DELAY` | `Gate` (constant) | 48 h | Notice before a validator is ADDED or the threshold is LOWERED |
| `maxPriceAge` | `SwapPool` (owner) | 1 day | How stale a price may be before the pool refuses to trade it |
| `maxPriceDeviationBps` + `minPriceUpdateInterval` | `SwapPool` (owner) | 10 % / 1 h | How fast the oracle may move a price |
| `FALLBACK_GRACE` | `SwapRouter` (constant) | 6 h | How long a blocked destination swap is retried before the carrier stable is delivered instead |
| `block_confirmation` | validator / indexer | per chain | Reorg depth the scanner is safe against |
| rate limit / body cap | `sig-store`, `graphql-api` | 50 rps, 256 kB | What one credential can cost the service |

### 9.1 Rotating a validator

Adding a validator and lowering the threshold both grant signing power, so both wait out `GOVERNANCE_DELAY`. Removing one and raising the threshold both take power away, so both are immediate — that asymmetry is what keeps incident response fast.

```bash
# 1. queue it (emits GovernanceScheduled with the readyAt timestamp)
cast send $GATE "scheduleGovernance(bytes32)" \
  $(cast call $GATE "addValidatorActionId(address)(bytes32)" $NEW_VALIDATOR)
# 2. wait 48h, then
cast send $GATE "setValidator(address,bool)" $NEW_VALIDATOR true
```

`cancelScheduledGovernance(bytes32)` drops a queued action, and the guardian may call it as well as the owner.

**The one case that needs planning.** A removal cannot drop `validatorCount` below `threshold`. So evicting a validator from a set where `validatorCount == threshold` (a 3-of-3, say) means lowering the threshold first, which does wait out the delay. Size the set with headroom — a 2-of-3 can evict immediately — and use `pause()` if you want everything stopped in the meantime. A minority validator cannot move funds on its own, so the wait costs safety nothing.

### 9.2 Deploying the store

`sig-store` refuses to bind with no bearer token configured, rather than serving an open store. Set at least one of `SIG_STORE_{VALIDATOR,KEEPER,READER,ADMIN}_TOKEN`; `--allow-unauthenticated` is the explicit dev opt-out. `graphql-api` takes `--production` to drop GraphiQL and introspection. The `chains` query serves each network's `public_rpc_url` (as `rpcUrl`, or `null`) and never its `rpc_url`; under `--production` a chain without a public url is a startup error. Every gate (EVM by `0x` address, Solana by base58 program id) and every swap pool (`swap_pool`) is registered from the chains file and read over that entry's `rpc_url`, so no url appears on the API's command line at all.

### 9.3 Wiring a gate: supportedChain, corridors, seal

Every gate, in this order, before it holds funds:

```bash
cast send $GATE "setSupportedChain(uint256,bool)" $PEER_CHAIN_ID true   # once per peer; instant, reversible
cast send $GATE "setLocalToken(bytes32,address)" $DEBRIDGE_ID $LOCAL_TOKEN  # once per inbound corridor; write-once
cast send $GATE "seal()"                                                  # last; irreversible
```

`scripts/run.sh` and `scripts/deploy-from-json.sh` do all three (`SEAL_GATES` / `gate.seal`, default `true`; `EXTRA_SUPPORTED_CHAINS` / `gate.extra_supported_chains` for peers outside the config, e.g. the Solana chain id) and assert the result. After `seal()`, adding a corridor is a governance action:

```bash
AID=$(cast call $GATE "setLocalTokenActionId(bytes32,address)(bytes32)" $DEBRIDGE_ID $LOCAL_TOKEN)
cast send $GATE "scheduleGovernance(bytes32)" $AID
# 48h later, within 7 days:
cast send $GATE "setLocalToken(bytes32,address)" $DEBRIDGE_ID $LOCAL_TOKEN
```

The same shape on the Solana gate (`gate-admin`): `set-validator` (add) and `set-threshold` (lower) print the action id they need; `schedule-governance <action-id>`, wait 48 h, then the call itself; `governance-status` lists what is pending and `cancel-governance <action-id>` (owner or guardian) drops it. The Solana gate has **no ownership transfer** — whoever signs `init` owns it — so the production profile requires `solana.init.owner` to name the multisig-controlled key, to match `solana.payer_keypair`, and to come with `solana.init.guardian`. Deploy the program and the relayer together: `SentRecord` grew by 8 bytes (legacy records still decode).
