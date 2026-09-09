# JSON configs

Two files, two jobs. JSON carries no comments, so this is the field reference.

| file | drives | script |
| --- | --- | --- |
| [`deploy.config.json`](deploy.config.json) | deploying + wiring the contracts | `bash scripts/deploy-from-json.sh [config]` |
| [`bridge.config.json`](bridge.config.json) | running the mesh (validators, keeper, indexer, API) | `bash scripts/bridge-from-json.sh [config]` |

They are meant to be used in that order: the deploy script writes the addresses
it produced into `config/deployments/<name>.json` **and** patches them straight
into the runtime config named by `output.update_bridge_config`, so the second
step needs no copy-paste.

```bash
bash scripts/deploy-from-json.sh config/deploy.config.json     # deploy + wire
bash scripts/bridge-from-json.sh config/bridge.config.json     # run the mesh
bash scripts/bridge-from-json.sh config/bridge.config.json --status
bash scripts/bridge-from-json.sh config/bridge.config.json --stop
```

`scripts/run.sh` + `scripts/run.config` (bash) still work and are unchanged —
these two are the JSON-driven equivalent, with deployment and operation split so
you can redeploy without restarting, or restart without redeploying.

---

## `deploy.config.json`

`bash scripts/deploy-from-json.sh [config] [--dry-run] [--no-config-update] [--redeploy] [--allow-local-profile-on-chain]`

`--dry-run` validates everything and prints the plan without sending a
transaction. `--no-config-update` skips patching the runtime config.
`--allow-local-profile-on-chain` lets the `local` profile run on a chain id that
is not in the script's `DEV_CHAIN_IDS` allowlist (anvil, Sepolia, Hoodi and the
other well-known testnets); without it that is refused, because a local-profile
gate is a hot-key-owned gate with no guardian (M-12).

| field | meaning |
| --- | --- |
| `name` | deployment label; names the output file and seeds a generated domain |
| `profile` | `"local"` or `"production"` — see the table below |
| `deployer.keystore` + `deployer.keystore_password_file` | encrypted Web3 keystore (preferred) |
| `deployer.private_key_env` | name of an env var holding the raw key |
| `deployer.private_key` | raw key inline — **dev only** |
| `gate.validators[]` | validator addresses baked into every gate. Duplicates are rejected: the Gate constructor dedupes, so `[A,B,B]` with threshold 2 would quietly ship a 2-of-2 gate |
| `gate.threshold` | signatures required to move funds |
| `gate.bridge_domain` | the mesh-generation binding, `0x` + 64 hex. Every gate in one generation shares it; a **new** deployment needs a **new** one, or the previous deployment's validator signatures replay against the fresh gates. `"auto"` derives one (local only) |
| `gate.guardian` | pause button, low trust, must differ from the owner (production) |
| `gate.owner` | multisig that receives ownership via two-step transfer (production) |
| `gate.seal` | call `seal()` on every gate once its corridors are registered (default `true`; production refuses `false`). Irreversible: afterwards a **new** corridor needs `scheduleGovernance(setLocalTokenActionId(id, token))` + 48 h — the delay that stops a stolen owner key from draining the gate through a fake corridor (H-1). Anything the deployer can no longer send (a sealed gate, a gate it does not own) is written to `governance_calls` in the output file, `scheduleGovernance` first |
| `gate.extra_supported_chains[]` | chain ids the gates may `send` to beyond `chains[]` (and the Solana chain id, which is added automatically when `solana.enabled`). `send` reverts `UnsupportedChain` for anything not listed (M-3); every chain in `chains[]` is listed on every other. The script asserts every listing at the end — hard failure under `production` |
| `chains[]` | `chain_id`, `name`, `rpc_url`; `deploy_gate: false` + `gate` reuses an existing one. The RPC's reported chain id is verified before anything is sent. `"enabled": false` parks a chain in the config — assets and pools that name it are skipped, so an unfunded chain can wait there instead of being deleted and re-added |
| `assets[].symbol/name/decimals` | the bridgeable asset |
| `assets[].deployments[]` | `chain_id` + `address`; `"auto"` deploys a fresh `TestToken` (local only) **only if `output.file` has no address recorded for it** — a re-run reuses what the last one produced. Deploying a second token silently rewires the mesh to it and orphans the liquidity in the first, so replacing one is opt-in: `--redeploy`. An explicit address must have contract code on that chain |
| `assets[].register_corridors` | wire the asset full-mesh with `setLocalToken` |
| `assets[].test_liquidity` | mint whole-token amounts to the deployer and the gate (local only) |
| `swap.pools[]` | one `SwapPool` per chain over the assets this config already deploys, so every bridged token is also swappable where it lands. `stable` names the pricing hub (listed at 1.0 by construction), `list[]` the tokens quoted against it (`price` in whole hub units), `seed` the reserves to fund, `mint_seed` whether to mint them first (test tokens only). A pool with no reserve of the OUT token quotes fine and then reverts on the swap |
| `swap.deploy` | the alternative shape: the demo `DeploySwap` script, which brings its own unrestricted-mint tokens. Local bring-up only |
| `solana` | the Solana leg — see below; `enabled: false` skips it entirely |
| `output.file` | where the produced addresses are written. Gitignored: the record repeats the RPC URLs it used, and a hosted endpoint's URL is a credential |
| `output.update_bridge_config` | runtime config to patch with gate/token/pool addresses and each chain's deploy block; `null` to skip |

### profiles

| | `local` | `production` |
| --- | --- | --- |
| gate deploy | `forge create` Gate impl + `GateProxy` | `script/DeployProd.s.sol`, which asserts every policy invariant on-chain |
| validators | ≥ 1 | ≥ 3 |
| threshold | ≥ 1 | strict majority (`> n/2`, and ≥ 2) |
| guardian / owner | optional | required; ownership goes to the multisig (two-step) |
| tokens | `"auto"` TestTokens allowed | real ERC-20 addresses only |
| test liquidity | allowed | refused |
| `bridge_domain` | `"auto"` allowed | must be pinned |
| chain ids | dev/testnet allowlist only (or `--allow-local-profile-on-chain`) | any |
| wiring | `setSupportedChain` per peer → `setLocalToken` per corridor → `seal()`, sent by the deployer | the same, sent by the deployer **while it is still the transient owner** (the handover is two-step and completes only on `acceptOwnership()`). Whatever it can no longer send — a gate it does not own, a corridor on an already-sealed gate — goes to `governance_calls` in the output file, `scheduleGovernance` first |
| post-checks | every peer listed; sealed if `gate.seal` | **hard failure** unless every gate `isSealed()` and lists every peer — do not fund a gate that failed here |
| Solana owner | payer | `solana.init.owner` required, must equal the payer, plus `init.guardian` |

After a production run the multisig must `acceptOwnership()` on every gate, then
execute any `governance_calls` in order.

### the Solana leg

Solana is not an entry in `chains[]`. It is a different VM with a different
toolchain and a separate process, so it gets its own `solana` block — but it is
the *same bridge*: the program is initialized with the same validator set,
threshold and `bridge_domain` as the EVM gates, which is what makes a
submissionId computed on one side verify on the other.

| field | meaning |
| --- | --- |
| `chain_id` | deBridge's id for Solana (`7565164`). Not a Solana concept — it is the value hashed into every submissionId, and both sides must agree |
| `rpc` / `cluster` | endpoint and a label for the log line |
| `payer_keypair` | the fee payer. It signs `solana program deploy` and every governance instruction, **and it becomes the gate's owner** — `init` requires the program's upgrade authority, and there is no ownership-transfer instruction on this side, unlike the EVM gate's two-step handover. Whichever key deploys the program governs it, for good |
| `init.owner` | the pubkey that is to own the gate — i.e. the multisig-controlled key. **Production requires it, requires it to equal the payer** (there is no handover, so the init signer *is* the owner) and refuses to run otherwise; a mismatch against an already-initialized program's owner is fatal too. Owner actions that widen trust (`set-validator` add, `set-threshold` lower) sit behind `gate-admin schedule-governance <action-id>` + 48 h (H-2); `governance-status` lists what is pending, `cancel-governance` (owner or guardian) drops it. Move the program's upgrade authority behind the same multisig/timelock (`solana program set-upgrade-authority`) — the script warns while it is the payer |
| `gate_admin_bin` / `build` | the `gate-admin` client. It lives in the `solana-relayer` crate — its own cargo project, because `solana-client` pins `zeroize <1.4` and alloy needs `^1.5`, so no EVM-side crate can host it |
| `program.deploy` / `program.program_id` / `program.so_path` | deploy `solana_gate.so` (build it with `scripts/testing/build-solana.sh`) or reuse a deployed program |
| `program.use_rpc` | send the deploy's write transactions over JSON-RPC instead of the leader's TPU. Leave it on for hosted endpoints and containerised validators: the TPU path needs gossip reachability and otherwise stalls 20s and fails |
| `init.run` | initialize the gate if it is not already. Re-running is safe — the script reads the on-chain config first and leaves an initialized gate alone |
| `init.guardian` | pause-only key (may pause, not unpause), as on the EVM side. Required under `production`, must differ from `init.owner` |
| `init.max_validators` / `max_corridors` | the config account is sized for these at init and both vectors are refused growth past them, so it can never outgrow its buffer |
| `register_corridors` | register every EVM chain in `chains[]` as a destination. `send` refuses any `chain_id_to` governance has not registered; the instruction is idempotent |
| `assets[].mint` / `.vault` | the SPL mint and the program-owned vault. **Supplied, never created here** — the vault must be an SPL account for that mint, owned by the program's `vault_authority` PDA, with no delegate and no close authority (the program rejects anything else) |
| `assets[].from_chains` | which EVM chains this asset may arrive from (`"all"` or a list). One registration per source chain, exactly as the EVM side needs one `setLocalToken` per corridor — a claim commits only to the debridgeId, and that id differs per origin |
| `assets[].swap_vault` | the SPL vault the SWAP pool uses for this mint — a different account from the bridge `vault`, owned by the swap program's own `vault_authority` PDA. The two programs share no liquidity |
| `assets[].seed_from` | a token account holding balance to seed the swap pool's reserve from |
| `assets[].debridge_id` | for a Solana-NATIVE asset, the id it is bridged under. It is registered on the program *and* mapped on every EVM gate that carries the symbol. Leave `null` for an EVM-native asset |

### the Solana swap pool

`solana.swap` deploys and configures `crates/solana-swap`, the Solana twin of
`SwapPool.sol`, so bridged assets can be swapped on Solana and not only on the
EVM chains.

| field | meaning |
| --- | --- |
| `deploy` / `program_id` / `so_path` | deploy the pool program (build it with `bash scripts/testing/build-solana.sh swap`) or reuse a deployed one. It is a SEPARATE program from the gate — a pricing bug must not be able to reach bridge liquidity |
| `hub` | which asset is the pool's unit of account. Its price is pinned at 1.0 forever and cannot be repriced |
| `list[]` | the other tokens, priced in WHOLE hub units (scaled by 1e18 internally) |
| `seed` | reserves to fund, in raw token units, taken from each asset's `seed_from` account |
| `fee_bps` / `deviation_bps` / `min_price_interval` | the fee, the largest single price move, and the cooldown between two moves of the same token — the pair bounds a compromised oracle to one capped step per interval |

Initialization is idempotent: an already-initialized pool and already-listed
tokens are left alone, so re-running only adds what is missing. The resulting
program id is written into the runtime config as another `graphql.swaps` entry —
the API tells a Solana pool from an EVM one by the address form (base58 vs `0x`),
so nothing else in the config has to declare which VM it is.

Swapping from the **browser** needs a Solana wallet (Phantom): the Swap view
switches to it automatically when the selected pool's address is a base58
program id rather than an `0x` contract, offers no approve step (an SPL transfer
is authorised by the signer), and builds the transaction locally — every account
that decides where the output lands is derived in the browser, never taken from
the API. See `frontend/src/wallet/solana.ts`.

Set `solana.include_in_registry: true` in the runtime config if you want the UI
to show it: an SPL mint carries no on-chain symbol (that lives in Metaplex
metadata), so the API takes token names from the registry and otherwise shows a
truncated address.

The script refuses to touch a program whose on-chain `bridge_domain` differs from
this deployment's: that program belongs to an earlier generation, its domain is
immutable, and the only symptom would be transfers that never claim.


## `bridge.config.json`

`bash scripts/bridge-from-json.sh [config] [--generate-only|--stop|--status]`

Generates one TOML per process into `runtime.run_dir` and starts them.
`--generate-only` stops after writing the TOMLs, so you can inspect exactly what
each process is handed (or ship them to separate hosts, which is what a real
validator set looks like — one operator per key, not one machine running all of
them).

| field | meaning |
| --- | --- |
| `threshold` | signatures a claim needs; must match the deployed gates |
| `runtime.run_dir` | generated configs, logs, pid file, validator cursors, `tokens.env`. Default (`null`): `${XDG_STATE_HOME:-~/.local/state}/selendra-bridge/<name>`. Created 0700 with every file 0600 (M-11: the TOMLs carry private keys). Keep it OUT of `/tmp` for anything long-running: `systemd-tmpfiles-clean` sweeps `/tmp` daily, and losing a validator's cursor means it restarts from `start_block` — on a live chain that is a backlog it may take hours to crawl back through |
| `runtime.bin_dir` | where the compiled services are (`target/debug`, `target/release`, …) |
| `runtime.build` | `cargo build` the services first |
| `database.url` | Postgres for the sig-store + indexer. Required when `database.docker.enabled` is `false`; otherwise **derived** from the docker fields below (leave it `null`) |
| `database.docker` | run that Postgres as a container, published on `127.0.0.1:<port>` only (M-10: a docker `-p` publish bypasses ufw). `password: null` means a random one per run dir, kept in `run_dir/tokens.env` (0600) and re-applied to the volume on every start; a configured password wins (and `"bridge"` earns a warning). `--stop` removes the container but **keeps** the volume: it holds signatures, history and indexer cursors, and validators resume from file cursors rather than re-signing blocks they already scanned |
| `sig_store.tokens` | scoped credentials, one per role. With none set the store runs **unauthenticated** — signatures, claim status and the allowlist become writable by anything that can reach the port. `generate_if_unset` mints a random one per role per run into `run_dir/tokens.env` |
| `defaults` | per-chain fallbacks for `poll_interval_ms`, `max_block_range`, `start_block`, `block_confirmation`, `allow_zero_confirmation` |
| `chains[].rpcs` | ordered endpoints; validators fail over to the next on error. `rpcs[0]` is also what the API and relayers use server-side — it is **never** served to a browser |
| `chains[].public_rpc` | the browser-safe (keyless) endpoint the GraphQL registry serves as `rpcUrl` (H-4). Unset: a loopback `rpcs[0]` is served as-is; anything else is served as `null` (the UI reads through the wallet's provider instead) with a warning at generation, and `graphql-api --production` refuses to start without it |
| `chains[].gate` | the **proxy** address (never the implementation) |
| `chains[].source` / `.destination` | which roles this chain plays. Both `true` = full mesh, which is the normal case |
| `chains[].start_block` | scan floor. `0` re-scans a live chain's entire history; the deploy script sets each chain's deploy block for you |
| `chains[].block_confirmation` | finality buffer — **security critical**. Signing an event at the chain tip lets a reorg erase the deposit *after* the destination paid out. It must exceed the chain's reorg depth. `0` is refused unless `allow_zero_confirmation` is set, which is only safe on an instant-final dev chain (anvil) |
| `chains[].enabled` | `false` parks a chain: it is not scanned, not served to the UI, and not counted anywhere |
| `chains[].pool` / `.router` | SwapPool / SwapRouter to index, if any (the deploy script fills `pool` in) |
| `chains[].tokens[]` | symbol + address, served to the UI; `tokens[0]` is the chain's primary |
| `validators[]` | one entry per validator process: `name`, `signer` (same custody options as the deployer), `sources` (`"all"` or a chain-id list), optional operator `api` |
| `refund` | the two-phase refund attestation loop. Disabled ⇒ no validator votes on cancels and stranded transfers stay stranded — the safe default, since a node that cannot read the destination must not have an opinion on delivery. Its own `block_confirmation` guards the destination read |
| `keepers[]` | `name`, `signer`, `targets` (claims), `refund_sources` (refunds pay out where the funds were locked). The keeper pays gas on **every** chain it targets, so fund its account on each one — a new chain in the mesh is a new chain the keeper needs native balance on, and without it claims simply never land. Split into two keeper entries — one with only `targets`, one with only `refund_sources` — when you don't want both loops sharing an account's nonce |
| `solana` | the Solana relayers — see below; `enabled: false` skips them |
| `indexer` | history + refund eligibility sweep; the only writer of `refund_status`. EVM chains only — it speaks EVM JSON-RPC, so a transfer **delivered on Solana** is recorded as `stuck` / `refund_status: eligible` forever: the `Sent` is on an EVM chain it watches, the `Claimed` is not. Nothing acts on that nomination (an EVM validator never attests for a destination outside its `refund.destinations`, and the relayer re-reads the Solana gate before attesting), but the UI will show those transfers as stuck |
| `frontend` | the vite dev server for the UI. It reaches the API through vite's proxy (`VITE_PROXY_TARGET`), so the API needs no CORS and no public port. `node_bin` pins a toolchain when node is not on PATH — an nvm install usually isn't; leave it `null` to auto-detect the newest one |
| `graphql.swaps[]` | one entry per pool (`chain_id`, `pool`, `from_block`), so a multi-chain mesh serves a Swap view on every chain. Each becomes that chain's `swap_pool` in the registry file (read over the chain's own `rpc_url`, with its own `max_block_range`: the `eth_getLogs` cap is a property of the endpoint, and on a fast chain the strictest cap in the mesh is not merely slow but fatal — a pool on 0.2s blocks produces them faster than a 10-block chunk can replay, so its token list never finishes backfilling). Nothing goes on the API's command line. `graphql.swap` is the older single-pool form and still works |
| `graphql` | the read API the frontend talks to. It holds no database credential — it reads history through the sig-store on its reader token, because it is the only service meant to face the internet |


### the Solana relayers

`solana-relayer` is the Solana leg's validator, and it is a separate process for
a hard reason: `solana-client` and alloy cannot live in one binary. It signs
Solana-origin transfers into the same sig-store the EVM validators use, and
(when `deliver` is set) submits EVM→Solana claims on-chain.

| field | meaning |
| --- | --- |
| `program_id` | the deployed gate program; the deploy script fills it in |
| `commitment` | Solana's finality control — there is no block count here. `confirmed` and `processed` can both be rolled back by a fork, which is the same double-spend `block_confirmation` defends against on EVM, so anything but `finalized` is refused unless `allow_unfinalized` is set (a local test validator only) |
| `relayers[]` | one process per validator key. Each holds the **same secp256k1 key** that validator uses on the EVM side — one validator set attests for both VMs. Only `private_key` / `private_key_env` are supported here (no keystore) |
| `relayers[].deliver` | run the claim-submitting half. `payer_keypair` pays fees and rent and carries no bridge authority — the validator signatures do |
| `tokens[]` | symbol → mint, for the record and for the optional UI listing |
| `include_in_registry` | **no longer gates anything**: when the leg is enabled the Solana row is always in the GraphQL registry, with `gate` = the base58 program id and `rpc_url` = `solana.rpc` — that is how the API reads the gate (corridor nonce, vault) and the Solana swap pool; it routes on address form (0x = EVM, base58 = Solana). `public_rpc` (browser-safe) is served as its `rpcUrl`; `solana.rpc` never is |
| `refund` (top level) | when enabled, every relayer also gets a `[refund]` block: the same `timeout_secs` as the validators and one `[[refund.evm]]` reader per EVM gate (`rpc_env = "RPC_<chain_id>"`, so a keyed url lives in the process environment, not the file; `block_confirmation` is the refund one, floored at 1). Without it the attester votes REFUND but never CANCEL, and a stranded EVM→Solana transfer is never released (M-13). The program and the relayer must be deployed together: `SentRecord` grew by 8 bytes (legacy records still decode) |
| `bin` / `build` | the relayer binary (its own cargo project — see above) |

**Run at least `threshold` relayers, each with a distinct key.** Solana `Sent`
events are signed *only* by relayers — the EVM validators never scan Solana — so
with fewer, Solana-origin transfers stall below quorum and nothing says why. The
launcher refuses to start that configuration, and refuses two relayers sharing a
key (which would count one key twice toward the quorum).

### running several bridges

One config = one mesh. Every chain listed bridges to every other one in both
directions, so a third chain is one more entry in `chains[]` — nothing else
changes. To run *separate* meshes side by side (say staging and production, or
two disjoint validator sets), copy the file and give each its own `name`,
`runtime.run_dir`, `sig_store.bind`/`url`, `graphql.bind`, and
`database.docker.container`/`port`/`volume`. `--stop` matches only the processes
its own config started, so the two never tear each other down.

## keeping secrets out of the files

`signer` (validators, keepers) and `deployer` both accept, in order of
preference: `keystore` + `keystore_password_file`, `private_key_env`, or an
inline `private_key` (dev only — a leaked config is then a leaked key, and the
services log a warning at startup). The sig-store tokens accept the same
treatment via the environment. The shipped local configs use the well-known
public anvil keys on purpose: they are worthless, and they must never appear in
anything that touches a real network.

## docker

`bash scripts/bridge-from-json.sh <config> --compose` writes a complete stack to
`docker/<name>/` from the same JSON: one generated TOML per process in
`configs/`, a `docker-compose.yml` wiring postgres → sig-store → validators →
keepers → relayers → indexer → graphql-api → frontend with health-gated
ordering, a gitignored `.env` holding freshly generated secrets, and a
committable `.env.example` holding none.

```bash
bash scripts/bridge-from-json.sh config/my.bridge.json --compose
cd docker/my-mesh && docker compose up -d --build
```

Re-running keeps the secrets in an existing `.env`, so regenerating after a
config change does not rotate the Postgres password out from under a live
volume; the `RPC_<chain_id>` / `RPC_SOLANA` lines are refreshed from the config
each time. The compose file references every RPC url as `${RPC_<chain>}` and
never inlines one — a keyed url in the compose file is what leaked in H-4, which
is why `docker/*/docker-compose.yml` is gitignored as generated output (only
`.env.example` in a generated stack is committable).

What differs from the host-run form, and why:

- endpoints become service names (`http://sig-store:8080`, `postgres:5432`);
- cursors and keypairs move to mounted paths (`/data`, `/keys`), each validator
  and relayer getting **its own** state volume — a shared one would make each
  resume from the other's position;
- the indexer's `database_url` is left out of its config file on purpose. The
  file value beats the `DATABASE_URL` environment variable, and the credential
  belongs in the environment, not in a generated file;
- the Solana relayer gets its own image (`docker/Dockerfile.relayer`), because
  `solana-client` pins `zeroize <1.4` and alloy needs `^1.5` — the two cannot
  share a binary;
- only the frontend publishes a port. nginx proxies `/graphql` and `/health` to
  the API, so the browser talks to it same-origin and the API needs no public
  port and no CORS.

The generated `configs/` hold validator and keeper **private keys**. The
directory is gitignored; treat it as secret material.
