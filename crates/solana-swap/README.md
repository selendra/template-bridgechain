# solana-swap

The Solana counterpart of `contracts/src/SwapPool.sol`: a same-chain, pegged-price
swap pool over SPL tokens, so a bridged asset can be swapped on the chain it
lands on rather than only on the EVM side.

## Why it is a separate program from the gate

The same reason `SwapPool.sol` is a separate contract from `Gate.sol`: the gate
holds bridge liquidity that validator signatures release, and a pricing bug must
not be able to reach it. The two programs share nothing on-chain — different
program ids, different vault authorities, different accounts.

## Layout

| account | seeds | holds |
| --- | --- | --- |
| pool | `["pool"]` | owner, oracle, guardian, hub mint, fee, price guards, pause, `max_price_age` |
| token | `["token", mint]` | price, decimals, vault, **internal reserve**, `price_set_at` |
| vault | — | an SPL account per mint, owned by `["vault_authority"]` |

`reserve` is accounting, never `balanceOf`: a raw donation must not raise the
payout ceiling, and a short transfer must not be credited. The output of any swap
is hard-capped by it, so a swap can never drain the pool.

Every PDA is created with `transfer + allocate + assign`, not `create_account`,
so a lamport sent to a derivable address ahead of time cannot make a mint
unlistable (audit M-5).

### Price guards (audit M-6)

Same three as `SwapPool.sol`, with the same semantics:

* **Deviation cap** (`max_price_deviation_bps`, 1..=10 000) — on EVERY `SetPrice`,
  the first after listing included. Only the **cooldown**
  (`min_price_update_interval`, >= 0) is waived for that first update.
* **Staleness** (`max_price_age`, default 86 400 s) — a swap refuses either leg
  whose `price_set_at` is older than this; the hub is exempt (its peg is fixed).
  A halted oracle stops the pool rather than leaving it quoting yesterday's
  price. The oracle clears it by re-confirming the price (a zero move is always
  within the cap). Unlike Solidity there is NO value that disables the check —
  `0` is what a pre-upgrade pool record decodes to and reads as the default —
  so relax it by setting it large.
* **Fee** at most 1 000 bps (10 %), in `Init` and `SetFee`.

Owner setters: `SetFee`, `SetMaxPriceDeviation`, `SetMaxPriceAge`,
`SetMinPriceUpdateInterval`.

### Layout migration (2026-09-09)

`price_set_at` (token) and `max_price_age` (pool) were added INTO the 32 bytes of
padding each account already carried: `POOL_SPACE`/`TOKEN_SPACE` are unchanged
and no realloc is needed. Records written by the previous program decode with
both fields as `0`, which fails closed — every non-hub token is stale until the
oracle issues one `SetPrice` per token (at the current price is fine). Do that
right after deploying the upgrade over an existing pool.

## The math is not a copy

Pricing and the account layouts live in `crates/swap-math`, which is linked by
BOTH this program and `graphql-api`. That crate depends on neither
`solana-program` nor alloy — it cannot, since those two trees are mutually
exclusive (`zeroize <1.4` vs `^1.5`) — which is exactly what lets one definition
serve both sides. `crates/swap-math/tests/parity.rs` checks it against fixtures
produced by the Solidity pool itself, so a quote shown by the UI and a swap
executed here agree to the unit.

## Build and deploy

```bash
bash scripts/testing/build-solana.sh swap          # -> target/deploy/solana_swap.so
solana program deploy target/deploy/solana_swap.so --use-rpc
cargo build --manifest-path crates/solana-relayer/Cargo.toml --bin swap-admin
swap-admin --rpc <url> --keypair <path> --program <id> init --hub-mint <m> --hub-vault <v>
swap-admin ... list-token --mint <m> --vault <v> --price 3180000000000000000000
swap-admin ... seed --mint <m> --amount N --from <token account>
swap-admin ... swap --mint-in <a> --mint-out <b> --amount N --from <ata> --to <ata>
```

Prices are `PRICE_ONE`-scaled (1e18), the same fixed point the Solidity pool uses.
`config/deploy.config.json`'s `solana.swap` block drives all of this from the
JSON config instead.

## Swapping from the UI

The frontend builds and signs its own transaction against this program — no
web3.js, for the same reason `wallet/eth.ts` hand-encodes calldata: every account
that decides where the output lands (the user's associated token accounts, the
pool PDAs) is derived in the browser. The API contributes a blockhash, an SPL
balance and the pool's vaults, none of which can misdirect funds — a wrong vault
is refused by this program, which pins it in its own token record.

Those bytes are pinned against `solana-sdk` itself:
`crates/solana-relayer/tests/swap_message_fixture.rs` builds the same
transaction through the real SDK and writes
`contracts/fixtures/solana_swap_tx.json`, which
`frontend/e2e/unit/solana.spec.ts` asserts against.

## Deliberate differences from the Solidity pool

* **No two-step ownership.** The deployer governs it, as with `solana-gate`: the
  BPF loader's upgrade authority is the real owner, and a second weaker ownership
  story would be theatre. Rotate the upgrade authority instead.
* **Amounts are `u64`,** because every SPL amount is. An 18-decimal mint can only
  hold ~18.4 whole tokens, so bridged EVM assets get a 6- or 9-decimal mint here.
* **No `SwapRouter` equivalent yet** — this is the same-chain primitive only.
