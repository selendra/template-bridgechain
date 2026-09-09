//! `swap-admin` — the on-chain client for the Solana swap pool.
//!
//! Same role `gate-admin` plays for the bridge gate: it builds and signs
//! transactions, and grants no authority of its own (every governance path is
//! owner- or oracle-gated ON-CHAIN).
//!
//! It lives in `solana-relayer` for the reason that crate exists at all:
//! `solana-client` pins `zeroize <1.4` and alloy needs `^1.5`, so no EVM-side
//! crate can host a Solana client.
//!
//! The instruction enum, account layouts and pricing math are IMPORTED from
//! `solana-swap` rather than mirrored here. Hand-copied definitions are how the
//! gate's two `Sent` structs drifted apart while both sides kept compiling.
//!
//!   swap-admin --rpc <url> --keypair <path> --program <pubkey> <command>
//!
//!     init --hub-mint <pubkey> --hub-vault <pubkey>
//!          [--fee-bps N] [--deviation-bps N] [--min-price-interval SECS]
//!          [--guardian <pubkey>] [--oracle <pubkey>]
//!     list-token --mint <pubkey> --vault <pubkey> --price <PRICE_ONE-scaled>
//!     set-price  --mint <pubkey> --price <PRICE_ONE-scaled>
//!     seed       --mint <pubkey> --amount N --from <token account>
//!     withdraw   --mint <pubkey> --amount N --to <token account>
//!     swap       --mint-in <pubkey> --mint-out <pubkey> --amount N
//!                --from <token account> --to <token account> [--min-out N]
//!     quote      --mint-in <pubkey> --mint-out <pubkey> --amount N
//!     pause | unpause | set-fee --fee-bps N | set-oracle --oracle <pubkey>
//!     set-guardian --guardian <pubkey>
//!     set-max-price-deviation --bps N       (1..=10000; per-reprice move cap)
//!     set-max-price-age --seconds N         (> 0; swaps refuse a price older than this)
//!     set-min-price-interval --seconds N    (>= 0; reprice cooldown, 0 disables)
//!     show [--mint <pubkey> ...]             (prints max_price_age and each token's
//!                                            price_set_at + freshness)
//!
//! `quote` refuses a leg whose price is stale (`PoolState::price_is_fresh`), the
//! same check the on-chain `swap` makes, so a quote never promises an output the
//! pool would refuse.
//!
//! Prices are PRICE_ONE-scaled (1e18), the same fixed point `SwapPool.sol` uses,
//! so a price of "one hub unit" is 1000000000000000000.

use std::str::FromStr;

use borsh::BorshDeserialize;
use solana_client::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{read_keypair_file, Signer};
use solana_sdk::transaction::Transaction;
use solana_swap::{
    math, InitPoolArgs, Pool, SwapInstruction, TokenRec, POOL_SEED, PRICE_ONE, TOKEN_SEED,
    VAULT_AUTHORITY_SEED,
};

/// The shared account layouts hold plain 32-byte keys (so the read API can link
/// them too); this is the display/compare boundary.
fn pk(b: &[u8; 32]) -> Pubkey {
    Pubkey::new_from_array(*b)
}

const SPL_TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

/// Minimal flag reader: `--name value`.
struct Args(Vec<String>);
impl Args {
    fn get(&self, name: &str) -> Option<String> {
        self.0.iter().position(|a| a == name).and_then(|i| self.0.get(i + 1)).cloned()
    }
    fn req(&self, name: &str) -> anyhow::Result<String> {
        self.get(name).ok_or_else(|| anyhow::anyhow!("missing required flag {name}"))
    }
    fn key(&self, name: &str) -> anyhow::Result<Pubkey> {
        Ok(Pubkey::from_str(&self.req(name)?)?)
    }
    fn num<T: FromStr>(&self, name: &str, default: T) -> anyhow::Result<T>
    where
        T::Err: std::fmt::Display,
    {
        match self.get(name) {
            None => Ok(default),
            Some(v) => v.parse::<T>().map_err(|e| anyhow::anyhow!("bad {name}: {e}")),
        }
    }
}

/// The cluster's unix time from the Clock sysvar — what the program compares
/// `price_set_at` against, so freshness is judged on the chain's clock, not ours.
fn cluster_now(rpc: &RpcClient) -> Option<i64> {
    let acct = rpc.get_account(&solana_sdk::sysvar::clock::id()).ok()?;
    solana_sdk::account::from_account::<solana_sdk::clock::Clock, _>(&acct).map(|c| c.unix_timestamp)
}

/// Human-readable freshness of a token's price under `pool`'s guard.
fn freshness_label(pool: &Pool, rec: &TokenRec, now: i64) -> String {
    if rec.mint == pool.hub_mint {
        return "FRESH (hub: pinned at PRICE_ONE)".into();
    }
    let age = now.saturating_sub(rec.price_set_at);
    if pool.price_is_fresh(rec, now) {
        format!("FRESH ({age}s old, max {}s)", pool.effective_max_price_age())
    } else if rec.price_set_at == 0 {
        "STALE (never stamped — reprice with set-price)".into()
    } else {
        format!("STALE ({age}s old, max {}s)", pool.effective_max_price_age())
    }
}

/// The check `swap` makes on-chain, applied to a quote: either leg stale => the
/// pool would refuse (`StalePrice`), so refuse the quote with the same reason.
fn stale_leg(pool: &Pool, rec_in: &TokenRec, rec_out: &TokenRec, now: i64) -> anyhow::Result<()> {
    for (label, rec) in [("in", rec_in), ("out", rec_out)] {
        if !pool.price_is_fresh(rec, now) {
            anyhow::bail!(
                "mint-{label} {} price is STALE (set_at {}, now {now}, max age {}s) — the pool would \
                 refuse this swap (StalePrice); reprice it first",
                pk(&rec.mint),
                rec.price_set_at,
                pool.effective_max_price_age()
            );
        }
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let cmd = argv
        .iter()
        .enumerate()
        .find(|(i, a)| {
            !a.starts_with("--") && !argv.get(i.wrapping_sub(1)).is_some_and(|p| p.starts_with("--"))
        })
        .map(|(_, a)| a.clone())
        .ok_or_else(|| anyhow::anyhow!("no command; see the header of this file"))?;
    let args = Args(argv);

    let rpc_url = args.req("--rpc")?;
    let program_id = args.key("--program")?;
    let payer = read_keypair_file(args.req("--keypair")?)
        .map_err(|e| anyhow::anyhow!("reading keypair: {e}"))?;
    let rpc = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());
    let token_program = Pubkey::from_str(SPL_TOKEN)?;

    let (pool_pda, _) = Pubkey::find_program_address(&[POOL_SEED], &program_id);
    let (vault_authority, _) = Pubkey::find_program_address(&[VAULT_AUTHORITY_SEED], &program_id);
    let token_pda = |mint: &Pubkey| {
        Pubkey::find_program_address(&[TOKEN_SEED, mint.as_ref()], &program_id).0
    };

    // --- read-only commands -------------------------------------------------
    if cmd == "show" {
        println!("program        : {program_id}");
        println!("pool PDA       : {pool_pda}");
        println!("vault authority: {vault_authority}");
        match rpc.get_account(&pool_pda) {
            Err(_) => println!("pool account   : NOT INITIALIZED (run `init`)"),
            Ok(acct) => {
                let pool = Pool::deserialize(&mut &acct.data[..])?;
                println!("  owner        : {}", pk(&pool.owner));
                println!("  oracle       : {}", pk(&pool.oracle));
                println!(
                    "  guardian     : {}",
                    if pool.guardian == [0u8; 32] { "none".into() } else { pk(&pool.guardian).to_string() }
                );
                println!("  hub mint     : {}", pk(&pool.hub_mint));
                println!("  fee          : {} bps", pool.fee_bps);
                println!("  price guards : max {} bps per {}s", pool.max_price_deviation_bps, pool.min_price_update_interval);
                println!(
                    "  max price age: {}s{}",
                    pool.effective_max_price_age(),
                    if pool.max_price_age == 0 { " (unset — failing closed at the default)" } else { "" }
                );
                println!("  paused       : {}", pool.paused);
                let now = cluster_now(&rpc);
                // The listed set is not enumerable from the pool account (each
                // token is its own PDA), so `show` reports the ones named on the
                // command line — pass --mint repeatedly to inspect them.
                for m in args.0.iter().enumerate().filter(|(_, a)| a.as_str() == "--mint").filter_map(|(i, _)| args.0.get(i + 1)) {
                    let mint = Pubkey::from_str(m)?;
                    match rpc.get_account(&token_pda(&mint)) {
                        Err(_) => println!("  token {mint}: NOT LISTED"),
                        Ok(a) => {
                            let r = TokenRec::deserialize(&mut &a.data[..])?;
                            println!(
                                "  token {} : price {} ({} dp) reserve {} vault {}",
                                pk(&r.mint), r.price, r.decimals, r.reserve, pk(&r.vault)
                            );
                            println!(
                                "    price_set_at {}  {}",
                                r.price_set_at,
                                match now {
                                    Some(now) => freshness_label(&pool, &r, now),
                                    None => "(cluster clock unreadable)".to_string(),
                                }
                            );
                        }
                    }
                }
            }
        }
        return Ok(());
    }

    if cmd == "quote" {
        let mint_in = args.key("--mint-in")?;
        let mint_out = args.key("--mint-out")?;
        let amount: u64 = args.req("--amount")?.parse()?;
        let pool = Pool::deserialize(&mut &rpc.get_account(&pool_pda)?.data[..])?;
        let ri = TokenRec::deserialize(&mut &rpc.get_account(&token_pda(&mint_in))?.data[..])?;
        let ro = TokenRec::deserialize(&mut &rpc.get_account(&token_pda(&mint_out))?.data[..])?;
        // The on-chain `swap` refuses a stale leg (`StalePrice`, 0x11); a quote
        // that ignored that would promise an output the pool will not honour.
        let now = cluster_now(&rpc).ok_or_else(|| anyhow::anyhow!("cannot read the cluster clock"))?;
        stale_leg(&pool, &ri, &ro, now)?;
        let out = math::amount_out(amount, ri.price, ri.decimals, ro.price, ro.decimals, pool.fee_bps)
            .ok_or_else(|| anyhow::anyhow!("quote overflows"))?;
        println!("{out}");
        if out > ro.reserve {
            eprintln!(
                "warning: {out} exceeds the pool's {} reserve — the swap would hit the lock",
                ro.reserve
            );
        }
        return Ok(());
    }

    // --- transactions -------------------------------------------------------
    let (data, accounts) = match cmd.as_str() {
        "init" => {
            let hub_mint = args.key("--hub-mint")?;
            let hub_vault = args.key("--hub-vault")?;
            let (program_data, _) = Pubkey::find_program_address(
                &[program_id.as_ref()],
                &solana_sdk::bpf_loader_upgradeable::id(),
            );
            (
                SwapInstruction::Init(InitPoolArgs {
                    fee_bps: args.num("--fee-bps", 0u16)?,
                    max_price_deviation_bps: args.num("--deviation-bps", 1000u16)?,
                    min_price_update_interval: args.num("--min-price-interval", 3600i64)?,
                    guardian: match args.get("--guardian") {
                        Some(g) => Pubkey::from_str(&g)?,
                        None => Pubkey::default(),
                    },
                    oracle: match args.get("--oracle") {
                        Some(o) => Pubkey::from_str(&o)?,
                        None => Pubkey::default(),
                    },
                })
                .to_bytes(),
                vec![
                    AccountMeta::new(pool_pda, false),
                    AccountMeta::new(payer.pubkey(), true),
                    AccountMeta::new_readonly(hub_mint, false),
                    AccountMeta::new_readonly(hub_vault, false),
                    AccountMeta::new(token_pda(&hub_mint), false),
                    AccountMeta::new_readonly(token_program, false),
                    AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                    AccountMeta::new_readonly(program_id, false),
                    AccountMeta::new_readonly(program_data, false),
                ],
            )
        }
        "list-token" => {
            let mint = args.key("--mint")?;
            let vault = args.key("--vault")?;
            (
                SwapInstruction::ListToken { price: args.req("--price")?.parse()? }.to_bytes(),
                vec![
                    AccountMeta::new_readonly(pool_pda, false),
                    AccountMeta::new(payer.pubkey(), true),
                    AccountMeta::new_readonly(mint, false),
                    AccountMeta::new_readonly(vault, false),
                    AccountMeta::new(token_pda(&mint), false),
                    AccountMeta::new_readonly(token_program, false),
                    AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                ],
            )
        }
        "set-price" => {
            let mint = args.key("--mint")?;
            (
                SwapInstruction::SetPrice { price: args.req("--price")?.parse()? }.to_bytes(),
                vec![
                    AccountMeta::new_readonly(pool_pda, false),
                    AccountMeta::new_readonly(payer.pubkey(), true),
                    AccountMeta::new(token_pda(&mint), false),
                ],
            )
        }
        "seed" | "withdraw" => {
            let mint = args.key("--mint")?;
            let amount: u64 = args.req("--amount")?.parse()?;
            let ata = if cmd == "seed" { args.key("--from")? } else { args.key("--to")? };
            let rec = TokenRec::deserialize(&mut &rpc.get_account(&token_pda(&mint))?.data[..])?;
            let ix = if cmd == "seed" {
                SwapInstruction::SeedLiquidity { amount }
            } else {
                SwapInstruction::WithdrawLiquidity { amount }
            };
            (
                ix.to_bytes(),
                vec![
                    AccountMeta::new_readonly(pool_pda, false),
                    AccountMeta::new(payer.pubkey(), true),
                    AccountMeta::new(token_pda(&mint), false),
                    AccountMeta::new(ata, false),
                    AccountMeta::new(pk(&rec.vault), false),
                    AccountMeta::new_readonly(mint, false),
                    AccountMeta::new_readonly(vault_authority, false),
                    AccountMeta::new_readonly(token_program, false),
                ],
            )
        }
        "swap" => {
            let mint_in = args.key("--mint-in")?;
            let mint_out = args.key("--mint-out")?;
            let amount_in: u64 = args.req("--amount")?.parse()?;
            let user_in = args.key("--from")?;
            let user_out = args.key("--to")?;
            let ri = TokenRec::deserialize(&mut &rpc.get_account(&token_pda(&mint_in))?.data[..])?;
            let ro = TokenRec::deserialize(&mut &rpc.get_account(&token_pda(&mint_out))?.data[..])?;
            (
                SwapInstruction::Swap { amount_in, min_amount_out: args.num("--min-out", 0u64)? }
                    .to_bytes(),
                vec![
                    AccountMeta::new_readonly(pool_pda, false),
                    AccountMeta::new_readonly(payer.pubkey(), true),
                    AccountMeta::new(token_pda(&mint_in), false),
                    AccountMeta::new(token_pda(&mint_out), false),
                    AccountMeta::new(user_in, false),
                    AccountMeta::new(user_out, false),
                    AccountMeta::new(pk(&ri.vault), false),
                    AccountMeta::new(pk(&ro.vault), false),
                    AccountMeta::new_readonly(mint_in, false),
                    AccountMeta::new_readonly(mint_out, false),
                    AccountMeta::new_readonly(vault_authority, false),
                    AccountMeta::new_readonly(token_program, false),
                ],
            )
        }
        "pause" | "unpause" => (
            if cmd == "pause" { SwapInstruction::Pause } else { SwapInstruction::Unpause }.to_bytes(),
            vec![
                AccountMeta::new(pool_pda, false),
                AccountMeta::new_readonly(payer.pubkey(), true),
            ],
        ),
        "set-fee" => (
            SwapInstruction::SetFee { fee_bps: args.req("--fee-bps")?.parse()? }.to_bytes(),
            vec![
                AccountMeta::new(pool_pda, false),
                AccountMeta::new_readonly(payer.pubkey(), true),
            ],
        ),
        "set-oracle" => (
            SwapInstruction::SetOracle { oracle: args.key("--oracle")? }.to_bytes(),
            vec![
                AccountMeta::new(pool_pda, false),
                AccountMeta::new_readonly(payer.pubkey(), true),
            ],
        ),
        "set-guardian" => (
            SwapInstruction::SetGuardian { guardian: args.key("--guardian")? }.to_bytes(),
            vec![
                AccountMeta::new(pool_pda, false),
                AccountMeta::new_readonly(payer.pubkey(), true),
            ],
        ),
        // Owner-only price guards, same `[pool(w), owner(s)]` shape as set-fee.
        // Ranges are enforced on-chain; checked here too so a typo fails before
        // it costs a transaction.
        "set-max-price-deviation" => {
            let bps: u16 = args.req("--bps")?.parse()?;
            anyhow::ensure!((1..=10_000).contains(&bps), "--bps must be 1..=10000");
            (
                SwapInstruction::SetMaxPriceDeviation { bps }.to_bytes(),
                vec![AccountMeta::new(pool_pda, false), AccountMeta::new_readonly(payer.pubkey(), true)],
            )
        }
        "set-max-price-age" => {
            let seconds: i64 = args.req("--seconds")?.parse()?;
            anyhow::ensure!(seconds > 0, "--seconds must be positive (there is no 'off')");
            (
                SwapInstruction::SetMaxPriceAge { seconds }.to_bytes(),
                vec![AccountMeta::new(pool_pda, false), AccountMeta::new_readonly(payer.pubkey(), true)],
            )
        }
        "set-min-price-interval" => {
            let seconds: i64 = args.req("--seconds")?.parse()?;
            anyhow::ensure!(seconds >= 0, "--seconds must be >= 0 (0 disables the cooldown)");
            (
                SwapInstruction::SetMinPriceUpdateInterval { seconds }.to_bytes(),
                vec![AccountMeta::new(pool_pda, false), AccountMeta::new_readonly(payer.pubkey(), true)],
            )
        }
        other => anyhow::bail!("unknown command {other:?}"),
    };

    let _ = PRICE_ONE; // documented unit; referenced so the import is not stale
    let ix = Instruction { program_id, accounts, data };
    let blockhash = rpc.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], blockhash);
    let sig = rpc.send_and_confirm_transaction(&tx)?;
    println!("{cmd} OK — tx {sig}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The enum is IMPORTED, so the compiler already keeps these names honest;
    /// the discriminants are pinned because the browser encodes them by hand.
    #[test]
    fn price_guard_instructions_sit_at_discriminants_11_to_13() {
        assert_eq!(SwapInstruction::SetFee { fee_bps: 1 }.to_bytes()[0], 10);
        assert_eq!(SwapInstruction::SetMaxPriceDeviation { bps: 1 }.to_bytes()[0], 11);
        assert_eq!(SwapInstruction::SetMaxPriceAge { seconds: 1 }.to_bytes()[0], 12);
        assert_eq!(SwapInstruction::SetMinPriceUpdateInterval { seconds: 1 }.to_bytes()[0], 13);
        // Payload widths: u16 LE, i64 LE, i64 LE.
        assert_eq!(SwapInstruction::SetMaxPriceDeviation { bps: 0x0102 }.to_bytes(), vec![11, 0x02, 0x01]);
        assert_eq!(SwapInstruction::SetMaxPriceAge { seconds: 2 }.to_bytes().len(), 9);
        assert_eq!(SwapInstruction::SetMinPriceUpdateInterval { seconds: 2 }.to_bytes().len(), 9);
    }

    /// `quote` must refuse exactly what `swap` refuses: a leg whose price is
    /// older than the pool's max age. The hub leg is always fresh.
    #[test]
    fn quote_refuses_a_stale_leg_and_accepts_fresh_ones() {
        let hub = [1u8; 32];
        let pool = Pool { hub_mint: hub, max_price_age: 100, ..Default::default() };
        let fresh = TokenRec { mint: [2u8; 32], price_set_at: 1_000, ..Default::default() };
        let stale = TokenRec { mint: [3u8; 32], price_set_at: 800, ..Default::default() };
        let hub_rec = TokenRec { mint: hub, price_set_at: 0, ..Default::default() };
        let now = 1_100;

        assert!(stale_leg(&pool, &fresh, &hub_rec, now).is_ok(), "fresh + hub is fine");
        assert!(stale_leg(&pool, &hub_rec, &fresh, now).is_ok());
        let e = stale_leg(&pool, &fresh, &stale, now).unwrap_err().to_string();
        assert!(e.contains("mint-out") && e.contains("STALE"), "{e}");
        let e = stale_leg(&pool, &stale, &fresh, now).unwrap_err().to_string();
        assert!(e.contains("mint-in"), "{e}");
        // A never-stamped (pre-upgrade) record is stale until repriced.
        let never = TokenRec { mint: [4u8; 32], price_set_at: 0, ..Default::default() };
        assert!(stale_leg(&pool, &never, &hub_rec, now).is_err());
        assert!(freshness_label(&pool, &never, now).contains("never stamped"));
        assert!(freshness_label(&pool, &hub_rec, now).starts_with("FRESH"));
        assert!(freshness_label(&pool, &stale, now).starts_with("STALE"));
    }
}
