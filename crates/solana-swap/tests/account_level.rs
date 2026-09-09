//! The swap handlers actually EXECUTED, not just their pure math asserted.
//!
//! `solana-program-test` runs `process_instruction` natively in a real test bank
//! and bundles the SPL token program, so the CPIs, PDA signing, rent and Borsh
//! round-trips all behave as they do on-chain.
//!
//! `Init` is not covered here, for the same reason the gate's `init` is not: it
//! reads the BPF-loader `Program`/`ProgramData` accounts to identify the upgrade
//! authority, and installing a loader-owned account at the program's own address
//! defeats `ProgramTest`'s builtin dispatch. These tests seed the pool and token
//! records exactly as a successful `Init` leaves them.

use borsh::BorshDeserialize;
use solana_program::clock::Clock;
use solana_program::instruction::{AccountMeta, Instruction};
use solana_program::program_option::COption;
use solana_program::program_pack::Pack;
use solana_program::pubkey::Pubkey;
use solana_program_test::{processor, ProgramTest, ProgramTestContext};
use solana_sdk::account::{Account, AccountSharedData};
use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::transaction::Transaction;

use solana_swap::{
    math, process_instruction, Pool, SwapError, SwapInstruction, TokenRec, DEFAULT_MAX_PRICE_AGE,
    MAX_FEE_BPS, POOL_SEED, POOL_SPACE, PRICE_ONE, TOKEN_SEED, TOKEN_SPACE, VAULT_AUTHORITY_SEED,
};

const PROGRAM_ID: Pubkey = Pubkey::new_from_array([11u8; 32]);
const HUB_DEC: u8 = 9;
const ALT_DEC: u8 = 9;
/// 3180 hub units per ALT, PRICE_ONE-scaled — the same peg the EVM pools use.
const ALT_PRICE: u128 = 3180 * PRICE_ONE;

fn pool_pda() -> Pubkey {
    Pubkey::find_program_address(&[POOL_SEED], &PROGRAM_ID).0
}
fn token_pda(mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[TOKEN_SEED, mint.as_ref()], &PROGRAM_ID).0
}
fn vault_authority() -> Pubkey {
    Pubkey::find_program_address(&[VAULT_AUTHORITY_SEED], &PROGRAM_ID).0
}

fn mint_account(decimals: u8) -> Account {
    let mut data = vec![0u8; spl_token::state::Mint::LEN];
    spl_token::state::Mint {
        mint_authority: COption::None,
        supply: u64::MAX / 2,
        decimals,
        is_initialized: true,
        freeze_authority: COption::None,
    }
    .pack_into_slice(&mut data);
    Account { lamports: 10_000_000, data, owner: spl_token::id(), executable: false, rent_epoch: 0 }
}

fn token_account(mint: Pubkey, owner: Pubkey, amount: u64) -> Account {
    let mut data = vec![0u8; spl_token::state::Account::LEN];
    spl_token::state::Account {
        mint,
        owner,
        amount,
        delegate: COption::None,
        state: spl_token::state::AccountState::Initialized,
        is_native: COption::None,
        delegated_amount: 0,
        close_authority: COption::None,
    }
    .pack_into_slice(&mut data);
    Account { lamports: 10_000_000, data, owner: spl_token::id(), executable: false, rent_epoch: 0 }
}

fn program_account<T: borsh::BorshSerialize>(v: &T, space: usize) -> Account {
    let mut data = borsh::to_vec(v).unwrap();
    data.resize(space, 0);
    Account { lamports: 10_000_000, data, owner: PROGRAM_ID, executable: false, rent_epoch: 0 }
}

/// A record as the PREVIOUS program version wrote it: the same account size,
/// but serialized without the fields added for M-6, so the padding is where
/// `price_set_at` / `max_price_age` now live. This is what the devnet pool's
/// accounts look like the moment the new program is deployed over them.
fn legacy_pool_account(p: &Pool) -> Account {
    let mut data = Vec::new();
    for k in [&p.owner, &p.oracle, &p.guardian, &p.hub_mint] {
        data.extend_from_slice(k);
    }
    data.extend_from_slice(&p.fee_bps.to_le_bytes());
    data.extend_from_slice(&p.max_price_deviation_bps.to_le_bytes());
    data.extend_from_slice(&p.min_price_update_interval.to_le_bytes());
    data.push(p.paused as u8);
    assert_eq!(data.len(), 141);
    data.resize(POOL_SPACE, 0);
    Account { lamports: 10_000_000, data, owner: PROGRAM_ID, executable: false, rent_epoch: 0 }
}
fn legacy_token_account(t: &TokenRec) -> Account {
    let mut data = Vec::new();
    data.extend_from_slice(&t.mint);
    data.extend_from_slice(&t.vault);
    data.push(t.decimals);
    data.extend_from_slice(&t.price.to_le_bytes());
    data.extend_from_slice(&t.reserve.to_le_bytes());
    data.extend_from_slice(&t.last_price_update.to_le_bytes());
    data.push(t.listed as u8);
    assert_eq!(data.len(), 98);
    data.resize(TOKEN_SPACE, 0);
    Account { lamports: 10_000_000, data, owner: PROGRAM_ID, executable: false, rent_epoch: 0 }
}

/// The custom-error suffix `process_transaction` reports for a `SwapError`.
fn custom(e: SwapError) -> String {
    format!("custom program error: {:#x}", e as u32 + 1)
}

/// Move the bank's clock forward by `secs`, so a staleness or cooldown bound
/// can be crossed deterministically instead of by sleeping.
async fn advance_clock(ctx: &mut ProgramTestContext, secs: i64) -> i64 {
    let mut clock: Clock = ctx.banks_client.get_sysvar().await.unwrap();
    clock.unix_timestamp += secs;
    ctx.set_sysvar(&clock);
    clock.unix_timestamp
}

struct Fx {
    ctx: ProgramTestContext,
    owner: Keypair,
    user: Keypair,
    hub_mint: Pubkey,
    alt_mint: Pubkey,
    hub_vault: Pubkey,
    alt_vault: Pubkey,
    user_hub: Pubkey,
    user_alt: Pubkey,
    /// A third mint with a vault ready, NOT listed — for `ListToken` tests.
    new_mint: Pubkey,
    new_vault: Pubkey,
}

/// Fixture knobs beyond the common four.
#[derive(Default)]
struct Opts {
    /// Write the pool and token records in the pre-M-6 byte layout (no
    /// `price_set_at`, no `max_price_age`) instead of the current one.
    legacy_layout: bool,
    /// Lamports to pre-fund the unlisted `new_mint`'s record PDA with.
    prefund_new_record: u64,
}

/// A pool with both sides listed and seeded, and a user holding hub tokens.
async fn setup(hub_reserve: u64, alt_reserve: u64, user_hub_balance: u64, fee_bps: u16) -> Fx {
    setup_with(hub_reserve, alt_reserve, user_hub_balance, fee_bps, Opts::default()).await
}

async fn setup_with(hub_reserve: u64, alt_reserve: u64, user_hub_balance: u64, fee_bps: u16, opts: Opts) -> Fx {
    let owner = Keypair::new();
    let user = Keypair::new();
    let hub_mint = Pubkey::new_unique();
    let alt_mint = Pubkey::new_unique();
    let hub_vault = Pubkey::new_unique();
    let alt_vault = Pubkey::new_unique();
    let user_hub = Pubkey::new_unique();
    let user_alt = Pubkey::new_unique();
    let new_mint = Pubkey::new_unique();
    let new_vault = Pubkey::new_unique();

    let mut pt = ProgramTest::new("solana_swap", PROGRAM_ID, processor!(process_instruction));
    for k in [owner.pubkey(), user.pubkey()] {
        pt.add_account(
            k,
            Account {
                lamports: 10_000_000_000,
                data: vec![],
                owner: solana_sdk::system_program::id(),
                executable: false,
                rent_epoch: 0,
            },
        );
    }
    pt.add_account(hub_mint, mint_account(HUB_DEC));
    pt.add_account(alt_mint, mint_account(ALT_DEC));
    pt.add_account(hub_vault, token_account(hub_mint, vault_authority(), hub_reserve));
    pt.add_account(alt_vault, token_account(alt_mint, vault_authority(), alt_reserve));
    pt.add_account(user_hub, token_account(hub_mint, user.pubkey(), user_hub_balance));
    pt.add_account(user_alt, token_account(alt_mint, user.pubkey(), 0));
    pt.add_account(new_mint, mint_account(ALT_DEC));
    pt.add_account(new_vault, token_account(new_mint, vault_authority(), 0));
    if opts.prefund_new_record > 0 {
        // The griefing pre-fund: lamports at the record address, no data,
        // system-owned — exactly what `create_account` chokes on.
        pt.add_account(
            token_pda(&new_mint),
            Account {
                lamports: opts.prefund_new_record,
                data: vec![],
                owner: solana_sdk::system_program::id(),
                executable: false,
                rent_epoch: 0,
            },
        );
    }

    let pool = Pool {
        owner: owner.pubkey().to_bytes(),
        oracle: owner.pubkey().to_bytes(),
        guardian: [0u8; 32],
        hub_mint: hub_mint.to_bytes(),
        fee_bps,
        max_price_deviation_bps: 1000,
        min_price_update_interval: 3600,
        paused: false,
        max_price_age: DEFAULT_MAX_PRICE_AGE,
    };
    // Reserves match the vault balances, as a real seed would leave them. The
    // hub's staleness stamp is left at 0 on purpose: it is exempt, and a swap
    // succeeding proves that exemption on every run.
    let hub_rec = TokenRec {
        mint: hub_mint.to_bytes(),
        vault: hub_vault.to_bytes(),
        decimals: HUB_DEC,
        price: PRICE_ONE,
        reserve: hub_reserve,
        last_price_update: 0,
        listed: true,
        price_set_at: 0,
    };
    let alt_rec = TokenRec {
        mint: alt_mint.to_bytes(),
        vault: alt_vault.to_bytes(),
        decimals: ALT_DEC,
        price: ALT_PRICE,
        reserve: alt_reserve,
        last_price_update: 0,
        listed: true,
        price_set_at: 0, // stamped from the bank clock below
    };
    if opts.legacy_layout {
        pt.add_account(pool_pda(), legacy_pool_account(&pool));
        pt.add_account(token_pda(&hub_mint), legacy_token_account(&hub_rec));
        pt.add_account(token_pda(&alt_mint), legacy_token_account(&alt_rec));
    } else {
        pt.add_account(pool_pda(), program_account(&pool, POOL_SPACE));
        pt.add_account(token_pda(&hub_mint), program_account(&hub_rec, TOKEN_SPACE));
        pt.add_account(token_pda(&alt_mint), program_account(&alt_rec, TOKEN_SPACE));
    }

    let mut ctx = pt.start_with_context().await;
    if !opts.legacy_layout {
        // Stamp the ALT price with the bank's own clock, as a real listing
        // would, so the default fixture is fresh regardless of wall time.
        let clock: Clock = ctx.banks_client.get_sysvar().await.unwrap();
        let fresh = TokenRec { price_set_at: clock.unix_timestamp, ..alt_rec };
        ctx.set_account(&token_pda(&alt_mint), &AccountSharedData::from(program_account(&fresh, TOKEN_SPACE)));
    }
    Fx { ctx, owner, user, hub_mint, alt_mint, hub_vault, alt_vault, user_hub, user_alt, new_mint, new_vault }
}

fn set_price_ix(fx: &Fx, mint: Pubkey, price: u128) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new_readonly(pool_pda(), false),
            AccountMeta::new_readonly(fx.owner.pubkey(), true),
            AccountMeta::new(token_pda(&mint), false),
        ],
        data: SwapInstruction::SetPrice { price }.to_bytes(),
    }
}

/// An owner-only pool setting (`SetFee`, `SetMaxPriceAge`, …), signed by `who`.
fn admin_ix(who: &Keypair, ix: SwapInstruction) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![AccountMeta::new(pool_pda(), false), AccountMeta::new_readonly(who.pubkey(), true)],
        data: ix.to_bytes(),
    }
}

fn list_token_ix(fx: &Fx, price: u128) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new_readonly(pool_pda(), false),
            AccountMeta::new(fx.owner.pubkey(), true),
            AccountMeta::new_readonly(fx.new_mint, false),
            AccountMeta::new_readonly(fx.new_vault, false),
            AccountMeta::new(token_pda(&fx.new_mint), false),
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        data: SwapInstruction::ListToken { price }.to_bytes(),
    }
}

async fn pool(ctx: &mut ProgramTestContext) -> Pool {
    let acct = ctx.banks_client.get_account(pool_pda()).await.unwrap().unwrap();
    Pool::deserialize(&mut &acct.data[..]).unwrap()
}

fn swap_ix(fx: &Fx, amount_in: u64, min_out: u64, reverse: bool) -> Instruction {
    let (rec_in, rec_out, user_in, user_out, vault_in, vault_out, mint_in, mint_out) = if reverse {
        (
            token_pda(&fx.alt_mint), token_pda(&fx.hub_mint), fx.user_alt, fx.user_hub,
            fx.alt_vault, fx.hub_vault, fx.alt_mint, fx.hub_mint,
        )
    } else {
        (
            token_pda(&fx.hub_mint), token_pda(&fx.alt_mint), fx.user_hub, fx.user_alt,
            fx.hub_vault, fx.alt_vault, fx.hub_mint, fx.alt_mint,
        )
    };
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new_readonly(pool_pda(), false),
            AccountMeta::new_readonly(fx.user.pubkey(), true),
            AccountMeta::new(rec_in, false),
            AccountMeta::new(rec_out, false),
            AccountMeta::new(user_in, false),
            AccountMeta::new(user_out, false),
            AccountMeta::new(vault_in, false),
            AccountMeta::new(vault_out, false),
            AccountMeta::new_readonly(mint_in, false),
            AccountMeta::new_readonly(mint_out, false),
            AccountMeta::new_readonly(vault_authority(), false),
            AccountMeta::new_readonly(spl_token::id(), false),
        ],
        data: SwapInstruction::Swap { amount_in, min_amount_out: min_out }.to_bytes(),
    }
}

async fn send(ctx: &mut ProgramTestContext, ix: Instruction, signer: &Keypair) -> Result<(), String> {
    let bh = ctx.banks_client.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&signer.pubkey()), &[signer], bh);
    ctx.banks_client.process_transaction(tx).await.map_err(|e| e.to_string())
}

async fn spl_amount(ctx: &mut ProgramTestContext, key: Pubkey) -> u64 {
    let acct = ctx.banks_client.get_account(key).await.unwrap().unwrap();
    spl_token::state::Account::unpack(&acct.data).unwrap().amount
}

async fn rec(ctx: &mut ProgramTestContext, mint: Pubkey) -> TokenRec {
    let acct = ctx.banks_client.get_account(token_pda(&mint)).await.unwrap().unwrap();
    TokenRec::deserialize(&mut &acct.data[..]).unwrap()
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn swap_pays_out_the_quoted_amount_and_books_both_reserves() {
    // 1000 hub units in, at 1.0 / 3180 => 0.314465408 ALT.
    let amount_in = 1_000_000_000_000u64;
    let expected = math::amount_out(amount_in, PRICE_ONE, HUB_DEC, ALT_PRICE, ALT_DEC, 0).unwrap();

    let mut fx = setup(0, 1_000_000_000_000, amount_in, 0).await;
    let ix = swap_ix(&fx, amount_in, 0, false);
    let user = fx.user.insecure_clone();
    send(&mut fx.ctx, ix, &user).await.expect("swap should succeed");

    assert_eq!(spl_amount(&mut fx.ctx, fx.user_alt).await, expected, "user received the quote");
    assert_eq!(spl_amount(&mut fx.ctx, fx.user_hub).await, 0, "input was taken");
    // The reserve is INTERNAL accounting and must track the vaults exactly.
    assert_eq!(rec(&mut fx.ctx, fx.hub_mint).await.reserve, amount_in);
    assert_eq!(rec(&mut fx.ctx, fx.alt_mint).await.reserve, 1_000_000_000_000 - expected);
    assert_eq!(spl_amount(&mut fx.ctx, fx.hub_vault).await, amount_in);
}

#[tokio::test]
async fn a_swap_can_never_drain_more_than_the_reserve() {
    // The output side holds one unit less than the swap would pay out.
    let amount_in = 1_000_000_000_000u64;
    let out = math::amount_out(amount_in, PRICE_ONE, HUB_DEC, ALT_PRICE, ALT_DEC, 0).unwrap();
    let mut fx = setup(0, out - 1, amount_in, 0).await;
    let ix = swap_ix(&fx, amount_in, 0, false);
    let user = fx.user.insecure_clone();
    let err = send(&mut fx.ctx, ix, &user).await.expect_err("must refuse to overdraw the lock");
    assert!(err.contains("custom program error"), "got: {err}");
    assert_eq!(spl_amount(&mut fx.ctx, fx.user_alt).await, 0, "nothing paid out");
}

#[tokio::test]
async fn slippage_bound_is_enforced() {
    let amount_in = 1_000_000_000_000u64;
    let out = math::amount_out(amount_in, PRICE_ONE, HUB_DEC, ALT_PRICE, ALT_DEC, 0).unwrap();
    let mut fx = setup(0, 1_000_000_000_000, amount_in, 0).await;
    let ix = swap_ix(&fx, amount_in, out + 1, false); // ask for one more than the quote
    let user = fx.user.insecure_clone();
    send(&mut fx.ctx, ix, &user).await.expect_err("must refuse below the caller's minimum");
    assert_eq!(spl_amount(&mut fx.ctx, fx.user_alt).await, 0);
}

#[tokio::test]
async fn the_fee_is_retained_as_reserve_not_paid_out() {
    let amount_in = 1_000_000_000_000u64;
    let gross = math::amount_out(amount_in, PRICE_ONE, HUB_DEC, ALT_PRICE, ALT_DEC, 0).unwrap();
    let net = math::amount_out(amount_in, PRICE_ONE, HUB_DEC, ALT_PRICE, ALT_DEC, 30).unwrap();
    assert!(net < gross, "a 30bps fee must reduce the output");

    let mut fx = setup(0, 1_000_000_000_000, amount_in, 30).await;
    let ix = swap_ix(&fx, amount_in, 0, false);
    let user = fx.user.insecure_clone();
    send(&mut fx.ctx, ix, &user).await.expect("swap should succeed");

    assert_eq!(spl_amount(&mut fx.ctx, fx.user_alt).await, net);
    // The input side grew by the WHOLE input while the output side shrank by
    // only the net — that difference is the fee, kept in the pool.
    assert_eq!(rec(&mut fx.ctx, fx.hub_mint).await.reserve, amount_in);
    assert_eq!(rec(&mut fx.ctx, fx.alt_mint).await.reserve, 1_000_000_000_000 - net);
}

#[tokio::test]
async fn a_paused_pool_refuses_swaps() {
    let amount_in = 1_000_000_000u64;
    let mut fx = setup(0, 1_000_000_000_000, amount_in, 0).await;

    let pause = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(pool_pda(), false),
            AccountMeta::new_readonly(fx.owner.pubkey(), true),
        ],
        data: SwapInstruction::Pause.to_bytes(),
    };
    let owner = fx.owner.insecure_clone();
    send(&mut fx.ctx, pause, &owner).await.expect("owner may pause");

    let ix = swap_ix(&fx, amount_in, 0, false);
    let user = fx.user.insecure_clone();
    send(&mut fx.ctx, ix, &user).await.expect_err("a paused pool must refuse");

    let unpause = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(pool_pda(), false),
            AccountMeta::new_readonly(fx.owner.pubkey(), true),
        ],
        data: SwapInstruction::Unpause.to_bytes(),
    };
    send(&mut fx.ctx, unpause, &owner).await.expect("owner may unpause");
    let ix = swap_ix(&fx, amount_in, 0, false);
    send(&mut fx.ctx, ix, &user).await.expect("swaps resume");
}

#[tokio::test]
async fn only_the_owner_may_unpause() {
    let mut fx = setup(0, 1_000, 1_000, 0).await;
    let stranger = Keypair::new();
    fx.ctx.banks_client.get_account(stranger.pubkey()).await.ok();
    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(pool_pda(), false),
            AccountMeta::new_readonly(fx.user.pubkey(), true),
        ],
        data: SwapInstruction::Unpause.to_bytes(),
    };
    let user = fx.user.insecure_clone();
    send(&mut fx.ctx, ix, &user).await.expect_err("a non-owner must not release the breaker");
}

#[tokio::test]
async fn the_hub_price_can_never_be_moved() {
    let mut fx = setup(0, 1_000, 1_000, 0).await;
    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new_readonly(pool_pda(), false),
            AccountMeta::new_readonly(fx.owner.pubkey(), true),
            AccountMeta::new(token_pda(&fx.hub_mint), false),
        ],
        data: SwapInstruction::SetPrice { price: 2 * PRICE_ONE }.to_bytes(),
    };
    let owner = fx.owner.insecure_clone();
    send(&mut fx.ctx, ix, &owner).await.expect_err("the unit of account is pinned at 1.0");
    assert_eq!(rec(&mut fx.ctx, fx.hub_mint).await.price, PRICE_ONE);
}

#[tokio::test]
async fn a_price_move_past_the_deviation_cap_is_refused() {
    let mut fx = setup(0, 1_000, 1_000, 0).await;
    let owner = fx.owner.insecure_clone();
    // The first move after listing skips the COOLDOWN (a -5.7% step, within cap).
    let ix = set_price_ix(&fx, fx.alt_mint, 3000 * PRICE_ONE);
    send(&mut fx.ctx, ix, &owner).await.expect("first reprice: no cooldown, within cap");
    assert_eq!(rec(&mut fx.ctx, fx.alt_mint).await.price, 3000 * PRICE_ONE);
    // Immediately again: the cooldown binds now.
    let ix = set_price_ix(&fx, fx.alt_mint, 3100 * PRICE_ONE);
    let err = send(&mut fx.ctx, ix, &owner).await.expect_err("second reprice inside the cooldown");
    assert!(err.contains(&custom(SwapError::PriceUpdateTooSoon)), "got: {err}");
    // Past the cooldown, the cap binds — 10% here, and this asks for +100%.
    advance_clock(&mut fx.ctx, 3601).await;
    let ix = set_price_ix(&fx, fx.alt_mint, 6000 * PRICE_ONE);
    let err = send(&mut fx.ctx, ix, &owner).await.expect_err("a 100% step past a 10% cap must be refused");
    assert!(err.contains(&custom(SwapError::PriceDeviationTooHigh)), "got: {err}");
    assert_eq!(rec(&mut fx.ctx, fx.alt_mint).await.price, 3000 * PRICE_ONE, "price unchanged");
}

/// M-6: the FIRST reprice after listing used to skip the deviation cap along
/// with the cooldown. Solidity exempts only the cooldown; so must this.
#[tokio::test]
async fn the_first_reprice_after_listing_is_capped_too() {
    let mut fx = setup(0, 1_000_000_000_000, 1_000, 0).await;
    let owner = fx.owner.insecure_clone();
    assert_eq!(rec(&mut fx.ctx, fx.alt_mint).await.last_price_update, 0, "never repriced");
    // A compromised oracle key's play: price the fresh listing at ~0 …
    let ix = set_price_ix(&fx, fx.alt_mint, 1);
    let err = send(&mut fx.ctx, ix, &owner).await.expect_err("first move past the cap must be refused");
    assert!(err.contains(&custom(SwapError::PriceDeviationTooHigh)), "got: {err}");
    // … or at 2x. Both exceed a 10% cap.
    let ix = set_price_ix(&fx, fx.alt_mint, 2 * ALT_PRICE);
    let err = send(&mut fx.ctx, ix, &owner).await.expect_err("first move past the cap must be refused");
    assert!(err.contains(&custom(SwapError::PriceDeviationTooHigh)), "got: {err}");
    assert_eq!(rec(&mut fx.ctx, fx.alt_mint).await.price, ALT_PRICE, "price unchanged");
    // Exactly at the cap (+10%) passes, and is still cooldown-free.
    let ix = set_price_ix(&fx, fx.alt_mint, ALT_PRICE + ALT_PRICE / 10);
    send(&mut fx.ctx, ix, &owner).await.expect("a step exactly at the cap is allowed");
    assert_eq!(rec(&mut fx.ctx, fx.alt_mint).await.price, ALT_PRICE + ALT_PRICE / 10);
}

// ---------------------------------------------------------------------------
// M-5: pre-funded PDAs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_prefunded_record_address_does_not_brick_list_token() {
    // Anyone can derive `["token", mint]` and send it a lamport before the
    // owner lists the mint; `create_account` would then fail forever.
    let mut fx = setup_with(0, 1_000, 1_000, 0, Opts { prefund_new_record: 1, ..Default::default() }).await;
    let owner = fx.owner.insecure_clone();
    let ix = list_token_ix(&fx, 5 * PRICE_ONE);
    send(&mut fx.ctx, ix, &owner).await.expect("a 1-lamport pre-fund must not block listing");
    let r = rec(&mut fx.ctx, fx.new_mint).await;
    assert!(r.listed);
    assert_eq!(r.price, 5 * PRICE_ONE);
    assert_eq!(r.vault, fx.new_vault.to_bytes());
    assert_ne!(r.price_set_at, 0, "listing starts the staleness clock");
    let acct = fx.ctx.banks_client.get_account(token_pda(&fx.new_mint)).await.unwrap().unwrap();
    assert_eq!(acct.owner, PROGRAM_ID);
    assert_eq!(acct.data.len(), TOKEN_SPACE);
    // Listing it AGAIN is still refused — the record exists now.
    let ix = list_token_ix(&fx, 6 * PRICE_ONE);
    let err = send(&mut fx.ctx, ix, &owner).await.expect_err("double listing");
    assert!(err.contains(&custom(SwapError::TokenAlreadyListed)), "got: {err}");
}

#[tokio::test]
async fn list_token_still_works_on_an_untouched_address() {
    let mut fx = setup(0, 1_000, 1_000, 0).await;
    let owner = fx.owner.insecure_clone();
    let ix = list_token_ix(&fx, 5 * PRICE_ONE);
    send(&mut fx.ctx, ix, &owner).await.expect("plain listing");
    assert!(rec(&mut fx.ctx, fx.new_mint).await.listed);
}

// ---------------------------------------------------------------------------
// M-6: price staleness
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_stale_price_refuses_swaps_until_the_oracle_confirms_it() {
    let amount_in = 1_000_000_000u64;
    let mut fx = setup(0, 1_000_000_000_000, 10 * amount_in, 0).await;
    let user = fx.user.insecure_clone();
    let owner = fx.owner.insecure_clone();

    // Fresh: trades. (The hub's stamp is 0 in the fixture — it is exempt.)
    let ix = swap_ix(&fx, amount_in, 0, false);
    send(&mut fx.ctx, ix, &user).await.expect("fresh price trades");

    // One second past the default day: refused, on either side of the pair.
    advance_clock(&mut fx.ctx, DEFAULT_MAX_PRICE_AGE + 1).await;
    let ix = swap_ix(&fx, amount_in + 1, 0, false);
    let err = send(&mut fx.ctx, ix, &user).await.expect_err("stale ALT as output");
    assert!(err.contains(&custom(SwapError::StalePrice)), "got: {err}");
    let ix = swap_ix(&fx, 1, 0, true);
    let err = send(&mut fx.ctx, ix, &user).await.expect_err("stale ALT as input");
    assert!(err.contains(&custom(SwapError::StalePrice)), "got: {err}");

    // The oracle re-confirms the SAME price (a zero move is within any cap and
    // the first reprice has no cooldown) and trading resumes.
    let ix = set_price_ix(&fx, fx.alt_mint, ALT_PRICE);
    send(&mut fx.ctx, ix, &owner).await.expect("re-confirming the price");
    let ix = swap_ix(&fx, amount_in + 2, 0, false);
    send(&mut fx.ctx, ix, &user).await.expect("confirmed price trades again");
}

/// The migration story: accounts written by the pre-M-6 program decode with the
/// new fields as 0 — which must fail CLOSED (default age, unstamped price =
/// stale), never open, and clear as soon as the oracle reprices.
#[tokio::test]
async fn a_legacy_record_fails_closed_until_repriced() {
    let amount_in = 1_000_000_000u64;
    let mut fx = setup_with(0, 1_000_000_000_000, 10 * amount_in, 0, Opts { legacy_layout: true, ..Default::default() }).await;
    let user = fx.user.insecure_clone();
    let owner = fx.owner.insecure_clone();

    let p = pool(&mut fx.ctx).await;
    assert_eq!(p.max_price_age, 0, "legacy pool decodes the new field as 0");
    assert_eq!(p.effective_max_price_age(), DEFAULT_MAX_PRICE_AGE);
    assert_eq!(rec(&mut fx.ctx, fx.alt_mint).await.price_set_at, 0);

    let ix = swap_ix(&fx, amount_in, 0, false);
    let err = send(&mut fx.ctx, ix, &user).await.expect_err("an unstamped price is stale");
    assert!(err.contains(&custom(SwapError::StalePrice)), "got: {err}");

    // Every other handler still reads the legacy record fine.
    let ix = set_price_ix(&fx, fx.alt_mint, ALT_PRICE);
    send(&mut fx.ctx, ix, &owner).await.expect("legacy record reprices");
    assert_ne!(rec(&mut fx.ctx, fx.alt_mint).await.price_set_at, 0);
    let ix = swap_ix(&fx, amount_in, 0, false);
    send(&mut fx.ctx, ix, &user).await.expect("trades once stamped");
    // And the record is now written in the current layout, same size.
    let acct = fx.ctx.banks_client.get_account(token_pda(&fx.alt_mint)).await.unwrap().unwrap();
    assert_eq!(acct.data.len(), TOKEN_SPACE);
}

#[tokio::test]
async fn set_max_price_age_is_owner_gated_positive_and_enforced() {
    let amount_in = 1_000_000_000u64;
    let mut fx = setup(0, 1_000_000_000_000, 10 * amount_in, 0).await;
    let user = fx.user.insecure_clone();
    let owner = fx.owner.insecure_clone();

    let ix = admin_ix(&user, SwapInstruction::SetMaxPriceAge { seconds: 10 });
    send(&mut fx.ctx, ix, &user).await.expect_err("not the owner");
    for bad in [0i64, -1, i64::MIN] {
        let ix = admin_ix(&owner, SwapInstruction::SetMaxPriceAge { seconds: bad });
        send(&mut fx.ctx, ix, &owner).await.expect_err("there is no value that turns the guard off");
    }
    assert_eq!(pool(&mut fx.ctx).await.max_price_age, DEFAULT_MAX_PRICE_AGE);

    let ix = admin_ix(&owner, SwapInstruction::SetMaxPriceAge { seconds: 10 });
    send(&mut fx.ctx, ix, &owner).await.expect("owner sets a 10s bound");
    assert_eq!(pool(&mut fx.ctx).await.max_price_age, 10);

    // Exactly at the bound still trades (<=), one past does not.
    advance_clock(&mut fx.ctx, 10).await;
    let ix = swap_ix(&fx, amount_in, 0, false);
    send(&mut fx.ctx, ix, &user).await.expect("10s old at a 10s bound is fresh");
    advance_clock(&mut fx.ctx, 1).await;
    let ix = swap_ix(&fx, amount_in + 1, 0, false);
    let err = send(&mut fx.ctx, ix, &user).await.expect_err("11s old is stale");
    assert!(err.contains(&custom(SwapError::StalePrice)), "got: {err}");
}

// ---------------------------------------------------------------------------
// M-6: parameter bounds
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_fee_is_capped_at_ten_percent() {
    let mut fx = setup(0, 1_000, 1_000, 0).await;
    let owner = fx.owner.insecure_clone();
    let ix = admin_ix(&owner, SwapInstruction::SetFee { fee_bps: MAX_FEE_BPS + 1 });
    let err = send(&mut fx.ctx, ix, &owner).await.expect_err("10.01% must be refused");
    assert!(err.contains(&custom(SwapError::FeeTooHigh)), "got: {err}");
    let ix = admin_ix(&owner, SwapInstruction::SetFee { fee_bps: 9_999 });
    let err = send(&mut fx.ctx, ix, &owner).await.expect_err("the old 99.99% ceiling is gone");
    assert!(err.contains(&custom(SwapError::FeeTooHigh)), "got: {err}");
    assert_eq!(pool(&mut fx.ctx).await.fee_bps, 0);
    let ix = admin_ix(&owner, SwapInstruction::SetFee { fee_bps: MAX_FEE_BPS });
    send(&mut fx.ctx, ix, &owner).await.expect("exactly 10% is allowed");
    assert_eq!(pool(&mut fx.ctx).await.fee_bps, MAX_FEE_BPS);
}

#[tokio::test]
async fn set_max_price_deviation_is_bounded_and_takes_effect() {
    let mut fx = setup(0, 1_000, 1_000, 0).await;
    let owner = fx.owner.insecure_clone();
    let user = fx.user.insecure_clone();
    let ix = admin_ix(&user, SwapInstruction::SetMaxPriceDeviation { bps: 500 });
    send(&mut fx.ctx, ix, &user).await.expect_err("not the owner");
    for bad in [0u16, 10_001, u16::MAX] {
        let ix = admin_ix(&owner, SwapInstruction::SetMaxPriceDeviation { bps: bad });
        send(&mut fx.ctx, ix, &owner).await.expect_err("outside 1..=10_000");
    }
    assert_eq!(pool(&mut fx.ctx).await.max_price_deviation_bps, 1000);
    let ix = admin_ix(&owner, SwapInstruction::SetMaxPriceDeviation { bps: 500 });
    send(&mut fx.ctx, ix, &owner).await.expect("owner tightens to 5%");
    assert_eq!(pool(&mut fx.ctx).await.max_price_deviation_bps, 500);
    // A 6% move now fails where it passed under the 10% cap.
    let ix = set_price_ix(&fx, fx.alt_mint, ALT_PRICE + ALT_PRICE * 6 / 100);
    let err = send(&mut fx.ctx, ix, &owner).await.expect_err("6% past a 5% cap");
    assert!(err.contains(&custom(SwapError::PriceDeviationTooHigh)), "got: {err}");
    let ix = set_price_ix(&fx, fx.alt_mint, ALT_PRICE + ALT_PRICE * 4 / 100);
    send(&mut fx.ctx, ix, &owner).await.expect("4% within a 5% cap");
}

#[tokio::test]
async fn the_reprice_cooldown_cannot_be_made_negative() {
    let mut fx = setup(0, 1_000, 1_000, 0).await;
    let owner = fx.owner.insecure_clone();
    let ix = admin_ix(&owner, SwapInstruction::SetMinPriceUpdateInterval { seconds: -1 });
    send(&mut fx.ctx, ix, &owner).await.expect_err("a negative cooldown is no cooldown");
    assert_eq!(pool(&mut fx.ctx).await.min_price_update_interval, 3600);
    let ix = admin_ix(&owner, SwapInstruction::SetMinPriceUpdateInterval { seconds: 0 });
    send(&mut fx.ctx, ix, &owner).await.expect("zero disables it, as in Solidity");
    assert_eq!(pool(&mut fx.ctx).await.min_price_update_interval, 0);
    let ix = admin_ix(&owner, SwapInstruction::SetMinPriceUpdateInterval { seconds: 60 });
    send(&mut fx.ctx, ix, &owner).await.expect("owner sets a minute");
    assert_eq!(pool(&mut fx.ctx).await.min_price_update_interval, 60);
}

#[tokio::test]
async fn swapping_a_token_for_itself_is_refused() {
    let amount_in = 1_000u64;
    let mut fx = setup(1_000_000, 1_000_000, amount_in, 0).await;
    let mut ix = swap_ix(&fx, amount_in, 0, false);
    // Point both sides at the hub.
    ix.accounts[3] = AccountMeta::new(token_pda(&fx.hub_mint), false);
    ix.accounts[5] = AccountMeta::new(fx.user_hub, false);
    ix.accounts[7] = AccountMeta::new(fx.hub_vault, false);
    ix.accounts[9] = AccountMeta::new_readonly(fx.hub_mint, false);
    let user = fx.user.insecure_clone();
    send(&mut fx.ctx, ix, &user).await.expect_err("same-token swap must be refused");
}

#[tokio::test]
async fn a_swap_cannot_be_pointed_at_another_assets_vault() {
    // The vault is pinned by the token record, so passing a different (even
    // well-formed) vault must fail rather than release the wrong liquidity.
    let amount_in = 1_000_000_000u64;
    let mut fx = setup(1_000_000_000_000, 1_000_000_000_000, amount_in, 0).await;
    let mut ix = swap_ix(&fx, amount_in, 0, false);
    ix.accounts[7] = AccountMeta::new(fx.hub_vault, false); // out-vault := hub's
    let user = fx.user.insecure_clone();
    send(&mut fx.ctx, ix, &user).await.expect_err("vault must match the token record");
}
