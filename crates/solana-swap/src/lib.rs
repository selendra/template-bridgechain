//! Solana same-chain swap pool — the on-chain counterpart of `SwapPool.sol`.
//!
//! Same primitive, different VM: every listed token carries an oracle-set price
//! quoted against ONE hub mint (price pinned at 1.0), a swap converts at the
//! pegged rate normalising for decimals, and the output is HARD-CAPPED by the
//! output token's reserve — so a swap can never drain the pool.
//!
//! The pricing math lives in [`math`] and is proven equal to the Solidity
//! contract's against fixtures that contract produced (`tests/parity.rs`). That
//! matters for the same reason the submissionId hash does: the UI quotes with
//! one implementation and the chain executes with the other, and a disagreement
//! of one unit is a swap that reverts or a payout that is wrong.
//!
//! Build: `bash scripts/testing/build-solana.sh swap`.
//!
//! Account model:
//!   * **Pool PDA** (`["pool"]`) — owner, oracle, guardian, hub mint, fee,
//!     price-move guards, pause flag. Initialized only by the program's upgrade
//!     authority, so governance cannot be front-run at deploy time (same rule as
//!     the gate's config).
//!   * **Token PDA** (`["token", mint]`) — one per listed mint: its price,
//!     decimals, vault and INTERNAL reserve. The reserve is accounting, not
//!     `balanceOf`: a raw token donation must not move the price cap, and a
//!     short transfer must not be credited (both mirror the Solidity pool).
//!   * **Vault** — an SPL token account per listed mint, owned by the single
//!     vault-authority PDA (`["vault_authority"]`), holding the pool's liquidity.
//!
//! Liquidity is protocol-owned: the owner seeds and withdraws it, there are no
//! LP shares. That is v1 in Solidity too.
//!
//! ## What this deliberately does NOT mirror
//!
//! `SwapPool.sol` has two-step ownership. This program has none: like
//! `solana-gate`, the account that deploys it governs it, because the BPF loader
//! already makes the upgrade authority the ultimate owner and a second,
//! weaker ownership story would be theatre. Rotate the upgrade authority instead.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    bpf_loader_upgradeable::{self, UpgradeableLoaderState},
    clock::Clock,
    entrypoint::ProgramResult,
    msg,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    program_pack::Pack,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    sysvar::Sysvar,
};

/// The pricing math and account layouts, shared with the off-chain readers.
pub use swap_math as math;
pub use swap_math::{
    amount_out, usd_value, PoolState as Pool, SwappedEvent, TokenState as TokenRec, BPS_DENOM,
    DEFAULT_MAX_PRICE_AGE, MAX_FEE_BPS, POOL_SEED, POOL_SPACE, PRICE_ONE, TOKEN_SEED, TOKEN_SPACE,
    VAULT_AUTHORITY_SEED,
};

// ---------------------------------------------------------------------------
// Instructions
// ---------------------------------------------------------------------------

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct InitPoolArgs {
    /// Swap fee in bps, charged on the USD value and retained as reserve. At
    /// most [`MAX_FEE_BPS`].
    pub fee_bps: u16,
    /// Largest price move a single `SetPrice` may make, in bps (1..=10_000).
    pub max_price_deviation_bps: u16,
    /// Minimum seconds between two reprices of the SAME token. With the
    /// deviation cap this bounds the price to one capped step per interval; the
    /// cap alone would let a compromised oracle walk the price within one slot.
    /// Must not be negative (a negative interval would let the oracle skip the
    /// cooldown entirely).
    ///
    /// The staleness bound is not an argument: every pool starts at
    /// [`DEFAULT_MAX_PRICE_AGE`] and the owner tunes it with `SetMaxPriceAge`.
    pub min_price_update_interval: i64,
    /// May pause but not unpause. `Pubkey::default()` for none.
    pub guardian: Pubkey,
    /// May set prices but not move liquidity. Defaults to the owner when
    /// `Pubkey::default()`.
    pub oracle: Pubkey,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub enum SwapInstruction {
    /// Create the pool. The hub mint's price is pinned at `PRICE_ONE` forever.
    Init(InitPoolArgs),
    /// List a mint at `price` (PRICE_ONE-scaled, quoted in hub units).
    ListToken { price: u128 },
    /// Move a listed token's price. Oracle-gated, deviation- and cooldown-capped.
    SetPrice { price: u128 },
    /// Move `amount` from the owner into the token's vault as reserve.
    SeedLiquidity { amount: u64 },
    /// Take `amount` of reserve back out to the owner.
    WithdrawLiquidity { amount: u64 },
    /// Swap `amount_in` of one listed token for another. Permissionless.
    Swap { amount_in: u64, min_amount_out: u64 },
    /// Trip the circuit breaker (owner or guardian).
    Pause,
    /// Release it (owner only — a guardian may stop but not start, as in Solidity).
    Unpause,
    SetGuardian { guardian: Pubkey },
    SetOracle { oracle: Pubkey },
    /// Owner only; at most [`MAX_FEE_BPS`].
    SetFee { fee_bps: u16 },
    // New variants are appended, never inserted: the discriminant is the wire
    // format, and `swap-admin` plus the browser encode the ones above by hand.
    /// Owner only; `1..=10_000` bps, as `SwapPool.setMaxPriceDeviation`.
    SetMaxPriceDeviation { bps: u16 },
    /// Owner only; seconds a token's price may be old before swaps refuse it.
    /// Must be positive — there is no "off" (see `PoolState::max_price_age`).
    SetMaxPriceAge { seconds: i64 },
    /// Owner only; the reprice cooldown, in seconds (zero disables it, as
    /// `SwapPool.setMinPriceUpdateInterval` allows; negative is refused).
    SetMinPriceUpdateInterval { seconds: i64 },
}

impl SwapInstruction {
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("instruction serializes")
    }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(thiserror::Error, Debug, Copy, Clone)]
pub enum SwapError {
    #[error("token is not listed")]
    TokenNotListed,
    #[error("token is already listed")]
    TokenAlreadyListed,
    #[error("tokenIn and tokenOut are the same")]
    SameToken,
    #[error("amount is zero")]
    ZeroAmount,
    #[error("price is zero")]
    ZeroPrice,
    #[error("output below the caller's minimum")]
    Slippage,
    #[error("output exceeds the token's reserve — the swap lock")]
    ExceedsLock,
    #[error("the hub mint's price is fixed at 1.0 and cannot be moved")]
    HubRepriceForbidden,
    #[error("price move exceeds the per-update deviation cap")]
    PriceDeviationTooHigh,
    #[error("price was updated too recently")]
    PriceUpdateTooSoon,
    #[error("pool is paused")]
    Paused,
    #[error("caller may not pause")]
    NotAuthorizedToPause,
    #[error("arithmetic overflow")]
    Overflow,
    #[error("vault is not owned by the pool's vault authority")]
    VaultNotOwned,
    #[error("vault has a delegate or close authority set")]
    VaultNotExclusive,
    #[error("account does not match the one the pool registered")]
    AccountMismatch,
    #[error("token's price is older than the pool's max_price_age")]
    StalePrice,
    #[error("fee exceeds the 10% cap")]
    FeeTooHigh,
}

impl From<SwapError> for ProgramError {
    fn from(e: SwapError) -> Self {
        ProgramError::Custom(e as u32 + 1)
    }
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let ix = SwapInstruction::try_from_slice(data).map_err(|_| ProgramError::InvalidInstructionData)?;
    match ix {
        SwapInstruction::Init(args) => process_init(program_id, accounts, args),
        SwapInstruction::ListToken { price } => process_list_token(program_id, accounts, price),
        SwapInstruction::SetPrice { price } => process_set_price(program_id, accounts, price),
        SwapInstruction::SeedLiquidity { amount } => process_liquidity(program_id, accounts, amount, true),
        SwapInstruction::WithdrawLiquidity { amount } => process_liquidity(program_id, accounts, amount, false),
        SwapInstruction::Swap { amount_in, min_amount_out } => {
            process_swap(program_id, accounts, amount_in, min_amount_out)
        }
        SwapInstruction::Pause => process_set_paused(program_id, accounts, true),
        SwapInstruction::Unpause => process_set_paused(program_id, accounts, false),
        SwapInstruction::SetGuardian { guardian } => process_set_role(program_id, accounts, Role::Guardian(guardian)),
        SwapInstruction::SetOracle { oracle } => process_set_role(program_id, accounts, Role::Oracle(oracle)),
        SwapInstruction::SetFee { fee_bps } => process_set_role(program_id, accounts, Role::Fee(fee_bps)),
        SwapInstruction::SetMaxPriceDeviation { bps } => {
            process_set_role(program_id, accounts, Role::MaxPriceDeviation(bps))
        }
        SwapInstruction::SetMaxPriceAge { seconds } => {
            process_set_role(program_id, accounts, Role::MaxPriceAge(seconds))
        }
        SwapInstruction::SetMinPriceUpdateInterval { seconds } => {
            process_set_role(program_id, accounts, Role::MinPriceUpdateInterval(seconds))
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The shared account layouts store plain 32-byte keys so they can also be
/// linked into the (alloy-using) read API; these convert at the boundary.
fn k(p: &Pubkey) -> swap_math::Key {
    p.to_bytes()
}
fn pk(b: &swap_math::Key) -> Pubkey {
    Pubkey::new_from_array(*b)
}

fn load_pool(program_id: &Pubkey, ai: &AccountInfo) -> Result<Pool, ProgramError> {
    let (expected, _) = Pubkey::find_program_address(&[POOL_SEED], program_id);
    if ai.key != &expected || ai.owner != program_id {
        return Err(SwapError::AccountMismatch.into());
    }
    // `deserialize`, not `try_from_slice`: accounts are sized with slack, and
    // `try_from_slice` treats the zero padding as trailing garbage.
    Pool::deserialize(&mut &ai.data.borrow()[..]).map_err(|_| ProgramError::InvalidAccountData)
}

fn store<T: BorshSerialize>(ai: &AccountInfo, v: &T) -> ProgramResult {
    let bytes = borsh::to_vec(v).map_err(|_| ProgramError::InvalidAccountData)?;
    let mut data = ai.data.borrow_mut();
    if bytes.len() > data.len() {
        return Err(ProgramError::AccountDataTooSmall);
    }
    data[..bytes.len()].copy_from_slice(&bytes);
    Ok(())
}

fn load_token(program_id: &Pubkey, ai: &AccountInfo, mint: &Pubkey) -> Result<TokenRec, ProgramError> {
    let (expected, _) = Pubkey::find_program_address(&[TOKEN_SEED, mint.as_ref()], program_id);
    if ai.key != &expected || ai.owner != program_id {
        return Err(SwapError::AccountMismatch.into());
    }
    let rec = TokenRec::deserialize(&mut &ai.data.borrow()[..])
        .map_err(|_| ProgramError::InvalidAccountData)?;
    if !rec.listed {
        return Err(SwapError::TokenNotListed.into());
    }
    Ok(rec)
}

fn require_owner(pool: &Pool, signer: &AccountInfo) -> ProgramResult {
    if k(signer.key) != pool.owner || !signer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    Ok(())
}

/// The initializer must be the program's upgrade authority — the deployer — so
/// nobody can race the deploy and claim a pool users may already be funding.
fn require_upgrade_authority(
    program_id: &Pubkey,
    program_ai: &AccountInfo,
    program_data_ai: &AccountInfo,
    who: &Pubkey,
) -> ProgramResult {
    if program_ai.key != program_id || program_ai.owner != &bpf_loader_upgradeable::id() {
        return Err(ProgramError::IncorrectProgramId);
    }
    let (expected_pd, _) =
        Pubkey::find_program_address(&[program_id.as_ref()], &bpf_loader_upgradeable::id());
    if program_data_ai.key != &expected_pd {
        return Err(ProgramError::InvalidArgument);
    }
    match bincode::deserialize::<UpgradeableLoaderState>(&program_data_ai.data.borrow())
        .map_err(|_| ProgramError::InvalidAccountData)?
    {
        UpgradeableLoaderState::ProgramData { upgrade_authority_address, .. } => {
            if upgrade_authority_address != Some(*who) {
                msg!("init: signer is not the program's upgrade authority");
                return Err(ProgramError::MissingRequiredSignature);
            }
            Ok(())
        }
        _ => Err(ProgramError::InvalidAccountData),
    }
}

/// A vault must hold this mint, be owned by the canonical vault-authority PDA,
/// and be controlled by nobody else — a pre-set delegate or close authority
/// drains liquidity past every other check (the gate's finding M-6).
fn check_vault(
    program_id: &Pubkey,
    vault: &AccountInfo,
    mint: &Pubkey,
    token_program: &Pubkey,
) -> ProgramResult {
    if vault.owner != token_program {
        return Err(ProgramError::IllegalOwner);
    }
    let state = spl_token::state::Account::unpack(&vault.data.borrow())
        .map_err(|_| ProgramError::InvalidAccountData)?;
    if &state.mint != mint {
        return Err(SwapError::AccountMismatch.into());
    }
    let (auth, _) = Pubkey::find_program_address(&[VAULT_AUTHORITY_SEED], program_id);
    if state.owner != auth {
        return Err(SwapError::VaultNotOwned.into());
    }
    let delegate: Option<Pubkey> = state.delegate.into();
    let close_authority: Option<Pubkey> = state.close_authority.into();
    if delegate.is_some() || close_authority.is_some() {
        return Err(SwapError::VaultNotExclusive.into());
    }
    Ok(())
}

fn vault_balance(vault: &AccountInfo) -> Result<u64, ProgramError> {
    Ok(spl_token::state::Account::unpack(&vault.data.borrow())
        .map_err(|_| ProgramError::InvalidAccountData)?
        .amount)
}

/// Create a program-owned PDA, tolerating a pre-funded address.
///
/// NOT `system_instruction::create_account`: that fails with "already in use"
/// when the address holds even one lamport, and every PDA here is derivable in
/// advance (`["pool"]`, `["token", mint]`), so anyone could send a lamport to a
/// mint's record address and make that mint unlistable — or brick `Init` —
/// until the program was redeployed (audit M-5; the gate's H-2). Transfer the
/// rent shortfall, then `allocate` + `assign`, which the system program permits
/// on a funded-but-empty account. Same sequence as the gate's `create_marker`.
fn create_pda<'a>(
    payer: &AccountInfo<'a>,
    account: &AccountInfo<'a>,
    system_program: &AccountInfo<'a>,
    program_id: &Pubkey,
    seeds: &[&[u8]],
    bump: u8,
    space: usize,
) -> ProgramResult {
    // A pre-funded address has lamports but no data and is still owned by the
    // system program; anything else is a genuine "already exists".
    if !account.data_is_empty() || account.owner != &solana_program::system_program::id() {
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    if system_program.key != &solana_program::system_program::id() {
        return Err(ProgramError::IncorrectProgramId);
    }
    let rent = Rent::get()?.minimum_balance(space);
    let have = account.lamports();
    if have < rent {
        invoke(
            &system_instruction::transfer(payer.key, account.key, rent - have),
            &[payer.clone(), account.clone(), system_program.clone()],
        )?;
    }
    let mut signer_seeds: Vec<&[u8]> = seeds.to_vec();
    let bump_arr = [bump];
    signer_seeds.push(&bump_arr);
    invoke_signed(
        &system_instruction::allocate(account.key, space as u64),
        &[account.clone(), system_program.clone()],
        &[&signer_seeds],
    )?;
    invoke_signed(
        &system_instruction::assign(account.key, program_id),
        &[account.clone(), system_program.clone()],
        &[&signer_seeds],
    )
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Accounts: [pool(w), payer(s,w), hub_mint, hub_vault, hub_token_rec(w),
///            token_program, system_program, program, program_data]
fn process_init(program_id: &Pubkey, accounts: &[AccountInfo], args: InitPoolArgs) -> ProgramResult {
    let it = &mut accounts.iter();
    let pool_ai = next_account_info(it)?;
    let payer = next_account_info(it)?;
    let hub_mint = next_account_info(it)?;
    let hub_vault = next_account_info(it)?;
    let hub_rec_ai = next_account_info(it)?;
    let token_program = next_account_info(it)?;
    let system_program = next_account_info(it)?;
    let program_ai = next_account_info(it)?;
    let program_data_ai = next_account_info(it)?;

    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    require_upgrade_authority(program_id, program_ai, program_data_ai, payer.key)?;
    if token_program.key != &spl_token::id() {
        return Err(ProgramError::IncorrectProgramId);
    }
    validate_init_args(&args)?;

    let (_, pool_bump) = Pubkey::find_program_address(&[POOL_SEED], program_id);
    let (expected_pool, _) = Pubkey::find_program_address(&[POOL_SEED], program_id);
    if pool_ai.key != &expected_pool {
        return Err(ProgramError::InvalidSeeds);
    }
    create_pda(payer, pool_ai, system_program, program_id, &[POOL_SEED], pool_bump, POOL_SPACE)?;

    let pool = Pool {
        owner: k(payer.key),
        oracle: k(&if args.oracle == Pubkey::default() { *payer.key } else { args.oracle }),
        guardian: k(&args.guardian),
        hub_mint: k(hub_mint.key),
        fee_bps: args.fee_bps,
        max_price_deviation_bps: args.max_price_deviation_bps,
        min_price_update_interval: args.min_price_update_interval,
        paused: false,
        // A day, as the Solidity constructor sets. Deliberately not an Init
        // argument: the dangerous configuration should be one an operator has
        // to choose afterwards, on purpose, via SetMaxPriceAge.
        max_price_age: DEFAULT_MAX_PRICE_AGE,
    };
    store(pool_ai, &pool)?;
    let now = Clock::get()?.unix_timestamp;

    // The hub is listed here, at exactly 1.0, so the pool is never in a state
    // where its unit of account is missing.
    let decimals = spl_token::state::Mint::unpack(&hub_mint.data.borrow())
        .map_err(|_| ProgramError::InvalidAccountData)?
        .decimals;
    check_vault(program_id, hub_vault, hub_mint.key, token_program.key)?;
    let (_, rec_bump) = Pubkey::find_program_address(&[TOKEN_SEED, hub_mint.key.as_ref()], program_id);
    create_pda(
        payer,
        hub_rec_ai,
        system_program,
        program_id,
        &[TOKEN_SEED, hub_mint.key.as_ref()],
        rec_bump,
        TOKEN_SPACE,
    )?;
    store(
        hub_rec_ai,
        &TokenRec {
            mint: k(hub_mint.key),
            vault: k(hub_vault.key),
            decimals,
            price: PRICE_ONE,
            reserve: 0,
            last_price_update: 0,
            listed: true,
            // The hub is exempt from the staleness check (its peg is fixed),
            // but stamp it so the record reads like every other token's.
            price_set_at: now,
        },
    )?;
    msg!("pool initialized; hub {} at 1.0", hub_mint.key);
    Ok(())
}

/// Accounts: [pool, owner(s,w), mint, vault, token_rec(w), token_program, system_program]
fn process_list_token(program_id: &Pubkey, accounts: &[AccountInfo], price: u128) -> ProgramResult {
    let it = &mut accounts.iter();
    let pool_ai = next_account_info(it)?;
    let owner = next_account_info(it)?;
    let mint = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let rec_ai = next_account_info(it)?;
    let token_program = next_account_info(it)?;
    let system_program = next_account_info(it)?;

    let pool = load_pool(program_id, pool_ai)?;
    require_owner(&pool, owner)?;
    if price == 0 {
        return Err(SwapError::ZeroPrice.into());
    }
    if token_program.key != &spl_token::id() {
        return Err(ProgramError::IncorrectProgramId);
    }
    // Listed means "has our record", not "has lamports": a pre-funded address
    // is still listable (see `create_pda`).
    if !rec_ai.data_is_empty() || rec_ai.owner == program_id {
        return Err(SwapError::TokenAlreadyListed.into());
    }
    check_vault(program_id, vault, mint.key, token_program.key)?;

    let decimals = spl_token::state::Mint::unpack(&mint.data.borrow())
        .map_err(|_| ProgramError::InvalidAccountData)?
        .decimals;
    let (expected, bump) = Pubkey::find_program_address(&[TOKEN_SEED, mint.key.as_ref()], program_id);
    if rec_ai.key != &expected {
        return Err(ProgramError::InvalidSeeds);
    }
    create_pda(owner, rec_ai, system_program, program_id, &[TOKEN_SEED, mint.key.as_ref()], bump, TOKEN_SPACE)?;
    store(
        rec_ai,
        &TokenRec {
            mint: k(mint.key),
            vault: k(vault.key),
            decimals,
            price,
            reserve: 0,
            // Stays 0 so the FIRST reprice skips the cooldown (Solidity's
            // `lastPriceUpdate`) …
            last_price_update: 0,
            listed: true,
            // … while the staleness clock starts now (Solidity's `priceSetAt`).
            price_set_at: Clock::get()?.unix_timestamp,
        },
    )?;
    msg!("listed {} at {}", mint.key, price);
    Ok(())
}

/// Accounts: [pool, oracle(s), token_rec(w)]
fn process_set_price(program_id: &Pubkey, accounts: &[AccountInfo], price: u128) -> ProgramResult {
    let it = &mut accounts.iter();
    let pool_ai = next_account_info(it)?;
    let oracle = next_account_info(it)?;
    let rec_ai = next_account_info(it)?;

    let pool = load_pool(program_id, pool_ai)?;
    if k(oracle.key) != pool.oracle || !oracle.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if price == 0 {
        return Err(SwapError::ZeroPrice.into());
    }
    let mut rec = TokenRec::deserialize(&mut &rec_ai.data.borrow()[..])
        .map_err(|_| ProgramError::InvalidAccountData)?;
    let rec_check = load_token(program_id, rec_ai, &pk(&rec.mint))?;
    if rec_check.mint != rec.mint {
        return Err(SwapError::AccountMismatch.into());
    }
    if rec.mint == pool.hub_mint {
        return Err(SwapError::HubRepriceForbidden.into());
    }

    let now = Clock::get()?.unix_timestamp;
    // Time gate: only the FIRST reprice after listing is exempt, and only from
    // the cooldown. After that the pair of guards binds the price to one capped
    // step per interval.
    if rec.last_price_update != 0
        && now < rec.last_price_update.saturating_add(pool.min_price_update_interval)
    {
        return Err(SwapError::PriceUpdateTooSoon.into());
    }
    // Deviation cap: on EVERY update, the first included — exactly as
    // `SwapPool.setPrice`. The listing price is the owner's, and exempting the
    // oracle's first move from the cap let a compromised oracle key reprice a
    // fresh token to ~0 and swap the reserve out in one step (audit M-6).
    let old = rec.price;
    let diff = if price > old { price - old } else { old - price };
    let cap = math::mul_div_floor(old, pool.max_price_deviation_bps as u128, BPS_DENOM as u128)
        .ok_or(SwapError::Overflow)?;
    if diff > cap {
        return Err(SwapError::PriceDeviationTooHigh.into());
    }
    msg!("price {} -> {}", rec.price, price);
    rec.price = price;
    rec.last_price_update = now;
    rec.price_set_at = now;
    store(rec_ai, &rec)
}

/// Seed (`inward = true`) or withdraw. Owner-gated both ways: liquidity is
/// protocol-owned in v1, exactly as in Solidity.
///
/// Accounts: [pool, owner(s), token_rec(w), owner_token_account(w), vault(w),
///            mint, vault_authority, token_program]
fn process_liquidity(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
    inward: bool,
) -> ProgramResult {
    let it = &mut accounts.iter();
    let pool_ai = next_account_info(it)?;
    let owner = next_account_info(it)?;
    let rec_ai = next_account_info(it)?;
    let owner_ata = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let mint = next_account_info(it)?;
    let vault_authority = next_account_info(it)?;
    let token_program = next_account_info(it)?;

    let pool = load_pool(program_id, pool_ai)?;
    require_owner(&pool, owner)?;
    if amount == 0 {
        return Err(SwapError::ZeroAmount.into());
    }
    let mut rec = load_token(program_id, rec_ai, mint.key)?;
    if rec.vault != k(vault.key) {
        return Err(SwapError::AccountMismatch.into());
    }
    if token_program.key != &spl_token::id() {
        return Err(ProgramError::IncorrectProgramId);
    }

    let before = vault_balance(vault)?;
    if inward {
        invoke(
            &spl_token::instruction::transfer_checked(
                token_program.key,
                owner_ata.key,
                mint.key,
                vault.key,
                owner.key,
                &[],
                amount,
                rec.decimals,
            )?,
            &[owner_ata.clone(), mint.clone(), vault.clone(), owner.clone(), token_program.clone()],
        )?;
        // Credit what ARRIVED, not what was asked for.
        let received = vault_balance(vault)?.checked_sub(before).ok_or(SwapError::Overflow)?;
        rec.reserve = rec.reserve.checked_add(received).ok_or(SwapError::Overflow)?;
        msg!("seeded {} (reserve {})", received, rec.reserve);
    } else {
        if amount > rec.reserve {
            return Err(SwapError::ExceedsLock.into());
        }
        let (auth, bump) = Pubkey::find_program_address(&[VAULT_AUTHORITY_SEED], program_id);
        if vault_authority.key != &auth {
            return Err(SwapError::VaultNotOwned.into());
        }
        // Effects first: the reserve is debited before the transfer goes out.
        rec.reserve -= amount;
        invoke_signed(
            &spl_token::instruction::transfer_checked(
                token_program.key,
                vault.key,
                mint.key,
                owner_ata.key,
                &auth,
                &[],
                amount,
                rec.decimals,
            )?,
            &[vault.clone(), mint.clone(), owner_ata.clone(), vault_authority.clone(), token_program.clone()],
            &[&[VAULT_AUTHORITY_SEED, &[bump]]],
        )?;
        msg!("withdrew {} (reserve {})", amount, rec.reserve);
    }
    store(rec_ai, &rec)
}

/// Accounts: [pool, user(s), rec_in(w), rec_out(w), user_in(w), user_out(w),
///            vault_in(w), vault_out(w), mint_in, mint_out, vault_authority,
///            token_program]
fn process_swap(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount_in: u64,
    min_amount_out: u64,
) -> ProgramResult {
    let it = &mut accounts.iter();
    let pool_ai = next_account_info(it)?;
    let user = next_account_info(it)?;
    let rec_in_ai = next_account_info(it)?;
    let rec_out_ai = next_account_info(it)?;
    let user_in = next_account_info(it)?;
    let user_out = next_account_info(it)?;
    let vault_in = next_account_info(it)?;
    let vault_out = next_account_info(it)?;
    let mint_in = next_account_info(it)?;
    let mint_out = next_account_info(it)?;
    let vault_authority = next_account_info(it)?;
    let token_program = next_account_info(it)?;

    let pool = load_pool(program_id, pool_ai)?;
    if pool.paused {
        return Err(SwapError::Paused.into());
    }
    if !user.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if mint_in.key == mint_out.key {
        return Err(SwapError::SameToken.into());
    }
    if amount_in == 0 {
        return Err(SwapError::ZeroAmount.into());
    }
    if token_program.key != &spl_token::id() {
        return Err(ProgramError::IncorrectProgramId);
    }

    let mut rec_in = load_token(program_id, rec_in_ai, mint_in.key)?;
    let mut rec_out = load_token(program_id, rec_out_ai, mint_out.key)?;
    // The vaults are pinned by the token records, never by whatever the caller
    // passed: otherwise a swap could be pointed at another asset's liquidity.
    if rec_in.vault != k(vault_in.key) || rec_out.vault != k(vault_out.key) {
        return Err(SwapError::AccountMismatch.into());
    }
    // Refuse a price the oracle has stopped confirming — on BOTH sides, since
    // either one being stale misprices the trade. Fail closed: a halted feed
    // must stop the pool, not leave it paying out at yesterday's price. The
    // rate limits on SetPrice do not cover this; they bound how fast a price
    // may move, not how old it may be.
    let now = Clock::get()?.unix_timestamp;
    if !pool.price_is_fresh(&rec_in, now) || !pool.price_is_fresh(&rec_out, now) {
        return Err(SwapError::StalePrice.into());
    }

    // Pull first, price on what arrived.
    let before = vault_balance(vault_in)?;
    invoke(
        &spl_token::instruction::transfer_checked(
            token_program.key,
            user_in.key,
            mint_in.key,
            vault_in.key,
            user.key,
            &[],
            amount_in,
            rec_in.decimals,
        )?,
        &[user_in.clone(), mint_in.clone(), vault_in.clone(), user.clone(), token_program.clone()],
    )?;
    let received = vault_balance(vault_in)?.checked_sub(before).ok_or(SwapError::Overflow)?;
    if received == 0 {
        return Err(SwapError::ZeroAmount.into());
    }

    let out = math::amount_out(
        received,
        rec_in.price,
        rec_in.decimals,
        rec_out.price,
        rec_out.decimals,
        pool.fee_bps,
    )
    .ok_or(SwapError::Overflow)?;
    if out == 0 {
        return Err(SwapError::ZeroAmount.into());
    }
    if out < min_amount_out {
        return Err(SwapError::Slippage.into());
    }
    // THE LOCK: never pay out more than this token's reserve.
    if out > rec_out.reserve {
        return Err(SwapError::ExceedsLock.into());
    }

    // Effects before the outgoing transfer. The fee stays behind as reserve:
    // the input side grows by the whole input, the output side shrinks by only
    // the net output.
    rec_in.reserve = rec_in.reserve.checked_add(received).ok_or(SwapError::Overflow)?;
    rec_out.reserve -= out;
    store(rec_in_ai, &rec_in)?;
    store(rec_out_ai, &rec_out)?;

    let (auth, bump) = Pubkey::find_program_address(&[VAULT_AUTHORITY_SEED], program_id);
    if vault_authority.key != &auth {
        return Err(SwapError::VaultNotOwned.into());
    }
    invoke_signed(
        &spl_token::instruction::transfer_checked(
            token_program.key,
            vault_out.key,
            mint_out.key,
            user_out.key,
            &auth,
            &[],
            out,
            rec_out.decimals,
        )?,
        &[vault_out.clone(), mint_out.clone(), user_out.clone(), vault_authority.clone(), token_program.clone()],
        &[&[VAULT_AUTHORITY_SEED, &[bump]]],
    )?;

    let ev = SwappedEvent {
        version: 1,
        sender: k(user.key),
        mint_in: k(mint_in.key),
        mint_out: k(mint_out.key),
        amount_in: received,
        amount_out: out,
        to: k(user_out.key),
    };
    solana_program::log::sol_log_data(&[&borsh::to_vec(&ev).map_err(|_| ProgramError::InvalidAccountData)?]);
    msg!("swapped {} -> {}", received, out);
    Ok(())
}

/// Accounts: [pool(w), signer(s)]
fn process_set_paused(program_id: &Pubkey, accounts: &[AccountInfo], paused: bool) -> ProgramResult {
    let it = &mut accounts.iter();
    let pool_ai = next_account_info(it)?;
    let who = next_account_info(it)?;

    let mut pool = load_pool(program_id, pool_ai)?;
    if !who.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    // A guardian may stop the pool but not start it — the same asymmetry the
    // Solidity pool and the gate both enforce.
    let allowed = if paused {
        k(who.key) == pool.owner
            || (pool.guardian != swap_math::Key::default() && k(who.key) == pool.guardian)
    } else {
        k(who.key) == pool.owner
    };
    if !allowed {
        return Err(SwapError::NotAuthorizedToPause.into());
    }
    pool.paused = paused;
    store(pool_ai, &pool)
}

enum Role {
    Guardian(Pubkey),
    Oracle(Pubkey),
    Fee(u16),
    MaxPriceDeviation(u16),
    MaxPriceAge(i64),
    MinPriceUpdateInterval(i64),
}

/// The bounds `Init` puts on its arguments — the same ones the setters enforce
/// afterwards, so a pool cannot be born in a state it could never be moved to.
/// Public and pure because `Init` itself cannot run under `solana-program-test`
/// (it reads the BPF loader's `ProgramData`), and these checks are what M-6
/// asked for.
pub fn validate_init_args(args: &InitPoolArgs) -> ProgramResult {
    check_deviation_bps(args.max_price_deviation_bps)?;
    check_fee_bps(args.fee_bps)?;
    if args.min_price_update_interval < 0 {
        return Err(ProgramError::InvalidArgument);
    }
    Ok(())
}

/// `SwapPool.setFee`'s bound: at most 10 %. The old `< 100 %` check let a fee
/// alone round every payout to zero.
fn check_fee_bps(bps: u16) -> ProgramResult {
    if bps > MAX_FEE_BPS {
        return Err(SwapError::FeeTooHigh.into());
    }
    Ok(())
}

/// `SwapPool.setMaxPriceDeviation`'s bound: `1..=10_000`. Zero would freeze
/// every price forever; above 100 % is meaningless.
fn check_deviation_bps(bps: u16) -> ProgramResult {
    if bps == 0 || bps > BPS_DENOM {
        return Err(ProgramError::InvalidArgument);
    }
    Ok(())
}

/// Accounts: [pool(w), owner(s)]
fn process_set_role(program_id: &Pubkey, accounts: &[AccountInfo], role: Role) -> ProgramResult {
    let it = &mut accounts.iter();
    let pool_ai = next_account_info(it)?;
    let owner = next_account_info(it)?;

    let mut pool = load_pool(program_id, pool_ai)?;
    require_owner(&pool, owner)?;
    match role {
        Role::Guardian(g) => pool.guardian = k(&g),
        Role::Oracle(o) => pool.oracle = k(&o),
        Role::Fee(f) => {
            check_fee_bps(f)?;
            pool.fee_bps = f;
        }
        Role::MaxPriceDeviation(bps) => {
            check_deviation_bps(bps)?;
            pool.max_price_deviation_bps = bps;
        }
        Role::MaxPriceAge(s) => {
            // Strictly positive: 0 is the "unconfigured" encoding an old record
            // decodes to, and there is deliberately no value that turns the
            // guard off. Relax it by setting it large.
            if s <= 0 {
                return Err(ProgramError::InvalidArgument);
            }
            pool.max_price_age = s;
        }
        Role::MinPriceUpdateInterval(s) => {
            if s < 0 {
                return Err(ProgramError::InvalidArgument);
            }
            pool.min_price_update_interval = s;
        }
    }
    store(pool_ai, &pool)
}

#[cfg(test)]
mod init_arg_tests {
    use super::*;

    fn args(fee_bps: u16, dev: u16, interval: i64) -> InitPoolArgs {
        InitPoolArgs {
            fee_bps,
            max_price_deviation_bps: dev,
            min_price_update_interval: interval,
            guardian: Pubkey::default(),
            oracle: Pubkey::default(),
        }
    }

    #[test]
    fn init_accepts_the_solidity_defaults() {
        assert_eq!(validate_init_args(&args(0, 1000, 3600)), Ok(()));
        assert_eq!(validate_init_args(&args(MAX_FEE_BPS, BPS_DENOM, 0)), Ok(()), "bounds are inclusive");
    }

    #[test]
    fn init_caps_the_fee_at_ten_percent() {
        // The old check was `< 100%`, which let a fee alone round every payout
        // to zero — `SwapPool.setFee` caps at 1000.
        assert_eq!(validate_init_args(&args(MAX_FEE_BPS + 1, 1000, 3600)), Err(SwapError::FeeTooHigh.into()));
        assert_eq!(validate_init_args(&args(9999, 1000, 3600)), Err(SwapError::FeeTooHigh.into()));
    }

    #[test]
    fn init_bounds_the_deviation_cap() {
        assert_eq!(validate_init_args(&args(0, 0, 3600)), Err(ProgramError::InvalidArgument));
        assert_eq!(validate_init_args(&args(0, BPS_DENOM + 1, 3600)), Err(ProgramError::InvalidArgument));
    }

    #[test]
    fn init_refuses_a_negative_cooldown() {
        // `now < last + (-1)` is never true for a fresh update, so a negative
        // interval would let the oracle skip the cooldown entirely.
        assert_eq!(validate_init_args(&args(0, 1000, -1)), Err(ProgramError::InvalidArgument));
    }

    #[test]
    fn new_instruction_variants_are_appended_after_the_existing_discriminants() {
        // The discriminant IS the wire format the admin tool and the browser
        // hand-encode; a reorder would silently repoint every one of them.
        assert_eq!(SwapInstruction::Init(args(0, 1000, 0)).to_bytes()[0], 0);
        assert_eq!(SwapInstruction::SetFee { fee_bps: 0 }.to_bytes()[0], 10);
        assert_eq!(SwapInstruction::SetMaxPriceDeviation { bps: 0 }.to_bytes(), vec![11, 0, 0]);
        assert_eq!(SwapInstruction::SetMaxPriceAge { seconds: 1 }.to_bytes(), [vec![12], 1i64.to_le_bytes().to_vec()].concat());
        assert_eq!(SwapInstruction::SetMinPriceUpdateInterval { seconds: 1 }.to_bytes()[0], 13);
    }
}
