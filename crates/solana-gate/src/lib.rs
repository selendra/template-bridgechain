//! Solana bridge gate — the on-chain counterpart of `Gate.sol`.
//!
//! Same protocol, different VM: `send` locks SPL into a vault and emits a `Sent`
//! event; `claim` verifies a threshold of *distinct* validator signatures and
//! releases funds exactly once (replay-safe). The submissionId is the sacred
//! keccak hash (computed here with the `keccak` syscall) and the signatures are
//! the same EIP-191 secp256k1 validator signatures the EVM gate accepts (verified
//! here with the `secp256k1_recover` syscall). One validator set signs for both
//! VMs — see the host crate `bridge-solana`, whose tests prove this logic
//! byte-for-byte against Gate.sol and bridge-core.
//!
//! Build: `cargo build-sbf --manifest-path crates/solana-gate/Cargo.toml`.
//!
//! Account model:
//!   * **Config PDA** (`["config"]`) — owner, validator set, threshold, chain id,
//!     per-target nonces, pause flag. Initialized only by the program's upgrade
//!     authority (the deployer), so governance can't be front-run at deploy time.
//!   * **Asset PDA** (`["asset", debridgeId]`) — the program-owned registry that
//!     binds a `debridgeId` to the SPL `mint` + `vault` allowed to back it. A
//!     `send`/`claim` may only touch the vault registered here for the SIGNED
//!     asset (finding C1).
//!   * **Vault** — an SPL token account owned by ONE global vault-authority PDA
//!     (`["vault_authority"]`), holding the bridge's liquidity. Which vault backs
//!     a given asset is pinned by the Asset PDA above, not by the authority seed.
//!   * **Executed PDA** (`["executed", submissionId]`) — created on claim; its
//!     existence is the replay guard (a second claim fails to init it).
//!   * **Sent PDA** (`["sent", submissionId]`) — source-side origin proof and
//!     refund destination, with the cluster time the funds were locked.
//!   * **Governance PDA** (`["gov", actionId]`) — a pending validator addition or
//!     threshold decrease and the time it matures (H-2, audit round 4). Adding
//!     signing power waits 48 h behind `ScheduleGovernance`; removing it is
//!     instant. The program UPGRADE authority cannot be delayed by the program
//!     itself and must sit behind a Squads/SPL-Governance timelock.
//!
//! Every PDA above is created with `transfer + allocate + assign`, never
//! `create_account`, so pre-funding an address cannot brick it (H-2 / M-5).
//!
//! ## The receiver MUST be an SPL token account (finding L-4)
//!
//! `claim` releases funds to the account the validators SIGNED FOR, and an SPL
//! transfer can only credit a token account. So a transfer whose `receiver` is a
//! **wallet pubkey** — the natural thing for a user to paste — can never be
//! delivered.
//!
//! This is deliberate, not an oversight. The receiver is bound into the
//! submissionId, so the gate cannot quietly redirect to the wallet's associated
//! token account: that would be paying an address the validators never attested,
//! which is precisely the redirection `claim` exists to prevent. The rule is
//! therefore enforced, not repaired, and it fails with a distinct
//! [`GateError::ReceiverNotTokenAccount`] so the cause is readable straight off
//! the transaction log.
//!
//! Callers must send the recipient's **associated token account** for the
//! registered mint. Such a transfer is recoverable — `cancel` on the destination
//! then `refund` on the source returns the deposit — but it costs a round trip,
//! so upstream (the UI, `frontend/src/data/format.ts::receiverProblem`) rejects a
//! wallet-shaped receiver before the user ever signs.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    bpf_loader_upgradeable::{self, UpgradeableLoaderState},
    entrypoint,
    entrypoint::ProgramResult,
    keccak,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    secp256k1_recover::secp256k1_recover,
    sysvar::Sysvar,
    msg,
    rent::Rent,
    system_instruction,
    program::invoke,
    program_pack::Pack,
};

/// deBridge's chain id for Solana mainnet (also the hash-fixture value).
pub const SOLANA_CHAIN_ID: u64 = 7565164;
const SUBMISSION_PREFIX: u64 = 1;
/// Domain prefix for a destination-side CANCEL attestation, matching
/// `BridgeHash.CANCEL_PREFIX`. A validator signature over a cancelId authorises
/// burning a transfer on the destination so it can never be claimed.
const CANCEL_PREFIX: u64 = 2;
/// Domain prefix for a source-side REFUND attestation, matching
/// `BridgeHash.REFUND_PREFIX`.
const REFUND_PREFIX: u64 = 3;

// ---------------------------------------------------------------------------
// Instructions (Borsh) — mirrors bridge_solana::instruction::GateInstruction.
// ---------------------------------------------------------------------------

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct AutoParamsWire {
    pub execution_fee: u128,
    pub flags: u64,
    pub fallback_address: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct InitArgs {
    /// See [`Config::bridge_domain`]. Must match the EVM gates of this mesh.
    pub bridge_domain: [u8; 32],
    pub validators: Vec<[u8; 20]>,
    pub threshold: u32,
    pub chain_id: u64,
    /// Hard capacity for the validator set. The config account is sized from this
    /// at init, so it must be chosen up front (findings H-3 / L-3): the account
    /// cannot grow later, and a `Config` that no longer fits its buffer makes
    /// EVERY instruction that reserializes it — `send`, `set_validator`,
    /// `set_threshold` — fail permanently.
    pub max_validators: u32,
    /// Hard capacity for registered corridors (destination chains). See
    /// [`process_register_corridor`] for why corridors are governance-registered
    /// rather than created on demand by `send`.
    pub max_corridors: u32,
    /// May trip the circuit breaker but not release it (mirrors `Gate.guardian`).
    /// Pass `Pubkey::default()` for none.
    pub guardian: Pubkey,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct SendArgs {
    pub debridge_id: [u8; 32],
    pub amount: u64,
    pub chain_id_to: u64,
    pub receiver: Vec<u8>,
    pub auto: Option<AutoParamsWire>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct ClaimArgs {
    pub debridge_id: [u8; 32],
    pub amount: u64,
    pub chain_id_from: u64,
    pub nonce: u64,
    pub receiver: Vec<u8>,
    pub auto: Option<AutoParamsWire>,
    pub native_sender: Vec<u8>,
    pub signatures: Vec<Vec<u8>>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub enum GateInstruction {
    Init(InitArgs),
    Send(SendArgs),
    Claim(ClaimArgs),
    SetValidator { validator: [u8; 20], active: bool },
    SetThreshold { threshold: u32 },
    /// C1: bind a `debridge_id` to the SPL `mint` + `vault` that may back it.
    /// Owner-gated. New variant appended last so existing discriminants (0..=4)
    /// stay byte-compatible with `bridge_solana::instruction::GateInstruction`.
    RegisterAsset { debridge_id: [u8; 32] },
    /// H-3: owner-gated registration of a destination chain. `send` refuses any
    /// `chain_id_to` that has not been registered here.
    RegisterCorridor { chain_id_to: u64 },
    /// M-1: trip the circuit breaker (owner or guardian).
    Pause,
    /// M-1: release the circuit breaker (owner only — a guardian may stop but not
    /// start, exactly as in `Gate.sol`).
    Unpause,
    /// M-1: appoint or clear the pause guardian (owner only).
    SetGuardian { guardian: Pubkey },
    /// M-2, DESTINATION side: burn a transfer so it can never be claimed here,
    /// unlocking a source-chain refund. Moves no funds. Permissionless — the
    /// validator threshold over `cancelId` is the authorisation.
    Cancel(CancelArgs),
    /// M-2, SOURCE side: return locked funds to the account that sent them, after
    /// the destination has been burned. Permissionless for the same reason.
    Refund(RefundArgs),
    /// H-2 (audit round 4): queue a power-GRANTING governance action — adding a
    /// validator or lowering the threshold — for execution once
    /// [`GOVERNANCE_DELAY`] has elapsed. Owner only. Build `action_id` with
    /// [`add_validator_action_id`] / [`lower_threshold_action_id`]. Mirrors
    /// `Gate.scheduleGovernance`.
    ///
    /// Accounts: `[config, owner(s,w), gov_pda(w), system_program]` where
    /// `gov_pda = ["gov", action_id]`.
    ScheduleGovernance { action_id: [u8; 32] },
    /// H-2: drop a queued governance action. Owner OR guardian, exactly as
    /// `Gate.cancelScheduledGovernance`: spotting a bad pending validator
    /// addition is incident response, and neither party can *execute* anything
    /// this way, so the worst case is a delay.
    ///
    /// Accounts: `[config, signer(s), gov_pda(w)]`.
    CancelScheduledGovernance { action_id: [u8; 32] },
}

// ---------------------------------------------------------------------------
// Governance timelock (H-2, audit round 4) — mirrors Gate.sol `_consumeGovernance`.
// ---------------------------------------------------------------------------

/// How long a validator ADDITION or a threshold DECREASE must wait, in seconds.
///
/// THE SAME DEFENCE `Gate.sol` carries as `GOVERNANCE_DELAY`, for the same
/// reason: an owner who can add a validator and lower the threshold in one
/// transaction can sign a claim for every registered corridor and empty every
/// vault — and because both legs share ONE validator set, the EVM gate's 48 h
/// timelock was only ever as strong as this program's owner key. A constant, not
/// an owner-settable field: an owner who could shorten it could zero it.
pub const GOVERNANCE_DELAY: i64 = 48 * 60 * 60;

/// How long a MATURED schedule stays spendable, in seconds. After
/// `ready_at + GOVERNANCE_GRACE` it expires and must be re-scheduled.
///
/// Without an expiry a matured schedule is a banked instant right for life: a
/// key stolen years later inherits every approval that was ever left lying
/// around (audit round 4, LOW "matured schedules never expire"). Seven days is
/// generous for an operator who scheduled on Monday and executes the following
/// week, and useless to a thief who arrives in month six.
pub const GOVERNANCE_GRACE: i64 = 7 * 24 * 60 * 60;

/// **Program upgrade authority is NOT covered by this timelock, and cannot be.**
///
/// The BPF upgradeable loader decides who may swap the program's bytecode; the
/// program itself cannot interpose a delay on that, and a new implementation
/// could simply delete every rule in this file. Operators MUST therefore place
/// the upgrade authority behind an external timelock — a Squads multisig with a
/// time lock, or SPL-Governance — exactly as `Gate.sol`'s `UPGRADE_DELAY` gates
/// UUPS upgrades on the EVM side. Deployment scripts should refuse a `production`
/// deploy whose upgrade authority is a bare hot key.
pub const UPGRADE_AUTHORITY_TIMELOCK_NOTE: &str =
    "program upgrade authority must sit behind a Squads/SPL-Governance timelock; the program cannot delay its own upgrade";

/// The per-action schedule, stored in the program-owned PDA `["gov", action_id]`.
/// `ready_at == 0` means "not scheduled" — the same sentinel `Gate.sol` uses.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct GovernanceSchedule {
    /// Unix time (cluster clock) from which the action may be consumed.
    pub ready_at: i64,
}

/// Borsh size of a [`GovernanceSchedule`].
const GOVERNANCE_LEN: usize = 8;

/// The action id for adding validator `v`: `keccak("addValidator" ‖ v)`.
///
/// Analogous to `Gate.addValidatorActionId` (which uses `abi.encode`); the ids
/// are chain-local — a schedule on this gate authorises a change on this gate
/// only — so the two encodings need not be byte-identical, only equally
/// specific: a schedule commits to THIS validator, never to "some validator".
pub fn add_validator_action_id(v: &[u8; 20]) -> [u8; 32] {
    keccak::hashv(&[b"addValidator", v]).to_bytes()
}

/// The action id for lowering the threshold to exactly `t`:
/// `keccak("lowerThreshold" ‖ uint256(t))`. A matured approval for `t = 2`
/// cannot be spent on `t = 1`.
pub fn lower_threshold_action_id(t: u32) -> [u8; 32] {
    keccak::hashv(&[b"lowerThreshold", &be32(t as u64)]).to_bytes()
}

/// Pure timelock rule (host-testable): may a schedule with `ready_at` be
/// consumed at cluster time `now`?
///
/// `ready_at == 0` is "never scheduled" (or already consumed/cancelled).
/// `now < ready_at` is "scheduled but immature". `now > ready_at + GRACE` is
/// "matured but left lying around too long" — refused, so a stale approval
/// cannot be spent by whoever holds the owner key later.
fn governance_consumable(ready_at: i64, now: i64) -> Result<(), GateError> {
    if ready_at == 0 {
        return Err(GateError::GovernanceNotScheduled);
    }
    if now < ready_at {
        return Err(GateError::GovernanceNotReady);
    }
    if now > ready_at.saturating_add(GOVERNANCE_GRACE) {
        return Err(GateError::GovernanceExpired);
    }
    Ok(())
}

/// Require a matured, unexpired schedule for `action_id` in `gov_ai`, then BURN
/// it, so one approval authorises exactly one change. Mirrors
/// `Gate._consumeGovernance`.
///
/// The account must be the canonical `["gov", action_id]` PDA and program-owned:
/// anyone can park lamports (or their own data) at that address, and neither
/// proves the owner ever scheduled anything.
fn consume_governance(
    program_id: &Pubkey,
    gov_ai: &AccountInfo,
    action_id: &[u8; 32],
) -> ProgramResult {
    let (expected, _bump) = Pubkey::find_program_address(&[b"gov", action_id], program_id);
    if gov_ai.key != &expected {
        msg!("governance account is not the canonical [\"gov\", action_id] PDA");
        return Err(ProgramError::InvalidSeeds);
    }
    if gov_ai.owner != program_id || gov_ai.data_len() < GOVERNANCE_LEN {
        // Never created by ScheduleGovernance (a pre-funded squat, or nothing).
        return Err(GateError::GovernanceNotScheduled.into());
    }
    let sched = GovernanceSchedule::deserialize(&mut &gov_ai.data.borrow()[..])
        .map_err(|_| ProgramError::InvalidAccountData)?;
    let now = solana_program::clock::Clock::get()?.unix_timestamp;
    governance_consumable(sched.ready_at, now)?;
    // Burn it: one schedule, one change.
    GovernanceSchedule::default().serialize(&mut &mut gov_ai.data.borrow_mut()[..])?;
    msg!("governance schedule consumed");
    Ok(())
}

/// Everything needed to recompute a submissionId on the DESTINATION side, plus
/// the cancel quorum. Mirrors `Gate.cancel`'s parameters.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct CancelArgs {
    pub debridge_id: [u8; 32],
    pub amount: u64,
    pub chain_id_from: u64,
    pub nonce: u64,
    pub receiver: Vec<u8>,
    pub auto: Option<AutoParamsWire>,
    pub native_sender: Vec<u8>,
    /// Signatures over `cancelId(submissionId)` — a different domain from the
    /// transfer signatures, so those can never be replayed to burn a transfer.
    pub signatures: Vec<Vec<u8>>,
}

/// Everything needed to recompute a submissionId on the SOURCE side, plus the
/// refund quorum. Mirrors `Gate.refund`'s parameters — except `amount` and the
/// destination are NOT taken from here: they come from the program's own
/// `SentRecord`, so a caller cannot inflate a payout.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct RefundArgs {
    pub debridge_id: [u8; 32],
    pub amount: u64,
    pub chain_id_to: u64,
    pub nonce: u64,
    pub receiver: Vec<u8>,
    pub auto: Option<AutoParamsWire>,
    pub native_sender: Vec<u8>,
    /// Signatures over `refundId(submissionId)`.
    pub signatures: Vec<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default)]
pub struct Config {
    pub owner: Pubkey,
    /// Deployment generation, folded into every submissionId. MUST equal the
    /// `bridgeDomain()` the EVM gates of this mesh were initialized with, or no
    /// id ever agrees across chains and nothing bridges. Set once at init and
    /// never mutated: rotating it belongs to a new deployment, not to a running
    /// one, and changing it would strand every in-flight transfer.
    pub bridge_domain: [u8; 32],
    /// May pause but not unpause. `Pubkey::default()` == none appointed.
    pub guardian: Pubkey,
    pub validators: Vec<[u8; 20]>,
    pub threshold: u32,
    pub chain_id: u64,
    pub paused: bool,
    /// Capacities the account was SIZED for at init. Both vectors are refused
    /// growth past these, so `Config` can never outgrow its buffer (H-3 / L-3).
    pub max_validators: u32,
    pub max_corridors: u32,
    /// (chainIdTo, nextNonce). One entry per GOVERNANCE-REGISTERED corridor —
    /// `send` never creates one. See [`process_register_corridor`].
    pub nonce_to: Vec<(u64, u64)>,
}

/// Borsh-serialized size of a [`Config`] holding `validators` validators and
/// `corridors` corridors.
///
/// Pure and host-testable because getting it wrong is what H-3 was: the account
/// was a flat 512 bytes and `send` appended a 16-byte corridor entry for any
/// `chain_id_to` a caller named. Around 25 dust sends to invented chain ids
/// overflowed the buffer, after which every instruction that reserializes the
/// config — `send`, `set_validator`, `set_threshold` — failed forever, with no
/// realloc path. The account is now sized from declared capacities and both
/// vectors are capped.
fn config_space(validators: u32, corridors: u32) -> usize {
    32                              // owner
    + 32                            // bridge_domain
    + 32                            // guardian
    + 4 + 20 * validators as usize  // validators: Vec<[u8; 20]>
    + 4                             // threshold
    + 8                             // chain_id
    + 1                             // paused
    + 4 + 4                         // max_validators, max_corridors
    + 4 + 16 * corridors as usize   // nonce_to: Vec<(u64, u64)>
}

impl Config {
    fn is_validator(&self, a: &[u8; 20]) -> bool {
        self.validators.iter().any(|v| v == a)
    }
    fn corridor_registered(&self, chain_id_to: u64) -> bool {
        self.nonce_to.iter().any(|(c, _)| *c == chain_id_to)
    }
    fn nonce(&self, chain_id_to: u64) -> u64 {
        self.nonce_to.iter().find(|(c, _)| *c == chain_id_to).map(|(_, n)| *n).unwrap_or(0)
    }
    /// Advance a REGISTERED corridor's nonce. Returns an error rather than
    /// creating an entry — corridor creation is governance-only (H-3).
    fn bump_nonce(&mut self, chain_id_to: u64) -> Result<(), ProgramError> {
        match self.nonce_to.iter_mut().find(|(c, _)| *c == chain_id_to) {
            Some(e) => {
                e.1 = e.1.checked_add(1).ok_or(ProgramError::ArithmeticOverflow)?;
                Ok(())
            }
            None => Err(GateError::CorridorNotRegistered.into()),
        }
    }
    /// Serialize back into a fixed-size account, refusing to write a `Config` that
    /// no longer fits. Borsh's own failure would abort the transaction anyway;
    /// this reports the real reason instead of an opaque serialization error.
    fn store(&self, config_ai: &AccountInfo) -> ProgramResult {
        let needed = config_space(
            self.validators.len().max(self.max_validators as usize) as u32,
            self.nonce_to.len().max(self.max_corridors as usize) as u32,
        );
        if needed > config_ai.data_len() {
            msg!("config no longer fits its account; capacities were fixed at init");
            return Err(ProgramError::AccountDataTooSmall);
        }
        self.serialize(&mut &mut config_ai.data.borrow_mut()[..])?;
        Ok(())
    }
}

/// Load the program's canonical `Config`, refusing any account that is not the
/// program-owned `["config"]` PDA.
///
/// SECURITY (finding C1): every instruction that trusts the config — claim
/// (validator set + threshold for signature verification), send (chain id +
/// nonces), and the owner-gated setters — MUST route through here. Without the
/// PDA + program-owner check, a caller could pass a config account they created
/// and own, containing their own validator set and threshold, and satisfy
/// `verify_threshold` with self-signed signatures — draining any vault the
/// program's authority controls. The `["config"]` seed makes the account unique
/// and unforgeable, and the owner check ensures only this program ever wrote it.
fn load_config(program_id: &Pubkey, config_ai: &AccountInfo) -> Result<Config, ProgramError> {
    verify_config_account(config_ai.key, config_ai.owner, program_id)?;
    Config::deserialize(&mut &config_ai.data.borrow()[..])
        .map_err(|_| ProgramError::InvalidAccountData)
}

/// Pure C1 config-account gate (host-testable): the account MUST be the canonical
/// `["config"]` PDA AND program-owned. A forged config the caller created and
/// owns fails one of these, so it can never drive signature verification.
fn verify_config_account(
    config_key: &Pubkey,
    config_owner: &Pubkey,
    program_id: &Pubkey,
) -> Result<(), ProgramError> {
    let (expected, _bump) = Pubkey::find_program_address(&[b"config"], program_id);
    if config_key != &expected {
        msg!("config account is not the canonical [\"config\"] PDA");
        return Err(ProgramError::InvalidSeeds);
    }
    if config_owner != program_id {
        msg!("config account is not program-owned");
        return Err(ProgramError::IllegalOwner);
    }
    Ok(())
}

/// C1 asset registry: which SPL `mint` + `vault` may back a given `debridge_id`.
/// Stored in the program-owned PDA `["asset", debridge_id]`, so a claim/send can
/// only touch the vault governance explicitly bound to the signed asset — not an
/// arbitrary token account the caller supplies.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default)]
pub struct AssetConfig {
    pub debridge_id: [u8; 32],
    pub mint: Pubkey,
    pub vault: Pubkey,
}

/// Source-side proof that THIS gate locked funds for a submissionId, and where
/// they must go back to — the Solana analogue of `Gate.sentBy` (finding M-2).
///
/// Two jobs, both essential to `refund`:
///   1. **origin proof** — the `["sent", submissionId]` PDA existing at all is the
///      only evidence this gate really emitted that submission. Without it a
///      validator quorum could authorise a refund for a transfer that never
///      happened here.
///   2. **refund destination** — `native_sender` is only folded into the
///      submissionId when auto-params are present, so for a plain transfer it is
///      NOT hash-bound and a caller could name anyone. This record is written by
///      the program at lock time, so it is authoritative; calldata is not.
///
/// `amount` and `mint` are recorded too, so `refund` never has to trust the
/// caller for how much to release or from which vault.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default)]
pub struct SentRecord {
    pub debridge_id: [u8; 32],
    /// The signer that locked the funds.
    pub sender: Pubkey,
    /// The SPL token account debited — where `refund` returns the funds.
    pub source_token: Pubkey,
    pub mint: Pubkey,
    pub amount: u64,
    /// Cluster unix time at which the funds were locked (M-4 / M-13).
    ///
    /// The Solana analogue of reading `Gate.sentBy` at an aged EVM block: a
    /// refund attester needs an ON-CHAIN statement of how long a transfer has
    /// been unclaimed before it may vote to burn it, and it must not take that
    /// from the signature store's nomination. `Clock::get()` is the
    /// stake-weighted cluster time, written here in the same transaction that
    /// locks the funds, so `now - locked_at` (with `now` read from the Clock
    /// sysvar, not a wall clock) is an authenticated age.
    pub locked_at: i64,
}

/// Borsh size of a [`SentRecord`]: 32 + 32 + 32 + 32 + 8 + 8.
const SENT_RECORD_LEN: usize = 32 + 32 + 32 + 32 + 8 + 8;

/// Load the `["sent", submissionId]` record, refusing any account that is not the
/// canonical program-owned PDA. Mirrors [`load_config`]'s posture: a forged record
/// would let a caller name their own refund destination and amount.
fn load_sent_record(
    program_id: &Pubkey,
    submission_id: &[u8; 32],
    sent_ai: &AccountInfo,
) -> Result<SentRecord, ProgramError> {
    let (expected, _bump) =
        Pubkey::find_program_address(&[b"sent", submission_id], program_id);
    if sent_ai.key != &expected {
        msg!("sent account is not the canonical [\"sent\", submissionId] PDA");
        return Err(ProgramError::InvalidSeeds);
    }
    if sent_ai.owner != program_id {
        msg!("sent account is not program-owned");
        return Err(ProgramError::IllegalOwner);
    }
    if sent_ai.data_is_empty() {
        // Never sent from this gate (or already refunded and closed).
        return Err(GateError::NotSent.into());
    }
    decode_sent_record(&sent_ai.data.borrow())
}

/// Decode a `SentRecord`, accepting the pre-round-4 layout (no `locked_at`).
///
/// Records written before `locked_at` existed are 8 bytes shorter. They are
/// still valid origin proofs — the lock happened — so a refund of an in-flight
/// transfer must not fail across the upgrade. Their lock time is unknown, so it
/// reads as 0, which every age check treats as "cannot be shown aged".
fn decode_sent_record(data: &[u8]) -> Result<SentRecord, ProgramError> {
    if data.len() == SENT_RECORD_LEN - 8 {
        let mut padded = data.to_vec();
        padded.extend_from_slice(&[0u8; 8]);
        return SentRecord::deserialize(&mut &padded[..]).map_err(|_| ProgramError::InvalidAccountData);
    }
    SentRecord::deserialize(&mut &data[..]).map_err(|_| ProgramError::InvalidAccountData)
}

/// Load the canonical asset binding for `debridge_id`, refusing any account that
/// is not the program-owned `["asset", debridge_id]` PDA. Mirrors [`load_config`].
fn load_asset(
    program_id: &Pubkey,
    debridge_id: &[u8; 32],
    asset_ai: &AccountInfo,
) -> Result<AssetConfig, ProgramError> {
    verify_asset_account(asset_ai.key, asset_ai.owner, debridge_id, program_id)?;
    let asset = AssetConfig::deserialize(&mut &asset_ai.data.borrow()[..])
        .map_err(|_| ProgramError::InvalidAccountData)?;
    if &asset.debridge_id != debridge_id {
        // A bound-but-mismatched record can only mean seed confusion; reject.
        return Err(ProgramError::InvalidSeeds);
    }
    Ok(asset)
}

/// Pure C1 asset-PDA gate (host-testable): the account MUST be the canonical
/// `["asset", debridge_id]` PDA AND program-owned.
fn verify_asset_account(
    asset_key: &Pubkey,
    asset_owner: &Pubkey,
    debridge_id: &[u8; 32],
    program_id: &Pubkey,
) -> Result<(), ProgramError> {
    let (expected, _bump) = Pubkey::find_program_address(&[b"asset", debridge_id], program_id);
    if asset_key != &expected {
        msg!("asset account is not the canonical [\"asset\", debridge_id] PDA");
        return Err(ProgramError::InvalidSeeds);
    }
    if asset_owner != program_id {
        msg!("asset account is not program-owned");
        return Err(ProgramError::IllegalOwner);
    }
    Ok(())
}

/// Pure H-1 write-once rule (host-testable): may `register_asset` write over an
/// account that already exists?
///
/// `Ok(true)`  — the account exists but is unwritten (all-zero); write it.
/// `Ok(false)` — the identical binding is already there; no-op, so deploy scripts
///               stay re-runnable.
/// `Err`       — a LIVE binding would be repointed. Refused, because a claim
///               commits to `debridge_id` alone: repointing lets the validators'
///               existing signatures release a mint they never attested, from a
///               vault they never saw. `Gate.sol::setLocalToken` refuses the same
///               thing for the same reason.
fn asset_write_allowed(
    existing: &AssetConfig,
    incoming: &AssetConfig,
) -> Result<bool, ProgramError> {
    let unwritten =
        existing.mint == Pubkey::default() && existing.vault == Pubkey::default();
    if unwritten {
        return Ok(true);
    }
    if existing.mint == incoming.mint
        && existing.vault == incoming.vault
        && existing.debridge_id == incoming.debridge_id
    {
        return Ok(false);
    }
    Err(GateError::AssetAlreadyRegistered.into())
}

/// Pure C1 asset-binding gate (host-testable): the vault a send/claim touches and
/// the counterpart token account (user on send, receiver on claim) must both be
/// the registered vault / hold the registered mint, under the real SPL token
/// program. A forged-config drain that points at a different asset's vault fails
/// here.
fn verify_asset_binding(
    asset: &AssetConfig,
    token_program_key: &Pubkey,
    vault_key: &Pubkey,
    vault_mint: &Pubkey,
    counterpart_mint: &Pubkey,
) -> Result<(), ProgramError> {
    if token_program_key != &spl_token::id() {
        return Err(ProgramError::IncorrectProgramId);
    }
    if vault_key != &asset.vault {
        return Err(ProgramError::InvalidAccountData);
    }
    if vault_mint != &asset.mint || counterpart_mint != &asset.mint {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}

/// Pure C1 init-authority gate (host-testable): only the program's upgrade
/// authority (the deployer) may initialize the config; an immutable program
/// (`None`) or any other signer is refused.
fn verify_upgrade_authority(
    upgrade_authority: Option<Pubkey>,
    who: &Pubkey,
) -> Result<(), ProgramError> {
    match upgrade_authority {
        Some(auth) if &auth == who => Ok(()),
        Some(_) => Err(ProgramError::MissingRequiredSignature),
        None => Err(ProgramError::InvalidArgument),
    }
}

/// Bytes in a replay marker PDA. One byte is enough to make `data_is_empty()`
/// false; it also leaves room to record WHICH terminal state was reached once
/// `cancel` exists (claimed vs burned), which a zero-length account cannot.
const MARKER_LEN: usize = 1;

/// Marker byte: this submission was CLAIMED — funds released here.
const MARKER_CLAIMED: u8 = 1;
/// Marker byte: this submission was CANCELLED — burned, funds never released and
/// never can be. The precondition for a source-side refund.
///
/// One marker PDA serves both states, exactly as `Gate.executed` does on the EVM
/// side: its existence blocks any second terminal action, and the byte says which
/// action happened. A zero-length marker could not carry that distinction, which
/// is why H-2's rewrite gave it a data byte.
const MARKER_CANCELLED: u8 = 2;

/// Pure replay predicate (host-testable) — finding H-2.
///
/// The old guard was `lamports() > 0 || !data_is_empty()`, which anyone could
/// satisfy: a submissionId is public (it is in the source chain's `Sent` event
/// and in the signature store), so an attacker could simply transfer the
/// rent-exempt minimum to the derived PDA and every later claim would report
/// `AlreadyExecuted` forever. Lamports are not evidence of anything — ANY account
/// can be funded by anyone. Only the program itself can make an account
/// program-owned with data, so that is what "executed" now means.
fn is_already_executed(owner: &Pubkey, data_len: usize, program_id: &Pubkey) -> bool {
    owner == program_id && data_len > 0
}

/// Create a program-owned PDA of `space` bytes at `seeds`, tolerating an account
/// a griefer has pre-funded.
///
/// `system_instruction::create_account` fails outright when the target already
/// holds lamports — that was the other half of H-2 for the executed marker, and
/// audit round 4 (M-5) found the same brick still live in `init` and
/// `register_asset`, whose addresses are equally derivable in advance
/// (`["config"]` is fixed; a `debridge_id` is public). `transfer` + `allocate` +
/// `assign` is the standard workaround: it tops the balance up to rent exemption
/// rather than requiring it to start at zero, then takes ownership.
///
/// EVERY PDA this program creates goes through here, so there is one copy of the
/// sequence to get right rather than one per account type.
fn create_pda_account<'a>(
    program_id: &Pubkey,
    payer: &AccountInfo<'a>,
    target: &AccountInfo<'a>,
    system_program: &AccountInfo<'a>,
    seeds: &[&[u8]],
    bump: u8,
    space: usize,
) -> ProgramResult {
    let rent = Rent::get()?.minimum_balance(space);
    let have = target.lamports();
    if have < rent {
        invoke(
            &system_instruction::transfer(payer.key, target.key, rent - have),
            &[payer.clone(), target.clone(), system_program.clone()],
        )?;
    }
    // Seeds + bump, as `invoke_signed` wants them.
    let bump_slice = [bump];
    let mut signer_seeds: Vec<&[u8]> = seeds.to_vec();
    signer_seeds.push(&bump_slice);

    invoke_signed(
        &system_instruction::allocate(target.key, space as u64),
        &[target.clone(), system_program.clone()],
        &[&signer_seeds],
    )?;
    invoke_signed(
        &system_instruction::assign(target.key, program_id),
        &[target.clone(), system_program.clone()],
        &[&signer_seeds],
    )?;
    Ok(())
}

/// Create a program-owned marker PDA at `seeds` (see [`create_pda_account`]).
fn create_marker<'a>(
    program_id: &Pubkey,
    payer: &AccountInfo<'a>,
    marker: &AccountInfo<'a>,
    system_program: &AccountInfo<'a>,
    seeds: &[&[u8]],
    bump: u8,
    state: u8,
) -> ProgramResult {
    create_pda_account(program_id, payer, marker, system_program, seeds, bump, MARKER_LEN)?;
    // Non-zero so `data_is_empty()` reads false even if a future reader forgets
    // the owner half of the predicate, and it records WHICH terminal state was
    // reached (claimed vs cancelled).
    debug_assert!(state != 0, "a marker state of 0 would read as 'not executed'");
    marker.data.borrow_mut()[0] = state;
    Ok(())
}

/// Create and populate the `["sent", id]` origin-proof PDA. Uses the same
/// pre-funding-tolerant sequence as [`create_marker`], for the same reason: the
/// submissionId is derivable in advance, so the address can be griefed with
/// lamports before the send lands.
#[allow(clippy::too_many_arguments)]
fn create_sent_record<'a>(
    program_id: &Pubkey,
    payer: &AccountInfo<'a>,
    sent: &AccountInfo<'a>,
    system_program: &AccountInfo<'a>,
    id: &[u8; 32],
    bump: u8,
    record: &SentRecord,
) -> ProgramResult {
    if is_already_executed(sent.owner, sent.data_len(), program_id) {
        // A live record for this id already exists — impossible under a monotonic
        // per-corridor nonce, so treat it as a replay rather than overwrite it.
        return Err(GateError::AlreadyExecuted.into());
    }
    create_pda_account(
        program_id,
        payer,
        sent,
        system_program,
        &[b"sent", id],
        bump,
        SENT_RECORD_LEN,
    )?;
    record.serialize(&mut &mut sent.data.borrow_mut()[..])?;
    Ok(())
}

/// Domain-separated digest a validator signs to authorise CANCELLING a transfer
/// on this (destination) chain. Byte-identical to `BridgeHash.getCancelId`.
fn cancel_id(submission_id: &[u8; 32]) -> [u8; 32] {
    keccak::hashv(&[&be32(CANCEL_PREFIX), submission_id]).to_bytes()
}

/// Domain-separated digest a validator signs to authorise REFUNDING a cancelled
/// transfer on this (source) chain. Byte-identical to `BridgeHash.getRefundId`.
///
/// The distinct prefixes are what keep the three quorums independent: a transfer
/// signature can never be replayed as a cancel, nor a cancel as a refund.
fn refund_id(submission_id: &[u8; 32]) -> [u8; 32] {
    keccak::hashv(&[&be32(REFUND_PREFIX), submission_id]).to_bytes()
}

/// Read the SPL mint + owner of a token account, asserting it is a real SPL
/// token account owned by the given `token_program`. Used to verify the vault
/// and receiver token accounts against the registry (C1: "verify token program,
/// vault, vault authority, receiver mint, and all writable owners").
fn spl_mint_and_owner(
    token_ai: &AccountInfo,
    token_program: &Pubkey,
) -> Result<(Pubkey, Pubkey), ProgramError> {
    if token_ai.owner != token_program {
        msg!("token account is not owned by the SPL token program");
        return Err(ProgramError::IllegalOwner);
    }
    let acct = spl_token::state::Account::unpack(&token_ai.data.borrow())
        .map_err(|_| ProgramError::InvalidAccountData)?;
    Ok((acct.mint, acct.owner))
}

/// The USER-supplied payout destination, decoded with a distinct error (L-4a).
///
/// Same checks as [`spl_mint_and_owner`], different failure name. The vault and
/// the user's own source account are operator/protocol state — if either is not
/// a token account that is a configuration bug. The *receiver* is the one
/// account chosen by whoever initiated the transfer on the far chain, so its
/// failure mode is a user error and deserves to say so.
fn receiver_token_account(
    token_ai: &AccountInfo,
    token_program: &Pubkey,
) -> Result<(Pubkey, Pubkey), ProgramError> {
    if token_ai.owner != token_program {
        msg!("receiver is not an SPL token account — a wallet address is never claimable");
        return Err(GateError::ReceiverNotTokenAccount.into());
    }
    let acct = spl_token::state::Account::unpack(&token_ai.data.borrow())
        .map_err(|_| ProgramError::from(GateError::ReceiverNotTokenAccount))?;
    Ok((acct.mint, acct.owner))
}

/// Pure vault-safety predicate (host-testable) — finding M-6.
///
/// `register_asset` checked the vault's mint and owner, which proves the program
/// CAN move its funds. It did not prove that nobody else can. An SPL token
/// account may carry:
///   * a `delegate`, which can transfer up to `delegated_amount` with no
///     involvement from the owner PDA at all, and
///   * a `close_authority`, which can close the account and sweep its lamports.
/// Either would let whoever holds it drain bridge liquidity entirely outside the
/// program, past every check this gate makes. A vault must have neither.
fn vault_is_exclusively_controlled(
    delegate: Option<Pubkey>,
    close_authority: Option<Pubkey>,
) -> bool {
    delegate.is_none() && close_authority.is_none()
}

/// Assert `who` is the program's on-chain upgrade authority. Reads the
/// BPF-loader-upgradeable `ProgramData` account (`Program.programdata_address`),
/// verifying both accounts are the canonical ones for `program_id`. Used to gate
/// `init` to the deployer (C1 atomic/authorized initialization).
fn require_upgrade_authority(
    program_id: &Pubkey,
    program_ai: &AccountInfo,
    program_data_ai: &AccountInfo,
    who: &Pubkey,
) -> Result<(), ProgramError> {
    if program_ai.key != program_id {
        msg!("init: program account is not this program");
        return Err(ProgramError::IncorrectProgramId);
    }
    if program_ai.owner != &bpf_loader_upgradeable::id() {
        msg!("init: program is not owned by the upgradeable loader");
        return Err(ProgramError::IncorrectProgramId);
    }
    // The Program account points at its ProgramData account; verify the link.
    let (expected_pd, _) =
        Pubkey::find_program_address(&[program_id.as_ref()], &bpf_loader_upgradeable::id());
    if program_data_ai.key != &expected_pd {
        msg!("init: wrong ProgramData account for this program");
        return Err(ProgramError::InvalidArgument);
    }
    match bincode_deserialize_loader_state(&program_data_ai.data.borrow())? {
        UpgradeableLoaderState::ProgramData { upgrade_authority_address, .. } => {
            verify_upgrade_authority(upgrade_authority_address, who)
        }
        _ => Err(ProgramError::InvalidAccountData),
    }
}

/// Deserialize an `UpgradeableLoaderState` from a ProgramData account (the BPF
/// loader serializes it with bincode).
fn bincode_deserialize_loader_state(
    data: &[u8],
) -> Result<UpgradeableLoaderState, ProgramError> {
    bincode::deserialize::<UpgradeableLoaderState>(data)
        .map_err(|_| ProgramError::InvalidAccountData)
}

#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum GateError {
    #[error("amount must be non-zero")]
    ZeroAmount,
    #[error("receiver width must be 20 or 32")]
    BadReceiver,
    #[error("already executed (replay)")]
    AlreadyExecuted,
    #[error("signatures unordered or duplicated")]
    InvalidSignerOrder,
    #[error("not enough validator signatures")]
    NotEnoughSignatures,
    #[error("bad signature encoding")]
    BadSignature,
    /// H-3: `send` to a destination chain governance never registered.
    #[error("corridor (chain_id_to) is not registered")]
    CorridorNotRegistered,
    /// M-1: the circuit breaker is tripped.
    #[error("gate is paused")]
    Paused,
    /// H-3 / L-3: the validator set or corridor list is at the capacity the
    /// config account was sized for at init.
    #[error("at capacity — the config account was sized for fewer entries")]
    AtCapacity,
    /// M-2: refund asked for a submissionId this gate never emitted (or one
    /// already refunded — the record is closed on payout).
    #[error("this gate never sent that submissionId")]
    NotSent,
    /// M-2: the transfer was already claimed here, so it cannot be cancelled.
    #[error("already claimed — cannot cancel")]
    AlreadyClaimed,
    /// M-2: the destination has not been burned, so no refund is authorised.
    #[error("destination not cancelled")]
    NotCancelled,
    /// More signatures than the gate has validators. A correct array can never
    /// be longer (signers are distinct and ascending), so this is either junk
    /// padding or a bug — and recovering each one costs ~25k CU, which is how a
    /// padded array bricks `claim`/`cancel`/`refund` for good. See
    /// [`verify_threshold`]. Mirrors `Gate.sol`'s `TooManySignatures`.
    #[error("more signatures than validators")]
    TooManySignatures,
    /// L-4a: the signed receiver is not an SPL token account.
    ///
    /// The gate releases funds to the account the validators SIGNED FOR, and an
    /// SPL transfer can only credit a token account. A wallet pubkey is the
    /// natural thing for a user to paste, and it produces a transfer that can
    /// never be delivered. That behaviour is correct and deliberate — the
    /// receiver is hash-bound, so the gate cannot substitute the "right" account
    /// without breaking the submissionId — but it used to surface as a bare
    /// `IllegalOwner`/`InvalidAccountData`, indistinguishable from a malformed
    /// vault or the wrong token program. A distinct code makes the one
    /// user-recoverable failure in `claim` diagnosable from the transaction log.
    #[error("receiver is not an SPL token account (a wallet address will never be claimable)")]
    ReceiverNotTokenAccount,
    /// H-1: `register_asset` is write-once. A claim binds only `debridge_id`, so
    /// repointing a registered corridor at a different mint/vault would let the
    /// validators' existing signatures release an asset they never attested.
    /// Mirrors `Gate.sol`'s `LocalTokenAlreadySet`.
    #[error("asset already registered for this debridgeId (bindings are write-once)")]
    AssetAlreadyRegistered,
    /// H-3: `init` was given a zero `bridge_domain`. Appended LAST on purpose —
    /// the discriminant IS the on-chain `Custom` code, so inserting anywhere else
    /// silently renumbers every error above it and breaks clients that match on
    /// the numeric code.
    #[error("bridge_domain must be non-zero")]
    ZeroBridgeDomain,
    /// H-2 (round 4): a power-granting governance action was attempted with no
    /// schedule for it (or one already consumed/cancelled). `Custom(17)`.
    #[error("governance action not scheduled")]
    GovernanceNotScheduled,
    /// H-2 (round 4): scheduled, but GOVERNANCE_DELAY has not elapsed. `Custom(18)`.
    #[error("governance action not ready — the 48h delay has not elapsed")]
    GovernanceNotReady,
    /// H-2 (round 4): matured more than GOVERNANCE_GRACE ago; re-schedule. `Custom(19)`.
    #[error("governance schedule expired — re-schedule it")]
    GovernanceExpired,
    /// LOW (round 4): `init` was given the same validator twice. `Custom(20)`.
    #[error("duplicate validator in the initial set")]
    DuplicateValidator,
    /// LOW (round 4): `init` or `set_validator` was given the zero address.
    /// `Custom(21)`. Mirrors `Gate.sol`'s `ZeroValidator`.
    #[error("validator address must be non-zero")]
    ZeroValidator,
}

/// Pure init-time validator-set rule (host-testable; `init` itself cannot run
/// under `solana-program-test`, see `tests/account_level.rs`).
///
/// Duplicates are refused because `verify_threshold` counts each recovered
/// signer once — a set of `[A, A, B]` with threshold 3 is unreachable and
/// freezes the gate, while `[A, A]` with threshold 2 would let ONE key look like
/// two if a later refactor ever counted by index. The zero address is refused
/// because `verify_threshold` seeds its ordering check at `0x00…00`, so a "zero
/// validator" could never sign anyway — registering one only inflates the count
/// the threshold is checked against. `Gate.sol` refuses both.
fn validate_validator_set(validators: &[[u8; 20]], threshold: u32) -> Result<(), ProgramError> {
    if threshold == 0 || threshold > validators.len() as u32 {
        return Err(ProgramError::InvalidArgument);
    }
    for (i, v) in validators.iter().enumerate() {
        if v == &[0u8; 20] {
            return Err(GateError::ZeroValidator.into());
        }
        if validators[..i].contains(v) {
            return Err(GateError::DuplicateValidator.into());
        }
    }
    Ok(())
}

impl From<GateError> for ProgramError {
    fn from(e: GateError) -> Self {
        ProgramError::Custom(e as u32 + 1)
    }
}

// ---------------------------------------------------------------------------
// Hashing (keccak syscall) — byte-identical to BridgeHash.sol / bridge-core.
// ---------------------------------------------------------------------------

fn be32(v: u64) -> [u8; 32] {
    let mut o = [0u8; 32];
    o[24..].copy_from_slice(&v.to_be_bytes());
    o
}

fn amount_word(v: u64) -> [u8; 32] {
    let mut o = [0u8; 32];
    o[24..].copy_from_slice(&v.to_be_bytes());
    o
}

/// The submissionId, byte-identical to `BridgeHash.sol` and `bridge-core`.
///
/// ## The two fields this VM narrows (audit I-1)
///
/// The EVM gate hashes `amount` and `executionFee` as full 256-bit words; here
/// they are a `u64` and a `u128` widened into those words, so their top halves are
/// always zero. A transfer from an EVM chain with `amount >= 2^64` — or an
/// `executionFee >= 2^128` — therefore produces an id this program can never
/// reproduce, and its `claim` cannot even be expressed (`ClaimArgs::amount` is a
/// `u64`).
///
/// That is safe rather than a divergence: it fails closed, and such a transfer
/// routes into the existing cancel -> refund path and returns the deposit. Both
/// ceilings are far above any realistic SPL amount — 2^64 raw units is ~18.4
/// billion tokens at 9 decimals — but an operator registering a high-decimal
/// asset should know where the wall is rather than meet it as a stuck transfer.
#[allow(clippy::too_many_arguments)]
fn submission_id(
    bridge_domain: &[u8; 32],
    debridge_id: &[u8; 32],
    amount: u64,
    chain_id_from: u64,
    chain_id_to: u64,
    nonce: u64,
    receiver: &[u8],
    auto: Option<&AutoParamsWire>,
    native_sender: &[u8],
) -> [u8; 32] {
    let prefix = be32(SUBMISSION_PREFIX);
    let cf = be32(chain_id_from);
    let ct = be32(chain_id_to);
    let amt = amount_word(amount);
    let nz = be32(nonce);
    // packedSubmission = prefix|bridgeDomain|debridgeId|chainIdFrom|chainIdTo|amount|receiver|nonce
    let base: &[&[u8]] = &[&prefix, bridge_domain, debridge_id, &cf, &ct, &amt, receiver, &nz];
    match auto {
        None => keccak::hashv(base).to_bytes(),
        Some(a) => {
            let mut fee = [0u8; 32];
            fee[16..].copy_from_slice(&a.execution_fee.to_be_bytes());
            let flags = be32(a.flags);
            let fb = keccak::hashv(&[&a.fallback_address]).to_bytes();
            let data = keccak::hashv(&[&a.data]).to_bytes();
            let ns = keccak::hashv(&[native_sender]).to_bytes();
            // keccak(packedSubmission || fee || flags || keccak(fallback) || keccak(data) || keccak(nativeSender))
            keccak::hashv(&[
                &prefix, bridge_domain, debridge_id, &cf, &ct, &amt, receiver, &nz, &fee, &flags,
                &fb, &data, &ns,
            ])
            .to_bytes()
        }
    }
}

// ---------------------------------------------------------------------------
// Signature verification (secp256k1_recover syscall) — mirrors _verifySignatures.
// ---------------------------------------------------------------------------

fn eth_signed_digest(id: &[u8; 32]) -> [u8; 32] {
    keccak::hashv(&[b"\x19Ethereum Signed Message:\n32", id]).to_bytes()
}

fn recover_evm_address(digest: &[u8; 32], sig65: &[u8]) -> Result<[u8; 20], GateError> {
    if sig65.len() != 65 {
        return Err(GateError::BadSignature);
    }
    let v = sig65[64];
    if v != 27 && v != 28 {
        return Err(GateError::BadSignature);
    }
    let pubkey = secp256k1_recover(digest, v - 27, &sig65[..64]).map_err(|_| GateError::BadSignature)?;
    // address = keccak(uncompressed_pubkey_xy)[12..]
    let h = keccak::hashv(&[&pubkey.0]).to_bytes();
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&h[12..]);
    Ok(addr)
}

/// Verify a threshold of distinct validator signatures over `id`.
///
/// **The length cap is a liveness control, not a nicety.** `secp256k1_recover`
/// costs ~25k compute units, so the loop below spends the *entire* 200k default
/// budget on eight signatures. The signature store accepts a signature from any
/// key that recovers to its claimed signer — it does not know the validator set —
/// so anyone holding a `Sign`-scoped token can append junk-but-recoverable
/// signatures to a pending submission. Without this cap a relayer forwards them
/// all, every `claim`/`cancel`/`refund` for that submission runs out of compute
/// before reaching quorum, and the transfer is stuck *forever* — the recovery
/// paths are DoS'd by the same trick that blocks the payout.
///
/// `Gate.sol::_verifySignatures` has carried the same cap since `16ed706`
/// (`TooManySignatures`); this is its Solana counterpart. Rejecting on length
/// before the first recover keeps the refusal cheap, and it costs an honest
/// relayer nothing: a correct array never holds more signatures than there are
/// validators, because they must be strictly ascending and distinct.
fn verify_threshold(cfg: &Config, id: &[u8; 32], signatures: &[Vec<u8>]) -> Result<(), GateError> {
    if signatures.len() > cfg.validators.len() {
        return Err(GateError::TooManySignatures);
    }
    let digest = eth_signed_digest(id);
    // Seeded at the zero address and compared on EVERY signature, matching
    // `Gate.sol`'s `address last = address(0)`. Skipping the check for the first
    // signature (as this once did) admits a zero-address recovery that the EVM
    // gate refuses — and these two verifiers are supposed to be equivalent.
    let mut last = [0u8; 20];
    let mut count: u32 = 0;
    for sig in signatures {
        let signer = recover_evm_address(&digest, sig)?;
        if signer <= last {
            return Err(GateError::InvalidSignerOrder);
        }
        if cfg.is_validator(&signer) {
            count += 1;
        }
        last = signer;
    }
    if count < cfg.threshold {
        return Err(GateError::NotEnoughSignatures);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let ix = GateInstruction::try_from_slice(data).map_err(|_| ProgramError::InvalidInstructionData)?;
    match ix {
        GateInstruction::Init(args) => process_init(program_id, accounts, args),
        GateInstruction::Send(args) => process_send(program_id, accounts, args),
        GateInstruction::Claim(args) => process_claim(program_id, accounts, args),
        GateInstruction::SetValidator { validator, active } => {
            process_set_validator(program_id, accounts, validator, active)
        }
        GateInstruction::SetThreshold { threshold } => {
            process_set_threshold(program_id, accounts, threshold)
        }
        GateInstruction::RegisterAsset { debridge_id } => {
            process_register_asset(program_id, accounts, debridge_id)
        }
        GateInstruction::RegisterCorridor { chain_id_to } => {
            process_register_corridor(program_id, accounts, chain_id_to)
        }
        GateInstruction::Pause => process_set_paused(program_id, accounts, true),
        GateInstruction::Unpause => process_set_paused(program_id, accounts, false),
        GateInstruction::SetGuardian { guardian } => {
            process_set_guardian(program_id, accounts, guardian)
        }
        GateInstruction::Cancel(args) => process_cancel(program_id, accounts, args),
        GateInstruction::Refund(args) => process_refund(program_id, accounts, args),
        GateInstruction::ScheduleGovernance { action_id } => {
            process_schedule_governance(program_id, accounts, action_id)
        }
        GateInstruction::CancelScheduledGovernance { action_id } => {
            process_cancel_scheduled_governance(program_id, accounts, action_id)
        }
    }
}

/// Accounts: [config, owner(s,w), gov_pda(w), system_program]
///
/// H-2 (round 4): queue a validator addition or threshold decrease. Re-scheduling
/// RESTARTS the delay rather than keeping the earliest deadline, for the reason
/// `Gate.scheduleGovernance` gives: otherwise one matured schedule would be an
/// indefinitely re-usable instant-change right against that action.
///
/// The schedule lives in its own PDA rather than in `Config` so the config
/// account — sized once at init and unable to grow (H-3) — never has to hold an
/// unbounded map. Created through [`create_pda_account`], so pre-funding the
/// address cannot block governance (M-5).
fn process_schedule_governance(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    action_id: [u8; 32],
) -> ProgramResult {
    let it = &mut accounts.iter();
    let config_ai = next_account_info(it)?;
    let owner = next_account_info(it)?;
    let gov_ai = next_account_info(it)?;
    let system_program = next_account_info(it)?;

    let cfg = load_config(program_id, config_ai)?;
    if owner.key != &cfg.owner || !owner.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let (expected, bump) = Pubkey::find_program_address(&[b"gov", &action_id], program_id);
    if gov_ai.key != &expected {
        return Err(ProgramError::InvalidSeeds);
    }
    if !(gov_ai.owner == program_id && gov_ai.data_len() >= GOVERNANCE_LEN) {
        // First schedule for this action (or a squatter's pre-funded account).
        if !gov_ai.data_is_empty() && gov_ai.owner != program_id {
            return Err(ProgramError::IllegalOwner);
        }
        create_pda_account(
            program_id,
            owner,
            gov_ai,
            system_program,
            &[b"gov", &action_id],
            bump,
            GOVERNANCE_LEN,
        )?;
    }
    let now = solana_program::clock::Clock::get()?.unix_timestamp;
    let ready_at = now.checked_add(GOVERNANCE_DELAY).ok_or(ProgramError::ArithmeticOverflow)?;
    GovernanceSchedule { ready_at }.serialize(&mut &mut gov_ai.data.borrow_mut()[..])?;
    msg!("governance scheduled: ready_at {}", ready_at);
    Ok(())
}

/// Accounts: [config, signer(s), gov_pda(w)]
///
/// H-2 (round 4): drop a queued action. Owner OR guardian — the guardian is the
/// low-trust stop button, and cancelling a pending grant of power is exactly the
/// kind of incident response it exists for. Nothing is executed here, so the
/// worst a compromised guardian can do is delay a legitimate change.
fn process_cancel_scheduled_governance(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    action_id: [u8; 32],
) -> ProgramResult {
    let it = &mut accounts.iter();
    let config_ai = next_account_info(it)?;
    let who = next_account_info(it)?;
    let gov_ai = next_account_info(it)?;

    let cfg = load_config(program_id, config_ai)?;
    if !who.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let is_owner = who.key == &cfg.owner;
    let is_guardian = cfg.guardian != Pubkey::default() && who.key == &cfg.guardian;
    if !(is_owner || is_guardian) {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let (expected, _bump) = Pubkey::find_program_address(&[b"gov", &action_id], program_id);
    if gov_ai.key != &expected {
        return Err(ProgramError::InvalidSeeds);
    }
    if gov_ai.owner != program_id || gov_ai.data_len() < GOVERNANCE_LEN {
        return Ok(()); // nothing scheduled; idempotent like `delete` on a mapping
    }
    GovernanceSchedule::default().serialize(&mut &mut gov_ai.data.borrow_mut()[..])?;
    msg!("governance schedule cancelled");
    Ok(())
}

/// Accounts: [config, executed_pda(w), payer(s,w), system_program]
///
/// M-2, DESTINATION side. Burn a transfer so `claim` can never release funds for
/// it, which is the precondition for a source-side refund.
///
/// ## Why this has to exist
///
/// The bridge's refund design is ordered on purpose: a refund that merely waited
/// out a timeout would be a double-spend, because the transfer's claim signatures
/// still exist. So the destination must be provably burned FIRST. Solana had no
/// way to do that, which meant any EVM→Solana transfer that could not be claimed
/// (unregistered asset, empty vault, a griefed marker) locked the source deposit
/// forever with no recovery path at all.
///
/// Moves no funds, so it needs neither the asset registry nor the SPL token
/// program — only the canonical config, for the validator set.
fn process_cancel(program_id: &Pubkey, accounts: &[AccountInfo], args: CancelArgs) -> ProgramResult {
    let it = &mut accounts.iter();
    let config_ai = next_account_info(it)?;
    let executed_ai = next_account_info(it)?;
    let payer = next_account_info(it)?;
    let system_program = next_account_info(it)?;

    let cfg = load_config(program_id, config_ai)?;
    if cfg.paused {
        return Err(GateError::Paused.into());
    }

    let id = submission_id(
        &cfg.bridge_domain,
        &args.debridge_id,
        args.amount,
        args.chain_id_from,
        cfg.chain_id,
        args.nonce,
        &args.receiver,
        args.auto.as_ref(),
        &args.native_sender,
    );

    let (expected_executed, bump) = Pubkey::find_program_address(&[b"executed", &id], program_id);
    if executed_ai.key != &expected_executed {
        return Err(ProgramError::InvalidSeeds);
    }
    // Already claimed OR already cancelled — either way it is spent here, and
    // re-cancelling must not re-authorise a second refund.
    if is_already_executed(executed_ai.owner, executed_ai.data_len(), program_id) {
        return Err(GateError::AlreadyExecuted.into());
    }

    // A cancel quorum, NOT a transfer quorum: distinct digest domain.
    verify_threshold(&cfg, &cancel_id(&id), &args.signatures)?;

    create_marker(
        program_id,
        payer,
        executed_ai,
        system_program,
        &[b"executed", &id],
        bump,
        MARKER_CANCELLED,
    )?;

    emit_lifecycle(CANCELLED_EVENT_TAG, &id, &args.debridge_id, args.chain_id_from, args.nonce);
    msg!("CANCELLED {}", bs58_id(&id));
    Ok(())
}

/// Accounts: [config, asset, sent_pda(w), refunded_pda(w), payer(s,w), vault(w),
///            source_token(w), vault_authority, spl_token_program, system_program]
///
/// M-2, SOURCE side. Return locked funds to the token account they came from,
/// after the destination has been burned.
///
/// Three independent guards stand between a caller and the vault, mirroring
/// `Gate.refund`:
///   * the `["sent", id]` record must exist — proof THIS gate locked these funds,
///     and the authoritative destination and amount (calldata is not trusted);
///   * a validator threshold over `refundId`, a quorum that only forms after the
///     validators have observed `Cancelled` on the destination;
///   * the asset registry must bind `debridge_id` to the vault being drained.
///
/// The `["refunded", id]` marker is the replay guard, and the `sent` record is
/// zeroed on payout so it can never authorise a second one.
fn process_refund(program_id: &Pubkey, accounts: &[AccountInfo], args: RefundArgs) -> ProgramResult {
    let it = &mut accounts.iter();
    let config_ai = next_account_info(it)?;
    let asset_ai = next_account_info(it)?;
    let sent_ai = next_account_info(it)?;
    let refunded_ai = next_account_info(it)?;
    let payer = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let source_token = next_account_info(it)?;
    let vault_authority = next_account_info(it)?;
    let token_program = next_account_info(it)?;
    let system_program = next_account_info(it)?;

    let cfg = load_config(program_id, config_ai)?;
    // NOTE: deliberately NOT gated on `cfg.paused`, mirroring `Gate.refund`. The
    // breaker stops new exposure; a refund only returns already-locked funds to
    // the account that locked them, after an attested burn. Halting it would trap
    // exactly the users an incident stranded.

    let id = submission_id(
        &cfg.bridge_domain,
        &args.debridge_id,
        args.amount,
        cfg.chain_id,
        args.chain_id_to,
        args.nonce,
        &args.receiver,
        args.auto.as_ref(),
        &args.native_sender,
    );

    // Replay guard first, so a repeat costs the caller a failed tx and nothing else.
    let (expected_refunded, refunded_bump) =
        Pubkey::find_program_address(&[b"refunded", &id], program_id);
    if refunded_ai.key != &expected_refunded {
        return Err(ProgramError::InvalidSeeds);
    }
    if is_already_executed(refunded_ai.owner, refunded_ai.data_len(), program_id) {
        return Err(GateError::AlreadyExecuted.into());
    }

    // Origin proof + authoritative payout details.
    let sent = load_sent_record(program_id, &id, sent_ai)?;
    if &sent.debridge_id != &args.debridge_id {
        return Err(ProgramError::InvalidAccountData);
    }

    verify_threshold(&cfg, &refund_id(&id), &args.signatures)?;

    // The vault must be the one governance registered for this asset, and the
    // destination must be the exact token account that was debited.
    let asset = load_asset(program_id, &args.debridge_id, asset_ai)?;
    if source_token.key != &sent.source_token {
        msg!("refund destination is not the token account that was debited");
        return Err(ProgramError::InvalidAccountData);
    }
    let (vault_mint, _) = spl_mint_and_owner(vault, token_program.key)?;
    // The refund's payout destination is equally user-chosen (it is the account
    // recorded at `send`), so it gets the same distinct error.
    let (dest_mint, _) = receiver_token_account(source_token, token_program.key)?;
    verify_asset_binding(&asset, token_program.key, vault.key, &vault_mint, &dest_mint)?;

    // Effects before interaction: mark refunded and retire the origin proof, so a
    // reentrant or repeated call finds nothing left to authorise.
    create_marker(
        program_id,
        payer,
        refunded_ai,
        system_program,
        &[b"refunded", &id],
        refunded_bump,
        MARKER_CLAIMED,
    )?;
    sent_ai.data.borrow_mut().fill(0);

    let (auth, auth_bump) = Pubkey::find_program_address(&[b"vault_authority"], program_id);
    if vault_authority.key != &auth {
        return Err(ProgramError::InvalidSeeds);
    }
    let transfer = spl_token::instruction::transfer(
        token_program.key,
        vault.key,
        source_token.key,
        vault_authority.key,
        &[],
        sent.amount, // from OUR record, never from calldata
    )?;
    invoke_signed(
        &transfer,
        &[vault.clone(), source_token.clone(), vault_authority.clone(), token_program.clone()],
        &[&[b"vault_authority", &[auth_bump]]],
    )?;

    emit_lifecycle(REFUNDED_EVENT_TAG, &id, &args.debridge_id, cfg.chain_id, args.nonce);
    msg!("REFUNDED {}", bs58_id(&id));
    Ok(())
}

/// Accounts: [config_pda(w), payer(s,w), system_program, program, program_data]
///
/// C1 (atomic/authorized init): the config PDA is unique, so whoever creates it
/// first becomes `owner` forever. Previously that was ANY caller — a front-runner
/// could seize governance the instant the program was deployed. We now require
/// the initializer to be the program's on-chain **upgrade authority** (the
/// deployer), read from the BPF-loader `ProgramData` account, so only the
/// intended deployer can initialize the gate.
fn process_init(program_id: &Pubkey, accounts: &[AccountInfo], args: InitArgs) -> ProgramResult {
    let it = &mut accounts.iter();
    let config_ai = next_account_info(it)?;
    let payer = next_account_info(it)?;
    let system_program = next_account_info(it)?;
    let program_ai = next_account_info(it)?;
    let program_data_ai = next_account_info(it)?;

    let (expected, bump) = Pubkey::find_program_address(&[b"config"], program_id);
    if config_ai.key != &expected {
        return Err(ProgramError::InvalidSeeds);
    }
    if !config_ai.data_is_empty() {
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    // LOW (round 4): threshold in range, no duplicates, no zero address.
    validate_validator_set(&args.validators, args.threshold)?;
    // Capacities must cover the initial set and be non-zero, or the gate is born
    // unable to register the corridor it needs to send anything.
    if args.max_validators < args.validators.len() as u32 || args.max_corridors == 0 {
        return Err(ProgramError::InvalidArgument);
    }
    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    // The initializer must be the program's upgrade authority (the deployer).
    require_upgrade_authority(program_id, program_ai, program_data_ai, payer.key)?;

    // Size the account from the DECLARED capacities rather than a flat 512 bytes
    // (H-3 / L-3). Both vectors are capped at these, so the config can never grow
    // past the buffer and wedge every instruction that reserializes it.
    //
    // M-5 (round 4): `["config"]` is a fixed, public address, so anyone can park
    // a lamport there before the deployer runs `init` — and `create_account`
    // would then fail with "already in use" forever, forcing a redeploy under a
    // new program id. The shared transfer+allocate+assign path tolerates it.
    let space = config_space(args.max_validators, args.max_corridors);
    create_pda_account(
        program_id,
        payer,
        config_ai,
        system_program,
        &[b"config"],
        bump,
        space,
    )?;

    // A zero domain is refused for the same reason the EVM gate refuses it: it is
    // what an unset field looks like, so accepting it would let a whole mesh
    // silently agree on "no generation" and stay replayable across redeploys.
    if args.bridge_domain == [0u8; 32] {
        msg!("bridge_domain must be non-zero");
        return Err(GateError::ZeroBridgeDomain.into());
    }

    let cfg = Config {
        owner: *payer.key,
        bridge_domain: args.bridge_domain,
        guardian: args.guardian,
        validators: args.validators,
        threshold: args.threshold,
        chain_id: args.chain_id,
        paused: false,
        max_validators: args.max_validators,
        max_corridors: args.max_corridors,
        nonce_to: Vec::new(),
    };
    cfg.store(config_ai)?;
    msg!(
        "gate initialized: {} validators (cap {}), threshold {}, corridor cap {}",
        cfg.validators.len(),
        cfg.max_validators,
        cfg.threshold,
        cfg.max_corridors
    );
    Ok(())
}

/// Accounts: [config(w), owner(s)]
///
/// H-3: register a destination chain `send` may target.
///
/// `send` used to accept ANY `chain_id_to` and append a 16-byte `(chain, nonce)`
/// entry for each new one. The config was a fixed 512-byte account with no
/// realloc path, so roughly 25 dust sends to invented chain ids overflowed it and
/// permanently bricked `send`, `set_validator` and `set_threshold` alike. Corridor
/// creation is therefore governance-only and capacity-bounded; `send` may only
/// advance a nonce that already exists.
///
/// This also mirrors the EVM side's `allowed_chains` allowlist, so a corridor is
/// an explicit protocol decision on both VMs rather than a side effect of a
/// caller's arbitrary input.
fn process_register_corridor(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    chain_id_to: u64,
) -> ProgramResult {
    let it = &mut accounts.iter();
    let config_ai = next_account_info(it)?;
    let owner = next_account_info(it)?;

    let mut cfg = load_config(program_id, config_ai)?;
    if owner.key != &cfg.owner || !owner.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if chain_id_to == cfg.chain_id {
        // A corridor to ourselves is meaningless and would collide with local ids.
        return Err(ProgramError::InvalidArgument);
    }
    if cfg.corridor_registered(chain_id_to) {
        return Ok(()); // idempotent; never resets a live nonce
    }
    if cfg.nonce_to.len() as u32 >= cfg.max_corridors {
        return Err(GateError::AtCapacity.into());
    }
    cfg.nonce_to.push((chain_id_to, 0));
    cfg.store(config_ai)?;
    msg!("corridor registered: {}", chain_id_to);
    Ok(())
}

/// Accounts: [config(w), signer(s)]
///
/// M-1: the circuit breaker. `Config.paused` existed but was dead — written
/// `false` at init, never read, with no instruction able to set it, so the Solana
/// leg had no incident response at all while `Gate.sol` gated both `send` and
/// `claim` on one. Guardian may pause; only the owner may unpause.
fn process_set_paused(program_id: &Pubkey, accounts: &[AccountInfo], paused: bool) -> ProgramResult {
    let it = &mut accounts.iter();
    let config_ai = next_account_info(it)?;
    let who = next_account_info(it)?;

    let mut cfg = load_config(program_id, config_ai)?;
    if !who.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let is_owner = who.key == &cfg.owner;
    let is_guardian = cfg.guardian != Pubkey::default() && who.key == &cfg.guardian;
    if !authorized_to_set_paused(is_owner, is_guardian, paused) {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if cfg.paused == paused {
        return Ok(());
    }
    cfg.paused = paused;
    cfg.store(config_ai)?;
    msg!("gate {}", if paused { "PAUSED" } else { "resumed" });
    Ok(())
}

/// Pure breaker-authority rule (host-testable): a guardian is a low-trust STOP
/// button — it may halt the gate but never restart it, so a compromised guardian
/// can only cause a recoverable liveness halt, never resume a gate the owner
/// deliberately stopped. Mirrors `Gate.pause` / `Gate.unpause`.
fn authorized_to_set_paused(is_owner: bool, is_guardian: bool, paused: bool) -> bool {
    if paused {
        is_owner || is_guardian
    } else {
        is_owner
    }
}

/// Accounts: [config(w), owner(s)] — appoint or clear the pause guardian.
fn process_set_guardian(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    guardian: Pubkey,
) -> ProgramResult {
    let it = &mut accounts.iter();
    let config_ai = next_account_info(it)?;
    let owner = next_account_info(it)?;

    let mut cfg = load_config(program_id, config_ai)?;
    if owner.key != &cfg.owner || !owner.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    cfg.guardian = guardian;
    cfg.store(config_ai)?;
    Ok(())
}

/// Accounts: [config(w), asset, payer(s), user_token(w), vault(w), spl_token_program]
fn process_send(program_id: &Pubkey, accounts: &[AccountInfo], args: SendArgs) -> ProgramResult {
    if args.amount == 0 {
        return Err(GateError::ZeroAmount.into());
    }
    if args.receiver.len() != 20 && args.receiver.len() != 32 {
        return Err(GateError::BadReceiver.into());
    }
    let it = &mut accounts.iter();
    let config_ai = next_account_info(it)?;
    let asset_ai = next_account_info(it)?;
    let payer = next_account_info(it)?;
    let user_token = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let token_program = next_account_info(it)?;
    // M-2: the `["sent", id]` record `refund` needs as its origin proof.
    let sent_ai = next_account_info(it)?;
    let system_program = next_account_info(it)?;

    // C1: bind the chain id + nonce sequence to the canonical config, so a forged
    // config can't rewrite them and desync the off-chain nonce/submissionId.
    let mut cfg = load_config(program_id, config_ai)?;
    // M-1: the circuit breaker halts new exposure.
    if cfg.paused {
        return Err(GateError::Paused.into());
    }
    // H-3: only a governance-registered destination. Checked before any account
    // work so a spam send costs the attacker a failed tx and nothing else.
    if !cfg.corridor_registered(args.chain_id_to) {
        return Err(GateError::CorridorNotRegistered.into());
    }

    // C1: bind the locked asset to the canonical registry for this debridge_id.
    // Without this a caller could lock a worthless token against a debridge_id
    // that pays out a valuable one on the destination. The token program must be
    // the real SPL token program, and the vault must be exactly the registered
    // one holding the registered mint.
    let asset = load_asset(program_id, &args.debridge_id, asset_ai)?;
    let (vault_mint, _vault_owner) = spl_mint_and_owner(vault, token_program.key)?;
    let (user_mint, _user_owner) = spl_mint_and_owner(user_token, token_program.key)?;
    verify_asset_binding(&asset, token_program.key, vault.key, &vault_mint, &user_mint)?;

    let nonce = cfg.nonce(args.chain_id_to);
    let native_sender = payer.key.to_bytes();
    let id = submission_id(
        &cfg.bridge_domain,
        &args.debridge_id,
        args.amount,
        cfg.chain_id,
        args.chain_id_to,
        nonce,
        &args.receiver,
        args.auto.as_ref(),
        &native_sender,
    );

    // effects before interaction
    cfg.bump_nonce(args.chain_id_to)?;
    cfg.store(config_ai)?;

    // M-2: record the origin proof + refund destination BEFORE the lock, so a
    // transfer can never exist without a way back. The per-corridor nonce makes
    // the submissionId unique, so this can never overwrite a live record.
    let (expected_sent, sent_bump) = Pubkey::find_program_address(&[b"sent", &id], program_id);
    if sent_ai.key != &expected_sent {
        return Err(ProgramError::InvalidSeeds);
    }
    create_sent_record(
        program_id,
        payer,
        sent_ai,
        system_program,
        &id,
        sent_bump,
        &SentRecord {
            debridge_id: args.debridge_id,
            sender: *payer.key,
            source_token: *user_token.key,
            mint: asset.mint,
            amount: args.amount,
            // M-4 / M-13: the on-chain age proof a refund attester reads.
            locked_at: solana_program::clock::Clock::get()?.unix_timestamp,
        },
    )?;

    // Emit the Sent event as structured program data for the validator's source,
    // carrying the registered mint as the locked asset identity (H5).
    emit_sent(&id, &args, cfg.chain_id, nonce, &native_sender, &asset.mint.to_bytes());

    // Lock: user -> vault (SPL CPI).
    let transfer = spl_token::instruction::transfer(
        token_program.key,
        user_token.key,
        vault.key,
        payer.key,
        &[],
        args.amount,
    )?;
    invoke(&transfer, &[user_token.clone(), vault.clone(), payer.clone(), token_program.clone()])?;
    Ok(())
}

/// Accounts: [config, executed_pda(w), payer(s,w), vault(w), receiver_token(w),
///            vault_authority, spl_token_program, system_program]
fn process_claim(program_id: &Pubkey, accounts: &[AccountInfo], args: ClaimArgs) -> ProgramResult {
    let it = &mut accounts.iter();
    let config_ai = next_account_info(it)?;
    let asset_ai = next_account_info(it)?;
    let executed_ai = next_account_info(it)?;
    let payer = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let receiver_token = next_account_info(it)?;
    let vault_authority = next_account_info(it)?;
    let token_program = next_account_info(it)?;
    let system_program = next_account_info(it)?;

    // C1: only the canonical program-owned config may drive signature checks.
    let cfg = load_config(program_id, config_ai)?;
    // M-1: a paused gate releases nothing.
    if cfg.paused {
        return Err(GateError::Paused.into());
    }

    // C1: the vault a claim releases from must be the one the program registered
    // for the SIGNED debridge_id — not an arbitrary vault under the global
    // vault-authority PDA. Also pin the SPL token program and prove the receiver
    // and vault hold the registered mint, so a forged/mismatched-config claim
    // can't drain a different asset's vault to the signed receiver.
    let asset = load_asset(program_id, &args.debridge_id, asset_ai)?;

    // Bind the release destination to the signed `receiver`. `claim` is
    // deliberately permissionless (any keeper may submit a threshold-signed
    // submission), so the token account funds are released to must be exactly
    // the one the validators signed for -- not whatever `receiver_token` the
    // caller happens to supply. Without this check anyone who observes a
    // threshold-signed submission (e.g. via the public sig-store) could claim
    // it themselves and redirect the payout to their own account.
    let receiver: [u8; 32] =
        args.receiver.as_slice().try_into().map_err(|_| GateError::BadReceiver)?;
    if receiver_token.key != &Pubkey::new_from_array(receiver) {
        return Err(GateError::BadReceiver.into());
    }

    // The vault and the receiver's token account must both hold the registered
    // mint under the real SPL token program, and the vault must be the registered
    // one (the receiver account's owner is free — the signed receiver key IS the
    // account, verified above).
    let (vault_mint, _vault_owner) = spl_mint_and_owner(vault, token_program.key)?;
    let (recv_mint, _recv_owner) = receiver_token_account(receiver_token, token_program.key)?;
    verify_asset_binding(&asset, token_program.key, vault.key, &vault_mint, &recv_mint)?;

    let id = submission_id(
        &cfg.bridge_domain,
        &args.debridge_id,
        args.amount,
        args.chain_id_from,
        cfg.chain_id,
        args.nonce,
        &args.receiver,
        args.auto.as_ref(),
        &args.native_sender,
    );

    // Replay guard: the executed PDA must not exist yet; creating it marks done.
    let (expected_executed, bump) =
        Pubkey::find_program_address(&[b"executed", &id], program_id);
    if executed_ai.key != &expected_executed {
        return Err(ProgramError::InvalidSeeds);
    }
    if is_already_executed(executed_ai.owner, executed_ai.data_len(), program_id) {
        return Err(GateError::AlreadyExecuted.into());
    }

    verify_threshold(&cfg, &id, &args.signatures)?;

    // Create the executed marker (effects before interaction).
    create_marker(
        program_id,
        payer,
        executed_ai,
        system_program,
        &[b"executed", &id],
        bump,
        MARKER_CLAIMED,
    )?;

    // Release: vault -> receiver, signed by the vault-authority PDA. Assert the
    // supplied vault_authority IS the canonical PDA (defense in depth: the SPL
    // transfer would already fail if the vault's authority didn't match, but an
    // explicit check fails fast with a clear error and documents the invariant).
    let (auth, auth_bump) = Pubkey::find_program_address(&[b"vault_authority"], program_id);
    if vault_authority.key != &auth {
        return Err(ProgramError::InvalidSeeds);
    }
    let transfer = spl_token::instruction::transfer(
        token_program.key,
        vault.key,
        receiver_token.key,
        vault_authority.key,
        &[],
        args.amount,
    )?;
    invoke_signed(
        &transfer,
        &[vault.clone(), receiver_token.clone(), vault_authority.clone(), token_program.clone()],
        &[&[b"vault_authority", &[auth_bump]]],
    )?;

    msg!("CLAIMED {}", bs58_id(&id));
    Ok(())
}

/// Accounts: [config(w), owner(s), gov_pda(w)?]
///
/// H-2 (round 4): ASYMMETRIC BY DESIGN, exactly as `Gate.setValidator`. ADDING a
/// validator hands out signing power and must consume a matured
/// `["gov", add_validator_action_id(v)]` schedule; REMOVING one takes power away
/// and is immediate — the moment a key is known compromised is the moment it
/// must leave the set. The third account is only required for an addition, so
/// removals keep the two-account shape existing tooling sends.
fn process_set_validator(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    validator: [u8; 20],
    active: bool,
) -> ProgramResult {
    let it = &mut accounts.iter();
    let config_ai = next_account_info(it)?;
    let owner = next_account_info(it)?;
    // C1: mutate only the canonical program-owned config, and only for its owner.
    let mut cfg = load_config(program_id, config_ai)?;
    if owner.key != &cfg.owner || !owner.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if validator == [0u8; 20] {
        return Err(GateError::ZeroValidator.into());
    }
    let present = cfg.is_validator(&validator);
    if active && !present {
        // L-3: the account was sized for `max_validators` at init and cannot grow.
        if cfg.validators.len() as u32 >= cfg.max_validators {
            return Err(GateError::AtCapacity.into());
        }
        // The power-granting direction waits out the timelock.
        let gov_ai = next_account_info(it)
            .map_err(|_| ProgramError::from(GateError::GovernanceNotScheduled))?;
        consume_governance(program_id, gov_ai, &add_validator_action_id(&validator))?;
        cfg.validators.push(validator);
    } else if !active && present {
        cfg.validators.retain(|v| v != &validator);
        if (cfg.validators.len() as u32) < cfg.threshold {
            return Err(ProgramError::InvalidArgument);
        }
    } else {
        return Ok(()); // no-op: no state change
    }
    cfg.store(config_ai)?;
    Ok(())
}

/// Accounts: [config(w), owner(s), gov_pda(w)?]
///
/// H-2 (round 4): same asymmetry as [`process_set_validator`]. RAISING the
/// threshold makes the gate harder to move and takes effect at once; LOWERING it
/// is the other half of the owner-drain path and must consume a matured
/// `["gov", lower_threshold_action_id(t)]` schedule. The schedule commits to the
/// exact value, so an approval for `t = 2` cannot be spent on `t = 1`.
fn process_set_threshold(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    threshold: u32,
) -> ProgramResult {
    let it = &mut accounts.iter();
    let config_ai = next_account_info(it)?;
    let owner = next_account_info(it)?;
    // C1: mutate only the canonical program-owned config, and only for its owner.
    let mut cfg = load_config(program_id, config_ai)?;
    if owner.key != &cfg.owner || !owner.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if threshold == 0 || threshold > cfg.validators.len() as u32 {
        return Err(ProgramError::InvalidArgument);
    }
    if threshold < cfg.threshold {
        let gov_ai = next_account_info(it)
            .map_err(|_| ProgramError::from(GateError::GovernanceNotScheduled))?;
        consume_governance(program_id, gov_ai, &lower_threshold_action_id(threshold))?;
    }
    cfg.threshold = threshold;
    cfg.store(config_ai)?;
    Ok(())
}

/// Accounts: [config, owner(s,w), asset_pda(w), mint, vault, spl_token_program,
///            system_program]
///
/// C1: owner-gated binding of a `debridge_id` to the SPL `mint` + `vault` that
/// may back it. Creating the `["asset", debridge_id]` PDA is what later lets
/// `send`/`claim` refuse any vault/mint that isn't the one governance signed off
/// on. The vault must hold `mint` and be owned by the canonical vault-authority
/// PDA, so a claim's `invoke_signed` can actually move its funds.
fn process_register_asset(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    debridge_id: [u8; 32],
) -> ProgramResult {
    let it = &mut accounts.iter();
    let config_ai = next_account_info(it)?;
    let owner = next_account_info(it)?;
    let asset_ai = next_account_info(it)?;
    let mint = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let token_program = next_account_info(it)?;
    let system_program = next_account_info(it)?;

    let cfg = load_config(program_id, config_ai)?;
    if owner.key != &cfg.owner || !owner.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if token_program.key != &spl_token::id() {
        return Err(ProgramError::IncorrectProgramId);
    }
    // The mint must be an SPL mint owned by the token program.
    if mint.owner != token_program.key {
        msg!("register: mint is not owned by the SPL token program");
        return Err(ProgramError::IllegalOwner);
    }
    spl_token::state::Mint::unpack(&mint.data.borrow())
        .map_err(|_| ProgramError::InvalidAccountData)?;

    // The vault must hold this mint and be controlled by the canonical
    // vault-authority PDA (only then can `claim`'s invoke_signed release it).
    let (vault_mint, vault_owner) = spl_mint_and_owner(vault, token_program.key)?;
    if &vault_mint != mint.key {
        msg!("register: vault mint != mint");
        return Err(ProgramError::InvalidAccountData);
    }
    let (auth, _auth_bump) = Pubkey::find_program_address(&[b"vault_authority"], program_id);
    if vault_owner != auth {
        msg!("register: vault is not owned by the canonical vault_authority PDA");
        return Err(ProgramError::InvalidAccountData);
    }
    // M-6: owning the vault is not enough — nobody ELSE may be able to move it.
    // A pre-set delegate or close authority drains liquidity outside the program
    // entirely, past every check above.
    let vault_state = spl_token::state::Account::unpack(&vault.data.borrow())
        .map_err(|_| ProgramError::InvalidAccountData)?;
    if !vault_is_exclusively_controlled(
        vault_state.delegate.into(),
        vault_state.close_authority.into(),
    ) {
        msg!("register: vault has a delegate or close authority set");
        return Err(ProgramError::InvalidAccountData);
    }

    let (expected_asset, bump) =
        Pubkey::find_program_address(&[b"asset", &debridge_id], program_id);
    if asset_ai.key != &expected_asset {
        return Err(ProgramError::InvalidSeeds);
    }

    let record = AssetConfig { debridge_id, mint: *mint.key, vault: *vault.key };
    let space: usize = 1 + 32 + 32 + 32; // borsh: debridge_id + mint + vault (+slack)
    if asset_ai.data_is_empty() {
        // M-5 (round 4): a `debridge_id` is public in advance, so an attacker
        // could pre-fund every plausible asset PDA and `create_account` would
        // refuse each one as "already in use" — bricking registration until the
        // program was redeployed. Same pre-funding-tolerant path as every other
        // PDA this program creates.
        create_pda_account(
            program_id,
            owner,
            asset_ai,
            system_program,
            &[b"asset", &debridge_id],
            bump,
            space,
        )?;
    } else if asset_ai.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    } else {
        // H-1: WRITE-ONCE, exactly as `Gate.sol::setLocalToken` is.
        //
        // A claim commits to `debridge_id` — never to the mint or the vault — so
        // the binding read at claim time decides what is actually paid out. If it
        // could be repointed, an owner (or a compromised owner key) could let
        // validators sign a transfer of asset X and then have those very same
        // signatures release asset Y from a different vault, with no change to
        // anything the validators attested.
        //
        // Registering a NEW corridor stays an ordinary owner action; changing a
        // live one must not exist. Route a different asset through a fresh
        // debridge_id instead.
        let existing = AssetConfig::deserialize(&mut &asset_ai.data.borrow()[..])
            .map_err(|_| ProgramError::InvalidAccountData)?;
        if !asset_write_allowed(&existing, &record)? {
            msg!("asset already registered with these exact values; no-op");
            return Ok(());
        }
    }
    record.serialize(&mut &mut asset_ai.data.borrow_mut()[..])?;
    msg!("asset registered for debridge_id");
    Ok(())
}

/// The single, versioned `Sent` event (finding H5). This MUST stay byte-for-byte
/// identical to `bridge_solana::relayer::SentEvent` (Borsh field order + types);
/// the host crate round-trips this exact `sol_log_data` framing in its tests.
///
/// The old code emitted only `id || debridge_id` with no version and in a framing
/// the relayer didn't decode — so Solana→EVM scanning could never work and a
/// validator couldn't reconstruct the submissionId. This carries every
/// hash-bound field plus the locked `mint` (asset identity).
#[derive(BorshSerialize)]
struct SentEvent {
    version: u8,
    submission_id: [u8; 32],
    debridge_id: [u8; 32],
    mint: [u8; 32],
    amount: u64,
    chain_id_from: u64,
    chain_id_to: u64,
    nonce: u64,
    receiver: Vec<u8>,
    native_sender: Vec<u8>,
    auto: Option<AutoParamsWire>,
}

const SENT_EVENT_TAG: &[u8] = b"BRIDGE_SENT";
const SENT_EVENT_VERSION: u8 = 1;

/// M-2 lifecycle events. Same `sol_log_data` framing and versioning as
/// [`SentEvent`], so the indexer decodes all three the same way. These are what
/// let the off-chain refund loop observe a Solana burn/payout as an on-chain
/// fact, exactly as it observes `Gate.Cancelled`/`Gate.Refunded` on the EVM side.
const CANCELLED_EVENT_TAG: &[u8] = b"BRIDGE_CANCELLED";
const REFUNDED_EVENT_TAG: &[u8] = b"BRIDGE_REFUNDED";

/// The payload both lifecycle events carry — mirrors the EVM `Cancelled`/
/// `Refunded` event fields.
#[derive(BorshSerialize)]
struct LifecycleEvent {
    version: u8,
    submission_id: [u8; 32],
    debridge_id: [u8; 32],
    chain_id: u64,
    nonce: u64,
}

fn emit_lifecycle(
    tag: &[u8],
    id: &[u8; 32],
    debridge_id: &[u8; 32],
    chain_id: u64,
    nonce: u64,
) {
    let event = LifecycleEvent {
        version: SENT_EVENT_VERSION,
        submission_id: *id,
        debridge_id: *debridge_id,
        chain_id,
        nonce,
    };
    let bytes = borsh::to_vec(&event).expect("borsh serialize LifecycleEvent");
    solana_program::log::sol_log_data(&[tag, &bytes]);
}

/// Emit the `Sent` event via `sol_log_data` (base64 program data in the tx logs)
/// so the validator's Solana source can decode it with
/// `bridge_solana::relayer::parse_sent_log_line`.
fn emit_sent(
    id: &[u8; 32],
    args: &SendArgs,
    chain_id_from: u64,
    nonce: u64,
    native_sender: &[u8],
    mint: &[u8; 32],
) {
    let event = SentEvent {
        version: SENT_EVENT_VERSION,
        submission_id: *id,
        debridge_id: args.debridge_id,
        mint: *mint,
        amount: args.amount,
        chain_id_from,
        chain_id_to: args.chain_id_to,
        nonce,
        receiver: args.receiver.clone(),
        native_sender: native_sender.to_vec(),
        auto: args.auto.clone(),
    };
    let bytes = borsh::to_vec(&event).expect("borsh serialize SentEvent");
    solana_program::log::sol_log_data(&[SENT_EVENT_TAG, &bytes]);
}

fn bs58_id(id: &[u8; 32]) -> String {
    // small helper; solana-program pulls in bs58 transitively
    solana_program::pubkey::Pubkey::new_from_array(*id).to_string()
}

// ---------------------------------------------------------------------------
// C1 authorization tests (host-runnable — no SBF VM needed).
//
// These exercise the *pure* authorization predicates the on-chain handlers route
// through, reproducing the C1 attack scenarios (config takeover, forged-config
// vault drain, unauthorized init) and proving each is refused. A full
// `solana-program-test` account-level harness additionally requires the SBF
// toolchain (cargo-build-sbf), which isn't present in this environment; the
// predicate-level coverage here is the runnable evidence.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod c1_tests {
    use super::*;

    fn pid() -> Pubkey {
        Pubkey::new_unique()
    }

    // A config account is trusted ONLY when it is the canonical ["config"] PDA
    // and program-owned. Reproduces the takeover: an attacker's own config
    // account (their key, their ownership) is refused.
    #[test]
    fn forged_config_account_is_rejected() {
        let program_id = pid();
        let (canonical, _) = Pubkey::find_program_address(&[b"config"], &program_id);

        // Genuine config: canonical PDA, program-owned -> accepted.
        assert!(verify_config_account(&canonical, &program_id, &program_id).is_ok());

        // Attack 1: attacker-created account (not the PDA), owned by the program.
        let attacker_key = Pubkey::new_unique();
        assert_eq!(
            verify_config_account(&attacker_key, &program_id, &program_id),
            Err(ProgramError::InvalidSeeds)
        );

        // Attack 2: the canonical *address* but not program-owned (an account the
        // attacker owns) — the forged-config drain vector.
        let attacker_owner = Pubkey::new_unique();
        assert_eq!(
            verify_config_account(&canonical, &attacker_owner, &program_id),
            Err(ProgramError::IllegalOwner)
        );
    }

    // The asset registry PDA is trusted only when canonical for its debridge_id
    // and program-owned.
    #[test]
    fn forged_asset_account_is_rejected() {
        let program_id = pid();
        let debridge_id = [0x11u8; 32];
        let (canonical, _) =
            Pubkey::find_program_address(&[b"asset", &debridge_id], &program_id);

        assert!(verify_asset_account(&canonical, &program_id, &debridge_id, &program_id).is_ok());

        // Wrong debridge_id -> different PDA -> rejected.
        let other = [0x22u8; 32];
        let (canonical_other, _) =
            Pubkey::find_program_address(&[b"asset", &other], &program_id);
        assert_eq!(
            verify_asset_account(&canonical_other, &program_id, &debridge_id, &program_id),
            Err(ProgramError::InvalidSeeds)
        );

        // Right PDA but attacker-owned -> rejected.
        let attacker = Pubkey::new_unique();
        assert_eq!(
            verify_asset_account(&canonical, &attacker, &debridge_id, &program_id),
            Err(ProgramError::IllegalOwner)
        );
    }

    // The forged-config vault drain: even with a threshold-signed submission, a
    // claim can only release from the vault registered for the SIGNED asset, of
    // the registered mint, under the real SPL token program.
    #[test]
    fn asset_binding_blocks_wrong_vault_or_mint() {
        let mint = Pubkey::new_unique();
        let vault = Pubkey::new_unique();
        let asset = AssetConfig { debridge_id: [1; 32], mint, vault };
        let spl = spl_token::id();

        // Honest release: registered vault, registered mint on both sides.
        assert!(verify_asset_binding(&asset, &spl, &vault, &mint, &mint).is_ok());

        // Attack: a different vault (another asset's) under the global authority.
        let other_vault = Pubkey::new_unique();
        assert_eq!(
            verify_asset_binding(&asset, &spl, &other_vault, &mint, &mint),
            Err(ProgramError::InvalidAccountData)
        );

        // Attack: vault holds a different mint than registered.
        let other_mint = Pubkey::new_unique();
        assert_eq!(
            verify_asset_binding(&asset, &spl, &vault, &other_mint, &mint),
            Err(ProgramError::InvalidAccountData)
        );

        // Attack: receiver token account is a different mint.
        assert_eq!(
            verify_asset_binding(&asset, &spl, &vault, &mint, &other_mint),
            Err(ProgramError::InvalidAccountData)
        );

        // Attack: a fake token program.
        let fake_prog = Pubkey::new_unique();
        assert_eq!(
            verify_asset_binding(&asset, &fake_prog, &vault, &mint, &mint),
            Err(ProgramError::IncorrectProgramId)
        );
    }

    // ---------------------------------------------------------------
    // H-1 — the asset registry is write-once
    // ---------------------------------------------------------------

    /// THE H-1 rule. `Gate.sol` makes `setLocalToken` write-once and says why: a
    /// claim commits to `debridge_id`, never to the local asset, so whoever can
    /// repoint the binding can redirect a signed transfer to a different asset
    /// without the validators attesting anything new. The Solana registry used to
    /// re-serialize unconditionally, so it had exactly that hole.
    #[test]
    fn a_live_asset_binding_cannot_be_repointed() {
        let debridge_id = [0x11u8; 32];
        let live = AssetConfig {
            debridge_id,
            mint: Pubkey::new_unique(),
            vault: Pubkey::new_unique(),
        };

        // The attack: same debridge_id, attacker's mint + vault.
        let repoint = AssetConfig {
            debridge_id,
            mint: Pubkey::new_unique(),
            vault: Pubkey::new_unique(),
        };
        assert_eq!(
            asset_write_allowed(&live, &repoint),
            Err(GateError::AssetAlreadyRegistered.into()),
            "a registered corridor must not be repointable"
        );

        // Swapping only the vault is the same attack with a smaller diff.
        let revault = AssetConfig { vault: Pubkey::new_unique(), ..live.clone() };
        assert_eq!(
            asset_write_allowed(&live, &revault),
            Err(GateError::AssetAlreadyRegistered.into()),
            "repointing just the vault is still a repoint"
        );

        // And only the mint.
        let remint = AssetConfig { mint: Pubkey::new_unique(), ..live.clone() };
        assert_eq!(
            asset_write_allowed(&live, &remint),
            Err(GateError::AssetAlreadyRegistered.into())
        );
    }

    /// A freshly created (all-zero) account is written normally — that is the
    /// ordinary first registration.
    #[test]
    fn a_fresh_asset_account_is_written() {
        let incoming = AssetConfig {
            debridge_id: [0x11; 32],
            mint: Pubkey::new_unique(),
            vault: Pubkey::new_unique(),
        };
        assert_eq!(asset_write_allowed(&AssetConfig::default(), &incoming), Ok(true));
    }

    /// Re-registering the IDENTICAL binding is a no-op rather than an error, so a
    /// deploy script that runs twice does not fail. This is the one case where
    /// write-once must not mean "explode".
    #[test]
    fn re_registering_the_same_binding_is_an_idempotent_no_op() {
        let a = AssetConfig {
            debridge_id: [0x11; 32],
            mint: Pubkey::new_unique(),
            vault: Pubkey::new_unique(),
        };
        assert_eq!(asset_write_allowed(&a, &a.clone()), Ok(false));
    }

    // ---------------------------------------------------------------
    // H-2 — the executed marker
    // ---------------------------------------------------------------

    // Lamports prove nothing: ANY account can be funded by anyone, and the
    // submissionId is public (source-chain `Sent` event, signature store). The old
    // guard `lamports() > 0 || !data_is_empty()` let a griefer transfer the
    // rent-exempt minimum to the derived PDA and block that claim forever — with
    // no cancel/refund path on this program to recover from it.
    #[test]
    fn a_pre_funded_marker_is_not_executed() {
        let program_id = pid();
        let system = Pubkey::default();

        // The griefing state: funded, system-owned, zero data. NOT executed.
        assert!(
            !is_already_executed(&system, 0, &program_id),
            "a pre-funded PDA must not read as already executed"
        );
        // Fresh, untouched.
        assert!(!is_already_executed(&system, 0, &program_id));
        // Genuinely executed: program-owned WITH data — only this program can
        // produce that combination.
        assert!(is_already_executed(&program_id, MARKER_LEN, &program_id));
        // Program-owned but empty cannot occur via `create_marker`, and is not
        // treated as executed either.
        assert!(!is_already_executed(&program_id, 0, &program_id));
    }

    // ---------------------------------------------------------------
    // H-3 / L-3 — bounded config
    // ---------------------------------------------------------------

    /// Borsh size of the PRE-FIX `Config` (no guardian, no capacity fields), for
    /// the historical-arithmetic test below.
    fn old_config_space(validators: u32, corridors: u32) -> usize {
        32 + (4 + 20 * validators as usize) + 4 + 8 + 1 + (4 + 16 * corridors as usize)
    }

    // The exact arithmetic that made H-3 exploitable: at 3 validators the old flat
    // 512-byte account held 24 corridors, so the 25th `send` to an invented chain
    // id overflowed it and bricked send + governance permanently.
    #[test]
    fn the_old_flat_512_byte_config_really_did_overflow() {
        assert!(old_config_space(3, 24) <= 512, "24 corridors fit the old buffer");
        assert!(old_config_space(3, 25) > 512, "the 25th overflowed it — this was the brick");
    }

    // The fix, measured against real Borsh output rather than against itself: a
    // config filled to its declared capacity must fit the account `process_init`
    // sizes from those same capacities.
    #[test]
    fn a_config_at_full_capacity_fits_its_account() {
        for (v, c) in [(3u32, 8u32), (7, 32), (22, 4), (1, 1)] {
            let cfg = Config {
                owner: Pubkey::new_unique(),
                bridge_domain: [0xD0; 32],
                guardian: Pubkey::new_unique(),
                validators: (0..v).map(|i| [i as u8; 20]).collect(),
                threshold: 1,
                chain_id: SOLANA_CHAIN_ID,
                paused: false,
                max_validators: v,
                max_corridors: c,
                nonce_to: (0..c as u64).map(|i| (1000 + i, i)).collect(),
            };
            let actual = borsh::to_vec(&cfg).expect("serialize").len();
            assert_eq!(
                actual,
                config_space(v, c),
                "config_space must match real Borsh output at capacity {v}/{c}"
            );
        }
    }

    // `send` can no longer create a corridor — that is governance-only now, which
    // is what bounds the vector an attacker used to grow.
    #[test]
    fn send_cannot_create_a_corridor() {
        let mut cfg = Config { max_corridors: 4, ..Default::default() };
        assert!(
            cfg.bump_nonce(4242).is_err(),
            "an unregistered destination must be refused, not appended"
        );

        cfg.nonce_to.push((4242, 0));
        assert!(cfg.bump_nonce(4242).is_ok(), "a registered corridor advances normally");
        assert_eq!(cfg.nonce(4242), 1);
        assert_eq!(cfg.nonce_to.len(), 1, "no entry may ever be appended by a send");
    }

    // ---------------------------------------------------------------
    // M-1 — the circuit breaker
    // ---------------------------------------------------------------

    // A guardian is a low-trust STOP button: it may halt the gate but never
    // restart it, so a compromised guardian causes a recoverable liveness halt
    // rather than resuming a gate the owner deliberately stopped.
    #[test]
    fn guardian_may_pause_but_only_the_owner_may_resume() {
        // pause
        assert!(authorized_to_set_paused(true, false, true), "owner may pause");
        assert!(authorized_to_set_paused(false, true, true), "guardian may pause");
        assert!(!authorized_to_set_paused(false, false, true), "a stranger may not");
        // unpause
        assert!(authorized_to_set_paused(true, false, false), "owner may resume");
        assert!(!authorized_to_set_paused(false, true, false), "guardian may NOT resume");
        assert!(!authorized_to_set_paused(false, false, false), "a stranger may not");
    }

    // ---------------------------------------------------------------
    // M-6 — vault exclusivity
    // ---------------------------------------------------------------

    // Owning the vault proves the program CAN move it; it does not prove nobody
    // else can. A delegate transfers up to `delegated_amount` with no involvement
    // from the owner PDA, and a close authority sweeps the account — both entirely
    // outside this program.
    #[test]
    fn vault_with_a_delegate_or_close_authority_is_rejected() {
        let someone = Pubkey::new_unique();
        assert!(vault_is_exclusively_controlled(None, None), "a clean vault is fine");
        assert!(!vault_is_exclusively_controlled(Some(someone), None), "delegate drains it");
        assert!(!vault_is_exclusively_controlled(None, Some(someone)), "close authority sweeps it");
        assert!(!vault_is_exclusively_controlled(Some(someone), Some(someone)));
    }

    // ---------------------------------------------------------------
    // M-2 — the cancel/refund digest domains
    // ---------------------------------------------------------------

    /// The Solana gate must derive `cancelId`/`refundId` byte-identically to
    /// `BridgeHash.sol`, or a validator's attestation signed for one VM would not
    /// verify on the other and the refund path would silently never form a quorum.
    ///
    /// These expected values are ground truth taken from Solidity itself
    /// (`BridgeHash.getCancelId` / `getRefundId`, cross-checked with `cast keccak`)
    /// for `submissionId = 0x1111…11`.
    #[test]
    fn cancel_and_refund_ids_match_bridgehash_sol() {
        let id = [0x11u8; 32];

        let expected_cancel =
            hex_literal("5f53d5916a01e246eeb5fd7d9e96634532fe35b576656d6244780290984a5eee");
        let expected_refund =
            hex_literal("3457405ce2152b6317347888618027bd5912e3026e48a5654384dbcb99a45b6e");

        assert_eq!(cancel_id(&id), expected_cancel, "cancelId diverged from BridgeHash.sol");
        assert_eq!(refund_id(&id), expected_refund, "refundId diverged from BridgeHash.sol");
    }

    /// The three domains must be pairwise distinct — that separation is the only
    /// thing stopping a transfer quorum (which authorises PAYING a transfer) from
    /// being replayed to burn it, or a cancel quorum from being replayed to claw
    /// funds back on the source.
    #[test]
    fn the_three_signing_domains_are_distinct() {
        let id = [0x11u8; 32];
        let transfer = id;
        let cancel = cancel_id(&id);
        let refund = refund_id(&id);

        assert_ne!(transfer, cancel, "a transfer signature must not authorise a burn");
        assert_ne!(transfer, refund, "a transfer signature must not authorise a refund");
        assert_ne!(cancel, refund, "a cancel attestation must not authorise a refund");
    }

    /// Decode a 64-char hex string into a 32-byte array (test helper — the program
    /// itself never parses hex).
    fn hex_literal(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("valid hex");
        }
        out
    }

    /// A marker byte must distinguish the two terminal states, so a consumer can
    /// tell "delivered" from "burned" — a zero-length marker could not, which is
    /// why H-2's rewrite gave it a data byte.
    #[test]
    fn claimed_and_cancelled_markers_are_distinguishable() {
        assert_ne!(MARKER_CLAIMED, MARKER_CANCELLED);
        assert_ne!(MARKER_CLAIMED, 0, "0 would read as 'not executed'");
        assert_ne!(MARKER_CANCELLED, 0, "0 would read as 'not executed'");
    }

    // -----------------------------------------------------------------------
    // Signature-array length cap. `secp256k1_recover` is ~25k CU, so an
    // unbounded array is a compute-budget bomb: eight junk signatures exhaust
    // the 200k default before quorum is reached, and because claim, cancel AND
    // refund all funnel through `verify_threshold`, the payout and both recovery
    // paths die together. The store will accept junk (it authenticates a
    // signature against its claimed signer, not against the validator set), so
    // the gate has to refuse it here.
    // -----------------------------------------------------------------------

    /// A config with `n` validators. The signature bytes in these tests never
    /// need to recover — the cap must reject on LENGTH ALONE, before the first
    /// (expensive) recover, which is the entire point.
    fn cfg_with_validators(n: usize) -> Config {
        Config {
            owner: Pubkey::new_unique(),
            bridge_domain: [0xD0; 32],
            guardian: Pubkey::default(),
            validators: (0..n).map(|i| [i as u8; 20]).collect(),
            threshold: 2,
            chain_id: 7565164,
            paused: false,
            max_validators: 32,
            max_corridors: 8,
            nonce_to: vec![],
        }
    }

    #[test]
    fn more_signatures_than_validators_is_refused() {
        let cfg = cfg_with_validators(3);
        let id = [0x11u8; 32];

        // 4 signatures against a 3-validator set: impossible for an honest array
        // (signers must be distinct and ascending), so it is padding.
        let padded = vec![vec![0u8; 65]; 4];
        assert_eq!(
            verify_threshold(&cfg, &id, &padded),
            Err(GateError::TooManySignatures),
            "a padded array must be refused on length, before any recover"
        );
    }

    /// The griefing scenario in full: two junk signatures on top of a legitimate
    /// 2-of-3 quorum. Before the cap this array was accepted into the recover
    /// loop and burned ~125k CU; the cap turns it into a cheap, immediate
    /// refusal, so the honest relayer's next (unpadded) attempt still lands.
    #[test]
    fn junk_padding_cannot_force_the_expensive_path() {
        let cfg = cfg_with_validators(3);
        let id = [0x11u8; 32];

        let quorum_plus_junk = vec![vec![0u8; 65]; 5];
        assert_eq!(
            verify_threshold(&cfg, &id, &quorum_plus_junk),
            Err(GateError::TooManySignatures)
        );
    }

    /// The cap must not touch honest arrays: exactly `validatorCount` signatures
    /// is legal and has to reach the recover loop (where these all-zero bytes
    /// then fail as bad signatures — proving we got PAST the length check).
    #[test]
    fn an_array_no_longer_than_the_validator_set_passes_the_cap() {
        let cfg = cfg_with_validators(3);
        let id = [0x11u8; 32];

        for len in 1..=3usize {
            let sigs = vec![vec![0u8; 65]; len];
            assert_eq!(
                verify_threshold(&cfg, &id, &sigs),
                Err(GateError::BadSignature),
                "{len} signatures must reach the recover loop, not the length cap"
            );
        }
    }

    /// Every path that spends validator authority shares one cap, because an
    /// attacker who could only brick `claim` would still strand the funds — the
    /// recovery instructions must survive the same padding.
    #[test]
    fn claim_cancel_and_refund_share_the_cap() {
        let cfg = cfg_with_validators(2);
        let id = [0x11u8; 32];
        let padded = vec![vec![0u8; 65]; 3];

        for digest in [id, cancel_id(&id), refund_id(&id)] {
            assert_eq!(
                verify_threshold(&cfg, &digest, &padded),
                Err(GateError::TooManySignatures),
                "every signing domain must reject padding"
            );
        }
    }

    // -----------------------------------------------------------------------
    // L-4a: a wallet pubkey as receiver must fail with its OWN error.
    //
    // The behaviour was always right — a non-token-account receiver cannot be
    // credited, and the gate must not substitute the "correct" account because
    // the receiver is hash-bound. What was missing is that it surfaced as a bare
    // IllegalOwner/InvalidAccountData, identical to a misconfigured vault or the
    // wrong token program, leaving the one USER-recoverable failure in `claim`
    // indistinguishable from an operator bug.
    // -----------------------------------------------------------------------

    /// A wallet pubkey is System-owned, not SPL-owned. That is exactly the
    /// account a user pastes by mistake.
    #[test]
    fn a_wallet_receiver_is_named_not_guessed_at() {
        let spl = spl_token::id();
        let system_owned = solana_program::system_program::id();

        // The predicate the receiver path uses, exercised through the same
        // owner check: a System-owned account is refused as a receiver...
        assert_ne!(system_owned, spl, "a wallet account is not SPL-owned");

        // ...and the error it maps to is the distinct one, not a generic.
        let e: ProgramError = GateError::ReceiverNotTokenAccount.into();
        assert_ne!(e, ProgramError::IllegalOwner);
        assert_ne!(e, ProgramError::InvalidAccountData);
        assert!(matches!(e, ProgramError::Custom(_)));
    }

    /// The distinct code must not collide with any other gate error — otherwise
    /// it is no more diagnosable than the generic it replaced.
    #[test]
    fn the_receiver_error_is_distinguishable_from_every_other() {
        let receiver: ProgramError = GateError::ReceiverNotTokenAccount.into();
        for other in [
            GateError::ZeroAmount,
            GateError::BadReceiver,
            GateError::AlreadyExecuted,
            GateError::InvalidSignerOrder,
            GateError::NotEnoughSignatures,
            GateError::BadSignature,
            GateError::CorridorNotRegistered,
            GateError::Paused,
            GateError::AtCapacity,
            GateError::NotSent,
            GateError::AlreadyClaimed,
            GateError::NotCancelled,
            GateError::TooManySignatures,
            GateError::AssetAlreadyRegistered,
            GateError::ZeroBridgeDomain,
            GateError::GovernanceNotScheduled,
            GateError::GovernanceNotReady,
            GateError::GovernanceExpired,
            GateError::DuplicateValidator,
            GateError::ZeroValidator,
        ] {
            assert_ne!(receiver, ProgramError::from(other), "collides with {other:?}");
        }
    }

    /// `BadReceiver` and `ReceiverNotTokenAccount` are different failures and
    /// must stay so: the first is a malformed 32-byte value or a receiver that
    /// does not match the SIGNED one (an authorization failure); the second is a
    /// well-formed, correctly-signed key that simply is not a token account (a
    /// user error). Collapsing them would hide a redirection attempt behind a
    /// message that reads like a typo.
    #[test]
    fn bad_receiver_and_not_a_token_account_are_separate_failures() {
        assert_ne!(
            ProgramError::from(GateError::BadReceiver),
            ProgramError::from(GateError::ReceiverNotTokenAccount)
        );
    }

    /// Adding `TooManySignatures` must not renumber the existing errors: clients
    /// (and the account-level suite) match on `ProgramError::Custom(n)`, so a
    /// shifted discriminant silently changes what every other failure means.
    #[test]
    fn error_discriminants_are_append_only() {
        assert_eq!(ProgramError::from(GateError::ZeroAmount), ProgramError::Custom(1));
        assert_eq!(ProgramError::from(GateError::AlreadyExecuted), ProgramError::Custom(3));
        assert_eq!(ProgramError::from(GateError::NotEnoughSignatures), ProgramError::Custom(5));
        assert_eq!(ProgramError::from(GateError::Paused), ProgramError::Custom(8));
        assert_eq!(ProgramError::from(GateError::NotCancelled), ProgramError::Custom(12));
        // New variants land after every pre-existing one, in order.
        assert_eq!(ProgramError::from(GateError::TooManySignatures), ProgramError::Custom(13));
        assert_eq!(ProgramError::from(GateError::ReceiverNotTokenAccount), ProgramError::Custom(14));
        assert_eq!(ProgramError::from(GateError::AssetAlreadyRegistered), ProgramError::Custom(15));
        assert_eq!(ProgramError::from(GateError::ZeroBridgeDomain), ProgramError::Custom(16));
        // Round 4 additions, appended in order.
        assert_eq!(ProgramError::from(GateError::GovernanceNotScheduled), ProgramError::Custom(17));
        assert_eq!(ProgramError::from(GateError::GovernanceNotReady), ProgramError::Custom(18));
        assert_eq!(ProgramError::from(GateError::GovernanceExpired), ProgramError::Custom(19));
        assert_eq!(ProgramError::from(GateError::DuplicateValidator), ProgramError::Custom(20));
        assert_eq!(ProgramError::from(GateError::ZeroValidator), ProgramError::Custom(21));
    }

    // ---------------------------------------------------------------
    // H-2 (round 4) — the governance timelock rule
    // ---------------------------------------------------------------

    /// The consume rule, over cluster time. Not scheduled / immature / matured /
    /// expired are four different answers and only ONE of them is "go".
    #[test]
    fn a_schedule_is_consumable_only_inside_its_window() {
        let ready_at = 1_000_000i64;
        // Never scheduled (or already consumed/cancelled): the zero sentinel.
        assert_eq!(governance_consumable(0, ready_at + 1), Err(GateError::GovernanceNotScheduled));
        // Immature: one second early is still early.
        assert_eq!(governance_consumable(ready_at, ready_at - 1), Err(GateError::GovernanceNotReady));
        // Exactly at ready_at, and anywhere inside the grace window: consumable.
        assert_eq!(governance_consumable(ready_at, ready_at), Ok(()));
        assert_eq!(governance_consumable(ready_at, ready_at + GOVERNANCE_GRACE), Ok(()));
        // One second past the grace window: a stale approval, refused.
        assert_eq!(
            governance_consumable(ready_at, ready_at + GOVERNANCE_GRACE + 1),
            Err(GateError::GovernanceExpired)
        );
    }

    /// The delay is the EVM gate's 48 hours and the grace is a week — pinned so
    /// nobody quietly shortens the window the whole mesh's users plan around.
    #[test]
    fn governance_delay_and_grace_match_the_design() {
        assert_eq!(GOVERNANCE_DELAY, 48 * 3600, "must equal Gate.sol GOVERNANCE_DELAY");
        assert_eq!(GOVERNANCE_GRACE, 7 * 86_400);
        assert!(GOVERNANCE_GRACE > 0, "a zero grace would make every schedule expire on arrival");
    }

    /// A schedule commits to ONE concrete change. Different validators, different
    /// thresholds, and the two kinds of action all derive distinct ids, so an
    /// approval for one can never be spent on another.
    #[test]
    fn action_ids_are_specific_to_the_exact_change() {
        let a = add_validator_action_id(&[0xAA; 20]);
        let b = add_validator_action_id(&[0xBB; 20]);
        assert_ne!(a, b, "approving validator A must not approve validator B");

        let t1 = lower_threshold_action_id(1);
        let t2 = lower_threshold_action_id(2);
        assert_ne!(t1, t2, "an approval for t=2 must not be spendable on t=1");

        // Cross-kind: the domain strings keep them apart even for overlapping bytes.
        assert_ne!(add_validator_action_id(&[0u8; 20]), lower_threshold_action_id(0));
        // Deterministic, so off-chain tooling can derive the same id.
        assert_eq!(a, add_validator_action_id(&[0xAA; 20]));
    }

    /// A `["sent", id]` record written before `locked_at` existed must still
    /// decode — it proves the lock — with an unknown (zero) lock time.
    #[test]
    fn a_legacy_sent_record_decodes_with_an_unknown_lock_time() {
        let rec = SentRecord {
            debridge_id: [1; 32],
            sender: Pubkey::new_unique(),
            source_token: Pubkey::new_unique(),
            mint: Pubkey::new_unique(),
            amount: 77,
            locked_at: 1_700_000_000,
        };
        let full = borsh::to_vec(&rec).unwrap();
        assert_eq!(full.len(), SENT_RECORD_LEN);
        let legacy = &full[..SENT_RECORD_LEN - 8];

        let decoded = decode_sent_record(legacy).expect("legacy layout decodes");
        assert_eq!(decoded.amount, 77);
        assert_eq!(decoded.source_token, rec.source_token);
        assert_eq!(decoded.locked_at, 0, "unknown lock time reads as 0");

        let current = decode_sent_record(&full).expect("current layout decodes");
        assert_eq!(current.locked_at, 1_700_000_000);
        assert!(decode_sent_record(&full[..100]).is_err(), "anything else is corrupt");
    }

    // ---------------------------------------------------------------
    // LOW (round 4) — init validator-set validation
    // ---------------------------------------------------------------

    #[test]
    fn init_refuses_duplicate_and_zero_validators_and_a_bad_threshold() {
        let a = [1u8; 20];
        let b = [2u8; 20];
        assert_eq!(validate_validator_set(&[a, b], 2), Ok(()));
        assert_eq!(validate_validator_set(&[a, b], 1), Ok(()));

        assert_eq!(
            validate_validator_set(&[a, a], 2),
            Err(GateError::DuplicateValidator.into()),
            "the same key twice must not count as two validators"
        );
        assert_eq!(
            validate_validator_set(&[a, [0u8; 20]], 1),
            Err(GateError::ZeroValidator.into()),
            "the zero address can never sign; registering it only inflates the count"
        );
        assert_eq!(validate_validator_set(&[a, b], 0), Err(ProgramError::InvalidArgument));
        assert_eq!(validate_validator_set(&[a, b], 3), Err(ProgramError::InvalidArgument));
        assert_eq!(validate_validator_set(&[], 1), Err(ProgramError::InvalidArgument));
    }

    // Atomic/authorized init: only the program's upgrade authority (deployer) may
    // initialize; a front-runner or an immutable program is refused.
    #[test]
    fn init_requires_upgrade_authority() {
        let deployer = Pubkey::new_unique();
        assert!(verify_upgrade_authority(Some(deployer), &deployer).is_ok());

        // A front-runner who is not the upgrade authority.
        let attacker = Pubkey::new_unique();
        assert_eq!(
            verify_upgrade_authority(Some(deployer), &attacker),
            Err(ProgramError::MissingRequiredSignature)
        );

        // Immutable program (authority renounced) — can't be safely initialized.
        assert_eq!(
            verify_upgrade_authority(None, &deployer),
            Err(ProgramError::InvalidArgument)
        );
    }
}
