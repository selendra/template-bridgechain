//! The Borsh instruction wire format a Solana gate program (de)serializes.
//!
//! Solana crate take a raw byte buffer as instruction data; the convention is
//! Borsh. This is the on-the-wire contract between the off-chain keeper (which
//! builds a `Claim`) and the on-chain program (which decodes and executes it).
//! Governance instructions are included for completeness; the bridge hot path is
//! `Send` (source) and `Claim` (target).

use borsh::{BorshDeserialize, BorshSerialize};

/// Execution payload, Borsh-encoded (Solana-native form of `AutoParamsTo`).
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct AutoParamsWire {
    pub execution_fee: u128,
    pub flags: u64,
    pub fallback_address: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct SendArgs {
    pub debridge_id: [u8; 32],
    pub amount: u64,
    pub chain_id_to: u64,
    /// 20-byte EVM address (Solana→EVM).
    pub receiver: Vec<u8>,
    pub auto: Option<AutoParamsWire>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct ClaimArgs {
    pub debridge_id: [u8; 32],
    pub amount: u64,
    pub chain_id_from: u64,
    pub nonce: u64,
    /// 32-byte Solana token account (EVM→Solana).
    pub receiver: Vec<u8>,
    pub auto: Option<AutoParamsWire>,
    /// Packed source-chain sender; needed to recompute the id when `auto` is set.
    pub native_sender: Vec<u8>,
    /// 65-byte `r||s||v` validator signatures, sorted ascending by signer.
    pub signatures: Vec<Vec<u8>>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct InitArgs {
    /// Deployment generation, folded into every submissionId. MUST match the
    /// `bridgeDomain()` of the EVM gates in this mesh, and MUST be rotated for a
    /// new deployment generation. Field order mirrors `solana_gate::InitArgs`
    /// exactly — this struct is Borsh-serialized into the instruction the
    /// program deserializes, so a mismatch in order silently misparses.
    pub bridge_domain: [u8; 32],
    /// EVM validator addresses (the same set the EVM gate trusts).
    pub validators: Vec<[u8; 20]>,
    pub threshold: u32,
    /// This gate's chain id (Solana).
    pub chain_id: u64,
    /// Hard capacity for the validator set — the config account is SIZED from
    /// this at init and can never grow (findings H-3 / L-3).
    pub max_validators: u32,
    /// Hard capacity for registered corridors (destination chains).
    pub max_corridors: u32,
    /// May trip the circuit breaker but not release it. 32 zero bytes == none.
    pub guardian: [u8; 32],
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum GateInstruction {
    /// Create + populate the Config PDA (validator set, threshold, chain id).
    Init(InitArgs),
    Send(SendArgs),
    Claim(ClaimArgs),
    SetValidator { validator: [u8; 20], active: bool },
    SetThreshold { threshold: u32 },
    /// C1: bind a `debridge_id` to the SPL mint + vault that may back it
    /// (owner-gated on-chain). Appended last so discriminants 0..=4 stay stable
    /// and byte-compatible with the deployable program's enum.
    RegisterAsset { debridge_id: [u8; 32] },
    /// H-3: owner-gated registration of a destination chain. `send` refuses any
    /// `chain_id_to` not registered here, which is what bounds the corridor
    /// vector an attacker could previously grow until the config no longer fit
    /// its account.
    RegisterCorridor { chain_id_to: u64 },
    /// M-1: trip the circuit breaker (owner or guardian).
    Pause,
    /// M-1: release it (owner only — a guardian may stop but not start).
    Unpause,
    /// M-1: appoint or clear the pause guardian (owner only).
    SetGuardian { guardian: [u8; 32] },
    /// M-2, DESTINATION side: burn a transfer so it can never be claimed,
    /// unlocking a source-chain refund. Moves no funds.
    Cancel(CancelArgs),
    /// M-2, SOURCE side: return locked funds after the destination was burned.
    Refund(RefundArgs),
    /// H-2 (round 4): queue a validator ADDITION or threshold DECREASE behind the
    /// program's 48 h `GOVERNANCE_DELAY`. Owner only. `action_id` is
    /// [`add_validator_action_id`] / [`lower_threshold_action_id`]; the schedule
    /// lives in the PDA `["gov", action_id]`. Discriminant 12.
    ///
    /// Accounts: `[config, owner(s,w), gov_pda(w), system_program]`.
    ScheduleGovernance { action_id: [u8; 32] },
    /// H-2 (round 4): drop a queued action. Owner OR guardian. Discriminant 13.
    ///
    /// Accounts: `[config, signer(s), gov_pda(w)]`.
    CancelScheduledGovernance { action_id: [u8; 32] },
}

/// The program's `GOVERNANCE_DELAY`, in seconds: how long a scheduled validator
/// addition or threshold decrease waits. Mirrors `Gate.sol`'s 48 hours.
pub const GOVERNANCE_DELAY_SECS: i64 = 48 * 60 * 60;
/// The program's `GOVERNANCE_GRACE`: how long a matured schedule stays spendable.
pub const GOVERNANCE_GRACE_SECS: i64 = 7 * 24 * 60 * 60;

/// `keccak("addValidator" ‖ v)` — the action id `ScheduleGovernance` needs before
/// `SetValidator { active: true }` will admit `v`. Must equal the program's
/// `add_validator_action_id`; `solana-gate`'s account-level suite pins it.
pub fn add_validator_action_id(v: &[u8; 20]) -> [u8; 32] {
    let mut p = Vec::with_capacity(12 + 20);
    p.extend_from_slice(b"addValidator");
    p.extend_from_slice(v);
    crate::hash::keccak(&p)
}

/// `keccak("lowerThreshold" ‖ uint256(t))` — the action id a threshold DECREASE
/// to exactly `t` must have scheduled.
pub fn lower_threshold_action_id(t: u32) -> [u8; 32] {
    let mut p = Vec::with_capacity(14 + 32);
    p.extend_from_slice(b"lowerThreshold");
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&(t as u64).to_be_bytes());
    p.extend_from_slice(&word);
    crate::hash::keccak(&p)
}

/// The `["gov", action_id]` schedule account body: `ready_at == 0` means "not
/// scheduled". Mirrors `solana_gate::GovernanceSchedule`.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct GovernanceSchedule {
    pub ready_at: i64,
}

/// Destination-side burn. `signatures` are over `cancelId(submissionId)` — a
/// different digest domain from the transfer signatures, so a transfer quorum can
/// never be replayed to burn a healthy transfer.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct CancelArgs {
    pub debridge_id: [u8; 32],
    pub amount: u64,
    pub chain_id_from: u64,
    pub nonce: u64,
    pub receiver: Vec<u8>,
    pub auto: Option<AutoParamsWire>,
    pub native_sender: Vec<u8>,
    pub signatures: Vec<Vec<u8>>,
}

/// Source-side payout. `signatures` are over `refundId(submissionId)`. The amount
/// actually released comes from the program's own `["sent", id]` record, not from
/// this struct, so a caller cannot inflate it.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct RefundArgs {
    pub debridge_id: [u8; 32],
    pub amount: u64,
    pub chain_id_to: u64,
    pub nonce: u64,
    pub receiver: Vec<u8>,
    pub auto: Option<AutoParamsWire>,
    pub native_sender: Vec<u8>,
    pub signatures: Vec<Vec<u8>>,
}

impl GateInstruction {
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("borsh serialize GateInstruction")
    }

    pub fn try_from_bytes(data: &[u8]) -> std::io::Result<Self> {
        borsh::from_slice(data)
    }
}
