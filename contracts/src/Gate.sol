// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {BridgeHash} from "./BridgeHash.sol";

/// @title Gate
/// @notice External-validator bridge gate, modeled on deBridge's DeBridgeGate.
///         Deployed on every supported chain. `send()` locks an ERC-20 and emits
///         a `Sent` event; `claim()` verifies a threshold of validator signatures
///         and releases funds exactly once (replay-safe).
/// @dev    EVM <-> EVM, lock/unlock model: the target gate holds pre-funded
///         liquidity of the local token registered for a debridgeId.
///
/// @dev    LIQUIDITY MODEL — read before adding a corridor (finding L-6).
///
///         This gate keeps ONE balance per ERC-20, not one per corridor. `claim`
///         releases `tokenOf[debridgeId]` from that shared balance with no
///         per-`debridgeId` accounting, so every corridor mapped to the same
///         local token draws on the same pot. Consequences to plan around:
///
///           * Corridors are NOT isolated. If chains B and C both bridge into
///             this gate's USDC, a surge (or a compromise) on B can exhaust the
///             liquidity C's users depend on. The failure surfaces as a claim
///             reverting on transfer, which the two-phase refund then recovers —
///             availability, not loss.
///           * Locked value on the source and claimable value on the destination
///             are related only by operator provisioning. Nothing on-chain
///             enforces that this gate holds enough to honour what other chains
///             have locked against it.
///
///         Two ways to bound that, neither implemented here because both change
///         how operators provision and are a product decision rather than a
///         defect fix: per-`debridgeId` balance accounting (credit on `send` from
///         the paired chain, debit on `claim`), or a per-corridor rate/volume cap.
///         Until then, treat shared-token corridors as one trust domain and size
///         liquidity for their combined worst case.
///
/// @dev    UPGRADEABILITY. This is a UUPS implementation and is meant to live
///         behind an ERC1967 proxy — the proxy address is the gate, and it is
///         what `CHAINS` and every validator/keeper config must point at.
///
///         Deploying it upgradeable is not a convenience. A gate accumulates
///         liquidity, per-corridor registrations and, critically, `nonceTo`; a
///         *replacement* gate starts all of that from scratch, and a submissionId
///         binds to `bridgeDomain` + nonce rather than to a contract address, so
///         a fresh deployment is the event that historically let old attestations
///         replay. Upgrading in place keeps one address and one storage, which
///         removes the need to ever redeploy for a fix.
///
///         The base classes are storage-safe to inherit: `UUPSUpgradeable` keeps
///         only an `immutable` (bytecode, not storage) and `Initializable` uses
///         ERC-7201 namespaced storage, so `owner` remains at slot 0 and the
///         layout below is exactly what a non-proxied deploy would have. When
///         adding state in a future version, APPEND to the end and shrink
///         `__gap` by the same number of slots — never reorder or insert.
contract Gate is Initializable, UUPSUpgradeable {
    using SafeERC20 for IERC20;

    /// @dev To-side execution payload, abi.encode'd into `send`/`claim` autoParams.
    struct AutoParamsTo {
        uint256 executionFee;
        uint256 flags;
        bytes fallbackAddress;
        bytes data;
    }

    // --- validator set / governance ---
    address public owner;
    address public pendingOwner;
    mapping(address => bool) public isValidator;
    uint256 public validatorCount;
    uint256 public threshold;

    /// @notice Identifies this DEPLOYMENT GENERATION of the mesh, and is folded
    ///         into every submissionId (see {BridgeHash.packedSubmission}).
    ///
    /// @dev    Every gate in one mesh — every EVM chain AND the Solana program —
    ///         must be initialized with the SAME value, or no two of them ever
    ///         compute the same submissionId and nothing bridges at all. That
    ///         loud failure is deliberate; the alternative was the silent one.
    ///
    ///         Set once at {initialize} and never mutable afterwards: changing it
    ///         on a live gate would strand every in-flight transfer, because the
    ///         source has already emitted ids under the old domain while the
    ///         destination would only accept ids under the new one. A new domain
    ///         belongs to a new deployment generation, not to an upgrade.
    bytes32 public bridgeDomain;

    // --- emergency circuit breaker ---
    /// @dev when true, `send` and `claim` are halted (incident response)
    bool public paused;
    /// @dev may trip the breaker (fast incident response) but cannot un-pause;
    ///      only `owner` can resume. address(0) until the owner appoints one.
    address public guardian;

    // --- source-side state ---
    /// @dev per-target-chain monotonic nonce
    mapping(uint256 chainIdTo => uint256) public nonceTo;
    /// @dev who locked the funds for each submissionId this gate emitted.
    ///
    ///      Two jobs, both essential to `refund`:
    ///        1. **origin proof** — a nonzero entry is the only evidence that this
    ///           gate really sent `submissionId`. Without it a validator quorum
    ///           could authorise a refund for a transfer that never happened here.
    ///        2. **refund recipient** — `nativeSender` is only folded into the
    ///           submissionId when `autoParams` is non-empty, so for a plain
    ///           transfer it is NOT bound by the hash and a caller could name any
    ///           address. Storage is authoritative; the calldata is not trusted.
    ///
    ///      Cleared on `refund` (and left set otherwise, so it doubles as the
    ///      "still refundable" flag).
    mapping(bytes32 submissionId => address sender) public sentBy;
    /// @dev source-side replay guard: a submissionId may only be refunded once
    mapping(bytes32 submissionId => bool) public refunded;

    // --- target-side state ---
    /// @dev replay guard: a submissionId may only ever be executed once.
    ///      Set by `claim` (funds released) AND by `cancel` (funds permanently
    ///      NOT released) — check `cancelled` to tell the two apart.
    mapping(bytes32 submissionId => bool) public executed;
    /// @dev target-side: this submissionId was burned by `cancel`, not claimed.
    ///      Consumers that treat `executed` as "delivered" (e.g. SwapRouter's
    ///      `finalize`) MUST also check this, or they will act on a delivery that
    ///      never happened.
    mapping(bytes32 submissionId => bool) public cancelled;
    /// @dev asset registry: which local ERC-20 backs a given debridgeId on THIS chain
    mapping(bytes32 debridgeId => address localToken) public tokenOf;

    // --- upgrade timelock ---
    /// @notice Earliest timestamp at which a scheduled implementation may be
    ///         installed. Zero means "not scheduled" — and {_authorizeUpgrade}
    ///         treats zero as a refusal, so an implementation can never be
    ///         installed without first sitting out the delay in public view.
    mapping(address implementation => uint256 readyAt) public upgradeReadyAt;

    /// @notice How long a scheduled upgrade must wait before it can be executed.
    /// @dev    A gate holds other people's funds and an upgrade can rewrite every
    ///         rule below, so the delay exists to give users a window to exit
    ///         before an implementation swap takes effect. It is a CONSTANT, not
    ///         an owner-settable parameter: an owner who could shorten it could
    ///         set it to zero and the timelock would be decorative.
    ///
    ///         This does not slow down incident response — that is what
    ///         {pause} and the guardian are for, and pausing takes effect in one
    ///         transaction. Upgrades are for fixes, not for emergencies.
    uint256 public constant UPGRADE_DELAY = 48 hours;

    // --- governance timelock (validator set / threshold) ---

    /// @notice Earliest timestamp at which a scheduled governance action may run.
    ///         Zero means "not scheduled", and {_consumeGovernance} treats zero as
    ///         a refusal — so a delayed action can never run without first sitting
    ///         out {GOVERNANCE_DELAY} in public view.
    /// @dev    Keyed by the action ids {addValidatorActionId} /
    ///         {lowerThresholdActionId} / {setLocalTokenActionId} derive, so a
    ///         schedule authorises exactly one concrete change (this validator,
    ///         that threshold, this corridor) rather than a blanket right.
    mapping(bytes32 actionId => uint256 readyAt) public governanceReadyAt;

    /// @notice How long a validator ADDITION, a threshold DECREASE or (once
    ///         {isSealed}) a corridor REGISTRATION must wait.
    ///
    /// @dev    THIS IS THE SAME DEFENCE AS {UPGRADE_DELAY}, and it exists because
    ///         without it the upgrade timelock was decorative.
    ///
    ///         An owner who can add a validator and lower the threshold in one
    ///         transaction can sign a claim for every registered corridor and
    ///         empty the gate — the exact outcome a malicious upgrade buys, with
    ///         none of the 48-hour notice the upgrade path forces. Delaying the
    ///         implementation swap while leaving that door open protected nothing,
    ///         and was worse than no timelock at all, because operators and users
    ///         plan around a window they were told they had.
    ///
    ///         Constant, not owner-settable, for the reason {UPGRADE_DELAY} is.
    uint256 public constant GOVERNANCE_DELAY = 48 hours;

    /// @notice How long a MATURED schedule (governance or upgrade) stays
    ///         executable before it expires.
    ///
    /// @dev    Without this a schedule was a banked instant right for life: an
    ///         owner could queue a validator addition, let it mature, and hold it
    ///         unused for years — and a key stolen at any later date inherited
    ///         every matured schedule as an instant action, which is exactly what
    ///         {GOVERNANCE_DELAY} exists to deny. The window is generous enough to
    ///         execute a planned change across a weekend or a missed maintenance
    ///         slot, and short enough that a stale approval cannot outlive the
    ///         public attention the delay bought. An expired schedule is simply
    ///         re-scheduled, which restarts the delay in public view again.
    ///
    ///         Constant, not owner-settable, for the reason {UPGRADE_DELAY} is.
    uint256 public constant SCHEDULE_GRACE = 7 days;

    // --- corridor registry (appended in the H-1 / M-3 revision) ---

    /// @notice One-way flag: once set, registering a NEW corridor via
    ///         {setLocalToken} goes through {scheduleGovernance} + {GOVERNANCE_DELAY}
    ///         like every other power-granting owner action.
    ///
    /// @dev    WHY A SETUP PHASE. A gate starts with an empty registry, and an
    ///         operator wiring a fresh mesh registers tens of corridors in one
    ///         sitting while the gate holds nothing. Forcing 48 hours per corridor
    ///         there protects no funds and would push operators toward keeping a
    ///         separate "instant" path around. So `setLocalToken` is a plain owner
    ///         action while `!isSealed`, and the deployment procedure ends with
    ///         {seal} BEFORE liquidity is provisioned.
    ///
    ///         WHY IT MUST BE ONE-WAY. After seal the registry is what stands
    ///         between an owner key and the vault (finding H-1): a fake asset on
    ///         chain A, honestly attested by validators, mapped onto this gate's
    ///         USDC, is a full drain in one block. With the delay, observers see
    ///         `GovernanceScheduled(setLocalTokenActionId(...))` and have
    ///         {GOVERNANCE_DELAY} to verify the SOURCE asset behind the debridgeId
    ///         — and the guardian can {cancelScheduledGovernance} it. An owner who
    ///         could un-seal would have that delay only nominally.
    bool public isSealed;

    /// @notice Destination chains `send` may lock funds towards.
    ///
    /// @dev    A transfer needs a gate on `chainIdTo` to be either claimed or
    ///         cancelled, and a refund requires the cancel. Funds sent to a chain
    ///         id with no gate (a typo, a chain this mesh never joined) were
    ///         therefore locked with no recovery path at all (finding M-3). The
    ///         registry makes that impossible: `send` refuses any chain the owner
    ///         has not listed. Listing is an instant owner action because it only
    ///         ever RESTRICTS what users can do — it grants no power over funds —
    ///         and de-listing is likewise instant so a dead corridor can be closed
    ///         the moment it is known to be dead.
    mapping(uint256 chainId => bool) public supportedChain;

    /// @dev Reserved so a future version can append state without colliding with
    ///      anything a child contract or a later gap-consuming field occupies.
    ///      Adding N slots of new state means shrinking this by exactly N.
    ///      (`governanceReadyAt` took one: 50 -> 49. `isSealed` and
    ///      `supportedChain` took one each: 49 -> 47. The gap still ends at
    ///      slot 63, so the layout is upgrade-compatible with the live gates.)
    uint256[47] private __gap;

    /// @param token the ERC-20 locked on THIS chain. Not part of the submissionId
    ///        (which commits to `debridgeId`, a one-way hash of it), so it is
    ///        emitted explicitly — the refund relayer needs the concrete address
    ///        to build `refund()`, and keccak is not invertible.
    event Sent(
        bytes32 indexed submissionId,
        bytes32 indexed debridgeId,
        uint256 amount,
        uint256 chainIdFrom,
        uint256 chainIdTo,
        bytes receiver,
        uint256 nonce,
        bytes autoParams,
        bytes nativeSender,
        address token
    );

    event Claimed(
        bytes32 indexed submissionId,
        bytes32 indexed debridgeId,
        address indexed receiver,
        uint256 amount
    );

    /// @notice Emitted on the DESTINATION chain when a transfer is burned so it
    ///         can never be claimed — the precondition for a source-side refund.
    event Cancelled(
        bytes32 indexed submissionId,
        bytes32 indexed debridgeId,
        uint256 chainIdFrom,
        uint256 nonce
    );

    /// @notice Emitted on the SOURCE chain when locked funds are returned.
    event Refunded(
        bytes32 indexed submissionId,
        bytes32 indexed debridgeId,
        address indexed sender,
        uint256 amount
    );

    // --- governance events (auditability) ---
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event ValidatorSet(address indexed validator, bool active);
    event ThresholdSet(uint256 threshold);
    event LocalTokenSet(bytes32 indexed debridgeId, address indexed localToken);
    event GuardianSet(address indexed guardian);
    event Paused(address indexed account);
    event Unpaused(address indexed account);
    /// @notice An implementation entered the upgrade queue. `readyAt` is when it
    ///         becomes installable — the public warning users act on.
    event UpgradeScheduled(address indexed implementation, uint256 readyAt);
    event UpgradeCancelled(address indexed implementation);
    /// @notice A validator addition or threshold decrease entered the queue.
    ///         `readyAt` is when it becomes executable — the public warning.
    event GovernanceScheduled(bytes32 indexed actionId, uint256 readyAt);
    event GovernanceCancelled(bytes32 indexed actionId);
    /// @notice The setup phase ended: from now on every new corridor waits out
    ///         {GOVERNANCE_DELAY}. Irreversible.
    event Sealed();
    /// @notice A destination chain was listed (`ok`) or de-listed for `send`.
    event SupportedChainSet(uint256 indexed chainId, bool ok);

    error NotOwner();
    error ZeroAmount();
    error AlreadyExecuted();
    error NotEnoughSignatures(uint256 got, uint256 want);
    error InvalidSignerOrder();
    error UnknownAsset(bytes32 debridgeId);
    error BadReceiver();
    /// @dev the gate received a different amount than `amount` on transferIn — a
    ///      fee-on-transfer / rebasing token, which this gate does not support
    ///      (the signed `amount` would exceed what was actually locked, letting a
    ///      claim on the destination release more than was received).
    error UnsupportedTokenBehavior(uint256 expected, uint256 received);
    /// @dev more signatures supplied than there are validators — junk padding.
    error TooManySignatures(uint256 supplied, uint256 validatorCount);
    error ZeroValidator();
    error ZeroAddress();
    /// @dev threshold must always satisfy 0 < threshold <= validatorCount
    error InvalidThreshold(uint256 threshold, uint256 validatorCount);
    error EnforcedPause();
    error NotAuthorizedToPause();
    /// @dev refund asked for a submissionId this gate never emitted (or one
    ///      already refunded — `sentBy` is cleared on payout)
    error NotSent(bytes32 submissionId);
    error AlreadyRefunded(bytes32 submissionId);
    /// @dev the `token` passed to `refund` is not the one `debridgeId` commits to
    error TokenMismatch(bytes32 debridgeId, address token);
    /// @dev `setLocalToken` is write-once: a registered corridor cannot be
    ///      repointed at a different asset, because in-flight claims bind only the
    ///      `debridgeId` and would then release the new token.
    error LocalTokenAlreadySet(bytes32 debridgeId, address current);
    /// @dev a zero domain is refused because it is what an uninitialized proxy
    ///      would report, and a mesh that silently agreed on "unset" would be
    ///      exactly as replayable as having no domain at all.
    error ZeroBridgeDomain();
    /// @dev {upgradeToAndCall} reached an implementation that was never put
    ///      through {scheduleUpgrade}
    error UpgradeNotScheduled(address implementation);
    /// @dev the scheduled implementation is still inside its {UPGRADE_DELAY}
    error UpgradeNotReady(address implementation, uint256 readyAt);
    /// @dev a validator addition / threshold decrease was attempted without first
    ///      going through {scheduleGovernance}
    error GovernanceNotScheduled(bytes32 actionId);
    /// @dev the scheduled governance action is still inside its {GOVERNANCE_DELAY}
    error GovernanceNotReady(bytes32 actionId, uint256 readyAt);
    /// @dev the schedule matured more than {SCHEDULE_GRACE} ago and is void; it
    ///      must be re-scheduled. `key` is the governance `actionId`, or for an
    ///      upgrade the implementation address left-padded into a bytes32.
    error ScheduleExpired(bytes32 key, uint256 readyAt);
    /// @dev {seal} was called on a gate that is already sealed
    error AlreadySealed();
    /// @dev `send` towards a chain the owner has not listed in {supportedChain}
    error UnsupportedChain(uint256 chainIdTo);
    /// @dev a 32-byte (non-EVM) receiver was given an amount the destination VM
    ///      cannot represent. The Solana gate carries amounts as u64 and rejects
    ///      anything wider on BOTH claim and cancel, so such a transfer could
    ///      neither be delivered nor refunded (finding H-3).
    error AmountTooWide(uint256 amount);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert EnforcedPause();
        _;
    }

    /// @dev The implementation contract is only ever delegatecall'd through the
    ///      proxy, so its OWN storage must stay permanently uninitialized. Without
    ///      this, anyone can call {initialize} directly on the implementation and
    ///      become its `owner`; a UUPS implementation that has an owner can then
    ///      be told to `upgradeToAndCall` arbitrary code in its own context. Cheap
    ///      to prevent, unrecoverable if skipped.
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the gate behind its proxy. Replaces the constructor —
    ///         a proxy never runs one, so any state set there would live in the
    ///         implementation's storage and be invisible to every user.
    /// @param bridgeDomain_ the mesh-wide deployment domain; see {bridgeDomain}.
    function initialize(address[] memory validators, uint256 threshold_, bytes32 bridgeDomain_)
        external
        initializer
    {
        // No `__UUPSUpgradeable_init()` here: that belongs to the separate
        // openzeppelin-contracts-upgradeable package. The UUPSUpgradeable in
        // openzeppelin-contracts holds no initializable state at all — only the
        // `__self` immutable — so there is nothing to initialize.
        if (bridgeDomain_ == bytes32(0)) revert ZeroBridgeDomain();
        bridgeDomain = bridgeDomain_;

        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);

        for (uint256 i = 0; i < validators.length; i++) {
            address v = validators[i];
            if (v == address(0)) revert ZeroValidator();
            if (!isValidator[v]) {
                isValidator[v] = true;
                validatorCount++;
                emit ValidatorSet(v, true);
            }
        }

        // A zero (or unreachable) threshold is fatal: threshold == 0 would let
        // claim() pass with NO signatures; threshold > validatorCount freezes funds.
        if (threshold_ == 0 || threshold_ > validatorCount) {
            revert InvalidThreshold(threshold_, validatorCount);
        }
        threshold = threshold_;
        emit ThresholdSet(threshold_);
    }

    // ---------------------------------------------------------------------
    // Upgrades (UUPS, owner-gated, behind a fixed timelock)
    // ---------------------------------------------------------------------

    /// @notice Queue `implementation` for installation once {UPGRADE_DELAY} has
    ///         elapsed. Emits {UpgradeScheduled} so holders can see the pending
    ///         change and withdraw before it lands.
    /// @dev    Re-scheduling an implementation RESTARTS its delay rather than
    ///         keeping the earliest deadline. Otherwise an owner could schedule
    ///         an address once, wait out the window, and hold an indefinitely
    ///         re-usable instant-upgrade right against it.
    function scheduleUpgrade(address implementation) external onlyOwner {
        if (implementation == address(0)) revert ZeroAddress();
        uint256 readyAt = block.timestamp + UPGRADE_DELAY;
        upgradeReadyAt[implementation] = readyAt;
        emit UpgradeScheduled(implementation, readyAt);
    }

    /// @notice Drop a queued implementation. The guardian may do this as well as
    ///         the owner: spotting a bad pending upgrade is incident response,
    ///         and the guardian exists precisely to act fast there. Neither can
    ///         *install* anything this way, so the worst case is a delay.
    function cancelScheduledUpgrade(address implementation) external {
        if (msg.sender != owner && msg.sender != guardian) revert NotAuthorizedToPause();
        delete upgradeReadyAt[implementation];
        emit UpgradeCancelled(implementation);
    }

    /// @dev The UUPS hook. Enforces owner + scheduled + matured, then BURNS the
    ///      schedule so one approval installs exactly one implementation; without
    ///      the delete, a rolled-back upgrade could be re-installed instantly.
    ///
    ///      Deliberately does NOT have a pause/emergency bypass. An upgrade that
    ///      is urgent enough to skip the delay is indistinguishable on-chain from
    ///      an owner takeover, which is the exact thing the delay defends against;
    ///      genuine emergencies are served by {pause}, which is immediate.
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
        uint256 readyAt = upgradeReadyAt[newImplementation];
        if (readyAt == 0) revert UpgradeNotScheduled(newImplementation);
        if (block.timestamp < readyAt) revert UpgradeNotReady(newImplementation, readyAt);
        // A matured schedule is not a right for life — see {SCHEDULE_GRACE}.
        if (block.timestamp > readyAt + SCHEDULE_GRACE) {
            revert ScheduleExpired(bytes32(uint256(uint160(newImplementation))), readyAt);
        }
        delete upgradeReadyAt[newImplementation];
    }

    // ---------------------------------------------------------------------
    // Governance
    // ---------------------------------------------------------------------

    /// @notice Begin a two-step ownership handover (the new owner must accept).
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    /// @notice Complete an ownership handover. Two-step so a typo'd address can't
    ///         brick governance.
    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotOwner();
        emit OwnershipTransferred(owner, pendingOwner);
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    /// @notice The action id for adding `v` to the validator set.
    function addValidatorActionId(address v) public pure returns (bytes32) {
        return keccak256(abi.encode("addValidator", v));
    }

    /// @notice The action id for lowering the threshold to `t`.
    function lowerThresholdActionId(uint256 t) public pure returns (bytes32) {
        return keccak256(abi.encode("lowerThreshold", t));
    }

    /// @notice The action id for registering `localToken` as the asset behind
    ///         `debridgeId` (required by {setLocalToken} once {isSealed}).
    /// @dev    Commits to BOTH halves, so a matured approval for "debridgeId X
    ///         pays out token Y" cannot be spent to point X at anything else.
    function setLocalTokenActionId(bytes32 debridgeId, address localToken)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode("setLocalToken", debridgeId, localToken));
    }

    /// @notice Queue a validator addition, threshold decrease or (after {seal})
    ///         corridor registration for execution once {GOVERNANCE_DELAY} has
    ///         elapsed. Build `actionId` with {addValidatorActionId} /
    ///         {lowerThresholdActionId} / {setLocalTokenActionId}.
    /// @dev    Re-scheduling RESTARTS the delay, for the same reason
    ///         {scheduleUpgrade} does: otherwise one matured schedule would be an
    ///         indefinitely re-usable instant-change right against that action.
    function scheduleGovernance(bytes32 actionId) external onlyOwner {
        uint256 readyAt = block.timestamp + GOVERNANCE_DELAY;
        governanceReadyAt[actionId] = readyAt;
        emit GovernanceScheduled(actionId, readyAt);
    }

    /// @notice Drop a queued governance action. Guardian as well as owner, exactly
    ///         as {cancelScheduledUpgrade}: spotting a bad pending validator
    ///         addition is incident response, and neither party can *execute*
    ///         anything this way, so the worst case is a delay.
    function cancelScheduledGovernance(bytes32 actionId) external {
        if (msg.sender != owner && msg.sender != guardian) revert NotAuthorizedToPause();
        delete governanceReadyAt[actionId];
        emit GovernanceCancelled(actionId);
    }

    /// @dev Require a matured, unexpired schedule for `actionId`, then BURN it,
    ///      so one approval authorises exactly one change. Mirrors
    ///      {_authorizeUpgrade}, including the {SCHEDULE_GRACE} expiry.
    function _consumeGovernance(bytes32 actionId) internal {
        uint256 readyAt = governanceReadyAt[actionId];
        if (readyAt == 0) revert GovernanceNotScheduled(actionId);
        if (block.timestamp < readyAt) revert GovernanceNotReady(actionId, readyAt);
        if (block.timestamp > readyAt + SCHEDULE_GRACE) revert ScheduleExpired(actionId, readyAt);
        delete governanceReadyAt[actionId];
    }

    /// @notice Add or remove a validator.
    ///
    /// @dev    ASYMMETRIC BY DESIGN. Adding a validator hands out signing power and
    ///         waits out {GOVERNANCE_DELAY}; REMOVING one takes it away and is
    ///         immediate.
    ///
    ///         Delaying a removal would be the wrong direction entirely: the moment
    ///         you learn a validator key is compromised is the moment you want it
    ///         out of the set, and every rule here that shrinks the attacker's
    ///         reach — this, {pause}, {cancelScheduledUpgrade} — is instant for
    ///         that reason. Only the directions that grant power wait.
    ///
    ///         OPERATOR NOTE. A removal still cannot drop `validatorCount` below
    ///         `threshold` (that would freeze the gate). So evicting a validator
    ///         from a set already at `validatorCount == threshold` means lowering
    ///         the threshold first, which DOES wait out the delay. That is the
    ///         intended trade and it costs nothing in an incident: a minority
    ///         validator cannot move funds on its own, and {pause} is immediate if
    ///         you want everything stopped meanwhile.
    function setValidator(address v, bool active) external onlyOwner {
        if (v == address(0)) revert ZeroValidator();
        if (active && !isValidator[v]) {
            _consumeGovernance(addValidatorActionId(v));
            isValidator[v] = true;
            validatorCount++;
        } else if (!active && isValidator[v]) {
            isValidator[v] = false;
            validatorCount--;
            // never let the active set fall below the threshold (liveness)
            if (validatorCount < threshold) revert InvalidThreshold(threshold, validatorCount);
        } else {
            return; // no-op: no state change, no event
        }
        emit ValidatorSet(v, active);
    }

    /// @notice Change how many validator signatures a claim needs.
    ///
    /// @dev    Same asymmetry as {setValidator}, for the same reason: RAISING the
    ///         threshold makes the gate harder to move and takes effect at once;
    ///         LOWERING it is the other half of the owner-drain path
    ///         ({GOVERNANCE_DELAY} explains it) and waits.
    ///
    ///         The schedule commits to the exact value, not to "may lower", so a
    ///         matured approval for `t = 2` cannot be spent on `t = 1`.
    function setThreshold(uint256 t) external onlyOwner {
        if (t == 0 || t > validatorCount) revert InvalidThreshold(t, validatorCount);
        if (t < threshold) _consumeGovernance(lowerThresholdActionId(t));
        threshold = t;
        emit ThresholdSet(t);
    }

    /// @notice Register the local ERC-20 that backs `debridgeId` on this chain.
    /// @dev    WRITE-ONCE. A claim commits to a `debridgeId` — a one-way hash of
    ///         the SOURCE asset — never to the local token, so the mapping read at
    ///         claim time decides what is actually paid out. If it could be
    ///         repointed, an owner (or a compromised key) could let validators sign
    ///         a transfer of asset X and then have the very same signatures release
    ///         asset Y, with no change to anything the validators attested. The
    ///         same read backs `SwapRouter._settle`'s `UnexpectedAsset` guard.
    ///
    ///         So a nonzero mapping is immutable; *changing* a corridor is never
    ///         possible — deploy a new gate, or route the asset through a fresh
    ///         debridgeId. `address(0)` is rejected because zero is the
    ///         "unregistered" sentinel `claim` tests against.
    ///
    ///         DELAYED AFTER {seal} (finding H-1). Write-once stops a corridor from
    ///         being REPOINTED, but registering a NEW one is just as dangerous once
    ///         the gate holds liquidity: the owner mints a worthless token W on
    ///         chain A, `send`s 1,000,000 of it here, validators honestly attest
    ///         the fact, and `setLocalToken(keccak(A, W), USDC)` turns those
    ///         signatures into a claim on this gate's entire USDC pot — in one
    ///         block, with none of the notice the validator/threshold/upgrade
    ///         timelocks force. So while `!isSealed` (the empty gate is being wired)
    ///         this is an instant owner action; after {seal} it consumes a matured
    ///         {setLocalTokenActionId} schedule, which gives observers
    ///         {GOVERNANCE_DELAY} to inspect the SOURCE asset behind `debridgeId`
    ///         and the guardian time to {cancelScheduledGovernance} a bad one.
    function setLocalToken(bytes32 debridgeId, address localToken) external onlyOwner {
        if (localToken == address(0)) revert ZeroAddress();
        address current = tokenOf[debridgeId];
        if (current != address(0)) revert LocalTokenAlreadySet(debridgeId, current);
        if (isSealed) _consumeGovernance(setLocalTokenActionId(debridgeId, localToken));
        tokenOf[debridgeId] = localToken;
        emit LocalTokenSet(debridgeId, localToken);
    }

    /// @notice End the setup phase. From here on every new corridor waits out
    ///         {GOVERNANCE_DELAY}. IRREVERSIBLE — see {isSealed} for why.
    /// @dev    Call this as the last wiring step and BEFORE provisioning
    ///         liquidity: an unsealed gate that holds funds is exactly the H-1
    ///         drain waiting for an owner key.
    function seal() external onlyOwner {
        if (isSealed) revert AlreadySealed();
        isSealed = true;
        emit Sealed();
    }

    /// @notice List (or de-list) a destination chain for `send`.
    /// @dev    Instant in both directions, deliberately — see {supportedChain}.
    ///         Listing a chain grants nobody power over funds (a claim there still
    ///         needs its own gate and a validator quorum), and de-listing only
    ///         stops NEW locks; in-flight transfers are unaffected because
    ///         `claim`, `cancel` and `refund` never consult this registry.
    function setSupportedChain(uint256 chainId, bool ok) external onlyOwner {
        supportedChain[chainId] = ok;
        emit SupportedChainSet(chainId, ok);
    }

    /// @notice Appoint (or clear) the guardian who can trip the circuit breaker.
    /// @dev    The guardian is a low-trust "stop button": it can pause but never
    ///         un-pause or move funds, so a compromised guardian can only cause a
    ///         (recoverable) liveness halt, not theft. Pass address(0) to revoke.
    function setGuardian(address newGuardian) external onlyOwner {
        guardian = newGuardian;
        emit GuardianSet(newGuardian);
    }

    /// @notice Halt `send`/`claim` in an incident. Callable by owner or guardian.
    function pause() external {
        if (msg.sender != owner && msg.sender != guardian) revert NotAuthorizedToPause();
        if (!paused) {
            paused = true;
            emit Paused(msg.sender);
        }
    }

    /// @notice Resume `send`/`claim`. Owner only — guardians can stop but not start.
    function unpause() external onlyOwner {
        if (paused) {
            paused = false;
            emit Unpaused(msg.sender);
        }
    }

    // ---------------------------------------------------------------------
    // Source side: lock + emit
    // ---------------------------------------------------------------------

    /// @notice Lock `amount` of `token` and emit a `Sent` event for validators.
    /// @param token      the ERC-20 to lock on this (source) chain
    /// @param amount     amount to bridge
    /// @param chainIdTo  destination chain id. Must be listed in {supportedChain}:
    ///                   a chain with no gate can neither claim nor cancel, so
    ///                   funds locked towards it would have no recovery path.
    /// @param receiver   destination recipient. Its width is fixed by the target VM:
    ///                   20 bytes for an EVM address, or 32 bytes for a non-EVM
    ///                   account key (e.g. a Solana pubkey / SPL associated token
    ///                   account). Any other length is rejected so funds can't lock
    ///                   here against a receiver the target gate can't decode. A
    ///                   32-byte receiver additionally caps `amount` at
    ///                   `type(uint64).max` — the widest amount the Solana gate
    ///                   can claim OR cancel, so anything larger would be locked
    ///                   with no way out.
    /// @param autoParams empty bytes for none, or abi.encode(AutoParamsTo) for an
    ///                   execution payload
    function send(
        address token,
        uint256 amount,
        uint256 chainIdTo,
        bytes calldata receiver,
        bytes calldata autoParams
    ) external whenNotPaused returns (bytes32 submissionId) {
        if (amount == 0) revert ZeroAmount();
        if (!supportedChain[chainIdTo]) revert UnsupportedChain(chainIdTo);
        // The receiver is only ever hashed and emitted here (never dereferenced on
        // this chain), but we still pin its width to the destination address size:
        // 20 = EVM address, 32 = Solana/non-EVM account key. A wrong length means a
        // malformed recipient, so reject rather than lock funds against garbage.
        if (receiver.length != 20 && receiver.length != 32) revert BadReceiver();
        // Non-EVM leg: the Solana program's ClaimArgs/CancelArgs carry `amount`
        // as a u64 and recompute the submissionId from it, so an amount that does
        // not fit can be neither delivered nor cancelled — and without a cancel
        // there is no refund. Refuse to lock it in the first place. Note that no
        // decimals normalisation exists anywhere in this bridge; for an 18-dec
        // token the cap is ~18.44 whole tokens, which is the point of the check.
        if (receiver.length == 32 && amount > type(uint64).max) revert AmountTooWide(amount);

        uint256 nonce = nonceTo[chainIdTo];
        bytes32 debridgeId = BridgeHash.getDebridgeId(block.chainid, token);
        bytes memory nativeSender = abi.encodePacked(msg.sender);

        submissionId = _idFor(
            debridgeId, amount, block.chainid, chainIdTo, nonce, receiver, autoParams, nativeSender
        );

        // Effects BEFORE the external transfer (checks-effects-interactions):
        // reserve the nonce and emit before calling into `token`. Otherwise a
        // token with a transfer hook could reenter send(), read the same nonce,
        // and emit a colliding `Sent` — desyncing the off-chain nonce sequence.
        nonceTo[chainIdTo] = nonce + 1;
        // Bind the refund recipient at lock time. The monotonic per-corridor
        // nonce makes submissionId unique, so this never overwrites a live entry.
        sentBy[submissionId] = msg.sender;
        emit Sent(
            submissionId,
            debridgeId,
            amount,
            block.chainid,
            chainIdTo,
            receiver,
            nonce,
            autoParams,
            nativeSender,
            token
        );

        // Exact-transfer policy: credit only tokens whose balance delta equals the
        // signed `amount`. A fee-on-transfer / rebasing token would deliver less
        // than `amount` while the emitted event (and thus the destination claim)
        // promises the full `amount` — draining shared liquidity by the shortfall.
        // Reject rather than silently over-credit. (A reentrant transfer hook can
        // only make `received` differ, which also reverts, rolling back the nonce
        // and the emitted Sent.)
        uint256 balBefore = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        uint256 received = IERC20(token).balanceOf(address(this)) - balBefore;
        if (received != amount) revert UnsupportedTokenBehavior(amount, received);
    }

    // ---------------------------------------------------------------------
    // Target side: verify + execute (replay-safe)
    // ---------------------------------------------------------------------

    /// @notice Verify a threshold of validator signatures and release funds once.
    /// @dev    `signatures` MUST be sorted by recovered signer address, strictly
    ///         ascending. This both de-duplicates signers and bounds gas.
    /// @param nativeSender the packed source-chain sender; required to recompute
    ///                     the id when `autoParams` is non-empty (else ignored)
    function claim(
        bytes32 debridgeId,
        uint256 amount,
        uint256 chainIdFrom,
        uint256 nonce,
        bytes calldata receiver,
        bytes calldata autoParams,
        bytes calldata nativeSender,
        bytes[] calldata signatures
    ) external whenNotPaused returns (bytes32 submissionId) {
        submissionId = _idFor(
            debridgeId, amount, chainIdFrom, block.chainid, nonce, receiver, autoParams, nativeSender
        );

        if (executed[submissionId]) revert AlreadyExecuted();

        _verifySignatures(submissionId, signatures);

        // effects before interactions
        executed[submissionId] = true;

        address localToken = tokenOf[debridgeId];
        if (localToken == address(0)) revert UnknownAsset(debridgeId);
        address to = _toAddress(receiver);

        IERC20(localToken).safeTransfer(to, amount);

        emit Claimed(submissionId, debridgeId, to, amount);
    }

    // ---------------------------------------------------------------------
    // Refund path: cancel on the destination, then refund on the source
    // ---------------------------------------------------------------------
    //
    // A transfer can strand: the destination gate may lack liquidity for the
    // asset, the corridor may be de-listed after the funds were locked, or the
    // target chain may be down long enough that nobody ever claims. The locked
    // funds must be returnable — but a refund that merely waits out a timeout is
    // a DOUBLE-SPEND: the transfer's validator signatures still exist, so a
    // keeper can `claim()` on the destination in the same window the source pays
    // the refund, and the same tokens are released twice.
    //
    // So the two legs are ordered, and the ordering is enforced on-chain rather
    // than by any timing assumption:
    //
    //   1. `cancel()` on the DESTINATION burns `executed[submissionId]`. From
    //      that moment `claim()` reverts with AlreadyExecuted — the destination
    //      can never pay out, permanently and verifiably.
    //   2. Validators observe the resulting `Cancelled` event (an ordinary
    //      on-chain fact, attested exactly like a `Sent` is) and only then sign
    //      the refund digest.
    //   3. `refund()` on the SOURCE returns the funds.
    //
    // If a keeper wins the race and claims first, step 1 simply reverts and no
    // refund is ever authorised. There is no interleaving that pays out twice.

    /// @notice DESTINATION side. Burn a transfer so it can never be claimed here,
    ///         unlocking a source-chain refund. Moves no funds.
    /// @dev    Requires a threshold of validator signatures over
    ///         `BridgeHash.getCancelId(submissionId)` — a distinct signing domain,
    ///         so the validators' original transfer signatures (which authorise
    ///         *paying* this submissionId) can never be replayed to burn it.
    ///
    ///         Unlike {refund}, this DOES stay behind the breaker. A cancel is
    ///         irreversible and forecloses the payout permanently, so during an
    ///         incident it is a state change worth freezing. The asymmetry is
    ///         deliberate: {refund} only returns funds already locked and already
    ///         burned on the far side, so it can create no new exposure.
    function cancel(
        bytes32 debridgeId,
        uint256 amount,
        uint256 chainIdFrom,
        uint256 nonce,
        bytes calldata receiver,
        bytes calldata autoParams,
        bytes calldata nativeSender,
        bytes[] calldata signatures
    ) external whenNotPaused returns (bytes32 submissionId) {
        submissionId = _idFor(
            debridgeId, amount, chainIdFrom, block.chainid, nonce, receiver, autoParams, nativeSender
        );

        // Already claimed (or already cancelled) — either way it is spent here,
        // and re-cancelling must not re-authorise a second refund.
        if (executed[submissionId]) revert AlreadyExecuted();

        _verifySignatures(BridgeHash.getCancelId(submissionId), signatures);

        executed[submissionId] = true;
        cancelled[submissionId] = true;

        emit Cancelled(submissionId, debridgeId, chainIdFrom, nonce);
    }

    /// @notice SOURCE side. Return locked funds to the original sender after the
    ///         destination has been cancelled.
    /// @dev    Three independent guards stand between a caller and the vault:
    ///           * `sentBy[submissionId]` must be set — proof THIS gate locked
    ///             these funds, and the authoritative recipient (the calldata's
    ///             `nativeSender` is not hash-bound for a plain transfer, so it is
    ///             never trusted for the payout address);
    ///           * a validator threshold over `BridgeHash.getRefundId(...)`, whose
    ///             quorum only forms after `Cancelled` is observed on the target;
    ///           * `token` must be exactly the asset `debridgeId` commits to.
    /// @param token the ERC-20 originally locked. `debridgeId` is a one-way hash
    ///        of it, so it is supplied by the caller and checked here rather than
    ///        stored — untrusted input, exactly verified.
    /// @dev    Deliberately NOT `whenNotPaused`. The breaker exists to stop new
    ///         exposure — `send` locking more funds, `claim` releasing them — but a
    ///         refund only returns already-locked funds to the address that locked
    ///         them, and only after validators have attested a destination burn.
    ///         It cannot create exposure. Halting it would trap exactly the users
    ///         an incident stranded, for as long as the incident lasted, which is
    ///         the opposite of what the breaker is for.
    function refund(
        address token,
        bytes32 debridgeId,
        uint256 amount,
        uint256 chainIdTo,
        uint256 nonce,
        bytes calldata receiver,
        bytes calldata autoParams,
        bytes calldata nativeSender,
        bytes[] calldata signatures
    ) external returns (bytes32 submissionId) {
        submissionId = _idFor(
            debridgeId, amount, block.chainid, chainIdTo, nonce, receiver, autoParams, nativeSender
        );

        if (refunded[submissionId]) revert AlreadyRefunded(submissionId);

        // Origin proof AND payout address, both from storage this gate wrote at
        // lock time. Zero means "we never sent this" (or it is already refunded).
        address sender = sentBy[submissionId];
        if (sender == address(0)) revert NotSent(submissionId);

        // debridgeId = keccak(thisChain, token): an exact binding, so a caller
        // cannot name a different (more valuable) asset held by this gate.
        if (BridgeHash.getDebridgeId(block.chainid, token) != debridgeId) {
            revert TokenMismatch(debridgeId, token);
        }

        _verifySignatures(BridgeHash.getRefundId(submissionId), signatures);

        // effects before interactions
        refunded[submissionId] = true;
        delete sentBy[submissionId];

        IERC20(token).safeTransfer(sender, amount);

        emit Refunded(submissionId, debridgeId, sender, amount);
    }

    /// @notice Recompute a submissionId without executing (hash-equivalence tests).
    function computeSubmissionId(
        bytes32 debridgeId,
        uint256 amount,
        uint256 chainIdFrom,
        uint256 chainIdTo,
        uint256 nonce,
        bytes calldata receiver,
        bytes calldata autoParams,
        bytes calldata nativeSender
    ) external view returns (bytes32) {
        return _idFor(
            debridgeId, amount, chainIdFrom, chainIdTo, nonce, receiver, autoParams, nativeSender
        );
    }

    // ---------------------------------------------------------------------
    // Internal
    // ---------------------------------------------------------------------

    function _idFor(
        bytes32 debridgeId,
        uint256 amount,
        uint256 chainIdFrom,
        uint256 chainIdTo,
        uint256 nonce,
        bytes memory receiver,
        bytes memory autoParams,
        bytes memory nativeSender
    ) internal view returns (bytes32) {
        // Pin the receiver width HERE, where the ambiguity it prevents actually
        // lives, not only in `send`.
        //
        // `packedSubmission` ends `…, receiver, nonce` with `receiver` a dynamic
        // field carrying no length prefix, and the auto-params variant appends a
        // further 160 fixed bytes. A no-auto preimage with a 180-byte receiver
        // therefore has the same length AND layout as an auto preimage with a
        // 20-byte one — the two forms are distinguishable only by a length
        // invariant. That invariant was enforced in `send` alone, while `claim`,
        // `cancel` and `refund` all hashed a caller-supplied `receiver` of any
        // length before their own width checks ran.
        //
        // Not exploitable as it stood (no signed id could have a long receiver,
        // because `send` refused to emit one), but the safety of the construction
        // rested on a restriction two functions away from the hash. One comparison
        // makes it local.
        if (receiver.length != 20 && receiver.length != 32) revert BadReceiver();

        // `view`, not `pure`, only because of `bridgeDomain` — every id this gate
        // computes is scoped to this deployment generation.
        if (autoParams.length == 0) {
            return BridgeHash.getSubmissionId(
                bridgeDomain, debridgeId, amount, chainIdFrom, chainIdTo, nonce, receiver
            );
        }
        AutoParamsTo memory ap = abi.decode(autoParams, (AutoParamsTo));
        return BridgeHash.getSubmissionIdWithAuto(
            bridgeDomain,
            debridgeId,
            amount,
            chainIdFrom,
            chainIdTo,
            nonce,
            receiver,
            BridgeHash.AutoParams({
                executionFee: ap.executionFee,
                flags: ap.flags,
                fallbackAddress: ap.fallbackAddress,
                data: ap.data,
                nativeSender: nativeSender
            })
        );
    }

    /// @dev Verify a validator threshold over the EIP-191 `eth_sign` digest of a
    ///      raw 32-byte message.
    /// @param message one of three domain-separated values — a `submissionId`
    ///        (authorises paying a transfer out), a `cancelId` (authorises
    ///        burning it on the destination), or a `refundId` (authorises
    ///        returning it on the source). `BridgeHash` derives the latter two
    ///        under distinct prefixes, so a quorum for one is never a quorum for
    ///        another.
    function _verifySignatures(bytes32 message, bytes[] calldata signatures)
        internal
        view
    {
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(message);

        // A useful quorum needs at most `validatorCount` distinct signers (the
        // ascending-order rule already forbids duplicates, and non-validators are
        // ignored below). Cap the array there so a caller can't pad it with junk
        // to inflate ECDSA-recovery gas / RPC estimation load.
        if (signatures.length > validatorCount) {
            revert TooManySignatures(signatures.length, validatorCount);
        }

        address last = address(0);
        uint256 count = 0;
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = ECDSA.recover(digest, signatures[i]);
            // strictly ascending => distinct signers, no duplicates
            if (signer <= last) revert InvalidSignerOrder();
            if (isValidator[signer]) {
                count++;
            }
            last = signer;
        }
        if (count < threshold) revert NotEnoughSignatures(count, threshold);
    }

    /// @dev Decode `receiver` as an EVM address. EXACTLY 20 bytes — see below.
    ///
    ///      `send` accepts a 20- or 32-byte receiver because it cannot know the
    ///      destination VM: 20 for an EVM address, 32 for a Solana account key.
    ///      But on THIS chain a receiver is an address, so 20 is the only width
    ///      that can be correct here, and anything else is malformed.
    ///
    ///      This used to accept `>= 20` and take the first 20 bytes, which turned
    ///      a user's format mistake into permanent loss. Two ways in, both silent:
    ///
    ///        * a Solana pubkey pasted for an EVM destination — the leading 20
    ///          bytes are effectively random, so `claim` pays an address nobody
    ///          holds a key for;
    ///        * `abi.encode(address)`, which is 32 bytes with the address in the
    ///          LAST 20 — the leading 20 are zero, so `claim` pays `address(0)`.
    ///
    ///      Neither was recoverable: the refund path only rescues transfers that
    ///      CANNOT be claimed, and both of these claim perfectly well.
    ///
    ///      Rejecting instead makes such a transfer unclaimable, which routes it
    ///      into the existing cancel -> refund path and returns the funds to the
    ///      sender. It also mirrors the Solana gate, which already requires
    ///      exactly 32 bytes (`process_claim`'s `try_into::<[u8; 32]>`), so each
    ///      VM now accepts exactly its own address width and nothing else.
    function _toAddress(bytes calldata receiver) internal pure returns (address addr) {
        if (receiver.length != 20) revert BadReceiver();
        addr = address(bytes20(receiver[0:20]));
    }
}
