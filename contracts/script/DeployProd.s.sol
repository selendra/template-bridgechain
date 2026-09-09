// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {Gate} from "../src/Gate.sol";
import {GateDeployer} from "../src/GateDeployer.sol";

/// @notice Production Gate deployment with enforced safety parameters.
///
/// Unlike the demo scripts (which deploy single-validator, threshold-1 gates and
/// unrestricted-mint test tokens for local bring-up), this script:
///   * guards the target chain id (a fat-fingered RPC can't deploy to the wrong
///     network);
///   * requires a real multi-validator set and a STRICT-MAJORITY threshold
///     (never threshold-1, which a single compromised signer could abuse);
///   * appoints a guardian (low-trust pause button, separable from the owner);
///   * hands ownership to a multisig via the two-step transfer (the multisig must
///     call acceptOwnership to finish);
///   * deploys NO mintable tokens — real assets are registered later, per asset,
///     by governance via setLocalToken;
///   * asserts every post-deploy invariant and reverts the whole deployment if
///     any is off.
///
/// POST-DEPLOY WIRING (done by the owner, NOT by this script, since it registers
/// no corridors). The gate leaves here UNSEALED, i.e. in its setup phase, and
/// the operator must — in this order, before provisioning any liquidity:
///   1. `setSupportedChain(chainId, true)` for every peer chain `send` may
///      target (M-3: an unlisted destination is refused, nothing is locked);
///   2. `setLocalToken(debridgeId, localToken)` for every inbound corridor
///      (instant while unsealed);
///   3. `seal()` — irreversible. From then on every NEW corridor needs
///      `scheduleGovernance(setLocalTokenActionId(...))` plus GOVERNANCE_DELAY,
///      which is what stops an owner key from draining the gate through a fake
///      corridor (H-1). An unsealed gate that holds funds is that drain waiting.
///
/// The deployment logic lives in `_deploy(Params)` so it can be unit-tested
/// (see test/DeployProd.t.sol) without env plumbing or a live RPC.
///
/// Env in (for `forge script`):
///   EXPECTED_CHAIN_ID (uint)  — the chain this MUST run on
///   VALIDATORS (address[],",") — comma-separated validator addresses (>= 3)
///   THRESHOLD (uint)          — strict-majority signature threshold (>= 2)
///   GUARDIAN (address)        — the pause guardian (nonzero, != owner)
///   OWNER (address)           — the multisig to receive ownership (nonzero)
contract DeployProd is Script {
    struct Params {
        uint256 expectedChainId;
        address[] validators;
        uint256 threshold;
        address guardian;
        address owner;
        /// @dev The mesh-wide deployment domain. EVERY gate in this generation —
        ///      every EVM chain and the Solana program — must be given the same
        ///      value, and a NEW generation must be given a new one, or the old
        ///      generation's validator attestations replay against these gates.
        bytes32 bridgeDomain;
    }

    error WrongChain(uint256 got, uint256 want);
    error TooFewValidators(uint256 count);
    error WeakThreshold(uint256 threshold, uint256 validatorCount);
    error ZeroConfigAddress();
    error GuardianEqualsOwner();
    /// @dev the same validator address appears twice in VALIDATORS. The Gate
    ///      constructor silently dedupes, so a duplicate would quietly shrink the
    ///      real validator set below the intended size while every check here
    ///      still passed against the (longer) supplied array.
    error DuplicateValidator(address validator);
    error ZeroValidatorAddress();
    /// @dev BRIDGE_DOMAIN was unset. Refused rather than defaulted: a default
    ///      shared by every deployment is the same as having no domain at all.
    error ZeroBridgeDomain();

    function run() external {
        Params memory p = Params({
            expectedChainId: vm.envUint("EXPECTED_CHAIN_ID"),
            validators: vm.envAddress("VALIDATORS", ","),
            threshold: vm.envUint("THRESHOLD"),
            guardian: vm.envAddress("GUARDIAN"),
            owner: vm.envAddress("OWNER"),
            bridgeDomain: vm.envBytes32("BRIDGE_DOMAIN")
        });

        vm.startBroadcast();
        Gate gate = _deploy(p);
        vm.stopBroadcast();

        console2.log("Gate deployed:", address(gate));
        console2.log("  validatorCount:", gate.validatorCount());
        console2.log("  threshold:", gate.threshold());
        console2.log("  guardian:", gate.guardian());
        console2.log("  pendingOwner (accept from multisig):", gate.pendingOwner());
        console2.log("  isSealed (seal() after wiring corridors, before funding):", gate.isSealed());
    }

    /// @dev Deploy + configure + assert. Public so tests can exercise it; the
    ///      caller (broadcaster or test) becomes the transient owner that appoints
    ///      the guardian and starts the ownership handover.
    function _deploy(Params memory p) public returns (Gate gate) {
        // --- production policy pre-flight (revert before spending gas on deploy) ---
        if (block.chainid != p.expectedChainId) revert WrongChain(block.chainid, p.expectedChainId);
        if (p.validators.length < 3) revert TooFewValidators(p.validators.length);
        if (p.guardian == address(0) || p.owner == address(0)) revert ZeroConfigAddress();
        if (p.guardian == p.owner) revert GuardianEqualsOwner();
        // The majority rule below counts the SUPPLIED array, but Gate's constructor
        // dedupes as it registers. Without this check `[A, B, B]` with threshold 2
        // passes every rule here and every post-deploy assertion, yet ships a 2-of-2
        // gate instead of the intended 2-of-3 — a quorum one key short of what the
        // operator signed off on. Reject duplicates so length == validatorCount.
        for (uint256 i = 0; i < p.validators.length; i++) {
            if (p.validators[i] == address(0)) revert ZeroValidatorAddress();
            for (uint256 j = i + 1; j < p.validators.length; j++) {
                if (p.validators[i] == p.validators[j]) revert DuplicateValidator(p.validators[j]);
            }
        }
        // Strict majority: threshold > validators/2 AND at least 2. This forbids
        // the demo threshold-1 and any sub-majority quorum. (Gate's own constructor
        // only rejects 0 and > count.)
        if (p.threshold < 2 || p.threshold * 2 <= p.validators.length || p.threshold > p.validators.length) {
            revert WeakThreshold(p.threshold, p.validators.length);
        }

        if (p.bridgeDomain == bytes32(0)) revert ZeroBridgeDomain();

        gate = GateDeployer.deploy(p.validators, p.threshold, p.bridgeDomain);
        gate.setGuardian(p.guardian);
        gate.transferOwnership(p.owner); // two-step: p.owner must acceptOwnership()

        // --- post-deploy assertions (revert the deployment if any fails) ---
        require(gate.threshold() == p.threshold, "post: threshold mismatch");
        require(gate.bridgeDomain() == p.bridgeDomain, "post: bridgeDomain mismatch");
        require(gate.guardian() == p.guardian, "post: guardian mismatch");
        require(gate.pendingOwner() == p.owner, "post: pendingOwner mismatch");
        require(gate.validatorCount() >= p.threshold, "post: validatorCount < threshold");
        // The deduplication check above makes these equal; assert it rather than
        // assume it, so a future change to Gate's constructor cannot silently
        // reintroduce a smaller-than-intended validator set.
        require(gate.validatorCount() == p.validators.length, "post: validatorCount != supplied");
        require(gate.threshold() * 2 > gate.validatorCount(), "post: threshold not a strict majority");
        for (uint256 i = 0; i < p.validators.length; i++) {
            require(gate.isValidator(p.validators[i]), "post: validator not registered");
        }
    }
}
