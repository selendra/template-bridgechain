// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {Gate} from "../src/Gate.sol";
import {deployTestGate} from "./helpers/TestGate.sol";
import {TestToken} from "../src/TestToken.sol";
import {BridgeHash} from "../src/BridgeHash.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @dev A trivial next version, only so an upgrade has somewhere to go.
contract GateV2b is Gate {
    function version() external pure returns (string memory) {
        return "v2";
    }
}

/// @notice Audit round 4 (2026-09-09) — the corridor registry and the schedule
///         lifetime.
///
///         H-1  `setLocalToken` on a fresh debridgeId was instant, so the 48 h
///              governance timelock did not stop an owner drain. Now: instant
///              during the setup phase, delayed once the gate is {seal}ed.
///         M-3  `send` accepted any `chainIdTo`; funds sent to a chain with no
///              gate were locked with no recovery. Now: {supportedChain}.
///         LOW  A matured schedule was a banked instant right for life. Now it
///              expires {SCHEDULE_GRACE} after maturing.
contract CorridorGovernanceTest is Test {
    Gate gate;
    TestToken usdc;

    uint256 v1pk = 0xA11CE;
    address v1;
    address guardian = address(0x6A2D);
    address attacker = address(0xBAD);
    address user = address(0xBEEF);

    uint256 constant CHAIN_A = 1337; // the "source" of the drain corridor
    uint256 constant CHAIN_TO = 1338;
    bytes32 debridgeId; // a corridor from chain A into this gate
    address fakeSourceAsset = address(0xF4CE);

    function setUp() public {
        v1 = vm.addr(v1pk);
        address[] memory validators = new address[](1);
        validators[0] = v1;
        gate = deployTestGate(validators, 1);
        gate.setGuardian(guardian);
        gate.setSupportedChain(CHAIN_TO, true);

        usdc = new TestToken("USD Coin", "USDC");
        debridgeId = BridgeHash.getDebridgeId(CHAIN_A, fakeSourceAsset);
    }

    function _sign(uint256 pk, bytes32 message) internal pure returns (bytes[] memory sigs) {
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(pk, MessageHashUtils.toEthSignedMessageHash(message));
        sigs = new bytes[](1);
        sigs[0] = abi.encodePacked(r, s, v);
    }

    // -----------------------------------------------------------------
    // H-1: setup phase, then seal
    // -----------------------------------------------------------------

    function test_SetLocalToken_IsInstantWhileUnsealed() public {
        assertFalse(gate.isSealed(), "a fresh gate starts in its setup phase");
        gate.setLocalToken(debridgeId, address(usdc));
        assertEq(gate.tokenOf(debridgeId), address(usdc));
    }

    function test_Seal_EmitsAndIsOnlyOwner() public {
        vm.prank(attacker);
        vm.expectRevert(Gate.NotOwner.selector);
        gate.seal();

        vm.expectEmit(true, true, true, true);
        emit Gate.Sealed();
        gate.seal();
        assertTrue(gate.isSealed());
    }

    function test_Seal_IsIrreversible() public {
        gate.seal();
        vm.expectRevert(Gate.AlreadySealed.selector);
        gate.seal();
        assertTrue(gate.isSealed(), "there is no un-seal, by design");
    }

    function test_SetLocalToken_AfterSeal_RevertsWithoutASchedule() public {
        gate.seal();
        bytes32 action = gate.setLocalTokenActionId(debridgeId, address(usdc));
        vm.expectRevert(abi.encodeWithSelector(Gate.GovernanceNotScheduled.selector, action));
        gate.setLocalToken(debridgeId, address(usdc));
        assertEq(gate.tokenOf(debridgeId), address(0), "registry untouched");
    }

    function test_SetLocalToken_AfterSeal_SucceedsOnceTheDelayElapsed() public {
        gate.seal();
        bytes32 action = gate.setLocalTokenActionId(debridgeId, address(usdc));

        gate.scheduleGovernance(action);
        uint256 readyAt = gate.governanceReadyAt(action);
        assertEq(readyAt, block.timestamp + gate.GOVERNANCE_DELAY());

        vm.warp(readyAt - 1);
        vm.expectRevert(abi.encodeWithSelector(Gate.GovernanceNotReady.selector, action, readyAt));
        gate.setLocalToken(debridgeId, address(usdc));

        vm.warp(readyAt);
        gate.setLocalToken(debridgeId, address(usdc));
        assertEq(gate.tokenOf(debridgeId), address(usdc));
        assertEq(gate.governanceReadyAt(action), 0, "one approval, one registration");
    }

    /// The schedule commits to BOTH halves: an approval to map X -> USDC cannot be
    /// spent mapping X -> some other token, nor Y -> USDC.
    function test_SetLocalToken_ScheduleIsBoundToBothDebridgeIdAndToken() public {
        gate.seal();
        TestToken other = new TestToken("Other", "OTH");
        gate.scheduleGovernance(gate.setLocalTokenActionId(debridgeId, address(usdc)));
        vm.warp(block.timestamp + gate.GOVERNANCE_DELAY());

        vm.expectRevert(
            abi.encodeWithSelector(
                Gate.GovernanceNotScheduled.selector,
                gate.setLocalTokenActionId(debridgeId, address(other))
            )
        );
        gate.setLocalToken(debridgeId, address(other));

        bytes32 otherId = keccak256("other-corridor");
        vm.expectRevert(
            abi.encodeWithSelector(
                Gate.GovernanceNotScheduled.selector,
                gate.setLocalTokenActionId(otherId, address(usdc))
            )
        );
        gate.setLocalToken(otherId, address(usdc));

        gate.setLocalToken(debridgeId, address(usdc)); // the one it did authorise
        assertEq(gate.tokenOf(debridgeId), address(usdc));
    }

    function test_SetLocalToken_GuardianCanCancelAScheduledRegistration() public {
        gate.seal();
        bytes32 action = gate.setLocalTokenActionId(debridgeId, address(usdc));
        gate.scheduleGovernance(action);

        vm.prank(guardian);
        gate.cancelScheduledGovernance(action);
        assertEq(gate.governanceReadyAt(action), 0);

        vm.warp(block.timestamp + gate.GOVERNANCE_DELAY());
        vm.expectRevert(abi.encodeWithSelector(Gate.GovernanceNotScheduled.selector, action));
        gate.setLocalToken(debridgeId, address(usdc));
        assertEq(gate.tokenOf(debridgeId), address(0), "the corridor never opened");
    }

    /// Sealing does not touch the write-once rule: an existing corridor still
    /// cannot be repointed even with a matured schedule for the new mapping.
    function test_SetLocalToken_AfterSeal_StillWriteOnce() public {
        gate.setLocalToken(debridgeId, address(usdc));
        gate.seal();
        TestToken other = new TestToken("Other", "OTH");
        gate.scheduleGovernance(gate.setLocalTokenActionId(debridgeId, address(other)));
        vm.warp(block.timestamp + gate.GOVERNANCE_DELAY());

        vm.expectRevert(
            abi.encodeWithSelector(Gate.LocalTokenAlreadySet.selector, debridgeId, address(usdc))
        );
        gate.setLocalToken(debridgeId, address(other));
    }

    /// THE H-1 DRAIN, end to end. The owner "sends" a worthless asset from chain A
    /// (modelled here as a validator honestly attesting the resulting id — the
    /// validators' allowlist is opt-in and empty by default), then tries to map
    /// that debridgeId onto this gate's USDC and claim. Before the fix this was one
    /// block; now the registration cannot happen without the public delay, so the
    /// claim has nothing to pay from.
    function test_Drain_OwnerCannotRegisterAFakeCorridorAndClaimInOneBlock() public {
        // Operator finishes wiring, seals, THEN provisions liquidity.
        gate.seal();
        usdc.mint(address(gate), 1_000_000e18);

        // The honestly-attested id of a 1,000,000-unit transfer of the fake asset.
        uint256 amount = 1_000_000e18;
        bytes memory receiver = abi.encodePacked(attacker);
        bytes32 id = gate.computeSubmissionId(debridgeId, amount, CHAIN_A, block.chainid, 0, receiver, "", "");
        bytes[] memory sigs = _sign(v1pk, id);

        // Step 1 of the drain: point the fake corridor at USDC. Refused.
        vm.expectRevert(
            abi.encodeWithSelector(
                Gate.GovernanceNotScheduled.selector,
                gate.setLocalTokenActionId(debridgeId, address(usdc))
            )
        );
        gate.setLocalToken(debridgeId, address(usdc));

        // Step 2 therefore has no asset to release.
        vm.expectRevert(abi.encodeWithSelector(Gate.UnknownAsset.selector, debridgeId));
        gate.claim(debridgeId, amount, CHAIN_A, 0, receiver, "", "", sigs);

        assertEq(usdc.balanceOf(attacker), 0, "not a single unit left the pot");
        assertEq(usdc.balanceOf(address(gate)), 1_000_000e18, "liquidity intact");

        // Even the honest route takes the full public delay first — the window
        // in which observers verify the source asset and the guardian cancels.
        bytes32 action = gate.setLocalTokenActionId(debridgeId, address(usdc));
        gate.scheduleGovernance(action);
        vm.expectRevert(
            abi.encodeWithSelector(
                Gate.GovernanceNotReady.selector, action, gate.governanceReadyAt(action)
            )
        );
        gate.setLocalToken(debridgeId, address(usdc));
    }

    /// The control for the drain test: WITHOUT the seal the same sequence still
    /// works in one block. That is what the setup phase is, and why {seal} must
    /// run before a gate is funded.
    function test_Drain_ControlAnUnsealedGateIsDrainableInOneBlock() public {
        usdc.mint(address(gate), 1_000_000e18);
        uint256 amount = 1_000_000e18;
        bytes memory receiver = abi.encodePacked(attacker);
        bytes32 id = gate.computeSubmissionId(debridgeId, amount, CHAIN_A, block.chainid, 0, receiver, "", "");

        gate.setLocalToken(debridgeId, address(usdc));
        gate.claim(debridgeId, amount, CHAIN_A, 0, receiver, "", "", _sign(v1pk, id));
        assertEq(usdc.balanceOf(attacker), amount, "control: unsealed == the H-1 hole");
    }

    // -----------------------------------------------------------------
    // M-3: destination registry
    // -----------------------------------------------------------------

    function test_Send_RevertsForAnUnsupportedChain() public {
        usdc.mint(user, 10 ether);
        vm.startPrank(user);
        usdc.approve(address(gate), type(uint256).max);

        uint256 noGateHere = 4242;
        assertFalse(gate.supportedChain(noGateHere));
        vm.expectRevert(abi.encodeWithSelector(Gate.UnsupportedChain.selector, noGateHere));
        gate.send(address(usdc), 1 ether, noGateHere, abi.encodePacked(address(0xCAFE)), "");
        vm.stopPrank();

        assertEq(usdc.balanceOf(address(gate)), 0, "nothing locked");
        assertEq(gate.nonceTo(noGateHere), 0, "nonce untouched");
    }

    function test_SetSupportedChain_OpensAndClosesADestination() public {
        usdc.mint(user, 10 ether);
        vm.prank(user);
        usdc.approve(address(gate), type(uint256).max);
        bytes memory receiver = abi.encodePacked(address(0xCAFE));

        uint256 chain = 4242;
        vm.expectEmit(true, true, true, true);
        emit Gate.SupportedChainSet(chain, true);
        gate.setSupportedChain(chain, true);
        assertTrue(gate.supportedChain(chain));

        vm.prank(user);
        gate.send(address(usdc), 1 ether, chain, receiver, "");
        assertEq(gate.nonceTo(chain), 1);

        // De-listing is instant and stops NEW locks only.
        gate.setSupportedChain(chain, false);
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Gate.UnsupportedChain.selector, chain));
        gate.send(address(usdc), 1 ether, chain, receiver, "");
    }

    function test_SetSupportedChain_OnlyOwner() public {
        vm.prank(attacker);
        vm.expectRevert(Gate.NotOwner.selector);
        gate.setSupportedChain(4242, true);
    }

    /// The registry is a plain restriction, so it is enforced regardless of the
    /// setup phase — an unsealed gate must not be a way around it.
    function test_Send_UnsupportedChainIsEnforcedEvenWhileUnsealed() public {
        assertFalse(gate.isSealed());
        usdc.mint(user, 10 ether);
        vm.startPrank(user);
        usdc.approve(address(gate), type(uint256).max);
        vm.expectRevert(abi.encodeWithSelector(Gate.UnsupportedChain.selector, 4242));
        gate.send(address(usdc), 1 ether, 4242, abi.encodePacked(address(0xCAFE)), "");
        vm.stopPrank();
    }

    /// De-listing must not strand in-flight transfers: refund never consults the
    /// registry, so a transfer locked towards a chain that is later closed can
    /// still come back.
    function test_Refund_IgnoresTheDestinationRegistry() public {
        usdc.mint(user, 10 ether);
        vm.startPrank(user);
        usdc.approve(address(gate), type(uint256).max);
        bytes memory receiver = abi.encodePacked(address(0xCAFE));
        bytes32 id = gate.send(address(usdc), 1 ether, CHAIN_TO, receiver, "");
        vm.stopPrank();

        gate.setSupportedChain(CHAIN_TO, false);
        bytes32 did = BridgeHash.getDebridgeId(block.chainid, address(usdc));
        gate.refund(
            address(usdc), did, 1 ether, CHAIN_TO, 0, receiver, "", "",
            _sign(v1pk, BridgeHash.getRefundId(id))
        );
        assertEq(usdc.balanceOf(user), 10 ether, "refund still works after de-listing");
    }

    // -----------------------------------------------------------------
    // LOW: matured schedules expire
    // -----------------------------------------------------------------

    function test_Governance_ScheduleExpiresAfterTheGrace() public {
        address newV = vm.addr(0xB0B);
        bytes32 action = gate.addValidatorActionId(newV);
        gate.scheduleGovernance(action);
        uint256 readyAt = gate.governanceReadyAt(action);

        // Void one second past the grace window. The PoC in the audit executed
        // an add three years after scheduling; that is now impossible.
        vm.warp(readyAt + gate.SCHEDULE_GRACE() + 1);
        vm.expectRevert(abi.encodeWithSelector(Gate.ScheduleExpired.selector, action, readyAt));
        gate.setValidator(newV, true);
        assertFalse(gate.isValidator(newV));

        vm.warp(readyAt + 3 * 365 days);
        vm.expectRevert(abi.encodeWithSelector(Gate.ScheduleExpired.selector, action, readyAt));
        gate.setValidator(newV, true);

        // Re-scheduling restarts the delay in public view, as intended.
        gate.scheduleGovernance(action);
        assertEq(gate.governanceReadyAt(action), block.timestamp + gate.GOVERNANCE_DELAY());
    }

    /// The boundary itself is inclusive: the last second of the grace window
    /// still executes, so a change planned for "a week after maturity" works.
    function test_Governance_ScheduleIsStillGoodOnTheLastSecondOfTheGrace() public {
        address newV = vm.addr(0xB0B);
        bytes32 action = gate.addValidatorActionId(newV);
        gate.scheduleGovernance(action);
        vm.warp(gate.governanceReadyAt(action) + gate.SCHEDULE_GRACE());
        gate.setValidator(newV, true);
        assertTrue(gate.isValidator(newV));
    }

    function test_Governance_ExpiryAppliesToCorridorRegistrationsToo() public {
        gate.seal();
        bytes32 action = gate.setLocalTokenActionId(debridgeId, address(usdc));
        gate.scheduleGovernance(action);
        uint256 readyAt = gate.governanceReadyAt(action);

        vm.warp(readyAt + gate.SCHEDULE_GRACE() + 1);
        vm.expectRevert(abi.encodeWithSelector(Gate.ScheduleExpired.selector, action, readyAt));
        gate.setLocalToken(debridgeId, address(usdc));
        assertEq(gate.tokenOf(debridgeId), address(0));
    }

    function test_Upgrade_ScheduleExpiresAfterTheGrace() public {
        address v2 = address(new GateV2b());
        gate.scheduleUpgrade(v2);
        uint256 readyAt = gate.upgradeReadyAt(v2);

        vm.warp(readyAt + gate.SCHEDULE_GRACE() + 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                Gate.ScheduleExpired.selector, bytes32(uint256(uint160(v2))), readyAt
            )
        );
        gate.upgradeToAndCall(v2, "");

        // Inside the window it installs normally.
        gate.scheduleUpgrade(v2);
        vm.warp(gate.upgradeReadyAt(v2) + gate.SCHEDULE_GRACE());
        gate.upgradeToAndCall(v2, "");
        assertEq(GateV2b(address(gate)).version(), "v2");
    }
}
