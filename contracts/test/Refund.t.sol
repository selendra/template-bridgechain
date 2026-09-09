// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {Gate} from "../src/Gate.sol";
import {deployTestGate, TEST_BRIDGE_DOMAIN} from "./helpers/TestGate.sol";
import {TestToken} from "../src/TestToken.sol";
import {BridgeHash} from "../src/BridgeHash.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @notice Security suite for the two-phase refund path.
///
///         The property under test is that locked funds are recoverable WITHOUT
///         ever being payable twice. That rests on an ordering enforced on-chain
///         rather than by any timeout: the destination is burned by `cancel`
///         first, which makes `claim` permanently impossible, and only then can
///         the source `refund`.
///
///         Both chains are modelled in one test by moving `block.chainid` with
///         `vm.chainId` — the source gate lives on 1337, the destination on 1338,
///         and each derives the same submissionId from its own side.
contract RefundTest is Test {
    Gate srcGate; // chain 1337 — holds the locked funds
    Gate dstGate; // chain 1338 — where the transfer would have been claimed
    TestToken token;

    uint256 v1pk = 0xA11CE;
    uint256 v2pk = 0xB0B;
    uint256 v3pk = 0xC0FFEE;
    uint256 strangerPk = 0xBADBAD;

    address v1;
    address v2;
    address v3;

    address user = address(0x5E4DE2);
    address attacker = address(0xBADA55);
    address receiverAddr = address(0xCAFE);

    uint256 constant CHAIN_SRC = 1337;
    uint256 constant CHAIN_DST = 1338;
    uint256 constant AMOUNT = 100 ether;
    uint256 constant NONCE = 0;

    bytes receiver;
    bytes EMPTY_AUTO = "";
    bytes EMPTY_SENDER = "";

    bytes32 debridgeId;
    bytes32 submissionId;

    function setUp() public {
        v1 = vm.addr(v1pk);
        v2 = vm.addr(v2pk);
        v3 = vm.addr(v3pk);
        receiver = abi.encodePacked(receiverAddr);

        address[] memory validators = new address[](3);
        validators[0] = v1;
        validators[1] = v2;
        validators[2] = v3;

        // --- source chain ---
        vm.chainId(CHAIN_SRC);
        srcGate = deployTestGate(validators, 1);
        srcGate.setSupportedChain(CHAIN_DST, true);
        token = new TestToken("Test", "TST");
        token.mint(user, 1_000 ether);

        // The user locks funds bound for a chain that will never deliver.
        vm.startPrank(user);
        token.approve(address(srcGate), AMOUNT);
        submissionId = srcGate.send(address(token), AMOUNT, CHAIN_DST, receiver, EMPTY_AUTO);
        vm.stopPrank();

        debridgeId = BridgeHash.getDebridgeId(CHAIN_SRC, address(token));

        // --- destination chain ---
        vm.chainId(CHAIN_DST);
        dstGate = deployTestGate(validators, 1);
        // give the destination real liquidity, so a successful claim is possible
        // and "no double spend" is a meaningful claim rather than a side effect
        // of an empty vault
        TestToken dstToken = new TestToken("Test", "TST");
        dstToken.mint(address(dstGate), 1_000 ether);
        dstGate.setLocalToken(debridgeId, address(dstToken));

        vm.chainId(CHAIN_SRC);
    }

    // --- helpers ---

    function _sign(uint256 pk, bytes32 message) internal pure returns (bytes memory) {
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _one(uint256 pk, bytes32 message) internal pure returns (bytes[] memory sigs) {
        sigs = new bytes[](1);
        sigs[0] = _sign(pk, message);
    }

    /// @dev two signatures ordered by recovered signer ascending, as the Gate requires
    function _sortedTwo(uint256 pkA, uint256 pkB, bytes32 message)
        internal
        returns (bytes[] memory sigs)
    {
        sigs = new bytes[](2);
        if (vm.addr(pkA) < vm.addr(pkB)) {
            sigs[0] = _sign(pkA, message);
            sigs[1] = _sign(pkB, message);
        } else {
            sigs[0] = _sign(pkB, message);
            sigs[1] = _sign(pkA, message);
        }
    }

    function _cancelId() internal view returns (bytes32) {
        return BridgeHash.getCancelId(submissionId);
    }

    function _refundId() internal view returns (bytes32) {
        return BridgeHash.getRefundId(submissionId);
    }

    /// @dev run `cancel` on the destination gate with the given signatures
    function _cancel(bytes[] memory sigs) internal returns (bytes32 id) {
        vm.chainId(CHAIN_DST);
        id = dstGate.cancel(
            debridgeId, AMOUNT, CHAIN_SRC, NONCE, receiver, EMPTY_AUTO, EMPTY_SENDER, sigs
        );
        vm.chainId(CHAIN_SRC);
    }

    /// @dev run `claim` on the destination gate
    function _claim(bytes[] memory sigs) internal returns (bytes32 id) {
        vm.chainId(CHAIN_DST);
        id = dstGate.claim(
            debridgeId, AMOUNT, CHAIN_SRC, NONCE, receiver, EMPTY_AUTO, EMPTY_SENDER, sigs
        );
        vm.chainId(CHAIN_SRC);
    }

    function _refund(bytes[] memory sigs) internal returns (bytes32) {
        return srcGate.refund(
            address(token), debridgeId, AMOUNT, CHAIN_DST, NONCE, receiver, EMPTY_AUTO, EMPTY_SENDER, sigs
        );
    }

    /// @dev the full, correctly-ordered refund: burn the destination, then pay out
    function _cancelThenRefund() internal {
        _cancel(_one(v1pk, _cancelId()));
        _refund(_one(v1pk, _refundId()));
    }

    // -----------------------------------------------------------------
    // The headline property: funds come back, and only once
    // -----------------------------------------------------------------

    function test_Refund_HappyPath_ReturnsFundsToSender() public {
        assertEq(token.balanceOf(user), 900 ether, "send did not lock");
        assertEq(srcGate.sentBy(submissionId), user, "sender not recorded at lock time");

        _cancelThenRefund();

        assertEq(token.balanceOf(user), 1_000 ether, "sender not made whole");
        assertEq(token.balanceOf(address(srcGate)), 0, "gate still holds the funds");
        assertTrue(srcGate.refunded(submissionId), "refunded flag not set");
        assertEq(srcGate.sentBy(submissionId), address(0), "sentBy not cleared");
    }

    function test_ClaimAfterCancel_Reverts() public {
        // THE double-spend guard. Once the destination is burned, the transfer's
        // original validator signatures are worthless there — forever.
        _cancel(_one(v1pk, _cancelId()));

        vm.chainId(CHAIN_DST);
        vm.expectRevert(Gate.AlreadyExecuted.selector);
        dstGate.claim(
            debridgeId, AMOUNT, CHAIN_SRC, NONCE, receiver, EMPTY_AUTO, EMPTY_SENDER,
            _one(v1pk, submissionId)
        );
        vm.chainId(CHAIN_SRC);
    }

    function test_CancelAfterClaim_Reverts() public {
        // The mirror case: if a keeper delivers first, the refund can never be
        // authorised, because `cancel` is the only thing that unlocks it.
        _claim(_one(v1pk, submissionId));

        vm.chainId(CHAIN_DST);
        vm.expectRevert(Gate.AlreadyExecuted.selector);
        dstGate.cancel(
            debridgeId, AMOUNT, CHAIN_SRC, NONCE, receiver, EMPTY_AUTO, EMPTY_SENDER,
            _one(v1pk, _cancelId())
        );
        vm.chainId(CHAIN_SRC);
    }

    function test_Cancel_MovesNoFunds() public {
        TestToken dstToken = TestToken(dstGate.tokenOf(debridgeId));
        uint256 gateBefore = dstToken.balanceOf(address(dstGate));

        bytes32 id = _cancel(_one(v1pk, _cancelId()));

        assertEq(dstToken.balanceOf(receiverAddr), 0, "cancel paid the receiver");
        assertEq(dstToken.balanceOf(address(dstGate)), gateBefore, "cancel moved gate liquidity");
        assertTrue(dstGate.executed(id), "executed not set");
        assertTrue(dstGate.cancelled(id), "cancelled not set");
    }

    // -----------------------------------------------------------------
    // Refund authorisation
    // -----------------------------------------------------------------

    function test_Refund_WithoutPriorSend_Reverts() public {
        // A validator quorum alone must not be able to drain the gate: the funds
        // must demonstrably have been locked HERE.
        uint256 ghostNonce = 99;
        bytes32 ghostId = BridgeHash.getSubmissionId(
            TEST_BRIDGE_DOMAIN, debridgeId, AMOUNT, CHAIN_SRC, CHAIN_DST, ghostNonce, receiver
        );

        vm.expectRevert(abi.encodeWithSelector(Gate.NotSent.selector, ghostId));
        srcGate.refund(
            address(token), debridgeId, AMOUNT, CHAIN_DST, ghostNonce, receiver, EMPTY_AUTO,
            EMPTY_SENDER, _one(v1pk, BridgeHash.getRefundId(ghostId))
        );
    }

    function test_Refund_Replay_Reverts() public {
        _cancelThenRefund();

        vm.expectRevert(abi.encodeWithSelector(Gate.AlreadyRefunded.selector, submissionId));
        _refund(_one(v1pk, _refundId()));
    }

    function test_Refund_PaysRecordedSender_NotCalldata() public {
        // For a plain transfer `nativeSender` is NOT folded into the submissionId,
        // so calldata can name anyone. The payout address comes from storage the
        // gate wrote at lock time, so an attacker naming themselves changes
        // nothing.
        _cancel(_one(v1pk, _cancelId()));

        vm.prank(attacker);
        srcGate.refund(
            address(token), debridgeId, AMOUNT, CHAIN_DST, NONCE, receiver, EMPTY_AUTO,
            abi.encodePacked(attacker), _one(v1pk, _refundId())
        );

        assertEq(token.balanceOf(attacker), 0, "attacker was paid");
        assertEq(token.balanceOf(user), 1_000 ether, "original sender not paid");
    }

    function test_Refund_WrongToken_Reverts() public {
        _cancel(_one(v1pk, _cancelId()));

        TestToken other = new TestToken("Other", "OTH");
        other.mint(address(srcGate), 1_000 ether);

        vm.expectRevert(
            abi.encodeWithSelector(Gate.TokenMismatch.selector, debridgeId, address(other))
        );
        srcGate.refund(
            address(other), debridgeId, AMOUNT, CHAIN_DST, NONCE, receiver, EMPTY_AUTO,
            EMPTY_SENDER, _one(v1pk, _refundId())
        );
    }

    function test_Refund_BelowThreshold_Reverts() public {
        srcGate.setThreshold(2);
        _cancel(_one(v1pk, _cancelId()));

        vm.expectRevert(abi.encodeWithSelector(Gate.NotEnoughSignatures.selector, 1, 2));
        _refund(_one(v1pk, _refundId()));
    }

    function test_Refund_TwoOfThree_Succeeds() public {
        srcGate.setThreshold(2);
        _cancel(_one(v1pk, _cancelId()));

        _refund(_sortedTwo(v1pk, v2pk, _refundId()));
        assertEq(token.balanceOf(user), 1_000 ether);
    }

    function test_Refund_NonValidatorSignature_Reverts() public {
        _cancel(_one(v1pk, _cancelId()));

        vm.expectRevert(abi.encodeWithSelector(Gate.NotEnoughSignatures.selector, 0, 1));
        _refund(_one(strangerPk, _refundId()));
    }

    function test_Refund_DuplicateSigner_Reverts() public {
        srcGate.setThreshold(2);
        _cancel(_one(v1pk, _cancelId()));

        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(v1pk, _refundId());
        sigs[1] = _sign(v1pk, _refundId());

        vm.expectRevert(Gate.InvalidSignerOrder.selector);
        _refund(sigs);
    }

    /// A paused gate must STILL refund (finding L-2). The breaker exists to stop
    /// new exposure — `send` locking more, `claim` releasing more — but a refund
    /// only returns already-locked funds to the address that locked them, and only
    /// after validators attested a destination burn. Halting it would trap exactly
    /// the users the incident stranded, for as long as the incident lasted.
    function test_Refund_WhenPaused_StillPaysOut() public {
        _cancel(_one(v1pk, _cancelId()));
        srcGate.pause();

        uint256 before = token.balanceOf(user);
        _refund(_one(v1pk, _refundId()));

        assertEq(token.balanceOf(user), before + AMOUNT, "paused gate must still refund");
        assertTrue(srcGate.refunded(submissionId), "refund must be recorded");
        assertTrue(srcGate.paused(), "the breaker itself stays tripped");
    }

    /// ...but the exposure-creating paths stay halted, so the exemption above is
    /// narrow and deliberate rather than a hole in the breaker.
    function test_Pause_StillHaltsSendAndCancel() public {
        vm.chainId(CHAIN_SRC);
        srcGate.pause();

        vm.startPrank(user);
        token.approve(address(srcGate), AMOUNT);
        vm.expectRevert(Gate.EnforcedPause.selector);
        srcGate.send(address(token), AMOUNT, CHAIN_DST, receiver, EMPTY_AUTO);
        vm.stopPrank();

        // And a cancel on the destination is frozen too — it is irreversible and
        // forecloses the payout, so it is not exempt the way `refund` is.
        vm.chainId(CHAIN_DST);
        dstGate.pause();
        vm.expectRevert(Gate.EnforcedPause.selector);
        _cancel(_one(v1pk, _cancelId()));
    }

    // -----------------------------------------------------------------
    // Domain separation — the three quorums must not be interchangeable
    // -----------------------------------------------------------------

    function test_Refund_RejectsReplayedTransferSignature() public {
        // The validators already signed this submissionId to authorise PAYING it
        // out on the destination. That signature must not also authorise clawing
        // the funds back on the source.
        _cancel(_one(v1pk, _cancelId()));

        vm.expectRevert(abi.encodeWithSelector(Gate.NotEnoughSignatures.selector, 0, 1));
        _refund(_one(v1pk, submissionId));
    }

    function test_Refund_RejectsReplayedCancelSignature() public {
        _cancel(_one(v1pk, _cancelId()));

        vm.expectRevert(abi.encodeWithSelector(Gate.NotEnoughSignatures.selector, 0, 1));
        _refund(_one(v1pk, _cancelId()));
    }

    function test_Cancel_RejectsReplayedTransferSignature() public {
        // Otherwise anyone holding the ordinary claim signatures could burn a
        // healthy transfer and strand it.
        vm.chainId(CHAIN_DST);
        vm.expectRevert(abi.encodeWithSelector(Gate.NotEnoughSignatures.selector, 0, 1));
        dstGate.cancel(
            debridgeId, AMOUNT, CHAIN_SRC, NONCE, receiver, EMPTY_AUTO, EMPTY_SENDER,
            _one(v1pk, submissionId)
        );
        vm.chainId(CHAIN_SRC);
    }

    function test_Cancel_RejectsReplayedRefundSignature() public {
        vm.chainId(CHAIN_DST);
        vm.expectRevert(abi.encodeWithSelector(Gate.NotEnoughSignatures.selector, 0, 1));
        dstGate.cancel(
            debridgeId, AMOUNT, CHAIN_SRC, NONCE, receiver, EMPTY_AUTO, EMPTY_SENDER,
            _one(v1pk, _refundId())
        );
        vm.chainId(CHAIN_SRC);
    }

    function test_DigestDomains_AreDistinct() public view {
        assertTrue(_cancelId() != submissionId, "cancelId collides with submissionId");
        assertTrue(_refundId() != submissionId, "refundId collides with submissionId");
        assertTrue(_cancelId() != _refundId(), "cancelId collides with refundId");
    }

    // -----------------------------------------------------------------
    // Cancel authorisation
    // -----------------------------------------------------------------

    function test_Cancel_Replay_Reverts() public {
        _cancel(_one(v1pk, _cancelId()));

        vm.chainId(CHAIN_DST);
        vm.expectRevert(Gate.AlreadyExecuted.selector);
        dstGate.cancel(
            debridgeId, AMOUNT, CHAIN_SRC, NONCE, receiver, EMPTY_AUTO, EMPTY_SENDER,
            _one(v1pk, _cancelId())
        );
        vm.chainId(CHAIN_SRC);
    }

    function test_Cancel_BelowThreshold_Reverts() public {
        vm.chainId(CHAIN_DST);
        dstGate.setThreshold(2);
        vm.expectRevert(abi.encodeWithSelector(Gate.NotEnoughSignatures.selector, 1, 2));
        dstGate.cancel(
            debridgeId, AMOUNT, CHAIN_SRC, NONCE, receiver, EMPTY_AUTO, EMPTY_SENDER,
            _one(v1pk, _cancelId())
        );
        vm.chainId(CHAIN_SRC);
    }

    function test_Cancel_NonValidatorSignature_Reverts() public {
        vm.chainId(CHAIN_DST);
        vm.expectRevert(abi.encodeWithSelector(Gate.NotEnoughSignatures.selector, 0, 1));
        dstGate.cancel(
            debridgeId, AMOUNT, CHAIN_SRC, NONCE, receiver, EMPTY_AUTO, EMPTY_SENDER,
            _one(strangerPk, _cancelId())
        );
        vm.chainId(CHAIN_SRC);
    }

    function test_Cancel_WhenPaused_Reverts() public {
        vm.chainId(CHAIN_DST);
        dstGate.pause();
        vm.expectRevert(Gate.EnforcedPause.selector);
        dstGate.cancel(
            debridgeId, AMOUNT, CHAIN_SRC, NONCE, receiver, EMPTY_AUTO, EMPTY_SENDER,
            _one(v1pk, _cancelId())
        );
        vm.chainId(CHAIN_SRC);
    }

    // -----------------------------------------------------------------
    // Refund cannot outrun the cancel
    // -----------------------------------------------------------------

    function test_Refund_IsNotBlockedByAnUncancelledDestination() public {
        // Documenting the honest limit of the on-chain guard: the source gate
        // cannot read the destination, so `refund` does NOT itself verify the
        // cancel. What enforces the ordering is that the refund quorum only
        // exists because validators observed `Cancelled` on-chain before signing
        // (see crates/validator refund loop). On-chain, a refund with a valid
        // quorum succeeds regardless — so the validators' attestation rule is a
        // load-bearing part of the design, not a convenience.
        _refund(_one(v1pk, _refundId()));
        assertEq(token.balanceOf(user), 1_000 ether);
    }

    // -----------------------------------------------------------------
    // L-1: a wrong-width receiver must be unclaimable, hence refundable
    // -----------------------------------------------------------------

    /// A 32-byte receiver means "non-EVM destination" to `send`, which then caps
    /// the amount at u64 (H-3) — so these transfers use an amount that fits.
    uint256 constant WIDE_AMOUNT = 1 ether;

    /// Lock funds bound for this chain pair with a 32-byte `receiver`, and return
    /// the resulting submissionId. `send` accepts the width because it cannot know
    /// the destination VM — 32 bytes is correct for a Solana destination.
    function _sendWithWideReceiver(bytes memory wide) internal returns (bytes32 id) {
        vm.chainId(CHAIN_SRC);
        vm.startPrank(user);
        token.approve(address(srcGate), WIDE_AMOUNT);
        id = srcGate.send(address(token), WIDE_AMOUNT, CHAIN_DST, wide, EMPTY_AUTO);
        vm.stopPrank();
    }

    /// THE L-1 defect, in both shapes it takes.
    ///
    /// `claim` used to read the FIRST 20 bytes of any receiver >= 20 bytes long,
    /// so a 32-byte receiver aimed at an EVM chain paid a live, unowned address:
    ///
    ///   * a Solana pubkey  -> leading 20 bytes are effectively random, funds gone
    ///   * abi.encode(addr) -> leading 20 bytes are ZERO, funds to address(0)
    ///
    /// Neither was rescuable, because the refund path only reaches transfers that
    /// cannot be claimed — and both of these claimed perfectly well.
    function test_Claim_WrongWidthReceiver_IsRefusedNotMisdelivered() public {
        bytes[2] memory malformed = [
            // a Solana account key pasted for an EVM destination
            abi.encodePacked(bytes32(uint256(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef))),
            // abi.encode(address): 32 bytes, address in the LAST 20, leading 20 zero
            abi.encode(receiverAddr)
        ];

        for (uint256 i = 0; i < malformed.length; i++) {
            bytes memory wide = malformed[i];
            assertEq(wide.length, 32, "premise: a 32-byte receiver");

            bytes32 id = _sendWithWideReceiver(wide);
            // Read every argument BEFORE arming expectRevert — it binds to the
            // next call, and an argument expression that makes one would consume it.
            uint256 nonce = srcGate.nonceTo(CHAIN_DST) - 1;
            bytes[] memory sigs = _one(v1pk, id);

            vm.chainId(CHAIN_DST);
            address wouldHaveBeenPaid = address(bytes20(wide));
            TestToken dstToken = TestToken(dstGate.tokenOf(debridgeId));
            uint256 before = dstToken.balanceOf(wouldHaveBeenPaid);

            vm.expectRevert(Gate.BadReceiver.selector);
            dstGate.claim(
                debridgeId, WIDE_AMOUNT, CHAIN_SRC, nonce,
                wide, EMPTY_AUTO, EMPTY_SENDER, sigs
            );

            assertEq(
                dstToken.balanceOf(wouldHaveBeenPaid),
                before,
                "not a single token may reach the truncated address"
            );
            assertFalse(dstGate.executed(id), "a refused claim must not burn the transfer");
            vm.chainId(CHAIN_SRC);
        }
    }

    /// ...and because it is now unclaimable, the existing two-phase refund gets the
    /// money back. That is the whole point of refusing rather than truncating: the
    /// failure moves from "silently paid to nobody" to "recoverable".
    function test_WrongWidthReceiver_IsRecoveredByTheRefundPath() public {
        bytes memory wide = abi.encodePacked(bytes32(uint256(0xDEADBEEF)));
        bytes32 id = _sendWithWideReceiver(wide);
        uint256 nonce = srcGate.nonceTo(CHAIN_DST) - 1;
        uint256 balanceAfterLock = token.balanceOf(user);

        // Destination burns it (the transfer can never be delivered).
        vm.chainId(CHAIN_DST);
        dstGate.cancel(
            debridgeId, WIDE_AMOUNT, CHAIN_SRC, nonce, wide, EMPTY_AUTO, EMPTY_SENDER,
            _one(v1pk, BridgeHash.getCancelId(id))
        );
        assertTrue(dstGate.cancelled(id), "destination must be burned");

        // Source returns the funds to whoever locked them.
        vm.chainId(CHAIN_SRC);
        srcGate.refund(
            address(token), debridgeId, WIDE_AMOUNT, CHAIN_DST, nonce, wide, EMPTY_AUTO, EMPTY_SENDER,
            _one(v1pk, BridgeHash.getRefundId(id))
        );

        assertEq(
            token.balanceOf(user),
            balanceAfterLock + WIDE_AMOUNT,
            "a malformed-receiver transfer must be fully recoverable"
        );
    }

    /// The correct 20-byte width still claims normally — the guard must not have
    /// broken the ordinary path.
    function test_Claim_ExactWidthReceiver_StillWorks() public {
        vm.chainId(CHAIN_DST);
        dstGate.claim(
            debridgeId, AMOUNT, CHAIN_SRC, NONCE, receiver, EMPTY_AUTO, EMPTY_SENDER,
            _one(v1pk, submissionId)
        );
        assertEq(
            TestToken(dstGate.tokenOf(debridgeId)).balanceOf(receiverAddr),
            AMOUNT,
            "a well-formed 20-byte receiver must still be paid"
        );
        vm.chainId(CHAIN_SRC);
    }
}
