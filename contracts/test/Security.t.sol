// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {Gate} from "../src/Gate.sol";
import {deployTestGate, initTestGate, TEST_BRIDGE_DOMAIN} from "./helpers/TestGate.sol";
import {TestToken} from "../src/TestToken.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @dev A token whose transferFrom reenters `Gate.send` exactly once, to probe
///      the source-side nonce sequencing under reentrancy (finding C2).
contract ReentrantToken is ERC20 {
    Gate public gate;
    uint256 public chainTo;
    bool public entered;

    constructor() ERC20("Re", "RE") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    /// Arm the hook and self-fund so the reentrant send has something to pull.
    function arm(Gate g, uint256 c) external {
        gate = g;
        chainTo = c;
        _mint(address(this), 1 ether);
        _approve(address(this), address(g), type(uint256).max);
    }

    function transferFrom(address from, address to, uint256 amount)
        public
        override
        returns (bool)
    {
        bool ok = super.transferFrom(from, to, amount);
        if (!entered && address(gate) != address(0)) {
            entered = true;
            // reenter the gate from inside the token transfer
            gate.send(address(this), 1, chainTo, abi.encodePacked(address(0xCAFE)), "");
        }
        return ok;
    }
}

contract SecurityTest is Test {
    Gate gate;
    TestToken token;

    address v1 = address(0xA11CE);
    address v2 = address(0xB0B);
    address v3 = address(0xC0FFEE);
    address attacker = address(0xBAD);
    uint256 constant CHAIN_TO = 1338;

    function _validators(uint256 n) internal view returns (address[] memory vs) {
        vs = new address[](n);
        if (n > 0) vs[0] = v1;
        if (n > 1) vs[1] = v2;
        if (n > 2) vs[2] = v3;
    }

    function setUp() public {
        gate = deployTestGate(_validators(3), 2);
        gate.setSupportedChain(CHAIN_TO, true);
        token = new TestToken("Test", "TST");
    }

    // ---- C1: threshold bounds ----

    function test_Constructor_RevertsZeroThreshold() public {
        Gate impl = new Gate();
        vm.expectRevert(abi.encodeWithSelector(Gate.InvalidThreshold.selector, 0, 3));
        initTestGate(impl, _validators(3), 0);
    }

    function test_Constructor_RevertsThresholdAboveValidatorCount() public {
        Gate impl = new Gate();
        vm.expectRevert(abi.encodeWithSelector(Gate.InvalidThreshold.selector, 4, 3));
        initTestGate(impl, _validators(3), 4);
    }

    function test_Constructor_RevertsZeroValidator() public {
        address[] memory vs = new address[](1);
        vs[0] = address(0);
        Gate impl = new Gate();
        vm.expectRevert(Gate.ZeroValidator.selector);
        initTestGate(impl, vs, 1);
    }

    function test_SetThreshold_RevertsZero() public {
        vm.expectRevert(abi.encodeWithSelector(Gate.InvalidThreshold.selector, 0, 3));
        gate.setThreshold(0);
    }

    function test_SetThreshold_RevertsAboveValidatorCount() public {
        vm.expectRevert(abi.encodeWithSelector(Gate.InvalidThreshold.selector, 5, 3));
        gate.setThreshold(5);
    }

    function test_SetValidator_CannotDropBelowThreshold() public {
        // threshold 2, validatorCount 3 -> remove one is fine (count 2)
        gate.setValidator(v3, false);
        assertEq(gate.validatorCount(), 2);
        // removing another would make count 1 < threshold 2 -> revert
        vm.expectRevert(abi.encodeWithSelector(Gate.InvalidThreshold.selector, 2, 1));
        gate.setValidator(v2, false);
    }

    // ---- C1 (impact): a zero threshold would have allowed a no-signature drain ----

    function test_NoZeroThresholdDrainPossible() public {
        // There is simply no way to reach threshold == 0, so claim() can never
        // pass with an empty signature set. Both entry points revert:
        vm.expectRevert(abi.encodeWithSelector(Gate.InvalidThreshold.selector, 0, 3));
        gate.setThreshold(0);
        Gate impl = new Gate();
        vm.expectRevert(abi.encodeWithSelector(Gate.InvalidThreshold.selector, 0, 1));
        initTestGate(impl, _validators(1), 0);
    }

    // ---- C2 / M8: a token that reenters send() is rejected ----
    //
    // Originally this proved CEI nonce ordering left a clean nonce=2 when a token
    // reentered send(). The M8 exact-transfer check (report.md) now REJECTS such a
    // token outright: the inner reentrant send deposits extra, so the outer send's
    // balance delta no longer equals its signed `amount` and it reverts. That is a
    // strictly stronger guarantee (a reentering / non-exact-transfer token can
    // never lock funds here). CEI ordering remains in the code as defense in depth;
    // plain sequential nonces are covered by test_Send_NonceIncrementsPerTarget.
    function test_Send_ReentrantTokenIsRejected() public {
        ReentrantToken rt = new ReentrantToken();
        rt.mint(attacker, 10 ether);
        rt.arm(gate, CHAIN_TO);

        vm.startPrank(attacker);
        rt.approve(address(gate), type(uint256).max);
        // outer signed 1 ether; the reentrant inner send deposits 1 extra wei, so
        // the outer balance delta is 1 ether + 1 and the exact-transfer check trips.
        vm.expectRevert(
            abi.encodeWithSelector(Gate.UnsupportedTokenBehavior.selector, 1 ether, 1 ether + 1)
        );
        gate.send(address(rt), 1 ether, CHAIN_TO, abi.encodePacked(address(0xCAFE)), "");
        vm.stopPrank();

        // The whole tx rolled back: no funds locked, no nonce consumed.
        assertEq(rt.balanceOf(address(gate)), 0, "no funds should be locked");
        assertEq(gate.nonceTo(CHAIN_TO), 0, "nonce must not advance on a rejected send");
    }

    // ---- C3: receiver width must be 20 (EVM) or 32 (Solana/non-EVM) ----
    // The 32-byte case is a *valid* Solana receiver now; see SolanaBridge.t.sol.

    function test_Send_RevertsReceiverTooLong() public {
        token.mint(attacker, 10 ether);
        vm.startPrank(attacker);
        token.approve(address(gate), type(uint256).max);
        // 33 bytes — wider than any supported destination address size.
        bytes memory tooLong = new bytes(33);
        vm.expectRevert(Gate.BadReceiver.selector);
        gate.send(address(token), 1 ether, CHAIN_TO, tooLong, "");
        vm.stopPrank();
    }

    function test_Send_RevertsReceiverTooShort() public {
        token.mint(attacker, 10 ether);
        vm.startPrank(attacker);
        token.approve(address(gate), type(uint256).max);
        vm.expectRevert(Gate.BadReceiver.selector);
        gate.send(address(token), 1 ether, CHAIN_TO, hex"1234", "");
        vm.stopPrank();
    }

    // ---- C4: two-step ownership + access control ----

    function test_TransferOwnership_TwoStep() public {
        address newOwner = address(0xBEEF);
        gate.transferOwnership(newOwner);
        // not transferred until accepted
        assertEq(gate.owner(), address(this));
        assertEq(gate.pendingOwner(), newOwner);

        vm.prank(newOwner);
        gate.acceptOwnership();
        assertEq(gate.owner(), newOwner);
        assertEq(gate.pendingOwner(), address(0));
    }

    function test_AcceptOwnership_OnlyPending() public {
        gate.transferOwnership(address(0xBEEF));
        vm.prank(attacker);
        vm.expectRevert(Gate.NotOwner.selector);
        gate.acceptOwnership();
    }

    function test_TransferOwnership_RejectsZero() public {
        vm.expectRevert(Gate.ZeroAddress.selector);
        gate.transferOwnership(address(0));
    }

    function test_Setters_OnlyOwner() public {
        vm.startPrank(attacker);
        vm.expectRevert(Gate.NotOwner.selector);
        gate.setThreshold(1);
        vm.expectRevert(Gate.NotOwner.selector);
        gate.setValidator(attacker, true);
        vm.expectRevert(Gate.NotOwner.selector);
        gate.setLocalToken(bytes32(0), address(token));
        vm.stopPrank();
    }

    // ---- C5: emergency circuit breaker ----

    function test_Pause_HaltsSend() public {
        token.mint(attacker, 10 ether);
        gate.pause();
        assertTrue(gate.paused());
        vm.startPrank(attacker);
        token.approve(address(gate), type(uint256).max);
        vm.expectRevert(Gate.EnforcedPause.selector);
        gate.send(address(token), 1 ether, CHAIN_TO, abi.encodePacked(address(0xCAFE)), "");
        vm.stopPrank();
    }

    function test_Pause_HaltsClaim() public {
        gate.pause();
        // any claim must revert on the pause guard before touching signatures
        bytes[] memory sigs = new bytes[](0);
        vm.expectRevert(Gate.EnforcedPause.selector);
        gate.claim(bytes32(0), 1 ether, 1337, 0, abi.encodePacked(address(0xCAFE)), "", "", sigs);
    }

    function test_Unpause_ResumesSend() public {
        token.mint(attacker, 10 ether);
        gate.pause();
        gate.unpause();
        assertFalse(gate.paused());
        vm.startPrank(attacker);
        token.approve(address(gate), type(uint256).max);
        // no revert: a normal send goes through again
        gate.send(address(token), 1 ether, CHAIN_TO, abi.encodePacked(address(0xCAFE)), "");
        vm.stopPrank();
    }

    function test_Guardian_CanPauseButNotUnpause() public {
        address guardian = address(0x6A5D);
        gate.setGuardian(guardian);
        assertEq(gate.guardian(), guardian);

        // guardian trips the breaker
        vm.prank(guardian);
        gate.pause();
        assertTrue(gate.paused());

        // but a guardian cannot resume — only the owner can
        vm.prank(guardian);
        vm.expectRevert(Gate.NotOwner.selector);
        gate.unpause();

        gate.unpause();
        assertFalse(gate.paused());
    }

    function test_Pause_OnlyOwnerOrGuardian() public {
        vm.prank(attacker);
        vm.expectRevert(Gate.NotAuthorizedToPause.selector);
        gate.pause();
    }

    function test_SetGuardian_OnlyOwner() public {
        vm.prank(attacker);
        vm.expectRevert(Gate.NotOwner.selector);
        gate.setGuardian(attacker);
    }

    // -----------------------------------------------------------------
    // M-5: the asset registry is write-once
    // -----------------------------------------------------------------

    /// A claim commits to a `debridgeId` — a one-way hash of the SOURCE asset —
    /// never to the local token. So the mapping read at claim time is what decides
    /// the payout. If it could be repointed, validators could sign a transfer of
    /// asset X and the very same signatures would release asset Y, with nothing
    /// they attested having changed.
    function test_SetLocalToken_IsWriteOnce() public {
        bytes32 did = keccak256("some-corridor");
        gate.setLocalToken(did, address(token));
        assertEq(gate.tokenOf(did), address(token));

        TestToken other = new TestToken("Other", "OTH");
        vm.expectRevert(
            abi.encodeWithSelector(Gate.LocalTokenAlreadySet.selector, did, address(token))
        );
        gate.setLocalToken(did, address(other));

        assertEq(gate.tokenOf(did), address(token), "registered asset must be immutable");
    }

    /// Zero is the "unregistered" sentinel `claim` tests against, so it must never
    /// be storable — otherwise it would read as a corridor that was never set up.
    function test_SetLocalToken_RejectsZero() public {
        vm.expectRevert(Gate.ZeroAddress.selector);
        gate.setLocalToken(keccak256("z"), address(0));
    }

    function test_SetLocalToken_OnlyOwner() public {
        vm.prank(attacker);
        vm.expectRevert(Gate.NotOwner.selector);
        gate.setLocalToken(keccak256("x"), address(token));
    }

    // ---- L-2: the packed preimage must not be ambiguous ----

    /// `packedSubmission` ends `…, receiver, nonce` with `receiver` carrying no
    /// length prefix, and the auto-params variant appends 160 more fixed bytes. A
    /// no-auto preimage with a 180-byte receiver has the same length AND layout as
    /// an auto preimage with a 20-byte one, so the two forms are told apart only by
    /// a width invariant. That invariant lived in `send` alone, while `claim`,
    /// `cancel` and `refund` hashed a caller-supplied receiver of any length first.
    function test_IdComputation_RefusesAnAmbiguousReceiverWidth() public {
        bytes memory long180 = new bytes(180);
        bytes memory odd = new bytes(21);

        for (uint256 i; i < 2; i++) {
            bytes memory bad = i == 0 ? long180 : odd;
            vm.expectRevert(Gate.BadReceiver.selector);
            gate.computeSubmissionId(bytes32(0), 1, 1337, 1338, 0, bad, "", "");
        }

        // The two legitimate widths still hash, so nothing real is affected.
        gate.computeSubmissionId(bytes32(0), 1, 1337, 1338, 0, new bytes(20), "", "");
        gate.computeSubmissionId(bytes32(0), 1, 1337, 1338, 0, new bytes(32), "", "");
    }

    /// The same guard has to hold on the entry points that used to skip it — a
    /// wrong-width `cancel` must not even reach signature verification.
    function test_Cancel_RefusesAnAmbiguousReceiverWidth() public {
        bytes[] memory none = new bytes[](0);
        vm.expectRevert(Gate.BadReceiver.selector);
        gate.cancel(bytes32(0), 1, 1337, 0, new bytes(180), "", "", none);
    }

}
