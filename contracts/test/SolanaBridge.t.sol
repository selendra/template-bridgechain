// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {Gate} from "../src/Gate.sol";
import {deployTestGate, TEST_BRIDGE_DOMAIN} from "./helpers/TestGate.sol";
import {TestToken} from "../src/TestToken.sol";
import {BridgeHash} from "../src/BridgeHash.sol";

/// @notice EVM -> Solana send path (Phase 8).
///
/// Solana account keys are 32 bytes, not 20. `send()` must accept a 32-byte
/// receiver so a transfer can target a Solana pubkey / SPL token account, while
/// still rejecting any other malformed width. The emitted `submissionId` is the
/// same sacred keccak hash the Solana gate program recomputes on the claim side.
contract SolanaBridgeTest is Test {
    Gate gate;
    TestToken token;

    address user = address(0xBEEF);

    /// deBridge's chain id for Solana mainnet — the same value used in the
    /// cross-language hash fixtures (contracts/fixtures/submission_ids.json).
    uint256 constant SOLANA_CHAIN_ID = 7565164;

    // A real-looking 32-byte Solana pubkey (base58 "Aaa…" decodes to 32 bytes).
    bytes constant SOLANA_RECEIVER =
        hex"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

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

    function setUp() public {
        address[] memory validators = new address[](1);
        validators[0] = address(0xA11CE);
        gate = deployTestGate(validators, 1);
        gate.setSupportedChain(SOLANA_CHAIN_ID, true);
        gate.setSupportedChain(1338, true);

        token = new TestToken("Test", "TST");
        token.mint(user, 1_000 ether);

        vm.prank(user);
        token.approve(address(gate), type(uint256).max);
    }

    function test_Send_ToSolana_EmitsExpectedSubmissionId() public {
        // 1e19 < 2^64: the widest an 18-decimal amount can be and still fit the
        // Solana gate's u64 (H-3 caps 32-byte-receiver sends there).
        uint256 amount = 10 ether;
        bytes memory autoParams = "";
        bytes memory nativeSender = abi.encodePacked(user);

        bytes32 debridgeId = BridgeHash.getDebridgeId(block.chainid, address(token));
        bytes32 expectedId = BridgeHash.getSubmissionId(
            TEST_BRIDGE_DOMAIN, debridgeId, amount, block.chainid, SOLANA_CHAIN_ID, 0, SOLANA_RECEIVER
        );

        vm.expectEmit(true, true, true, true);
        emit Sent(
            expectedId,
            debridgeId,
            amount,
            block.chainid,
            SOLANA_CHAIN_ID,
            SOLANA_RECEIVER,
            0,
            autoParams,
            nativeSender,
            address(token)
        );

        vm.prank(user);
        bytes32 id = gate.send(address(token), amount, SOLANA_CHAIN_ID, SOLANA_RECEIVER, autoParams);

        assertEq(id, expectedId, "returned id mismatch");
    }

    function test_Send_ToSolana_LocksTokens() public {
        vm.prank(user);
        gate.send(address(token), 10 ether, SOLANA_CHAIN_ID, SOLANA_RECEIVER, "");

        assertEq(token.balanceOf(address(gate)), 10 ether, "gate did not hold funds");
        assertEq(token.balanceOf(user), 990 ether, "user not debited");
    }

    // -----------------------------------------------------------------
    // H-3: a non-EVM leg cannot carry an amount wider than u64
    // -----------------------------------------------------------------

    /// The Solana gate's ClaimArgs/CancelArgs carry `amount` as a u64 and the
    /// relayer parses it as one, so an EVM->Solana transfer of >= 2^64 units could
    /// be neither claimed nor cancelled — and without a cancel, never refunded.
    /// `send` must refuse to lock it. (For an 18-decimal token that is ~18.44
    /// whole tokens; nothing in this bridge normalises decimals.)
    function test_Send_ToSolana_RevertsWhenAmountDoesNotFitU64() public {
        uint256 tooWide = uint256(type(uint64).max) + 1;
        token.mint(user, tooWide);
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Gate.AmountTooWide.selector, tooWide));
        gate.send(address(token), tooWide, SOLANA_CHAIN_ID, SOLANA_RECEIVER, "");

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Gate.AmountTooWide.selector, 100 ether));
        gate.send(address(token), 100 ether, SOLANA_CHAIN_ID, SOLANA_RECEIVER, "");

        assertEq(gate.nonceTo(SOLANA_CHAIN_ID), 0, "nothing was locked");
    }

    function test_Send_ToSolana_AcceptsExactlyU64Max() public {
        uint256 widest = type(uint64).max;
        token.mint(user, widest);
        vm.prank(user);
        gate.send(address(token), widest, SOLANA_CHAIN_ID, SOLANA_RECEIVER, "");
        assertEq(gate.nonceTo(SOLANA_CHAIN_ID), 1);
    }

    /// The cap is keyed on the receiver WIDTH (the only signal `send` has for the
    /// destination VM), so a 20-byte EVM receiver keeps the full uint256 range.
    function test_Send_ToEvm_IsNotCappedAtU64() public {
        uint256 wide = uint256(type(uint64).max) + 1;
        token.mint(user, wide);
        vm.prank(user);
        gate.send(address(token), wide, 1338, abi.encodePacked(address(0xCAFE)), "");
        assertEq(gate.nonceTo(1338), 1);
    }

    function test_Send_StillAccepts_20ByteEvmReceiver() public {
        bytes memory evmReceiver = abi.encodePacked(address(0xCAFE));
        vm.prank(user);
        gate.send(address(token), 1 ether, 1338, evmReceiver, "");
        // no revert == pass
    }

    function test_Send_Reverts_On_21ByteReceiver() public {
        bytes memory bad = new bytes(21);
        vm.prank(user);
        vm.expectRevert(Gate.BadReceiver.selector);
        gate.send(address(token), 1 ether, SOLANA_CHAIN_ID, bad, "");
    }

    function test_Send_Reverts_On_31ByteReceiver() public {
        bytes memory bad = new bytes(31);
        vm.prank(user);
        vm.expectRevert(Gate.BadReceiver.selector);
        gate.send(address(token), 1 ether, SOLANA_CHAIN_ID, bad, "");
    }

    function test_Send_Reverts_On_EmptyReceiver() public {
        vm.prank(user);
        vm.expectRevert(Gate.BadReceiver.selector);
        gate.send(address(token), 1 ether, SOLANA_CHAIN_ID, "", "");
    }
}
