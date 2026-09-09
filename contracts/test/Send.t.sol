// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {Gate} from "../src/Gate.sol";
import {deployTestGate, TEST_BRIDGE_DOMAIN} from "./helpers/TestGate.sol";
import {TestToken} from "../src/TestToken.sol";
import {BridgeHash} from "../src/BridgeHash.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// Minimal fee-on-transfer token: burns `feeBps` of every transfer so the
/// recipient receives less than `amount`. Used to prove the gate rejects it.
contract FeeToken is ERC20 {
    uint256 public immutable feeBps;

    constructor(uint256 feeBps_) ERC20("Fee", "FEE") {
        feeBps = feeBps_;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function _update(address from, address to, uint256 value) internal override {
        if (from != address(0) && to != address(0) && feeBps > 0) {
            uint256 fee = (value * feeBps) / 10_000;
            super._update(from, to, value - fee);
            super._update(from, address(0xdead), fee); // burn-ish sink
        } else {
            super._update(from, to, value);
        }
    }
}

contract SendTest is Test {
    Gate gate;
    TestToken token;

    address user = address(0xBEEF);
    uint256 constant CHAIN_TO = 1338;

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
        // M-3: `send` refuses destinations the owner has not listed.
        gate.setSupportedChain(CHAIN_TO, true);
        gate.setSupportedChain(9999, true);

        token = new TestToken("Test", "TST");
        token.mint(user, 1_000 ether);

        vm.prank(user);
        token.approve(address(gate), type(uint256).max);
    }

    function test_Send_EmitsEventWithExpectedFields() public {
        uint256 amount = 100 ether;
        bytes memory receiver = abi.encodePacked(address(0xCAFE));
        bytes memory autoParams = "";
        bytes memory nativeSender = abi.encodePacked(user);

        bytes32 debridgeId = BridgeHash.getDebridgeId(block.chainid, address(token));
        bytes32 expectedId = BridgeHash.getSubmissionId(
            TEST_BRIDGE_DOMAIN, debridgeId, amount, block.chainid, CHAIN_TO, 0, receiver
        );

        vm.expectEmit(true, true, true, true);
        emit Sent(
            expectedId,
            debridgeId,
            amount,
            block.chainid,
            CHAIN_TO,
            receiver,
            0,
            autoParams,
            nativeSender,
            address(token)
        );

        vm.prank(user);
        bytes32 id = gate.send(address(token), amount, CHAIN_TO, receiver, autoParams);

        assertEq(id, expectedId, "returned id mismatch");
    }

    function test_Send_LocksTokensInGate() public {
        uint256 amount = 100 ether;
        bytes memory receiver = abi.encodePacked(address(0xCAFE));

        vm.prank(user);
        gate.send(address(token), amount, CHAIN_TO, receiver, "");

        assertEq(token.balanceOf(address(gate)), amount, "gate did not hold funds");
        assertEq(token.balanceOf(user), 900 ether, "user not debited");
    }

    function test_Send_NonceIncrementsPerTarget() public {
        bytes memory receiver = abi.encodePacked(address(0xCAFE));

        assertEq(gate.nonceTo(CHAIN_TO), 0);

        vm.prank(user);
        gate.send(address(token), 1 ether, CHAIN_TO, receiver, "");
        assertEq(gate.nonceTo(CHAIN_TO), 1, "nonce should be 1 after first send");

        vm.prank(user);
        gate.send(address(token), 1 ether, CHAIN_TO, receiver, "");
        assertEq(gate.nonceTo(CHAIN_TO), 2, "nonce should be 2 after second send");
    }

    function test_Send_NoncesAreIndependentPerTargetChain() public {
        bytes memory receiver = abi.encodePacked(address(0xCAFE));

        vm.prank(user);
        gate.send(address(token), 1 ether, 1338, receiver, "");
        vm.prank(user);
        gate.send(address(token), 1 ether, 9999, receiver, "");

        assertEq(gate.nonceTo(1338), 1);
        assertEq(gate.nonceTo(9999), 1);
    }

    function test_Send_RevertsOnZeroAmount() public {
        vm.prank(user);
        vm.expectRevert(Gate.ZeroAmount.selector);
        gate.send(address(token), 0, CHAIN_TO, abi.encodePacked(address(0xCAFE)), "");
    }

    function test_Send_RejectsFeeOnTransferToken() public {
        // A 1% fee-on-transfer token: the gate would receive 99 for a signed 100,
        // so a destination claim would release 100 from shared liquidity — a
        // shortfall drain. The exact-transfer check must reject it.
        FeeToken fee = new FeeToken(100); // 1%
        fee.mint(user, 1_000 ether);
        vm.prank(user);
        fee.approve(address(gate), type(uint256).max);

        uint256 amount = 100 ether;
        uint256 received = amount - (amount * 100) / 10_000; // 99 ether
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(Gate.UnsupportedTokenBehavior.selector, amount, received)
        );
        gate.send(address(fee), amount, CHAIN_TO, abi.encodePacked(address(0xCAFE)), "");

        // and nothing was locked / no nonce consumed (the whole tx reverted)
        assertEq(fee.balanceOf(address(gate)), 0, "no funds should be locked");
        assertEq(gate.nonceTo(CHAIN_TO), 0, "nonce must not advance on a rejected send");
    }

    function test_Send_AcceptsExactTransferToken() public {
        // Sanity: a normal (exact-transfer) token still works after the check.
        uint256 amount = 100 ether;
        vm.prank(user);
        gate.send(address(token), amount, CHAIN_TO, abi.encodePacked(address(0xCAFE)), "");
        assertEq(token.balanceOf(address(gate)), amount);
    }
}
