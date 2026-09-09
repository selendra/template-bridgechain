// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {Gate} from "../src/Gate.sol";
import {deployTestGate, TEST_BRIDGE_DOMAIN} from "./helpers/TestGate.sol";
import {SwapPool} from "../src/SwapPool.sol";
import {SwapRouter} from "../src/SwapRouter.sol";
import {BridgeHash} from "../src/BridgeHash.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @dev Mintable ERC-20 with configurable decimals (same helper the deploy uses).
contract MockToken is ERC20 {
    uint8 private immutable _dec;

    constructor(string memory n, string memory s, uint8 d) ERC20(n, s) {
        _dec = d;
    }

    function decimals() public view override returns (uint8) {
        return _dec;
    }

    function mint(address to, uint256 amt) external {
        _mint(to, amt);
    }
}

/// @dev The M-7 attacker. In ONE transaction: buy the entire `tokenOut` reserve
///      out of the pool (so the router's `_swapBlocked` sees `out > reserve`),
///      call `finalize` as a stranger, then sell the reserve straight back. Capital
///      is committed for one block, not for the grace window.
contract Sandwicher {
    struct Args {
        bytes32 debridgeId;
        uint256 amount;
        uint256 chainIdFrom;
        uint256 nonce;
        bytes receiver;
        bytes autoParams;
        bytes nativeSender;
    }

    function sandwich(SwapPool pool, address stable, address tokenOut, SwapRouter router, Args calldata a)
        external
    {
        (,,, uint256 reserve) = pool.tokens(tokenOut);
        // Cost of the whole reserve at the pegged rate (fee is zero in tests);
        // trim any rounding so the swap lands exactly on the lock.
        uint256 cost = pool.quote(tokenOut, stable, reserve);
        while (pool.quote(stable, tokenOut, cost) > reserve) cost -= 1;

        IERC20(stable).approve(address(pool), cost);
        pool.swap(stable, tokenOut, cost, 0, address(this));

        router.finalize(a.debridgeId, a.amount, a.chainIdFrom, a.nonce, a.receiver, a.autoParams, a.nativeSender);

        uint256 got = IERC20(tokenOut).balanceOf(address(this));
        IERC20(tokenOut).approve(address(pool), got);
        pool.swap(tokenOut, stable, got, 0, address(this));
    }
}

/// @notice End-to-end cross-chain swap over the SwapRouter, simulating TWO chains
///         in one EVM via `vm.chainId`. A user on chain A swaps WETH into TT on
///         chain B: WETH --poolA--> stable --Gate--> stable --poolB--> TT.
///
///         Neither Gate nor SwapPool is modified; the destination leg is trustless
///         (proven by Gate.executed[submissionId]) with a stable-refund fallback.
contract SwapRouterTest is Test {
    // two "chains"
    uint256 constant CHAIN_A = 1337;
    uint256 constant CHAIN_B = 8453;
    uint16 constant DEVIATION_BPS = 1000;

    // one validator, threshold 1 (signature machinery proven in Claim.t.sol)
    uint256 v1pk = 0xA11CE;
    address v1;

    // chain A
    Gate gateA;
    SwapPool poolA;
    SwapRouter routerA;
    MockToken usdA; // 6-dec stable
    MockToken weth; // 18-dec, priced 3180

    // chain B
    Gate gateB;
    SwapPool poolB;
    SwapRouter routerB;
    MockToken usdB; // 6-dec stable
    MockToken tt; // 18-dec, priced 2

    address user = address(0xB0B);
    address finalReceiver = address(0xBEEF);

    uint256 constant WETH_PRICE = 3180e18;
    uint256 constant TT_PRICE = 2e18;

    function setUp() public {
        v1 = vm.addr(v1pk);
        address[] memory vals = new address[](1);
        vals[0] = v1;

        // --- chain A ---
        vm.chainId(CHAIN_A);
        gateA = deployTestGate(vals, 1);
        gateA.setSupportedChain(CHAIN_B, true);
        usdA = new MockToken("USD A", "USDa", 6);
        weth = new MockToken("Wrapped Ether", "WETH", 18);
        poolA = new SwapPool(address(usdA), DEVIATION_BPS);
        poolA.listToken(address(weth), WETH_PRICE);
        _seed(poolA, usdA, 10_000_000e6);
        _seed(poolA, weth, 100e18);
        routerA = new SwapRouter(gateA, poolA);

        // --- chain B ---
        vm.chainId(CHAIN_B);
        gateB = deployTestGate(vals, 1);
        gateB.setSupportedChain(CHAIN_A, true);
        usdB = new MockToken("USD B", "USDb", 6);
        tt = new MockToken("Test Token", "TT", 18);
        poolB = new SwapPool(address(usdB), DEVIATION_BPS);
        poolB.listToken(address(tt), TT_PRICE);
        _seed(poolB, usdB, 10_000_000e6);
        _seed(poolB, tt, 1_000_000e18);
        routerB = new SwapRouter(gateB, poolB);

        // wire the corridor A <-> B
        routerA.setRemoteRouter(CHAIN_B, abi.encodePacked(address(routerB)));
        routerB.setRemoteRouter(CHAIN_A, abi.encodePacked(address(routerA)));

        // The stable bridges A->B as (native chain A, usdA) -> local usdB. Register
        // the mapping on B and pre-fund gateB with target-side stable liquidity.
        bytes32 stableDid = BridgeHash.getDebridgeId(CHAIN_A, address(usdA));
        gateB.setLocalToken(stableDid, address(usdB));
        usdB.mint(address(gateB), 10_000_000e6);
    }

    function _seed(SwapPool pool, MockToken token, uint256 amt) internal {
        token.mint(address(this), amt);
        token.approve(address(pool), amt);
        pool.seedLiquidity(address(token), amt);
    }

    function _sign(uint256 pk, bytes32 id) internal pure returns (bytes[] memory sigs) {
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(id);
        (uint8 vv, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        sigs = new bytes[](1);
        sigs[0] = abi.encodePacked(r, s, vv);
    }

    // The bridged transfer's fields, as they appear in the source `Sent` event.
    struct Leg {
        bytes32 debridgeId;
        uint256 amount; // stable bridged (= poolA WETH->stable output)
        uint256 nonce;
        bytes receiver; // routerB
        bytes autoParams;
        bytes nativeSender; // routerA
        bytes32 id;
    }

    /// @dev Run the source leg on chain A and reconstruct the resulting transfer.
    function _sourceLeg(uint256 amountIn, address finalToken, uint256 finalMinOut)
        internal
        returns (Leg memory leg)
    {
        vm.chainId(CHAIN_A);
        weth.mint(user, amountIn);
        vm.startPrank(user);
        weth.approve(address(routerA), amountIn);
        leg.id = routerA.swapAndBridge(
            address(weth), amountIn, 0, CHAIN_B, finalToken, finalReceiver, finalMinOut
        );
        vm.stopPrank();

        // Reconstruct the transfer fields deterministically (asserts our encoding).
        leg.debridgeId = BridgeHash.getDebridgeId(CHAIN_A, address(usdA));
        leg.amount = poolA.quote(address(weth), address(usdA), amountIn);
        leg.nonce = 0; // first send A->B
        leg.receiver = abi.encodePacked(address(routerB));
        leg.nativeSender = abi.encodePacked(address(routerA));
        Gate.AutoParamsTo memory ap = Gate.AutoParamsTo({
            executionFee: 0,
            flags: 0,
            fallbackAddress: abi.encodePacked(finalReceiver),
            data: abi.encode(finalToken, finalReceiver, finalMinOut)
        });
        leg.autoParams = abi.encode(ap);

        // the id the router returned must equal the canonical id we rebuild
        bytes32 rebuilt = gateA.computeSubmissionId(
            leg.debridgeId, leg.amount, CHAIN_A, CHAIN_B, leg.nonce, leg.receiver, leg.autoParams, leg.nativeSender
        );
        assertEq(leg.id, rebuilt, "source id mismatch");
    }

    // ------------------------------------------------------------------
    // Happy path: WETH@A -> TT@B, one atomic claimAndFinalize on B
    // ------------------------------------------------------------------
    function test_CrossChain_SwapAndBridge_ClaimAndFinalize() public {
        uint256 amountIn = 1e18; // 1 WETH
        Leg memory leg = _sourceLeg(amountIn, address(tt), 0);

        // 3180 USD of stable bridged (WETH price 3180, stable 6-dec)
        assertEq(leg.amount, 3180e6, "bridged stable wrong");

        // expected TT out on B: 3180 USD / 2 = 1590 TT
        uint256 expectedTt = poolB.quote(address(usdB), address(tt), leg.amount);
        assertEq(expectedTt, 1590e18, "dest quote wrong");

        vm.chainId(CHAIN_B);
        bytes[] memory sigs = _sign(v1pk, leg.id);
        bytes32 got = routerB.claimAndFinalize(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce, leg.receiver, leg.autoParams, leg.nativeSender, sigs
        );

        assertEq(got, leg.id, "finalized id mismatch");
        assertEq(tt.balanceOf(finalReceiver), expectedTt, "final receiver not paid in TT");
        assertTrue(gateB.executed(leg.id), "claim not recorded");
        assertTrue(routerB.finalized(leg.id), "finalize not recorded");
        // router holds no residual stable
        assertEq(usdB.balanceOf(address(routerB)), 0, "stable stranded at router");
    }

    // ------------------------------------------------------------------
    // A cancelled transfer is NOT a delivered one
    // ------------------------------------------------------------------
    function test_Finalize_AfterCancel_Reverts() public {
        // `Gate.cancel` burns a stranded transfer by setting `executed` — without
        // ever releasing the stable. `finalize` used to read `executed` as proof
        // of delivery, so it would have paid `finalReceiver` out of whatever
        // liquidity happened to be resting at the router (another user's in-flight
        // transfer), while the source chain separately refunded the sender.
        Leg memory leg = _sourceLeg(1e18, address(tt), 0);

        vm.chainId(CHAIN_B);
        bytes32 cancelId = BridgeHash.getCancelId(leg.id);
        gateB.cancel(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce, leg.receiver, leg.autoParams,
            leg.nativeSender, _sign(v1pk, cancelId)
        );
        assertTrue(gateB.executed(leg.id), "cancel did not burn the transfer");
        assertTrue(gateB.cancelled(leg.id), "cancelled flag not set");

        // strand some stable at the router, so a buggy finalize WOULD have paid out
        usdB.mint(address(routerB), leg.amount);

        vm.expectRevert(abi.encodeWithSelector(SwapRouter.NotDelivered.selector, leg.id));
        routerB.finalize(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce, leg.receiver, leg.autoParams, leg.nativeSender
        );

        assertEq(tt.balanceOf(finalReceiver), 0, "receiver paid for a cancelled transfer");
        assertFalse(routerB.finalized(leg.id), "cancelled transfer marked finalized");
    }

    // ------------------------------------------------------------------
    // Two-step: keeper claims via the Gate, then anyone calls finalize
    // ------------------------------------------------------------------
    function test_CrossChain_Finalize_AfterPlainClaim() public {
        Leg memory leg = _sourceLeg(1e18, address(tt), 0);

        vm.chainId(CHAIN_B);
        bytes[] memory sigs = _sign(v1pk, leg.id);
        // a keeper claims into the router (stable released to routerB)
        gateB.claim(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce, leg.receiver, leg.autoParams, leg.nativeSender, sigs
        );
        assertEq(usdB.balanceOf(address(routerB)), leg.amount, "stable not delivered to router");

        // a permissionless finalize completes the swap
        vm.prank(address(0xDEAD));
        routerB.finalize(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce, leg.receiver, leg.autoParams, leg.nativeSender
        );
        assertEq(tt.balanceOf(finalReceiver), 1590e18, "final swap did not run");
        assertEq(usdB.balanceOf(address(routerB)), 0, "stable not fully consumed");
    }

    // ------------------------------------------------------------------
    // Finalize before delivery must revert (no free swaps)
    // ------------------------------------------------------------------
    function test_Finalize_NotDelivered_Reverts() public {
        Leg memory leg = _sourceLeg(1e18, address(tt), 0);

        vm.chainId(CHAIN_B);
        vm.expectRevert(abi.encodeWithSelector(SwapRouter.NotDelivered.selector, leg.id));
        routerB.finalize(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce, leg.receiver, leg.autoParams, leg.nativeSender
        );
    }

    // ------------------------------------------------------------------
    // Idempotency: a second finalize on the same transfer reverts
    // ------------------------------------------------------------------
    function test_Finalize_Idempotent() public {
        Leg memory leg = _sourceLeg(1e18, address(tt), 0);

        vm.chainId(CHAIN_B);
        bytes[] memory sigs = _sign(v1pk, leg.id);
        routerB.claimAndFinalize(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce, leg.receiver, leg.autoParams, leg.nativeSender, sigs
        );

        vm.expectRevert(abi.encodeWithSelector(SwapRouter.AlreadyFinalized.selector, leg.id));
        routerB.finalize(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce, leg.receiver, leg.autoParams, leg.nativeSender
        );
    }

    // ------------------------------------------------------------------
    // Fallback: if the destination swap can't complete, deliver the stable
    // ------------------------------------------------------------------
    function test_Finalize_Fallback_DeliversStable_OnlyAfterTheGraceWindow() public {
        // Ask for more TT than the pool's reserve can pay. That used to hand the
        // user the stable on the spot; it is a recoverable condition, so the router
        // now waits out FALLBACK_GRACE first and only then gives up.
        vm.chainId(CHAIN_B);
        poolB.withdrawLiquidity(address(tt), 1_000_000e18 - 1e18, address(this)); // leave 1 TT

        Leg memory leg = _sourceLeg(1e18, address(tt), 0); // wants 1590 TT, only 1 left

        vm.chainId(CHAIN_B);
        bytes[] memory sigs = _sign(v1pk, leg.id);
        routerB.claimAndFinalize(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce, leg.receiver, leg.autoParams, leg.nativeSender, sigs
        );

        // Deferred, not settled: the stable is still at the router and the transfer
        // is still finalizable, so a refill can still deliver the real token.
        assertEq(usdB.balanceOf(finalReceiver), 0, "must not downgrade inside the window");
        assertEq(usdB.balanceOf(address(routerB)), leg.amount, "stable should still be held");
        assertFalse(routerB.finalized(leg.id), "must stay finalizable");
        assertEq(routerB.deferredSince(leg.id), block.timestamp, "grace clock not started");

        vm.warp(block.timestamp + routerB.FALLBACK_GRACE());
        // The receiver, not a keeper, decides to take the stable (M-7).
        vm.prank(finalReceiver);
        routerB.finalize(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce, leg.receiver, leg.autoParams, leg.nativeSender
        );

        // The window proved the condition durable: no TT paid, stable refunded.
        assertEq(tt.balanceOf(finalReceiver), 0, "should not have paid TT");
        assertEq(usdB.balanceOf(finalReceiver), leg.amount, "stable fallback not delivered");
        assertEq(usdB.balanceOf(address(routerB)), 0, "stable stranded after fallback");
        assertTrue(routerB.finalized(leg.id), "finalize should be recorded on fallback");
    }

    /// THE regression. `finalize` is permissionless, so the pre-fix router let
    /// anyone manufacture the fallback condition — swap the `finalToken` reserve
    /// below the required output, call `finalize` — and force the user to take the
    /// carrier stable instead of the token they signed for. One transaction, and
    /// the idempotency guard meant there was no second attempt after the reserve
    /// recovered. The user's signed `finalMinOut` was never consulted.
    function test_Finalize_AGriefedReserveDoesNotDowngradeTheUser() public {
        vm.chainId(CHAIN_B);
        poolB.withdrawLiquidity(address(tt), 1_000_000e18 - 1e18, address(this)); // grief

        Leg memory leg = _sourceLeg(1e18, address(tt), 0);
        vm.chainId(CHAIN_B);
        gateB.claim(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce,
            leg.receiver, leg.autoParams, leg.nativeSender, _sign(v1pk, leg.id)
        );

        // The attacker's finalize achieves nothing.
        vm.prank(address(0xBAD));
        routerB.finalize(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce, leg.receiver, leg.autoParams, leg.nativeSender
        );
        assertFalse(routerB.finalized(leg.id), "attacker must not settle the transfer");
        assertEq(usdB.balanceOf(finalReceiver), 0, "attacker must not force the stable out");

        // The reserve is refilled inside the window, and the user gets the token
        // they actually asked for.
        _seed(poolB, tt, 1_000_000e18);
        routerB.finalize(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce, leg.receiver, leg.autoParams, leg.nativeSender
        );
        assertGt(tt.balanceOf(finalReceiver), 0, "the real swap must complete once possible");
        assertEq(usdB.balanceOf(finalReceiver), 0, "no stable downgrade");
        assertTrue(routerB.finalized(leg.id));
    }

    /// Pausing the pool during an incident used to convert every in-flight
    /// cross-chain swap into a stable payout — the opposite of what a circuit
    /// breaker is for, and irreversible because `finalized` was already set.
    function test_Finalize_APausedPoolDefersRatherThanDowngrades() public {
        Leg memory leg = _sourceLeg(1e18, address(tt), 0);
        vm.chainId(CHAIN_B);
        gateB.claim(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce,
            leg.receiver, leg.autoParams, leg.nativeSender, _sign(v1pk, leg.id)
        );

        poolB.pause();
        routerB.finalize(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce, leg.receiver, leg.autoParams, leg.nativeSender
        );
        assertFalse(routerB.finalized(leg.id), "a pause must not settle anything");
        assertEq(usdB.balanceOf(finalReceiver), 0, "a pause must not force the stable out");

        poolB.unpause();
        routerB.finalize(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce, leg.receiver, leg.autoParams, leg.nativeSender
        );
        assertGt(tt.balanceOf(finalReceiver), 0, "the swap must complete after the incident");
        assertTrue(routerB.finalized(leg.id));
    }

    /// The user's own signed floor is a first-class reason to wait, not a reason
    /// to hand them a different asset.
    function test_Finalize_SlippageFloorDefersRatherThanDowngrades() public {
        // A floor far above what the pegged pool can pay for this input.
        Leg memory leg = _sourceLeg(1e18, address(tt), 1_000_000e18);
        vm.chainId(CHAIN_B);
        gateB.claim(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce,
            leg.receiver, leg.autoParams, leg.nativeSender, _sign(v1pk, leg.id)
        );

        routerB.finalize(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce, leg.receiver, leg.autoParams, leg.nativeSender
        );
        assertFalse(routerB.finalized(leg.id), "must not settle under the signed floor");
        assertEq(usdB.balanceOf(finalReceiver), 0, "must not downgrade under the signed floor");

        // Still unreachable when the window expires, so the funds come back as the
        // stable rather than stranding at the router forever — at the receiver's
        // own request.
        vm.warp(block.timestamp + routerB.FALLBACK_GRACE());
        vm.prank(finalReceiver);
        routerB.finalize(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce, leg.receiver, leg.autoParams, leg.nativeSender
        );
        assertEq(usdB.balanceOf(finalReceiver), leg.amount, "funds must never strand");
        assertTrue(routerB.finalized(leg.id));
    }

    // ------------------------------------------------------------------
    // finalToken == stable degenerate intent: deliver stable, no swap
    // ------------------------------------------------------------------
    function test_Finalize_StableIntent_DeliversStable() public {
        Leg memory leg = _sourceLeg(1e18, address(usdB), 0); // wants the stable itself

        vm.chainId(CHAIN_B);
        bytes[] memory sigs = _sign(v1pk, leg.id);
        routerB.claimAndFinalize(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce, leg.receiver, leg.autoParams, leg.nativeSender, sigs
        );
        assertEq(usdB.balanceOf(finalReceiver), leg.amount, "stable intent not delivered");
    }

    // ------------------------------------------------------------------
    // Access / config
    // ------------------------------------------------------------------
    function test_SwapAndBridge_UnconfiguredRoute_Reverts() public {
        vm.chainId(CHAIN_A);
        uint256 unknownChain = 999;
        weth.mint(user, 1e18);
        vm.startPrank(user);
        weth.approve(address(routerA), 1e18);
        vm.expectRevert(abi.encodeWithSelector(SwapRouter.RouteNotConfigured.selector, unknownChain));
        routerA.swapAndBridge(address(weth), 1e18, 0, unknownChain, address(tt), finalReceiver, 0);
        vm.stopPrank();
    }

    function test_SetRemoteRouter_OnlyOwner() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(SwapRouter.NotOwner.selector);
        routerA.setRemoteRouter(CHAIN_B, abi.encodePacked(address(0x1234)));
    }

    // ------------------------------------------------------------------
    // M-1: the try/catch fallback must not be reachable by gas starvation
    // ------------------------------------------------------------------

    /// `_deliver` wraps the destination swap in try/catch so an impossible swap
    /// falls back to delivering the stable rather than stranding funds. But
    /// `finalize` is permissionless and sets `finalized[id]` BEFORE attempting the
    /// swap, so without a gas floor anyone could call it with just enough gas that
    /// `pool.swap` runs out inside the call — the 63/64 rule leaves this frame
    /// alive to catch it — and the user silently receives the carrier stable
    /// instead of the token they asked for. There is no retry.
    ///
    /// The floor makes the catch mean "this swap is impossible", never "the caller
    /// was stingy".
    function test_Finalize_GasStarvation_IsRefused_NotSilentlyDowngraded() public {
        uint256 amountIn = 1e18;
        Leg memory leg = _sourceLeg(amountIn, address(tt), 0);

        // Deliver the stable to routerB on chain B, exactly as a keeper would.
        vm.chainId(CHAIN_B);
        gateB.claim(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce,
            leg.receiver, leg.autoParams, leg.nativeSender, _sign(v1pk, leg.id)
        );

        uint256 ttBefore = tt.balanceOf(finalReceiver);
        uint256 usdBefore = usdB.balanceOf(finalReceiver);

        // THE ATTACK: a griefer calls finalize with barely any gas.
        // `MIN_DELIVER_GAS` is checked with `gasleft()` INSIDE the call, so
        // forwarding just under it is what a starving caller achieves.
        // Assert the SPECIFIC guard fires — a bare expectRevert would also pass on
        // a plain out-of-gas, which is not what we are proving. `have` is
        // `gasleft()` and therefore not predictable, so match on the selector.
        vm.prank(address(0xBAD));
        vm.expectPartialRevert(SwapRouter.InsufficientGas.selector);
        routerB.finalize{gas: 200_000}(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce,
            leg.receiver, leg.autoParams, leg.nativeSender
        );

        // Nothing was delivered and, crucially, the idempotency guard did NOT
        // consume the transfer — a real relayer can still finalize it properly.
        assertEq(tt.balanceOf(finalReceiver), ttBefore, "no TT should move");
        assertEq(usdB.balanceOf(finalReceiver), usdBefore, "no stable downgrade");
        assertFalse(routerB.finalized(leg.id), "a starved call must not consume the transfer");

        // With adequate gas the honest path runs and the user gets their TOKEN.
        uint256 expectedTt = poolB.quote(address(usdB), address(tt), leg.amount);
        routerB.finalize(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce,
            leg.receiver, leg.autoParams, leg.nativeSender
        );
        assertTrue(routerB.finalized(leg.id), "honest finalize must complete");
        assertEq(tt.balanceOf(finalReceiver), ttBefore + expectedTt, "user must receive TT");
        assertEq(usdB.balanceOf(finalReceiver), usdBefore, "must not fall back to stable");
    }

    /// The fallback must STILL work when the swap is genuinely impossible — the
    /// gas floor must not have turned a recoverable case into a stranded one.
    function test_Finalize_GenuinelyImpossibleSwap_StillFallsBackToStable() public {
        uint256 amountIn = 1e18;
        // An unlisted final token: pool.swap reverts TokenNotListed, for real.
        MockToken unlisted = new MockToken("Nope", "NOPE", 18);
        Leg memory leg = _sourceLeg(amountIn, address(unlisted), 0);

        vm.chainId(CHAIN_B);
        gateB.claim(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce,
            leg.receiver, leg.autoParams, leg.nativeSender, _sign(v1pk, leg.id)
        );

        uint256 usdBefore = usdB.balanceOf(finalReceiver);

        // A delisting can be reversed, so the first attempt only starts the clock.
        routerB.finalize(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce,
            leg.receiver, leg.autoParams, leg.nativeSender
        );
        assertFalse(routerB.finalized(leg.id), "must not settle inside the window");

        vm.warp(block.timestamp + routerB.FALLBACK_GRACE());
        vm.prank(finalReceiver);
        routerB.finalize(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce,
            leg.receiver, leg.autoParams, leg.nativeSender
        );
        assertEq(
            usdB.balanceOf(finalReceiver),
            usdBefore + leg.amount,
            "an impossible swap must still deliver the stable rather than strand it"
        );
        assertTrue(routerB.finalized(leg.id));
    }

    // ------------------------------------------------------------------
    // L-5 / audit LOW: rescue must not take funds a pending delivery is owed
    // ------------------------------------------------------------------

    /// `rescue` is for stranded dust, but it could not tell dust from a delivery
    /// still in flight. Sweeping the stable between `claim` and `finalize` makes
    /// `finalize` revert while `executed` is already set on the Gate — so the
    /// two-phase refund cannot recover it either, and the funds are gone from both
    /// ends. The stable is therefore never swept instantly: it goes through a
    /// public 48 h schedule, and execution respects `owedStable`.
    function test_Rescue_CannotTakeStableOwedToAPendingDelivery() public {
        vm.chainId(CHAIN_B);
        poolB.withdrawLiquidity(address(tt), 1_000_000e18 - 1e18, address(this));

        Leg memory leg = _sourceLeg(1e18, address(tt), 0);
        vm.chainId(CHAIN_B);
        gateB.claim(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce,
            leg.receiver, leg.autoParams, leg.nativeSender, _sign(v1pk, leg.id)
        );
        // Defer it: the stable is now held on the user's behalf.
        vm.prank(address(0xDEAD));
        routerB.finalize(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce, leg.receiver, leg.autoParams, leg.nativeSender
        );
        assertEq(routerB.owedStable(), leg.amount, "owed not tracked");

        // The instant path refuses the stable outright, owed or not.
        vm.expectRevert(SwapRouter.StableRescueRequiresSchedule.selector);
        routerB.rescue(address(usdB), leg.amount, address(this));

        // The scheduled path matures but still cannot touch the owed balance.
        routerB.scheduleStableRescue(leg.amount, address(this));
        vm.warp(block.timestamp + routerB.STABLE_RESCUE_DELAY());
        vm.expectRevert(
            abi.encodeWithSelector(SwapRouter.RescueWouldTakeOwedFunds.selector, leg.amount, 0)
        );
        routerB.executeStableRescue();

        // Genuine dust on top of the owed balance is sweepable — after its own delay.
        usdB.mint(address(routerB), 5e6);
        routerB.scheduleStableRescue(5e6, address(this));
        vm.warp(block.timestamp + routerB.STABLE_RESCUE_DELAY());
        uint256 before = usdB.balanceOf(address(this));
        routerB.executeStableRescue();
        assertEq(usdB.balanceOf(address(this)), before + 5e6, "dust must be sweepable");
        assertEq(usdB.balanceOf(address(routerB)), leg.amount, "owed balance must be intact");

        // And the delivery still completes once the reserve is back (the pool's
        // price went stale over the four days, so the oracle refreshes it too).
        _seed(poolB, tt, 1_000_000e18);
        poolB.setPrice(address(tt), TT_PRICE);
        vm.prank(address(0xDEAD));
        routerB.finalize(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce, leg.receiver, leg.autoParams, leg.nativeSender
        );
        assertGt(tt.balanceOf(finalReceiver), 0, "delivery must still complete");
        assertEq(usdB.balanceOf(finalReceiver), 0, "no stable downgrade");
        assertEq(routerB.owedStable(), 0, "owed not cleared on settlement");
    }

    /// THE audit case. A keeper `Gate.claim`s straight into the router and nobody
    /// has called `finalize` yet, so `owedStable` knows nothing about it. The
    /// pre-fix `rescue` would have swept it as dust. Now the sweep must be
    /// announced 48 h ahead, and in that window the routine keeper retry
    /// finalizes the transfer — after which there is nothing free to take.
    function test_Rescue_ScheduledStable_ProtectsAClaimedButUnobservedTransfer() public {
        Leg memory leg = _sourceLeg(1e18, address(tt), 0);
        vm.chainId(CHAIN_B);
        gateB.claim(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce,
            leg.receiver, leg.autoParams, leg.nativeSender, _sign(v1pk, leg.id)
        );
        assertEq(routerB.owedStable(), 0, "an unobserved claim is invisible to owedStable");
        assertEq(usdB.balanceOf(address(routerB)), leg.amount);

        // The owner mistakes the whole balance for dust.
        routerB.scheduleStableRescue(leg.amount, address(this));
        (uint256 amt, address to, uint256 readyAt) = routerB.pendingStableRescue();
        assertEq(amt, leg.amount);
        assertEq(to, address(this));
        assertEq(readyAt, block.timestamp + 48 hours);

        // Not yet.
        vm.expectRevert(abi.encodeWithSelector(SwapRouter.StableRescueNotReady.selector, readyAt));
        routerB.executeStableRescue();

        // Inside the window the keeper's retry loop delivers the user their TT.
        vm.warp(block.timestamp + 1 hours);
        vm.prank(address(0xDEAD));
        routerB.finalize(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce, leg.receiver, leg.autoParams, leg.nativeSender
        );
        assertEq(tt.balanceOf(finalReceiver), 1590e18, "user must be paid in TT");

        // The matured sweep finds nothing free and cannot pay itself from the next
        // transfer's liquidity.
        vm.warp(readyAt);
        vm.expectRevert(
            abi.encodeWithSelector(SwapRouter.RescueWouldTakeOwedFunds.selector, leg.amount, 0)
        );
        routerB.executeStableRescue();
    }

    function test_Rescue_ScheduledStable_ExpiresAfterTheWindow() public {
        vm.chainId(CHAIN_B);
        usdB.mint(address(routerB), 7e6); // genuine dust
        routerB.scheduleStableRescue(7e6, address(this));
        (,, uint256 readyAt) = routerB.pendingStableRescue();

        vm.warp(readyAt + routerB.STABLE_RESCUE_WINDOW() + 1);
        vm.expectRevert(abi.encodeWithSelector(SwapRouter.StableRescueExpired.selector, readyAt));
        routerB.executeStableRescue();

        // Re-scheduling restarts the clock and then works.
        routerB.scheduleStableRescue(7e6, address(this));
        vm.warp(block.timestamp + routerB.STABLE_RESCUE_DELAY());
        routerB.executeStableRescue();
        assertEq(usdB.balanceOf(address(routerB)), 0, "dust must be swept");
        (,, uint256 cleared) = routerB.pendingStableRescue();
        assertEq(cleared, 0, "schedule must be consumed");

        vm.expectRevert(SwapRouter.StableRescueNotScheduled.selector);
        routerB.executeStableRescue();
    }

    function test_Rescue_ScheduledStable_GuardianCanCancel_StrangerCannot() public {
        vm.chainId(CHAIN_B);
        address g = address(0x6A4D);
        routerB.setGuardian(g);
        routerB.scheduleStableRescue(1e6, address(this));

        vm.prank(address(0xBAD));
        vm.expectRevert(SwapRouter.NotAuthorized.selector);
        routerB.cancelStableRescue();

        vm.prank(g);
        routerB.cancelStableRescue();
        (,, uint256 readyAt) = routerB.pendingStableRescue();
        assertEq(readyAt, 0, "cancel must clear the schedule");

        vm.expectRevert(SwapRouter.StableRescueNotScheduled.selector);
        routerB.cancelStableRescue();

        // Only the owner schedules or executes.
        vm.prank(g);
        vm.expectRevert(SwapRouter.NotOwner.selector);
        routerB.scheduleStableRescue(1e6, g);
        vm.prank(g);
        vm.expectRevert(SwapRouter.NotOwner.selector);
        routerB.executeStableRescue();
    }

    /// Non-stable tokens are not held on anyone's behalf and sweep instantly.
    function test_Rescue_NonStableSweepsInstantly() public {
        vm.chainId(CHAIN_B);
        tt.mint(address(routerB), 3e18);
        routerB.rescue(address(tt), 3e18, address(this));
        assertEq(tt.balanceOf(address(routerB)), 0);

        vm.prank(address(0xBAD));
        vm.expectRevert(SwapRouter.NotOwner.selector);
        routerB.rescue(address(tt), 1, address(0xBAD));
    }

    function test_SetGuardian_OnlyOwner() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(SwapRouter.NotOwner.selector);
        routerB.setGuardian(address(0xBAD));
        routerB.setGuardian(address(0x6A4D));
        assertEq(routerB.guardian(), address(0x6A4D));
    }

    /// A transfer that settles on the first attempt never becomes "owed" at all.
    function test_Rescue_AStraightThroughDeliveryOwesNothing() public {
        Leg memory leg = _sourceLeg(1e18, address(tt), 0);
        vm.chainId(CHAIN_B);
        routerB.claimAndFinalize(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce,
            leg.receiver, leg.autoParams, leg.nativeSender, _sign(v1pk, leg.id)
        );
        assertEq(routerB.owedStable(), 0, "a straight-through delivery owes nothing");
        assertTrue(routerB.finalized(leg.id));
    }

    /// ...and the stable fallback clears the debt the deferral created, so a
    /// long-dead corridor does not permanently shrink what `rescue` can reach.
    function test_Rescue_TheStableFallbackClearsTheDebt() public {
        vm.chainId(CHAIN_B);
        (uint256 ttReserve,) = poolB.maxSwapOut(address(tt));
        poolB.withdrawLiquidity(address(tt), ttReserve, address(this));

        Leg memory leg = _sourceLeg(1e18, address(tt), 0);
        vm.chainId(CHAIN_B);
        routerB.claimAndFinalize(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce,
            leg.receiver, leg.autoParams, leg.nativeSender, _sign(v1pk, leg.id)
        );
        assertEq(routerB.owedStable(), leg.amount, "deferred delivery must be owed");

        vm.warp(block.timestamp + routerB.FALLBACK_GRACE());
        routerB.finalize(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce,
            leg.receiver, leg.autoParams, leg.nativeSender
        );
        assertEq(routerB.owedStable(), 0, "fallback must clear the debt");
        assertEq(usdB.balanceOf(finalReceiver), leg.amount, "fallback must pay out");
    }

    // ------------------------------------------------------------------
    // M-7: the stable fallback is the receiver's (or governance's) to take
    // ------------------------------------------------------------------

    function _args(Leg memory leg) internal pure returns (Sandwicher.Args memory a) {
        a = Sandwicher.Args({
            debridgeId: leg.debridgeId,
            amount: leg.amount,
            chainIdFrom: CHAIN_A,
            nonce: leg.nonce,
            receiver: leg.receiver,
            autoParams: leg.autoParams,
            nativeSender: leg.nativeSender
        });
    }

    function _finalizeAs(address who, Leg memory leg) internal {
        vm.prank(who);
        routerB.finalize(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce, leg.receiver, leg.autoParams, leg.nativeSender
        );
    }

    /// Claim on B and hold the TT reserve below what the transfer needs.
    function _claimedAndBlocked() internal returns (Leg memory leg) {
        vm.chainId(CHAIN_B);
        poolB.withdrawLiquidity(address(tt), 1_000_000e18 - 1e18, address(this)); // leave 1 TT
        leg = _sourceLeg(1e18, address(tt), 0); // wants 1590 TT
        vm.chainId(CHAIN_B);
        gateB.claim(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce,
            leg.receiver, leg.autoParams, leg.nativeSender, _sign(v1pk, leg.id)
        );
    }

    /// A stranger cannot force the stable out, not even after the grace window.
    /// The transfer merely stays deferred; the receiver can then take it.
    function test_M7_ThirdPartyCannotForceFallback_EvenAfterGrace() public {
        Leg memory leg = _claimedAndBlocked();

        _finalizeAs(address(0xBAD), leg);
        uint256 since = routerB.deferredSince(leg.id);
        assertEq(since, block.timestamp, "clock should start on a real blockage");

        vm.warp(since + routerB.FALLBACK_GRACE() + 1 days);

        vm.expectEmit(true, true, false, true);
        emit SwapRouter.FinalizeDeferred(leg.id, finalReceiver, address(tt), since + routerB.FALLBACK_GRACE());
        _finalizeAs(address(0xBAD), leg);
        assertFalse(routerB.finalized(leg.id), "a stranger must not settle the transfer");
        assertEq(usdB.balanceOf(finalReceiver), 0, "a stranger must not force the stable out");
        assertEq(usdB.balanceOf(address(routerB)), leg.amount, "stable must stay at the router");
        assertEq(routerB.owedStable(), leg.amount, "still owed");

        // A keeper is a stranger too.
        _finalizeAs(address(0xDEAD), leg);
        assertFalse(routerB.finalized(leg.id));

        // The receiver may take the stable.
        vm.expectEmit(true, true, false, true);
        emit SwapRouter.FinalizeFallback(leg.id, finalReceiver, leg.amount);
        _finalizeAs(finalReceiver, leg);
        assertTrue(routerB.finalized(leg.id));
        assertEq(usdB.balanceOf(finalReceiver), leg.amount, "receiver-initiated fallback must pay");
        assertEq(routerB.owedStable(), 0, "debt cleared");
    }

    /// The receiver is bound by the window like everyone else.
    function test_M7_ReceiverCannotFallBackInsideTheWindow() public {
        Leg memory leg = _claimedAndBlocked();
        _finalizeAs(finalReceiver, leg);
        assertFalse(routerB.finalized(leg.id), "no fallback inside the window");
        assertEq(usdB.balanceOf(finalReceiver), 0);

        vm.warp(block.timestamp + routerB.FALLBACK_GRACE() - 1);
        _finalizeAs(finalReceiver, leg);
        assertFalse(routerB.finalized(leg.id), "one second early is still inside");

        vm.warp(block.timestamp + 1);
        _finalizeAs(finalReceiver, leg);
        assertTrue(routerB.finalized(leg.id));
        assertEq(usdB.balanceOf(finalReceiver), leg.amount);
    }

    function test_M7_OwnerCanTakeFallbackAfterGrace() public {
        Leg memory leg = _claimedAndBlocked();
        _finalizeAs(address(0xDEAD), leg);
        vm.warp(block.timestamp + routerB.FALLBACK_GRACE());
        _finalizeAs(routerB.owner(), leg);
        assertTrue(routerB.finalized(leg.id));
        assertEq(usdB.balanceOf(finalReceiver), leg.amount, "owner releases to the signed receiver only");
    }

    function test_M7_GuardianCanTakeFallbackAfterGrace() public {
        address g = address(0x6A4D);
        routerB.setGuardian(g);
        Leg memory leg = _claimedAndBlocked();
        _finalizeAs(address(0xDEAD), leg);
        vm.warp(block.timestamp + routerB.FALLBACK_GRACE());

        _finalizeAs(g, leg);
        assertTrue(routerB.finalized(leg.id));
        assertEq(usdB.balanceOf(finalReceiver), leg.amount, "guardian releases to the signed receiver only");
        assertEq(usdB.balanceOf(g), 0, "guardian never receives anything");
    }

    /// The honest fallback still works: a pool paused through the whole window
    /// leaves the receiver free to take the stable rather than wait indefinitely.
    function test_M7_HonestFallback_PoolPausedThroughTheWindow() public {
        Leg memory leg = _sourceLeg(1e18, address(tt), 0);
        vm.chainId(CHAIN_B);
        gateB.claim(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce,
            leg.receiver, leg.autoParams, leg.nativeSender, _sign(v1pk, leg.id)
        );
        poolB.pause();

        _finalizeAs(address(0xDEAD), leg); // starts the clock
        vm.warp(block.timestamp + routerB.FALLBACK_GRACE());
        _finalizeAs(address(0xDEAD), leg); // keeper still cannot downgrade
        assertFalse(routerB.finalized(leg.id));

        _finalizeAs(finalReceiver, leg);
        assertTrue(routerB.finalized(leg.id));
        assertEq(usdB.balanceOf(finalReceiver), leg.amount, "stable must reach the receiver");
        assertEq(tt.balanceOf(finalReceiver), 0);
    }

    /// The attack the audit found was untested: swap-out -> finalize -> swap-back
    /// in ONE tx starts the clock at the cost of a block's worth of capital. It
    /// must not lead to a fallback later — by the attacker after the window, nor
    /// by the keeper's routine retry, which must deliver the real token.
    function test_M7_SandwichedFinalize_DoesNotLeadToAFallbackLater() public {
        Leg memory leg = _sourceLeg(1e18, address(tt), 0);
        vm.chainId(CHAIN_B);
        gateB.claim(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce,
            leg.receiver, leg.autoParams, leg.nativeSender, _sign(v1pk, leg.id)
        );

        Sandwicher atk = new Sandwicher();
        usdB.mint(address(atk), 2_000_000e6); // enough to buy the whole TT reserve
        (uint256 reserveBefore,) = poolB.maxSwapOut(address(tt));

        // Sandwich #1: starts the grace clock in a single transaction.
        atk.sandwich(poolB, address(usdB), address(tt), routerB, _args(leg));
        (uint256 reserveAfter,) = poolB.maxSwapOut(address(tt));
        assertEq(reserveAfter, reserveBefore, "reserve restored in the same tx");
        assertEq(routerB.deferredSince(leg.id), block.timestamp, "the clock was started for free");
        assertFalse(routerB.finalized(leg.id));
        assertEq(usdB.balanceOf(address(routerB)), leg.amount, "stable still held");

        // Wait out the window, then sandwich #2: the pre-fix router paid the stable
        // here. Now the stranger's call only re-defers.
        vm.warp(block.timestamp + routerB.FALLBACK_GRACE() + 1);
        atk.sandwich(poolB, address(usdB), address(tt), routerB, _args(leg));
        assertFalse(routerB.finalized(leg.id), "attacker must not settle after the window either");
        assertEq(usdB.balanceOf(finalReceiver), 0, "no stable was forced out");

        // The keeper's next retry finds the reserve intact and delivers TT — the
        // long-expired clock is irrelevant when the swap can run.
        uint256 expectedTt = poolB.quote(address(usdB), address(tt), leg.amount);
        _finalizeAs(address(0xDEAD), leg);
        assertTrue(routerB.finalized(leg.id));
        assertEq(tt.balanceOf(finalReceiver), expectedTt, "user gets the token they signed for");
        assertEq(usdB.balanceOf(finalReceiver), 0, "never the stable");
        assertEq(routerB.owedStable(), 0);
        assertEq(usdB.balanceOf(address(routerB)), 0);
    }

    /// Even the receiver's own late call delivers the TOKEN when the swap is
    /// possible at that instant; the fallback is never taken on a stale clock.
    function test_M7_ReceiverLateCall_StillDeliversTokenWhenUnblocked() public {
        Leg memory leg = _sourceLeg(1e18, address(tt), 0);
        vm.chainId(CHAIN_B);
        gateB.claim(
            leg.debridgeId, leg.amount, CHAIN_A, leg.nonce,
            leg.receiver, leg.autoParams, leg.nativeSender, _sign(v1pk, leg.id)
        );
        Sandwicher atk = new Sandwicher();
        usdB.mint(address(atk), 2_000_000e6);
        atk.sandwich(poolB, address(usdB), address(tt), routerB, _args(leg));
        assertGt(routerB.deferredSince(leg.id), 0);

        vm.warp(block.timestamp + routerB.FALLBACK_GRACE() + 1);
        _finalizeAs(finalReceiver, leg);
        assertEq(tt.balanceOf(finalReceiver), 1590e18, "unblocked swap runs even for the receiver");
        assertEq(usdB.balanceOf(finalReceiver), 0);
    }
}
