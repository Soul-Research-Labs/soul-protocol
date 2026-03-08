// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {ForkTestBase} from "../base/ForkTestBase.t.sol";
import {UniswapV3RebalanceAdapter} from "../../contracts/integrations/UniswapV3RebalanceAdapter.sol";
import {IRebalanceSwapAdapter} from "../../contracts/interfaces/IRebalanceSwapAdapter.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title UniswapV3ForkTest
 * @notice Fork tests for UniswapV3RebalanceAdapter against live Arbitrum Uniswap V3 deployment
 * @dev Run locally:  forge test --match-contract UniswapV3ForkTest -vvv
 *      Run on fork:  FORK_TESTS=true forge test --match-contract UniswapV3ForkTest -vvv
 *
 *      Requires ARBITRUM_RPC_URL env var for fork mode.
 *      In local mode, tests are skipped with vm.skip() since they need real pool state.
 */
contract UniswapV3ForkTest is ForkTestBase {
    // =========================================================================
    // Arbitrum Mainnet Addresses
    // =========================================================================

    address constant UNISWAP_V3_ROUTER =
        0xE592427A0AEce92De3Edee1F18E0157C05861564;
    address constant UNISWAP_V3_QUOTER =
        0x61fFE014bA17989E743c5F6cB21bF9697530B21e;
    address constant UNISWAP_V3_FACTORY =
        0x1F98431c8aD98523631AE4a59f267346ea31F984;
    address constant WETH_ARB = 0x82aF49447D8a07e3bd95BD0d56f35241523fBab1;
    address constant USDC_ARB = 0xaf88d065e77c8cC2239327C5EDb3A432268e5831;
    address constant USDT_ARB = 0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9;

    // =========================================================================
    // State
    // =========================================================================

    UniswapV3RebalanceAdapter adapter;

    // =========================================================================
    // Setup
    // =========================================================================

    function setUp() public override {
        super.setUp();
        _registerChain(L2Chain.Arbitrum);
        _initForks();
    }

    function _deployOnChain(L2Chain) internal override {
        // Not used — we deploy per-test
    }

    function _deployAdapter() internal {
        vm.prank(admin);
        adapter = new UniswapV3RebalanceAdapter(
            admin,
            admin,
            UNISWAP_V3_ROUTER,
            UNISWAP_V3_QUOTER,
            UNISWAP_V3_FACTORY,
            WETH_ARB
        );
        vm.prank(admin);
        adapter.setAuthorizedCaller(user, true);
    }

    // =========================================================================
    // Fork-only modifier
    // =========================================================================

    modifier forkOnly() {
        if (!useForks) {
            vm.skip(true);
        }
        _;
    }

    // =========================================================================
    // Tests
    // =========================================================================

    /// @notice Verify adapter deploys correctly against real Uniswap V3 addresses
    function test_fork_deployment() public forkOnly onChain(L2Chain.Arbitrum) {
        _deployAdapter();
        assertEq(address(adapter.swapRouter()), UNISWAP_V3_ROUTER);
        assertEq(address(adapter.quoter()), UNISWAP_V3_QUOTER);
        assertEq(address(adapter.factory()), UNISWAP_V3_FACTORY);
        assertEq(address(adapter.weth()), WETH_ARB);
    }

    /// @notice Pool existence check against live Uniswap V3 Factory
    function test_fork_isSwapSupported_WETH_USDC()
        public
        forkOnly
        onChain(L2Chain.Arbitrum)
    {
        _deployAdapter();
        bool supported = adapter.isSwapSupported(WETH_ARB, USDC_ARB);
        assertTrue(supported, "WETH/USDC pool should exist on Arbitrum");
    }

    /// @notice Pool existence check for USDT pair
    function test_fork_isSwapSupported_WETH_USDT()
        public
        forkOnly
        onChain(L2Chain.Arbitrum)
    {
        _deployAdapter();
        bool supported = adapter.isSwapSupported(WETH_ARB, USDT_ARB);
        assertTrue(supported, "WETH/USDT pool should exist on Arbitrum");
    }

    /// @notice Unsupported pair returns false
    function test_fork_isSwapSupported_invalidPair()
        public
        forkOnly
        onChain(L2Chain.Arbitrum)
    {
        _deployAdapter();
        address fakeToken = makeAddr("fakeToken");
        bool supported = adapter.isSwapSupported(WETH_ARB, fakeToken);
        assertFalse(supported, "Fake token pair should not be supported");
    }

    /// @notice Get a quote for WETH → USDC on live pools
    function test_fork_getQuote_WETH_USDC()
        public
        forkOnly
        onChain(L2Chain.Arbitrum)
    {
        _deployAdapter();
        uint256 amountIn = 1 ether;
        uint256 amountOut = adapter.getQuote(WETH_ARB, USDC_ARB, amountIn);
        // ETH price > $100 in any reasonable scenario
        assertGt(amountOut, 100e6, "WETH->USDC quote too low");
        console.log("1 WETH -> %s USDC (6 decimals)", amountOut);
    }

    /// @notice Execute a real WETH → USDC swap on forked Arbitrum
    function test_fork_swap_WETH_to_USDC()
        public
        forkOnly
        onChain(L2Chain.Arbitrum)
    {
        _deployAdapter();

        uint256 swapAmount = 0.1 ether;

        // Fund user with WETH by depositing ETH
        vm.deal(user, swapAmount + 1 ether);
        vm.startPrank(user);

        // Wrap ETH to WETH
        (bool ok, ) = WETH_ARB.call{value: swapAmount}("");
        require(ok, "WETH deposit failed");

        // Approve adapter to spend WETH
        IERC20(WETH_ARB).approve(address(adapter), swapAmount);

        // Get a quote for minAmountOut (apply 2% slippage tolerance)
        uint256 quote = adapter.getQuote(WETH_ARB, USDC_ARB, swapAmount);
        uint256 minOut = (quote * 98) / 100;

        uint256 usdcBefore = IERC20(USDC_ARB).balanceOf(user);

        // Execute swap
        uint256 amountOut = adapter.swap(
            WETH_ARB,
            USDC_ARB,
            swapAmount,
            minOut,
            user,
            block.timestamp + 300
        );

        vm.stopPrank();

        uint256 usdcAfter = IERC20(USDC_ARB).balanceOf(user);

        assertGe(amountOut, minOut, "Output below minAmountOut");
        assertEq(usdcAfter - usdcBefore, amountOut, "Balance mismatch");
        console.log("Swapped 0.1 WETH -> %s USDC", amountOut);
    }

    /// @notice Execute a real ETH → USDC swap (native ETH, adapter wraps)
    function test_fork_swap_ETH_to_USDC()
        public
        forkOnly
        onChain(L2Chain.Arbitrum)
    {
        _deployAdapter();

        uint256 swapAmount = 0.1 ether;
        vm.deal(user, swapAmount + 1 ether);

        // Get quote using WETH as tokenIn (adapter auto-wraps)
        uint256 quote = adapter.getQuote(WETH_ARB, USDC_ARB, swapAmount);
        uint256 minOut = (quote * 98) / 100;

        uint256 usdcBefore = IERC20(USDC_ARB).balanceOf(user);

        vm.prank(user);
        uint256 amountOut = adapter.swap{value: swapAmount}(
            address(0), // ETH sentinel
            USDC_ARB,
            swapAmount,
            minOut,
            user,
            block.timestamp + 300
        );

        uint256 usdcAfter = IERC20(USDC_ARB).balanceOf(user);
        assertGe(amountOut, minOut, "Output below minAmountOut");
        assertEq(usdcAfter - usdcBefore, amountOut, "Balance mismatch");
        console.log("Swapped 0.1 ETH -> %s USDC", amountOut);
    }

    /// @notice Custom fee tier override affects swap routing
    function test_fork_feeTierOverride()
        public
        forkOnly
        onChain(L2Chain.Arbitrum)
    {
        _deployAdapter();

        // Set 0.05% fee tier for WETH/USDC (the deep liquidity tier on Arbitrum)
        vm.prank(admin);
        adapter.setFeeTierOverride(WETH_ARB, USDC_ARB, 500);

        uint256 swapAmount = 0.1 ether;
        vm.deal(user, swapAmount + 1 ether);
        vm.startPrank(user);

        (bool ok, ) = WETH_ARB.call{value: swapAmount}("");
        require(ok, "WETH deposit failed");

        IERC20(WETH_ARB).approve(address(adapter), swapAmount);

        uint256 quote = adapter.getQuote(WETH_ARB, USDC_ARB, swapAmount);
        uint256 minOut = (quote * 98) / 100;

        uint256 amountOut = adapter.swap(
            WETH_ARB,
            USDC_ARB,
            swapAmount,
            minOut,
            user,
            block.timestamp + 300
        );
        vm.stopPrank();

        assertGe(
            amountOut,
            minOut,
            "Output below minAmountOut with 500 fee tier"
        );
        console.log("0.05%% fee tier swap: 0.1 WETH -> %s USDC", amountOut);
    }

    /// @notice Unauthorized caller cannot swap
    function test_fork_unauthorized_revert()
        public
        forkOnly
        onChain(L2Chain.Arbitrum)
    {
        _deployAdapter();

        vm.deal(attacker, 1 ether);
        vm.prank(attacker);
        vm.expectRevert(UniswapV3RebalanceAdapter.UnauthorizedCaller.selector);
        adapter.swap(
            WETH_ARB,
            USDC_ARB,
            0.1 ether,
            0,
            attacker,
            block.timestamp + 300
        );
    }

    /// @notice Slippage protection: unreasonable minAmountOut reverts
    function test_fork_slippage_revert()
        public
        forkOnly
        onChain(L2Chain.Arbitrum)
    {
        _deployAdapter();

        uint256 swapAmount = 0.1 ether;
        vm.deal(user, swapAmount + 1 ether);
        vm.startPrank(user);

        (bool ok, ) = WETH_ARB.call{value: swapAmount}("");
        require(ok, "WETH deposit failed");
        IERC20(WETH_ARB).approve(address(adapter), swapAmount);

        // Request absurdly high minAmountOut (1 billion USDC for 0.1 ETH)
        vm.expectRevert();
        adapter.swap(
            WETH_ARB,
            USDC_ARB,
            swapAmount,
            1_000_000_000e6,
            user,
            block.timestamp + 300
        );

        vm.stopPrank();
    }
}
