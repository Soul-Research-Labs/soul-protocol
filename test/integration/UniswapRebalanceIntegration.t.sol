// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {CrossChainLiquidityVault} from "../../contracts/bridge/CrossChainLiquidityVault.sol";
import {ICrossChainLiquidityVault} from "../../contracts/interfaces/ICrossChainLiquidityVault.sol";
import {IRebalanceSwapAdapter} from "../../contracts/interfaces/IRebalanceSwapAdapter.sol";
import {MockRebalanceSwapAdapter} from "../../contracts/mocks/MockRebalanceSwapAdapter.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @notice Minimal ERC20 for testing
contract MockToken is ERC20 {
    constructor(
        string memory name_,
        string memory symbol_
    ) ERC20(name_, symbol_) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/**
 * @title UniswapRebalanceIntegrationTest
 * @notice Tests for settlement-with-swap (Uniswap rebalancing) in CrossChainLiquidityVault
 *
 * TESTS COVER:
 * 1. executeSettlementWithSwap — ETH outflow swapped to ERC20
 * 2. executeSettlementWithSwap — ERC20 outflow swapped to different ERC20
 * 3. receiveSettlementWithSwap — ERC20 inflow swapped to ETH
 * 4. receiveSettlementWithSwap — ETH inflow swapped to ERC20
 * 5. receiveSettlementWithSwap — ERC20 to ERC20
 * 6. Slippage protection enforcement
 * 7. Deadline enforcement
 * 8. Access control (SETTLER_ROLE required)
 * 9. Revert when adapter not set
 * 10. setRebalanceAdapter admin function
 */
contract UniswapRebalanceIntegrationTest is Test {
    CrossChainLiquidityVault public vault;
    MockRebalanceSwapAdapter public mockAdapter;
    MockToken public usdc;
    MockToken public dai;

    address public admin = makeAddr("admin");
    address public operator = makeAddr("operator");
    address public guardian = makeAddr("guardian");
    address public privacyHub = makeAddr("privacyHub");
    address public lp1 = makeAddr("lp1");
    address public recipient = makeAddr("recipient");
    address public attacker = makeAddr("attacker");

    uint256 constant SOURCE_CHAIN_ID = 10; // Optimism
    uint256 constant DEST_CHAIN_ID = 42161; // Arbitrum

    function setUp() public {
        vault = new CrossChainLiquidityVault(
            admin,
            operator,
            guardian,
            privacyHub,
            5000 // 50% LP fee share
        );

        usdc = new MockToken("USD Coin", "USDC");
        dai = new MockToken("DAI Stablecoin", "DAI");

        // Deploy mock adapter at 95% exchange rate (5% slippage simulation)
        mockAdapter = new MockRebalanceSwapAdapter(9500);

        // Fund LP
        vm.deal(lp1, 200 ether);
        usdc.mint(lp1, 10_000e18);
        dai.mint(lp1, 10_000e18);

        // Fund adapter with output tokens for swaps
        vm.deal(address(mockAdapter), 10_000 ether);
        usdc.mint(address(mockAdapter), 100_000e18);
        dai.mint(address(mockAdapter), 100_000e18);

        // Register remote vaults
        vm.startPrank(operator);
        vault.registerRemoteVault(SOURCE_CHAIN_ID, makeAddr("remoteVaultOpt"));
        vault.registerRemoteVault(DEST_CHAIN_ID, makeAddr("remoteVaultArb"));
        // Set rebalance adapter
        vault.setRebalanceAdapter(address(mockAdapter));
        vm.stopPrank();
    }

    // =========================================================================
    // ADMIN: setRebalanceAdapter
    // =========================================================================

    function test_setRebalanceAdapter() public {
        address newAdapter = makeAddr("newAdapter");

        vm.prank(operator);
        vault.setRebalanceAdapter(newAdapter);

        assertEq(address(vault.rebalanceAdapter()), newAdapter);
    }

    function test_setRebalanceAdapter_emitsEvent() public {
        address newAdapter = makeAddr("newAdapter");

        vm.prank(operator);
        vm.expectEmit(true, true, false, false);
        emit CrossChainLiquidityVault.RebalanceAdapterUpdated(
            address(mockAdapter),
            newAdapter
        );
        vault.setRebalanceAdapter(newAdapter);
    }

    function test_setRebalanceAdapter_onlyOperator() public {
        vm.prank(attacker);
        vm.expectRevert();
        vault.setRebalanceAdapter(makeAddr("adapter"));
    }

    function test_setRebalanceAdapter_zeroDisablesSwaps() public {
        vm.prank(operator);
        vault.setRebalanceAdapter(address(0));
        assertEq(address(vault.rebalanceAdapter()), address(0));
    }

    // =========================================================================
    // executeSettlementWithSwap — ETH outflow → ERC20
    // =========================================================================

    function test_executeSettlementWithSwap_ETH_to_ERC20() public {
        // Setup: LP deposits ETH, create outflow situation
        _depositAndCreateOutflow_ETH(5 ether);

        // Propose settlement (outflow: we owe dest chain)
        vm.prank(operator);
        bytes32 batchId = vault.proposeSettlement(DEST_CHAIN_ID, address(0));

        // Execute with swap: ETH → USDC
        uint256 expectedOut = (5 ether * 9500) / 10000; // 4.75 ETH worth of USDC
        uint256 settlerBalBefore = usdc.balanceOf(operator);

        vm.prank(operator);
        vault.executeSettlementWithSwap(
            batchId,
            address(usdc),
            expectedOut,
            block.timestamp + 1 hours
        );

        // Settler received USDC output
        assertEq(
            usdc.balanceOf(operator) - settlerBalBefore,
            expectedOut
        );

        // Adapter was called
        assertEq(mockAdapter.swapCallCount(), 1);

        // Net flows reset
        (uint256 netAmount, ) = vault.getNetSettlement(
            DEST_CHAIN_ID,
            address(0)
        );
        assertEq(netAmount, 0);
    }

    // =========================================================================
    // executeSettlementWithSwap — ERC20 outflow → different ERC20
    // =========================================================================

    function test_executeSettlementWithSwap_ERC20_to_ERC20() public {
        // Setup: LP deposits USDC, create outflow
        _depositAndCreateOutflow_ERC20(usdc, 1000e18);

        vm.prank(operator);
        bytes32 batchId = vault.proposeSettlement(DEST_CHAIN_ID, address(usdc));

        uint256 expectedOut = (1000e18 * 9500) / 10000; // 950 DAI
        uint256 settlerBalBefore = dai.balanceOf(operator);

        vm.prank(operator);
        vault.executeSettlementWithSwap(
            batchId,
            address(dai),
            expectedOut,
            block.timestamp + 1 hours
        );

        assertEq(
            dai.balanceOf(operator) - settlerBalBefore,
            expectedOut
        );
        assertEq(mockAdapter.swapCallCount(), 1);
    }

    // =========================================================================
    // receiveSettlementWithSwap — ERC20 inflow → ETH
    // =========================================================================

    function test_receiveSettlementWithSwap_ERC20_to_ETH() public {
        uint256 amount = 1000e18;
        uint256 expectedOut = (amount * 9500) / 10000;

        // Fund settler with USDC for the settlement inflow
        usdc.mint(operator, amount);

        uint256 vaultETHBefore = vault.totalETH();

        vm.startPrank(operator);
        usdc.approve(address(vault), amount);
        vault.receiveSettlementWithSwap(
            SOURCE_CHAIN_ID,
            address(usdc),
            amount,
            address(0), // target = ETH
            expectedOut,
            block.timestamp + 1 hours
        );
        vm.stopPrank();

        // Vault's ETH pool increased by swap output
        assertEq(vault.totalETH() - vaultETHBefore, expectedOut);
        assertEq(mockAdapter.swapCallCount(), 1);
    }

    // =========================================================================
    // receiveSettlementWithSwap — ETH inflow → ERC20
    // =========================================================================

    function test_receiveSettlementWithSwap_ETH_to_ERC20() public {
        uint256 amount = 5 ether;
        uint256 expectedOut = (amount * 9500) / 10000;

        uint256 vaultUSDCBefore = vault.totalTokens(address(usdc));

        vm.deal(operator, amount);
        vm.prank(operator);
        vault.receiveSettlementWithSwap{value: amount}(
            SOURCE_CHAIN_ID,
            address(0), // ETH in
            amount,
            address(usdc), // target = USDC
            expectedOut,
            block.timestamp + 1 hours
        );

        assertEq(
            vault.totalTokens(address(usdc)) - vaultUSDCBefore,
            expectedOut
        );
    }

    // =========================================================================
    // receiveSettlementWithSwap — ERC20 → ERC20
    // =========================================================================

    function test_receiveSettlementWithSwap_ERC20_to_ERC20() public {
        uint256 amount = 500e18;
        uint256 expectedOut = (amount * 9500) / 10000;

        usdc.mint(operator, amount);

        vm.startPrank(operator);
        usdc.approve(address(vault), amount);
        vault.receiveSettlementWithSwap(
            SOURCE_CHAIN_ID,
            address(usdc),
            amount,
            address(dai),
            expectedOut,
            block.timestamp + 1 hours
        );
        vm.stopPrank();

        assertEq(vault.totalTokens(address(dai)), expectedOut);
    }

    // =========================================================================
    // SLIPPAGE PROTECTION
    // =========================================================================

    function test_executeSettlementWithSwap_slippageReverts() public {
        _depositAndCreateOutflow_ETH(5 ether);

        vm.prank(operator);
        bytes32 batchId = vault.proposeSettlement(DEST_CHAIN_ID, address(0));

        // Request more than adapter will output (95% rate, requesting 100%)
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                IRebalanceSwapAdapter.SlippageExceeded.selector,
                (5 ether * 9500) / 10000,
                5 ether
            )
        );
        vault.executeSettlementWithSwap(
            batchId,
            address(usdc),
            5 ether, // minAmountOut too high
            block.timestamp + 1 hours
        );
    }

    // =========================================================================
    // DEADLINE ENFORCEMENT
    // =========================================================================

    function test_executeSettlementWithSwap_deadlineReverts() public {
        _depositAndCreateOutflow_ETH(5 ether);

        vm.prank(operator);
        bytes32 batchId = vault.proposeSettlement(DEST_CHAIN_ID, address(0));

        // Set deadline in the past
        vm.prank(operator);
        vm.expectRevert(IRebalanceSwapAdapter.SwapDeadlineExpired.selector);
        vault.executeSettlementWithSwap(
            batchId,
            address(usdc),
            0,
            block.timestamp - 1 // expired
        );
    }

    // =========================================================================
    // ACCESS CONTROL
    // =========================================================================

    function test_executeSettlementWithSwap_onlySettler() public {
        _depositAndCreateOutflow_ETH(5 ether);

        vm.prank(operator);
        bytes32 batchId = vault.proposeSettlement(DEST_CHAIN_ID, address(0));

        vm.prank(attacker);
        vm.expectRevert();
        vault.executeSettlementWithSwap(
            batchId,
            address(usdc),
            0,
            block.timestamp + 1 hours
        );
    }

    function test_receiveSettlementWithSwap_onlySettler() public {
        vm.prank(attacker);
        vm.expectRevert();
        vault.receiveSettlementWithSwap(
            SOURCE_CHAIN_ID,
            address(usdc),
            100e18,
            address(0),
            0,
            block.timestamp + 1 hours
        );
    }

    // =========================================================================
    // ADAPTER NOT SET
    // =========================================================================

    function test_executeSettlementWithSwap_revertsWithoutAdapter() public {
        // Remove adapter
        vm.prank(operator);
        vault.setRebalanceAdapter(address(0));

        _depositAndCreateOutflow_ETH(5 ether);

        vm.prank(operator);
        bytes32 batchId = vault.proposeSettlement(DEST_CHAIN_ID, address(0));

        vm.prank(operator);
        vm.expectRevert(ICrossChainLiquidityVault.ZeroAddress.selector);
        vault.executeSettlementWithSwap(
            batchId,
            address(usdc),
            0,
            block.timestamp + 1 hours
        );
    }

    function test_receiveSettlementWithSwap_revertsWithoutAdapter() public {
        vm.prank(operator);
        vault.setRebalanceAdapter(address(0));

        vm.prank(operator);
        vm.expectRevert(ICrossChainLiquidityVault.ZeroAddress.selector);
        vault.receiveSettlementWithSwap(
            SOURCE_CHAIN_ID,
            address(usdc),
            100e18,
            address(0),
            0,
            block.timestamp + 1 hours
        );
    }

    // =========================================================================
    // ALREADY EXECUTED BATCH
    // =========================================================================

    function test_executeSettlementWithSwap_alreadyExecutedReverts() public {
        _depositAndCreateOutflow_ETH(5 ether);

        vm.prank(operator);
        bytes32 batchId = vault.proposeSettlement(DEST_CHAIN_ID, address(0));

        // Execute normally
        vm.prank(operator);
        vault.executeSettlement(batchId);

        // Try swap-execute same batch
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICrossChainLiquidityVault.SettlementAlreadyExecuted.selector,
                batchId
            )
        );
        vault.executeSettlementWithSwap(
            batchId,
            address(usdc),
            0,
            block.timestamp + 1 hours
        );
    }

    // =========================================================================
    // INFLOW BATCH REJECTS SWAP EXECUTE
    // =========================================================================

    function test_executeSettlementWithSwap_inflowReverts() public {
        // Disable denomination enforcement
        vm.prank(operator);
        vault.setDenominationEnforcement(false);

        // Create inflow scenario (remote chain owes us)
        vm.prank(lp1);
        vault.depositETH{value: 10 ether}();

        bytes32 requestId = keccak256("inflow-request");
        vm.prank(privacyHub);
        vault.releaseLiquidity(
            requestId,
            address(0),
            recipient,
            3 ether,
            SOURCE_CHAIN_ID
        );

        // This is an INFLOW (remote owes us), not outflow
        vm.prank(operator);
        bytes32 batchId = vault.proposeSettlement(SOURCE_CHAIN_ID, address(0));

        vm.prank(operator);
        vm.expectRevert(ICrossChainLiquidityVault.InvalidAmount.selector);
        vault.executeSettlementWithSwap(
            batchId,
            address(usdc),
            0,
            block.timestamp + 1 hours
        );
    }

    // =========================================================================
    // CHAIN NOT REGISTERED
    // =========================================================================

    function test_receiveSettlementWithSwap_chainNotRegistered() public {
        usdc.mint(operator, 100e18);

        vm.startPrank(operator);
        usdc.approve(address(vault), 100e18);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICrossChainLiquidityVault.ChainNotRegistered.selector,
                999999
            )
        );
        vault.receiveSettlementWithSwap(
            999999,
            address(usdc),
            100e18,
            address(0),
            0,
            block.timestamp + 1 hours
        );
        vm.stopPrank();
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    /**
     * @dev Create an ETH outflow scenario:
     *      1. LP deposits ETH
     *      2. Lock liquidity (source chain)
     *      3. Unlock after completion (triggers negative netFlow = outflow)
     */
    function _depositAndCreateOutflow_ETH(uint256 amount) internal {
        // Disable denomination enforcement for test flexibility
        vm.prank(operator);
        vault.setDenominationEnforcement(false);

        // LP deposits
        vm.prank(lp1);
        vault.depositETH{value: amount * 2}();

        // Lock + unlock creates outflow to DEST_CHAIN
        bytes32 requestId = keccak256("outflow-eth-request");
        vm.prank(privacyHub);
        vault.lockLiquidity(requestId, address(0), amount, DEST_CHAIN_ID);

        vm.prank(privacyHub);
        vault.unlockAfterCompletion(requestId);

        // Verify outflow exists
        (uint256 netAmount, bool isOutflow) = vault.getNetSettlement(
            DEST_CHAIN_ID,
            address(0)
        );
        assertEq(netAmount, amount);
        assertTrue(isOutflow);
    }

    /**
     * @dev Create an ERC20 outflow scenario (same pattern as ETH)
     */
    function _depositAndCreateOutflow_ERC20(
        MockToken tok,
        uint256 amount
    ) internal {
        // Disable denomination enforcement for arbitrary amounts
        vm.prank(operator);
        vault.setDenominationEnforcement(false);

        // LP deposits token
        vm.startPrank(lp1);
        tok.approve(address(vault), amount * 2);
        vault.depositToken(address(tok), amount * 2);
        vm.stopPrank();

        // Lock + unlock
        bytes32 requestId = keccak256("outflow-erc20-request");
        vm.prank(privacyHub);
        vault.lockLiquidity(
            requestId,
            address(tok),
            amount,
            DEST_CHAIN_ID
        );

        vm.prank(privacyHub);
        vault.unlockAfterCompletion(requestId);

        // Verify outflow
        (uint256 netAmount, bool isOutflow) = vault.getNetSettlement(
            DEST_CHAIN_ID,
            address(tok)
        );
        assertEq(netAmount, amount);
        assertTrue(isOutflow);
    }
}
