// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/crosschain/ArbitrumBridgeAdapter.sol";

contract ArbitrumBridgeFuzz is Test {
    ArbitrumBridgeAdapter public bridge;

    address public admin = address(0xA);
    address public operator = address(0xB);
    address public guardian = address(0xC);
    address public executor = address(0xD);
    address public user1 = address(0xE);
    address public treasury = address(0xF1);

    function setUp() public {
        bridge = new ArbitrumBridgeAdapter(admin);
        vm.startPrank(admin);
        bridge.grantRole(bridge.OPERATOR_ROLE(), operator);
        bridge.grantRole(bridge.GUARDIAN_ROLE(), guardian);
        bridge.grantRole(bridge.EXECUTOR_ROLE(), executor);
        bridge.setTreasury(treasury);
        vm.stopPrank();
    }

    // --- Fee Configuration ---
    function testFuzz_setBridgeFeeRejectsExcessive(uint256 fee) public {
        vm.assume(fee > 1000);
        vm.prank(operator);
        vm.expectRevert(ArbitrumBridgeAdapter.FeeTooHigh.selector);
        bridge.setBridgeFee(fee);
    }

    function testFuzz_setBridgeFeeAcceptsValid(uint256 fee) public {
        fee = bound(fee, 0, 100);
        vm.prank(operator);
        bridge.setBridgeFee(fee);
        assertEq(bridge.bridgeFee(), fee);
    }

    // --- Deposit Limits ---
    function testFuzz_setDepositLimitsValid(uint256 minAmt, uint256 maxAmt) public {
        vm.assume(minAmt > 0 && maxAmt > minAmt);
        vm.prank(operator);
        bridge.setDepositLimits(minAmt, maxAmt);
        assertEq(bridge.minDepositAmount(), minAmt);
        assertEq(bridge.maxDepositAmount(), maxAmt);
    }

    // --- Deposit Rejects Without Rollup ---
    function testFuzz_depositRevertsWithoutRollup(uint256 amount) public {
        amount = bound(amount, 1e15, 1e24);
        vm.deal(user1, amount + 1 ether);
        vm.prank(user1);
        vm.expectRevert(ArbitrumBridgeAdapter.RollupNotConfigured.selector);
        bridge.deposit{value: amount}(42161, user1, address(0), amount, 1000000, 100000000);
    }

    // --- Rollup Configuration ---
    function testFuzz_onlyOperatorCanConfigureRollup(address caller) public {
        vm.assume(caller != admin && caller != operator);
        vm.prank(caller);
        vm.expectRevert();
        bridge.configureRollup(42161, address(1), address(2), address(3), address(4), ArbitrumBridgeAdapter.RollupType(0));
    }

    // --- Token Mapping ---
    function testFuzz_mapToken(address l1Token, address l2Token, uint256 chainId, uint8 decimals) public {
        vm.assume(l1Token != address(0) && l2Token != address(0));
        vm.prank(operator);
        bridge.mapToken(l1Token, l2Token, chainId, decimals);
    }

    // --- Pause Mechanism ---
    function testFuzz_onlyGuardianCanPause(address caller) public {
        vm.assume(caller != admin && caller != guardian);
        vm.prank(caller);
        vm.expectRevert();
        bridge.pause();
    }

    function test_pauseAndUnpause() public {
        vm.prank(guardian);
        bridge.pause();
        assertTrue(bridge.paused());
        vm.prank(guardian);
        bridge.unpause();
        assertFalse(bridge.paused());
    }

    // --- Liquidity ---
    function testFuzz_provideLiquidity(uint256 amount) public {
        amount = bound(amount, 1, 100 ether);
        vm.deal(user1, amount);
        vm.prank(user1);
        bridge.provideLiquidity{value: amount}();
        assertEq(bridge.liquidityProviders(user1), amount);
    }

    function testFuzz_withdrawLiquidityReverts(uint256 amount) public {
        amount = bound(amount, 1, 100 ether);
        vm.prank(user1);
        vm.expectRevert(ArbitrumBridgeAdapter.InsufficientLiquidity.selector);
        bridge.withdrawLiquidity(amount);
    }

    // --- Fast Exit Toggle ---
    function test_guardianCanToggleFastExit() public {
        assertTrue(bridge.fastExitEnabled());
        vm.prank(guardian);
        bridge.setFastExitEnabled(false);
        assertFalse(bridge.fastExitEnabled());
        vm.prank(guardian);
        bridge.setFastExitEnabled(true);
        assertTrue(bridge.fastExitEnabled());
    }

    // --- Withdrawal Not Found ---
    function testFuzz_claimWithdrawalNotFound(bytes32 id) public {
        bytes32[] memory proof = new bytes32[](0);
        vm.prank(user1);
        vm.expectRevert(ArbitrumBridgeAdapter.WithdrawalNotFound.selector);
        bridge.claimWithdrawal(id, proof, 0);
    }

    function testFuzz_fastExitWithdrawalNotFound(bytes32 id) public {
        vm.prank(user1);
        vm.expectRevert(ArbitrumBridgeAdapter.WithdrawalNotFound.selector);
        bridge.fastExit(id);
    }

    // --- Statistics ---
    function test_initialStats() public view {
        (uint256 dc, uint256 wc, uint256 vd, uint256 vw, uint256 fe, uint256 fees) = bridge.getBridgeStats();
        assertEq(dc, 0);
        assertEq(wc, 0);
        assertEq(vd, 0);
        assertEq(vw, 0);
        assertEq(fe, 0);
        assertEq(fees, 0);
    }

    // --- Access Control ---
    function testFuzz_onlyAdminCanSetTreasury(address caller) public {
        vm.assume(caller != admin);
        vm.prank(caller);
        vm.expectRevert();
        bridge.setTreasury(address(0x999));
    }

    // --- Confirm Deposit Reverts ---
    function testFuzz_confirmDepositNotFound(bytes32 id) public {
        vm.prank(executor);
        vm.expectRevert(ArbitrumBridgeAdapter.DepositNotFound.selector);
        bridge.confirmDeposit(id);
    }

    // --- Receive ETH ---
    function testFuzz_receiveETH(uint256 amount) public {
        amount = bound(amount, 1, 10 ether);
        vm.deal(user1, amount);
        vm.prank(user1);
        (bool ok,) = address(bridge).call{value: amount}("");
        assertTrue(ok);
    }
}
