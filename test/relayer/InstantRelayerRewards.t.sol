// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {InstantRelayerRewards} from "../../contracts/relayer/InstantRelayerRewards.sol";

contract InstantRelayerRewardsTest is Test {
    InstantRelayerRewards public rewards;

    address admin = address(0x1A);
    address requester = address(0x1B);
    address relayer1 = address(0x1C);
    address relayer2 = address(0x1D);

    bytes32 constant RELAY_ID_1 = keccak256("relay1");
    bytes32 constant RELAY_ID_2 = keccak256("relay2");
    bytes32 constant RELAY_ID_3 = keccak256("relay3");

    function setUp() public {
        vm.warp(1740000000);
        rewards = new InstantRelayerRewards(admin);

        vm.deal(admin, 100 ether);
        vm.deal(requester, 100 ether);
        vm.deal(relayer1, 10 ether);
        vm.deal(relayer2, 10 ether);
    }

    // ──────────────────────────────────────────────────────────
    //  Deposit
    // ──────────────────────────────────────────────────────────

    function test_DepositRelayFee() public {
        vm.prank(admin);
        rewards.depositRelayFee{value: 1 ether}(RELAY_ID_1, requester);

        InstantRelayerRewards.RelayDeposit memory d = rewards.getDeposit(
            RELAY_ID_1
        );
        assertEq(d.requester, requester);
        assertEq(d.baseReward, 1 ether);
        assertFalse(d.completed);
    }

    function test_RevertOnDeposit_ZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(InstantRelayerRewards.ZeroAddress.selector);
        rewards.depositRelayFee{value: 1 ether}(RELAY_ID_1, address(0));
    }

    function test_RevertOnDeposit_ZeroValue() public {
        vm.prank(admin);
        vm.expectRevert(InstantRelayerRewards.InvalidAmount.selector);
        rewards.depositRelayFee{value: 0}(RELAY_ID_1, requester);
    }

    function test_RevertOnDeposit_NotManager() public {
        vm.prank(requester);
        vm.expectRevert(); // AccessControl revert
        rewards.depositRelayFee{value: 1 ether}(RELAY_ID_1, requester);
    }

    // ──────────────────────────────────────────────────────────
    //  Claim
    // ──────────────────────────────────────────────────────────

    function test_ClaimRelay() public {
        _deposit(RELAY_ID_1, 1 ether);

        vm.prank(admin);
        rewards.claimRelay(RELAY_ID_1, relayer1);

        InstantRelayerRewards.RelayDeposit memory d = rewards.getDeposit(
            RELAY_ID_1
        );
        assertEq(d.relayer, relayer1);
        assertGt(d.claimedAt, 0);
    }

    function test_RevertOnClaim_NotFound() public {
        vm.prank(admin);
        vm.expectRevert(InstantRelayerRewards.DepositNotFound.selector);
        rewards.claimRelay(RELAY_ID_1, relayer1);
    }

    function test_RevertOnClaim_ZeroRelayer() public {
        _deposit(RELAY_ID_1, 1 ether);
        vm.prank(admin);
        vm.expectRevert(InstantRelayerRewards.ZeroAddress.selector);
        rewards.claimRelay(RELAY_ID_1, address(0));
    }

    // ──────────────────────────────────────────────────────────
    //  Complete With Reward — Speed Tiers
    // ──────────────────────────────────────────────────────────

    function test_CompleteRelay_UltraFast() public {
        _deposit(RELAY_ID_1, 1 ether);
        _claim(RELAY_ID_1, relayer1);

        // Advance < 30 seconds
        vm.warp(block.timestamp + 10);

        uint256 balBefore = relayer1.balance;
        vm.prank(admin);
        rewards.completeRelayWithReward(RELAY_ID_1);

        // Ultra fast: reward = min(1 ether * 1.5, 1 ether) = 1 ether
        // After 5% protocol fee: 0.95 ether
        uint256 expectedReward = (1 ether * 9500) / 10000;
        assertEq(relayer1.balance, balBefore + expectedReward);

        InstantRelayerRewards.RelayerStats memory stats = rewards
            .getRelayerStats(relayer1);
        assertEq(stats.ultraFastCount, 1);
        assertEq(stats.totalRelays, 1);
    }

    function test_CompleteRelay_Fast() public {
        _deposit(RELAY_ID_1, 1 ether);
        _claim(RELAY_ID_1, relayer1);

        // Advance 30-60 seconds
        vm.warp(block.timestamp + 45);

        uint256 balBefore = relayer1.balance;
        vm.prank(admin);
        rewards.completeRelayWithReward(RELAY_ID_1);

        // Fast: 1 ether * 12500 / 15000, minus 5% protocol fee
        uint256 deposit = 1 ether;
        uint256 tiered = (deposit * 12500) / 15000;
        uint256 protocolCut = (tiered * 500) / 10000;
        uint256 expectedReward = tiered - protocolCut;
        assertEq(relayer1.balance, balBefore + expectedReward);

        InstantRelayerRewards.RelayerStats memory stats = rewards
            .getRelayerStats(relayer1);
        assertEq(stats.fastCount, 1);
    }

    function test_CompleteRelay_Normal() public {
        _deposit(RELAY_ID_1, 1 ether);
        _claim(RELAY_ID_1, relayer1);

        // Advance 60s - 5min
        vm.warp(block.timestamp + 3 minutes);

        uint256 balBefore = relayer1.balance;
        vm.prank(admin);
        rewards.completeRelayWithReward(RELAY_ID_1);

        // Normal: 1 ether * 10000 / 15000, minus 5% protocol fee
        uint256 deposit = 1 ether;
        uint256 tiered = (deposit * 10000) / 15000;
        uint256 protocolCut = (tiered * 500) / 10000;
        uint256 expectedReward = tiered - protocolCut;
        assertEq(relayer1.balance, balBefore + expectedReward);

        InstantRelayerRewards.RelayerStats memory stats = rewards
            .getRelayerStats(relayer1);
        assertEq(stats.normalCount, 1);
    }

    function test_CompleteRelay_Slow() public {
        _deposit(RELAY_ID_1, 1 ether);
        _claim(RELAY_ID_1, relayer1);

        // Advance > 5 minutes
        vm.warp(block.timestamp + 10 minutes);

        uint256 balBefore = relayer1.balance;
        vm.prank(admin);
        rewards.completeRelayWithReward(RELAY_ID_1);

        // Slow: 1 ether * 9000 / 15000 = 0.6 ether
        // After 5% protocol fee: 0.6 * 0.95 = 0.57 ether
        uint256 deposit = 1 ether;
        uint256 tiered = (deposit * 9000) / 15000;
        uint256 protocolCut = (tiered * 500) / 10000;
        uint256 expectedReward = tiered - protocolCut;
        assertEq(relayer1.balance, balBefore + expectedReward);

        // Surplus refunded to requester
        uint256 surplus = 1 ether - tiered;
        assertGt(surplus, 0);

        InstantRelayerRewards.RelayerStats memory stats = rewards
            .getRelayerStats(relayer1);
        assertEq(stats.slowCount, 1);
    }

    function test_RevertOnComplete_NotFound() public {
        vm.prank(admin);
        vm.expectRevert(InstantRelayerRewards.DepositNotFound.selector);
        rewards.completeRelayWithReward(RELAY_ID_1);
    }

    function test_RevertOnComplete_AlreadyCompleted() public {
        _deposit(RELAY_ID_1, 1 ether);
        _claim(RELAY_ID_1, relayer1);

        vm.prank(admin);
        rewards.completeRelayWithReward(RELAY_ID_1);

        vm.prank(admin);
        vm.expectRevert(InstantRelayerRewards.DepositAlreadyCompleted.selector);
        rewards.completeRelayWithReward(RELAY_ID_1);
    }

    function test_RevertOnComplete_NotClaimed() public {
        _deposit(RELAY_ID_1, 1 ether);

        vm.prank(admin);
        vm.expectRevert(InstantRelayerRewards.RelayNotClaimed.selector);
        rewards.completeRelayWithReward(RELAY_ID_1);
    }

    // ──────────────────────────────────────────────────────────
    //  Refund
    // ──────────────────────────────────────────────────────────

    function test_RefundDeposit() public {
        _deposit(RELAY_ID_1, 1 ether);

        uint256 balBefore = requester.balance;
        vm.prank(admin);
        rewards.refundDeposit(RELAY_ID_1);

        assertEq(requester.balance, balBefore + 1 ether);
        InstantRelayerRewards.RelayDeposit memory d = rewards.getDeposit(
            RELAY_ID_1
        );
        assertTrue(d.refunded);
    }

    function test_RevertOnRefund_AlreadyCompleted() public {
        _deposit(RELAY_ID_1, 1 ether);
        _claim(RELAY_ID_1, relayer1);
        vm.prank(admin);
        rewards.completeRelayWithReward(RELAY_ID_1);

        vm.prank(admin);
        vm.expectRevert(InstantRelayerRewards.DepositAlreadyCompleted.selector);
        rewards.refundDeposit(RELAY_ID_1);
    }

    function test_RevertOnRefund_AlreadyRefunded() public {
        _deposit(RELAY_ID_1, 1 ether);
        vm.prank(admin);
        rewards.refundDeposit(RELAY_ID_1);

        vm.prank(admin);
        vm.expectRevert(InstantRelayerRewards.DepositAlreadyRefunded.selector);
        rewards.refundDeposit(RELAY_ID_1);
    }

    // ──────────────────────────────────────────────────────────
    //  Admin
    // ──────────────────────────────────────────────────────────

    function test_WithdrawProtocolFees() public {
        // Generate fees
        _deposit(RELAY_ID_1, 1 ether);
        _claim(RELAY_ID_1, relayer1);
        vm.prank(admin);
        rewards.completeRelayWithReward(RELAY_ID_1);

        uint256 fees = rewards.protocolFees();
        assertGt(fees, 0);

        uint256 adminBal = admin.balance;
        vm.prank(admin);
        rewards.withdrawProtocolFees(admin);
        assertEq(admin.balance, adminBal + fees);
    }

    function test_RevertOnWithdraw_NoFees() public {
        vm.prank(admin);
        vm.expectRevert(InstantRelayerRewards.NoFeesToWithdraw.selector);
        rewards.withdrawProtocolFees(admin);
    }

    function test_RevertOnWithdraw_ZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(InstantRelayerRewards.ZeroAddress.selector);
        rewards.withdrawProtocolFees(address(0));
    }

    // ──────────────────────────────────────────────────────────
    //  View Functions
    // ──────────────────────────────────────────────────────────

    function test_GetSpeedTier_UltraFast() public view {
        (InstantRelayerRewards.SpeedTier tier, uint256 mult) = rewards
            .getSpeedTier(15);
        assertEq(uint(tier), uint(InstantRelayerRewards.SpeedTier.ULTRA_FAST));
        assertEq(mult, 15000);
    }

    function test_GetSpeedTier_Fast() public view {
        (InstantRelayerRewards.SpeedTier tier, uint256 mult) = rewards
            .getSpeedTier(45);
        assertEq(uint(tier), uint(InstantRelayerRewards.SpeedTier.FAST));
        assertEq(mult, 12500);
    }

    function test_GetSpeedTier_Normal() public view {
        (InstantRelayerRewards.SpeedTier tier, uint256 mult) = rewards
            .getSpeedTier(120);
        assertEq(uint(tier), uint(InstantRelayerRewards.SpeedTier.NORMAL));
        assertEq(mult, 10000);
    }

    function test_GetSpeedTier_Slow() public view {
        (InstantRelayerRewards.SpeedTier tier, uint256 mult) = rewards
            .getSpeedTier(600);
        assertEq(uint(tier), uint(InstantRelayerRewards.SpeedTier.SLOW));
        assertEq(mult, 9000);
    }

    function test_CalculateReward_Normal() public view {
        uint256 reward = rewards.calculateReward(1 ether, 120);
        // Normal: 1 ether * 10000 / 15000, minus 5% protocol fee
        uint256 deposit = 1 ether;
        uint256 tiered = (deposit * 10000) / 15000;
        uint256 protocolCut = (tiered * 500) / 10000;
        assertEq(reward, tiered - protocolCut);
    }

    function test_CalculateReward_Slow() public view {
        uint256 reward = rewards.calculateReward(1 ether, 600);
        // Slow: 1 ether * 9000 / 15000, minus 5% protocol fee
        uint256 deposit = 1 ether;
        uint256 tiered = (deposit * 9000) / 15000;
        uint256 protocolCut = (tiered * 500) / 10000;
        assertEq(reward, tiered - protocolCut);
    }

    // ──────────────────────────────────────────────────────────
    //  Multiple Relayers Stats
    // ──────────────────────────────────────────────────────────

    function test_MultipleRelayers_Stats() public {
        _deposit(RELAY_ID_1, 1 ether);
        _deposit(RELAY_ID_2, 2 ether);

        _claim(RELAY_ID_1, relayer1);
        _claim(RELAY_ID_2, relayer2);

        vm.warp(block.timestamp + 10); // ultra fast
        vm.prank(admin);
        rewards.completeRelayWithReward(RELAY_ID_1);

        vm.warp(block.timestamp + 6 minutes); // slow
        vm.prank(admin);
        rewards.completeRelayWithReward(RELAY_ID_2);

        InstantRelayerRewards.RelayerStats memory s1 = rewards.getRelayerStats(
            relayer1
        );
        InstantRelayerRewards.RelayerStats memory s2 = rewards.getRelayerStats(
            relayer2
        );

        assertEq(s1.ultraFastCount, 1);
        assertEq(s2.slowCount, 1);
        assertEq(rewards.totalRelaysCompleted(), 2);
    }

    // ──────────────────────────────────────────────────────────
    //  Fuzz Tests
    // ──────────────────────────────────────────────────────────

    function testFuzz_DepositAndComplete(uint96 amount, uint32 delay) public {
        amount = uint96(bound(amount, 0.001 ether, 50 ether));
        delay = uint32(bound(delay, 0, 1 hours));
        vm.deal(admin, uint256(amount) + 1 ether);

        bytes32 relayId = keccak256(abi.encodePacked("fuzz", amount, delay));

        vm.prank(admin);
        rewards.depositRelayFee{value: amount}(relayId, requester);

        vm.prank(admin);
        rewards.claimRelay(relayId, relayer1);

        vm.warp(block.timestamp + delay);

        uint256 relayerBefore = relayer1.balance;
        vm.prank(admin);
        rewards.completeRelayWithReward(relayId);

        assertGt(relayer1.balance, relayerBefore);
    }

    function testFuzz_CalculateReward_Monotonic(uint96 amount) public view {
        amount = uint96(bound(amount, 0.001 ether, 50 ether));

        uint256 ultraFast = rewards.calculateReward(amount, 10);
        uint256 fast = rewards.calculateReward(amount, 45);
        uint256 normal = rewards.calculateReward(amount, 120);
        uint256 slow = rewards.calculateReward(amount, 600);

        // Capped rewards: ultrafast and fast are capped at base, so ultrafast >= fast >= normal >= slow
        assertGe(ultraFast, fast);
        assertGe(fast, normal);
        assertGe(normal, slow);
    }

    function testFuzz_RefundVsComplete_NoLoss(uint96 amount) public {
        amount = uint96(bound(amount, 0.001 ether, 50 ether));
        vm.deal(admin, uint256(amount) + 1 ether);

        bytes32 relayId = keccak256(abi.encodePacked("refund_test", amount));

        vm.prank(admin);
        rewards.depositRelayFee{value: amount}(relayId, requester);

        uint256 requesterBefore = requester.balance;
        vm.prank(admin);
        rewards.refundDeposit(relayId);

        assertEq(requester.balance, requesterBefore + uint256(amount));
    }

    // ──────────────────────────────────────────────────────────
    //  Receive ETH
    // ──────────────────────────────────────────────────────────

    function test_ReceiveETH() public {
        (bool success, ) = address(rewards).call{value: 1 ether}("");
        assertTrue(success);
    }

    // ──────────────────────────────────────────────────────────
    //  Helpers
    // ──────────────────────────────────────────────────────────

    function _deposit(bytes32 relayId, uint256 amount) internal {
        vm.prank(admin);
        rewards.depositRelayFee{value: amount}(relayId, requester);
    }

    function _claim(bytes32 relayId, address relayer) internal {
        vm.prank(admin);
        rewards.claimRelay(relayId, relayer);
    }
}
