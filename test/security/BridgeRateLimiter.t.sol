// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {BridgeRateLimiter} from "../../contracts/security/BridgeRateLimiter.sol";

contract BridgeRateLimiterTest is Test {
    BridgeRateLimiter public limiter;
    address public admin;
    address public operator = address(0xAA01);
    address public guardian = address(0xAA02);
    address public user = address(0xCCCC);

    function setUp() public {
        admin = address(this);
        limiter = new BridgeRateLimiter(admin);
        limiter.grantRole(limiter.OPERATOR_ROLE(), operator);
        limiter.grantRole(limiter.GUARDIAN_ROLE(), guardian);

        // Raise velocity threshold so it doesn't interfere with limit tests
        // Default threshold is 100 (triggers at hourlyVolume >= 1 ether)
        limiter.setCircuitBreakerConfig(
            500 ether, // largeTransferThreshold
            100_000, // velocityThreshold (very high)
            2000, // tvlDropThreshold (20%)
            3600, // cooldownPeriod
            true // autoBreakEnabled
        );
    }

    // ======= Check Transfer Limits =======

    function test_checkTransfer_allowed() public view {
        (bool allowed, string memory reason) = limiter.checkTransfer(
            user,
            10 ether
        );
        assertTrue(allowed);
        assertEq(bytes(reason).length, 0);
    }

    function test_checkTransfer_exceedsSingleTxLimit() public view {
        (bool allowed, string memory reason) = limiter.checkTransfer(
            user,
            101 ether
        );
        assertFalse(allowed);
        assertEq(reason, "Exceeds user single tx limit");
    }

    function test_checkTransfer_exceedsGlobalSingleTxLimit() public view {
        (bool allowed, string memory reason) = limiter.checkTransfer(
            user,
            501 ether
        );
        assertFalse(allowed);
        assertEq(reason, "Exceeds global single tx limit");
    }

    function test_checkTransfer_exceedsHourlyLimit() public {
        // Record until hourly limit is near
        vm.prank(operator);
        limiter.recordTransfer(user, 95 ether);

        (bool allowed, string memory reason) = limiter.checkTransfer(
            user,
            10 ether
        );
        assertFalse(allowed);
        assertEq(reason, "Exceeds user hourly limit");
    }

    function test_checkTransfer_hourlyLimitResets() public {
        // Use most of hourly limit
        vm.prank(operator);
        limiter.recordTransfer(user, 90 ether);

        // Advance past hour boundary
        vm.warp(block.timestamp + 3601);

        // Should be allowed again
        (bool allowed, ) = limiter.checkTransfer(user, 90 ether);
        assertTrue(allowed);
    }

    function test_checkTransfer_dailyLimit() public {
        // Use explicit absolute timestamps to ensure hourly windows reset
        uint256 baseTime = 10000;

        vm.warp(baseTime);
        vm.prank(operator);
        limiter.recordTransfer(user, 99 ether);

        vm.warp(baseTime + 3601);
        vm.prank(operator);
        limiter.recordTransfer(user, 99 ether);

        vm.warp(baseTime + 7202);
        vm.prank(operator);
        limiter.recordTransfer(user, 99 ether);

        vm.warp(baseTime + 10803);
        vm.prank(operator);
        limiter.recordTransfer(user, 99 ether);

        vm.warp(baseTime + 14404);
        vm.prank(operator);
        limiter.recordTransfer(user, 99 ether);

        // Warp to a fresh hour to reset hourly, daily remains at 495
        vm.warp(baseTime + 18005);

        (bool allowed, string memory reason) = limiter.checkTransfer(
            user,
            10 ether
        );
        assertFalse(allowed);
        assertEq(reason, "Exceeds user daily limit");
    }

    function test_checkTransfer_minTimeBetweenTx() public {
        vm.prank(operator);
        limiter.recordTransfer(user, 1 ether);

        // Try immediately (default minTimeBetweenTx is 60s for users)
        (bool allowed, string memory reason) = limiter.checkTransfer(
            user,
            1 ether
        );
        assertFalse(allowed);
        assertEq(reason, "Too soon between transactions");
    }

    function test_checkTransfer_afterCooldown() public {
        vm.prank(operator);
        limiter.recordTransfer(user, 1 ether);

        vm.warp(block.timestamp + 61);

        (bool allowed, ) = limiter.checkTransfer(user, 1 ether);
        assertTrue(allowed);
    }

    // ======= Blacklist / Whitelist =======

    function test_blacklist_blocks() public {
        vm.prank(guardian);
        limiter.setBlacklist(user, true);

        (bool allowed, string memory reason) = limiter.checkTransfer(
            user,
            1 ether
        );
        assertFalse(allowed);
        assertEq(reason, "Address blacklisted");
    }

    function test_whitelist_bypasses() public {
        limiter.setWhitelist(user, true);

        // Even large amounts pass
        (bool allowed, string memory reason) = limiter.checkTransfer(
            user,
            10000 ether
        );
        assertTrue(allowed);
        assertEq(reason, "Whitelisted");
    }

    function test_blacklist_removable() public {
        vm.prank(guardian);
        limiter.setBlacklist(user, true);
        vm.prank(guardian);
        limiter.setBlacklist(user, false);

        (bool allowed, ) = limiter.checkTransfer(user, 1 ether);
        assertTrue(allowed);
    }

    // ======= TVL Cap =======

    function test_tvlCap_blocks() public {
        limiter.setTVLCap(1000 ether);

        // Set TVL close to cap
        vm.prank(operator);
        limiter.recordTVLChange(999 ether, true);

        (bool allowed, string memory reason) = limiter.checkTransfer(
            user,
            10 ether
        );
        assertFalse(allowed);
        assertEq(reason, "TVL cap exceeded");
    }

    function test_tvlCap_unlimited() public view {
        // Default tvlCap is 0 (unlimited)
        (bool allowed, ) = limiter.checkTransfer(user, 1 ether);
        assertTrue(allowed);
    }

    // ======= Circuit Breaker =======

    function test_circuitBreaker_manualTrigger() public {
        vm.prank(guardian);
        limiter.triggerCircuitBreaker("Suspicious activity");

        (bool allowed, ) = limiter.checkTransfer(user, 1 ether);
        assertFalse(allowed);
    }

    function test_circuitBreaker_cooldown() public {
        vm.prank(guardian);
        limiter.triggerCircuitBreaker("Test trigger");

        // Wait for cooldown
        vm.warp(block.timestamp + 3601);

        (bool allowed, ) = limiter.checkTransfer(user, 1 ether);
        assertTrue(allowed);
    }

    function test_circuitBreaker_reset() public {
        vm.prank(guardian);
        limiter.triggerCircuitBreaker("Test trigger");

        // Wait for cooldown to expire before resetting
        vm.warp(block.timestamp + 3601);

        // resetCircuitBreaker requires DEFAULT_ADMIN_ROLE
        limiter.resetCircuitBreaker();

        (bool allowed, ) = limiter.checkTransfer(user, 1 ether);
        assertTrue(allowed);
    }

    function test_circuitBreaker_tvlDropAutoTrigger() public {
        // Build up TVL
        vm.prank(operator);
        limiter.recordTVLChange(1000 ether, true);

        // Withdraw 25% (exceeds 20% threshold)
        vm.prank(operator);
        limiter.recordTVLChange(250 ether, false);

        // Should have triggered circuit breaker
        (bool allowed, ) = limiter.checkTransfer(user, 1 ether);
        assertFalse(allowed);
    }

    // ======= Record Transfer =======

    function test_recordTransfer_updatesUsage() public {
        vm.prank(operator);
        limiter.recordTransfer(user, 10 ether);

        (
            uint256 hourlyUsed,
            uint256 dailyUsed,
            ,
            ,
            uint256 lastTx,
            uint256 txCount
        ) = limiter.userUsage(user);
        assertEq(hourlyUsed, 10 ether);
        assertEq(dailyUsed, 10 ether);
        assertEq(txCount, 1);
        assertTrue(lastTx > 0);
    }

    function test_recordTransfer_onlyOperator() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert();
        limiter.recordTransfer(user, 1 ether);
    }

    // ======= TVL Tracking =======

    function test_recordTVLChange_deposit() public {
        vm.prank(operator);
        limiter.recordTVLChange(100 ether, true);

        (, , , , uint256 tvl, uint256 peak, ) = limiter.globalStats();
        assertEq(tvl, 100 ether);
        assertEq(peak, 100 ether);
    }

    function test_recordTVLChange_withdrawal() public {
        vm.prank(operator);
        limiter.recordTVLChange(100 ether, true);

        vm.prank(operator);
        limiter.recordTVLChange(30 ether, false);

        (, , , , uint256 tvl, , ) = limiter.globalStats();
        assertEq(tvl, 70 ether);
    }

    function test_recordTVLChange_withdrawalClampsToZero() public {
        vm.prank(operator);
        limiter.recordTVLChange(10 ether, true);

        vm.prank(operator);
        limiter.recordTVLChange(20 ether, false); // more than TVL

        (, , , , uint256 tvl, , ) = limiter.globalStats();
        assertEq(tvl, 0);
    }

    // ======= Pause =======

    function test_pauseBlocksTransfers() public {
        vm.prank(guardian);
        limiter.pause();

        (bool allowed, string memory reason) = limiter.checkTransfer(
            user,
            1 ether
        );
        assertFalse(allowed);
        assertEq(reason, "Bridge paused");
    }

    // ======= Configuration =======

    function test_updateConfig() public {
        limiter.setGlobalConfig(2000 ether, 20000 ether, 1000 ether, 0, true);

        (uint256 hourly, uint256 daily, uint256 max, , ) = limiter
            .globalConfig();
        assertEq(hourly, 2000 ether);
        assertEq(daily, 20000 ether);
        assertEq(max, 1000 ether);
    }

    // ======= Fuzz Tests =======

    function testFuzz_checkTransfer(uint256 amount) public view {
        amount = bound(amount, 0, 10 ether);
        (bool allowed, ) = limiter.checkTransfer(user, amount);
        assertTrue(allowed);
    }

    function testFuzz_recordTransfer(uint256 amount) public {
        amount = bound(amount, 1, 99 ether); // within single tx limit

        vm.prank(operator);
        limiter.recordTransfer(user, amount);

        (uint256 hourlyUsed, , , , , ) = limiter.userUsage(user);
        assertEq(hourlyUsed, amount);
    }

    function testFuzz_tvlChanges(uint256 deposit, uint256 withdraw) public {
        deposit = bound(deposit, 1, 1_000_000 ether);
        withdraw = bound(withdraw, 0, deposit);

        vm.startPrank(operator);
        limiter.recordTVLChange(deposit, true);
        limiter.recordTVLChange(withdraw, false);
        vm.stopPrank();

        (, , , , uint256 tvl, , ) = limiter.globalStats();
        assertEq(tvl, deposit - withdraw);
    }
}
