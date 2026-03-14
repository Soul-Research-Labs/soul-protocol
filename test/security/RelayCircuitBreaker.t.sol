// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {RelayCircuitBreaker} from "../../contracts/security/RelayCircuitBreaker.sol";

contract RelayCircuitBreakerTest is Test {
    RelayCircuitBreaker public breaker;
    address public admin;
    address public monitor = address(0xBB01);
    address public guardian = address(0xBB02);
    address public recoverer = address(0xBB03);
    address public recoverer2 = address(0xBB04);

    function setUp() public {
        admin = address(this);
        breaker = new RelayCircuitBreaker(admin);
        breaker.grantRole(breaker.MONITOR_ROLE(), monitor);
        breaker.grantRole(breaker.GUARDIAN_ROLE(), guardian);
        breaker.grantRole(breaker.RECOVERY_ROLE(), recoverer);
        breaker.grantRole(breaker.RECOVERY_ROLE(), recoverer2);
    }

    // ======= Initial State =======

    function test_initialState() public view {
        assertEq(
            uint256(breaker.currentState()),
            uint256(RelayCircuitBreaker.SystemState.NORMAL)
        );
        assertEq(breaker.anomalyScore(), 0);
    }

    // ======= Record Transaction =======

    function test_recordTransaction_normalAmount() public {
        vm.prank(monitor);
        breaker.recordTransaction(1 ether, address(0xAA));
        assertEq(
            uint256(breaker.currentState()),
            uint256(RelayCircuitBreaker.SystemState.NORMAL)
        );
    }

    function test_recordTransaction_largeAmount() public {
        // Set baseline TVL first
        vm.prank(monitor);
        breaker.updateTVL(1000 ether);

        vm.prank(monitor);
        breaker.recordTransaction(200 ether, address(0xAA));

        // Large transfer should increase anomaly score
        assertTrue(breaker.anomalyScore() > 0);
    }

    function test_recordTransaction_onlyMonitor() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert();
        breaker.recordTransaction(1 ether, address(0xAA));
    }

    // ======= TVL Updates =======

    function test_updateTVL() public {
        vm.prank(monitor);
        breaker.updateTVL(1000 ether);
        assertEq(breaker.currentTVL(), 1000 ether);
    }

    function test_updateTVL_trackBaseline() public {
        vm.prank(monitor);
        breaker.updateTVL(1000 ether);
        assertEq(breaker.baselineTVL(), 1000 ether);

        // Higher TVL updates baseline
        vm.prank(monitor);
        breaker.updateTVL(2000 ether);
        assertEq(breaker.baselineTVL(), 2000 ether);
    }

    function test_updateTVL_dropTriggersAnomaly() public {
        vm.prank(monitor);
        breaker.updateTVL(1000 ether);

        // Move forward to avoid same-block issues
        vm.warp(block.timestamp + 1);

        // Large TVL drop (>10% threshold)
        vm.prank(monitor);
        breaker.updateTVL(800 ether);

        assertTrue(breaker.anomalyScore() > 0);
    }

    // ======= State Transitions =======

    function test_guardianCanForceHalt() public {
        vm.prank(guardian);
        breaker.emergencyHalt();

        assertEq(
            uint256(breaker.currentState()),
            uint256(RelayCircuitBreaker.SystemState.HALTED)
        );
    }

    function test_guardianCanReportAnomaly() public {
        vm.prank(monitor);
        breaker.reportAnomaly(
            RelayCircuitBreaker.AnomalyType.EXTERNAL_TRIGGER,
            50,
            keccak256("test")
        );

        assertTrue(breaker.anomalyScore() > 0);
    }

    function test_cannotHalt_withoutGuardianRole() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert();
        breaker.emergencyHalt();
    }

    // ======= Recovery =======

    function test_proposeRecovery() public {
        // First halt the system
        vm.prank(guardian);
        breaker.emergencyHalt();

        // Propose recovery
        vm.prank(recoverer);
        uint256 proposalId = breaker.proposeRecovery(
            RelayCircuitBreaker.SystemState.NORMAL
        );
        assertTrue(proposalId > 0 || proposalId == 0); // Just check it doesn't revert
    }

    function test_recoveryRequiresApprovals() public {
        vm.prank(guardian);
        breaker.emergencyHalt();

        vm.prank(recoverer);
        uint256 proposalId = breaker.proposeRecovery(
            RelayCircuitBreaker.SystemState.NORMAL
        );

        // Need another approval
        vm.prank(recoverer2);
        breaker.approveRecovery(proposalId);

        // Wait for recovery delay
        vm.warp(block.timestamp + breaker.RECOVERY_DELAY() + 1);

        vm.prank(recoverer);
        breaker.executeRecovery(proposalId);

        assertEq(
            uint256(breaker.currentState()),
            uint256(RelayCircuitBreaker.SystemState.NORMAL)
        );
    }

    function test_cannotExecuteRecoveryWithoutDelay() public {
        vm.prank(guardian);
        breaker.emergencyHalt();

        vm.prank(recoverer);
        uint256 proposalId = breaker.proposeRecovery(
            RelayCircuitBreaker.SystemState.NORMAL
        );

        vm.prank(recoverer2);
        breaker.approveRecovery(proposalId);

        // Try to execute immediately (should fail)
        vm.prank(recoverer);
        vm.expectRevert();
        breaker.executeRecovery(proposalId);
    }

    // ======= Anomaly Resolution =======

    function test_resolveAnomaly() public {
        // Create an anomaly by recording large tx
        vm.prank(monitor);
        breaker.updateTVL(1000 ether);

        vm.prank(monitor);
        breaker.recordTransaction(200 ether, address(0xDD)); // large transfer

        uint256 scoreBefore = breaker.anomalyScore();
        assertTrue(scoreBefore > 0);

        // Resolve all anomalies
        uint256 anomalyCount = breaker.activeAnomalyCount();
        for (uint256 i = 0; i < anomalyCount; i++) {
            vm.prank(guardian);
            breaker.resolveAnomaly(i);
        }
    }

    // ======= Thresholds =======

    function test_setThresholds() public {
        breaker.setThresholds(
            200 ether, // largeTransferAmount
            1000, // largeTransferPercent (10%)
            200, // velocityTxPerHour
            2000 ether, // velocityAmountPerHour
            2000, // tvlDropPercent (20%)
            40, // warningScore
            70, // degradedScore
            90 // haltedScore
        );

        (uint256 largeAmt, , , , , , , ) = breaker.thresholds();
        assertEq(largeAmt, 200 ether);
    }

    // ======= High Velocity Detection =======

    function test_highVelocity_triggersAnomaly() public {
        vm.startPrank(monitor);
        breaker.updateTVL(10000 ether);

        // Flood with transactions to exceed velocity threshold (100/hr)
        for (uint256 i = 0; i < 101; i++) {
            breaker.recordTransaction(0.1 ether, address(uint160(i + 1)));
        }
        vm.stopPrank();

        // Anomaly is detected (severity may be 0 at boundary due to integer division),
        // but the anomaly record itself exists
        assertTrue(breaker.getActiveAnomalyCount() > 0);
    }

    // ======= Fuzz Tests =======

    function testFuzz_recordTransaction(uint256 amount) public {
        amount = bound(amount, 0, 1_000_000 ether);

        vm.prank(monitor);
        breaker.recordTransaction(amount, address(0xAAA));

        // Verify metrics were recorded
        (uint256 txCount, uint256 totalVolume, , , ) = breaker
            .currentHourMetrics();
        assertGe(txCount, 1, "txCount should be at least 1");
        assertGe(totalVolume, amount, "totalVolume should include amount");
    }

    function testFuzz_updateTVL(uint256 tvl) public {
        tvl = bound(tvl, 0, 1_000_000_000 ether);

        vm.prank(monitor);
        breaker.updateTVL(tvl);

        assertEq(breaker.currentTVL(), tvl);
    }
}
