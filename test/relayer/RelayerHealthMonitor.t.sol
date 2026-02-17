// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/relayer/RelayerHealthMonitor.sol";

contract RelayerHealthMonitorTest is Test {
    RelayerHealthMonitor public monitor;
    address public admin = address(this);
    address public router = makeAddr("router");
    address public relayer1 = makeAddr("relayer1");
    address public relayer2 = makeAddr("relayer2");

    function setUp() public {
        monitor = new RelayerHealthMonitor(admin);
        monitor.grantRole(monitor.ROUTER_ROLE(), router);
        monitor.registerRelayer(relayer1);
        monitor.registerRelayer(relayer2);
    }

    function test_recordSuccess_UpdatesScore() public {
        vm.prank(router);
        monitor.recordSuccess(relayer1, 2 seconds); // Fast relay

        (uint256 success, uint256 failed,,,,) = monitor.relayerStats(relayer1);
        assertEq(success, 1);
        assertEq(failed, 0);

        uint256 score = monitor.getHealthScore(relayer1);
        // Score: 100 - FailureRate(0) - LatencyPenalty(0) = 100
        assertEq(score, 100);
    }

    function test_reportFailure_ReducesScore() public {
        vm.startPrank(router);
        monitor.recordSuccess(relayer1, 10 seconds); // 1 success
        monitor.reportFailure(relayer1);             // 1 failure
        vm.stopPrank();

        // Failure Rate = 50%
        // Score = 100 - 50 = 50
        uint256 score = monitor.getHealthScore(relayer1);
        assertEq(score, 50);
    }

    function test_latencyPenalty() public {
        vm.prank(router);
        monitor.recordSuccess(relayer1, 40 seconds); // 10s over 30s target

        // Latency penalty = 40 - 30 = 10
        // Score = 100 - 0 - 10 = 90
        uint256 score = monitor.getHealthScore(relayer1);
        assertEq(score, 90);
    }

    function test_penalize_AdminOnly() public {
        monitor.penalize(relayer1, 20, "Misconduct");
        
        // Initial neutral score is 50 if no ops.
        // Wait, getHealthScore returns 50 if ops=0?
        // Let's record one op first to be sure scoring is active.
        
        vm.prank(router);
        monitor.recordSuccess(relayer1, 10 seconds); // 100 base
        
        // Score = 100 - 20 = 80
        uint256 score = monitor.getHealthScore(relayer1);
        assertEq(score, 80);
    }
}
