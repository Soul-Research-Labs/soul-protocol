// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/core/DynamicRoutingOrchestrator.sol";
import "../../contracts/interfaces/IDynamicRoutingOrchestrator.sol";

/**
 * @title DynamicRoutingFuzz
 * @notice Fuzz tests for DynamicRoutingOrchestrator covering pool management,
 *         bridge outcomes, and route scoring consistency
 * @dev Run with: forge test --match-contract DynamicRoutingFuzz --fuzz-runs 10000
 */
contract DynamicRoutingFuzz is Test {
    DynamicRoutingOrchestrator public orchestrator;

    address public admin = address(0xAD);
    address public oracle = address(0xB0);
    address public bridgeAdmin = address(0xC0);

    function setUp() public {
        orchestrator = new DynamicRoutingOrchestrator(
            admin,
            oracle,
            bridgeAdmin
        );
    }

    /*//////////////////////////////////////////////////////////////
                SECTION 1 — registerPool FUZZ
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz pool registration with various chain IDs and capacity amounts
    function testFuzz_registerPool(
        uint256 chainId,
        uint256 capacity,
        uint256 fee
    ) public {
        chainId = bound(chainId, 1, 100_000);
        capacity = bound(capacity, 0, 100_000 ether);
        fee = bound(fee, 0, 2 ether);

        vm.prank(bridgeAdmin);
        orchestrator.registerPool(chainId, capacity, fee);

        assertTrue(
            orchestrator.poolExists(chainId),
            "Pool should exist after registration"
        );

        IDynamicRoutingOrchestrator.BridgeCapacity memory pool = orchestrator
            .getPool(chainId);
        assertEq(pool.chainId, chainId);
        assertEq(pool.availableCapacity, capacity);
        assertEq(pool.totalCapacity, capacity);
        assertEq(pool.utilizationBps, 0);
        assertEq(
            uint8(pool.status),
            uint8(IDynamicRoutingOrchestrator.PoolStatus.ACTIVE)
        );

        // Fee should be at least MIN_BASE_FEE
        assertGe(
            pool.currentFee,
            orchestrator.MIN_BASE_FEE(),
            "Fee should be >= MIN_BASE_FEE"
        );
    }

    /// @notice Fuzz: registering pool with chainId == 0 should revert
    function testFuzz_registerPool_zeroChainReverts(uint256 capacity) public {
        capacity = bound(capacity, 0, 100 ether);

        vm.prank(bridgeAdmin);
        vm.expectRevert();
        orchestrator.registerPool(0, capacity, 0.001 ether);
    }

    /// @notice Fuzz: cannot register duplicate pool
    function testFuzz_registerPool_duplicate(uint256 chainId) public {
        chainId = bound(chainId, 1, 1000);

        vm.startPrank(bridgeAdmin);
        orchestrator.registerPool(chainId, 100 ether, 0.01 ether);

        vm.expectRevert();
        orchestrator.registerPool(chainId, 200 ether, 0.02 ether);
        vm.stopPrank();
    }

    /// @notice Fuzz: non-bridge-admin cannot register
    function testFuzz_registerPool_accessControl(address caller) public {
        vm.assume(caller != bridgeAdmin && caller != admin);

        vm.prank(caller);
        vm.expectRevert();
        orchestrator.registerPool(42, 100 ether, 0.01 ether);
    }

    /*//////////////////////////////////////////////////////////////
              SECTION 2 — updateCapacity FUZZ
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz capacity updates — utilization should stay within [0, BPS]
    function testFuzz_updateCapacity(
        uint256 initialCapacity,
        uint256 newCapacity
    ) public {
        initialCapacity = bound(initialCapacity, 1 ether, 10_000 ether);
        newCapacity = bound(newCapacity, 0, 20_000 ether);

        uint256 chainId = 42;

        vm.prank(bridgeAdmin);
        orchestrator.registerPool(chainId, initialCapacity, 0.01 ether);

        vm.prank(oracle);
        orchestrator.updateCapacity(chainId, newCapacity);

        IDynamicRoutingOrchestrator.BridgeCapacity memory pool = orchestrator
            .getPool(chainId);
        assertEq(pool.availableCapacity, newCapacity);
        assertLe(
            pool.utilizationBps,
            10_000,
            "Utilization must be <= 10000 bps"
        );
    }

    /// @notice Fuzz: updating non-existent pool should revert
    function testFuzz_updateCapacity_nonExistentPool(uint256 chainId) public {
        chainId = bound(chainId, 1, 100_000);
        vm.assume(!orchestrator.poolExists(chainId));

        vm.prank(oracle);
        vm.expectRevert();
        orchestrator.updateCapacity(chainId, 50 ether);
    }

    /// @notice Fuzz: non-oracle cannot update capacity
    function testFuzz_updateCapacity_accessControl(address caller) public {
        vm.assume(caller != oracle && caller != admin);

        vm.prank(bridgeAdmin);
        orchestrator.registerPool(99, 100 ether, 0.01 ether);

        vm.prank(caller);
        vm.expectRevert();
        orchestrator.updateCapacity(99, 50 ether);
    }

    /// @notice Fuzz: dynamic fee stays within [MIN_BASE_FEE, MAX_BASE_FEE] after updates
    function testFuzz_feeBounds_afterCapacityUpdate(
        uint256 initialCapacity,
        uint256 newCapacity
    ) public {
        initialCapacity = bound(initialCapacity, 1 ether, 10_000 ether);
        newCapacity = bound(newCapacity, 0, 20_000 ether);

        uint256 chainId = 7;

        vm.prank(bridgeAdmin);
        orchestrator.registerPool(chainId, initialCapacity, 0.01 ether);

        vm.prank(oracle);
        orchestrator.updateCapacity(chainId, newCapacity);

        IDynamicRoutingOrchestrator.BridgeCapacity memory pool = orchestrator
            .getPool(chainId);
        assertGe(
            pool.currentFee,
            orchestrator.MIN_BASE_FEE(),
            "Fee should be >= MIN_BASE_FEE"
        );
        assertLe(
            pool.currentFee,
            orchestrator.MAX_BASE_FEE(),
            "Fee should be <= MAX_BASE_FEE"
        );
    }

    /*//////////////////////////////////////////////////////////////
            SECTION 3 — recordBridgeOutcome FUZZ
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz bridge success reports — successful transfers should not exceed total
    function testFuzz_recordBridgeOutcome_success(
        uint48 latency,
        uint256 value
    ) public {
        latency = uint48(bound(uint256(latency), 1, 3600));
        value = bound(value, 0, 1000 ether);

        address bridge = address(0x5000);
        uint256[] memory chains = new uint256[](1);
        chains[0] = 1;

        vm.prank(bridgeAdmin);
        orchestrator.registerBridge(bridge, chains, 8000);

        vm.prank(admin); // admin has ROUTER_ROLE
        orchestrator.recordBridgeOutcome(bridge, true, latency, value);

        IDynamicRoutingOrchestrator.BridgeMetrics memory metrics = orchestrator
            .getBridgeMetrics(bridge);
        assertEq(metrics.totalRelays, 1);
        assertEq(metrics.successfulRelays, 1);
        assertEq(metrics.totalValueRouted, value);
        assertLe(metrics.successfulRelays, metrics.totalRelays);
    }

    /// @notice Fuzz bridge failure reports — lastFailure should update on failure
    function testFuzz_recordBridgeOutcome_failure(uint8 failCount) public {
        failCount = uint8(bound(failCount, 1, 10));

        address bridge = address(0x5001);
        uint256[] memory chains = new uint256[](1);
        chains[0] = 1;

        vm.prank(bridgeAdmin);
        orchestrator.registerBridge(bridge, chains, 7000);

        for (uint8 i = 0; i < failCount; i++) {
            vm.prank(admin);
            orchestrator.recordBridgeOutcome(bridge, false, 0, 0);
        }

        IDynamicRoutingOrchestrator.BridgeMetrics memory metrics = orchestrator
            .getBridgeMetrics(bridge);
        assertEq(metrics.totalRelays, failCount);
        assertEq(metrics.successfulRelays, 0);
        assertGt(
            metrics.lastFailure,
            0,
            "lastFailure should be set after failure"
        );
    }

    /// @notice Fuzz mixed success/failure outcomes — successful <= total always
    function testFuzz_recordBridgeOutcome_mixed(
        uint8 successes,
        uint8 failures
    ) public {
        successes = uint8(bound(successes, 0, 20));
        failures = uint8(bound(failures, 0, 20));
        vm.assume(uint256(successes) + uint256(failures) > 0);

        address bridge = address(0x5002);
        uint256[] memory chains = new uint256[](1);
        chains[0] = 1;

        vm.prank(bridgeAdmin);
        orchestrator.registerBridge(bridge, chains, 9000);

        for (uint8 i = 0; i < successes; i++) {
            vm.prank(admin);
            orchestrator.recordBridgeOutcome(bridge, true, 30, 1 ether);
        }
        for (uint8 i = 0; i < failures; i++) {
            vm.prank(admin);
            orchestrator.recordBridgeOutcome(bridge, false, 0, 0);
        }

        IDynamicRoutingOrchestrator.BridgeMetrics memory metrics = orchestrator
            .getBridgeMetrics(bridge);
        assertEq(
            metrics.totalRelays,
            uint256(successes) + uint256(failures)
        );
        assertEq(metrics.successfulRelays, successes);
        assertLe(metrics.successfulRelays, metrics.totalRelays);
    }

    /// @notice Fuzz: recording outcome for unregistered bridge should revert
    function testFuzz_recordBridgeOutcome_unregistered(address bridge) public {
        vm.assume(!orchestrator.bridgeRegistered(bridge));

        vm.prank(admin);
        vm.expectRevert();
        orchestrator.recordBridgeOutcome(bridge, true, 10, 1 ether);
    }

    /*//////////////////////////////////////////////////////////////
          SECTION 4 — ROUTE SCORING CONSISTENCY
    //////////////////////////////////////////////////////////////*/

    /// @notice Scoring weights must always sum to 10000 BPS
    function testFuzz_scoringWeightsInvariant() public view {
        (
            uint16 costW,
            uint16 speedW,
            uint16 reliabilityW,
            uint16 securityW
        ) = orchestrator.scoringWeights();
        uint256 total = uint256(costW) + speedW + reliabilityW + securityW;
        assertEq(total, 10_000, "Scoring weights must sum to 10000 bps");
    }

    /// @notice Fuzz: registerBridge with security score — should be bounded [0, BPS]
    function testFuzz_registerBridge_securityScore(uint16 scoreBps) public {
        address bridge = address(uint160(0x6000 + uint256(scoreBps)));
        uint256[] memory chains = new uint256[](1);
        chains[0] = 1;

        vm.prank(bridgeAdmin);
        orchestrator.registerBridge(bridge, chains, scoreBps);

        IDynamicRoutingOrchestrator.BridgeMetrics memory metrics = orchestrator
            .getBridgeMetrics(bridge);
        assertEq(metrics.securityScoreBps, scoreBps);
    }

    /// @notice Fuzz: constants are consistent and accessible
    function testFuzz_constantsAccessible() public view {
        assertEq(orchestrator.MAX_HOPS(), 4);
        assertEq(orchestrator.MAX_ROUTES(), 5);
        assertGt(orchestrator.MIN_BASE_FEE(), 0, "MIN_BASE_FEE should be > 0");
        assertGt(
            orchestrator.MAX_BASE_FEE(),
            orchestrator.MIN_BASE_FEE(),
            "MAX > MIN"
        );
        assertEq(orchestrator.BPS(), 10_000);
    }

    /// @notice Fuzz: pool status update
    function testFuzz_setPoolStatus(uint8 statusRaw) public {
        uint256 chainId = 50;

        vm.prank(bridgeAdmin);
        orchestrator.registerPool(chainId, 100 ether, 0.01 ether);

        // PoolStatus has 4 values: 0..3
        statusRaw = uint8(bound(statusRaw, 0, 3));
        IDynamicRoutingOrchestrator.PoolStatus newStatus = IDynamicRoutingOrchestrator
                .PoolStatus(statusRaw);

        vm.prank(bridgeAdmin);
        orchestrator.setPoolStatus(chainId, newStatus);

        IDynamicRoutingOrchestrator.BridgeCapacity memory pool = orchestrator
            .getPool(chainId);
        assertEq(uint8(pool.status), statusRaw);
    }
}
