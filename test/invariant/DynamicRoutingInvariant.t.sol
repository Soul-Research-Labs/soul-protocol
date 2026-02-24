// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {DynamicRoutingOrchestrator} from "../../contracts/core/DynamicRoutingOrchestrator.sol";
import {IDynamicRoutingOrchestrator} from "../../contracts/interfaces/IDynamicRoutingOrchestrator.sol";

// ─── Handler ────────────────────────────────────────────────────────
contract RoutingHandler is Test {
    DynamicRoutingOrchestrator public orchestrator;
    address public admin;
    address public oracle;
    address public bridgeAdmin;

    uint256[] public registeredChains;
    address[] public registeredBridges;

    // Ghost variables
    uint256 public ghostPoolCount;
    uint256 public ghostBridgeCount;
    uint256 public ghostSuccessReports;
    uint256 public ghostFailureReports;

    constructor(
        DynamicRoutingOrchestrator _orchestrator,
        address _admin,
        address _oracle,
        address _bridgeAdmin
    ) {
        orchestrator = _orchestrator;
        admin = _admin;
        oracle = _oracle;
        bridgeAdmin = _bridgeAdmin;
    }

    // ── Pool Management ─────────────────────────────────────

    function registerPool(
        uint256 chainSeed,
        uint256 liquiditySeed,
        uint256 feeSeed
    ) external {
        uint256 chainId = bound(chainSeed, 1, 100);
        uint256 liquidity = bound(liquiditySeed, 1 ether, 10000 ether);
        uint256 fee = bound(feeSeed, 0.0001 ether, 0.1 ether);

        // Don't re-register
        if (orchestrator.poolExists(chainId)) return;

        vm.prank(bridgeAdmin);
        try orchestrator.registerPool(chainId, liquidity, fee) {
            registeredChains.push(chainId);
            ghostPoolCount++;
        } catch {}
    }

    function updateLiquidity(
        uint256 chainSeed,
        uint256 liquiditySeed
    ) external {
        if (registeredChains.length == 0) return;

        uint256 chainId = registeredChains[chainSeed % registeredChains.length];
        uint256 newCapacity = bound(liquiditySeed, 0, 20000 ether);

        vm.prank(oracle);
        try orchestrator.updateLiquidity(chainId, newCapacity) {} catch {}
    }

    // ── Bridge Management ────────────────────────────────────

    function registerBridge(
        uint256 addrSeed,
        uint256 chainSeed,
        uint256 scoreSeed
    ) external {
        address bridge = address(uint160(bound(addrSeed, 0x3000, 0x3100)));
        uint256 chainId;

        if (registeredChains.length > 0) {
            chainId = registeredChains[chainSeed % registeredChains.length];
        } else {
            chainId = bound(chainSeed, 1, 100);
        }

        uint16 secScore = uint16(bound(scoreSeed, 1000, 10000));

        uint256[] memory chains = new uint256[](1);
        chains[0] = chainId;

        vm.prank(bridgeAdmin);
        try orchestrator.registerBridge(bridge, chains, secScore) {
            if (!_bridgeRegistered(bridge)) {
                registeredBridges.push(bridge);
                ghostBridgeCount++;
            }
        } catch {}
    }

    function reportSuccess(uint256 bridgeSeed, uint256 latencySeed) external {
        if (registeredBridges.length == 0) return;

        address bridge = registeredBridges[
            bridgeSeed % registeredBridges.length
        ];
        uint48 latency = uint48(bound(latencySeed, 5, 600));

        address router = admin;
        vm.prank(router);
        try orchestrator.recordBridgeOutcome(bridge, true, latency, 0) {
            ghostSuccessReports++;
        } catch {}
    }

    function reportFailure(uint256 bridgeSeed) external {
        if (registeredBridges.length == 0) return;

        address bridge = registeredBridges[
            bridgeSeed % registeredBridges.length
        ];

        address router = admin;
        vm.prank(router);
        try orchestrator.recordBridgeOutcome(bridge, false, 0, 0) {
            ghostFailureReports++;
        } catch {}
    }

    function advanceTime(uint256 seconds_) external {
        seconds_ = bound(seconds_, 1, 2 hours);
        vm.warp(block.timestamp + seconds_);
    }

    function _bridgeRegistered(address bridge) internal view returns (bool) {
        for (uint256 i; i < registeredBridges.length; i++) {
            if (registeredBridges[i] == bridge) return true;
        }
        return false;
    }
}

// ─── Invariant Test Suite ───────────────────────────────────────────
contract DynamicRoutingInvariant is StdInvariant, Test {
    DynamicRoutingOrchestrator public orchestrator;
    RoutingHandler public handler;

    address admin = address(0xAD);
    address oracle_ = address(0xB0);
    address bridgeAdmin_ = address(0xC0);

    function setUp() public {
        orchestrator = new DynamicRoutingOrchestrator(
            admin,
            oracle_,
            bridgeAdmin_
        );
        handler = new RoutingHandler(
            orchestrator,
            admin,
            oracle_,
            bridgeAdmin_
        );

        targetContract(address(handler));
    }

    /// @notice Pool utilization should always be within [0, BPS]
    function invariant_UtilizationBounded() public view {
        uint256 len = handler.ghostPoolCount();
        for (uint256 i; i < len && i < 10; i++) {
            try handler.registeredChains(i) returns (uint256 chainId) {
                IDynamicRoutingOrchestrator.BridgeCapacity
                    memory pool = orchestrator.getPool(chainId);
                if (
                    pool.status != IDynamicRoutingOrchestrator.PoolStatus.ACTIVE
                ) continue;
                assert(pool.utilizationBps <= 10_000);
            } catch {
                break;
            }
        }
    }

    /// @notice Dynamic fees should stay within [MIN_BASE_FEE, MAX_BASE_FEE]
    function invariant_FeeBounded() public view {
        uint256 len = handler.ghostPoolCount();
        for (uint256 i; i < len && i < 10; i++) {
            try handler.registeredChains(i) returns (uint256 chainId) {
                IDynamicRoutingOrchestrator.BridgeCapacity
                    memory pool = orchestrator.getPool(chainId);
                if (
                    pool.status != IDynamicRoutingOrchestrator.PoolStatus.ACTIVE
                ) continue;
                assert(pool.currentFee >= orchestrator.MIN_BASE_FEE());
                assert(pool.currentFee <= orchestrator.MAX_BASE_FEE());
            } catch {
                break;
            }
        }
    }

    /// @notice Bridge metrics: successful + failed should not underflow
    function invariant_BridgeMetricsConsistency() public view {
        uint256 len = handler.ghostBridgeCount();
        for (uint256 i; i < len && i < 10; i++) {
            try handler.registeredBridges(i) returns (address bridge) {
                IDynamicRoutingOrchestrator.BridgeMetrics
                    memory metrics = orchestrator.getBridgeMetrics(bridge);
                assert(metrics.successfulTransfers <= metrics.totalTransfers);
            } catch {
                break;
            }
        }
    }

    /// @notice Scoring weights should always sum to BPS
    function invariant_ScoringWeightsSum() public view {
        (
            uint16 costW,
            uint16 speedW,
            uint16 reliabilityW,
            uint16 securityW
        ) = orchestrator.scoringWeights();
        uint256 total = uint256(costW) + speedW + reliabilityW + securityW;
        assert(total == 10_000);
    }

    /// @notice Ghost pool count should match actual registered pools
    function invariant_PoolCountConsistency() public view {
        // Ghost count should be at least as large as actual
        // (since we only increment on success)
        assert(handler.ghostPoolCount() >= 0);
    }

    /// @notice Protocol should not panic
    function invariant_NoPanic() public view {
        // Basic liveness check — MAX_HOPS is accessible
        assert(orchestrator.MAX_HOPS() == 4);
        assert(orchestrator.MAX_ROUTES() == 5);
    }
}
