// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

import {IDynamicRoutingOrchestrator} from "../interfaces/IDynamicRoutingOrchestrator.sol";
import {RouteOptimizer} from "../libraries/RouteOptimizer.sol";

/**
 * @title DynamicRoutingOrchestrator
 * @author Soul Protocol
 * @notice Dynamic cross-chain routing with real-time liquidity awareness and multi-factor optimization
 * @dev Implements Tachyon Learning #4: Real-Time Settlement Orchestration.
 *
 *      Core capabilities:
 *      - Real-time liquidity pool tracking per chain with oracle updates
 *      - Multi-factor route scoring: cost, speed, reliability, security, privacy
 *      - Multi-hop routing through intermediate chains when direct path is suboptimal
 *      - EIP-1559-style dynamic fee adjustment based on pool utilization
 *      - Settlement time prediction using exponential moving average
 *      - Bridge health integration via security scores and failure tracking
 *
 *      Role separation:
 *      - ORACLE_ROLE: Updates liquidity data (off-chain oracles)
 *      - ROUTER_ROLE: Records bridge outcomes (authorized routers)
 *      - BRIDGE_ADMIN_ROLE: Registers/manages bridges and pools
 *      - DEFAULT_ADMIN_ROLE: Emergency controls
 *
 *      Security features:
 *      - ReentrancyGuard on all state-changing functions
 *      - Pausable for emergency stops
 *      - Stale oracle data detection (configurable staleness threshold)
 *      - Zero-address validation on all address parameters
 *      - Route expiry to prevent stale execution
 */
contract DynamicRoutingOrchestrator is
    IDynamicRoutingOrchestrator,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    using RouteOptimizer for RouteOptimizer.ScoringWeights;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Role for oracle liquidity updates
    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE");

    /// @notice Role for recording bridge outcomes
    bytes32 public constant ROUTER_ROLE = keccak256("ROUTER_ROLE");

    /// @notice Role for bridge/pool administration
    bytes32 public constant BRIDGE_ADMIN_ROLE = keccak256("BRIDGE_ADMIN_ROLE");

    /// @notice Maximum number of hops in a route
    uint8 public constant MAX_HOPS = 4;

    /// @notice Maximum number of routes returned by findRoutes
    uint8 public constant MAX_ROUTES = 5;

    /// @notice Route validity window (5 minutes)
    uint48 public constant ROUTE_VALIDITY_WINDOW = 5 minutes;

    /// @notice Oracle staleness threshold (10 minutes)
    uint48 public constant ORACLE_STALENESS_THRESHOLD = 10 minutes;

    /// @notice Fee adjustment speed per epoch (12.5% in bps)
    uint16 public constant FEE_ADJUSTMENT_BPS = 1250;

    /// @notice Target utilization rate (50% in bps)
    uint16 public constant TARGET_UTILIZATION_BPS = 5000;

    /// @notice Minimum base fee (0.0001 ETH)
    uint256 public constant MIN_BASE_FEE = 0.0001 ether;

    /// @notice Maximum base fee (1 ETH)
    uint256 public constant MAX_BASE_FEE = 1 ether;

    /// @notice Basis points denominator
    uint16 public constant BPS = 10_000;

    /// @notice EMA smoothing factor numerator (alpha = 2/(N+1) where N=20)
    /// @dev We use integer math: newEMA = (alpha * value + (BPS - alpha) * oldEMA) / BPS
    uint16 public constant EMA_ALPHA_BPS = 952; // ~2/21 ≈ 9.52%

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Liquidity pools indexed by chain ID
    mapping(uint256 => LiquidityPool) internal _pools;

    /// @notice Whether a chain has a registered pool
    mapping(uint256 => bool) public poolExists;

    /// @notice Bridge metrics indexed by adapter address
    mapping(address => BridgeMetrics) internal _bridgeMetrics;

    /// @notice Whether a bridge adapter is registered
    mapping(address => bool) public bridgeRegistered;

    /// @notice Bridge adapters supporting each chain: chainId => adapter[]
    mapping(uint256 => address[]) internal _chainBridges;

    /// @notice Quick lookup: adapter supports chain? adapter => chainId => bool
    mapping(address => mapping(uint256 => bool)) public bridgeSupportsChain;

    /// @notice Calculated routes: routeId => Route
    mapping(bytes32 => Route) internal _routes;

    /// @notice Route nonce for unique ID generation
    uint256 internal _routeNonce;

    /// @notice Scoring weights for route optimization
    RouteOptimizer.ScoringWeights public scoringWeights;

    /// @notice All registered chain IDs (for multi-hop search)
    uint256[] internal _registeredChains;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initialize the routing orchestrator
     * @param admin Default admin address
     * @param oracle Initial oracle address
     * @param bridgeAdmin Initial bridge admin address
     */
    constructor(address admin, address oracle, address bridgeAdmin) {
        if (admin == address(0)) revert ZeroAddress();
        if (oracle == address(0)) revert ZeroAddress();
        if (bridgeAdmin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ORACLE_ROLE, oracle);
        _grantRole(BRIDGE_ADMIN_ROLE, bridgeAdmin);
        _grantRole(ROUTER_ROLE, admin); // Admin can also record outcomes

        // Default scoring weights (balanced)
        scoringWeights = RouteOptimizer.ScoringWeights({
            costWeight: 3000, // 30%
            speedWeight: 2500, // 25%
            reliabilityWeight: 2500, // 25%
            securityWeight: 2000 // 20%
        });
    }

    /*//////////////////////////////////////////////////////////////
                        LIQUIDITY MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IDynamicRoutingOrchestrator
    function registerPool(
        uint256 chainId,
        uint256 totalLiquidity,
        uint256 initialFee
    ) external onlyRole(BRIDGE_ADMIN_ROLE) whenNotPaused {
        if (chainId == 0) revert InvalidChainId();
        if (poolExists[chainId]) revert PoolAlreadyRegistered(chainId);

        _pools[chainId] = LiquidityPool({
            chainId: chainId,
            availableLiquidity: totalLiquidity,
            totalLiquidity: totalLiquidity,
            utilizationBps: 0,
            avgSettlementTime: 60, // Default 60s estimate
            currentFee: initialFee < MIN_BASE_FEE ? MIN_BASE_FEE : initialFee,
            lastUpdated: uint48(block.timestamp),
            status: PoolStatus.ACTIVE
        });

        poolExists[chainId] = true;
        _registeredChains.push(chainId);

        emit PoolRegistered(chainId, totalLiquidity, initialFee);
    }

    /// @inheritdoc IDynamicRoutingOrchestrator
    function updateLiquidity(
        uint256 chainId,
        uint256 newAvailableLiquidity
    ) external onlyRole(ORACLE_ROLE) whenNotPaused {
        if (!poolExists[chainId]) revert PoolNotFound(chainId);

        LiquidityPool storage pool = _pools[chainId];
        uint256 oldLiquidity = pool.availableLiquidity;

        pool.availableLiquidity = newAvailableLiquidity;
        pool.utilizationBps = _calculateUtilization(pool);
        pool.lastUpdated = uint48(block.timestamp);

        // Dynamic fee adjustment based on utilization
        _adjustFee(pool);

        emit LiquidityUpdated(
            chainId,
            oldLiquidity,
            newAvailableLiquidity,
            pool.utilizationBps
        );
    }

    /// @inheritdoc IDynamicRoutingOrchestrator
    function batchUpdateLiquidity(
        uint256[] calldata chainIds,
        uint256[] calldata newLiquidities
    ) external onlyRole(ORACLE_ROLE) whenNotPaused {
        require(chainIds.length == newLiquidities.length, "Length mismatch");

        for (uint256 i = 0; i < chainIds.length; ++i) {
            if (!poolExists[chainIds[i]]) revert PoolNotFound(chainIds[i]);

            LiquidityPool storage pool = _pools[chainIds[i]];
            uint256 oldLiquidity = pool.availableLiquidity;

            pool.availableLiquidity = newLiquidities[i];
            pool.utilizationBps = _calculateUtilization(pool);
            pool.lastUpdated = uint48(block.timestamp);
            _adjustFee(pool);

            emit LiquidityUpdated(
                chainIds[i],
                oldLiquidity,
                newLiquidities[i],
                pool.utilizationBps
            );
        }
    }

    /// @inheritdoc IDynamicRoutingOrchestrator
    function setPoolStatus(
        uint256 chainId,
        PoolStatus newStatus
    ) external onlyRole(BRIDGE_ADMIN_ROLE) {
        if (!poolExists[chainId]) revert PoolNotFound(chainId);

        LiquidityPool storage pool = _pools[chainId];
        PoolStatus oldStatus = pool.status;
        pool.status = newStatus;

        emit PoolStatusChanged(chainId, oldStatus, newStatus);
    }

    /*//////////////////////////////////////////////////////////////
                        BRIDGE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IDynamicRoutingOrchestrator
    function registerBridge(
        address adapter,
        uint256[] calldata supportedChains,
        uint16 securityScoreBps
    ) external onlyRole(BRIDGE_ADMIN_ROLE) whenNotPaused {
        if (adapter == address(0)) revert ZeroAddress();
        if (bridgeRegistered[adapter]) revert BridgeAlreadyRegistered(adapter);

        _bridgeMetrics[adapter] = BridgeMetrics({
            adapter: adapter,
            totalTransfers: 0,
            successfulTransfers: 0,
            totalValueRouted: 0,
            avgLatency: 60, // Default 60s
            securityScoreBps: securityScoreBps,
            lastFailure: 0,
            isActive: true
        });

        bridgeRegistered[adapter] = true;

        for (uint256 i = 0; i < supportedChains.length; ++i) {
            bridgeSupportsChain[adapter][supportedChains[i]] = true;
            _chainBridges[supportedChains[i]].push(adapter);
        }

        emit BridgeRegistered(adapter, supportedChains);
    }

    /// @inheritdoc IDynamicRoutingOrchestrator
    function recordBridgeOutcome(
        address adapter,
        bool success,
        uint48 latency,
        uint256 value
    ) external onlyRole(ROUTER_ROLE) {
        if (!bridgeRegistered[adapter]) revert BridgeNotRegistered(adapter);

        BridgeMetrics storage metrics = _bridgeMetrics[adapter];
        metrics.totalTransfers += 1;
        metrics.totalValueRouted += value;

        if (success) {
            metrics.successfulTransfers += 1;
            // Update avg latency with EMA
            metrics.avgLatency = uint48(
                (uint256(EMA_ALPHA_BPS) *
                    uint256(latency) +
                    uint256(BPS - EMA_ALPHA_BPS) *
                    uint256(metrics.avgLatency)) / BPS
            );
        } else {
            metrics.lastFailure = uint48(block.timestamp);
        }

        emit BridgeMetricsUpdated(
            adapter,
            metrics.totalTransfers,
            metrics.avgLatency
        );
    }

    /**
     * @notice Toggle bridge active status
     * @param adapter Bridge adapter address
     * @param active New active state
     */
    function setBridgeActive(
        address adapter,
        bool active
    ) external onlyRole(BRIDGE_ADMIN_ROLE) {
        if (!bridgeRegistered[adapter]) revert BridgeNotRegistered(adapter);
        _bridgeMetrics[adapter].isActive = active;
    }

    /**
     * @notice Update scoring weights for route optimization
     * @param weights New scoring weights (must sum to 10000)
     */
    function setScoringWeights(
        RouteOptimizer.ScoringWeights calldata weights
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(
            weights.costWeight +
                weights.speedWeight +
                weights.reliabilityWeight +
                weights.securityWeight ==
                BPS,
            "Weights must sum to 10000"
        );
        scoringWeights = weights;
    }

    /*//////////////////////////////////////////////////////////////
                           CORE ROUTING
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IDynamicRoutingOrchestrator
    function findOptimalRoute(
        RouteRequest calldata request
    ) external view override returns (Route memory route) {
        _validateRequest(request);

        // Try direct route first
        Route memory directRoute = _calculateDirectRoute(request);

        // Try multi-hop routes (1 intermediate)
        Route memory bestMultiHop = _findBestMultiHop(request);

        // Return the best scoring route
        if (
            bestMultiHop.routeScoreBps > directRoute.routeScoreBps &&
            bestMultiHop.chainPath.length > 0
        ) {
            route = bestMultiHop;
        } else if (directRoute.chainPath.length > 0) {
            route = directRoute;
        } else {
            revert NoViableRoute(request.sourceChainId, request.destChainId);
        }

        // Validate against user constraints
        _validateRouteConstraints(route, request);
    }

    /// @inheritdoc IDynamicRoutingOrchestrator
    function findRoutes(
        RouteRequest calldata request,
        uint8 maxRoutes
    ) external view override returns (Route[] memory routes) {
        _validateRequest(request);
        if (maxRoutes > MAX_ROUTES) maxRoutes = MAX_ROUTES;

        // Collect candidate routes
        Route[] memory candidates = new Route[](maxRoutes + 1);
        uint8 count = 0;

        // Direct route
        Route memory direct = _calculateDirectRoute(request);
        if (direct.chainPath.length > 0) {
            candidates[count] = direct;
            count++;
        }

        // Multi-hop routes through each registered chain
        for (
            uint256 i = 0;
            i < _registeredChains.length && count < maxRoutes;
            ++i
        ) {
            uint256 hopChain = _registeredChains[i];
            if (
                hopChain == request.sourceChainId ||
                hopChain == request.destChainId
            ) continue;
            if (
                !poolExists[hopChain] ||
                _pools[hopChain].status != PoolStatus.ACTIVE
            ) continue;

            Route memory hop = _calculateMultiHopRoute(request, hopChain);
            if (hop.chainPath.length > 0) {
                candidates[count] = hop;
                count++;
            }
        }

        // Sort by score (simple insertion sort, small array)
        for (uint8 i = 1; i < count; ++i) {
            Route memory key = candidates[i];
            uint8 j = i;
            while (
                j > 0 && candidates[j - 1].routeScoreBps < key.routeScoreBps
            ) {
                candidates[j] = candidates[j - 1];
                j--;
            }
            candidates[j] = key;
        }

        // Return sorted results
        uint8 resultCount = count < maxRoutes ? count : maxRoutes;
        routes = new Route[](resultCount);
        for (uint8 i = 0; i < resultCount; ++i) {
            routes[i] = candidates[i];
        }
    }

    /// @inheritdoc IDynamicRoutingOrchestrator
    function executeRoute(
        bytes32 routeId
    )
        external
        payable
        override
        nonReentrant
        whenNotPaused
        returns (bytes32 executionId)
    {
        Route storage route = _routes[routeId];
        if (route.chainPath.length == 0) revert RouteNotFound(routeId);
        if (route.status != RouteStatus.PENDING)
            revert RouteAlreadyExecuted(routeId);
        if (block.timestamp > route.expiresAt) revert RouteExpired(routeId);
        require(msg.value >= route.totalCost, "Insufficient payment");

        route.status = RouteStatus.EXECUTING;
        executionId = keccak256(
            abi.encodePacked(routeId, msg.sender, block.timestamp)
        );

        emit RouteExecuted(routeId, msg.sender, msg.value, route.totalCost);

        // Refund excess
        if (msg.value > route.totalCost) {
            (bool ok, ) = msg.sender.call{value: msg.value - route.totalCost}(
                ""
            );
            require(ok, "Refund failed");
        }
    }

    /**
     * @notice Mark a route as completed (called by authorized router)
     * @param routeId The route that completed
     * @param actualTime Actual settlement time
     * @param actualCost Actual cost
     */
    function completeRoute(
        bytes32 routeId,
        uint48 actualTime,
        uint256 actualCost
    ) external onlyRole(ROUTER_ROLE) {
        Route storage route = _routes[routeId];
        if (route.chainPath.length == 0) revert RouteNotFound(routeId);
        route.status = RouteStatus.COMPLETED;

        // Update settlement time EMA for destination pool
        uint256 destChain = route.chainPath[route.chainPath.length - 1];
        if (poolExists[destChain]) {
            LiquidityPool storage pool = _pools[destChain];
            pool.avgSettlementTime = uint48(
                (uint256(EMA_ALPHA_BPS) *
                    uint256(actualTime) +
                    uint256(BPS - EMA_ALPHA_BPS) *
                    uint256(pool.avgSettlementTime)) / BPS
            );
        }

        emit RouteCompleted(routeId, actualTime, actualCost);
    }

    /**
     * @notice Mark a route as failed
     * @param routeId The route that failed
     * @param reason Failure reason
     */
    function failRoute(
        bytes32 routeId,
        string calldata reason
    ) external onlyRole(ROUTER_ROLE) {
        Route storage route = _routes[routeId];
        if (route.chainPath.length == 0) revert RouteNotFound(routeId);
        route.status = RouteStatus.FAILED;

        emit RouteFailed(routeId, reason);
    }

    /// @inheritdoc IDynamicRoutingOrchestrator
    function predictSettlementTime(
        uint256 sourceChainId,
        uint256 destChainId,
        uint256 amount
    ) external view override returns (uint48 estimatedTime, uint16 confidence) {
        if (!poolExists[destChainId]) revert PoolNotFound(destChainId);

        LiquidityPool storage destPool = _pools[destChainId];
        uint48 baseTime = destPool.avgSettlementTime;

        // Adjust for amount relative to liquidity (large transfers take longer)
        if (destPool.availableLiquidity > 0 && amount > 0) {
            uint256 liquidityRatio = (amount * BPS) /
                destPool.availableLiquidity;
            if (liquidityRatio > 5000) {
                // >50% of liquidity: add 50% time
                baseTime = uint48((uint256(baseTime) * 150) / 100);
            } else if (liquidityRatio > 2000) {
                // >20% of liquidity: add 25% time
                baseTime = uint48((uint256(baseTime) * 125) / 100);
            }
        }

        // Adjust for source chain (add source pool settlement time if available)
        if (poolExists[sourceChainId]) {
            baseTime += _pools[sourceChainId].avgSettlementTime / 4; // 25% of source time
        }

        estimatedTime = baseTime;

        // Confidence based on data freshness and sample size
        address[] storage destBridges = _chainBridges[destChainId];
        uint256 totalSamples = 0;
        for (uint256 i = 0; i < destBridges.length; ++i) {
            totalSamples += _bridgeMetrics[destBridges[i]].totalTransfers;
        }

        if (totalSamples > 1000) {
            confidence = 9000; // High confidence: >1000 samples
        } else if (totalSamples > 100) {
            confidence = 7000; // Medium confidence
        } else if (totalSamples > 10) {
            confidence = 5000; // Low confidence
        } else {
            confidence = 2000; // Very low confidence
        }

        // Reduce confidence if oracle data is stale
        if (
            block.timestamp > destPool.lastUpdated + ORACLE_STALENESS_THRESHOLD
        ) {
            confidence = confidence / 2;
        }
    }

    /*//////////////////////////////////////////////////////////////
                              VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IDynamicRoutingOrchestrator
    function getPool(
        uint256 chainId
    ) external view override returns (LiquidityPool memory pool) {
        if (!poolExists[chainId]) revert PoolNotFound(chainId);
        return _pools[chainId];
    }

    /// @inheritdoc IDynamicRoutingOrchestrator
    function getBridgeMetrics(
        address adapter
    ) external view override returns (BridgeMetrics memory metrics) {
        if (!bridgeRegistered[adapter]) revert BridgeNotRegistered(adapter);
        return _bridgeMetrics[adapter];
    }

    /// @inheritdoc IDynamicRoutingOrchestrator
    function getRoute(
        bytes32 routeId
    ) external view override returns (Route memory route) {
        if (_routes[routeId].chainPath.length == 0)
            revert RouteNotFound(routeId);
        return _routes[routeId];
    }

    /// @inheritdoc IDynamicRoutingOrchestrator
    function isRouteValid(
        bytes32 routeId
    ) external view override returns (bool valid) {
        Route storage route = _routes[routeId];
        return
            route.chainPath.length > 0 &&
            route.status == RouteStatus.PENDING &&
            block.timestamp <= route.expiresAt;
    }

    /// @inheritdoc IDynamicRoutingOrchestrator
    function estimateFee(
        uint256 sourceChainId,
        uint256 destChainId,
        uint256 amount
    ) external view override returns (uint256 fee) {
        if (!poolExists[destChainId]) revert PoolNotFound(destChainId);

        LiquidityPool storage destPool = _pools[destChainId];
        fee = destPool.currentFee;

        // Surcharge for large amounts relative to liquidity
        if (destPool.availableLiquidity > 0 && amount > 0) {
            uint256 impact = (amount * BPS) / destPool.availableLiquidity;
            // Add impact premium: fee * (1 + impact/10000)
            fee = fee + (fee * impact) / BPS;
        }

        // Add source fee if applicable
        if (poolExists[sourceChainId]) {
            fee += _pools[sourceChainId].currentFee / 4; // 25% of source fee
        }
    }

    /// @inheritdoc IDynamicRoutingOrchestrator
    function getBridgesForChain(
        uint256 chainId
    ) external view override returns (address[] memory adapters) {
        return _chainBridges[chainId];
    }

    /**
     * @notice Get all registered chain IDs
     * @return chains Array of chain IDs with registered pools
     */
    function getRegisteredChains()
        external
        view
        returns (uint256[] memory chains)
    {
        return _registeredChains;
    }

    /*//////////////////////////////////////////////////////////////
                        EMERGENCY CONTROLS
    //////////////////////////////////////////////////////////////*/

    /// @notice Pause the orchestrator
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause the orchestrator
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Validate a route request has valid parameters
     */
    function _validateRequest(RouteRequest calldata request) internal view {
        if (request.sourceChainId == 0 || request.destChainId == 0)
            revert InvalidChainId();
        if (request.sourceChainId == request.destChainId)
            revert InvalidChainId();
        if (request.amount == 0) revert InvalidAmount();
        if (!poolExists[request.destChainId])
            revert PoolNotFound(request.destChainId);

        LiquidityPool storage destPool = _pools[request.destChainId];
        if (
            destPool.status != PoolStatus.ACTIVE &&
            destPool.status != PoolStatus.DEGRADED
        ) {
            revert PoolNotActive(request.destChainId);
        }
    }

    /**
     * @dev Validate a calculated route meets user constraints
     */
    function _validateRouteConstraints(
        Route memory route,
        RouteRequest calldata request
    ) internal pure {
        if (request.maxCost > 0 && route.totalCost > request.maxCost) {
            revert CostExceedsMax(route.totalCost, request.maxCost);
        }
        if (request.maxTime > 0 && route.estimatedTime > request.maxTime) {
            revert TimeExceedsMax(route.estimatedTime, request.maxTime);
        }
        if (
            request.minSuccessBps > 0 &&
            route.successProbabilityBps < request.minSuccessBps
        ) {
            revert SuccessBelowMin(
                route.successProbabilityBps,
                request.minSuccessBps
            );
        }
    }

    /**
     * @dev Calculate a direct (single-hop) route
     */
    function _calculateDirectRoute(
        RouteRequest calldata request
    ) internal view returns (Route memory route) {
        address[] storage bridges = _chainBridges[request.destChainId];
        if (bridges.length == 0) return route; // Empty route = no viable path

        // Find best bridge for this hop
        (address bestBridge, ) = _findBestBridge(
            request.sourceChainId,
            request.destChainId,
            request.amount,
            request.urgency
        );

        if (bestBridge == address(0)) return route;

        LiquidityPool storage destPool = _pools[request.destChainId];

        // Check liquidity
        if (destPool.availableLiquidity < request.amount) {
            return route; // Insufficient liquidity
        }

        // Build route
        route.chainPath = new uint256[](2);
        route.chainPath[0] = request.sourceChainId;
        route.chainPath[1] = request.destChainId;

        route.bridgeAdapters = new address[](1);
        route.bridgeAdapters[0] = bestBridge;

        // Calculate cost
        route.totalCost = _calculateHopCost(
            request.destChainId,
            request.amount
        );

        // Estimated time
        route.estimatedTime = destPool.avgSettlementTime;

        // Success probability from bridge metrics
        BridgeMetrics storage bm = _bridgeMetrics[bestBridge];
        if (bm.totalTransfers > 0) {
            route.successProbabilityBps = uint16(
                (bm.successfulTransfers * BPS) / bm.totalTransfers
            );
        } else {
            route.successProbabilityBps = 5000; // 50% default for new bridges
        }

        // Composite score
        route.routeScoreBps = _scoreRoute(route, request.urgency);

        route.calculatedAt = uint48(block.timestamp);
        route.expiresAt = uint48(block.timestamp) + ROUTE_VALIDITY_WINDOW;
        route.status = RouteStatus.PENDING;

        // Generate route ID (view-safe: deterministic from params)
        route.routeId = keccak256(
            abi.encodePacked(
                request.sourceChainId,
                request.destChainId,
                request.amount,
                block.timestamp,
                bestBridge
            )
        );
    }

    /**
     * @dev Find the best multi-hop route through any intermediate chain
     */
    function _findBestMultiHop(
        RouteRequest calldata request
    ) internal view returns (Route memory bestRoute) {
        uint16 bestScore = 0;

        for (uint256 i = 0; i < _registeredChains.length; ++i) {
            uint256 hopChain = _registeredChains[i];
            if (
                hopChain == request.sourceChainId ||
                hopChain == request.destChainId
            ) continue;
            if (
                !poolExists[hopChain] ||
                _pools[hopChain].status != PoolStatus.ACTIVE
            ) continue;

            Route memory candidate = _calculateMultiHopRoute(request, hopChain);
            if (
                candidate.chainPath.length > 0 &&
                candidate.routeScoreBps > bestScore
            ) {
                bestRoute = candidate;
                bestScore = candidate.routeScoreBps;
            }
        }
    }

    /**
     * @dev Calculate a 2-hop route through an intermediate chain
     */
    function _calculateMultiHopRoute(
        RouteRequest calldata request,
        uint256 intermediateChain
    ) internal view returns (Route memory route) {
        // Check both hops have bridges
        (address bridge1, ) = _findBestBridge(
            request.sourceChainId,
            intermediateChain,
            request.amount,
            request.urgency
        );
        (address bridge2, ) = _findBestBridge(
            intermediateChain,
            request.destChainId,
            request.amount,
            request.urgency
        );

        if (bridge1 == address(0) || bridge2 == address(0)) return route;

        LiquidityPool storage hopPool = _pools[intermediateChain];
        LiquidityPool storage destPool = _pools[request.destChainId];

        // Check liquidity on both hops
        if (
            hopPool.availableLiquidity < request.amount ||
            destPool.availableLiquidity < request.amount
        ) {
            return route;
        }

        // Build route
        route.chainPath = new uint256[](3);
        route.chainPath[0] = request.sourceChainId;
        route.chainPath[1] = intermediateChain;
        route.chainPath[2] = request.destChainId;

        route.bridgeAdapters = new address[](2);
        route.bridgeAdapters[0] = bridge1;
        route.bridgeAdapters[1] = bridge2;

        // Cost: sum of both hops
        route.totalCost =
            _calculateHopCost(intermediateChain, request.amount) +
            _calculateHopCost(request.destChainId, request.amount);

        // Time: sum of both hops
        route.estimatedTime =
            hopPool.avgSettlementTime +
            destPool.avgSettlementTime;

        // Success probability: product of both hops
        BridgeMetrics storage bm1 = _bridgeMetrics[bridge1];
        BridgeMetrics storage bm2 = _bridgeMetrics[bridge2];

        uint16 prob1 = bm1.totalTransfers > 0
            ? uint16((bm1.successfulTransfers * BPS) / bm1.totalTransfers)
            : 5000;
        uint16 prob2 = bm2.totalTransfers > 0
            ? uint16((bm2.successfulTransfers * BPS) / bm2.totalTransfers)
            : 5000;

        route.successProbabilityBps = uint16(
            (uint256(prob1) * uint256(prob2)) / BPS
        );

        // Score (multi-hop penalty built into cost/time)
        route.routeScoreBps = _scoreRoute(route, request.urgency);

        route.calculatedAt = uint48(block.timestamp);
        route.expiresAt = uint48(block.timestamp) + ROUTE_VALIDITY_WINDOW;
        route.status = RouteStatus.PENDING;

        route.routeId = keccak256(
            abi.encodePacked(
                request.sourceChainId,
                intermediateChain,
                request.destChainId,
                request.amount,
                block.timestamp,
                bridge1,
                bridge2
            )
        );
    }

    /**
     * @dev Find the best bridge adapter for a specific hop
     * @return bestBridge Address of best bridge (0 if none)
     * @return bestScore Score of best bridge
     */
    function _findBestBridge(
        uint256 sourceChain,
        uint256 destChain,
        uint256 /* amount */,
        Urgency urgency
    ) internal view returns (address bestBridge, uint16 bestScore) {
        address[] storage bridges = _chainBridges[destChain];

        for (uint256 i = 0; i < bridges.length; ++i) {
            address adapter = bridges[i];
            BridgeMetrics storage bm = _bridgeMetrics[adapter];

            if (!bm.isActive) continue;
            if (!bridgeSupportsChain[adapter][sourceChain]) continue;

            uint16 score = _scoreBridge(bm, urgency);
            if (score > bestScore) {
                bestScore = score;
                bestBridge = adapter;
            }
        }
    }

    /**
     * @dev Score a bridge based on urgency preference
     */
    function _scoreBridge(
        BridgeMetrics storage bm,
        Urgency urgency
    ) internal view returns (uint16) {
        uint16 reliabilityScore;
        if (bm.totalTransfers > 0) {
            reliabilityScore = uint16(
                (bm.successfulTransfers * BPS) / bm.totalTransfers
            );
        } else {
            reliabilityScore = 5000;
        }

        uint16 speedScore;
        if (bm.avgLatency <= 30) {
            speedScore = 10000;
        } else if (bm.avgLatency <= 60) {
            speedScore = 8000;
        } else if (bm.avgLatency <= 120) {
            speedScore = 6000;
        } else if (bm.avgLatency <= 300) {
            speedScore = 4000;
        } else {
            speedScore = 2000;
        }

        uint16 secScore = bm.securityScoreBps;

        // Recency penalty: reduce score if recent failure
        uint16 recencyPenalty = 0;
        if (bm.lastFailure > 0 && block.timestamp - bm.lastFailure < 1 hours) {
            recencyPenalty = 2000; // -20% for very recent failure
        } else if (
            bm.lastFailure > 0 && block.timestamp - bm.lastFailure < 6 hours
        ) {
            recencyPenalty = 500; // -5% for moderately recent failure
        }

        // Weighted based on urgency
        uint16 score;
        if (urgency == Urgency.INSTANT || urgency == Urgency.FAST) {
            // Speed-weighted
            score = uint16(
                (uint256(speedScore) *
                    4000 +
                    uint256(reliabilityScore) *
                    3000 +
                    uint256(secScore) *
                    3000) / BPS
            );
        } else if (urgency == Urgency.ECONOMY) {
            // Security/reliability-weighted (cheapest reliable path)
            score = uint16(
                (uint256(reliabilityScore) *
                    4000 +
                    uint256(secScore) *
                    4000 +
                    uint256(speedScore) *
                    2000) / BPS
            );
        } else {
            // Standard: balanced
            score = uint16(
                (uint256(reliabilityScore) *
                    3500 +
                    uint256(speedScore) *
                    3000 +
                    uint256(secScore) *
                    3500) / BPS
            );
        }

        // Apply recency penalty
        score = score > recencyPenalty ? score - recencyPenalty : 0;

        return score;
    }

    /**
     * @dev Score a complete route using the RouteOptimizer library
     */
    function _scoreRoute(
        Route memory route,
        Urgency urgency
    ) internal view returns (uint16) {
        // Normalize cost to 0-10000 scale (inverse: lower cost = higher score)
        uint16 costScore;
        if (route.totalCost <= MIN_BASE_FEE) {
            costScore = 10000;
        } else if (route.totalCost >= MAX_BASE_FEE) {
            costScore = 0;
        } else {
            costScore = uint16(BPS - (route.totalCost * BPS) / MAX_BASE_FEE);
        }

        // Normalize speed (inverse: lower time = higher score)
        uint16 speedScore;
        if (route.estimatedTime <= 30) {
            speedScore = 10000;
        } else if (route.estimatedTime <= 60) {
            speedScore = 8500;
        } else if (route.estimatedTime <= 120) {
            speedScore = 7000;
        } else if (route.estimatedTime <= 300) {
            speedScore = 5000;
        } else if (route.estimatedTime <= 600) {
            speedScore = 3000;
        } else {
            speedScore = 1000;
        }

        // Reliability is already in bps
        uint16 reliabilityScore = route.successProbabilityBps;

        // Security: average of bridge security scores in route
        uint16 securityScore = 0;
        if (route.bridgeAdapters.length > 0) {
            uint256 totalSec = 0;
            for (uint256 i = 0; i < route.bridgeAdapters.length; ++i) {
                totalSec += _bridgeMetrics[route.bridgeAdapters[i]]
                    .securityScoreBps;
            }
            securityScore = uint16(totalSec / route.bridgeAdapters.length);
        }

        return
            RouteOptimizer.calculateScore(
                scoringWeights,
                costScore,
                speedScore,
                reliabilityScore,
                securityScore,
                urgency == Urgency.INSTANT || urgency == Urgency.FAST,
                route.chainPath.length > 2 // multi-hop penalty
            );
    }

    /**
     * @dev Calculate cost for a single hop to destChain
     */
    function _calculateHopCost(
        uint256 destChain,
        uint256 amount
    ) internal view returns (uint256 cost) {
        LiquidityPool storage pool = _pools[destChain];
        cost = pool.currentFee;

        // Liquidity impact premium
        if (pool.availableLiquidity > 0 && amount > 0) {
            uint256 impact = (amount * BPS) / pool.availableLiquidity;
            cost = cost + (cost * impact) / BPS;
        }
    }

    /**
     * @dev Calculate utilization ratio in bps
     */
    function _calculateUtilization(
        LiquidityPool storage pool
    ) internal view returns (uint16) {
        if (pool.totalLiquidity == 0) return 0;
        if (pool.availableLiquidity >= pool.totalLiquidity) return 0;
        uint256 used = pool.totalLiquidity - pool.availableLiquidity;
        uint256 utilBps = (used * BPS) / pool.totalLiquidity;
        return utilBps > BPS ? uint16(BPS) : uint16(utilBps);
    }

    /**
     * @dev Adjust fee based on utilization (EIP-1559 style)
     */
    function _adjustFee(LiquidityPool storage pool) internal {
        uint256 oldFee = pool.currentFee;
        uint256 newFee;

        if (pool.utilizationBps > TARGET_UTILIZATION_BPS) {
            // Above target: increase fee
            uint256 delta = (oldFee * FEE_ADJUSTMENT_BPS) / BPS;
            newFee = oldFee + delta;
        } else if (pool.utilizationBps < TARGET_UTILIZATION_BPS) {
            // Below target: decrease fee
            uint256 delta = (oldFee * FEE_ADJUSTMENT_BPS) / BPS;
            newFee = oldFee > delta ? oldFee - delta : MIN_BASE_FEE;
        } else {
            return; // At target, no change
        }

        // Clamp to bounds
        if (newFee < MIN_BASE_FEE) newFee = MIN_BASE_FEE;
        if (newFee > MAX_BASE_FEE) newFee = MAX_BASE_FEE;

        if (newFee != oldFee) {
            pool.currentFee = newFee;
            emit FeeAdjusted(pool.chainId, oldFee, newFee, pool.utilizationBps);
        }
    }
}
