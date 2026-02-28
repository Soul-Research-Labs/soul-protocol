// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

import {IDynamicRoutingOrchestrator} from "../interfaces/IDynamicRoutingOrchestrator.sol";
import {RouteOptimizer} from "../libraries/RouteOptimizer.sol";

/**
 * @title DynamicRoutingOrchestrator
 * @author ZASEON
 * @notice Routes ZK proof relay requests through optimal bridge adapters
 * @dev ZASEON is proof middleware — this contract routes PROOFS, not tokens.
 *      AdapterCapacity data is oracle-observed metadata about external bridge adapters.
 *      Zaseon does NOT manage bridge capacity. It queries bridge capacity data to select
 *      the most efficient path for proof delivery.
 *
 *      Core capabilities:
 *      - Oracle-observed bridge capacity tracking per chain
 *      - Multi-factor route scoring: cost, speed, reliability, security, privacy
 *      - Multi-hop routing through intermediate chains when direct path is suboptimal
 *      - EIP-1559-style dynamic fee adjustment based on adapter utilization
 *      - Completion time prediction using exponential moving average
 *      - Adapter health integration via security scores and failure tracking
 *
 *      Role separation:
 *      - ORACLE_ROLE: Updates bridge capacity data (off-chain oracles)
 *      - ROUTER_ROLE: Records adapter outcomes (authorized routers)
 *      - ADAPTER_ADMIN_ROLE: Registers/manages adapters and capacity configs
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

    /// @notice Role for oracle capacity updates
    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE");

    /// @notice Role for recording bridge outcomes
    bytes32 public constant ROUTER_ROLE = keccak256("ROUTER_ROLE");

    /// @notice Role for bridge/pool administration
    bytes32 public constant ADAPTER_ADMIN_ROLE = keccak256("ADAPTER_ADMIN_ROLE");

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

    /// @notice Default estimated completion/latency time for new pools and bridges (seconds)
    uint48 public constant DEFAULT_COMPLETION_TIME = 60;

    /// @notice Default success probability for bridges with no history (50%)
    uint16 public constant DEFAULT_SUCCESS_BPS = 5000;

    /// @notice Source chain contribution divisor (25% of source chain time/fee)
    uint8 public constant SOURCE_CHAIN_WEIGHT_DIVISOR = 4;

    /// @notice Capacity impact threshold triggering high completion penalty (>50%)
    uint16 public constant HIGH_CAPACITY_IMPACT_BPS = 5000;

    /// @notice Capacity impact threshold triggering medium completion penalty (>20%)
    uint16 public constant MED_CAPACITY_IMPACT_BPS = 2000;

    /// @notice High-impact time multiplier numerator (150/100 = +50%)
    uint16 public constant HIGH_IMPACT_TIME_NUMERATOR = 150;

    /// @notice Medium-impact time multiplier numerator (125/100 = +25%)
    uint16 public constant MED_IMPACT_TIME_NUMERATOR = 125;

    /// @notice Percentage base denominator for time multipliers
    uint16 public constant PERCENT_BASE = 100;

    /// @notice Confidence: sample threshold for high confidence
    uint256 public constant CONFIDENCE_HIGH_THRESHOLD = 1000;

    /// @notice Confidence: sample threshold for medium confidence
    uint256 public constant CONFIDENCE_MED_THRESHOLD = 100;

    /// @notice Confidence: sample threshold for low confidence
    uint256 public constant CONFIDENCE_LOW_THRESHOLD = 10;

    /// @notice Confidence score: high (90%)
    uint16 public constant CONFIDENCE_HIGH_BPS = 9000;

    /// @notice Confidence score: medium (70%)
    uint16 public constant CONFIDENCE_MED_BPS = 7000;

    /// @notice Confidence score: low (50%)
    uint16 public constant CONFIDENCE_LOW_BPS = 5000;

    /// @notice Confidence score: very low (20%)
    uint16 public constant CONFIDENCE_VERY_LOW_BPS = 2000;

    /// @notice Bridge latency tier: excellent (≤30s)
    uint48 public constant LATENCY_EXCELLENT = 30;

    /// @notice Bridge latency tier: good (≤60s)
    uint48 public constant LATENCY_GOOD = 60;

    /// @notice Bridge latency tier: moderate (≤120s)
    uint48 public constant LATENCY_MODERATE = 120;

    /// @notice Bridge latency tier: slow (≤300s)
    uint48 public constant LATENCY_SLOW = 300;

    /// @notice Route latency tier: very slow (≤600s)
    uint48 public constant LATENCY_VERY_SLOW = 600;

    /// @notice Recency penalty window: very recent failure
    uint256 public constant RECENT_FAILURE_WINDOW = 1 hours;

    /// @notice Recency penalty window: moderately recent failure
    uint256 public constant MODERATE_FAILURE_WINDOW = 6 hours;

    /// @notice Recency penalty for very recent failure (−20%)
    uint16 public constant RECENT_FAILURE_PENALTY_BPS = 2000;

    /// @notice Recency penalty for moderately recent failure (−5%)
    uint16 public constant MODERATE_FAILURE_PENALTY_BPS = 500;

    /// @notice INSTANT/FAST urgency: speed weight
    uint16 public constant FAST_SPEED_WEIGHT = 4000;

    /// @notice INSTANT/FAST urgency: reliability weight
    uint16 public constant FAST_RELIABILITY_WEIGHT = 3000;

    /// @notice INSTANT/FAST urgency: security weight
    uint16 public constant FAST_SECURITY_WEIGHT = 3000;

    /// @notice ECONOMY urgency: reliability weight
    uint16 public constant ECONOMY_RELIABILITY_WEIGHT = 4000;

    /// @notice ECONOMY urgency: security weight
    uint16 public constant ECONOMY_SECURITY_WEIGHT = 4000;

    /// @notice ECONOMY urgency: speed weight
    uint16 public constant ECONOMY_SPEED_WEIGHT = 2000;

    /// @notice STANDARD urgency: reliability weight
    uint16 public constant STANDARD_RELIABILITY_WEIGHT = 3500;

    /// @notice STANDARD urgency: speed weight
    uint16 public constant STANDARD_SPEED_WEIGHT = 3000;

    /// @notice STANDARD urgency: security weight
    uint16 public constant STANDARD_SECURITY_WEIGHT = 3500;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Bridge capacity data indexed by chain ID
    mapping(uint256 => AdapterCapacity) internal _pools;

    /// @notice Whether a chain has a registered pool
    mapping(uint256 => bool) public poolExists;

    /// @notice Bridge metrics indexed by adapter address
    mapping(address => AdapterMetrics) internal _adapterMetrics;

    /// @notice Whether a bridge adapter is registered
    mapping(address => bool) public adapterRegistered;

    /// @notice Bridge adapters supporting each chain: chainId => adapter[]
    mapping(uint256 => address[]) internal _chainAdapters;

    /// @notice Quick lookup: adapter supports chain? adapter => chainId => bool
    mapping(address => mapping(uint256 => bool)) public adapterSupportsChain;

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
        _grantRole(ADAPTER_ADMIN_ROLE, bridgeAdmin);
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
                        CAPACITY MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IDynamicRoutingOrchestrator
        /**
     * @notice Registers pool
     * @param chainId The chain identifier
     * @param totalCapacity The total capacity
     * @param initialFee The initial fee
     */
function registerPool(
        uint256 chainId,
        uint256 totalCapacity,
        uint256 initialFee
    ) external onlyRole(ADAPTER_ADMIN_ROLE) whenNotPaused {
        if (chainId == 0) revert InvalidChainId();
        if (poolExists[chainId]) revert PoolAlreadyRegistered(chainId);

        _pools[chainId] = AdapterCapacity({
            chainId: chainId,
            availableCapacity: totalCapacity,
            totalCapacity: totalCapacity,
            utilizationBps: 0,
            avgCompletionTime: DEFAULT_COMPLETION_TIME,
            currentFee: initialFee < MIN_BASE_FEE ? MIN_BASE_FEE : initialFee,
            lastUpdated: uint48(block.timestamp),
            status: PoolStatus.ACTIVE
        });

        poolExists[chainId] = true;
        _registeredChains.push(chainId);

        emit PoolRegistered(chainId, totalCapacity, initialFee);
    }

    /// @inheritdoc IDynamicRoutingOrchestrator
        /**
     * @notice Updates capacity
     * @param chainId The chain identifier
     * @param newAvailableCapacity The new AvailableCapacity value
     */
function updateCapacity(
        uint256 chainId,
        uint256 newAvailableCapacity
    ) external onlyRole(ORACLE_ROLE) whenNotPaused {
        if (!poolExists[chainId]) revert PoolNotFound(chainId);

        AdapterCapacity storage pool = _pools[chainId];
        uint256 oldCapacity = pool.availableCapacity;

        pool.availableCapacity = newAvailableCapacity;
        pool.utilizationBps = _calculateUtilization(pool);
        pool.lastUpdated = uint48(block.timestamp);

        // Dynamic fee adjustment based on utilization
        _adjustFee(pool);

        emit CapacityUpdated(
            chainId,
            oldCapacity,
            newAvailableCapacity,
            pool.utilizationBps
        );
    }

    /// @inheritdoc IDynamicRoutingOrchestrator
        /**
     * @notice Batchs update capacity
     * @param chainIds The chainIds identifier
     * @param newCapacities The new Capacities value
     */
function batchUpdateCapacity(
        uint256[] calldata chainIds,
        uint256[] calldata newCapacities
    ) external onlyRole(ORACLE_ROLE) whenNotPaused {
        require(chainIds.length == newCapacities.length, "Length mismatch");

        for (uint256 i = 0; i < chainIds.length; ++i) {
            if (!poolExists[chainIds[i]]) revert PoolNotFound(chainIds[i]);

            AdapterCapacity storage pool = _pools[chainIds[i]];
            uint256 oldCapacity = pool.availableCapacity;

            pool.availableCapacity = newCapacities[i];
            pool.utilizationBps = _calculateUtilization(pool);
            pool.lastUpdated = uint48(block.timestamp);
            _adjustFee(pool);

            emit CapacityUpdated(
                chainIds[i],
                oldCapacity,
                newCapacities[i],
                pool.utilizationBps
            );
        }
    }

    /// @inheritdoc IDynamicRoutingOrchestrator
        /**
     * @notice Sets the pool status
     * @param chainId The chain identifier
     * @param newStatus The new Status value
     */
function setPoolStatus(
        uint256 chainId,
        PoolStatus newStatus
    ) external onlyRole(ADAPTER_ADMIN_ROLE) {
        if (!poolExists[chainId]) revert PoolNotFound(chainId);

        AdapterCapacity storage pool = _pools[chainId];
        PoolStatus oldStatus = pool.status;
        pool.status = newStatus;

        emit PoolStatusChanged(chainId, oldStatus, newStatus);
    }

    /*//////////////////////////////////////////////////////////////
                        BRIDGE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IDynamicRoutingOrchestrator
        /**
     * @notice Registers adapter
     * @param adapter The bridge adapter address
     * @param supportedChains The supported chains
     * @param securityScoreBps The security score bps
     */
function registerAdapter(
        address adapter,
        uint256[] calldata supportedChains,
        uint16 securityScoreBps
    ) external onlyRole(ADAPTER_ADMIN_ROLE) whenNotPaused {
        if (adapter == address(0)) revert ZeroAddress();
        if (adapterRegistered[adapter]) revert AdapterAlreadyRegistered(adapter);

        _adapterMetrics[adapter] = AdapterMetrics({
            adapter: adapter,
            totalRelays: 0,
            successfulRelays: 0,
            totalValueRouted: 0,
            avgLatency: DEFAULT_COMPLETION_TIME,
            securityScoreBps: securityScoreBps,
            lastFailure: 0,
            isActive: true
        });

        adapterRegistered[adapter] = true;

        for (uint256 i = 0; i < supportedChains.length; ++i) {
            adapterSupportsChain[adapter][supportedChains[i]] = true;
            _chainAdapters[supportedChains[i]].push(adapter);
        }

        emit AdapterRegistered(adapter, supportedChains);
    }

    /// @inheritdoc IDynamicRoutingOrchestrator
        /**
     * @notice Record adapter outcome
     * @param adapter The bridge adapter address
     * @param success The success
     * @param latency The latency
     * @param value The value to set
     */
function recordAdapterOutcome(
        address adapter,
        bool success,
        uint48 latency,
        uint256 value
    ) external onlyRole(ROUTER_ROLE) {
        if (!adapterRegistered[adapter]) revert AdapterNotRegistered(adapter);

        AdapterMetrics storage metrics = _adapterMetrics[adapter];
        metrics.totalRelays += 1;
        metrics.totalValueRouted += value;

        if (success) {
            metrics.successfulRelays += 1;
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

        emit AdapterMetricsUpdated(
            adapter,
            metrics.totalRelays,
            metrics.avgLatency
        );
    }

    /**
     * @notice Toggle bridge active status
     * @param adapter Bridge adapter address
     * @param active New active state
     */
    function setAdapterActive(
        address adapter,
        bool active
    ) external onlyRole(ADAPTER_ADMIN_ROLE) {
        if (!adapterRegistered[adapter]) revert AdapterNotRegistered(adapter);
        _adapterMetrics[adapter].isActive = active;
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
        /**
     * @notice Find optimal route
     * @param request The request
     * @return route The route
     */
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
        /**
     * @notice Find routes
     * @param request The request
     * @param maxRoutes The maxRoutes bound
     * @return routes The routes
     */
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
        /**
     * @notice Executes route
     * @param routeId The routeId identifier
     * @return executionId The execution id
     */
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
     * @param actualTime Actual completion time
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

        // Update completion time EMA for destination pool
        uint256 destChain = route.chainPath[route.chainPath.length - 1];
        if (poolExists[destChain]) {
            AdapterCapacity storage pool = _pools[destChain];
            pool.avgCompletionTime = uint48(
                (uint256(EMA_ALPHA_BPS) *
                    uint256(actualTime) +
                    uint256(BPS - EMA_ALPHA_BPS) *
                    uint256(pool.avgCompletionTime)) / BPS
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
        /**
     * @notice Predict completion time
     * @param sourceChainId The source chain identifier
     * @param destChainId The destination chain identifier
     * @param amount The amount to process
     * @return estimatedTime The estimated time
     * @return confidence The confidence
     */
function predictCompletionTime(
        uint256 sourceChainId,
        uint256 destChainId,
        uint256 amount
    ) external view override returns (uint48 estimatedTime, uint16 confidence) {
        if (!poolExists[destChainId]) revert PoolNotFound(destChainId);

        AdapterCapacity storage destPool = _pools[destChainId];
        uint48 baseTime = destPool.avgCompletionTime;

        // Adjust for amount relative to capacity (large relays take longer)
        if (destPool.availableCapacity > 0 && amount > 0) {
            uint256 capacityRatio = (amount * BPS) /
                destPool.availableCapacity;
            if (capacityRatio > HIGH_CAPACITY_IMPACT_BPS) {
                // >50% of capacity: add 50% time
                baseTime = uint48(
                    (uint256(baseTime) * HIGH_IMPACT_TIME_NUMERATOR) /
                        PERCENT_BASE
                );
            } else if (capacityRatio > MED_CAPACITY_IMPACT_BPS) {
                // >20% of capacity: add 25% time
                baseTime = uint48(
                    (uint256(baseTime) * MED_IMPACT_TIME_NUMERATOR) /
                        PERCENT_BASE
                );
            }
        }

        // Adjust for source chain (add source pool completion time if available)
        if (poolExists[sourceChainId]) {
            baseTime +=
                _pools[sourceChainId].avgCompletionTime /
                SOURCE_CHAIN_WEIGHT_DIVISOR;
        }

        estimatedTime = baseTime;

        // Confidence based on data freshness and sample size
        address[] storage destAdapters = _chainAdapters[destChainId];
        uint256 totalSamples = 0;
        for (uint256 i = 0; i < destAdapters.length; ++i) {
            totalSamples += _adapterMetrics[destAdapters[i]].totalRelays;
        }

        if (totalSamples > CONFIDENCE_HIGH_THRESHOLD) {
            confidence = CONFIDENCE_HIGH_BPS;
        } else if (totalSamples > CONFIDENCE_MED_THRESHOLD) {
            confidence = CONFIDENCE_MED_BPS;
        } else if (totalSamples > CONFIDENCE_LOW_THRESHOLD) {
            confidence = CONFIDENCE_LOW_BPS;
        } else {
            confidence = CONFIDENCE_VERY_LOW_BPS;
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
        /**
     * @notice Returns the pool
     * @param chainId The chain identifier
     * @return pool The pool
     */
function getPool(
        uint256 chainId
    ) external view override returns (AdapterCapacity memory pool) {
        if (!poolExists[chainId]) revert PoolNotFound(chainId);
        return _pools[chainId];
    }

    /// @inheritdoc IDynamicRoutingOrchestrator
        /**
     * @notice Returns the adapter metrics
     * @param adapter The bridge adapter address
     * @return metrics The metrics
     */
function getAdapterMetrics(
        address adapter
    ) external view override returns (AdapterMetrics memory metrics) {
        if (!adapterRegistered[adapter]) revert AdapterNotRegistered(adapter);
        return _adapterMetrics[adapter];
    }

    /// @inheritdoc IDynamicRoutingOrchestrator
        /**
     * @notice Returns the route
     * @param routeId The routeId identifier
     * @return route The route
     */
function getRoute(
        bytes32 routeId
    ) external view override returns (Route memory route) {
        if (_routes[routeId].chainPath.length == 0)
            revert RouteNotFound(routeId);
        return _routes[routeId];
    }

    /// @inheritdoc IDynamicRoutingOrchestrator
        /**
     * @notice Checks if route valid
     * @param routeId The routeId identifier
     * @return valid The valid
     */
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
        /**
     * @notice Estimate fee
     * @param sourceChainId The source chain identifier
     * @param destChainId The destination chain identifier
     * @param amount The amount to process
     * @return fee The fee
     */
function estimateFee(
        uint256 sourceChainId,
        uint256 destChainId,
        uint256 amount
    ) external view override returns (uint256 fee) {
        if (!poolExists[destChainId]) revert PoolNotFound(destChainId);

        AdapterCapacity storage destPool = _pools[destChainId];
        fee = destPool.currentFee;

        // Surcharge for large amounts relative to capacity
        if (destPool.availableCapacity > 0 && amount > 0) {
            uint256 impact = (amount * BPS) / destPool.availableCapacity;
            // Add impact premium: fee * (1 + impact/10000)
            fee = fee + (fee * impact) / BPS;
        }

        // Add source fee if applicable
        if (poolExists[sourceChainId]) {
            fee +=
                _pools[sourceChainId].currentFee /
                SOURCE_CHAIN_WEIGHT_DIVISOR;
        }
    }

    /// @inheritdoc IDynamicRoutingOrchestrator
        /**
     * @notice Returns the adapters for chain
     * @param chainId The chain identifier
     * @return adapters The adapters
     */
function getAdaptersForChain(
        uint256 chainId
    ) external view override returns (address[] memory adapters) {
        return _chainAdapters[chainId];
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
        /**
     * @notice Pauses the operation
     */
function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause the orchestrator
        /**
     * @notice Unpauses the operation
     */
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

        AdapterCapacity storage destPool = _pools[request.destChainId];
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
        address[] storage bridges = _chainAdapters[request.destChainId];
        if (bridges.length == 0) return route; // Empty route = no viable path

        // Find best bridge for this hop
        (address bestAdapter, ) = _findBestAdapter(
            request.sourceChainId,
            request.destChainId,
            request.amount,
            request.urgency
        );

        if (bestAdapter == address(0)) return route;

        AdapterCapacity storage destPool = _pools[request.destChainId];

        // Check capacity
        if (destPool.availableCapacity < request.amount) {
            return route; // Insufficient capacity
        }

        // Build route
        route.chainPath = new uint256[](2);
        route.chainPath[0] = request.sourceChainId;
        route.chainPath[1] = request.destChainId;

        route.relayAdapters = new address[](1);
        route.relayAdapters[0] = bestAdapter;

        // Calculate cost
        route.totalCost = _calculateHopCost(
            request.destChainId,
            request.amount
        );

        // Estimated time
        route.estimatedTime = destPool.avgCompletionTime;

        // Success probability from bridge metrics
        AdapterMetrics storage bm = _adapterMetrics[bestAdapter];
        if (bm.totalRelays > 0) {
            route.successProbabilityBps = uint16(
                (bm.successfulRelays * BPS) / bm.totalRelays
            );
        } else {
            route.successProbabilityBps = DEFAULT_SUCCESS_BPS;
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
                bestAdapter
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
        (address adapter1, ) = _findBestAdapter(
            request.sourceChainId,
            intermediateChain,
            request.amount,
            request.urgency
        );
        (address adapter2, ) = _findBestAdapter(
            intermediateChain,
            request.destChainId,
            request.amount,
            request.urgency
        );

        if (adapter1 == address(0) || adapter2 == address(0)) return route;

        AdapterCapacity storage hopPool = _pools[intermediateChain];
        AdapterCapacity storage destPool = _pools[request.destChainId];

        // Check capacity on both hops
        if (
            hopPool.availableCapacity < request.amount ||
            destPool.availableCapacity < request.amount
        ) {
            return route;
        }

        // Build route
        route.chainPath = new uint256[](3);
        route.chainPath[0] = request.sourceChainId;
        route.chainPath[1] = intermediateChain;
        route.chainPath[2] = request.destChainId;

        route.relayAdapters = new address[](2);
        route.relayAdapters[0] = adapter1;
        route.relayAdapters[1] = adapter2;

        // Cost: sum of both hops
        route.totalCost =
            _calculateHopCost(intermediateChain, request.amount) +
            _calculateHopCost(request.destChainId, request.amount);

        // Time: sum of both hops
        route.estimatedTime =
            hopPool.avgCompletionTime +
            destPool.avgCompletionTime;

        // Success probability: product of both hops
        AdapterMetrics storage bm1 = _adapterMetrics[adapter1];
        AdapterMetrics storage bm2 = _adapterMetrics[adapter2];

        uint16 prob1 = bm1.totalRelays > 0
            ? uint16((bm1.successfulRelays * BPS) / bm1.totalRelays)
            : DEFAULT_SUCCESS_BPS;
        uint16 prob2 = bm2.totalRelays > 0
            ? uint16((bm2.successfulRelays * BPS) / bm2.totalRelays)
            : DEFAULT_SUCCESS_BPS;

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
                adapter1,
                adapter2
            )
        );
    }

    /**
     * @dev Find the best bridge adapter for a specific hop
     * @return bestAdapter Address of best bridge (0 if none)
     * @return bestScore Score of best bridge
     */
    function _findBestAdapter(
        uint256 sourceChain,
        uint256 destChain,
        uint256 /* amount */,
        Urgency urgency
    ) internal view returns (address bestAdapter, uint16 bestScore) {
        address[] storage bridges = _chainAdapters[destChain];

        for (uint256 i = 0; i < bridges.length; ++i) {
            address adapter = bridges[i];
            AdapterMetrics storage bm = _adapterMetrics[adapter];

            if (!bm.isActive) continue;
            if (!adapterSupportsChain[adapter][sourceChain]) continue;

            uint16 score = _scoreBridge(bm, urgency);
            if (score > bestScore) {
                bestScore = score;
                bestAdapter = adapter;
            }
        }
    }

    /**
     * @dev Score a bridge based on urgency preference
     */
    function _scoreBridge(
        AdapterMetrics storage bm,
        Urgency urgency
    ) internal view returns (uint16) {
        uint16 reliabilityScore;
        if (bm.totalRelays > 0) {
            reliabilityScore = uint16(
                (bm.successfulRelays * BPS) / bm.totalRelays
            );
        } else {
            reliabilityScore = DEFAULT_SUCCESS_BPS;
        }

        uint16 speedScore;
        if (bm.avgLatency <= LATENCY_EXCELLENT) {
            speedScore = BPS;
        } else if (bm.avgLatency <= LATENCY_GOOD) {
            speedScore = 8000;
        } else if (bm.avgLatency <= LATENCY_MODERATE) {
            speedScore = 6000;
        } else if (bm.avgLatency <= LATENCY_SLOW) {
            speedScore = 4000;
        } else {
            speedScore = CONFIDENCE_VERY_LOW_BPS;
        }

        uint16 secScore = bm.securityScoreBps;

        // Recency penalty: reduce score if recent failure
        uint16 recencyPenalty = 0;
        if (
            bm.lastFailure > 0 &&
            block.timestamp - bm.lastFailure < RECENT_FAILURE_WINDOW
        ) {
            recencyPenalty = RECENT_FAILURE_PENALTY_BPS;
        } else if (
            bm.lastFailure > 0 &&
            block.timestamp - bm.lastFailure < MODERATE_FAILURE_WINDOW
        ) {
            recencyPenalty = MODERATE_FAILURE_PENALTY_BPS;
        }

        // Weighted based on urgency
        uint16 score;
        if (urgency == Urgency.INSTANT || urgency == Urgency.FAST) {
            // Speed-weighted
            score = uint16(
                (uint256(speedScore) *
                    FAST_SPEED_WEIGHT +
                    uint256(reliabilityScore) *
                    FAST_RELIABILITY_WEIGHT +
                    uint256(secScore) *
                    FAST_SECURITY_WEIGHT) / BPS
            );
        } else if (urgency == Urgency.ECONOMY) {
            // Security/reliability-weighted (cheapest reliable path)
            score = uint16(
                (uint256(reliabilityScore) *
                    ECONOMY_RELIABILITY_WEIGHT +
                    uint256(secScore) *
                    ECONOMY_SECURITY_WEIGHT +
                    uint256(speedScore) *
                    ECONOMY_SPEED_WEIGHT) / BPS
            );
        } else {
            // Standard: balanced
            score = uint16(
                (uint256(reliabilityScore) *
                    STANDARD_RELIABILITY_WEIGHT +
                    uint256(speedScore) *
                    STANDARD_SPEED_WEIGHT +
                    uint256(secScore) *
                    STANDARD_SECURITY_WEIGHT) / BPS
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
            costScore = BPS;
        } else if (route.totalCost >= MAX_BASE_FEE) {
            costScore = 0;
        } else {
            costScore = uint16(BPS - (route.totalCost * BPS) / MAX_BASE_FEE);
        }

        // Normalize speed (inverse: lower time = higher score)
        uint16 speedScore;
        if (route.estimatedTime <= LATENCY_EXCELLENT) {
            speedScore = BPS;
        } else if (route.estimatedTime <= LATENCY_GOOD) {
            speedScore = 8500;
        } else if (route.estimatedTime <= LATENCY_MODERATE) {
            speedScore = 7000;
        } else if (route.estimatedTime <= LATENCY_SLOW) {
            speedScore = 5000;
        } else if (route.estimatedTime <= LATENCY_VERY_SLOW) {
            speedScore = 3000;
        } else {
            speedScore = 1000;
        }

        // Reliability is already in bps
        uint16 reliabilityScore = route.successProbabilityBps;

        // Security: average of bridge security scores in route
        uint16 securityScore = 0;
        if (route.relayAdapters.length > 0) {
            uint256 totalSec = 0;
            for (uint256 i = 0; i < route.relayAdapters.length; ++i) {
                totalSec += _adapterMetrics[route.relayAdapters[i]]
                    .securityScoreBps;
            }
            securityScore = uint16(totalSec / route.relayAdapters.length);
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
        AdapterCapacity storage pool = _pools[destChain];
        cost = pool.currentFee;

        // Capacity impact premium
        if (pool.availableCapacity > 0 && amount > 0) {
            uint256 impact = (amount * BPS) / pool.availableCapacity;
            cost = cost + (cost * impact) / BPS;
        }
    }

    /**
     * @dev Calculate utilization ratio in bps
     */
    function _calculateUtilization(
        AdapterCapacity storage pool
    ) internal view returns (uint16) {
        if (pool.totalCapacity == 0) return 0;
        if (pool.availableCapacity >= pool.totalCapacity) return 0;
        uint256 used = pool.totalCapacity - pool.availableCapacity;
        uint256 utilBps = (used * BPS) / pool.totalCapacity;
        return utilBps > BPS ? uint16(BPS) : uint16(utilBps);
    }

    /**
     * @dev Adjust fee based on utilization (EIP-1559 style)
     */
    function _adjustFee(AdapterCapacity storage pool) internal {
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
