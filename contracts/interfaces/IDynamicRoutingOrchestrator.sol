// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IDynamicRoutingOrchestrator
 * @author Soul Protocol
 * @notice Interface for dynamic cross-chain proof routing with bridge capacity awareness
 * @dev Routes ZK proof relay requests through optimal bridge adapters.
 *      Soul Protocol is proof middleware — it does NOT manage liquidity pools.
 *      BridgeCapacity data is oracle-provided metadata about external bridge adapters.
 *      The orchestrator uses this data to select the best route for proof delivery,
 *      optimizing for cost, latency, and success probability.
 *      Supports multi-hop routing through intermediate chains.
 */
interface IDynamicRoutingOrchestrator {
    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Urgency level for route selection — affects cost/speed tradeoff
    enum Urgency {
        ECONOMY, // Cheapest route, no time constraint
        STANDARD, // Balanced cost and speed
        FAST, // Prioritize speed, higher cost acceptable
        INSTANT // Fastest possible, cost secondary
    }

    /// @notice Health status of a bridge adapter's capacity on a given chain
    enum PoolStatus {
        ACTIVE, // Normal operation
        DEGRADED, // Reduced capacity or elevated error rate
        PAUSED, // Temporarily unavailable
        DEPRECATED // Permanently disabled, drain only
    }

    /// @notice Status of a route execution
    enum RouteStatus {
        PENDING, // Route calculated, not yet executed
        EXECUTING, // Execution in progress
        COMPLETED, // Successfully settled
        FAILED, // Execution failed
        EXPIRED // Route expired before execution
    }

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Oracle-observed bridge adapter capacity for a specific chain.
    ///         Soul does NOT manage these pools — this is observed metadata from
    ///         external bridge adapters used to make routing decisions.
    struct BridgeCapacity {
        uint256 chainId; // Target chain ID
        uint256 availableCapacity; // Current available bridge throughput capacity (wei-equivalent)
        uint256 totalCapacity; // Total bridge adapter capacity (wei-equivalent)
        uint16 utilizationBps; // Current utilization (0-10000 bps)
        uint48 avgSettlementTime; // Avg settlement time (seconds)
        uint256 currentFee; // Current base fee (wei)
        uint48 lastUpdated; // Last oracle update timestamp
        PoolStatus status; // Pool health status
    }

    /// @notice A calculated route through one or more chains
    struct Route {
        bytes32 routeId; // Unique route identifier
        uint256[] chainPath; // Ordered chain IDs [source, ..hops.., dest]
        address[] bridgeAdapters; // Bridge adapter per hop
        uint256 totalCost; // Total estimated cost (wei)
        uint48 estimatedTime; // Estimated total settlement time (seconds)
        uint16 successProbabilityBps; // Success probability (0-10000 bps)
        uint16 routeScoreBps; // Composite score (0-10000 bps)
        uint48 calculatedAt; // Timestamp of calculation
        uint48 expiresAt; // Route validity expiry
        RouteStatus status; // Current status
    }

    /// @notice User's route request parameters
    struct RouteRequest {
        uint256 sourceChainId; // Source chain
        uint256 destChainId; // Destination chain
        uint256 amount; // Transfer amount (wei)
        Urgency urgency; // Speed/cost preference
        uint256 maxCost; // Maximum acceptable cost (wei, 0 = no limit)
        uint48 maxTime; // Maximum acceptable time (seconds, 0 = no limit)
        uint16 minSuccessBps; // Minimum success probability (bps, 0 = no limit)
        bool requirePrivacy; // Must use privacy-preserving route
    }

    /// @notice Bridge performance metrics tracked by the orchestrator
    struct BridgeMetrics {
        address adapter; // Bridge adapter address
        uint256 totalTransfers; // Total transfers processed
        uint256 successfulTransfers; // Successful completions
        uint256 totalValueRouted; // Cumulative value routed (wei)
        uint48 avgLatency; // Average latency (seconds)
        uint16 securityScoreBps; // Security score (0-10000 bps)
        uint48 lastFailure; // Last failure timestamp
        bool isActive; // Currently operational
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event PoolRegistered(
        uint256 indexed chainId,
        uint256 totalCapacity,
        uint256 initialFee
    );

    event PoolStatusChanged(
        uint256 indexed chainId,
        PoolStatus oldStatus,
        PoolStatus newStatus
    );

    event LiquidityUpdated(
        uint256 indexed chainId,
        uint256 oldCapacity,
        uint256 newCapacity,
        uint16 utilizationBps
    );

    event RouteCalculated(
        bytes32 indexed routeId,
        uint256 sourceChainId,
        uint256 destChainId,
        uint256 totalCost,
        uint48 estimatedTime,
        uint16 successProbabilityBps,
        uint256 hops
    );

    event RouteExecuted(
        bytes32 indexed routeId,
        address indexed executor,
        uint256 amount,
        uint256 actualCost
    );

    event RouteCompleted(
        bytes32 indexed routeId,
        uint48 actualTime,
        uint256 actualCost
    );

    event RouteFailed(bytes32 indexed routeId, string reason);

    event BridgeRegistered(address indexed adapter, uint256[] supportedChains);

    event BridgeMetricsUpdated(
        address indexed adapter,
        uint256 totalTransfers,
        uint48 avgLatency
    );

    event FeeAdjusted(
        uint256 indexed chainId,
        uint256 oldFee,
        uint256 newFee,
        uint16 utilizationBps
    );

    /*//////////////////////////////////////////////////////////////
                            CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error PoolAlreadyRegistered(uint256 chainId);
    error PoolNotFound(uint256 chainId);
    error PoolNotActive(uint256 chainId);
    error InsufficientLiquidity(
        uint256 chainId,
        uint256 required,
        uint256 available
    );
    error RouteNotFound(bytes32 routeId);
    error RouteExpired(bytes32 routeId);
    error RouteAlreadyExecuted(bytes32 routeId);
    error NoViableRoute(uint256 sourceChainId, uint256 destChainId);
    error CostExceedsMax(uint256 cost, uint256 maxCost);
    error TimeExceedsMax(uint48 time, uint48 maxTime);
    error SuccessBelowMin(uint16 probability, uint16 minRequired);
    error BridgeAlreadyRegistered(address adapter);
    error BridgeNotRegistered(address adapter);
    error InvalidChainId();
    error InvalidAmount();
    error StaleOracleData(uint256 chainId, uint48 lastUpdated);
    error ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                           CORE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Find the optimal route for a cross-chain transfer
     * @param request Route request parameters
     * @return route The optimal calculated route
     */
    function findOptimalRoute(
        RouteRequest calldata request
    ) external view returns (Route memory route);

    /**
     * @notice Find multiple viable routes ranked by score
     * @param request Route request parameters
     * @param maxRoutes Maximum number of routes to return
     * @return routes Array of viable routes, best first
     */
    function findRoutes(
        RouteRequest calldata request,
        uint8 maxRoutes
    ) external view returns (Route[] memory routes);

    /**
     * @notice Execute a previously calculated route
     * @param routeId The route to execute
     * @return executionId Unique execution tracking ID
     */
    function executeRoute(
        bytes32 routeId
    ) external payable returns (bytes32 executionId);

    /**
     * @notice Predict settlement time for a transfer
     * @param sourceChainId Source chain
     * @param destChainId Destination chain
     * @param amount Transfer amount
     * @return estimatedTime Predicted time in seconds
     * @return confidence Confidence level (0-10000 bps)
     */
    function predictSettlementTime(
        uint256 sourceChainId,
        uint256 destChainId,
        uint256 amount
    ) external view returns (uint48 estimatedTime, uint16 confidence);

    /*//////////////////////////////////////////////////////////////
                        LIQUIDITY MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a new liquidity pool for a chain
     * @param chainId The chain ID
     * @param totalCapacity Initial total liquidity
     * @param initialFee Initial base fee
     */
    function registerPool(
        uint256 chainId,
        uint256 totalCapacity,
        uint256 initialFee
    ) external;

    /**
     * @notice Update liquidity for a chain (oracle role)
     * @param chainId The chain to update
     * @param newAvailableCapacity Updated available liquidity
     */
    function updateLiquidity(
        uint256 chainId,
        uint256 newAvailableCapacity
    ) external;

    /**
     * @notice Batch update liquidity for multiple chains
     * @param chainIds Array of chain IDs
     * @param newCapacities Array of new available liquidities
     */
    function batchUpdateLiquidity(
        uint256[] calldata chainIds,
        uint256[] calldata newCapacities
    ) external;

    /**
     * @notice Update pool status
     * @param chainId The chain to update
     * @param newStatus New pool status
     */
    function setPoolStatus(uint256 chainId, PoolStatus newStatus) external;

    /*//////////////////////////////////////////////////////////////
                        BRIDGE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a bridge adapter with supported chains
     * @param adapter The bridge adapter address
     * @param supportedChains Chain IDs this bridge supports
     * @param securityScoreBps Initial security score (bps)
     */
    function registerBridge(
        address adapter,
        uint256[] calldata supportedChains,
        uint16 securityScoreBps
    ) external;

    /**
     * @notice Record bridge transfer outcome for metrics
     * @param adapter Bridge adapter address
     * @param success Whether transfer succeeded
     * @param latency Actual latency in seconds
     * @param value Transfer value
     */
    function recordBridgeOutcome(
        address adapter,
        bool success,
        uint48 latency,
        uint256 value
    ) external;

    /*//////////////////////////////////////////////////////////////
                              VIEWS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get liquidity pool info for a chain
     * @param chainId The chain ID
     * @return pool The liquidity pool data
     */
    function getPool(
        uint256 chainId
    ) external view returns (BridgeCapacity memory pool);

    /**
     * @notice Get bridge metrics
     * @param adapter Bridge adapter address
     * @return metrics The bridge performance metrics
     */
    function getBridgeMetrics(
        address adapter
    ) external view returns (BridgeMetrics memory metrics);

    /**
     * @notice Get a previously calculated route
     * @param routeId Route identifier
     * @return route The route data
     */
    function getRoute(
        bytes32 routeId
    ) external view returns (Route memory route);

    /**
     * @notice Check if a route is still valid (not expired)
     * @param routeId Route identifier
     * @return valid Whether the route can still be executed
     */
    function isRouteValid(bytes32 routeId) external view returns (bool valid);

    /**
     * @notice Get the current fee for a chain pair
     * @param sourceChainId Source chain
     * @param destChainId Destination chain
     * @param amount Transfer amount
     * @return fee Estimated fee in wei
     */
    function estimateFee(
        uint256 sourceChainId,
        uint256 destChainId,
        uint256 amount
    ) external view returns (uint256 fee);

    /**
     * @notice Get all registered bridge adapters for a chain
     * @param chainId The chain ID
     * @return adapters Array of bridge adapter addresses
     */
    function getBridgesForChain(
        uint256 chainId
    ) external view returns (address[] memory adapters);
}
