// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title NetworkHealthMonitor
 * @author Soul Protocol
 * @notice Global network health monitoring and automated circuit breakers
 * @dev Battle-tested patterns for network resilience and observability
 *
 * Security Properties:
 * - Automated anomaly detection with configurable thresholds
 * - Multi-level circuit breakers (warning, critical, emergency)
 * - Heartbeat monitoring for critical components
 * - Historical metrics for trend analysis
 */
contract NetworkHealthMonitor is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant MONITOR_ROLE = keccak256("MONITOR_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Health status levels
    enum HealthLevel {
        Healthy, // Normal operation
        Degraded, // Performance issues, still functional
        Warning, // Anomalies detected, investigation needed
        Critical, // Major issues, limited functionality
        Emergency // System halted, emergency mode
    }

    /// @notice Component status
    struct ComponentStatus {
        bytes32 componentId;
        string name;
        address contractAddress;
        HealthLevel health;
        uint256 lastHeartbeat;
        uint256 heartbeatInterval;
        uint256 failedHeartbeats;
        uint256 successfulOperations;
        uint256 failedOperations;
        bool isActive;
    }

    /// @notice Metric snapshot for trend analysis
    struct MetricSnapshot {
        uint256 timestamp;
        uint256 totalTransactions;
        uint256 failedTransactions;
        uint256 averageGasUsed;
        uint256 activeRelayers;
        uint256 pendingProofs;
        uint256 challengeCount;
        HealthLevel overallHealth;
    }

    /// @notice Alert configuration
    struct AlertConfig {
        uint256 failureRateThreshold; // Basis points (100 = 1%)
        uint256 responseTimeThreshold; // Seconds
        uint256 minHeartbeatInterval; // Seconds
        uint256 maxPendingOperations; // Count
        uint256 maxConsecutiveFailures; // Count
        bool autoCircuitBreak; // Auto-trigger circuit breaker
    }

    /// @notice Incident record
    struct Incident {
        bytes32 incidentId;
        bytes32 componentId;
        HealthLevel severity;
        string description;
        uint256 timestamp;
        uint256 resolvedAt;
        bool resolved;
        address reporter;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Registered components
    mapping(bytes32 => ComponentStatus) public components;
    bytes32[] public componentIds;

    /// @notice Component addresses to IDs
    mapping(address => bytes32) public addressToComponent;

    /// @notice Historical metrics (rolling 30 days, hourly snapshots)
    MetricSnapshot[] public metricHistory;
    uint256 public constant MAX_HISTORY_SIZE = 720; // 30 days * 24 hours

    /// @notice Alert configuration
    AlertConfig public alertConfig;

    /// @notice Active incidents
    mapping(bytes32 => Incident) public incidents;
    bytes32[] public activeIncidentIds;
    uint256 public totalIncidents;

    /// @notice Current overall health
    HealthLevel public currentHealth;

    /// @notice Circuit breaker states per component
    mapping(bytes32 => bool) public circuitBreakerTriggered;

    /// @notice Global circuit breaker
    bool public globalCircuitBreaker;

    /// @notice Cumulative metrics
    uint256 public totalOperations;
    uint256 public totalFailures;
    uint256 public lastMetricSnapshot;

    /// @notice Consecutive failure tracking
    mapping(bytes32 => uint256) public consecutiveFailures;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event ComponentRegistered(
        bytes32 indexed componentId,
        string name,
        address contractAddress
    );
    event ComponentUpdated(bytes32 indexed componentId, HealthLevel health);
    event HeartbeatReceived(bytes32 indexed componentId, uint256 timestamp);
    event HeartbeatMissed(bytes32 indexed componentId, uint256 missedCount);

    event HealthStatusChanged(
        HealthLevel indexed oldHealth,
        HealthLevel indexed newHealth,
        string reason
    );
    event CircuitBreakerTriggered(bytes32 indexed componentId, string reason);
    event CircuitBreakerReset(bytes32 indexed componentId);
    event GlobalCircuitBreakerTriggered(string reason);
    event GlobalCircuitBreakerReset();

    event IncidentCreated(
        bytes32 indexed incidentId,
        bytes32 indexed componentId,
        HealthLevel severity
    );
    event IncidentResolved(bytes32 indexed incidentId, uint256 resolvedAt);

    event MetricSnapshotRecorded(uint256 indexed timestamp, HealthLevel health);
    event AnomalyDetected(
        bytes32 indexed componentId,
        string anomalyType,
        uint256 value
    );

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error ComponentNotFound(bytes32 componentId);
    error ComponentAlreadyExists(bytes32 componentId);
    error InvalidThreshold();
    error CircuitBreakerActive();
    error IncidentNotFound(bytes32 incidentId);
    error IncidentAlreadyResolved(bytes32 incidentId);

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(MONITOR_ROLE, msg.sender);
        _grantRole(EMERGENCY_ROLE, msg.sender);

        // Default alert configuration
        alertConfig = AlertConfig({
            failureRateThreshold: 500, // 5%
            responseTimeThreshold: 30, // 30 seconds
            minHeartbeatInterval: 60, // 1 minute
            maxPendingOperations: 10000, // 10k pending
            maxConsecutiveFailures: 5, // 5 failures
            autoCircuitBreak: true
        });

        currentHealth = HealthLevel.Healthy;
        lastMetricSnapshot = block.timestamp;
    }

    /*//////////////////////////////////////////////////////////////
                        COMPONENT MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a new component for monitoring
     * @param name Human-readable component name
     * @param contractAddress The contract address to monitor
     * @param heartbeatInterval Expected heartbeat interval in seconds
     */
    function registerComponent(
        string calldata name,
        address contractAddress,
        uint256 heartbeatInterval
    ) external onlyRole(OPERATOR_ROLE) returns (bytes32 componentId) {
        componentId = keccak256(
            abi.encodePacked(name, contractAddress, block.timestamp)
        );

        if (components[componentId].isActive) {
            revert ComponentAlreadyExists(componentId);
        }

        components[componentId] = ComponentStatus({
            componentId: componentId,
            name: name,
            contractAddress: contractAddress,
            health: HealthLevel.Healthy,
            lastHeartbeat: block.timestamp,
            heartbeatInterval: heartbeatInterval,
            failedHeartbeats: 0,
            successfulOperations: 0,
            failedOperations: 0,
            isActive: true
        });

        componentIds.push(componentId);
        addressToComponent[contractAddress] = componentId;

        emit ComponentRegistered(componentId, name, contractAddress);
    }

    /**
     * @notice Deactivate a component
     */
    function deactivateComponent(
        bytes32 componentId
    ) external onlyRole(OPERATOR_ROLE) {
        if (!components[componentId].isActive) {
            revert ComponentNotFound(componentId);
        }
        components[componentId].isActive = false;
        emit ComponentUpdated(componentId, HealthLevel.Healthy);
    }

    /*//////////////////////////////////////////////////////////////
                          HEARTBEAT SYSTEM
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send heartbeat from a monitored component
     * @dev Should be called periodically by monitored contracts
     */
    function heartbeat() external {
        bytes32 componentId = addressToComponent[msg.sender];
        if (componentId == bytes32(0) || !components[componentId].isActive) {
            revert ComponentNotFound(componentId);
        }

        ComponentStatus storage status = components[componentId];
        status.lastHeartbeat = block.timestamp;
        status.failedHeartbeats = 0;

        // Reset consecutive failures on successful heartbeat
        consecutiveFailures[componentId] = 0;

        // Upgrade health if was degraded due to missed heartbeats
        if (
            status.health == HealthLevel.Warning ||
            status.health == HealthLevel.Degraded
        ) {
            status.health = HealthLevel.Healthy;
            emit ComponentUpdated(componentId, HealthLevel.Healthy);
        }

        emit HeartbeatReceived(componentId, block.timestamp);
    }

    /**
     * @notice Check all components for missed heartbeats
     * @dev Should be called periodically by a keeper/bot
     */
    function checkHeartbeats() external onlyRole(MONITOR_ROLE) {
        uint256 len = componentIds.length;
        for (uint256 i = 0; i < len; ) {
            bytes32 componentId = componentIds[i];
            ComponentStatus storage status = components[componentId];

            if (status.isActive) {
                uint256 timeSinceHeartbeat = block.timestamp -
                    status.lastHeartbeat;

                if (timeSinceHeartbeat > status.heartbeatInterval) {
                    status.failedHeartbeats++;
                    emit HeartbeatMissed(componentId, status.failedHeartbeats);

                    // Escalate health based on missed heartbeats
                    if (status.failedHeartbeats >= 5) {
                        _updateComponentHealth(
                            componentId,
                            HealthLevel.Critical
                        );
                    } else if (status.failedHeartbeats >= 3) {
                        _updateComponentHealth(
                            componentId,
                            HealthLevel.Warning
                        );
                    } else if (status.failedHeartbeats >= 1) {
                        _updateComponentHealth(
                            componentId,
                            HealthLevel.Degraded
                        );
                    }
                }
            }
            unchecked {
                ++i;
            }
        }

        _evaluateOverallHealth();
    }

    /*//////////////////////////////////////////////////////////////
                        OPERATION REPORTING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Report a successful operation
     */
    function reportSuccess() external {
        bytes32 componentId = addressToComponent[msg.sender];
        if (componentId != bytes32(0) && components[componentId].isActive) {
            components[componentId].successfulOperations++;
            consecutiveFailures[componentId] = 0;
        }
        unchecked {
            ++totalOperations;
        }
    }

    /**
     * @notice Report a failed operation
     * @param reason Failure reason for logging
     */
    function reportFailure(string calldata reason) external {
        bytes32 componentId = addressToComponent[msg.sender];

        if (componentId != bytes32(0) && components[componentId].isActive) {
            components[componentId].failedOperations++;
            consecutiveFailures[componentId]++;

            // Check for auto circuit breaker
            if (
                alertConfig.autoCircuitBreak &&
                consecutiveFailures[componentId] >=
                alertConfig.maxConsecutiveFailures
            ) {
                _triggerCircuitBreaker(componentId, reason);
            }
        }

        unchecked {
            ++totalOperations;
            ++totalFailures;
        }

        // Check failure rate threshold
        if (totalOperations > 100) {
            uint256 failureRate = (totalFailures * 10000) / totalOperations;
            if (failureRate > alertConfig.failureRateThreshold) {
                emit AnomalyDetected(
                    componentId,
                    "HIGH_FAILURE_RATE",
                    failureRate
                );
                _evaluateOverallHealth();
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                        CIRCUIT BREAKERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Trigger circuit breaker for a component
     */
    function triggerCircuitBreaker(
        bytes32 componentId,
        string calldata reason
    ) external onlyRole(OPERATOR_ROLE) {
        _triggerCircuitBreaker(componentId, reason);
    }

    /**
     * @notice Reset circuit breaker for a component
     */
    function resetCircuitBreaker(
        bytes32 componentId
    ) external onlyRole(OPERATOR_ROLE) {
        if (!circuitBreakerTriggered[componentId]) {
            return;
        }

        circuitBreakerTriggered[componentId] = false;
        consecutiveFailures[componentId] = 0;
        components[componentId].health = HealthLevel.Healthy;

        emit CircuitBreakerReset(componentId);
        _evaluateOverallHealth();
    }

    /**
     * @notice Trigger global circuit breaker (emergency)
     */
    function triggerGlobalCircuitBreaker(
        string calldata reason
    ) external onlyRole(EMERGENCY_ROLE) {
        globalCircuitBreaker = true;
        currentHealth = HealthLevel.Emergency;
        _pause();

        emit GlobalCircuitBreakerTriggered(reason);
        emit HealthStatusChanged(currentHealth, HealthLevel.Emergency, reason);
    }

    /**
     * @notice Reset global circuit breaker
     */
    function resetGlobalCircuitBreaker() external onlyRole(EMERGENCY_ROLE) {
        globalCircuitBreaker = false;
        _unpause();
        _evaluateOverallHealth();

        emit GlobalCircuitBreakerReset();
    }

    /**
     * @notice Check if operations should be allowed
     * @param componentId The component to check
     * @return allowed True if operations are allowed
     */
    function isOperationAllowed(
        bytes32 componentId
    ) external view returns (bool allowed) {
        if (globalCircuitBreaker) return false;
        if (circuitBreakerTriggered[componentId]) return false;
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                        INCIDENT MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a new incident
     */
    function createIncident(
        bytes32 componentId,
        HealthLevel severity,
        string calldata description
    ) external onlyRole(MONITOR_ROLE) returns (bytes32 incidentId) {
        incidentId = keccak256(
            abi.encodePacked(componentId, block.timestamp, totalIncidents)
        );

        incidents[incidentId] = Incident({
            incidentId: incidentId,
            componentId: componentId,
            severity: severity,
            description: description,
            timestamp: block.timestamp,
            resolvedAt: 0,
            resolved: false,
            reporter: msg.sender
        });

        activeIncidentIds.push(incidentId);
        unchecked {
            ++totalIncidents;
        }

        emit IncidentCreated(incidentId, componentId, severity);

        // Update component health if incident is critical
        if (severity >= HealthLevel.Critical) {
            _updateComponentHealth(componentId, severity);
        }
    }

    /**
     * @notice Resolve an incident
     */
    function resolveIncident(
        bytes32 incidentId
    ) external onlyRole(OPERATOR_ROLE) {
        Incident storage incident = incidents[incidentId];

        if (incident.timestamp == 0) {
            revert IncidentNotFound(incidentId);
        }
        if (incident.resolved) {
            revert IncidentAlreadyResolved(incidentId);
        }

        incident.resolved = true;
        incident.resolvedAt = block.timestamp;

        // Remove from active incidents
        _removeFromActiveIncidents(incidentId);

        emit IncidentResolved(incidentId, block.timestamp);
    }

    /*//////////////////////////////////////////////////////////////
                          METRICS & ANALYTICS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Record a metric snapshot
     * @dev Should be called hourly by a keeper
     */
    function recordMetricSnapshot(
        uint256 activeRelayers,
        uint256 pendingProofs,
        uint256 challengeCount,
        uint256 averageGasUsed
    ) external onlyRole(MONITOR_ROLE) {
        MetricSnapshot memory snapshot = MetricSnapshot({
            timestamp: block.timestamp,
            totalTransactions: totalOperations,
            failedTransactions: totalFailures,
            averageGasUsed: averageGasUsed,
            activeRelayers: activeRelayers,
            pendingProofs: pendingProofs,
            challengeCount: challengeCount,
            overallHealth: currentHealth
        });

        // Maintain rolling window
        if (metricHistory.length >= MAX_HISTORY_SIZE) {
            // Shift array (gas-expensive but necessary for accurate history)
            for (uint256 i = 0; i < metricHistory.length - 1; ) {
                metricHistory[i] = metricHistory[i + 1];
                unchecked {
                    ++i;
                }
            }
            metricHistory.pop();
        }

        metricHistory.push(snapshot);
        lastMetricSnapshot = block.timestamp;

        emit MetricSnapshotRecorded(block.timestamp, currentHealth);

        // Check for anomalies in pending operations
        if (pendingProofs > alertConfig.maxPendingOperations) {
            emit AnomalyDetected(
                bytes32(0),
                "HIGH_PENDING_PROOFS",
                pendingProofs
            );
        }
    }

    /**
     * @notice Get recent metrics
     */
    function getRecentMetrics(
        uint256 count
    ) external view returns (MetricSnapshot[] memory) {
        uint256 len = metricHistory.length;
        uint256 resultCount = count < len ? count : len;

        MetricSnapshot[] memory result = new MetricSnapshot[](resultCount);

        for (uint256 i = 0; i < resultCount; ) {
            result[i] = metricHistory[len - resultCount + i];
            unchecked {
                ++i;
            }
        }

        return result;
    }

    /**
     * @notice Get component health summary
     */
    function getHealthSummary()
        external
        view
        returns (
            HealthLevel overall,
            uint256 healthyCount,
            uint256 degradedCount,
            uint256 warningCount,
            uint256 criticalCount,
            uint256 activeIncidents
        )
    {
        overall = currentHealth;
        activeIncidents = activeIncidentIds.length;

        uint256 len = componentIds.length;
        for (uint256 i = 0; i < len; ) {
            ComponentStatus storage status = components[componentIds[i]];
            if (status.isActive) {
                if (status.health == HealthLevel.Healthy) healthyCount++;
                else if (status.health == HealthLevel.Degraded) degradedCount++;
                else if (status.health == HealthLevel.Warning) warningCount++;
                else if (status.health >= HealthLevel.Critical) criticalCount++;
            }
            unchecked {
                ++i;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                        CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update alert configuration
     */
    function updateAlertConfig(
        AlertConfig calldata newConfig
    ) external onlyRole(OPERATOR_ROLE) {
        if (newConfig.failureRateThreshold > 10000) revert InvalidThreshold();
        alertConfig = newConfig;
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _triggerCircuitBreaker(
        bytes32 componentId,
        string memory reason
    ) internal {
        circuitBreakerTriggered[componentId] = true;
        components[componentId].health = HealthLevel.Critical;

        emit CircuitBreakerTriggered(componentId, reason);
        _evaluateOverallHealth();
    }

    function _updateComponentHealth(
        bytes32 componentId,
        HealthLevel health
    ) internal {
        HealthLevel oldHealth = components[componentId].health;
        if (oldHealth != health) {
            components[componentId].health = health;
            emit ComponentUpdated(componentId, health);
        }
    }

    function _evaluateOverallHealth() internal {
        HealthLevel worst = HealthLevel.Healthy;

        uint256 len = componentIds.length;
        for (uint256 i = 0; i < len; ) {
            ComponentStatus storage status = components[componentIds[i]];
            if (status.isActive && status.health > worst) {
                worst = status.health;
            }
            unchecked {
                ++i;
            }
        }

        if (activeIncidentIds.length > 0) {
            // Check incident severity
            for (uint256 i = 0; i < activeIncidentIds.length; ) {
                if (incidents[activeIncidentIds[i]].severity > worst) {
                    worst = incidents[activeIncidentIds[i]].severity;
                }
                unchecked {
                    ++i;
                }
            }
        }

        if (currentHealth != worst) {
            HealthLevel oldHealth = currentHealth;
            currentHealth = worst;
            emit HealthStatusChanged(oldHealth, worst, "Health re-evaluated");
        }
    }

    function _removeFromActiveIncidents(bytes32 incidentId) internal {
        uint256 len = activeIncidentIds.length;
        for (uint256 i = 0; i < len; ) {
            if (activeIncidentIds[i] == incidentId) {
                activeIncidentIds[i] = activeIncidentIds[len - 1];
                activeIncidentIds.pop();
                break;
            }
            unchecked {
                ++i;
            }
        }
    }
}
