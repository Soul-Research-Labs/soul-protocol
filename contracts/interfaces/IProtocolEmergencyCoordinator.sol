// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IProtocolEmergencyCoordinator
 * @notice Interface for the unified emergency coordinator that wires together
 *         ProtocolHealthAggregator, EmergencyRecovery, EnhancedKillSwitch,
 *         RelayCircuitBreaker, and ZaseonProtocolHub.
 */
interface IProtocolEmergencyCoordinator {
    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Unified emergency severity — maps to subsystem-specific levels
    enum Severity {
        GREEN, // Normal operations
        YELLOW, // Warning — monitoring alert, no action taken yet
        ORANGE, // Degraded — non-critical modules paused, rate limits tightened
        RED, // Critical — all modules paused, bridges halted
        BLACK // Terminal — governance-only recovery required
    }

    /*//////////////////////////////////////////////////////////////
                             STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct Incident {
        uint256 id;
        Severity severity;
        address initiator;
        uint48 timestamp;
        uint48 resolvedAt;
        string reason;
        bytes32 evidenceHash;
    }

    struct SubsystemStatus {
        bool healthAggregatorHealthy;
        bool emergencyRecoveryMonitoring;
        bool killSwitchNone;
        bool circuitBreakerNormal;
        bool hubPaused;
    }

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event IncidentOpened(
        uint256 indexed incidentId,
        Severity severity,
        address indexed initiator,
        string reason
    );
    event IncidentResolved(
        uint256 indexed incidentId,
        Severity severity,
        address indexed resolver
    );
    event SeverityEscalated(
        Severity indexed oldLevel,
        Severity indexed newLevel,
        uint256 indexed incidentId
    );
    event EmergencyPlanExecuted(
        Severity severity,
        uint256 indexed incidentId,
        uint8 actionsPerformed
    );
    event RecoveryValidated(uint256 indexed incidentId, bool allClear);
    event RecoveryExecuted(uint256 indexed incidentId, Severity newSeverity);

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error InvalidEscalation(Severity current, Severity requested);
    error NoActiveIncident();
    error IncidentAlreadyActive();
    error IncidentNotActive(uint256 incidentId);
    error RecoveryNotClear();
    error CooldownNotElapsed(uint48 nextAllowed);

    /*//////////////////////////////////////////////////////////////
                            FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Open a new incident and escalate to the specified severity
    function openIncident(
        Severity severity,
        string calldata reason,
        bytes32 evidenceHash
    ) external returns (uint256 incidentId);

    /// @notice Escalate an existing incident to a higher severity
    function escalateIncident(
        uint256 incidentId,
        Severity newSeverity
    ) external;

    /// @notice Execute the emergency plan for the current severity level
    function executeEmergencyPlan(uint256 incidentId) external;

    /// @notice Validate that all subsystems are healthy enough for recovery
    function validateRecovery(
        uint256 incidentId
    ) external view returns (bool allClear, SubsystemStatus memory status);

    /// @notice Execute recovery after validation passes
    function executeRecovery(uint256 incidentId) external;

    /// @notice Get aggregate status of all connected subsystems
    function getSubsystemStatus()
        external
        view
        returns (SubsystemStatus memory);

    /// @notice Get the current unified severity
    function currentSeverity() external view returns (Severity);

    /// @notice Get the active incident ID (0 = none)
    function activeIncidentId() external view returns (uint256);

    /// @notice Get incident details
    function getIncident(
        uint256 incidentId
    ) external view returns (Incident memory);
}
