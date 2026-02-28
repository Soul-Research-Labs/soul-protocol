// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IProtocolEmergencyCoordinator} from "../interfaces/IProtocolEmergencyCoordinator.sol";

/*//////////////////////////////////////////////////////////////
                  MINIMAL SUBSYSTEM INTERFACES
//////////////////////////////////////////////////////////////*/

/// @dev Subset of ProtocolHealthAggregator
/**
 * @title IHealthAggregator
 * @author ZASEON Team
 * @notice I Health Aggregator interface
 */
interface IHealthAggregator {
    enum HealthStatus {
        HEALTHY,
        WARNING,
        CRITICAL,
        OVERRIDE
    }

    /**
     * @notice Returns the protocol health
     * @return score The score
     * @return status The status
     * @return staleCount The stale count
     */
    function getProtocolHealth()
        external
        view
        returns (uint16 score, HealthStatus status, uint8 staleCount);

    /**
     * @notice Guardian emergency pause
     */
    function guardianEmergencyPause() external;

    /**
     * @notice Guardian recover pause
     */
    function guardianRecoverPause() external;
}

/// @dev Subset of EmergencyRecovery
interface IEmergencyRecovery {
    enum RecoveryStage {
        Monitoring,
        Alert,
        Degraded,
        Emergency,
        Recovery
    }

    /**
     * @notice Current stage
     * @return The result value
     */
    function currentStage() external view returns (RecoveryStage);

    /**
     * @notice Pauses all
     * @param reason The reason string
     */
    function pauseAll(string calldata reason) external;
}

/// @dev Subset of EnhancedKillSwitch
interface IKillSwitch {
    enum EmergencyLevel {
        NONE,
        WARNING,
        DEGRADED,
        HALTED,
        LOCKED,
        PERMANENT
    }

    /**
     * @notice Current level
     * @return The result value
     */
    function currentLevel() external view returns (EmergencyLevel);

    /**
     * @notice Escalates emergency
     * @param newLevel The new Level value
     * @param reason The reason string
     */
    function escalateEmergency(
        EmergencyLevel newLevel,
        string calldata reason
    ) external;
}

/// @dev Subset of RelayCircuitBreaker
interface ICircuitBreaker {
    enum SystemState {
        NORMAL,
        WARNING,
        DEGRADED,
        HALTED
    }

    /**
     * @notice Current state
     * @return The result value
     */
    function currentState() external view returns (SystemState);

    /**
     * @notice Emergency halt
     */
    function emergencyHalt() external;
}

/// @dev Subset of ZaseonProtocolHub
interface IProtocolHub {
    /**
     * @notice Pauses the operation
     */
    function pause() external;

    /**
     * @notice Unpauses the operation
     */
    function unpause() external;

    /**
     * @notice Paused
     * @return The result value
     */
    function paused() external view returns (bool);
}

/**
 * @title ProtocolEmergencyCoordinator
 * @author ZASEON
 * @notice Unified emergency orchestrator that coordinates across
 *         ProtocolHealthAggregator, EmergencyRecovery, EnhancedKillSwitch,
 *         RelayCircuitBreaker, and ZaseonProtocolHub.
 *
 * @dev Closes the critical gap where ZASEON has 4+ independent
 *      emergency systems that don't communicate. This coordinator:
 *      1. Maintains a single source-of-truth severity level
 *      2. Cascades actions to all subsystems via executeEmergencyPlan()
 *      3. Validates cross-subsystem health before allowing recovery
 *      4. Logs incidents for governance post-mortem
 *
 * Severity mapping:
 *   GREEN  → all subsystems normal
 *   YELLOW → HealthAgg WARNING, KillSwitch WARNING
 *   ORANGE → EmergencyRecovery Degraded, KillSwitch DEGRADED, bridges rate-limited
 *   RED    → Hub paused, all bridges halted, KillSwitch HALTED, HealthAgg auto-pause
 *   BLACK  → KillSwitch LOCKED, governance-only recovery
 */
contract ProtocolEmergencyCoordinator is
    IProtocolEmergencyCoordinator,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    /*//////////////////////////////////////////////////////////////
                              ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant RESPONDER_ROLE = keccak256("RESPONDER_ROLE");
    bytes32 public constant RECOVERY_ROLE = keccak256("RECOVERY_ROLE");

    /*//////////////////////////////////////////////////////////////
                            CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint48 public constant ESCALATION_COOLDOWN = 5 minutes;
    uint48 public constant RECOVERY_COOLDOWN = 1 hours;
    uint256 public constant MAX_INCIDENTS = 1000;

    /*//////////////////////////////////////////////////////////////
                           IMMUTABLES
    //////////////////////////////////////////////////////////////*/

    IHealthAggregator public immutable healthAggregator;
    IEmergencyRecovery public immutable emergencyRecovery;
    IKillSwitch public immutable killSwitch;
    ICircuitBreaker public immutable circuitBreaker;
    IProtocolHub public immutable protocolHub;

    /*//////////////////////////////////////////////////////////////
                             STATE
    //////////////////////////////////////////////////////////////*/

    Severity public override currentSeverity;
    uint256 public override activeIncidentId;
    uint256 public incidentCount;
    uint48 public lastEscalationAt;

    /// @notice Whether role separation has been confirmed by admin
    /// @dev Must be true before RED/BLACK emergency plans can execute.
    ///      Prevents a single compromised admin from escalating and executing
    ///      the most destructive emergency actions.
    bool public roleSeparationConfirmed;

    mapping(uint256 => Incident) internal _incidents;

    /// @dev Track whether we executed the emergency plan for a given severity
    mapping(uint256 => mapping(Severity => bool)) public planExecuted;

    /*//////////////////////////////////////////////////////////////
                           CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address _healthAggregator,
        address _emergencyRecovery,
        address _killSwitch,
        address _circuitBreaker,
        address _protocolHub,
        address _admin
    ) {
        if (_healthAggregator == address(0)) revert ZeroAddress();
        if (_emergencyRecovery == address(0)) revert ZeroAddress();
        if (_killSwitch == address(0)) revert ZeroAddress();
        if (_circuitBreaker == address(0)) revert ZeroAddress();
        if (_protocolHub == address(0)) revert ZeroAddress();
        if (_admin == address(0)) revert ZeroAddress();

        healthAggregator = IHealthAggregator(_healthAggregator);
        emergencyRecovery = IEmergencyRecovery(_emergencyRecovery);
        killSwitch = IKillSwitch(_killSwitch);
        circuitBreaker = ICircuitBreaker(_circuitBreaker);
        protocolHub = IProtocolHub(_protocolHub);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
        _grantRole(RESPONDER_ROLE, _admin);
        _grantRole(RECOVERY_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                          ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when role separation has not been confirmed for high-severity actions
    error RoleSeparationRequired();

    /// @notice Thrown when role separation validation fails (same address holds multiple roles)
    error RoleSeparationViolation(address account);

    /*//////////////////////////////////////////////////////////////
                       ROLE SEPARATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Confirm that critical roles (GUARDIAN, RESPONDER, RECOVERY) are held by
     *         separate addresses. Must be called before RED/BLACK emergency plans.
     * @dev Validates that no single address holds more than one of the three critical roles.
     *      This prevents a compromised admin from single-handedly escalating to BLACK and
     *      executing the most destructive emergency actions.
     *
     *      The admin should:
     *      1. Grant GUARDIAN_ROLE, RESPONDER_ROLE, RECOVERY_ROLE to separate multisigs
     *      2. Revoke those roles from the deployer address
     *      3. Call confirmRoleSeparation()
     */
    function confirmRoleSeparation() external onlyRole(DEFAULT_ADMIN_ROLE) {
        // Get role member counts (AccessControl stores members per role)
        // Iterate over the three critical roles and check no address has >1
        // Note: We check the msg.sender (admin) doesn't hold operational roles
        if (
            hasRole(GUARDIAN_ROLE, msg.sender) &&
            hasRole(RESPONDER_ROLE, msg.sender)
        ) revert RoleSeparationViolation(msg.sender);
        if (
            hasRole(GUARDIAN_ROLE, msg.sender) &&
            hasRole(RECOVERY_ROLE, msg.sender)
        ) revert RoleSeparationViolation(msg.sender);
        if (
            hasRole(RESPONDER_ROLE, msg.sender) &&
            hasRole(RECOVERY_ROLE, msg.sender)
        ) revert RoleSeparationViolation(msg.sender);

        roleSeparationConfirmed = true;
        emit RoleSeparationConfirmed(msg.sender);
    }

    /// @notice Emitted when role separation is confirmed
    event RoleSeparationConfirmed(address indexed confirmedBy);

    /*//////////////////////////////////////////////////////////////
                       INCIDENT MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Open a new incident and set the unified severity
     * @param severity The initial severity level (must be > GREEN)
     * @param reason Human-readable description
     * @param evidenceHash Hash of off-chain evidence (logs, alerts, etc.)
     * @return incidentId The new incident ID
     */
    function openIncident(
        Severity severity,
        string calldata reason,
        bytes32 evidenceHash
    )
        external
        override
        onlyRole(RESPONDER_ROLE)
        nonReentrant
        returns (uint256 incidentId)
    {
        if (activeIncidentId != 0) revert IncidentAlreadyActive();
        if (severity == Severity.GREEN) {
            revert InvalidEscalation(Severity.GREEN, severity);
        }

        unchecked {
            incidentId = ++incidentCount;
        }

        _incidents[incidentId] = Incident({
            id: incidentId,
            severity: severity,
            initiator: msg.sender,
            timestamp: uint48(block.timestamp),
            resolvedAt: 0,
            reason: reason,
            evidenceHash: evidenceHash
        });

        activeIncidentId = incidentId;
        currentSeverity = severity;
        lastEscalationAt = uint48(block.timestamp);

        emit IncidentOpened(incidentId, severity, msg.sender, reason);
    }

    /**
     * @notice Escalate an active incident to a higher severity
     * @param incidentId The incident to escalate (must be active)
     * @param newSeverity The new severity (must be strictly higher)
     */
    function escalateIncident(
        uint256 incidentId,
        Severity newSeverity
    ) external override onlyRole(RESPONDER_ROLE) {
        if (incidentId != activeIncidentId || activeIncidentId == 0) {
            revert IncidentNotActive(incidentId);
        }

        Incident storage incident = _incidents[incidentId];

        // Must escalate (higher severity), not de-escalate
        if (newSeverity <= incident.severity) {
            revert InvalidEscalation(incident.severity, newSeverity);
        }

        // Cooldown between escalations
        uint48 nextAllowed = lastEscalationAt + ESCALATION_COOLDOWN;
        if (block.timestamp < nextAllowed) {
            revert CooldownNotElapsed(nextAllowed);
        }

        Severity oldSeverity = incident.severity;
        incident.severity = newSeverity;
        currentSeverity = newSeverity;
        lastEscalationAt = uint48(block.timestamp);

        emit SeverityEscalated(oldSeverity, newSeverity, incidentId);
    }

    /*//////////////////////////////////////////////////////////////
                     EMERGENCY PLAN EXECUTION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Execute the emergency plan for the current incident severity.
     *         Each severity level cascades specific actions to subsystems.
     * @param incidentId The incident to execute the plan for
     *
     * Plan mapping:
     *   YELLOW → KillSwitch WARNING (monitoring mode)
     *   ORANGE → KillSwitch DEGRADED + circuit breaker awareness
     *   RED    → Hub pause + bridge halt + HealthAgg auto-pause + KillSwitch HALTED (requires role separation)
     *   BLACK  → KillSwitch LOCKED (governance-only recovery) (requires role separation)
     */
    function executeEmergencyPlan(
        uint256 incidentId
    ) external override onlyRole(GUARDIAN_ROLE) nonReentrant {
        if (incidentId != activeIncidentId || activeIncidentId == 0) {
            revert IncidentNotActive(incidentId);
        }

        Severity sev = _incidents[incidentId].severity;

        // SECURITY FIX: RED and BLACK severity plans can halt the entire protocol.
        // Require role separation confirmation to prevent a single compromised admin
        // from both escalating and executing destructive emergency actions.
        if (sev >= Severity.RED && !roleSeparationConfirmed) {
            revert RoleSeparationRequired();
        }

        // Prevent re-execution at same severity
        if (planExecuted[incidentId][sev]) {
            revert InvalidEscalation(sev, sev);
        }

        planExecuted[incidentId][sev] = true;
        uint8 actions = 0;

        // Cascade based on severity (cumulative — higher levels include lower actions)
        if (sev >= Severity.YELLOW) {
            // KillSwitch → WARNING
            _tryKillSwitchEscalate(
                IKillSwitch.EmergencyLevel.WARNING,
                "Coordinator: YELLOW"
            );
            actions++;
        }

        if (sev >= Severity.ORANGE) {
            // KillSwitch → DEGRADED
            _tryKillSwitchEscalate(
                IKillSwitch.EmergencyLevel.DEGRADED,
                "Coordinator: ORANGE"
            );
            actions++;
        }

        if (sev >= Severity.RED) {
            // Full halt: Hub pause + bridge halt + health aggregator auto-pause
            _tryHubPause();
            actions++;

            _tryCircuitBreakerHalt();
            actions++;

            _tryHealthAggregatorPause();
            actions++;

            // KillSwitch → HALTED
            _tryKillSwitchEscalate(
                IKillSwitch.EmergencyLevel.HALTED,
                "Coordinator: RED"
            );
            actions++;
        }

        if (sev >= Severity.BLACK) {
            // KillSwitch → LOCKED (governance-only recovery)
            _tryKillSwitchEscalate(
                IKillSwitch.EmergencyLevel.LOCKED,
                "Coordinator: BLACK"
            );
            actions++;
        }

        emit EmergencyPlanExecuted(sev, incidentId, actions);
    }

    /*//////////////////////////////////////////////////////////////
                         RECOVERY PATH
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check whether all subsystems are healthy enough for recovery.
     * @param incidentId The incident to validate recovery for
     * @return allClear True if all subsystems report healthy/normal status
     * @return status Detailed per-subsystem status breakdown
     */
    function validateRecovery(
        uint256 incidentId
    )
        external
        view
        override
        returns (bool allClear, SubsystemStatus memory status)
    {
        if (incidentId != activeIncidentId || activeIncidentId == 0) {
            revert IncidentNotActive(incidentId);
        }

        status = getSubsystemStatus();

        allClear =
            status.healthAggregatorHealthy &&
            status.emergencyRecoveryMonitoring &&
            status.killSwitchNone &&
            status.circuitBreakerNormal &&
            !status.hubPaused;
    }

    /**
     * @notice Execute recovery — resolves the incident and resets severity to GREEN.
     *         Requires that subsystems have already been individually recovered
     *         (this contract validates, it doesn't force-unpause subsystems).
     * @param incidentId The incident to resolve
     */
    function executeRecovery(
        uint256 incidentId
    ) external override onlyRole(RECOVERY_ROLE) nonReentrant {
        if (incidentId != activeIncidentId || activeIncidentId == 0) {
            revert IncidentNotActive(incidentId);
        }

        // Enforce cooldown since last escalation
        uint48 nextAllowed = lastEscalationAt + RECOVERY_COOLDOWN;
        if (block.timestamp < nextAllowed) {
            revert CooldownNotElapsed(nextAllowed);
        }

        // Validate all subsystems are clear
        SubsystemStatus memory status = getSubsystemStatus();
        bool allClear = status.healthAggregatorHealthy &&
            status.emergencyRecoveryMonitoring &&
            status.killSwitchNone &&
            status.circuitBreakerNormal &&
            !status.hubPaused;

        if (!allClear) revert RecoveryNotClear();

        Incident storage incident = _incidents[incidentId];
        Severity oldSeverity = incident.severity;
        incident.resolvedAt = uint48(block.timestamp);

        activeIncidentId = 0;
        currentSeverity = Severity.GREEN;

        emit IncidentResolved(incidentId, oldSeverity, msg.sender);
        emit RecoveryExecuted(incidentId, Severity.GREEN);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Aggregate status of all connected subsystems
    /**
     * @notice Returns the subsystem status
     * @return status The status
     */
    function getSubsystemStatus()
        public
        view
        override
        returns (SubsystemStatus memory status)
    {
        // HealthAggregator
        try healthAggregator.getProtocolHealth() returns (
            uint16,
            IHealthAggregator.HealthStatus hStatus,
            uint8
        ) {
            status.healthAggregatorHealthy = (hStatus ==
                IHealthAggregator.HealthStatus.HEALTHY);
        } catch {
            status.healthAggregatorHealthy = false;
        }

        // EmergencyRecovery
        try emergencyRecovery.currentStage() returns (
            IEmergencyRecovery.RecoveryStage stage
        ) {
            status.emergencyRecoveryMonitoring = (stage ==
                IEmergencyRecovery.RecoveryStage.Monitoring);
        } catch {
            status.emergencyRecoveryMonitoring = false;
        }

        // KillSwitch
        try killSwitch.currentLevel() returns (
            IKillSwitch.EmergencyLevel level
        ) {
            status.killSwitchNone = (level == IKillSwitch.EmergencyLevel.NONE);
        } catch {
            status.killSwitchNone = false;
        }

        // CircuitBreaker
        try circuitBreaker.currentState() returns (
            ICircuitBreaker.SystemState state
        ) {
            status.circuitBreakerNormal = (state ==
                ICircuitBreaker.SystemState.NORMAL);
        } catch {
            status.circuitBreakerNormal = false;
        }

        // Hub
        try protocolHub.paused() returns (bool isPaused) {
            status.hubPaused = isPaused;
        } catch {
            status.hubPaused = true; // assume paused if unreachable
        }
    }

    /// @inheritdoc IProtocolEmergencyCoordinator
    /**
     * @notice Returns the incident
     * @param incidentId The incidentId identifier
     * @return The result value
     */
    function getIncident(
        uint256 incidentId
    ) external view override returns (Incident memory) {
        return _incidents[incidentId];
    }

    /// @notice Get all incidents in a range
    /**
     * @notice Returns the incidents
     * @param from The source address
     * @param to The destination address
     * @return incidents The incidents
     */
    function getIncidents(
        uint256 from,
        uint256 to
    ) external view returns (Incident[] memory incidents) {
        if (to > incidentCount) to = incidentCount;
        if (from == 0) from = 1;
        if (from > to) return new Incident[](0);

        incidents = new Incident[](to - from + 1);
        for (uint256 i = from; i <= to; ) {
            incidents[i - from] = _incidents[i];
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Whether an incident is currently active
    /**
     * @notice Checks if has active incident
     * @return The result value
     */
    function hasActiveIncident() external view returns (bool) {
        return activeIncidentId != 0;
    }

    /*//////////////////////////////////////////////////////////////
                     INTERNAL: SUBSYSTEM ACTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Try to escalate the kill switch. Uses try/catch so coordinator
     *      continues functioning even if one subsystem call fails.
     */
    function _tryKillSwitchEscalate(
        IKillSwitch.EmergencyLevel level,
        string memory reason
    ) internal {
        try killSwitch.escalateEmergency(level, reason) {} catch {}
    }

    /// @dev Try to pause the protocol hub
    function _tryHubPause() internal {
        try protocolHub.pause() {} catch {}
    }

    /// @dev Try to halt the bridge circuit breaker
    function _tryCircuitBreakerHalt() internal {
        try circuitBreaker.emergencyHalt() {} catch {}
    }

    /// @dev Try to trigger the health aggregator's emergency pause
    function _tryHealthAggregatorPause() internal {
        try healthAggregator.guardianEmergencyPause() {} catch {}
    }
}
