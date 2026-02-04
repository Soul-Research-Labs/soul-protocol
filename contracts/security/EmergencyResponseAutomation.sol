// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title EmergencyResponseAutomation
 * @author Soul Security Team
 * @notice Automated incident response system with runbooks and auto-remediation
 * @dev Implements automated response actions based on detected threats
 */
contract EmergencyResponseAutomation is
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    // ============ Roles ============
    bytes32 public constant RESPONDER_ROLE = keccak256("RESPONDER_ROLE");
    bytes32 public constant AUTOMATION_ROLE = keccak256("AUTOMATION_ROLE");
    bytes32 public constant RUNBOOK_ADMIN_ROLE =
        keccak256("RUNBOOK_ADMIN_ROLE");

    // ============ Enums ============
    enum IncidentSeverity {
        INFO,
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL,
        CATASTROPHIC
    }

    enum IncidentStatus {
        DETECTED,
        ACKNOWLEDGED,
        INVESTIGATING,
        REMEDIATING,
        RESOLVED,
        POST_MORTEM,
        CLOSED
    }

    enum ActionType {
        PAUSE_CONTRACT,
        UNPAUSE_CONTRACT,
        TRIGGER_CIRCUIT_BREAKER,
        ADJUST_RATE_LIMIT,
        BLACKLIST_ADDRESS,
        WHITELIST_ADDRESS,
        UPGRADE_TIMELOCK,
        NOTIFY_TEAM,
        SNAPSHOT_STATE,
        EXECUTE_CUSTOM,
        ESCALATE
    }

    enum AutomationTrigger {
        MANUAL,
        THRESHOLD_BREACH,
        ANOMALY_DETECTED,
        ORACLE_ALERT,
        WATCHTOWER_ALERT,
        CIRCUIT_BREAKER,
        SCHEDULED,
        CHAIN_EVENT
    }

    // ============ Structs ============
    struct Incident {
        bytes32 id;
        string title;
        string description;
        IncidentSeverity severity;
        IncidentStatus status;
        AutomationTrigger trigger;
        bytes32 runbookId;
        address reporter;
        address assignee;
        uint256 detectedAt;
        uint256 acknowledgedAt;
        uint256 resolvedAt;
        bytes32[] affectedContracts;
        bytes32[] executedActions;
        string postMortemUrl;
        mapping(uint256 => string) timeline;
        uint256 timelineCount;
    }

    struct Runbook {
        bytes32 id;
        string name;
        string description;
        IncidentSeverity minSeverity;
        bool active;
        bool autoExecute;
        uint256 createdAt;
        uint256 updatedAt;
        bytes32[] actionIds;
        uint256 executionCount;
        uint256 cooldownPeriod;
        uint256 lastExecutedAt;
    }

    struct AutomatedAction {
        bytes32 id;
        ActionType actionType;
        address targetContract;
        bytes4 functionSelector;
        bytes parameters;
        uint256 delaySeconds;
        bool requiresConfirmation;
        uint256 confirmationsRequired;
        uint256 gasLimit;
        bool active;
    }

    struct ExecutionRecord {
        bytes32 actionId;
        bytes32 incidentId;
        address executor;
        uint256 executedAt;
        bool success;
        bytes returnData;
        uint256 gasUsed;
    }

    struct EscalationPath {
        IncidentSeverity fromSeverity;
        IncidentSeverity toSeverity;
        uint256 escalateAfterSeconds;
        address[] notifyAddresses;
        bytes32 escalationRunbookId;
    }

    struct ResponseMetrics {
        uint256 totalIncidents;
        uint256 resolvedIncidents;
        uint256 avgDetectionToAckSeconds;
        uint256 avgAckToResolutionSeconds;
        uint256 autoRemediatedCount;
        uint256 manualRemediatedCount;
    }

    // ============ Constants ============
    uint256 public constant MAX_ACTIONS_PER_RUNBOOK = 20;
    uint256 public constant MAX_AUTO_EXECUTIONS_PER_HOUR = 10;
    uint256 public constant INCIDENT_TIMEOUT = 7 days;
    uint256 public constant MIN_CONFIRMATION_DELAY = 1 minutes;

    // ============ State Variables ============
    mapping(bytes32 => Incident) private _incidents;
    mapping(bytes32 => Runbook) public runbooks;
    mapping(bytes32 => AutomatedAction) public actions;
    mapping(bytes32 => ExecutionRecord[]) public executionHistory;
    mapping(IncidentSeverity => EscalationPath) public escalationPaths;
    mapping(address => mapping(bytes32 => uint256)) public pendingConfirmations;

    bytes32[] public incidentIds;
    bytes32[] public runbookIds;
    bytes32[] public actionIds;

    // Rate limiting for auto-execution
    uint256 public autoExecutionsThisHour;
    uint256 public currentHourTimestamp;

    // Response metrics
    ResponseMetrics public metrics;

    // Integration addresses
    address public circuitBreaker;
    address public rateLimiter;
    address public killSwitch;
    address public securityOracle;

    // ============ Events ============
    event IncidentCreated(
        bytes32 indexed incidentId,
        IncidentSeverity severity,
        AutomationTrigger trigger,
        address reporter
    );
    event IncidentStatusChanged(
        bytes32 indexed incidentId,
        IncidentStatus oldStatus,
        IncidentStatus newStatus
    );
    event IncidentAssigned(bytes32 indexed incidentId, address assignee);
    event IncidentEscalated(
        bytes32 indexed incidentId,
        IncidentSeverity newSeverity
    );
    event RunbookCreated(
        bytes32 indexed runbookId,
        string name,
        bool autoExecute
    );
    event RunbookExecuted(
        bytes32 indexed runbookId,
        bytes32 indexed incidentId,
        uint256 actionsExecuted
    );
    event ActionExecuted(
        bytes32 indexed actionId,
        bytes32 indexed incidentId,
        bool success
    );
    event ActionConfirmed(
        bytes32 indexed actionId,
        address confirmer,
        uint256 currentConfirmations
    );
    event TimelineEntryAdded(
        bytes32 indexed incidentId,
        uint256 entryIndex,
        string entry
    );
    event AutoRemediationTriggered(
        bytes32 indexed incidentId,
        bytes32 indexed runbookId
    );
    event IntegrationUpdated(string integration, address newAddress);

    // ============ Errors ============
    error IncidentNotFound();
    error RunbookNotFound();
    error ActionNotFound();
    error RunbookCooldown();
    error TooManyAutoExecutions();
    error InsufficientConfirmations();
    error InvalidParameters();
    error ExecutionFailed();
    error IncidentAlreadyClosed();
    error NotAssignee();
    error ZeroAddress();

    // ============ Constructor ============
    constructor(
        address _circuitBreaker,
        address _rateLimiter,
        address _killSwitch
    ) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(RESPONDER_ROLE, msg.sender);
        _grantRole(AUTOMATION_ROLE, msg.sender);
        _grantRole(RUNBOOK_ADMIN_ROLE, msg.sender);

        circuitBreaker = _circuitBreaker;
        rateLimiter = _rateLimiter;
        killSwitch = _killSwitch;

        currentHourTimestamp = block.timestamp;

        // Initialize default escalation paths
        _initializeEscalationPaths();
    }

    // ============ Incident Management ============

    /**
     * @notice Create a new incident
     * @param title Incident title
     * @param description Incident description
     * @param severity Incident severity
     * @param trigger What triggered the incident
     * @param affectedContracts List of affected contract hashes
     * @return incidentId The created incident ID
     */
    function createIncident(
        string calldata title,
        string calldata description,
        IncidentSeverity severity,
        AutomationTrigger trigger,
        bytes32[] calldata affectedContracts
    ) external onlyRole(RESPONDER_ROLE) returns (bytes32 incidentId) {
        incidentId = keccak256(
            abi.encode(title, severity, block.timestamp, msg.sender)
        );

        Incident storage incident = _incidents[incidentId];
        incident.id = incidentId;
        incident.title = title;
        incident.description = description;
        incident.severity = severity;
        incident.status = IncidentStatus.DETECTED;
        incident.trigger = trigger;
        incident.reporter = msg.sender;
        incident.detectedAt = block.timestamp;

        for (uint256 i = 0; i < affectedContracts.length; i++) {
            incident.affectedContracts.push(affectedContracts[i]);
        }

        incident.timeline[0] = string(
            abi.encodePacked(
                "Incident detected by ",
                _addressToString(msg.sender)
            )
        );
        incident.timelineCount = 1;

        incidentIds.push(incidentId);
        metrics.totalIncidents++;

        emit IncidentCreated(incidentId, severity, trigger, msg.sender);

        // Check for auto-remediation runbook
        _checkAutoRemediation(incidentId, severity);
    }

    /**
     * @notice Acknowledge an incident
     * @param incidentId Incident to acknowledge
     */
    function acknowledgeIncident(
        bytes32 incidentId
    ) external onlyRole(RESPONDER_ROLE) {
        Incident storage incident = _incidents[incidentId];
        if (incident.reporter == address(0)) revert IncidentNotFound();
        if (incident.status == IncidentStatus.CLOSED)
            revert IncidentAlreadyClosed();

        IncidentStatus oldStatus = incident.status;
        incident.status = IncidentStatus.ACKNOWLEDGED;
        incident.acknowledgedAt = block.timestamp;
        incident.assignee = msg.sender;

        _addTimelineEntry(
            incidentId,
            string(
                abi.encodePacked(
                    "Acknowledged by ",
                    _addressToString(msg.sender)
                )
            )
        );

        emit IncidentStatusChanged(
            incidentId,
            oldStatus,
            IncidentStatus.ACKNOWLEDGED
        );
        emit IncidentAssigned(incidentId, msg.sender);

        // Update metrics
        uint256 timeToAck = incident.acknowledgedAt - incident.detectedAt;
        metrics.avgDetectionToAckSeconds =
            (metrics.avgDetectionToAckSeconds *
                (metrics.totalIncidents - 1) +
                timeToAck) /
            metrics.totalIncidents;
    }

    /**
     * @notice Update incident status
     * @param incidentId Incident to update
     * @param newStatus New status
     */
    function updateIncidentStatus(
        bytes32 incidentId,
        IncidentStatus newStatus
    ) external onlyRole(RESPONDER_ROLE) {
        Incident storage incident = _incidents[incidentId];
        if (incident.reporter == address(0)) revert IncidentNotFound();
        if (incident.status == IncidentStatus.CLOSED)
            revert IncidentAlreadyClosed();

        IncidentStatus oldStatus = incident.status;
        incident.status = newStatus;

        if (newStatus == IncidentStatus.RESOLVED) {
            incident.resolvedAt = block.timestamp;
            metrics.resolvedIncidents++;

            if (incident.acknowledgedAt > 0) {
                uint256 resolutionTime = incident.resolvedAt -
                    incident.acknowledgedAt;
                metrics.avgAckToResolutionSeconds =
                    (metrics.avgAckToResolutionSeconds *
                        (metrics.resolvedIncidents - 1) +
                        resolutionTime) /
                    metrics.resolvedIncidents;
            }
        }

        _addTimelineEntry(
            incidentId,
            string(
                abi.encodePacked(
                    "Status changed to ",
                    _statusToString(newStatus)
                )
            )
        );

        emit IncidentStatusChanged(incidentId, oldStatus, newStatus);
    }

    /**
     * @notice Add post-mortem URL
     * @param incidentId Incident ID
     * @param postMortemUrl URL to post-mortem document
     */
    function addPostMortem(
        bytes32 incidentId,
        string calldata postMortemUrl
    ) external onlyRole(RESPONDER_ROLE) {
        Incident storage incident = _incidents[incidentId];
        if (incident.reporter == address(0)) revert IncidentNotFound();

        incident.postMortemUrl = postMortemUrl;
        incident.status = IncidentStatus.POST_MORTEM;

        _addTimelineEntry(incidentId, "Post-mortem added");
    }

    // ============ Runbook Management ============

    /**
     * @notice Create a new runbook
     * @param name Runbook name
     * @param description Runbook description
     * @param minSeverity Minimum severity to trigger
     * @param autoExecute Whether to auto-execute
     * @param cooldownPeriod Cooldown between executions
     * @return runbookId The created runbook ID
     */
    function createRunbook(
        string calldata name,
        string calldata description,
        IncidentSeverity minSeverity,
        bool autoExecute,
        uint256 cooldownPeriod
    ) external onlyRole(RUNBOOK_ADMIN_ROLE) returns (bytes32 runbookId) {
        runbookId = keccak256(
            abi.encode(name, block.timestamp, msg.sender)
        );

        runbooks[runbookId] = Runbook({
            id: runbookId,
            name: name,
            description: description,
            minSeverity: minSeverity,
            active: true,
            autoExecute: autoExecute,
            createdAt: block.timestamp,
            updatedAt: block.timestamp,
            actionIds: new bytes32[](0),
            executionCount: 0,
            cooldownPeriod: cooldownPeriod,
            lastExecutedAt: 0
        });

        runbookIds.push(runbookId);

        emit RunbookCreated(runbookId, name, autoExecute);
    }

    /**
     * @notice Add action to runbook
     * @param runbookId Runbook to add action to
     * @param actionType Type of action
     * @param targetContract Target contract address
     * @param functionSelector Function to call
     * @param parameters Encoded parameters
     * @param delaySeconds Delay before execution
     * @param requiresConfirmation Whether confirmation is required
     * @param confirmationsRequired Number of confirmations needed
     * @param gasLimit Gas limit for execution
     * @return actionId The created action ID
     */
    function addActionToRunbook(
        bytes32 runbookId,
        ActionType actionType,
        address targetContract,
        bytes4 functionSelector,
        bytes calldata parameters,
        uint256 delaySeconds,
        bool requiresConfirmation,
        uint256 confirmationsRequired,
        uint256 gasLimit
    ) external onlyRole(RUNBOOK_ADMIN_ROLE) returns (bytes32 actionId) {
        Runbook storage runbook = runbooks[runbookId];
        if (runbook.createdAt == 0) revert RunbookNotFound();
        if (runbook.actionIds.length >= MAX_ACTIONS_PER_RUNBOOK)
            revert InvalidParameters();

        actionId = keccak256(
            abi.encode(
                runbookId,
                actionType,
                targetContract,
                block.timestamp
            )
        );

        actions[actionId] = AutomatedAction({
            id: actionId,
            actionType: actionType,
            targetContract: targetContract,
            functionSelector: functionSelector,
            parameters: parameters,
            delaySeconds: delaySeconds,
            requiresConfirmation: requiresConfirmation,
            confirmationsRequired: confirmationsRequired,
            gasLimit: gasLimit,
            active: true
        });

        runbook.actionIds.push(actionId);
        runbook.updatedAt = block.timestamp;
        actionIds.push(actionId);
    }

    /**
     * @notice Execute a runbook for an incident
     * @param runbookId Runbook to execute
     * @param incidentId Associated incident
     * @return actionsExecuted Number of actions executed
     */
    function executeRunbook(
        bytes32 runbookId,
        bytes32 incidentId
    )
        external
        onlyRole(RESPONDER_ROLE)
        nonReentrant
        returns (uint256 actionsExecuted)
    {
        Runbook storage runbook = runbooks[runbookId];
        if (runbook.createdAt == 0) revert RunbookNotFound();
        if (!runbook.active) revert RunbookNotFound();

        // Check cooldown
        if (block.timestamp < runbook.lastExecutedAt + runbook.cooldownPeriod) {
            revert RunbookCooldown();
        }

        Incident storage incident = _incidents[incidentId];
        incident.runbookId = runbookId;
        incident.status = IncidentStatus.REMEDIATING;

        _addTimelineEntry(
            incidentId,
            string(abi.encodePacked("Executing runbook: ", runbook.name))
        );

        // Execute each action
        for (uint256 i = 0; i < runbook.actionIds.length; i++) {
            bytes32 actionId = runbook.actionIds[i];
            AutomatedAction storage action = actions[actionId];

            if (!action.active) continue;

            // Check if confirmation is needed
            if (action.requiresConfirmation) {
                if (
                    pendingConfirmations[action.targetContract][actionId] <
                    action.confirmationsRequired
                ) {
                    continue; // Skip actions requiring more confirmations
                }
            }

            bool success = _executeAction(action, incidentId);
            if (success) {
                actionsExecuted++;
                incident.executedActions.push(actionId);
            }
        }

        runbook.executionCount++;
        runbook.lastExecutedAt = block.timestamp;

        emit RunbookExecuted(runbookId, incidentId, actionsExecuted);
    }

    // ============ Action Confirmation ============

    /**
     * @notice Confirm a pending action
     * @param actionId Action to confirm
     */
    function confirmAction(bytes32 actionId) external onlyRole(RESPONDER_ROLE) {
        AutomatedAction storage action = actions[actionId];
        if (action.targetContract == address(0)) revert ActionNotFound();

        pendingConfirmations[action.targetContract][actionId]++;

        emit ActionConfirmed(
            actionId,
            msg.sender,
            pendingConfirmations[action.targetContract][actionId]
        );
    }

    // ============ Auto-Remediation ============

    /**
     * @notice Trigger automated response from external system
     * @param severity Incident severity
     * @param trigger Trigger type
     * @param description Description of the issue
     * @param affectedContract Affected contract hash
     */
    function triggerAutoResponse(
        IncidentSeverity severity,
        AutomationTrigger trigger,
        string calldata description,
        bytes32 affectedContract
    ) external onlyRole(AUTOMATION_ROLE) returns (bytes32 incidentId) {
        // Rate limit auto-executions
        _updateHourlyCounter();
        if (autoExecutionsThisHour >= MAX_AUTO_EXECUTIONS_PER_HOUR) {
            revert TooManyAutoExecutions();
        }

        bytes32[] memory affected = new bytes32[](1);
        affected[0] = affectedContract;

        incidentId = keccak256(
            abi.encode("AUTO", severity, block.timestamp, msg.sender)
        );

        Incident storage incident = _incidents[incidentId];
        incident.id = incidentId;
        incident.title = "Automated Incident";
        incident.description = description;
        incident.severity = severity;
        incident.status = IncidentStatus.DETECTED;
        incident.trigger = trigger;
        incident.reporter = msg.sender;
        incident.detectedAt = block.timestamp;
        incident.affectedContracts.push(affectedContract);

        incidentIds.push(incidentId);
        metrics.totalIncidents++;
        autoExecutionsThisHour++;

        emit IncidentCreated(incidentId, severity, trigger, msg.sender);

        // Auto-remediate if configured
        _checkAutoRemediation(incidentId, severity);
    }

    // ============ View Functions ============

    /**
     * @notice Get incident details
     * @param incidentId Incident ID
     */
    function getIncident(
        bytes32 incidentId
    )
        external
        view
        returns (
            string memory title,
            IncidentSeverity severity,
            IncidentStatus status,
            address reporter,
            address assignee,
            uint256 detectedAt,
            uint256 resolvedAt
        )
    {
        Incident storage incident = _incidents[incidentId];
        return (
            incident.title,
            incident.severity,
            incident.status,
            incident.reporter,
            incident.assignee,
            incident.detectedAt,
            incident.resolvedAt
        );
    }

    /**
     * @notice Get incident timeline
     * @param incidentId Incident ID
     * @param startIndex Start index
     * @param count Number of entries
     */
    function getIncidentTimeline(
        bytes32 incidentId,
        uint256 startIndex,
        uint256 count
    ) external view returns (string[] memory entries) {
        Incident storage incident = _incidents[incidentId];
        uint256 endIndex = startIndex + count;
        if (endIndex > incident.timelineCount)
            endIndex = incident.timelineCount;

        entries = new string[](endIndex - startIndex);
        for (uint256 i = startIndex; i < endIndex; i++) {
            entries[i - startIndex] = incident.timeline[i];
        }
    }

    /**
     * @notice Get runbook details
     * @param runbookId Runbook ID
     */
    function getRunbook(
        bytes32 runbookId
    ) external view returns (Runbook memory) {
        return runbooks[runbookId];
    }

    /**
     * @notice Get response metrics
     */
    function getMetrics() external view returns (ResponseMetrics memory) {
        return metrics;
    }

    /**
     * @notice Get all open incidents
     */
    function getOpenIncidents() external view returns (bytes32[] memory) {
        uint256 count = 0;
        for (uint256 i = 0; i < incidentIds.length; i++) {
            if (_incidents[incidentIds[i]].status != IncidentStatus.CLOSED) {
                count++;
            }
        }

        bytes32[] memory open = new bytes32[](count);
        uint256 index = 0;
        for (uint256 i = 0; i < incidentIds.length; i++) {
            if (_incidents[incidentIds[i]].status != IncidentStatus.CLOSED) {
                open[index++] = incidentIds[i];
            }
        }

        return open;
    }

    // ============ Admin Functions ============

    /**
     * @notice Update integration addresses
     * @param integration Integration name
     * @param newAddress New address
     */
    function updateIntegration(
        string calldata integration,
        address newAddress
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newAddress == address(0)) revert ZeroAddress();

        bytes32 integrationHash = keccak256(bytes(integration));

        if (integrationHash == keccak256("circuitBreaker")) {
            circuitBreaker = newAddress;
        } else if (integrationHash == keccak256("rateLimiter")) {
            rateLimiter = newAddress;
        } else if (integrationHash == keccak256("killSwitch")) {
            killSwitch = newAddress;
        } else if (integrationHash == keccak256("securityOracle")) {
            securityOracle = newAddress;
        }

        emit IntegrationUpdated(integration, newAddress);
    }

    /**
     * @notice Deactivate a runbook
     * @param runbookId Runbook to deactivate
     */
    function deactivateRunbook(
        bytes32 runbookId
    ) external onlyRole(RUNBOOK_ADMIN_ROLE) {
        runbooks[runbookId].active = false;
    }

    /**
     * @notice Pause automation
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause automation
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // ============ Internal Functions ============

    function _checkAutoRemediation(
        bytes32 incidentId,
        IncidentSeverity severity
    ) internal {
        // Find matching auto-execute runbook
        for (uint256 i = 0; i < runbookIds.length; i++) {
            Runbook storage runbook = runbooks[runbookIds[i]];
            if (
                runbook.active &&
                runbook.autoExecute &&
                uint8(severity) >= uint8(runbook.minSeverity)
            ) {
                if (
                    block.timestamp >=
                    runbook.lastExecutedAt + runbook.cooldownPeriod
                ) {
                    emit AutoRemediationTriggered(incidentId, runbookIds[i]);

                    // Execute automatically for CRITICAL and above
                    if (severity >= IncidentSeverity.CRITICAL) {
                        metrics.autoRemediatedCount++;
                        // Note: In production, this would be called async
                    }
                    break;
                }
            }
        }
    }

    function _executeAction(
        AutomatedAction storage action,
        bytes32 incidentId
    ) internal returns (bool success) {
        uint256 gasStart = gasleft();
        bytes memory returnData;

        if (action.actionType == ActionType.PAUSE_CONTRACT) {
            (success, returnData) = action.targetContract.call{
                gas: action.gasLimit
            }(abi.encodeWithSelector(bytes4(keccak256("pause()"))));
        } else if (action.actionType == ActionType.TRIGGER_CIRCUIT_BREAKER) {
            (success, returnData) = circuitBreaker.call{gas: action.gasLimit}(
                abi.encodeWithSignature(
                    "triggerCircuitBreaker(string)",
                    "Automated response"
                )
            );
        } else if (action.actionType == ActionType.EXECUTE_CUSTOM) {
            (success, returnData) = action.targetContract.call{
                gas: action.gasLimit
            }(abi.encodePacked(action.functionSelector, action.parameters));
        }

        uint256 gasUsed = gasStart - gasleft();

        executionHistory[action.id].push(
            ExecutionRecord({
                actionId: action.id,
                incidentId: incidentId,
                executor: msg.sender,
                executedAt: block.timestamp,
                success: success,
                returnData: returnData,
                gasUsed: gasUsed
            })
        );

        emit ActionExecuted(action.id, incidentId, success);
    }

    function _addTimelineEntry(
        bytes32 incidentId,
        string memory entry
    ) internal {
        Incident storage incident = _incidents[incidentId];
        incident.timeline[incident.timelineCount] = string(
            abi.encodePacked(
                "[",
                _uint256ToString(block.timestamp),
                "] ",
                entry
            )
        );
        incident.timelineCount++;

        emit TimelineEntryAdded(incidentId, incident.timelineCount - 1, entry);
    }

    function _updateHourlyCounter() internal {
        if (block.timestamp >= currentHourTimestamp + 1 hours) {
            currentHourTimestamp = block.timestamp;
            autoExecutionsThisHour = 0;
        }
    }

    function _initializeEscalationPaths() internal {
        // Auto-escalate after certain time if not acknowledged
        escalationPaths[IncidentSeverity.LOW] = EscalationPath({
            fromSeverity: IncidentSeverity.LOW,
            toSeverity: IncidentSeverity.MEDIUM,
            escalateAfterSeconds: 4 hours,
            notifyAddresses: new address[](0),
            escalationRunbookId: bytes32(0)
        });

        escalationPaths[IncidentSeverity.MEDIUM] = EscalationPath({
            fromSeverity: IncidentSeverity.MEDIUM,
            toSeverity: IncidentSeverity.HIGH,
            escalateAfterSeconds: 2 hours,
            notifyAddresses: new address[](0),
            escalationRunbookId: bytes32(0)
        });

        escalationPaths[IncidentSeverity.HIGH] = EscalationPath({
            fromSeverity: IncidentSeverity.HIGH,
            toSeverity: IncidentSeverity.CRITICAL,
            escalateAfterSeconds: 30 minutes,
            notifyAddresses: new address[](0),
            escalationRunbookId: bytes32(0)
        });
    }

    function _addressToString(
        address addr
    ) internal pure returns (string memory) {
        bytes32 value = bytes32(uint256(uint160(addr)));
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(42);
        str[0] = "0";
        str[1] = "x";
        for (uint256 i = 0; i < 20; i++) {
            str[2 + i * 2] = alphabet[uint8(value[i + 12] >> 4)];
            str[3 + i * 2] = alphabet[uint8(value[i + 12] & 0x0f)];
        }
        return string(str);
    }

    function _uint256ToString(
        uint256 value
    ) internal pure returns (string memory) {
        if (value == 0) return "0";
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }

    function _statusToString(
        IncidentStatus status
    ) internal pure returns (string memory) {
        if (status == IncidentStatus.DETECTED) return "DETECTED";
        if (status == IncidentStatus.ACKNOWLEDGED) return "ACKNOWLEDGED";
        if (status == IncidentStatus.INVESTIGATING) return "INVESTIGATING";
        if (status == IncidentStatus.REMEDIATING) return "REMEDIATING";
        if (status == IncidentStatus.RESOLVED) return "RESOLVED";
        if (status == IncidentStatus.POST_MORTEM) return "POST_MORTEM";
        if (status == IncidentStatus.CLOSED) return "CLOSED";
        return "UNKNOWN";
    }
}
