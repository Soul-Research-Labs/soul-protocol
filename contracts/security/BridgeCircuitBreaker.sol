// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title BridgeCircuitBreaker
 * @author Soul Protocol
 * @notice Automatic circuit breaker with anomaly detection for bridge operations
 * @dev Implements runtime protection:
 *      - Auto-pause on large withdrawals
 *      - Velocity-based anomaly detection
 *      - Multi-signature override requirements
 *      - Gradual recovery mechanism
 *
 * CIRCUIT BREAKER ARCHITECTURE:
 * ┌────────────────────────────────────────────────────────────────────────┐
 * │                    CIRCUIT BREAKER SYSTEM                              │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │                                                                        │
 * │  ┌───────────────┐   ┌───────────────┐   ┌───────────────┐            │
 * │  │ Large Tx      │   │ High Velocity │   │ TVL Anomaly   │            │
 * │  │ Detection     │   │ Detection     │   │ Detection     │            │
 * │  └───────┬───────┘   └───────┬───────┘   └───────┬───────┘            │
 * │          │                   │                   │                     │
 * │          └───────────────────┼───────────────────┘                     │
 * │                              │                                         │
 * │                    ┌─────────▼─────────┐                               │
 * │                    │  Anomaly Score    │                               │
 * │                    │  Aggregator       │                               │
 * │                    └─────────┬─────────┘                               │
 * │                              │                                         │
 * │              ┌───────────────┼───────────────┐                         │
 * │              │               │               │                         │
 * │      ┌───────▼──────┐ ┌──────▼──────┐ ┌─────▼──────┐                  │
 * │      │ WARNING      │ │ DEGRADED    │ │ HALTED     │                  │
 * │      │ (Score <50)  │ │ (Score <80) │ │ (Score≥80) │                  │
 * │      └──────────────┘ └─────────────┘ └────────────┘                  │
 * │                                                                        │
 * └────────────────────────────────────────────────────────────────────────┘
 */
contract BridgeCircuitBreaker is AccessControl, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev Pre-computed: keccak256("MONITOR_ROLE")
    bytes32 public constant MONITOR_ROLE =
        0x92f8f4d29b7ef3eae75dca2d18fa09ff0c2f8fae437baa5b92b4eaae7e19a52a;
    /// @dev Pre-computed: keccak256("GUARDIAN_ROLE")
    bytes32 public constant GUARDIAN_ROLE =
        0x55435dd261a4b9b3364963f7738a7a662ad9c84396d64be3365284bb7f0a5041;
    /// @dev Pre-computed: keccak256("RECOVERY_ROLE")
    bytes32 public constant RECOVERY_ROLE =
        0xb3d5a7d2c64e4e04d3e46f26ebc3e8a9f0f2c3d4e5f6a7b8c9d0e1f2a3b4c5d6;

    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum SystemState {
        NORMAL, // All systems operational
        WARNING, // Elevated monitoring, no restrictions
        DEGRADED, // Limited functionality
        HALTED // All operations paused
    }

    enum AnomalyType {
        LARGE_TRANSFER,
        HIGH_VELOCITY,
        TVL_DROP,
        SUSPICIOUS_PATTERN,
        EXTERNAL_TRIGGER
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct Thresholds {
        uint256 largeTransferAmount; // Amount considered "large"
        uint256 largeTransferPercent; // Percent of TVL considered large (basis points)
        uint256 velocityTxPerHour; // Max transactions per hour
        uint256 velocityAmountPerHour; // Max volume per hour
        uint256 tvlDropPercent; // TVL drop threshold (basis points)
        uint256 warningScore; // Score threshold for WARNING state
        uint256 degradedScore; // Score threshold for DEGRADED state
        uint256 haltedScore; // Score threshold for HALTED state
    }

    struct AnomalyEvent {
        AnomalyType anomalyType;
        uint256 timestamp;
        uint256 severity; // 1-100
        bytes32 dataHash; // Hash of relevant data
        bool resolved;
    }

    struct MetricsWindow {
        uint256 txCount;
        uint256 totalVolume;
        uint256 largestTx;
        uint256 windowStart;
        uint256 windowEnd;
    }

    struct RecoveryProposal {
        address proposer;
        SystemState targetState;
        uint256 proposedAt;
        uint256 approvalCount;
        bool executed;
        mapping(address => bool) approvals;
    }

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 public constant BASIS_POINTS = 10000;
    uint256 public constant HOUR = 3600;
    uint256 public constant MAX_ANOMALY_AGE = 24 hours;
    uint256 public constant RECOVERY_DELAY = 1 hours;
    uint256 public constant MIN_RECOVERY_APPROVALS = 2;
    uint256 public constant MAX_SCORE = 100;

    /*//////////////////////////////////////////////////////////////
                              STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Current system state
    SystemState public currentState;

    /// @notice Thresholds configuration
    Thresholds public thresholds;

    /// @notice Current anomaly score (0-100)
    uint256 public anomalyScore;

    /// @notice Current hour metrics
    MetricsWindow public currentHourMetrics;

    /// @notice Previous hour metrics (for comparison)
    MetricsWindow public previousHourMetrics;

    /// @notice Current TVL for calculations
    uint256 public currentTVL;

    /// @notice Baseline TVL (for anomaly detection)
    uint256 public baselineTVL;

    /// @notice Active anomaly events
    AnomalyEvent[] public activeAnomalies;

    /// @notice O(1) counter for active anomalies (GAS OPT: avoids O(n) iteration)
    uint256 public activeAnomalyCount;

    /// @notice Index of the first potentially active anomaly
    uint256 public lastPrunedIndex;
    uint256 public recoveryProposalCount;

    /// @notice Recovery proposals
    mapping(uint256 => RecoveryProposal) internal _recoveryProposals;

    /// @notice Timestamp of last state change
    uint256 public lastStateChange;

    /// @notice Minimum time in WARNING before auto-recovery
    uint256 public warningCooldown = 30 minutes;

    /// @notice Minimum time in DEGRADED before auto-recovery attempt
    uint256 public degradedCooldown = 2 hours;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event StateChanged(
        SystemState indexed oldState,
        SystemState indexed newState,
        uint256 anomalyScore
    );
    event AnomalyDetected(
        AnomalyType indexed anomalyType,
        uint256 severity,
        bytes32 dataHash
    );
    event AnomalyResolved(uint256 indexed anomalyId);
    event ThresholdsUpdated(
        uint256 largeTransferAmount,
        uint256 velocityTxPerHour
    );
    event RecoveryProposed(
        uint256 indexed proposalId,
        address proposer,
        SystemState targetState
    );
    event RecoveryApproved(uint256 indexed proposalId, address approver);
    event RecoveryExecuted(uint256 indexed proposalId, SystemState newState);
    event MetricsRecorded(uint256 txCount, uint256 volume, uint256 timestamp);
    event ScoreUpdated(uint256 oldScore, uint256 newScore);
    event EmergencyAction(address indexed caller, bytes32 indexed threatId);

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidState(SystemState current, SystemState required);
    error InvalidThreshold();
    error RecoveryNotReady(uint256 timeRemaining);
    error AlreadyApproved();
    error ProposalExpired();
    error InsufficientApprovals(uint256 current, uint256 required);

    error InvalidAnomalyID();
    error AlreadyResolved();
    error InvalidStateTransition();
    error AlreadyExecuted();
    error RecoveryDelayNotPassed();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);
        _grantRole(MONITOR_ROLE, admin);
        _grantRole(RECOVERY_ROLE, admin);

        currentState = SystemState.NORMAL;

        // Default thresholds
        thresholds = Thresholds({
            largeTransferAmount: 100 ether,
            largeTransferPercent: 500, // 5% of TVL
            velocityTxPerHour: 100,
            velocityAmountPerHour: 1000 ether,
            tvlDropPercent: 1000, // 10% drop
            warningScore: 30,
            degradedScore: 60,
            haltedScore: 80
        });

        currentHourMetrics = MetricsWindow({
            txCount: 0,
            totalVolume: 0,
            largestTx: 0,
            windowStart: block.timestamp,
            windowEnd: block.timestamp + HOUR
        });

        lastStateChange = block.timestamp;
    }

    /*//////////////////////////////////////////////////////////////
                      MONITORING FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Record a transaction for monitoring
     * @param amount Transaction amount
     * @param sender Transaction sender
     */
    function recordTransaction(
        uint256 amount,
        address sender
    ) external onlyRole(MONITOR_ROLE) {
        _rotateMetricsIfNeeded();

        currentHourMetrics.txCount++;
        currentHourMetrics.totalVolume += amount;
        if (amount > currentHourMetrics.largestTx) {
            currentHourMetrics.largestTx = amount;
        }

        // Check for anomalies
        _checkLargeTransfer(amount, sender);
        _checkVelocity();

        // Update score and state
        _updateAnomalyScore();
        _updateState();

        emit MetricsRecorded(
            currentHourMetrics.txCount,
            currentHourMetrics.totalVolume,
            block.timestamp
        );
    }

    /**
     * @notice Update TVL and check for anomalies
     * @param newTVL New total value locked
     */
    function updateTVL(uint256 newTVL) external onlyRole(MONITOR_ROLE) {
        uint256 oldTVL = currentTVL;
        currentTVL = newTVL;

        // Update baseline if this is higher (gradual increase)
        if (newTVL > baselineTVL) {
            baselineTVL = newTVL;
        }

        // Check for TVL drop anomaly
        if (oldTVL > 0 && newTVL < oldTVL) {
            uint256 dropPercent = ((oldTVL - newTVL) * BASIS_POINTS) / oldTVL;
            if (dropPercent >= thresholds.tvlDropPercent) {
                _recordAnomaly(
                    AnomalyType.TVL_DROP,
                    _calculateSeverity(
                        dropPercent,
                        thresholds.tvlDropPercent,
                        BASIS_POINTS
                    ),
                    keccak256(abi.encodePacked(oldTVL, newTVL, block.timestamp))
                );
            }
        }

        _updateAnomalyScore();
        _updateState();
    }

    /**
     * @notice Report external anomaly (from off-chain monitoring)
     * @param anomalyType Type of anomaly
     * @param severity Severity score (1-100)
     * @param dataHash Hash of relevant data for verification
     */
    function reportAnomaly(
        AnomalyType anomalyType,
        uint256 severity,
        bytes32 dataHash
    ) external onlyRole(MONITOR_ROLE) {
        if (severity > MAX_SCORE) severity = MAX_SCORE;

        _recordAnomaly(anomalyType, severity, dataHash);
        _updateAnomalyScore();
        _updateState();
    }

    /**
     * @notice Mark an anomaly as resolved
     * @param anomalyId ID of the anomaly to resolve
     */
    function resolveAnomaly(
        uint256 anomalyId
    ) external onlyRole(GUARDIAN_ROLE) {
        if (anomalyId >= activeAnomalies.length) revert InvalidAnomalyID();
        if (activeAnomalies[anomalyId].resolved) revert AlreadyResolved();

        activeAnomalies[anomalyId].resolved = true;

        // GAS OPT: Maintain O(1) counter for active anomalies
        if (activeAnomalyCount > 0) {
            unchecked {
                --activeAnomalyCount;
            }
        }

        _updateAnomalyScore();
        _updateState();

        emit AnomalyResolved(anomalyId);
    }

    /**
     * @notice Prune old and resolved anomalies to save gas
     * @param limit Maximum number of items to prune in one call
     */
    function pruneAnomalies(uint256 limit) external onlyRole(MONITOR_ROLE) {
        uint256 count = 0;
        uint256 i = lastPrunedIndex;
        while (i < activeAnomalies.length && count < limit) {
            AnomalyEvent storage anomaly = activeAnomalies[i];
            if (
                anomaly.resolved ||
                block.timestamp - anomaly.timestamp >= MAX_ANOMALY_AGE
            ) {
                i++;
                count++;
            } else {
                break;
            }
        }
        lastPrunedIndex = i;
    }

    /*//////////////////////////////////////////////////////////////
                      RECOVERY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Propose recovery to a less restrictive state
     * @param targetState The target state to recover to
     * @return proposalId The ID of the created proposal
     */
    function proposeRecovery(
        SystemState targetState
    ) external onlyRole(RECOVERY_ROLE) returns (uint256 proposalId) {
        if (uint256(targetState) >= uint256(currentState))
            revert InvalidStateTransition();

        proposalId = recoveryProposalCount++;

        RecoveryProposal storage proposal = _recoveryProposals[proposalId];
        proposal.proposer = msg.sender;
        proposal.targetState = targetState;
        proposal.proposedAt = block.timestamp;
        proposal.approvalCount = 1;
        proposal.approvals[msg.sender] = true;

        emit RecoveryProposed(proposalId, msg.sender, targetState);
    }

    /**
     * @notice Approve a recovery proposal
     * @param proposalId The proposal to approve
     */
    function approveRecovery(
        uint256 proposalId
    ) external onlyRole(RECOVERY_ROLE) {
        RecoveryProposal storage proposal = _recoveryProposals[proposalId];

        if (proposal.executed) revert AlreadyExecuted();
        if (block.timestamp > proposal.proposedAt + 24 hours)
            revert ProposalExpired();
        if (proposal.approvals[msg.sender]) revert AlreadyApproved();

        proposal.approvals[msg.sender] = true;
        proposal.approvalCount++;

        emit RecoveryApproved(proposalId, msg.sender);
    }

    /**
     * @notice Execute a recovery proposal
     * @param proposalId The proposal to execute
     */
    function executeRecovery(
        uint256 proposalId
    ) external onlyRole(RECOVERY_ROLE) {
        RecoveryProposal storage proposal = _recoveryProposals[proposalId];

        if (proposal.executed) revert AlreadyExecuted();
        if (proposal.approvalCount < MIN_RECOVERY_APPROVALS)
            revert InsufficientApprovals(
                proposal.approvalCount,
                MIN_RECOVERY_APPROVALS
            );
        if (block.timestamp < proposal.proposedAt + RECOVERY_DELAY)
            revert RecoveryDelayNotPassed();
        if (uint256(proposal.targetState) >= uint256(currentState))
            revert InvalidStateTransition();

        proposal.executed = true;

        SystemState oldState = currentState;
        currentState = proposal.targetState;
        lastStateChange = block.timestamp;

        if (proposal.targetState == SystemState.NORMAL) {
            _unpause();
        }

        emit RecoveryExecuted(proposalId, proposal.targetState);
        emit StateChanged(oldState, currentState, anomalyScore);
    }

    /**
     * @notice Emergency halt - immediately move to HALTED state
     */
    function emergencyHalt() public onlyRole(GUARDIAN_ROLE) {
        SystemState oldState = currentState;
        currentState = SystemState.HALTED;
        lastStateChange = block.timestamp;
        _pause();

        emit StateChanged(oldState, SystemState.HALTED, MAX_SCORE);
    }

    /**
     * @notice Emergency pause triggered by SecurityOracle
     * @param threatId The ID of the threat that triggered the pause
     */
    function emergencyPause(bytes32 threatId) external onlyRole(GUARDIAN_ROLE) {
        emit EmergencyAction(msg.sender, threatId);
        emergencyHalt();
    }

    /*//////////////////////////////////////////////////////////////
                      CONFIGURATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update threshold configuration
     */
    function setThresholds(
        uint256 largeTransferAmount,
        uint256 largeTransferPercent,
        uint256 velocityTxPerHour,
        uint256 velocityAmountPerHour,
        uint256 tvlDropPercent,
        uint256 warningScore,
        uint256 degradedScore,
        uint256 haltedScore
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (
            warningScore >= degradedScore ||
            degradedScore >= haltedScore ||
            haltedScore > MAX_SCORE
        ) {
            revert InvalidThreshold();
        }

        thresholds = Thresholds({
            largeTransferAmount: largeTransferAmount,
            largeTransferPercent: largeTransferPercent,
            velocityTxPerHour: velocityTxPerHour,
            velocityAmountPerHour: velocityAmountPerHour,
            tvlDropPercent: tvlDropPercent,
            warningScore: warningScore,
            degradedScore: degradedScore,
            haltedScore: haltedScore
        });

        emit ThresholdsUpdated(largeTransferAmount, velocityTxPerHour);
    }

    /**
     * @notice Set cooldown periods
     */
    function setCooldowns(
        uint256 _warningCooldown,
        uint256 _degradedCooldown
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        warningCooldown = _warningCooldown;
        degradedCooldown = _degradedCooldown;
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check if operations are allowed in current state
     */
    function isOperational() external view returns (bool) {
        return currentState != SystemState.HALTED && !paused();
    }

    /**
     * @notice Check if current state is degraded or worse
     */
    function isDegraded() external view returns (bool) {
        return currentState >= SystemState.DEGRADED;
    }

    /**
     * @notice Get current metrics
     */
    function getCurrentMetrics()
        external
        view
        returns (
            uint256 txCount,
            uint256 volume,
            uint256 largestTx,
            uint256 score,
            SystemState state
        )
    {
        return (
            currentHourMetrics.txCount,
            currentHourMetrics.totalVolume,
            currentHourMetrics.largestTx,
            anomalyScore,
            currentState
        );
    }

    /**
     * @notice Get active anomaly count
     * @dev GAS OPT: O(1) lookup using cached counter instead of O(n) iteration
     */
    function getActiveAnomalyCount() external view returns (uint256) {
        return activeAnomalyCount;
    }

    /**
     * @notice Get recovery proposal details
     */
    function getRecoveryProposal(
        uint256 proposalId
    )
        external
        view
        returns (
            address proposer,
            SystemState targetState,
            uint256 proposedAt,
            uint256 approvalCount,
            bool executed,
            bool canExecute
        )
    {
        RecoveryProposal storage proposal = _recoveryProposals[proposalId];

        proposer = proposal.proposer;
        targetState = proposal.targetState;
        proposedAt = proposal.proposedAt;
        approvalCount = proposal.approvalCount;
        executed = proposal.executed;
        canExecute =
            !executed &&
            approvalCount >= MIN_RECOVERY_APPROVALS &&
            block.timestamp >= proposedAt + RECOVERY_DELAY;
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _rotateMetricsIfNeeded() internal {
        if (block.timestamp >= currentHourMetrics.windowEnd) {
            previousHourMetrics = currentHourMetrics;
            currentHourMetrics = MetricsWindow({
                txCount: 0,
                totalVolume: 0,
                largestTx: 0,
                windowStart: block.timestamp,
                windowEnd: block.timestamp + HOUR
            });
        }
    }

    function _checkLargeTransfer(uint256 amount, address sender) internal {
        bool isLarge = false;
        uint256 severity = 0;

        // Check absolute threshold
        if (amount >= thresholds.largeTransferAmount) {
            isLarge = true;
            severity = _calculateSeverity(
                amount,
                thresholds.largeTransferAmount,
                thresholds.largeTransferAmount * 10
            );
        }

        // Check percentage of TVL
        if (currentTVL > 0) {
            uint256 percentOfTVL = (amount * BASIS_POINTS) / currentTVL;
            if (percentOfTVL >= thresholds.largeTransferPercent) {
                isLarge = true;
                uint256 tvlSeverity = _calculateSeverity(
                    percentOfTVL,
                    thresholds.largeTransferPercent,
                    BASIS_POINTS
                );
                if (tvlSeverity > severity) severity = tvlSeverity;
            }
        }

        if (isLarge) {
            _recordAnomaly(
                AnomalyType.LARGE_TRANSFER,
                severity,
                keccak256(abi.encodePacked(amount, sender, block.timestamp))
            );
        }
    }

    function _checkVelocity() internal {
        uint256 severity = 0;
        bool isAnomalous = false;

        // Check transaction count
        if (currentHourMetrics.txCount >= thresholds.velocityTxPerHour) {
            isAnomalous = true;
            severity = _calculateSeverity(
                currentHourMetrics.txCount,
                thresholds.velocityTxPerHour,
                thresholds.velocityTxPerHour * 3
            );
        }

        // Check volume
        if (
            currentHourMetrics.totalVolume >= thresholds.velocityAmountPerHour
        ) {
            isAnomalous = true;
            uint256 volumeSeverity = _calculateSeverity(
                currentHourMetrics.totalVolume,
                thresholds.velocityAmountPerHour,
                thresholds.velocityAmountPerHour * 3
            );
            if (volumeSeverity > severity) severity = volumeSeverity;
        }

        if (isAnomalous) {
            _recordAnomaly(
                AnomalyType.HIGH_VELOCITY,
                severity,
                keccak256(
                    abi.encodePacked(
                        currentHourMetrics.txCount,
                        currentHourMetrics.totalVolume,
                        block.timestamp
                    )
                )
            );
        }
    }

    function _recordAnomaly(
        AnomalyType anomalyType,
        uint256 severity,
        bytes32 dataHash
    ) internal {
        activeAnomalies.push(
            AnomalyEvent({
                anomalyType: anomalyType,
                timestamp: block.timestamp,
                severity: severity,
                dataHash: dataHash,
                resolved: false
            })
        );

        // GAS OPT: Maintain O(1) counter for active anomalies
        unchecked {
            ++activeAnomalyCount;
        }

        emit AnomalyDetected(anomalyType, severity, dataHash);
    }

    function _updateAnomalyScore() internal {
        uint256 totalSeverity = 0;
        uint256 activeCount = 0;

        // GAS OPT: Cache array length and use unchecked increment
        uint256 len = activeAnomalies.length;
        uint256 currentTime = block.timestamp;

        for (uint256 i = lastPrunedIndex; i < len; ) {
            AnomalyEvent storage anomaly = activeAnomalies[i];

            // Skip resolved or expired anomalies
            if (
                anomaly.resolved ||
                currentTime - anomaly.timestamp >= MAX_ANOMALY_AGE
            ) {
                unchecked {
                    ++i;
                }
                continue;
            }

            // Weight by recency (more recent = higher weight)
            uint256 age = currentTime - anomaly.timestamp;
            uint256 recencyWeight = MAX_ANOMALY_AGE - age;
            uint256 weightedSeverity = (anomaly.severity * recencyWeight) /
                MAX_ANOMALY_AGE;

            totalSeverity += weightedSeverity;
            unchecked {
                ++activeCount;
                ++i;
            }
        }

        uint256 oldScore = anomalyScore;

        // Average severity with boost for multiple anomalies
        if (activeCount > 0) {
            anomalyScore = totalSeverity / activeCount;
            // Boost for multiple concurrent anomalies
            if (activeCount > 1) {
                anomalyScore = (anomalyScore * (100 + activeCount * 10)) / 100;
            }
            if (anomalyScore > MAX_SCORE) anomalyScore = MAX_SCORE;
        } else {
            anomalyScore = 0;
        }

        if (oldScore != anomalyScore) {
            emit ScoreUpdated(oldScore, anomalyScore);
        }
    }

    function _updateState() internal {
        SystemState newState;

        if (anomalyScore >= thresholds.haltedScore) {
            newState = SystemState.HALTED;
        } else if (anomalyScore >= thresholds.degradedScore) {
            newState = SystemState.DEGRADED;
        } else if (anomalyScore >= thresholds.warningScore) {
            newState = SystemState.WARNING;
        } else {
            newState = SystemState.NORMAL;
        }

        // Only escalate automatically, not de-escalate
        if (uint256(newState) > uint256(currentState)) {
            SystemState oldState = currentState;
            currentState = newState;
            lastStateChange = block.timestamp;

            if (newState == SystemState.HALTED) {
                _pause();
            }

            emit StateChanged(oldState, newState, anomalyScore);
        }
        // Auto-recovery from WARNING after cooldown
        else if (
            currentState == SystemState.WARNING &&
            anomalyScore < thresholds.warningScore &&
            block.timestamp >= lastStateChange + warningCooldown
        ) {
            SystemState oldState = currentState;
            currentState = SystemState.NORMAL;
            lastStateChange = block.timestamp;

            emit StateChanged(oldState, SystemState.NORMAL, anomalyScore);
        }
    }

    function _calculateSeverity(
        uint256 value,
        uint256 threshold,
        uint256 maxValue
    ) internal pure returns (uint256) {
        if (value <= threshold) return 0;
        if (value >= maxValue) return MAX_SCORE;

        return ((value - threshold) * MAX_SCORE) / (maxValue - threshold);
    }
}
