// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title ProtocolHealthAggregator
 * @author ZASEON
 * @notice Unified protocol health monitoring that aggregates multi-subsystem health signals
 * @dev Collects health data from bridge circuit breakers, relayer monitors, routing orchestrators,
 *      and security scorecards into a single composite score. Auto-triggers graduated emergency
 *      responses when health degrades below configurable thresholds.
 *
 *      ARCHITECTURE:
 *      ┌─────────────────────────────────────────────────────────────────┐
 *      │                  PROTOCOL HEALTH AGGREGATOR                     │
 *      ├─────────────────────────────────────────────────────────────────┤
 *      │                                                                 │
 *      │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          │
 *      │  │ Circuit  │ │ Relayer  │ │ Routing  │ │ Security │          │
 *      │  │ Breaker  │ │ Health   │ │ Health   │ │ Score    │          │
 *      │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘          │
 *      │       │             │             │             │               │
 *      │       └─────────────┼─────────────┼─────────────┘               │
 *      │                     │             │                             │
 *      │              ┌──────▼─────────────▼──────┐                      │
 *      │              │  Weighted Aggregation     │                      │
 *      │              │  + Staleness Detection    │                      │
 *      │              └──────────┬────────────────┘                      │
 *      │                         │                                       │
 *      │           ┌─────────────┼─────────────┐                         │
 *      │           ▼             ▼             ▼                         │
 *      │      ┌─────────┐ ┌─────────┐ ┌─────────────┐                   │
 *      │      │ HEALTHY │ │ WARNING │ │ CRITICAL    │                   │
 *      │      │ (≥70)   │ │ (40-69) │ │ (<40)       │                   │
 *      │      └─────────┘ └─────────┘ └──────┬──────┘                   │
 *      │                                      │                         │
 *      │                              ┌───────▼────────┐                │
 *      │                              │ Auto-Pause     │                │
 *      │                              │ Registered     │                │
 *      │                              │ Contracts      │                │
 *      │                              └────────────────┘                │
 *      └─────────────────────────────────────────────────────────────────┘
 *
 *      Role separation:
 *      - MONITOR_ROLE: Push health updates from off-chain or on-chain monitors
 *      - GUARDIAN_ROLE: Override health, trigger/clear emergencies manually
 *      - DEFAULT_ADMIN_ROLE: Register subsystems, manage thresholds
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract ProtocolHealthAggregator is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Role for pushing health updates
    bytes32 public constant MONITOR_ROLE = keccak256("MONITOR_ROLE");

    /// @notice Role for emergency overrides
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    /// @notice Maximum health score (100)
    uint16 public constant MAX_SCORE = 100;

    /// @notice Basis points denominator
    uint16 public constant BPS = 10_000;

    /// @notice Maximum subsystems that can be registered
    uint8 public constant MAX_SUBSYSTEMS = 20;

    /// @notice Maximum pausable contracts that can be registered
    uint8 public constant MAX_PAUSABLE_CONTRACTS = 30;

    /// @notice Default health data staleness threshold (15 minutes)
    uint48 public constant DEFAULT_STALENESS_THRESHOLD = 15 minutes;

    /// @notice Minimum time between auto-pause triggers (prevents flapping)
    uint48 public constant AUTO_PAUSE_COOLDOWN = 5 minutes;

    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Protocol-wide health status
    enum HealthStatus {
        HEALTHY, // Score >= healthyThreshold (default 70)
        WARNING, // Score >= criticalThreshold but < healthyThreshold
        CRITICAL, // Score < criticalThreshold (default 40)
        OVERRIDE // Manually overridden by guardian
    }

    /// @notice Subsystem category for weighted aggregation
    enum SubsystemCategory {
        BRIDGE, // Bridge infra (circuit breaker, rate limiter)
        RELAYER, // Relayer network health
        ROUTING, // Route optimization and capacity
        SECURITY, // Security scorecards and fraud detection
        PRIVACY // Privacy subsystem health
    }

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Registered subsystem with health data
    struct Subsystem {
        bytes32 subsystemId; // Unique identifier
        string name; // Human-readable name
        address source; // Contract or oracle providing health data
        SubsystemCategory category; // Category for weight grouping
        uint16 healthScore; // Current health score (0-100)
        uint16 weightBps; // Weight in composite score (bps)
        uint48 lastUpdated; // Timestamp of last health update
        uint48 stalenessThreshold; // Custom staleness (0 = use default)
        bool isActive; // Whether included in aggregation
    }

    /// @notice A contract that can be auto-paused during emergencies
    struct PausableTarget {
        address target; // Contract address
        string name; // Human-readable name
        bool isRegistered; // Whether registered
        bool wasPausedByUs; // Whether we paused it (for recovery)
    }

    /// @notice Snapshot of protocol health for historical analysis
    struct HealthSnapshot {
        uint16 compositeScore; // Weighted composite score
        HealthStatus status; // Derived status
        uint48 timestamp; // When snapshot was taken
        uint8 activeSubsystems; // How many subsystems were active
        uint8 staleSubsystems; // How many were stale
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Registered subsystems by ID
    mapping(bytes32 => Subsystem) public subsystems;

    /// @notice Ordered list of subsystem IDs for iteration
    bytes32[] public subsystemIds;

    /// @notice Pausable targets by address
    mapping(address => PausableTarget) public pausableTargets;

    /// @notice List of pausable target addresses
    address[] public pausableTargetList;

    /// @notice Current composite health score (0-100)
    uint16 public compositeScore;

    /// @notice Current health status
    HealthStatus public currentStatus;

    /// @notice Threshold for HEALTHY status (default 70)
    uint16 public healthyThreshold;

    /// @notice Threshold below which status is CRITICAL (default 40)
    uint16 public criticalThreshold;

    /// @notice Whether auto-pause is enabled
    bool public autoPauseEnabled;

    /// @notice Last time auto-pause was triggered
    uint48 public lastAutoPauseAt;

    /// @notice Guardian override: when non-zero, this score overrides aggregation
    uint16 public overrideScore;

    /// @notice Whether a guardian override is active
    bool public overrideActive;

    /// @notice Recent health snapshots (ring buffer)
    HealthSnapshot[64] public snapshots;

    /// @notice Index for next snapshot write
    uint8 public snapshotIndex;

    /// @notice Total snapshots written
    uint256 public totalSnapshots;

    /// @notice Category weight multipliers (category => weightBps)
    mapping(SubsystemCategory => uint16) public categoryWeights;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event SubsystemRegistered(
        bytes32 indexed subsystemId,
        string name,
        address source,
        SubsystemCategory category,
        uint16 weightBps
    );

    event SubsystemDeactivated(bytes32 indexed subsystemId);
    event SubsystemReactivated(bytes32 indexed subsystemId);

    event HealthUpdated(
        bytes32 indexed subsystemId,
        uint16 oldScore,
        uint16 newScore
    );

    event CompositeScoreUpdated(
        uint16 oldScore,
        uint16 newScore,
        HealthStatus status
    );

    event StatusChanged(
        HealthStatus indexed oldStatus,
        HealthStatus indexed newStatus,
        uint16 compositeScore
    );

    event AutoPauseTriggered(uint16 compositeScore, uint8 contractsPaused);

    event AutoPauseRecovered(uint8 contractsUnpaused);

    event GuardianOverrideSet(uint16 score, address indexed guardian);
    event GuardianOverrideCleared(address indexed guardian);

    event PausableTargetRegistered(address indexed target, string name);
    event PausableTargetRemoved(address indexed target);

    event ThresholdsUpdated(uint16 healthy, uint16 critical);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error SubsystemAlreadyRegistered(bytes32 subsystemId);
    error SubsystemNotFound(bytes32 subsystemId);
    error ScoreOutOfRange(uint16 score);
    error WeightOutOfRange(uint16 weight);
    error MaxSubsystemsReached();
    error MaxPausableContractsReached();
    error TargetAlreadyRegistered(address target);
    error TargetNotRegistered(address target);
    error InvalidThresholds(uint16 healthy, uint16 critical);
    error AutoPauseCooldownActive(uint48 nextAllowed);
    error NoOverrideActive();

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @param admin Default admin and initial monitor/guardian
     * @param _healthyThreshold Score threshold for HEALTHY (e.g. 70)
     * @param _criticalThreshold Score below which CRITICAL (e.g. 40)
     */
    constructor(
        address admin,
        uint16 _healthyThreshold,
        uint16 _criticalThreshold
    ) {
        if (admin == address(0)) revert ZeroAddress();
        if (_healthyThreshold > MAX_SCORE || _criticalThreshold > MAX_SCORE) {
            revert InvalidThresholds(_healthyThreshold, _criticalThreshold);
        }
        if (_criticalThreshold >= _healthyThreshold) {
            revert InvalidThresholds(_healthyThreshold, _criticalThreshold);
        }

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(MONITOR_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);

        healthyThreshold = _healthyThreshold;
        criticalThreshold = _criticalThreshold;
        currentStatus = HealthStatus.HEALTHY;
        compositeScore = MAX_SCORE;
        autoPauseEnabled = true;

        // Default category weights (total = 10000 bps)
        categoryWeights[SubsystemCategory.BRIDGE] = 3000; // 30%
        categoryWeights[SubsystemCategory.RELAYER] = 2000; // 20%
        categoryWeights[SubsystemCategory.ROUTING] = 2000; // 20%
        categoryWeights[SubsystemCategory.SECURITY] = 2000; // 20%
        categoryWeights[SubsystemCategory.PRIVACY] = 1000; // 10%
    }

    /*//////////////////////////////////////////////////////////////
                          SUBSYSTEM MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a new health subsystem
     * @param name Human-readable name
     * @param source Contract address providing health data
     * @param category Subsystem category
     * @param weightBps Weight in composite score (bps within its category)
     * @param stalenessThreshold Custom staleness threshold (0 = use default)
     */
    function registerSubsystem(
        string calldata name,
        address source,
        SubsystemCategory category,
        uint16 weightBps,
        uint48 stalenessThreshold
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (source == address(0)) revert ZeroAddress();
        if (weightBps == 0 || weightBps > BPS)
            revert WeightOutOfRange(weightBps);
        if (subsystemIds.length >= MAX_SUBSYSTEMS)
            revert MaxSubsystemsReached();

        bytes32 subsystemId = keccak256(
            abi.encodePacked(name, source, block.timestamp)
        );
        if (subsystems[subsystemId].isActive)
            revert SubsystemAlreadyRegistered(subsystemId);

        subsystems[subsystemId] = Subsystem({
            subsystemId: subsystemId,
            name: name,
            source: source,
            category: category,
            healthScore: MAX_SCORE,
            weightBps: weightBps,
            lastUpdated: uint48(block.timestamp),
            stalenessThreshold: stalenessThreshold,
            isActive: true
        });

        subsystemIds.push(subsystemId);

        emit SubsystemRegistered(
            subsystemId,
            name,
            source,
            category,
            weightBps
        );
    }

    /**
     * @notice Deactivate a subsystem (excluded from aggregation)
     * @param subsystemId The subsystem to deactivate
     */
    function deactivateSubsystem(
        bytes32 subsystemId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        Subsystem storage sub = subsystems[subsystemId];
        if (!sub.isActive) revert SubsystemNotFound(subsystemId);

        sub.isActive = false;
        emit SubsystemDeactivated(subsystemId);

        _recalculateComposite();
    }

    /**
     * @notice Reactivate a deactivated subsystem
     * @param subsystemId The subsystem to reactivate
     */
    function reactivateSubsystem(
        bytes32 subsystemId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        Subsystem storage sub = subsystems[subsystemId];
        if (sub.source == address(0)) revert SubsystemNotFound(subsystemId);
        sub.isActive = true;
        emit SubsystemReactivated(subsystemId);

        _recalculateComposite();
    }

    /*//////////////////////////////////////////////////////////////
                           HEALTH UPDATES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update health score for a subsystem
     * @param subsystemId The subsystem to update
     * @param score New health score (0-100)
     */
    function updateHealth(
        bytes32 subsystemId,
        uint16 score
    ) external onlyRole(MONITOR_ROLE) nonReentrant {
        if (score > MAX_SCORE) revert ScoreOutOfRange(score);

        Subsystem storage sub = subsystems[subsystemId];
        if (!sub.isActive) revert SubsystemNotFound(subsystemId);

        uint16 oldScore = sub.healthScore;
        sub.healthScore = score;
        sub.lastUpdated = uint48(block.timestamp);

        emit HealthUpdated(subsystemId, oldScore, score);

        _recalculateComposite();
    }

    /**
     * @notice Batch update health scores for multiple subsystems
     * @param ids Array of subsystem IDs
     * @param scores Array of corresponding scores
     */
    function batchUpdateHealth(
        bytes32[] calldata ids,
        uint16[] calldata scores
    ) external onlyRole(MONITOR_ROLE) nonReentrant {
        uint256 len = ids.length;
        require(len == scores.length, "Length mismatch");
        require(len > 0, "Empty batch");

        for (uint256 i; i < len; ) {
            if (scores[i] > MAX_SCORE) revert ScoreOutOfRange(scores[i]);

            Subsystem storage sub = subsystems[ids[i]];
            if (!sub.isActive) revert SubsystemNotFound(ids[i]);

            uint16 oldScore = sub.healthScore;
            sub.healthScore = scores[i];
            sub.lastUpdated = uint48(block.timestamp);

            emit HealthUpdated(ids[i], oldScore, scores[i]);

            unchecked {
                ++i;
            }
        }

        _recalculateComposite();
    }

    /*//////////////////////////////////////////////////////////////
                        PAUSABLE TARGET MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a contract that can be auto-paused during emergencies
     * @param target Contract address (must implement Pausable-like pause()/unpause())
     * @param name Human-readable name
     */
    function registerPausableTarget(
        address target,
        string calldata name
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (target == address(0)) revert ZeroAddress();
        if (pausableTargets[target].isRegistered)
            revert TargetAlreadyRegistered(target);
        if (pausableTargetList.length >= MAX_PAUSABLE_CONTRACTS)
            revert MaxPausableContractsReached();

        pausableTargets[target] = PausableTarget({
            target: target,
            name: name,
            isRegistered: true,
            wasPausedByUs: false
        });

        pausableTargetList.push(target);
        emit PausableTargetRegistered(target, name);
    }

    /**
     * @notice Remove a pausable target
     * @param target Contract address to remove
     */
    function removePausableTarget(
        address target
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!pausableTargets[target].isRegistered)
            revert TargetNotRegistered(target);

        pausableTargets[target].isRegistered = false;

        // Remove from list (swap-and-pop)
        uint256 len = pausableTargetList.length;
        for (uint256 i; i < len; ) {
            if (pausableTargetList[i] == target) {
                pausableTargetList[i] = pausableTargetList[len - 1];
                pausableTargetList.pop();
                break;
            }
            unchecked {
                ++i;
            }
        }

        emit PausableTargetRemoved(target);
    }

    /*//////////////////////////////////////////////////////////////
                         GUARDIAN OVERRIDES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Guardian override: set a manual health score
     * @param score Override score (0-100)
     */
    function setGuardianOverride(
        uint16 score
    ) external onlyRole(GUARDIAN_ROLE) {
        if (score > MAX_SCORE) revert ScoreOutOfRange(score);

        overrideScore = score;
        overrideActive = true;

        emit GuardianOverrideSet(score, msg.sender);

        _recalculateComposite();
    }

    /**
     * @notice Clear guardian override, return to aggregated scoring
     */
    function clearGuardianOverride() external onlyRole(GUARDIAN_ROLE) {
        if (!overrideActive) revert NoOverrideActive();

        overrideActive = false;
        overrideScore = 0;

        emit GuardianOverrideCleared(msg.sender);

        _recalculateComposite();
    }

    /**
     * @notice Guardian can manually trigger auto-pause regardless of score
     */
    function guardianEmergencyPause()
        external
        onlyRole(GUARDIAN_ROLE)
        nonReentrant
    {
        _autoPauseTargets();
    }

    /**
     * @notice Guardian can manually recover auto-paused contracts
     */
    function guardianRecoverPause()
        external
        onlyRole(GUARDIAN_ROLE)
        nonReentrant
    {
        _autoRecoverTargets();
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN CONTROLS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update health thresholds
     * @param _healthy New healthy threshold
     * @param _critical New critical threshold
     */
    function updateThresholds(
        uint16 _healthy,
        uint16 _critical
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_healthy > MAX_SCORE || _critical > MAX_SCORE) {
            revert InvalidThresholds(_healthy, _critical);
        }
        if (_critical >= _healthy) {
            revert InvalidThresholds(_healthy, _critical);
        }

        healthyThreshold = _healthy;
        criticalThreshold = _critical;

        emit ThresholdsUpdated(_healthy, _critical);

        _recalculateComposite();
    }

    /**
     * @notice Update category weight
     * @param category The category to update
     * @param weightBps New weight in bps
     */
    function updateCategoryWeight(
        SubsystemCategory category,
        uint16 weightBps
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (weightBps > BPS) revert WeightOutOfRange(weightBps);
        categoryWeights[category] = weightBps;
    }

    /**
     * @notice Enable or disable auto-pause
     * @param enabled Whether auto-pause should be enabled
     */
    function setAutoPauseEnabled(
        bool enabled
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        autoPauseEnabled = enabled;
    }

    /// @notice Emergency pause this aggregator itself
        /**
     * @notice Pauses the operation
     */
function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /// @notice Unpause this aggregator
        /**
     * @notice Unpauses the operation
     */
function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get current composite health score and status
     * @return score Current composite score (0-100)
     * @return status Current health status
     * @return staleCount Number of stale subsystems
     */
    function getProtocolHealth()
        external
        view
        returns (uint16 score, HealthStatus status, uint8 staleCount)
    {
        score = compositeScore;
        status = currentStatus;
        staleCount = _countStaleSubsystems();
    }

    /**
     * @notice Get health details for a specific subsystem
     * @param subsystemId The subsystem to query
     * @return sub The subsystem data
     * @return isStale Whether the health data is stale
     */
    function getSubsystemHealth(
        bytes32 subsystemId
    ) external view returns (Subsystem memory sub, bool isStale) {
        sub = subsystems[subsystemId];
        uint48 threshold = sub.stalenessThreshold > 0
            ? sub.stalenessThreshold
            : DEFAULT_STALENESS_THRESHOLD;
        isStale = (block.timestamp - sub.lastUpdated) > threshold;
    }

    /**
     * @notice Get all active subsystem IDs
     * @return ids Array of active subsystem IDs
     */
    function getActiveSubsystemIds()
        external
        view
        returns (bytes32[] memory ids)
    {
        uint256 len = subsystemIds.length;
        uint256 activeCount;

        // Count active
        for (uint256 i; i < len; ) {
            if (subsystems[subsystemIds[i]].isActive) {
                unchecked {
                    ++activeCount;
                }
            }
            unchecked {
                ++i;
            }
        }

        ids = new bytes32[](activeCount);
        uint256 idx;
        for (uint256 i; i < len; ) {
            if (subsystems[subsystemIds[i]].isActive) {
                ids[idx] = subsystemIds[i];
                unchecked {
                    ++idx;
                }
            }
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Get count of registered subsystems
          * @return The result value
     */
    function subsystemCount() external view returns (uint256) {
        return subsystemIds.length;
    }

    /**
     * @notice Get count of registered pausable targets
          * @return The result value
     */
    function pausableTargetCount() external view returns (uint256) {
        return pausableTargetList.length;
    }

    /**
     * @notice Get recent health snapshots
     * @param count Number of recent snapshots to return (max 64)
     * @return result Array of snapshots (most recent first)
     */
    function getRecentSnapshots(
        uint8 count
    ) external view returns (HealthSnapshot[] memory result) {
        uint256 available = totalSnapshots < 64 ? totalSnapshots : 64;
        if (count > available) count = uint8(available);

        result = new HealthSnapshot[](count);
        uint8 readIdx = snapshotIndex;
        for (uint8 i; i < count; ) {
            readIdx = readIdx == 0 ? 63 : readIdx - 1;
            result[i] = snapshots[readIdx];
            unchecked {
                ++i;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                          INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Recalculate composite score using weighted aggregation with category grouping
     *      and staleness penalty. Also triggers auto-pause if needed.
     */
    function _recalculateComposite() internal {
        uint16 newScore;

        if (overrideActive) {
            newScore = overrideScore;
        } else {
            newScore = _calculateWeightedScore();
        }

        uint16 oldScore = compositeScore;
        compositeScore = newScore;

        // Determine new status
        HealthStatus newStatus = _deriveStatus(newScore);
        HealthStatus oldStatus = currentStatus;

        if (overrideActive) {
            newStatus = HealthStatus.OVERRIDE;
        }

        currentStatus = newStatus;

        // Record snapshot
        _recordSnapshot(newScore, newStatus);

        emit CompositeScoreUpdated(oldScore, newScore, newStatus);

        if (newStatus != oldStatus) {
            emit StatusChanged(oldStatus, newStatus, newScore);
        }

        // Auto-pause check
        if (autoPauseEnabled && !overrideActive) {
            if (newStatus == HealthStatus.CRITICAL) {
                if (
                    lastAutoPauseAt == 0 ||
                    block.timestamp >= lastAutoPauseAt + AUTO_PAUSE_COOLDOWN
                ) {
                    _autoPauseTargets();
                }
            } else if (
                newStatus == HealthStatus.HEALTHY &&
                oldStatus == HealthStatus.CRITICAL
            ) {
                _autoRecoverTargets();
            }
        }
    }

    /**
     * @dev Calculate weighted score across all active, non-stale subsystems
     *      Uses two-level weighting: category weight * subsystem weight within category
     */
    function _calculateWeightedScore() internal view returns (uint16) {
        uint256 len = subsystemIds.length;
        if (len == 0) return MAX_SCORE;

        uint256 totalWeightedScore;
        uint256 totalWeight;

        for (uint256 i; i < len; ) {
            Subsystem storage sub = subsystems[subsystemIds[i]];

            if (sub.isActive) {
                uint48 threshold = sub.stalenessThreshold > 0
                    ? sub.stalenessThreshold
                    : DEFAULT_STALENESS_THRESHOLD;

                uint256 score = sub.healthScore;

                // Apply staleness penalty: halve the score if stale
                if ((block.timestamp - sub.lastUpdated) > threshold) {
                    score = score / 2;
                }

                // Effective weight = category weight * subsystem weight / BPS
                uint256 catWeight = categoryWeights[sub.category];
                uint256 effectiveWeight = (catWeight * sub.weightBps) / BPS;

                totalWeightedScore += score * effectiveWeight;
                totalWeight += effectiveWeight;
            }

            unchecked {
                ++i;
            }
        }

        if (totalWeight == 0) return MAX_SCORE;

        uint256 result = totalWeightedScore / totalWeight;
        return result > MAX_SCORE ? MAX_SCORE : uint16(result);
    }

    /**
     * @dev Derive health status from composite score
     */
    function _deriveStatus(uint16 score) internal view returns (HealthStatus) {
        if (score >= healthyThreshold) return HealthStatus.HEALTHY;
        if (score >= criticalThreshold) return HealthStatus.WARNING;
        return HealthStatus.CRITICAL;
    }

    /**
     * @dev Count stale subsystems
     */
    function _countStaleSubsystems() internal view returns (uint8 count) {
        uint256 len = subsystemIds.length;
        for (uint256 i; i < len; ) {
            Subsystem storage sub = subsystems[subsystemIds[i]];
            if (sub.isActive) {
                uint48 threshold = sub.stalenessThreshold > 0
                    ? sub.stalenessThreshold
                    : DEFAULT_STALENESS_THRESHOLD;
                if ((block.timestamp - sub.lastUpdated) > threshold) {
                    unchecked {
                        ++count;
                    }
                }
            }
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @dev Record a health snapshot in the ring buffer
     */
    function _recordSnapshot(uint16 score, HealthStatus status) internal {
        uint8 staleCount = _countStaleSubsystems();
        uint8 activeCount;
        uint256 len = subsystemIds.length;
        for (uint256 i; i < len; ) {
            if (subsystems[subsystemIds[i]].isActive) {
                unchecked {
                    ++activeCount;
                }
            }
            unchecked {
                ++i;
            }
        }

        snapshots[snapshotIndex] = HealthSnapshot({
            compositeScore: score,
            status: status,
            timestamp: uint48(block.timestamp),
            activeSubsystems: activeCount,
            staleSubsystems: staleCount
        });

        snapshotIndex = (snapshotIndex + 1) % 64;
        unchecked {
            ++totalSnapshots;
        }
    }

    /**
     * @dev Attempt to pause all registered pausable targets
     *      Uses try/catch to not fail if individual contracts revert
     */
    function _autoPauseTargets() internal {
        uint256 len = pausableTargetList.length;
        uint8 paused;

        for (uint256 i; i < len; ) {
            address target = pausableTargetList[i];
            PausableTarget storage pt = pausableTargets[target];

            if (pt.isRegistered && !pt.wasPausedByUs) {
                // Try to call pause() — we don't require specific interface
                // solhint-disable-next-line avoid-low-level-calls
                (bool success, ) = target.call(
                    abi.encodeWithSignature("pause()")
                );
                if (success) {
                    pt.wasPausedByUs = true;
                    unchecked {
                        ++paused;
                    }
                }
            }

            unchecked {
                ++i;
            }
        }

        lastAutoPauseAt = uint48(block.timestamp);
        if (paused > 0) {
            emit AutoPauseTriggered(compositeScore, paused);
        }
    }

    /**
     * @dev Attempt to unpause contracts that we previously paused
     */
    function _autoRecoverTargets() internal {
        uint256 len = pausableTargetList.length;
        uint8 unpaused;

        for (uint256 i; i < len; ) {
            address target = pausableTargetList[i];
            PausableTarget storage pt = pausableTargets[target];

            if (pt.isRegistered && pt.wasPausedByUs) {
                // solhint-disable-next-line avoid-low-level-calls
                (bool success, ) = target.call(
                    abi.encodeWithSignature("unpause()")
                );
                if (success) {
                    pt.wasPausedByUs = false;
                    unchecked {
                        ++unpaused;
                    }
                }
            }

            unchecked {
                ++i;
            }
        }

        if (unpaused > 0) {
            emit AutoPauseRecovered(unpaused);
        }
    }
}
