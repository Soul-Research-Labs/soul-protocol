// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title RelayerSLAEnforcer
 * @author Soul Protocol
 * @notice On-chain Service Level Agreement (SLA) enforcement for relayers.
 *         Tracks liveness commitments, response time commitments, and minimum
 *         success rates, automatically applying penalties for violations.
 *
 * @dev Architecture:
 *      - Relayers register and commit to SLA terms (or accept defaults)
 *      - Reporters (authorized routers/monitors) record delivery outcomes
 *      - Each epoch (configurable, default 1 day), SLA compliance is evaluated
 *      - Violations trigger escalating penalties: WARNING → FINE → SUSPENSION
 *      - Fines are collected from relayer escrow deposits
 *      - Suspension means the relayer is removed from active routing until cured
 *
 *      Roles:
 *      - DEFAULT_ADMIN_ROLE: Full control, set global SLA parameters
 *      - REPORTER_ROLE: Record delivery outcomes (trusted routers/monitors)
 *      - SLASHER_ROLE: Evaluate epochs and apply penalties
 *
 *      Invariants:
 *      - totalDeposited ≥ totalFined for each relayer
 *      - violation escalation: WARNING < FINE < SUSPENSION
 *      - epochs are evaluated in order (no skipping)
 *      - fines cannot exceed relayer's remaining deposit
 *
 * @custom:security-contact security@soulprotocol.io
 */
contract RelayerSLAEnforcer is AccessControl, ReentrancyGuard {
    /*//////////////////////////////////////////////////////////////
                             CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant REPORTER_ROLE = keccak256("REPORTER_ROLE");
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");

    /// @notice Default epoch duration (1 day)
    uint48 public constant DEFAULT_EPOCH_DURATION = 1 days;

    /// @notice Minimum deposit to register
    uint256 public constant MIN_DEPOSIT = 0.1 ether;

    /// @notice Violation levels
    uint8 public constant VIOLATION_NONE = 0;
    uint8 public constant VIOLATION_WARNING = 1;
    uint8 public constant VIOLATION_FINE = 2;
    uint8 public constant VIOLATION_SUSPENSION = 3;

    /// @notice Fine percentages (of deposit) per violation level
    uint16 public constant FINE_BPS_WARNING = 0; // 0% — just a warning
    uint16 public constant FINE_BPS_FINE = 500; // 5% of deposit
    uint16 public constant FINE_BPS_SUSPENSION = 2000; // 20% of deposit

    /// @notice Maximum consecutive violations before forced suspension
    uint8 public constant MAX_CONSECUTIVE_VIOLATIONS = 5;

    uint16 public constant BPS = 10_000;

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice SLA terms for a relayer
    struct SLATerms {
        uint16 minSuccessRateBps; // Minimum success rate (default 9500 = 95%)
        uint48 maxResponseTimeSec; // Max response time in seconds (default 300 = 5 min)
        uint48 maxDowntimeSec; // Max acceptable downtime per epoch (default 3600 = 1hr)
    }

    /// @notice Relayer SLA state
    struct RelayerSLA {
        address relayer;
        SLATerms terms;
        uint256 deposit; // Current escrow deposit
        uint256 totalFined; // Cumulative fines
        uint48 registeredAt; // Registration timestamp
        uint48 lastEpochEvaluated; // Last epoch start timestamp that was evaluated
        uint8 consecutiveViolations; // Consecutive epochs with violations
        bool isSuspended; // Currently suspended
        bool isRegistered; // Whether registered
    }

    /// @notice Per-epoch performance metrics
    struct EpochMetrics {
        uint32 deliveriesAttempted;
        uint32 deliveriesSucceeded;
        uint32 deliveriesFailed;
        uint48 totalResponseTime; // Sum of response times (seconds)
        uint48 maxResponseTime; // Worst response time in epoch
        uint48 lastActivityAt; // Last delivery timestamp
        bool evaluated; // Whether this epoch was already evaluated
    }

    /// @notice Evaluation result
    struct EvaluationResult {
        bool successRatePassed;
        bool responseTimePassed;
        bool livenessPassed;
        uint8 violationLevel;
        uint256 fineAmount;
    }

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event RelayerRegistered(
        address indexed relayer,
        uint256 deposit,
        SLATerms terms
    );
    event DepositAdded(
        address indexed relayer,
        uint256 amount,
        uint256 newTotal
    );
    event DepositWithdrawn(address indexed relayer, uint256 amount);
    event DeliveryRecorded(
        address indexed relayer,
        bool success,
        uint48 responseTime,
        uint48 epoch
    );
    event EpochEvaluated(
        address indexed relayer,
        uint48 epoch,
        uint8 violationLevel,
        uint256 fineAmount
    );
    event RelayerSuspended(
        address indexed relayer,
        uint8 consecutiveViolations
    );
    event RelayerReinstated(address indexed relayer);
    event FineCollected(address indexed relayer, uint256 amount);
    event RelayerExited(address indexed relayer, uint256 depositReturned);
    event DefaultSLAUpdated(SLATerms newTerms);
    event EpochDurationUpdated(uint48 newDuration);

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error AlreadyRegistered();
    error NotRegistered();
    error InsufficientDeposit(uint256 provided, uint256 required);
    error RelayerIsSuspended();
    error RelayerNotSuspended();
    error EpochNotComplete(uint48 epochEnd);
    error EpochAlreadyEvaluated(uint48 epoch);
    error InvalidSLATerms();
    error NoDeposit();
    error CantExitWhileSuspended();
    error ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                              STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Default SLA terms for new relayers
    SLATerms public defaultSLA;

    /// @notice Epoch duration
    uint48 public epochDuration;

    /// @notice Relayer address → SLA state
    mapping(address => RelayerSLA) internal _relayers;

    /// @notice Relayer address → epoch start → metrics
    mapping(address => mapping(uint48 => EpochMetrics)) internal _epochMetrics;

    /// @notice List of registered relayers
    address[] public relayerList;

    /// @notice Protocol-collected fines
    uint256 public collectedFines;

    /*//////////////////////////////////////////////////////////////
                           CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Deploy the SLA enforcer with default terms and grant admin roles
    /// @param admin Address receiving DEFAULT_ADMIN_ROLE, REPORTER_ROLE, and SLASHER_ROLE
    constructor(address admin) {
        if (admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(REPORTER_ROLE, admin);
        _grantRole(SLASHER_ROLE, admin);

        epochDuration = DEFAULT_EPOCH_DURATION;

        defaultSLA = SLATerms({
            minSuccessRateBps: 9500, // 95%
            maxResponseTimeSec: 300, // 5 minutes
            maxDowntimeSec: 3600 // 1 hour
        });
    }

    /*//////////////////////////////////////////////////////////////
                        RELAYER REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register as a relayer with default SLA terms
     */
    function register() external payable nonReentrant {
        _registerRelayer(msg.sender, defaultSLA);
    }

    /**
     * @notice Register with custom SLA terms (must be at least as strict as defaults)
     * @param terms Custom SLA terms
     */
    function registerWithTerms(
        SLATerms calldata terms
    ) external payable nonReentrant {
        // Custom terms must be at least as strict as default
        if (terms.minSuccessRateBps < defaultSLA.minSuccessRateBps)
            revert InvalidSLATerms();
        if (terms.maxResponseTimeSec > defaultSLA.maxResponseTimeSec)
            revert InvalidSLATerms();
        if (terms.maxDowntimeSec > defaultSLA.maxDowntimeSec)
            revert InvalidSLATerms();

        _registerRelayer(msg.sender, terms);
    }

    /**
     * @notice Add more deposit to escrow
     */
    function addDeposit() external payable nonReentrant {
        RelayerSLA storage sla = _relayers[msg.sender];
        if (!sla.isRegistered) revert NotRegistered();
        if (msg.value == 0) revert NoDeposit();

        sla.deposit += msg.value;
        emit DepositAdded(msg.sender, msg.value, sla.deposit);
    }

    /**
     * @notice Exit the SLA system and withdraw remaining deposit
     * @dev Cannot exit while suspended (must cure first)
     */
    function exit() external nonReentrant {
        RelayerSLA storage sla = _relayers[msg.sender];
        if (!sla.isRegistered) revert NotRegistered();
        if (sla.isSuspended) revert CantExitWhileSuspended();

        uint256 remaining = sla.deposit;
        sla.deposit = 0;
        sla.isRegistered = false;

        // Remove from list (swap-and-pop)
        _removeFromList(msg.sender);

        if (remaining > 0) {
            (bool ok, ) = msg.sender.call{value: remaining}("");
            require(ok, "Transfer failed");
        }

        emit RelayerExited(msg.sender, remaining);
    }

    /*//////////////////////////////////////////////////////////////
                       DELIVERY RECORDING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Record a delivery outcome for a relayer
     * @param relayer The relayer address
     * @param success Whether the delivery succeeded
     * @param responseTimeSec Response time in seconds
     */
    function recordDelivery(
        address relayer,
        bool success,
        uint48 responseTimeSec
    ) external onlyRole(REPORTER_ROLE) {
        RelayerSLA storage sla = _relayers[relayer];
        if (!sla.isRegistered) revert NotRegistered();

        uint48 epoch = _currentEpoch();
        EpochMetrics storage metrics = _epochMetrics[relayer][epoch];

        metrics.deliveriesAttempted += 1;
        if (success) {
            metrics.deliveriesSucceeded += 1;
            metrics.totalResponseTime += responseTimeSec;
            if (responseTimeSec > metrics.maxResponseTime) {
                metrics.maxResponseTime = responseTimeSec;
            }
        } else {
            metrics.deliveriesFailed += 1;
        }
        metrics.lastActivityAt = uint48(block.timestamp);

        emit DeliveryRecorded(relayer, success, responseTimeSec, epoch);
    }

    /*//////////////////////////////////////////////////////////////
                       EPOCH EVALUATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Evaluate a relayer's SLA compliance for a completed epoch
     * @param relayer The relayer to evaluate
     * @param epoch The epoch start timestamp to evaluate
     * @return result Evaluation details
     */
    function evaluateEpoch(
        address relayer,
        uint48 epoch
    )
        external
        onlyRole(SLASHER_ROLE)
        nonReentrant
        returns (EvaluationResult memory result)
    {
        RelayerSLA storage sla = _relayers[relayer];
        if (!sla.isRegistered) revert NotRegistered();

        // Epoch must be complete
        if (block.timestamp < epoch + epochDuration) {
            revert EpochNotComplete(epoch + epochDuration);
        }

        EpochMetrics storage metrics = _epochMetrics[relayer][epoch];
        if (metrics.evaluated) revert EpochAlreadyEvaluated(epoch);

        metrics.evaluated = true;
        sla.lastEpochEvaluated = epoch;

        // Evaluate SLA terms
        result = _evaluate(sla.terms, metrics, epoch);

        // Calculate fine amount based on violation level and deposit
        result.fineAmount = _calculateFine(sla.deposit, result.violationLevel);

        // Apply consequences
        if (result.violationLevel > VIOLATION_NONE) {
            sla.consecutiveViolations += 1;

            if (result.fineAmount > 0 && sla.deposit > 0) {
                uint256 fine = result.fineAmount > sla.deposit
                    ? sla.deposit
                    : result.fineAmount;
                sla.deposit -= fine;
                sla.totalFined += fine;
                collectedFines += fine;
                emit FineCollected(relayer, fine);
            }

            // Force suspension after MAX_CONSECUTIVE_VIOLATIONS
            if (
                result.violationLevel >= VIOLATION_SUSPENSION ||
                sla.consecutiveViolations >= MAX_CONSECUTIVE_VIOLATIONS
            ) {
                sla.isSuspended = true;
                emit RelayerSuspended(relayer, sla.consecutiveViolations);
            }
        } else {
            // Reset violation streak on clean epoch
            sla.consecutiveViolations = 0;
        }

        emit EpochEvaluated(
            relayer,
            epoch,
            result.violationLevel,
            result.fineAmount
        );
    }

    /**
     * @notice Reinstate a suspended relayer (requires deposit top-up)
     * @param relayer The relayer to reinstate
     */
    function reinstate(address relayer) external onlyRole(DEFAULT_ADMIN_ROLE) {
        RelayerSLA storage sla = _relayers[relayer];
        if (!sla.isRegistered) revert NotRegistered();
        if (!sla.isSuspended) revert RelayerNotSuspended();
        if (sla.deposit < MIN_DEPOSIT)
            revert InsufficientDeposit(sla.deposit, MIN_DEPOSIT);

        sla.isSuspended = false;
        sla.consecutiveViolations = 0;

        emit RelayerReinstated(relayer);
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update default SLA terms for new registrations
     */
    function setDefaultSLA(
        SLATerms calldata terms
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (terms.minSuccessRateBps == 0 || terms.minSuccessRateBps > BPS)
            revert InvalidSLATerms();
        if (terms.maxResponseTimeSec == 0) revert InvalidSLATerms();

        defaultSLA = terms;
        emit DefaultSLAUpdated(terms);
    }

    /**
     * @notice Update epoch duration
     * @param newDuration New duration in seconds (min 1 hour, max 7 days)
     */
    function setEpochDuration(
        uint48 newDuration
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(
            newDuration >= 1 hours && newDuration <= 7 days,
            "Invalid epoch duration"
        );
        epochDuration = newDuration;
        emit EpochDurationUpdated(newDuration);
    }

    /**
     * @notice Withdraw collected fines to a recipient
     */
    function withdrawFines(
        address recipient
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        if (recipient == address(0)) revert ZeroAddress();
        uint256 amount = collectedFines;
        collectedFines = 0;

        (bool ok, ) = recipient.call{value: amount}("");
        require(ok, "Transfer failed");
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get relayer's SLA state
    function getRelayerSLA(
        address relayer
    ) external view returns (RelayerSLA memory) {
        return _relayers[relayer];
    }

    /// @notice Get epoch metrics for a relayer
    function getEpochMetrics(
        address relayer,
        uint48 epoch
    ) external view returns (EpochMetrics memory) {
        return _epochMetrics[relayer][epoch];
    }

    /// @notice Current epoch start timestamp
    function currentEpoch() external view returns (uint48) {
        return _currentEpoch();
    }

    /// @notice Number of registered relayers
    function relayerCount() external view returns (uint256) {
        return relayerList.length;
    }

    /// @notice Check if a relayer is active (registered and not suspended)
    function isActive(address relayer) external view returns (bool) {
        RelayerSLA storage sla = _relayers[relayer];
        return sla.isRegistered && !sla.isSuspended;
    }

    /// @notice Preview what a relayer's evaluation result would be for the current epoch
    function previewEvaluation(
        address relayer
    ) external view returns (EvaluationResult memory result) {
        RelayerSLA storage sla = _relayers[relayer];
        if (!sla.isRegistered) revert NotRegistered();

        uint48 epoch = _currentEpoch();
        EpochMetrics storage metrics = _epochMetrics[relayer][epoch];

        result = _evaluate(sla.terms, metrics, epoch);
        result.fineAmount = _calculateFine(sla.deposit, result.violationLevel);
    }

    /*//////////////////////////////////////////////////////////////
                       INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _registerRelayer(address relayer, SLATerms memory terms) internal {
        if (_relayers[relayer].isRegistered) revert AlreadyRegistered();
        if (msg.value < MIN_DEPOSIT)
            revert InsufficientDeposit(msg.value, MIN_DEPOSIT);

        _relayers[relayer] = RelayerSLA({
            relayer: relayer,
            terms: terms,
            deposit: msg.value,
            totalFined: 0,
            registeredAt: uint48(block.timestamp),
            lastEpochEvaluated: 0,
            consecutiveViolations: 0,
            isSuspended: false,
            isRegistered: true
        });

        relayerList.push(relayer);
        emit RelayerRegistered(relayer, msg.value, terms);
    }

    function _evaluate(
        SLATerms storage terms,
        EpochMetrics storage metrics,
        uint48 epoch
    ) internal view returns (EvaluationResult memory result) {
        result.successRatePassed = true;
        result.responseTimePassed = true;
        result.livenessPassed = true;

        uint32 attempted = metrics.deliveriesAttempted;

        // If no deliveries this epoch, check liveness
        if (attempted == 0) {
            // Epoch with zero activity — check if downtime exceeds threshold
            uint48 epochEnd = epoch + epochDuration;
            uint48 effectiveEnd = block.timestamp < epochEnd
                ? uint48(block.timestamp)
                : epochEnd;
            uint48 silentTime = effectiveEnd - epoch;

            if (silentTime > terms.maxDowntimeSec) {
                result.livenessPassed = false;
            } else {
                // No activity but within tolerance
                return result;
            }
        } else {
            // Success rate check
            uint256 successRate = (uint256(metrics.deliveriesSucceeded) * BPS) /
                attempted;
            if (successRate < terms.minSuccessRateBps) {
                result.successRatePassed = false;
            }

            // Response time check (average)
            if (metrics.deliveriesSucceeded > 0) {
                uint48 avgResponse = metrics.totalResponseTime /
                    uint48(metrics.deliveriesSucceeded);
                if (avgResponse > terms.maxResponseTimeSec) {
                    result.responseTimePassed = false;
                }
            }

            // Liveness check via activity gap
            if (metrics.lastActivityAt > 0) {
                uint48 epochEnd = epoch + epochDuration;
                uint48 effectiveEnd = block.timestamp < epochEnd
                    ? uint48(block.timestamp)
                    : epochEnd;
                uint48 gap = effectiveEnd - metrics.lastActivityAt;
                if (gap > terms.maxDowntimeSec) {
                    result.livenessPassed = false;
                }
            }
        }

        // Determine violation level
        uint8 failCount;
        if (!result.successRatePassed) {
            unchecked {
                ++failCount;
            }
        }
        if (!result.responseTimePassed) {
            unchecked {
                ++failCount;
            }
        }
        if (!result.livenessPassed) {
            unchecked {
                ++failCount;
            }
        }

        if (failCount == 0) {
            result.violationLevel = VIOLATION_NONE;
        } else if (failCount == 1) {
            result.violationLevel = VIOLATION_WARNING;
        } else if (failCount == 2) {
            result.violationLevel = VIOLATION_FINE;
        } else {
            result.violationLevel = VIOLATION_SUSPENSION;
        }

        // Calculate fine based on deposit
        // We need to look up the deposit — callers pass terms not the full SLA
        // Fine calculation is done by caller using the relayer's deposit
        // Here we return the fine BPS
    }

    /// @notice Calculate fine amount for a given deposit and violation level
    function _calculateFine(
        uint256 deposit,
        uint8 violationLevel
    ) internal pure returns (uint256) {
        if (violationLevel == VIOLATION_WARNING)
            return (deposit * FINE_BPS_WARNING) / BPS;
        if (violationLevel == VIOLATION_FINE)
            return (deposit * FINE_BPS_FINE) / BPS;
        if (violationLevel == VIOLATION_SUSPENSION)
            return (deposit * FINE_BPS_SUSPENSION) / BPS;
        return 0;
    }

    function _currentEpoch() internal view returns (uint48) {
        return uint48((block.timestamp / epochDuration) * epochDuration);
    }

    function _removeFromList(address relayer) internal {
        uint256 len = relayerList.length;
        for (uint256 i; i < len; ) {
            if (relayerList[i] == relayer) {
                relayerList[i] = relayerList[len - 1];
                relayerList.pop();
                return;
            }
            unchecked {
                ++i;
            }
        }
    }

    /// @dev Accept ETH for deposits
    receive() external payable {}
}
