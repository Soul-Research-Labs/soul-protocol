// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title SecurityOracle
 * @author Soul Protocol
 * @notice Decentralized security oracle for real-time threat detection
 * @dev Aggregates security signals from multiple sources to protect Soul protocol
 *
 * Features:
 * 1. Threat Reporting: Multiple reporters submit threat signals
 * 2. Threat Aggregation: Weighted consensus on threat severity
 * 3. Auto-Escalation: Automatic circuit breaker triggers
 * 4. Threat History: Historical threat analysis
 * 5. Reporter Reputation: Track reporter accuracy
 */
contract SecurityOracle is ReentrancyGuard, AccessControl, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error NotAuthorizedReporter();
    error ThreatAlreadyReported();
    error InvalidSeverity();
    error InvalidThreatType();
    error ReporterSlashed();
    error InsufficientStake();
    error CooldownNotExpired();
    error ThreatNotFound();
    error AlreadyResolved();

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event ThreatReported(
        bytes32 indexed threatId,
        address indexed reporter,
        ThreatType threatType,
        Severity severity,
        bytes32 targetHash,
        string description
    );

    event ThreatConfirmed(bytes32 indexed threatId, uint256 confirmations);
    event ThreatResolved(bytes32 indexed threatId, Resolution resolution);
    event SecurityLevelChanged(SecurityLevel oldLevel, SecurityLevel newLevel);
    event ReporterRegistered(address indexed reporter, uint256 stake);
    event ReporterSlashedEvent(
        address indexed reporter,
        uint256 amount,
        bytes32 reason
    );
    event CircuitBreakerTriggered(
        bytes32 indexed threatId,
        address indexed triggeredBy
    );
    event AutoEscalation(bytes32 indexed threatId, SecurityLevel newLevel);

    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    enum ThreatType {
        NONE,
        REENTRANCY_ATTACK,
        FLASH_LOAN_ATTACK,
        PRICE_MANIPULATION,
        GOVERNANCE_ATTACK,
        BRIDGE_EXPLOIT,
        PROOF_FORGERY,
        DOS_ATTACK,
        MEV_EXTRACTION,
        SMART_CONTRACT_BUG,
        ORACLE_MANIPULATION,
        OTHER
    }

    enum Severity {
        NONE,
        LOW, // Informational
        MEDIUM, // Potential issue
        HIGH, // Active threat
        CRITICAL // Immediate action required
    }

    enum SecurityLevel {
        NORMAL, // All operations allowed
        ELEVATED, // Enhanced monitoring
        HIGH, // Some operations restricted
        CRITICAL, // Emergency mode
        LOCKDOWN // All operations halted
    }

    enum Resolution {
        PENDING,
        CONFIRMED_THREAT,
        FALSE_POSITIVE,
        MITIGATED,
        IGNORED
    }

    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct Threat {
        bytes32 threatId;
        ThreatType threatType;
        Severity severity;
        bytes32 targetHash; // Hash of affected contract/tx
        string description;
        address reporter;
        uint256 reportedAt;
        uint256 confirmations;
        uint256 rejections;
        Resolution resolution;
        bool autoEscalated;
    }

    struct Reporter {
        bool isActive;
        uint256 stake;
        uint256 reportCount;
        uint256 accurateReports;
        uint256 falseReports;
        uint256 lastReportBlock;
        uint256 reputation; // 0-10000 (basis points)
        bool isSlashed;
    }

    struct SecurityStatus {
        SecurityLevel currentLevel;
        uint256 lastLevelChange;
        uint256 activeThreats;
        uint256 criticalThreats;
        bytes32 highestThreat;
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant REPORTER_ROLE = keccak256("REPORTER_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant RESOLVER_ROLE = keccak256("RESOLVER_ROLE");

    /// @notice Minimum stake to become a reporter
    uint256 public constant MIN_REPORTER_STAKE = 1 ether;

    /// @notice Confirmations needed for auto-escalation
    uint256 public constant CONFIRMATION_THRESHOLD = 3;

    /// @notice Cooldown between reports from same reporter
    uint256 public constant REPORT_COOLDOWN = 10; // blocks

    /// @notice Current security status
    SecurityStatus public securityStatus;

    /// @notice All threats
    mapping(bytes32 => Threat) public threats;

    /// @notice Reporter data
    mapping(address => Reporter) public reporters;

    /// @notice Threat confirmations by reporter
    mapping(bytes32 => mapping(address => bool)) public threatConfirmations;

    /// @notice Threat rejections by reporter
    mapping(bytes32 => mapping(address => bool)) public threatRejections;

    /// @notice Active threat IDs
    bytes32[] public activeThreatIds;

    /// @notice Circuit breaker contracts to notify
    address[] public circuitBreakers;

    /// @notice Threat count by type
    mapping(ThreatType => uint256) public threatCountByType;

    /// @notice Historical security levels
    mapping(uint256 => SecurityLevel) public historicalLevels;

    /// @notice Nonce for threat IDs
    uint256 public threatNonce;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);
        _grantRole(RESOLVER_ROLE, admin);

        securityStatus = SecurityStatus({
            currentLevel: SecurityLevel.NORMAL,
            lastLevelChange: block.timestamp,
            activeThreats: 0,
            criticalThreats: 0,
            highestThreat: bytes32(0)
        });
    }

    /*//////////////////////////////////////////////////////////////
                         REPORTER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register as a security reporter
     */
    function registerReporter() external payable nonReentrant {
        if (msg.value < MIN_REPORTER_STAKE) revert InsufficientStake();
        if (reporters[msg.sender].isSlashed) revert ReporterSlashed();

        reporters[msg.sender] = Reporter({
            isActive: true,
            stake: msg.value,
            reportCount: 0,
            accurateReports: 0,
            falseReports: 0,
            lastReportBlock: 0,
            reputation: 5000, // Start at 50%
            isSlashed: false
        });

        _grantRole(REPORTER_ROLE, msg.sender);

        emit ReporterRegistered(msg.sender, msg.value);
    }

    /**
     * @notice Report a security threat
     * @param threatType Type of threat
     * @param severity Severity level
     * @param targetHash Hash of affected target
     * @param description Human-readable description
     * @return threatId Unique threat identifier
     */
    function reportThreat(
        ThreatType threatType,
        Severity severity,
        bytes32 targetHash,
        string calldata description
    ) external onlyRole(REPORTER_ROLE) nonReentrant returns (bytes32 threatId) {
        Reporter storage reporter = reporters[msg.sender];

        if (!reporter.isActive) revert NotAuthorizedReporter();
        if (reporter.isSlashed) revert ReporterSlashed();
        if (block.number < reporter.lastReportBlock + REPORT_COOLDOWN) {
            revert CooldownNotExpired();
        }
        if (threatType == ThreatType.NONE) revert InvalidThreatType();
        if (severity == Severity.NONE) revert InvalidSeverity();

        threatId = keccak256(
            abi.encodePacked(
                msg.sender,
                threatType,
                targetHash,
                threatNonce++,
                block.timestamp
            )
        );

        threats[threatId] = Threat({
            threatId: threatId,
            threatType: threatType,
            severity: severity,
            targetHash: targetHash,
            description: description,
            reporter: msg.sender,
            reportedAt: block.timestamp,
            confirmations: 1, // Reporter counts as first confirmation
            rejections: 0,
            resolution: Resolution.PENDING,
            autoEscalated: false
        });

        threatConfirmations[threatId][msg.sender] = true;
        reporter.lastReportBlock = block.number;
        reporter.reportCount++;

        activeThreatIds.push(threatId);
        securityStatus.activeThreats++;
        threatCountByType[threatType]++;

        if (severity == Severity.CRITICAL) {
            securityStatus.criticalThreats++;
            securityStatus.highestThreat = threatId;
        }

        emit ThreatReported(
            threatId,
            msg.sender,
            threatType,
            severity,
            targetHash,
            description
        );

        // Auto-escalate for critical threats
        if (severity == Severity.CRITICAL) {
            _escalateSecurityLevel(SecurityLevel.HIGH);
        }
    }

    /**
     * @notice Confirm a reported threat
     * @param threatId Threat to confirm
     */
    function confirmThreat(
        bytes32 threatId
    ) external onlyRole(REPORTER_ROLE) nonReentrant {
        Threat storage threat = threats[threatId];
        Reporter storage reporter = reporters[msg.sender];

        if (threat.reportedAt == 0) revert ThreatNotFound();
        if (threat.resolution != Resolution.PENDING) revert AlreadyResolved();
        if (threatConfirmations[threatId][msg.sender])
            revert ThreatAlreadyReported();
        if (threatRejections[threatId][msg.sender])
            revert ThreatAlreadyReported();
        if (!reporter.isActive || reporter.isSlashed)
            revert NotAuthorizedReporter();

        threatConfirmations[threatId][msg.sender] = true;
        threat.confirmations++;

        emit ThreatConfirmed(threatId, threat.confirmations);

        // Auto-escalate if threshold reached
        if (
            threat.confirmations >= CONFIRMATION_THRESHOLD &&
            !threat.autoEscalated
        ) {
            threat.autoEscalated = true;
            _autoEscalate(threat);
        }
    }

    /**
     * @notice Reject a reported threat (false positive)
     * @param threatId Threat to reject
     */
    function rejectThreat(
        bytes32 threatId
    ) external onlyRole(REPORTER_ROLE) nonReentrant {
        Threat storage threat = threats[threatId];
        Reporter storage reporter = reporters[msg.sender];

        if (threat.reportedAt == 0) revert ThreatNotFound();
        if (threat.resolution != Resolution.PENDING) revert AlreadyResolved();
        if (threatConfirmations[threatId][msg.sender])
            revert ThreatAlreadyReported();
        if (threatRejections[threatId][msg.sender])
            revert ThreatAlreadyReported();
        if (!reporter.isActive || reporter.isSlashed)
            revert NotAuthorizedReporter();

        threatRejections[threatId][msg.sender] = true;
        threat.rejections++;
    }

    /*//////////////////////////////////////////////////////////////
                         RESOLVER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Resolve a threat
     * @param threatId Threat to resolve
     * @param resolution Resolution type
     */
    function resolveThreat(
        bytes32 threatId,
        Resolution resolution
    ) external onlyRole(RESOLVER_ROLE) {
        Threat storage threat = threats[threatId];

        if (threat.reportedAt == 0) revert ThreatNotFound();
        if (threat.resolution != Resolution.PENDING) revert AlreadyResolved();
        if (resolution == Resolution.PENDING) revert InvalidSeverity();

        threat.resolution = resolution;
        securityStatus.activeThreats--;

        if (threat.severity == Severity.CRITICAL) {
            securityStatus.criticalThreats--;
        }

        // Update reporter reputation
        Reporter storage reporter = reporters[threat.reporter];
        if (
            resolution == Resolution.CONFIRMED_THREAT ||
            resolution == Resolution.MITIGATED
        ) {
            reporter.accurateReports++;
            reporter.reputation = _min(reporter.reputation + 100, 10000);
        } else if (resolution == Resolution.FALSE_POSITIVE) {
            reporter.falseReports++;
            reporter.reputation = reporter.reputation > 200
                ? reporter.reputation - 200
                : 0;

            // Slash for repeated false positives
            if (reporter.falseReports > 3 && reporter.reputation < 3000) {
                _slashReporter(threat.reporter, "Repeated false positives");
            }
        }

        emit ThreatResolved(threatId, resolution);

        // Potentially lower security level
        _reevaluateSecurityLevel();
    }

    /**
     * @notice Manually set security level
     * @param newLevel New security level
     */
    function setSecurityLevel(
        SecurityLevel newLevel
    ) external onlyRole(GUARDIAN_ROLE) {
        _escalateSecurityLevel(newLevel);
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get current security level
     * @return level Current security level (0-4)
     */
    function getSecurityLevel() external view returns (uint8) {
        return uint8(securityStatus.currentLevel);
    }

    /**
     * @notice Get threat count by severity
     * @param severity Severity level
     * @return count Number of active threats at this severity
     */
    function getThreatCount(
        Severity severity
    ) external view returns (uint256 count) {
        for (uint256 i = 0; i < activeThreatIds.length; i++) {
            Threat storage t = threats[activeThreatIds[i]];
            if (t.severity == severity && t.resolution == Resolution.PENDING) {
                count++;
            }
        }
    }

    /**
     * @notice Check if system is safe for operations
     * @return safe Whether system is safe
     */
    function isSystemSafe() external view returns (bool safe) {
        return securityStatus.currentLevel < SecurityLevel.CRITICAL;
    }

    /**
     * @notice Get reporter reputation
     * @param reporter Reporter address
     * @return reputation Reputation score (0-10000)
     */
    function getReporterReputation(
        address reporter
    ) external view returns (uint256 reputation) {
        return reporters[reporter].reputation;
    }

    /**
     * @notice Get active threats
     * @return threatIds Array of active threat IDs
     */
    function getActiveThreats()
        external
        view
        returns (bytes32[] memory threatIds)
    {
        uint256 count = 0;
        for (uint256 i = 0; i < activeThreatIds.length; i++) {
            if (threats[activeThreatIds[i]].resolution == Resolution.PENDING) {
                count++;
            }
        }

        threatIds = new bytes32[](count);
        uint256 index = 0;
        for (uint256 i = 0; i < activeThreatIds.length && index < count; i++) {
            if (threats[activeThreatIds[i]].resolution == Resolution.PENDING) {
                threatIds[index++] = activeThreatIds[i];
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _autoEscalate(Threat storage threat) internal {
        SecurityLevel newLevel;

        if (threat.severity == Severity.CRITICAL) {
            newLevel = SecurityLevel.CRITICAL;
        } else if (threat.severity == Severity.HIGH) {
            newLevel = SecurityLevel.HIGH;
        } else {
            newLevel = SecurityLevel.ELEVATED;
        }

        if (newLevel > securityStatus.currentLevel) {
            _escalateSecurityLevel(newLevel);
            emit AutoEscalation(threat.threatId, newLevel);

            // Notify circuit breakers
            if (newLevel >= SecurityLevel.CRITICAL) {
                _triggerCircuitBreakers(threat.threatId);
            }
        }
    }

    function _escalateSecurityLevel(SecurityLevel newLevel) internal {
        SecurityLevel oldLevel = securityStatus.currentLevel;
        securityStatus.currentLevel = newLevel;
        securityStatus.lastLevelChange = block.timestamp;
        historicalLevels[block.timestamp] = newLevel;

        emit SecurityLevelChanged(oldLevel, newLevel);
    }

    function _reevaluateSecurityLevel() internal {
        if (
            securityStatus.criticalThreats == 0 &&
            securityStatus.activeThreats < 3
        ) {
            if (securityStatus.currentLevel > SecurityLevel.NORMAL) {
                _escalateSecurityLevel(SecurityLevel.NORMAL);
            }
        }
    }

    function _triggerCircuitBreakers(bytes32 threatId) internal {
        for (uint256 i = 0; i < circuitBreakers.length; i++) {
            // Call circuit breaker's emergency pause
            (bool success, ) = circuitBreakers[i].call(
                abi.encodeWithSignature("emergencyPause(bytes32)", threatId)
            );
            if (success) {
                emit CircuitBreakerTriggered(threatId, circuitBreakers[i]);
            }
        }
    }

    function _slashReporter(address reporter, string memory reason) internal {
        Reporter storage r = reporters[reporter];
        uint256 slashAmount = r.stake / 2;
        r.stake -= slashAmount;
        r.isSlashed = true;
        r.isActive = false;

        _revokeRole(REPORTER_ROLE, reporter);

        emit ReporterSlashedEvent(
            reporter,
            slashAmount,
            keccak256(bytes(reason))
        );
    }

    function _min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Add a circuit breaker contract
     * @param breaker Circuit breaker address
     */
    function addCircuitBreaker(
        address breaker
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        circuitBreakers.push(breaker);
    }

    /**
     * @notice Pause the oracle
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the oracle
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
