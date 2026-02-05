// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title RuntimeSecurityMonitor
 * @author Soul Protocol Security Team
 * @notice Real-time bytecode analysis and runtime invariant checking
 * @dev Monitors deployed contracts for suspicious behavior and invariant violations
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    Runtime Security Monitor                              │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  ┌─────────────────────────────────────────────────────────────────┐    │
 * │  │                    Bytecode Analyzer                             │    │
 * │  │  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐        │    │
 * │  │  │ Opcode Scan   │  │ Pattern Match │  │ Risk Scoring  │        │    │
 * │  │  └───────────────┘  └───────────────┘  └───────────────┘        │    │
 * │  └─────────────────────────────────────────────────────────────────┘    │
 * │                              │                                          │
 * │                              ▼                                          │
 * │  ┌─────────────────────────────────────────────────────────────────┐    │
 * │  │                    Invariant Checker                             │    │
 * │  │  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐        │    │
 * │  │  │ Balance Check │  │ State Check   │  │ Rate Limit    │        │    │
 * │  │  └───────────────┘  └───────────────┘  └───────────────┘        │    │
 * │  └─────────────────────────────────────────────────────────────────┘    │
 * │                              │                                          │
 * │                              ▼                                          │
 * │  ┌─────────────────────────────────────────────────────────────────┐    │
 * │  │                    Response Actions                              │    │
 * │  │  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐        │    │
 * │  │  │ Log Violation │  │ Alert Team    │  │ Circuit Break │        │    │
 * │  │  └───────────────┘  └───────────────┘  └───────────────┘        │    │
 * │  └─────────────────────────────────────────────────────────────────┘    │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * Suspicious Patterns Detected:
 * - SELFDESTRUCT opcode (+5 risk)
 * - DELEGATECALL opcode (+2 risk)
 * - CREATE2 opcode (+1 risk)
 * - External calls (tracked)
 *
 * Risk Levels:
 * - SAFE: suspiciousPatterns < 2
 * - LOW_RISK: suspiciousPatterns 2-4
 * - MEDIUM_RISK: suspiciousPatterns 5-9
 * - HIGH_RISK: suspiciousPatterns >= 10
 * - MALICIOUS: manually flagged
 *
 * @custom:security-contact security@soulprotocol.io
 */
contract RuntimeSecurityMonitor is AccessControl, ReentrancyGuard, Pausable {
    // ============================================
    // ROLES
    // ============================================

    bytes32 public constant MONITOR_ROLE = keccak256("MONITOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant ANALYZER_ROLE = keccak256("ANALYZER_ROLE");

    // ============================================
    // ENUMS
    // ============================================

    enum InvariantType {
        BALANCE_CONSERVATION, // Total balance must be conserved
        OWNERSHIP_IMMUTABLE, // Ownership cannot change unexpectedly
        SUPPLY_CAP, // Token supply within bounds
        TVL_BOUNDS, // TVL within expected range
        RATE_LIMIT, // Operation rate within limits
        STATE_CONSISTENCY, // State variables consistent
        ACCESS_CONTROL, // Access control integrity
        CUSTOM // User-defined invariant
    }

    enum ViolationSeverity {
        INFO,
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    enum ContractRiskLevel {
        UNKNOWN,
        SAFE,
        LOW_RISK,
        MEDIUM_RISK,
        HIGH_RISK,
        MALICIOUS
    }

    // ============================================
    // STRUCTS
    // ============================================

    struct Invariant {
        bytes32 id;
        address target;
        InvariantType invariantType;
        bytes checkData; // Encoded check parameters
        uint256 threshold; // Violation threshold
        bool active;
        uint256 lastChecked;
        uint256 violationCount;
    }

    struct Violation {
        bytes32 invariantId;
        address target;
        InvariantType invariantType;
        ViolationSeverity severity;
        bytes32 dataHash; // Hash of violation data
        uint256 timestamp;
        uint256 blockNumber;
        bool resolved;
    }

    struct BytecodeAnalysis {
        address target;
        bytes32 codeHash;
        bool hasSelfDestruct;
        bool hasDelegateCall;
        bool hasCreate2;
        bool hasExternalCalls;
        uint256 suspiciousPatterns;
        ContractRiskLevel riskLevel;
        uint256 analyzedAt;
    }

    struct StateSnapshot {
        address target;
        bytes32 stateRoot; // Merkle root of state
        uint256 balance;
        uint256 blockNumber;
        uint256 timestamp;
    }

    struct MonitoredContract {
        address target;
        bool active;
        uint256 addedAt;
        uint256 lastChecked;
        ContractRiskLevel riskLevel;
        bytes32[] invariantIds;
        uint256 violationCount;
    }

    // ============================================
    // CONSTANTS
    // ============================================

    uint256 public constant MAX_INVARIANTS_PER_CONTRACT = 50;
    uint256 public constant VIOLATION_COOLDOWN = 1 hours;
    uint256 public constant CRITICAL_VIOLATION_THRESHOLD = 3;
    uint256 public constant ANALYSIS_VALIDITY_PERIOD = 7 days;

    // Suspicious bytecode patterns (simplified opcodes)
    bytes1 private constant _OP_SELFDESTRUCT = 0xff;
    bytes1 private constant _OP_DELEGATECALL = 0xf4;
    bytes1 private constant _OP_CREATE2 = 0xf5;
    bytes1 private constant _OP_CALL = 0xf1;

    // ============================================
    // STATE VARIABLES
    // ============================================

    mapping(bytes32 => Invariant) public invariants;
    mapping(bytes32 => Violation) public violations;
    mapping(address => BytecodeAnalysis) public bytecodeAnalyses;
    mapping(address => MonitoredContract) public monitoredContracts;
    mapping(address => StateSnapshot[]) public stateHistory;
    mapping(address => mapping(bytes32 => uint256)) public lastViolationTime;

    bytes32[] public allInvariantIds;
    bytes32[] public allViolationIds;
    address[] public monitoredAddresses;

    // Circuit breaker integration
    address public circuitBreaker;
    bool public autoTriggerCircuitBreaker;
    uint256 public criticalViolationsInWindow;
    uint256 public windowStart;

    // ============================================
    // EVENTS
    // ============================================

    event ContractMonitored(
        address indexed target,
        ContractRiskLevel riskLevel
    );
    event ContractUnmonitored(address indexed target);
    event InvariantRegistered(
        bytes32 indexed invariantId,
        address indexed target,
        InvariantType invariantType
    );
    event InvariantDeactivated(bytes32 indexed invariantId);
    event InvariantViolation(
        bytes32 indexed violationId,
        bytes32 indexed invariantId,
        address indexed target,
        ViolationSeverity severity,
        bytes data
    );
    event ViolationResolved(bytes32 indexed violationId, address resolver);
    event BytecodeAnalyzed(
        address indexed target,
        ContractRiskLevel riskLevel,
        uint256 suspiciousPatterns
    );
    event StateSnapshotTaken(
        address indexed target,
        bytes32 stateRoot,
        uint256 blockNumber
    );
    event CircuitBreakerTriggered(bytes32 violationId, string reason);
    event RiskLevelUpdated(
        address indexed target,
        ContractRiskLevel oldLevel,
        ContractRiskLevel newLevel
    );
    event CircuitBreakerUpdated(address oldBreaker, address newBreaker);

    // ============================================
    // ERRORS
    // ============================================

    error ContractNotMonitored(address target);
    error InvariantNotFound(bytes32 invariantId);
    error TooManyInvariants(address target);
    error InvalidInvariantData();
    error ViolationCooldownActive(bytes32 invariantId);
    error ContractAlreadyMonitored(address target);
    error ZeroAddress();
    error NotAContract(address target);

    // ============================================
    // CONSTRUCTOR
    // ============================================

    /**
     * @notice Initialize the RuntimeSecurityMonitor
     * @param _circuitBreaker Address of the circuit breaker contract
     */
    constructor(address _circuitBreaker) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MONITOR_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);
        _grantRole(ANALYZER_ROLE, msg.sender);

        circuitBreaker = _circuitBreaker;
        autoTriggerCircuitBreaker = true;
        windowStart = block.timestamp;
    }

    // ============================================
    // CONTRACT MONITORING
    // ============================================

    /**
     * @notice Add a contract to monitoring
     * @param target Contract address to monitor
     */
    function monitorContract(
        address target
    ) external onlyRole(MONITOR_ROLE) whenNotPaused {
        if (target == address(0)) revert ZeroAddress();
        if (target.code.length == 0) revert NotAContract(target);
        if (monitoredContracts[target].active)
            revert ContractAlreadyMonitored(target);

        // Analyze bytecode
        BytecodeAnalysis memory analysis = _analyzeBytecode(target);
        bytecodeAnalyses[target] = analysis;

        // Register contract
        monitoredContracts[target] = MonitoredContract({
            target: target,
            active: true,
            addedAt: block.timestamp,
            lastChecked: block.timestamp,
            riskLevel: analysis.riskLevel,
            invariantIds: new bytes32[](0),
            violationCount: 0
        });

        monitoredAddresses.push(target);

        // Take initial state snapshot
        _takeStateSnapshot(target);

        emit ContractMonitored(target, analysis.riskLevel);
    }

    /**
     * @notice Remove a contract from monitoring
     * @param target Contract address to unmonitor
     */
    function unmonitorContract(
        address target
    ) external onlyRole(GUARDIAN_ROLE) {
        if (!monitoredContracts[target].active)
            revert ContractNotMonitored(target);

        // Deactivate all invariants
        bytes32[] storage invIds = monitoredContracts[target].invariantIds;
        for (uint256 i = 0; i < invIds.length; i++) {
            invariants[invIds[i]].active = false;
        }

        monitoredContracts[target].active = false;

        emit ContractUnmonitored(target);
    }

    // ============================================
    // INVARIANT REGISTRATION
    // ============================================

    /**
     * @notice Register a new invariant for a monitored contract
     * @param target Contract address
     * @param invariantType Type of invariant
     * @param checkData Encoded check parameters
     * @param threshold Violation threshold
     * @return invariantId The ID of the registered invariant
     */
    function registerInvariant(
        address target,
        InvariantType invariantType,
        bytes calldata checkData,
        uint256 threshold
    ) external onlyRole(MONITOR_ROLE) returns (bytes32 invariantId) {
        if (!monitoredContracts[target].active)
            revert ContractNotMonitored(target);
        if (
            monitoredContracts[target].invariantIds.length >=
            MAX_INVARIANTS_PER_CONTRACT
        ) {
            revert TooManyInvariants(target);
        }

        invariantId = keccak256(
            abi.encodePacked(
                target,
                invariantType,
                checkData,
                block.timestamp,
                msg.sender
            )
        );

        invariants[invariantId] = Invariant({
            id: invariantId,
            target: target,
            invariantType: invariantType,
            checkData: checkData,
            threshold: threshold,
            active: true,
            lastChecked: block.timestamp,
            violationCount: 0
        });

        monitoredContracts[target].invariantIds.push(invariantId);
        allInvariantIds.push(invariantId);

        emit InvariantRegistered(invariantId, target, invariantType);
    }

    /**
     * @notice Register common invariants for a contract
     * @param target Contract address
     */
    function registerCommonInvariants(
        address target
    ) external onlyRole(MONITOR_ROLE) {
        if (!monitoredContracts[target].active)
            revert ContractNotMonitored(target);

        // Balance conservation
        this.registerInvariant(
            target,
            InvariantType.BALANCE_CONSERVATION,
            abi.encode(target.balance),
            1 ether // 1 ETH threshold
        );

        // Rate limit check
        this.registerInvariant(
            target,
            InvariantType.RATE_LIMIT,
            abi.encode(100, 1 hours), // 100 operations per hour
            0
        );

        // State consistency
        this.registerInvariant(
            target,
            InvariantType.STATE_CONSISTENCY,
            abi.encode(_getStateRoot(target)),
            0
        );
    }

    /**
     * @notice Deactivate an invariant
     * @param invariantId Invariant to deactivate
     */
    function deactivateInvariant(
        bytes32 invariantId
    ) external onlyRole(GUARDIAN_ROLE) {
        if (!invariants[invariantId].active)
            revert InvariantNotFound(invariantId);
        invariants[invariantId].active = false;
        emit InvariantDeactivated(invariantId);
    }

    // ============================================
    // INVARIANT CHECKING
    // ============================================

    /**
     * @notice Check a specific invariant
     * @param invariantId Invariant to check
     * @return violated Whether the invariant is violated
     * @return severity Severity if violated
     */
    function checkInvariant(
        bytes32 invariantId
    )
        external
        onlyRole(ANALYZER_ROLE)
        returns (bool violated, ViolationSeverity severity)
    {
        Invariant storage inv = invariants[invariantId];
        if (!inv.active) revert InvariantNotFound(invariantId);

        inv.lastChecked = block.timestamp;
        monitoredContracts[inv.target].lastChecked = block.timestamp;

        (violated, severity) = _evaluateInvariant(inv);

        if (violated) {
            _recordViolation(
                invariantId,
                inv.target,
                inv.invariantType,
                severity
            );
        }
    }

    /**
     * @notice Check all invariants for a contract
     * @param target Contract address
     * @return violationCount Number of violations found
     */
    function checkAllInvariants(
        address target
    ) external onlyRole(ANALYZER_ROLE) returns (uint256 violationCount) {
        if (!monitoredContracts[target].active)
            revert ContractNotMonitored(target);

        monitoredContracts[target].lastChecked = block.timestamp;

        bytes32[] storage invIds = monitoredContracts[target].invariantIds;
        bytes32[] memory violatedIds = new bytes32[](invIds.length);
        InvariantType[] memory violationTypes = new InvariantType[](
            invIds.length
        );
        ViolationSeverity[]
            memory violationSeverities = new ViolationSeverity[](invIds.length);
        uint256 violationIndex;

        for (uint256 i = 0; i < invIds.length; i++) {
            Invariant storage inv = invariants[invIds[i]];
            if (!inv.active) continue;

            inv.lastChecked = block.timestamp;
            (bool violated, ViolationSeverity severity) = _evaluateInvariant(
                inv
            );

            if (violated) {
                violatedIds[violationIndex] = invIds[i];
                violationTypes[violationIndex] = inv.invariantType;
                violationSeverities[violationIndex] = severity;
                violationIndex++;
            }
        }

        for (uint256 i = 0; i < violationIndex; i++) {
            _recordViolation(
                violatedIds[i],
                target,
                violationTypes[i],
                violationSeverities[i]
            );
            violationCount++;
        }
    }

    // ============================================
    // BYTECODE ANALYSIS
    // ============================================

    /**
     * @notice Analyze contract bytecode for suspicious patterns
     * @param target Contract address
     * @return analysis The bytecode analysis result
     */
    function analyzeBytecode(
        address target
    )
        external
        onlyRole(ANALYZER_ROLE)
        returns (BytecodeAnalysis memory analysis)
    {
        analysis = _analyzeBytecode(target);
        bytecodeAnalyses[target] = analysis;

        emit BytecodeAnalyzed(
            target,
            analysis.riskLevel,
            analysis.suspiciousPatterns
        );
    }

    /**
     * @notice Re-analyze bytecode (for proxy contracts that may have changed)
     * @param target Contract address
     */
    function reanalyzeBytecode(
        address target
    ) external onlyRole(ANALYZER_ROLE) {
        BytecodeAnalysis memory oldAnalysis = bytecodeAnalyses[target];
        BytecodeAnalysis memory newAnalysis = _analyzeBytecode(target);

        if (newAnalysis.codeHash != oldAnalysis.codeHash) {
            // Code changed - this is suspicious for non-proxy contracts
            newAnalysis.suspiciousPatterns += 10;
            newAnalysis.riskLevel = ContractRiskLevel.HIGH_RISK;
        }

        bytecodeAnalyses[target] = newAnalysis;

        if (newAnalysis.riskLevel != oldAnalysis.riskLevel) {
            emit RiskLevelUpdated(
                target,
                oldAnalysis.riskLevel,
                newAnalysis.riskLevel
            );
        }
    }

    // ============================================
    // STATE SNAPSHOTS
    // ============================================

    /**
     * @notice Take a state snapshot of a monitored contract
     * @param target Contract address
     */
    function takeStateSnapshot(
        address target
    ) external onlyRole(ANALYZER_ROLE) {
        if (!monitoredContracts[target].active)
            revert ContractNotMonitored(target);
        _takeStateSnapshot(target);
    }

    /**
     * @notice Compare current state with historical snapshot
     * @param target Contract address
     * @param snapshotIndex Index of historical snapshot
     * @return changed Whether state has changed
     * @return balanceDelta Balance difference
     */
    function compareState(
        address target,
        uint256 snapshotIndex
    ) external view returns (bool changed, int256 balanceDelta) {
        StateSnapshot[] storage history = stateHistory[target];
        if (snapshotIndex >= history.length) return (false, 0);

        StateSnapshot storage snapshot = history[snapshotIndex];
        bytes32 currentStateRoot = _getStateRoot(target);
        uint256 currentBalance = target.balance;

        changed = currentStateRoot != snapshot.stateRoot;
        balanceDelta = int256(currentBalance) - int256(snapshot.balance);
    }

    // ============================================
    // VIOLATION MANAGEMENT
    // ============================================

    /**
     * @notice Resolve a violation
     * @param violationId Violation ID
     */
    function resolveViolation(
        bytes32 violationId
    ) external onlyRole(GUARDIAN_ROLE) {
        violations[violationId].resolved = true;
        emit ViolationResolved(violationId, msg.sender);
    }

    /**
     * @notice Get recent violations for a contract
     * @param target Contract address
     * @param count Maximum number of violations to return
     * @return recentViolations Array of recent violation IDs
     */
    function getRecentViolations(
        address target,
        uint256 count
    ) external view returns (bytes32[] memory recentViolations) {
        uint256 totalViolations = allViolationIds.length;
        uint256 found = 0;
        recentViolations = new bytes32[](count);

        for (uint256 i = totalViolations; i > 0 && found < count; i--) {
            bytes32 vId = allViolationIds[i - 1];
            if (violations[vId].target == target) {
                recentViolations[found] = vId;
                found++;
            }
        }

        // Resize array
        assembly {
            mstore(recentViolations, found)
        }
    }

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    /**
     * @notice Get contract security score (0-100)
     * @param target Contract address
     * @return score Security score
     */
    function getSecurityScore(
        address target
    ) external view returns (uint256 score) {
        BytecodeAnalysis storage analysis = bytecodeAnalyses[target];
        MonitoredContract storage monitored = monitoredContracts[target];

        score = 100;

        // Deduct for suspicious patterns
        score -= (analysis.suspiciousPatterns > 50)
            ? 50
            : analysis.suspiciousPatterns;

        // Deduct for violations
        uint256 violationPenalty = monitored.violationCount * 5;
        score -= (violationPenalty > 30) ? 30 : violationPenalty;

        // Deduct for risk level
        if (analysis.riskLevel == ContractRiskLevel.HIGH_RISK) score -= 20;
        else if (analysis.riskLevel == ContractRiskLevel.MALICIOUS) score = 0;
    }

    /**
     * @notice Get all monitored contracts
     * @return contracts Array of monitored addresses
     */
    function getMonitoredContracts() external view returns (address[] memory) {
        return monitoredAddresses;
    }

    /**
     * @notice Get invariants for a contract
     * @param target Contract address
     * @return ids Array of invariant IDs
     */
    function getContractInvariants(
        address target
    ) external view returns (bytes32[] memory ids) {
        return monitoredContracts[target].invariantIds;
    }

    /**
     * @notice Get violation details
     * @param violationId Violation ID
     * @return Violation struct
     */
    function getViolation(
        bytes32 violationId
    ) external view returns (Violation memory) {
        return violations[violationId];
    }

    /**
     * @notice Get invariant details
     * @param invariantId Invariant ID
     * @return Invariant struct
     */
    function getInvariant(
        bytes32 invariantId
    ) external view returns (Invariant memory) {
        return invariants[invariantId];
    }

    /**
     * @notice Get state history count for a contract
     * @param target Contract address
     * @return count Number of snapshots
     */
    function getStateHistoryCount(
        address target
    ) external view returns (uint256) {
        return stateHistory[target].length;
    }

    // ============================================
    // ADMIN FUNCTIONS
    // ============================================

    /**
     * @notice Set circuit breaker address
     * @param _circuitBreaker New circuit breaker address
     */
    function setCircuitBreaker(
        address _circuitBreaker
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        address old = circuitBreaker;
        circuitBreaker = _circuitBreaker;
        emit CircuitBreakerUpdated(old, _circuitBreaker);
    }

    /**
     * @notice Toggle auto circuit breaker triggering
     * @param enabled Whether to enable auto triggering
     */
    function setAutoTriggerCircuitBreaker(
        bool enabled
    ) external onlyRole(GUARDIAN_ROLE) {
        autoTriggerCircuitBreaker = enabled;
    }

    /**
     * @notice Pause the monitor
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the monitor
     */
    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    // ============================================
    // INTERNAL FUNCTIONS
    // ============================================

    function _analyzeBytecode(
        address target
    ) internal view returns (BytecodeAnalysis memory analysis) {
        bytes memory code = target.code;
        bytes32 codeHash = keccak256(code);

        analysis.target = target;
        analysis.codeHash = codeHash;
        analysis.analyzedAt = block.timestamp;

        // Scan for suspicious opcodes
        for (uint256 i = 0; i < code.length; i++) {
            bytes1 op = code[i];

            if (op == _OP_SELFDESTRUCT) {
                analysis.hasSelfDestruct = true;
                analysis.suspiciousPatterns += 5;
            } else if (op == _OP_DELEGATECALL) {
                analysis.hasDelegateCall = true;
                analysis.suspiciousPatterns += 2;
            } else if (op == _OP_CREATE2) {
                analysis.hasCreate2 = true;
                analysis.suspiciousPatterns += 1;
            } else if (op == _OP_CALL) {
                analysis.hasExternalCalls = true;
            }
        }

        // Determine risk level
        if (analysis.suspiciousPatterns >= 10) {
            analysis.riskLevel = ContractRiskLevel.HIGH_RISK;
        } else if (analysis.suspiciousPatterns >= 5) {
            analysis.riskLevel = ContractRiskLevel.MEDIUM_RISK;
        } else if (analysis.suspiciousPatterns >= 2) {
            analysis.riskLevel = ContractRiskLevel.LOW_RISK;
        } else {
            analysis.riskLevel = ContractRiskLevel.SAFE;
        }
    }

    function _evaluateInvariant(
        Invariant storage inv
    ) internal view returns (bool violated, ViolationSeverity severity) {
        if (inv.invariantType == InvariantType.BALANCE_CONSERVATION) {
            uint256 expectedBalance = abi.decode(inv.checkData, (uint256));
            uint256 currentBalance = inv.target.balance;

            if (currentBalance < expectedBalance) {
                uint256 diff = expectedBalance - currentBalance;
                violated = diff > inv.threshold;
                severity = diff > 10 ether
                    ? ViolationSeverity.CRITICAL
                    : ViolationSeverity.HIGH;
            }
        } else if (inv.invariantType == InvariantType.STATE_CONSISTENCY) {
            bytes32 expectedRoot = abi.decode(inv.checkData, (bytes32));
            bytes32 currentRoot = _getStateRoot(inv.target);
            violated = currentRoot != expectedRoot;
            severity = ViolationSeverity.MEDIUM;
        } else if (inv.invariantType == InvariantType.TVL_BOUNDS) {
            (uint256 minTVL, uint256 maxTVL) = abi.decode(
                inv.checkData,
                (uint256, uint256)
            );
            uint256 currentTVL = inv.target.balance;
            violated = currentTVL < minTVL || currentTVL > maxTVL;
            severity = ViolationSeverity.HIGH;
        }
        // Add more invariant type checks as needed
    }

    function _recordViolation(
        bytes32 invariantId,
        address target,
        InvariantType invariantType,
        ViolationSeverity severity
    ) internal {
        // Check cooldown
        if (
            block.timestamp <
            lastViolationTime[target][invariantId] + VIOLATION_COOLDOWN
        ) {
            return;
        }

        bytes32 violationId = keccak256(
            abi.encodePacked(invariantId, target, block.timestamp, block.number)
        );

        violations[violationId] = Violation({
            invariantId: invariantId,
            target: target,
            invariantType: invariantType,
            severity: severity,
            dataHash: keccak256(abi.encodePacked(target, block.timestamp)),
            timestamp: block.timestamp,
            blockNumber: block.number,
            resolved: false
        });

        allViolationIds.push(violationId);
        invariants[invariantId].violationCount++;
        monitoredContracts[target].violationCount++;
        lastViolationTime[target][invariantId] = block.timestamp;

        emit InvariantViolation(
            violationId,
            invariantId,
            target,
            severity,
            abi.encodePacked(invariantType, block.timestamp)
        );

        // Auto-trigger circuit breaker for critical violations
        if (
            severity == ViolationSeverity.CRITICAL && autoTriggerCircuitBreaker
        ) {
            _handleCriticalViolation(violationId);
        }
    }

    function _handleCriticalViolation(bytes32 violationId) internal {
        // Reset window if expired
        if (block.timestamp > windowStart + 1 hours) {
            windowStart = block.timestamp;
            criticalViolationsInWindow = 0;
        }

        criticalViolationsInWindow++;

        if (
            criticalViolationsInWindow >= CRITICAL_VIOLATION_THRESHOLD &&
            circuitBreaker != address(0)
        ) {
            // Trigger circuit breaker
            (bool success, ) = circuitBreaker.call(
                abi.encodeWithSignature(
                    "triggerCircuitBreaker(string)",
                    "Multiple critical violations detected"
                )
            );

            if (success) {
                emit CircuitBreakerTriggered(
                    violationId,
                    "Multiple critical violations in window"
                );
            }
        }
    }

    function _takeStateSnapshot(address target) internal {
        bytes32 stateRoot = _getStateRoot(target);

        stateHistory[target].push(
            StateSnapshot({
                target: target,
                stateRoot: stateRoot,
                balance: target.balance,
                blockNumber: block.number,
                timestamp: block.timestamp
            })
        );

        emit StateSnapshotTaken(target, stateRoot, block.number);
    }

    function _getStateRoot(address target) internal view returns (bytes32) {
        // Simplified state root - in production, use proper Merkle tree
        return
            keccak256(
                abi.encodePacked(
                    target,
                    target.balance,
                    target.code.length,
                    block.number
                )
            );
    }
}
