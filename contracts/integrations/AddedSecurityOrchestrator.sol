// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title AddedSecurityOrchestrator
 * @notice Lightweight orchestrator for added security modules
 * @dev Coordinates alerts and tracks protected contracts without tight coupling
 *
 * This contract provides:
 * - Centralized alert management
 * - Protected contract registry
 * - Security score tracking
 * - Integration points for external monitoring
 *
 * Integrated modules (referenced by address):
 * - RuntimeSecurityMonitor
 * - EmergencyResponseAutomation
 * - ZKFraudProof
 * - ThresholdSignature
 * - CryptographicAttestation
 * - FormalBugBounty
 */
contract AddedSecurityOrchestrator is AccessControl, ReentrancyGuard, Pausable {
    error ZeroAddress();
    error AlreadyProtected();
    error InvalidRiskLevel();
    error NotProtected();
    error InvalidAlertId();
    error AlreadyResolved();

    // ============================================
    // ROLES
    // ============================================

    bytes32 public constant ORCHESTRATOR_ROLE = keccak256("ORCHESTRATOR_ROLE");
    bytes32 public constant MONITOR_ROLE = keccak256("MONITOR_ROLE");

    // ============================================
    // MODULE ADDRESSES
    // ============================================

    /// @notice Address of RuntimeSecurityMonitor
    address public runtimeMonitor;

    /// @notice Address of EmergencyResponseAutomation
    address public emergencyResponse;

    /// @notice Address of ZKFraudProof
    address public zkFraudProof;

    /// @notice Address of ThresholdSignature
    address public thresholdSignature;

    /// @notice Address of CryptographicAttestation
    address public cryptoAttestation;

    /// @notice Address of FormalBugBounty
    address public bugBounty;

    /// @notice Circuit breaker for bridges
    address public circuitBreaker;

    /// @notice Rate limiter for bridges
    address public rateLimiter;

    /// @notice MEV protection module
    address public mevProtection;

    /// @notice Flash loan guard
    address public flashLoanGuard;

    // ============================================
    // SECURITY THRESHOLDS
    // ============================================

    struct SecurityThresholds {
        uint256 monitorScoreThreshold; // Below this triggers alert
        uint256 attestationValidityPeriod; // How long attestations are valid
        uint256 signatureThreshold; // Required threshold signatures
        uint256 fraudProofWindow; // Time window for fraud proofs
        uint256 escalationDelay; // Time before auto-escalation
    }

    SecurityThresholds public thresholds;

    // ============================================
    // PROTECTED CONTRACTS
    // ============================================

    /// @notice Protected contract info
    struct ProtectedContract {
        address target;
        uint8 riskLevel;
        uint256 securityScore;
        uint256 lastCheck;
        bool active;
    }

    /// @notice All protected contracts
    mapping(address => ProtectedContract) public protectedContracts;

    /// @notice List of protected addresses
    address[] public protectedAddresses;

    // ============================================
    // ALERTS
    // ============================================

    /// @notice Alert severity levels
    enum AlertSeverity {
        INFORMATIONAL,
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    /// @notice Active security alerts
    struct SecurityAlert {
        uint256 id;
        address target;
        AlertSeverity severity;
        string description;
        uint256 timestamp;
        bool resolved;
        address resolvedBy;
        uint256 resolvedAt;
    }

    /// @notice All alerts
    SecurityAlert[] public alerts;

    /// @notice Contract to alerts mapping
    mapping(address => uint256[]) public contractAlerts;

    /// @notice Critical ops threshold signature group
    uint256 public criticalOpsGroupId;

    // ============================================
    // EVENTS
    // ============================================

    event ModuleConfigured(string indexed moduleName, address moduleAddress);
    event ContractProtected(address indexed target, uint8 riskLevel);
    event ContractUnprotected(address indexed target);
    event SecurityScoreUpdated(
        address indexed target,
        uint256 oldScore,
        uint256 newScore
    );
    event AlertCreated(
        uint256 indexed alertId,
        address indexed target,
        AlertSeverity severity,
        string description
    );
    event AlertResolved(uint256 indexed alertId, address indexed resolver);
    event ThresholdsUpdated(SecurityThresholds newThresholds);
    event AutoResponseTriggered(address indexed target, uint8 responseType);

    // ============================================
    // CONSTRUCTOR
    // ============================================

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ORCHESTRATOR_ROLE, msg.sender);
        _grantRole(MONITOR_ROLE, msg.sender);

        // Set default thresholds
        thresholds = SecurityThresholds({
            monitorScoreThreshold: 70, // Alert if score < 70
            attestationValidityPeriod: 1 days,
            signatureThreshold: 2, // 2-of-n for critical ops
            fraudProofWindow: 7 days,
            escalationDelay: 1 hours
        });
    }

    // ============================================
    // MODULE CONFIGURATION
    // ============================================

    /**
     * @notice Configure RuntimeSecurityMonitor address
     */
    function setRuntimeMonitor(
        address _runtimeMonitor
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        runtimeMonitor = _runtimeMonitor;
        emit ModuleConfigured("RuntimeSecurityMonitor", _runtimeMonitor);
    }

    /**
     * @notice Configure EmergencyResponseAutomation address
     */
    function setEmergencyResponse(
        address _emergencyResponse
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        emergencyResponse = _emergencyResponse;
        emit ModuleConfigured(
            "EmergencyResponseAutomation",
            _emergencyResponse
        );
    }

    /**
     * @notice Configure ZKFraudProof address
     */
    function setZKFraudProof(
        address _zkFraudProof
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        zkFraudProof = _zkFraudProof;
        emit ModuleConfigured("ZKFraudProof", _zkFraudProof);
    }

    /**
     * @notice Configure ThresholdSignature address
     */
    function setThresholdSignature(
        address _thresholdSignature
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        thresholdSignature = _thresholdSignature;
        emit ModuleConfigured("ThresholdSignature", _thresholdSignature);
    }

    /**
     * @notice Configure CryptographicAttestation address
     */
    function setCryptoAttestation(
        address _cryptoAttestation
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        cryptoAttestation = _cryptoAttestation;
        emit ModuleConfigured("CryptographicAttestation", _cryptoAttestation);
    }

    /**
     * @notice Configure FormalBugBounty address
     */
    function setBugBounty(
        address _bugBounty
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        bugBounty = _bugBounty;
        emit ModuleConfigured("FormalBugBounty", _bugBounty);
    }

    /**
     * @notice Configure circuit breaker
     */
    function setCircuitBreaker(
        address _circuitBreaker
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        circuitBreaker = _circuitBreaker;
        emit ModuleConfigured("CircuitBreaker", _circuitBreaker);
    }

    /**
     * @notice Configure rate limiter
     */
    function setRateLimiter(
        address _rateLimiter
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        rateLimiter = _rateLimiter;
        emit ModuleConfigured("RateLimiter", _rateLimiter);
    }

    /**
     * @notice Configure MEV protection
     */
    function setMEVProtection(
        address _mevProtection
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        mevProtection = _mevProtection;
        emit ModuleConfigured("MEVProtection", _mevProtection);
    }

    /**
     * @notice Configure flash loan guard
     */
    function setFlashLoanGuard(
        address _flashLoanGuard
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        flashLoanGuard = _flashLoanGuard;
        emit ModuleConfigured("FlashLoanGuard", _flashLoanGuard);
    }

    // ============================================
    // PROTECTION MANAGEMENT
    // ============================================

    /**
     * @notice Add a contract to protection registry
     * @param target Contract to protect
     * @param riskLevel Risk level (0-4)
     */
    function protectContract(
        address target,
        uint8 riskLevel
    ) external onlyRole(ORCHESTRATOR_ROLE) {
        if (target == address(0)) revert ZeroAddress();
        if (protectedContracts[target].active) revert AlreadyProtected();
        if (riskLevel > 4) revert InvalidRiskLevel();

        protectedContracts[target] = ProtectedContract({
            target: target,
            riskLevel: riskLevel,
            securityScore: 100,
            lastCheck: block.timestamp,
            active: true
        });

        protectedAddresses.push(target);

        emit ContractProtected(target, riskLevel);
    }

    /**
     * @notice Remove a contract from protection
     * @param target Contract to unprotect
     */
    function unprotectContract(
        address target
    ) external onlyRole(ORCHESTRATOR_ROLE) {
        if (!protectedContracts[target].active) revert NotProtected();

        protectedContracts[target].active = false;

        emit ContractUnprotected(target);
    }

    /**
     * @notice Update security score for a protected contract
     * @param target Contract address
     * @param newScore New security score
     */
    function updateSecurityScore(
        address target,
        uint256 newScore
    ) external onlyRole(MONITOR_ROLE) {
        if (!protectedContracts[target].active) revert NotProtected();

        uint256 oldScore = protectedContracts[target].securityScore;
        protectedContracts[target].securityScore = newScore;
        protectedContracts[target].lastCheck = block.timestamp;

        emit SecurityScoreUpdated(target, oldScore, newScore);

        // Auto-create alert if score below threshold
        if (newScore < thresholds.monitorScoreThreshold) {
            _createAlert(
                target,
                AlertSeverity.HIGH,
                "Security score below threshold"
            );
        }
    }

    // ============================================
    // ALERT MANAGEMENT
    // ============================================

    /**
     * @notice Create a security alert
     * @param target Affected contract
     * @param severity Alert severity
     * @param description Alert description
     */
    function createAlert(
        address target,
        AlertSeverity severity,
        string calldata description
    ) external onlyRole(MONITOR_ROLE) returns (uint256 alertId) {
        return _createAlert(target, severity, description);
    }

    function _createAlert(
        address target,
        AlertSeverity severity,
        string memory description
    ) internal returns (uint256 alertId) {
        alertId = alerts.length;

        alerts.push(
            SecurityAlert({
                id: alertId,
                target: target,
                severity: severity,
                description: description,
                timestamp: block.timestamp,
                resolved: false,
                resolvedBy: address(0),
                resolvedAt: 0
            })
        );

        contractAlerts[target].push(alertId);

        emit AlertCreated(alertId, target, severity, description);

        // Critical alerts trigger auto-response
        if (severity == AlertSeverity.CRITICAL) {
            emit AutoResponseTriggered(target, 1); // Signal for external automation
        }
    }

    /**
     * @notice Resolve a security alert
     * @param alertId Alert to resolve
     */
    function resolveAlert(
        uint256 alertId
    ) external onlyRole(ORCHESTRATOR_ROLE) {
        if (alertId >= alerts.length) revert InvalidAlertId();
        if (alerts[alertId].resolved) revert AlreadyResolved();

        alerts[alertId].resolved = true;
        alerts[alertId].resolvedBy = msg.sender;
        alerts[alertId].resolvedAt = block.timestamp;

        emit AlertResolved(alertId, msg.sender);
    }

    // ============================================
    // THRESHOLD CONFIGURATION
    // ============================================

    /**
     * @notice Set critical operations threshold signature group
     * @param groupId Threshold signature group ID
     */
    function setCriticalOpsGroup(
        uint256 groupId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        criticalOpsGroupId = groupId;
    }

    /**
     * @notice Update security thresholds
     * @param _thresholds New thresholds
     */
    function updateThresholds(
        SecurityThresholds calldata _thresholds
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        thresholds = _thresholds;
        emit ThresholdsUpdated(_thresholds);
    }

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    /**
     * @notice Get all configured module addresses
     */
    function getModuleAddresses()
        external
        view
        returns (
            address _runtimeMonitor,
            address _emergencyResponse,
            address _zkFraudProof,
            address _thresholdSignature,
            address _cryptoAttestation,
            address _bugBounty
        )
    {
        return (
            runtimeMonitor,
            emergencyResponse,
            zkFraudProof,
            thresholdSignature,
            cryptoAttestation,
            bugBounty
        );
    }

    /**
     * @notice Get all protected contract addresses
     */
    function getProtectedAddresses() external view returns (address[] memory) {
        return protectedAddresses;
    }

    /**
     * @notice Get active protected contract count
     */
    function getActiveProtectedCount() external view returns (uint256 count) {
        for (uint256 i = 0; i < protectedAddresses.length; i++) {
            if (protectedContracts[protectedAddresses[i]].active) {
                count++;
            }
        }
    }

    /**
     * @notice Get alert details
     */
    function getAlert(
        uint256 alertId
    ) external view returns (SecurityAlert memory) {
        if (alertId >= alerts.length) revert InvalidAlertId();
        return alerts[alertId];
    }

    /**
     * @notice Get total alert count
     */
    function getAlertCount() external view returns (uint256) {
        return alerts.length;
    }

    /**
     * @notice Get unresolved alert count
     */
    function getUnresolvedAlertCount() external view returns (uint256 count) {
        for (uint256 i = 0; i < alerts.length; i++) {
            if (!alerts[i].resolved) {
                count++;
            }
        }
    }

    /**
     * @notice Get alerts for a specific contract
     */
    function getContractAlerts(
        address target
    ) external view returns (uint256[] memory) {
        return contractAlerts[target];
    }

    /**
     * @notice Get security posture summary
     */
    function getSecurityPosture()
        external
        view
        returns (
            uint256 protectedCount,
            uint256 totalAlerts,
            uint256 unresolvedAlerts,
            uint256 criticalAlerts,
            uint256 avgScore
        )
    {
        // Protected count
        for (uint256 i = 0; i < protectedAddresses.length; i++) {
            if (protectedContracts[protectedAddresses[i]].active) {
                protectedCount++;
                avgScore += protectedContracts[protectedAddresses[i]]
                    .securityScore;
            }
        }
        if (protectedCount > 0) {
            avgScore = avgScore / protectedCount;
        }

        // Alert counts
        totalAlerts = alerts.length;
        for (uint256 i = 0; i < alerts.length; i++) {
            if (!alerts[i].resolved) {
                unresolvedAlerts++;
                if (alerts[i].severity == AlertSeverity.CRITICAL) {
                    criticalAlerts++;
                }
            }
        }
    }

    /**
     * @notice Check if all added security modules are configured
     */
    function isFullyConfigured() external view returns (bool) {
        return
            runtimeMonitor != address(0) &&
            emergencyResponse != address(0) &&
            zkFraudProof != address(0) &&
            thresholdSignature != address(0) &&
            cryptoAttestation != address(0) &&
            bugBounty != address(0);
    }

    // ============================================
    // EMERGENCY CONTROLS
    // ============================================

    /**
     * @notice Pause the orchestrator
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the orchestrator
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
