// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title PQCGraduationManager
 * @author ZASEON
 * @notice Orchestrates PQC_SIGNATURES graduation through the
 *         ExperimentalFeatureRegistry pipeline: DISABLED → EXPERIMENTAL →
 *         BETA → PRODUCTION.
 *
 * ══════════════════════════════════════════════════════════════════════════
 *                          ARCHITECTURE
 * ══════════════════════════════════════════════════════════════════════════
 *
 * Phase 3 introduces a structured graduation manager that:
 *   1. Tracks graduation criteria for each stage transition
 *   2. Enforces minimum time-in-stage requirements
 *   3. Collects attestations (test passing, audit, monitoring)
 *   4. Manages risk limit escalation during graduation
 *   5. Provides a single entry point for the PQC graduation pipeline
 *
 * GRADUATION CRITERIA:
 *   DISABLED → EXPERIMENTAL:
 *     - Core contracts deployed ✓ (HybridPQCVerifier)
 *     - Basic test suite passing ✓ (Phase 1 tests)
 *     - Documentation complete ✓ (PQC Migration Guide)
 *
 *   EXPERIMENTAL → BETA:
 *     - Extended test suite (Phase 2 tests: stealth, bridge, ZK)
 *     - Shadow mode validation (no oracle mismatches)
 *     - 30-day minimum monitoring period
 *     - Peer review attestation
 *
 *   BETA → PRODUCTION:
 *     - Full test suite >99% pass rate
 *     - Third-party security audit attestation
 *     - 90-day minimum monitoring period
 *     - Zero critical incidents during beta
 *     - On-chain verification operational (precompile or ZK)
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract PQCGraduationManager is AccessControl, ReentrancyGuard {
    /*//////////////////////////////////////////////////////////////
                                ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant GRADUATION_ADMIN_ROLE =
        keccak256("GRADUATION_ADMIN_ROLE");
    bytes32 public constant ATTESTOR_ROLE = keccak256("ATTESTOR_ROLE");
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                             CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice PQC_SIGNATURES feature ID (matches ExperimentalFeatureRegistry)
    bytes32 public constant PQC_SIGNATURES = keccak256("PQC_SIGNATURES");

    /// @notice Minimum time in EXPERIMENTAL before advancing to BETA
    uint256 public constant MIN_EXPERIMENTAL_PERIOD = 30 days;

    /// @notice Minimum time in BETA before advancing to PRODUCTION
    uint256 public constant MIN_BETA_PERIOD = 90 days;

    /// @notice Risk limit escalation schedule (in ETH)
    uint256 public constant EXPERIMENTAL_RISK_LIMIT = 1 ether;
    uint256 public constant BETA_RISK_LIMIT = 100 ether;
    uint256 public constant PRODUCTION_RISK_LIMIT = 10_000 ether;

    /*//////////////////////////////////////////////////////////////
                                ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Feature status (mirrors ExperimentalFeatureRegistry)
    enum FeatureStatus {
        DISABLED,
        EXPERIMENTAL,
        BETA,
        PRODUCTION
    }

    /// @notice Attestation type
    enum AttestationType {
        TEST_SUITE_PASSING, // Automated test suite results
        SHADOW_MODE_CLEAN, // No oracle-onchain mismatches in shadow mode
        PEER_REVIEW, // Peer code review completed
        SECURITY_AUDIT, // Third-party security audit
        MONITORING_PERIOD, // Required monitoring period elapsed
        INCIDENT_FREE, // No critical incidents during stage
        ON_CHAIN_VERIFICATION, // On-chain verification operational
        FORMAL_VERIFICATION // Formal verification (Certora/Halmos) passed
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Graduation criteria for a stage transition
    struct GraduationCriteria {
        bool testSuitePassing;
        bool shadowModeClean;
        bool peerReview;
        bool securityAudit;
        bool monitoringPeriod;
        bool incidentFree;
        bool onChainVerification;
        bool formalVerification;
    }

    /// @notice Attestation record
    struct Attestation {
        AttestationType attestationType;
        address attestor;
        bytes32 evidenceHash; // Hash of evidence (e.g., test report hash)
        string description;
        uint256 timestamp;
        bool valid;
    }

    /// @notice Graduation stage record
    struct StageRecord {
        FeatureStatus status;
        uint256 enteredAt; // When this stage was entered
        uint256 exitedAt; // When this stage was exited (0 if current)
        GraduationCriteria criteria; // Criteria met for this stage
        uint256 attestationCount; // Number of attestations collected
        uint256 riskLimit; // Risk limit at this stage
    }

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice ExperimentalFeatureRegistry address
    address public featureRegistry;

    /// @notice HybridPQCVerifier address
    address public hybridPQCVerifier;

    /// @notice OnChainPQCVerifier address (Phase 3)
    address public onChainPQCVerifier;

    /// @notice Current PQC feature status
    FeatureStatus public currentStatus;

    /// @notice Stage records (indexed by FeatureStatus)
    mapping(FeatureStatus => StageRecord) public stageRecords;

    /// @notice Attestations per stage
    mapping(FeatureStatus => mapping(uint256 => Attestation))
        public attestations;

    /// @notice Attestation count per stage
    mapping(FeatureStatus => uint256) public attestationCounts;

    /// @notice Whether criteria is met per (stage, attestationType)
    mapping(FeatureStatus => mapping(AttestationType => bool))
        public criteriaStatus;

    /// @notice Total graduations completed
    uint256 public totalGraduations;

    /// @notice Total attestations submitted
    uint256 public totalAttestations;

    /// @notice Safety flag: halt graduations if critical issue found
    bool public graduationHalted;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event AttestationSubmitted(
        FeatureStatus indexed stage,
        AttestationType indexed attestationType,
        address indexed attestor,
        bytes32 evidenceHash,
        string description
    );

    event CriterionMet(FeatureStatus indexed stage, AttestationType criterion);

    event GraduationExecuted(
        FeatureStatus indexed fromStatus,
        FeatureStatus indexed toStatus,
        uint256 riskLimit,
        uint256 timestamp
    );

    event GraduationReadinessChecked(
        FeatureStatus indexed stage,
        bool ready,
        uint256 criteriaMet,
        uint256 criteriaRequired
    );

    event GraduationHalted(address indexed by, string reason);
    event GraduationResumed(address indexed by);

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error GraduationIsHalted();
    error InvalidStatusTransition(FeatureStatus from, FeatureStatus to);
    error CriteriaNotMet(FeatureStatus stage, string missing);
    error MinimumPeriodNotElapsed(uint256 required, uint256 elapsed);
    error RegistryCallFailed();
    error AlreadyInStage(FeatureStatus stage);
    error NotInExpectedStage(FeatureStatus expected, FeatureStatus actual);

    /*//////////////////////////////////////////////////////////////
                           CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address admin,
        address _featureRegistry,
        address _hybridPQCVerifier
    ) {
        if (admin == address(0)) revert ZeroAddress();
        if (_featureRegistry == address(0)) revert ZeroAddress();
        if (_hybridPQCVerifier == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GRADUATION_ADMIN_ROLE, admin);
        _grantRole(ATTESTOR_ROLE, admin);
        _grantRole(AUDITOR_ROLE, admin);

        featureRegistry = _featureRegistry;
        hybridPQCVerifier = _hybridPQCVerifier;
        currentStatus = FeatureStatus.DISABLED;

        // Initialize DISABLED stage record
        stageRecords[FeatureStatus.DISABLED] = StageRecord({
            status: FeatureStatus.DISABLED,
            enteredAt: block.timestamp,
            exitedAt: 0,
            criteria: GraduationCriteria(
                false,
                false,
                false,
                false,
                false,
                false,
                false,
                false
            ),
            attestationCount: 0,
            riskLimit: 0
        });
    }

    /*//////////////////////////////////////////////////////////////
                    ATTESTATION SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit an attestation for the current stage
     * @param attestationType Type of attestation
     * @param evidenceHash Hash of supporting evidence
     * @param description Human-readable description
     */
    function submitAttestation(
        AttestationType attestationType,
        bytes32 evidenceHash,
        string calldata description
    ) external onlyRole(ATTESTOR_ROLE) {
        FeatureStatus targetStage = _getNextStatus(currentStatus);

        uint256 idx = attestationCounts[targetStage];
        attestations[targetStage][idx] = Attestation({
            attestationType: attestationType,
            attestor: msg.sender,
            evidenceHash: evidenceHash,
            description: description,
            timestamp: block.timestamp,
            valid: true
        });

        attestationCounts[targetStage]++;
        totalAttestations++;

        // Update criteria tracking
        criteriaStatus[targetStage][attestationType] = true;

        emit AttestationSubmitted(
            targetStage,
            attestationType,
            msg.sender,
            evidenceHash,
            description
        );

        emit CriterionMet(targetStage, attestationType);
    }

    /**
     * @notice Submit an audit attestation (requires AUDITOR_ROLE)
     */
    function submitAuditAttestation(
        bytes32 auditReportHash,
        string calldata auditorName
    ) external onlyRole(AUDITOR_ROLE) {
        FeatureStatus targetStage = _getNextStatus(currentStatus);

        uint256 idx = attestationCounts[targetStage];
        attestations[targetStage][idx] = Attestation({
            attestationType: AttestationType.SECURITY_AUDIT,
            attestor: msg.sender,
            evidenceHash: auditReportHash,
            description: auditorName,
            timestamp: block.timestamp,
            valid: true
        });

        attestationCounts[targetStage]++;
        totalAttestations++;

        criteriaStatus[targetStage][AttestationType.SECURITY_AUDIT] = true;

        emit AttestationSubmitted(
            targetStage,
            AttestationType.SECURITY_AUDIT,
            msg.sender,
            auditReportHash,
            auditorName
        );

        emit CriterionMet(targetStage, AttestationType.SECURITY_AUDIT);
    }

    /*//////////////////////////////////////////////////////////////
                    GRADUATION EXECUTION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Execute graduation to EXPERIMENTAL
     */
    function graduateToExperimental()
        external
        onlyRole(GRADUATION_ADMIN_ROLE)
        nonReentrant
    {
        if (graduationHalted) revert GraduationIsHalted();
        if (currentStatus != FeatureStatus.DISABLED)
            revert NotInExpectedStage(FeatureStatus.DISABLED, currentStatus);

        // Check criteria for EXPERIMENTAL
        FeatureStatus target = FeatureStatus.EXPERIMENTAL;
        if (!criteriaStatus[target][AttestationType.TEST_SUITE_PASSING])
            revert CriteriaNotMet(target, "TEST_SUITE_PASSING");

        _executeGraduation(
            FeatureStatus.DISABLED,
            FeatureStatus.EXPERIMENTAL,
            EXPERIMENTAL_RISK_LIMIT
        );
    }

    /**
     * @notice Execute graduation to BETA
     */
    function graduateToBeta()
        external
        onlyRole(GRADUATION_ADMIN_ROLE)
        nonReentrant
    {
        if (graduationHalted) revert GraduationIsHalted();
        if (currentStatus != FeatureStatus.EXPERIMENTAL)
            revert NotInExpectedStage(
                FeatureStatus.EXPERIMENTAL,
                currentStatus
            );

        // Check time requirement
        uint256 elapsed = block.timestamp -
            stageRecords[FeatureStatus.EXPERIMENTAL].enteredAt;
        if (elapsed < MIN_EXPERIMENTAL_PERIOD)
            revert MinimumPeriodNotElapsed(MIN_EXPERIMENTAL_PERIOD, elapsed);

        // Check criteria for BETA
        FeatureStatus target = FeatureStatus.BETA;
        if (!criteriaStatus[target][AttestationType.TEST_SUITE_PASSING])
            revert CriteriaNotMet(target, "TEST_SUITE_PASSING");
        if (!criteriaStatus[target][AttestationType.SHADOW_MODE_CLEAN])
            revert CriteriaNotMet(target, "SHADOW_MODE_CLEAN");
        if (!criteriaStatus[target][AttestationType.PEER_REVIEW])
            revert CriteriaNotMet(target, "PEER_REVIEW");

        _executeGraduation(
            FeatureStatus.EXPERIMENTAL,
            FeatureStatus.BETA,
            BETA_RISK_LIMIT
        );
    }

    /**
     * @notice Execute graduation to PRODUCTION
     */
    function graduateToProduction()
        external
        onlyRole(GRADUATION_ADMIN_ROLE)
        nonReentrant
    {
        if (graduationHalted) revert GraduationIsHalted();
        if (currentStatus != FeatureStatus.BETA)
            revert NotInExpectedStage(FeatureStatus.BETA, currentStatus);

        // Check time requirement
        uint256 elapsed = block.timestamp -
            stageRecords[FeatureStatus.BETA].enteredAt;
        if (elapsed < MIN_BETA_PERIOD)
            revert MinimumPeriodNotElapsed(MIN_BETA_PERIOD, elapsed);

        // Check criteria for PRODUCTION
        FeatureStatus target = FeatureStatus.PRODUCTION;
        if (!criteriaStatus[target][AttestationType.TEST_SUITE_PASSING])
            revert CriteriaNotMet(target, "TEST_SUITE_PASSING");
        if (!criteriaStatus[target][AttestationType.SECURITY_AUDIT])
            revert CriteriaNotMet(target, "SECURITY_AUDIT");
        if (!criteriaStatus[target][AttestationType.INCIDENT_FREE])
            revert CriteriaNotMet(target, "INCIDENT_FREE");
        if (!criteriaStatus[target][AttestationType.ON_CHAIN_VERIFICATION])
            revert CriteriaNotMet(target, "ON_CHAIN_VERIFICATION");

        _executeGraduation(
            FeatureStatus.BETA,
            FeatureStatus.PRODUCTION,
            PRODUCTION_RISK_LIMIT
        );
    }

    /*//////////////////////////////////////////////////////////////
                     EMERGENCY CONTROLS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Halt all graduations (emergency)
     */
    function haltGraduation(
        string calldata reason
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        graduationHalted = true;
        emit GraduationHalted(msg.sender, reason);
    }

    /**
     * @notice Resume graduations
     */
    function resumeGraduation() external onlyRole(DEFAULT_ADMIN_ROLE) {
        graduationHalted = false;
        emit GraduationResumed(msg.sender);
    }

    /**
     * @notice Set OnChainPQCVerifier address
     */
    function setOnChainPQCVerifier(
        address newAddr
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newAddr == address(0)) revert ZeroAddress();
        onChainPQCVerifier = newAddr;
    }

    /*//////////////////////////////////////////////////////////////
                         VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check if graduation to the next stage is ready
     */
    function isGraduationReady()
        external
        view
        returns (bool ready, uint256 criteriaMet, uint256 criteriaRequired)
    {
        FeatureStatus nextStatus = _getNextStatus(currentStatus);

        if (nextStatus == FeatureStatus.EXPERIMENTAL) {
            criteriaRequired = 1;
            if (criteriaStatus[nextStatus][AttestationType.TEST_SUITE_PASSING])
                criteriaMet++;
        } else if (nextStatus == FeatureStatus.BETA) {
            criteriaRequired = 3;
            if (criteriaStatus[nextStatus][AttestationType.TEST_SUITE_PASSING])
                criteriaMet++;
            if (criteriaStatus[nextStatus][AttestationType.SHADOW_MODE_CLEAN])
                criteriaMet++;
            if (criteriaStatus[nextStatus][AttestationType.PEER_REVIEW])
                criteriaMet++;

            // Also check time requirement
            if (
                block.timestamp -
                    stageRecords[FeatureStatus.EXPERIMENTAL].enteredAt <
                MIN_EXPERIMENTAL_PERIOD
            ) {
                criteriaMet = 0; // Time not met
            }
        } else if (nextStatus == FeatureStatus.PRODUCTION) {
            criteriaRequired = 4;
            if (criteriaStatus[nextStatus][AttestationType.TEST_SUITE_PASSING])
                criteriaMet++;
            if (criteriaStatus[nextStatus][AttestationType.SECURITY_AUDIT])
                criteriaMet++;
            if (criteriaStatus[nextStatus][AttestationType.INCIDENT_FREE])
                criteriaMet++;
            if (
                criteriaStatus[nextStatus][
                    AttestationType.ON_CHAIN_VERIFICATION
                ]
            ) criteriaMet++;

            if (
                block.timestamp - stageRecords[FeatureStatus.BETA].enteredAt <
                MIN_BETA_PERIOD
            ) {
                criteriaMet = 0;
            }
        }

        ready = (criteriaMet >= criteriaRequired) && !graduationHalted;
    }

    /**
     * @notice Get graduation status summary
     */
    function getGraduationSummary()
        external
        view
        returns (
            FeatureStatus status,
            uint256 timeInCurrentStage,
            uint256 totalGraduationsDone,
            uint256 totalAttestationsReceived,
            bool halted
        )
    {
        status = currentStatus;
        timeInCurrentStage =
            block.timestamp -
            stageRecords[currentStatus].enteredAt;
        totalGraduationsDone = totalGraduations;
        totalAttestationsReceived = totalAttestations;
        halted = graduationHalted;
    }

    /**
     * @notice Get attestation details for a stage
     */
    function getAttestation(
        FeatureStatus stage,
        uint256 index
    ) external view returns (Attestation memory) {
        return attestations[stage][index];
    }

    /*//////////////////////////////////////////////////////////////
                       INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _executeGraduation(
        FeatureStatus from,
        FeatureStatus to,
        uint256 newRiskLimit
    ) internal {
        // Close current stage
        stageRecords[from].exitedAt = block.timestamp;

        // Open new stage
        stageRecords[to] = StageRecord({
            status: to,
            enteredAt: block.timestamp,
            exitedAt: 0,
            criteria: GraduationCriteria(
                false,
                false,
                false,
                false,
                false,
                false,
                false,
                false
            ),
            attestationCount: 0,
            riskLimit: newRiskLimit
        });

        currentStatus = to;
        totalGraduations++;

        // Update feature registry
        _updateFeatureRegistry(to, newRiskLimit);

        emit GraduationExecuted(from, to, newRiskLimit, block.timestamp);
    }

    function _updateFeatureRegistry(
        FeatureStatus newStatus,
        uint256 newRiskLimit
    ) internal {
        // Map FeatureStatus to ExperimentalFeatureRegistry.FeatureStatus enum value
        // DISABLED=0, EXPERIMENTAL=1, BETA=2, PRODUCTION=3
        uint8 registryStatus = uint8(newStatus);

        // Update status
        (bool success, ) = featureRegistry.call(
            abi.encodeWithSignature(
                "updateFeatureStatus(bytes32,uint8)",
                PQC_SIGNATURES,
                registryStatus
            )
        );
        if (!success) revert RegistryCallFailed();

        // Update risk limit
        (success, ) = featureRegistry.call(
            abi.encodeWithSignature(
                "updateRiskLimit(bytes32,uint256)",
                PQC_SIGNATURES,
                newRiskLimit
            )
        );
        // Risk limit update is best-effort
    }

    function _getNextStatus(
        FeatureStatus current
    ) internal pure returns (FeatureStatus) {
        if (current == FeatureStatus.DISABLED)
            return FeatureStatus.EXPERIMENTAL;
        if (current == FeatureStatus.EXPERIMENTAL) return FeatureStatus.BETA;
        if (current == FeatureStatus.BETA) return FeatureStatus.PRODUCTION;
        return FeatureStatus.PRODUCTION; // Already at max
    }
}
