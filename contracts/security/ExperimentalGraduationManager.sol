// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title IExperimentalFeatureRegistry
 * @notice Minimal interface for the ExperimentalFeatureRegistry used by the
 *         graduation manager.
 */
interface IExperimentalFeatureRegistry {
    enum FeatureStatus {
        DISABLED,
        EXPERIMENTAL,
        BETA,
        PRODUCTION
    }

        /**
     * @notice Features
     * @param featureId The featureId identifier
     * @return name The name
     * @return status The status
     * @return implementation The implementation
     * @return maxValueLocked The max value locked
     * @return currentValueLocked The current value locked
     * @return requiresWarning The requires warning
     * @return documentationUrl The documentation url
     * @return createdAt The created at
     * @return lastStatusChange The last status change
     */
function features(
        bytes32 featureId
    )
        external
        view
        returns (
            string memory name,
            FeatureStatus status,
            address implementation,
            uint256 maxValueLocked,
            uint256 currentValueLocked,
            bool requiresWarning,
            string memory documentationUrl,
            uint256 createdAt,
            uint256 lastStatusChange
        );

        /**
     * @notice Updates feature status
     * @param featureId The featureId identifier
     * @param newStatus The new Status value
     */
function updateFeatureStatus(
        bytes32 featureId,
        FeatureStatus newStatus
    ) external;
}

/**
 * @title ExperimentalGraduationManager
 * @author ZASEON
 * @notice Formalises the graduation lifecycle for experimental features.
 *         Enforces on-chain criteria (audit attestation, test-coverage attestation,
 *         minimum time-in-beta, security-review sign-off) before a feature can
 *         transition from BETA → PRODUCTION.
 *
 * @dev Architecture:
 *      - A GraduationCriteria struct defines per-feature requirements.
 *      - Authorised attesters (CI bots, auditors, security reviewers) submit
 *        attestations that are recorded on-chain.
 *      - A proposer calls `proposeGraduation` when all criteria are met.
 *      - After a configurable timelock, an executor calls `executeGraduation`
 *        which transitions the feature to PRODUCTION in the registry.
 *      - Emergency cancellation is always available.
 *      - Demotion path: PRODUCTION → BETA with recorded reason.
 *
 *      Roles:
 *      - DEFAULT_ADMIN_ROLE: Full control, set criteria, manage roles
 *      - PROPOSER_ROLE: Propose graduations
 *      - EXECUTOR_ROLE: Execute after timelock
 *      - AUDITOR_ROLE: Attest audit completion
 *      - CI_ROLE: Attest test coverage / fuzz results
 *      - SECURITY_ROLE: Attest security review
 *
 *      Invariants:
 *      - Cannot execute graduation before timelock expires
 *      - All criteria must be met before proposal
 *      - Attestation timestamps must be after feature entered BETA
 *      - Only one active proposal per feature at a time
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract ExperimentalGraduationManager is AccessControl, ReentrancyGuard {
    /*//////////////////////////////////////////////////////////////
                             CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");
    bytes32 public constant CI_ROLE = keccak256("CI_ROLE");
    bytes32 public constant SECURITY_ROLE = keccak256("SECURITY_ROLE");

    /// @notice Default graduation timelock (3 days)
    uint48 public constant DEFAULT_TIMELOCK = 3 days;

    /// @notice Minimum timelock (1 hour — for testing)
    uint48 public constant MIN_TIMELOCK = 1 hours;

    /// @notice Maximum timelock (30 days)
    uint48 public constant MAX_TIMELOCK = 30 days;

    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum ProposalStatus {
        NONE,
        PENDING,
        EXECUTED,
        CANCELLED
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Graduation criteria for a feature
    struct GraduationCriteria {
        uint48 minTimeInBeta; // Minimum seconds in BETA before graduation
        uint32 minTestCount; // Minimum unit + integration test count
        uint32 minFuzzRuns; // Minimum fuzz runs per test
        bool requiresAuditAttestation; // Must be signed off by auditor
        bool requiresSecurityReview; // Must be reviewed by security team
        bool requiresCertoraSpec; // Must have formal verification spec
    }

    /// @notice Attestation record
    struct Attestation {
        address attester; // Who attested
        uint48 attestedAt; // When
        bytes32 evidenceHash; // Hash of evidence (report hash, CI log hash, etc.)
    }

    /// @notice Graduation proposal
    struct GraduationProposal {
        bytes32 featureId;
        ProposalStatus status;
        address proposer;
        uint48 proposedAt;
        uint48 executableAfter; // Timelock expiry timestamp
    }

    /// @notice Feature graduation state (attestations + metadata)
    struct FeatureGraduation {
        Attestation auditAttestation;
        Attestation testAttestation;
        Attestation securityAttestation;
        Attestation certoraAttestation;
        uint32 reportedTestCount;
        uint32 reportedFuzzRuns;
        uint48 betaEntryTimestamp; // When feature entered BETA
        uint48 graduatedAt; // When graduated to PRODUCTION (0 if never)
        uint48 demotedAt; // Last demotion timestamp (0 if never)
        string demotionReason; // Reason for last demotion
        uint16 graduationCount; // Times graduated
        uint16 demotionCount; // Times demoted
    }

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event CriteriaSet(bytes32 indexed featureId, GraduationCriteria criteria);
    event BetaEntryRecorded(bytes32 indexed featureId, uint48 timestamp);
    event AuditAttested(
        bytes32 indexed featureId,
        address indexed auditor,
        bytes32 evidenceHash
    );
    event TestCoverageAttested(
        bytes32 indexed featureId,
        address indexed ci,
        uint32 testCount,
        uint32 fuzzRuns
    );
    event SecurityReviewAttested(
        bytes32 indexed featureId,
        address indexed reviewer,
        bytes32 evidenceHash
    );
    event CertoraSpecAttested(
        bytes32 indexed featureId,
        address indexed attester,
        bytes32 specHash
    );
    event GraduationProposed(
        bytes32 indexed featureId,
        uint256 indexed proposalId,
        uint48 executableAfter
    );
    event GraduationExecuted(
        bytes32 indexed featureId,
        uint256 indexed proposalId
    );
    event GraduationCancelled(
        bytes32 indexed featureId,
        uint256 indexed proposalId,
        string reason
    );
    event FeatureDemoted(bytes32 indexed featureId, string reason);
    event TimelockUpdated(uint48 oldTimelock, uint48 newTimelock);

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error FeatureNotInBeta(bytes32 featureId);
    error FeatureNotInProduction(bytes32 featureId);
    error CriteriaNotSet(bytes32 featureId);
    error CriteriaNotMet(bytes32 featureId, string reason);
    error ProposalAlreadyActive(bytes32 featureId);
    error NoActiveProposal(bytes32 featureId);
    error TimelockNotExpired(uint48 executableAfter);
    error ProposalNotPending(uint256 proposalId);
    error InvalidTimelockDuration();
    error AttestationTooOld(bytes32 featureId);

    /*//////////////////////////////////////////////////////////////
                              STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice The ExperimentalFeatureRegistry this manager controls
    IExperimentalFeatureRegistry public immutable registry;

    /// @notice Graduation timelock duration
    uint48 public timelockDuration;

    /// @notice Feature ID → graduation criteria
    mapping(bytes32 => GraduationCriteria) public criteria;

    /// @notice Feature ID → graduation state
    mapping(bytes32 => FeatureGraduation) internal _graduations;

    /// @notice Proposal counter
    uint256 public proposalCount;

    /// @notice Proposal ID → proposal
    mapping(uint256 => GraduationProposal) public proposals;

    /// @notice Feature ID → active proposal ID (0 if none)
    mapping(bytes32 => uint256) public activeProposal;

    /// @notice Feature ID → whether criteria have been set
    mapping(bytes32 => bool) public criteriaConfigured;

    /*//////////////////////////////////////////////////////////////
                           CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _registry, address admin) {
        if (_registry == address(0) || admin == address(0))
            revert ZeroAddress();

        registry = IExperimentalFeatureRegistry(_registry);

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PROPOSER_ROLE, admin);
        _grantRole(EXECUTOR_ROLE, admin);

        timelockDuration = DEFAULT_TIMELOCK;
    }

    /*//////////////////////////////////////////////////////////////
                       CRITERIA MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set graduation criteria for a feature
     * @param featureId The feature ID
     * @param _criteria The graduation requirements
     */
    function setCriteria(
        bytes32 featureId,
        GraduationCriteria calldata _criteria
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        criteria[featureId] = _criteria;
        criteriaConfigured[featureId] = true;
        emit CriteriaSet(featureId, _criteria);
    }

    /*//////////////////////////////////////////////////////////////
                       BETA ENTRY RECORDING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Record when a feature enters BETA status
     * @dev Should be called when the registry transitions a feature to BETA.
     *      Can also be called retrospectively by admin.
     * @param featureId The feature ID
     */
    function recordBetaEntry(
        bytes32 featureId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _graduations[featureId].betaEntryTimestamp = uint48(block.timestamp);
        emit BetaEntryRecorded(featureId, uint48(block.timestamp));
    }

    /*//////////////////////////////////////////////////////////////
                         ATTESTATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Attest that an audit has been completed for a feature
     * @param featureId The feature being attested
     * @param reportHash Hash of the audit report (IPFS CID, etc.)
     */
    function attestAudit(
        bytes32 featureId,
        bytes32 reportHash
    ) external onlyRole(AUDITOR_ROLE) {
        FeatureGraduation storage grad = _graduations[featureId];

        grad.auditAttestation = Attestation({
            attester: msg.sender,
            attestedAt: uint48(block.timestamp),
            evidenceHash: reportHash
        });

        emit AuditAttested(featureId, msg.sender, reportHash);
    }

    /**
     * @notice Attest test coverage metrics
     * @param featureId The feature being attested
     * @param testCount Number of passing tests
     * @param fuzzRuns Number of fuzz runs per fuzz test
     * @param evidenceHash Hash of CI output / test logs
     */
    function attestTestCoverage(
        bytes32 featureId,
        uint32 testCount,
        uint32 fuzzRuns,
        bytes32 evidenceHash
    ) external onlyRole(CI_ROLE) {
        FeatureGraduation storage grad = _graduations[featureId];

        grad.testAttestation = Attestation({
            attester: msg.sender,
            attestedAt: uint48(block.timestamp),
            evidenceHash: evidenceHash
        });
        grad.reportedTestCount = testCount;
        grad.reportedFuzzRuns = fuzzRuns;

        emit TestCoverageAttested(featureId, msg.sender, testCount, fuzzRuns);
    }

    /**
     * @notice Attest security review completion
     * @param featureId The feature being attested
     * @param reviewHash Hash of the security review document
     */
    function attestSecurityReview(
        bytes32 featureId,
        bytes32 reviewHash
    ) external onlyRole(SECURITY_ROLE) {
        FeatureGraduation storage grad = _graduations[featureId];

        grad.securityAttestation = Attestation({
            attester: msg.sender,
            attestedAt: uint48(block.timestamp),
            evidenceHash: reviewHash
        });

        emit SecurityReviewAttested(featureId, msg.sender, reviewHash);
    }

    /**
     * @notice Attest Certora formal verification spec
     * @param featureId The feature being attested
     * @param specHash Hash of the Certora spec file
     */
    function attestCertoraSpec(
        bytes32 featureId,
        bytes32 specHash
    ) external onlyRole(SECURITY_ROLE) {
        FeatureGraduation storage grad = _graduations[featureId];

        grad.certoraAttestation = Attestation({
            attester: msg.sender,
            attestedAt: uint48(block.timestamp),
            evidenceHash: specHash
        });

        emit CertoraSpecAttested(featureId, msg.sender, specHash);
    }

    /*//////////////////////////////////////////////////////////////
                    GRADUATION PROPOSAL & EXECUTION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Propose graduating a feature from BETA to PRODUCTION
     * @dev Validates all criteria are met before creating proposal.
     * @param featureId The feature to graduate
     * @return proposalId The new proposal ID
     */
    function proposeGraduation(
        bytes32 featureId
    ) external onlyRole(PROPOSER_ROLE) returns (uint256 proposalId) {
        // Must not have an active proposal
        if (activeProposal[featureId] != 0)
            revert ProposalAlreadyActive(featureId);

        // Feature must be in BETA
        _requireBetaStatus(featureId);

        // Criteria must be configured
        if (!criteriaConfigured[featureId]) revert CriteriaNotSet(featureId);

        // Validate all criteria are met
        _validateCriteria(featureId);

        // Create proposal
        proposalId = ++proposalCount;
        uint48 executableAfter = uint48(block.timestamp) + timelockDuration;

        proposals[proposalId] = GraduationProposal({
            featureId: featureId,
            status: ProposalStatus.PENDING,
            proposer: msg.sender,
            proposedAt: uint48(block.timestamp),
            executableAfter: executableAfter
        });

        activeProposal[featureId] = proposalId;

        emit GraduationProposed(featureId, proposalId, executableAfter);
    }

    /**
     * @notice Execute a graduation proposal after timelock expires
     * @param proposalId The proposal to execute
     */
    function executeGraduation(
        uint256 proposalId
    ) external onlyRole(EXECUTOR_ROLE) nonReentrant {
        GraduationProposal storage proposal = proposals[proposalId];
        if (proposal.status != ProposalStatus.PENDING)
            revert ProposalNotPending(proposalId);

        // Timelock must have expired
        if (block.timestamp < proposal.executableAfter) {
            revert TimelockNotExpired(proposal.executableAfter);
        }

        // Re-validate the feature is still in BETA
        _requireBetaStatus(proposal.featureId);

        // Execute: transition to PRODUCTION in the registry
        proposal.status = ProposalStatus.EXECUTED;
        activeProposal[proposal.featureId] = 0;

        FeatureGraduation storage grad = _graduations[proposal.featureId];
        grad.graduatedAt = uint48(block.timestamp);
        grad.graduationCount += 1;

        // Call the registry to update status
        registry.updateFeatureStatus(
            proposal.featureId,
            IExperimentalFeatureRegistry.FeatureStatus.PRODUCTION
        );

        emit GraduationExecuted(proposal.featureId, proposalId);
    }

    /**
     * @notice Cancel an active graduation proposal
     * @param proposalId The proposal to cancel
     * @param reason Reason for cancellation
     */
    function cancelGraduation(
        uint256 proposalId,
        string calldata reason
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        GraduationProposal storage proposal = proposals[proposalId];
        if (proposal.status != ProposalStatus.PENDING)
            revert ProposalNotPending(proposalId);

        proposal.status = ProposalStatus.CANCELLED;
        activeProposal[proposal.featureId] = 0;

        emit GraduationCancelled(proposal.featureId, proposalId, reason);
    }

    /*//////////////////////////////////////////////////////////////
                         DEMOTION PATH
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Demote a feature from PRODUCTION back to BETA
     * @param featureId The feature to demote
     * @param reason Reason for demotion
     */
    function demoteFeature(
        bytes32 featureId,
        string calldata reason
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        // Verify feature is in PRODUCTION
        (
            ,
            IExperimentalFeatureRegistry.FeatureStatus status,
            ,
            ,
            ,
            ,
            ,
            ,

        ) = registry.features(featureId);
        if (status != IExperimentalFeatureRegistry.FeatureStatus.PRODUCTION) {
            revert FeatureNotInProduction(featureId);
        }

        FeatureGraduation storage grad = _graduations[featureId];
        grad.demotedAt = uint48(block.timestamp);
        grad.demotionCount += 1;
        grad.demotionReason = reason;

        // Reset attestations (must re-attest after demotion)
        delete grad.auditAttestation;
        delete grad.testAttestation;
        delete grad.securityAttestation;
        delete grad.certoraAttestation;

        // Demote in registry (PRODUCTION → BETA is a valid transition)
        registry.updateFeatureStatus(
            featureId,
            IExperimentalFeatureRegistry.FeatureStatus.BETA
        );

        emit FeatureDemoted(featureId, reason);
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update the graduation timelock duration
     * @param newDuration New timelock in seconds
     */
    function setTimelockDuration(
        uint48 newDuration
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newDuration < MIN_TIMELOCK || newDuration > MAX_TIMELOCK) {
            revert InvalidTimelockDuration();
        }

        uint48 old = timelockDuration;
        timelockDuration = newDuration;
        emit TimelockUpdated(old, newDuration);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the full graduation state for a feature
        /**
     * @notice Returns the graduation
     * @param featureId The featureId identifier
     * @return The result value
     */
function getGraduation(
        bytes32 featureId
    ) external view returns (FeatureGraduation memory) {
        return _graduations[featureId];
    }

    /// @notice Check if a feature meets all graduation criteria
        /**
     * @notice Checks if graduation ready
     * @param featureId The featureId identifier
     * @return The result value
     */
function isGraduationReady(bytes32 featureId) external view returns (bool) {
        if (!criteriaConfigured[featureId]) return false;

        try this.checkCriteria(featureId) {
            return true;
        } catch {
            return false;
        }
    }

    /// @notice Get a breakdown of which criteria are met/unmet
        /**
     * @notice Returns the graduation progress
     * @param featureId The featureId identifier
     * @return timeMet The time met
     * @return testsMet The tests met
     * @return fuzzMet The fuzz met
     * @return auditMet The audit met
     * @return securityMet The security met
     * @return certoraMet The certora met
     */
function getGraduationProgress(
        bytes32 featureId
    )
        external
        view
        returns (
            bool timeMet,
            bool testsMet,
            bool fuzzMet,
            bool auditMet,
            bool securityMet,
            bool certoraMet
        )
    {
        GraduationCriteria storage crit = criteria[featureId];
        FeatureGraduation storage grad = _graduations[featureId];

        timeMet =
            grad.betaEntryTimestamp > 0 &&
            block.timestamp >= grad.betaEntryTimestamp + crit.minTimeInBeta;

        testsMet = grad.reportedTestCount >= crit.minTestCount;

        fuzzMet = grad.reportedFuzzRuns >= crit.minFuzzRuns;

        auditMet =
            !crit.requiresAuditAttestation ||
            grad.auditAttestation.attestedAt > 0;

        securityMet =
            !crit.requiresSecurityReview ||
            grad.securityAttestation.attestedAt > 0;

        certoraMet =
            !crit.requiresCertoraSpec ||
            grad.certoraAttestation.attestedAt > 0;
    }

    /**
     * @notice External wrapper for criteria validation (used by isGraduationReady)
     * @dev Reverts with CriteriaNotMet if any criterion fails
          * @param featureId The featureId identifier
     */
    function checkCriteria(bytes32 featureId) external view {
        _validateCriteria(featureId);
    }

    /*//////////////////////////////////////////////////////////////
                       INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _requireBetaStatus(bytes32 featureId) internal view {
        (
            ,
            IExperimentalFeatureRegistry.FeatureStatus status,
            ,
            ,
            ,
            ,
            ,
            ,

        ) = registry.features(featureId);
        if (status != IExperimentalFeatureRegistry.FeatureStatus.BETA) {
            revert FeatureNotInBeta(featureId);
        }
    }

    function _validateCriteria(bytes32 featureId) internal view {
        GraduationCriteria storage crit = criteria[featureId];
        FeatureGraduation storage grad = _graduations[featureId];

        // 1. Time-in-beta check
        if (crit.minTimeInBeta > 0) {
            if (grad.betaEntryTimestamp == 0) {
                revert CriteriaNotMet(featureId, "Beta entry not recorded");
            }
            if (
                block.timestamp < grad.betaEntryTimestamp + crit.minTimeInBeta
            ) {
                revert CriteriaNotMet(featureId, "Insufficient time in beta");
            }
        }

        // 2. Test count check
        if (
            crit.minTestCount > 0 && grad.reportedTestCount < crit.minTestCount
        ) {
            revert CriteriaNotMet(featureId, "Insufficient test count");
        }

        // 3. Fuzz runs check
        if (crit.minFuzzRuns > 0 && grad.reportedFuzzRuns < crit.minFuzzRuns) {
            revert CriteriaNotMet(featureId, "Insufficient fuzz runs");
        }

        // 4. Audit attestation check
        if (
            crit.requiresAuditAttestation &&
            grad.auditAttestation.attestedAt == 0
        ) {
            revert CriteriaNotMet(featureId, "Missing audit attestation");
        }

        // 5. Security review check
        if (
            crit.requiresSecurityReview &&
            grad.securityAttestation.attestedAt == 0
        ) {
            revert CriteriaNotMet(featureId, "Missing security review");
        }

        // 6. Certora spec check
        if (
            crit.requiresCertoraSpec && grad.certoraAttestation.attestedAt == 0
        ) {
            revert CriteriaNotMet(featureId, "Missing Certora spec");
        }
    }
}
