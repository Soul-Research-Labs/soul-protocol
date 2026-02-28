// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IProofVerifier} from "../interfaces/IProofVerifier.sol";

/**
 * @title ComplianceReportingModule
 * @author ZASEON
 * @notice On-chain compliance reporting with ZK privacy preservation
 * @dev Generates verifiable compliance reports without revealing transaction details.
 *
 * DESIGN:
 *  - Reports are stored as encrypted blobs with public metadata (time range, entity)
 *  - ZK proofs attest that the report covers all transactions in a time window
 *  - Authorized auditors/regulators can be added as viewers for specific reports
 *  - Immutable audit trail tracks all report generations and accesses
 *
 * INTEGRATION:
 *  - Works alongside SelectiveDisclosureManager for field-level access
 *  - Uses IProofVerifier for compliance proof verification
 *  - Compatible with ZaseonComplianceV2 KYC tiers for access gating
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract ComplianceReportingModule is AccessControl, ReentrancyGuard {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant COMPLIANCE_OFFICER =
        keccak256("COMPLIANCE_OFFICER");
    bytes32 public constant REPORT_AUDITOR = keccak256("REPORT_AUDITOR");

    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Report type categories
    enum ReportType {
        TRANSACTION_SUMMARY, // Summary of transactions in a time window
        AML_CHECK, // Anti-money laundering check result
        KYC_VERIFICATION, // KYC compliance attestation
        SANCTIONS_SCREENING, // Sanctions list screening result
        REGULATORY_FILING, // Regulatory filing attestation
        CUSTOM // Custom compliance report
    }

    /// @notice Report lifecycle status
    enum ReportStatus {
        DRAFT, // Being generated
        SUBMITTED, // Submitted for review
        VERIFIED, // ZK proof verified
        EXPIRED, // Past retention period
        REVOKED // Invalidated
    }

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice A compliance report
    struct ComplianceReport {
        bytes32 reportId;
        address entity; // Entity the report covers
        ReportType reportType;
        ReportStatus status;
        uint48 periodStart; // Start of reporting period
        uint48 periodEnd; // End of reporting period
        uint48 createdAt;
        uint48 expiresAt; // When the report expires
        bytes32 reportHash; // Hash of encrypted report data
        bytes32 complianceProofHash; // Hash of the ZK compliance proof
        uint16 txCount; // Number of transactions covered
        uint16 viewerCount; // Number of authorized viewers
    }

    /// @notice Audit event for a report
    struct ReportAuditEntry {
        address accessor;
        uint48 accessedAt;
        bytes32 accessProof; // Optional ZK proof of authorized access
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice ZK proof verifier for compliance attestations
    IProofVerifier public complianceVerifier;

    /// @notice Report storage (reportId => report)
    mapping(bytes32 => ComplianceReport) public reports;

    /// @notice Authorized viewers per report (reportId => viewer => authorized)
    mapping(bytes32 => mapping(address => bool)) public reportViewers;

    /// @notice Audit trail per report (reportId => entries)
    mapping(bytes32 => ReportAuditEntry[]) internal _reportAuditTrail;

    /// @notice Entity report history (entity => reportIds)
    mapping(address => bytes32[]) public entityReports;

    /// @notice Report generation nonce per entity (for unique IDs)
    mapping(address => uint256) public reportNonce;

    /// @notice Default report retention period
    uint256 public defaultRetentionPeriod = 365 days;

    /// @notice Total reports generated
    uint256 public totalReports;

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 public constant MAX_VIEWERS_PER_REPORT = 20;
    uint256 public constant MAX_AUDIT_TRAIL_PER_REPORT = 200;
    uint256 public constant MAX_RETENTION_PERIOD = 3650 days; // 10 years
    uint256 public constant MIN_RETENTION_PERIOD = 30 days;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event ReportGenerated(
        bytes32 indexed reportId,
        address indexed entity,
        ReportType reportType,
        uint48 periodStart,
        uint48 periodEnd,
        uint16 txCount
    );
    event ReportVerified(bytes32 indexed reportId, bytes32 proofHash);
    event ReportViewerAdded(bytes32 indexed reportId, address indexed viewer);
    event ReportViewerRemoved(bytes32 indexed reportId, address indexed viewer);
    event ReportAccessed(bytes32 indexed reportId, address indexed accessor);
    event ReportRevoked(bytes32 indexed reportId, address indexed revoker);
    event ReportExpired(bytes32 indexed reportId);
    event ComplianceVerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier
    );
    event RetentionPeriodUpdated(uint256 oldPeriod, uint256 newPeriod);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error ReportNotFound();
    error ReportAlreadyExists();
    error ReportNotVerified();
    error ReportIsExpired();
    error ReportIsRevoked();
    error UnauthorizedAccess();
    error MaxViewersReached();
    error MaxAuditEntriesReached();
    error InvalidTimeRange();
    error RetentionOutOfRange();
    error ZeroAddress();
    error InvalidProof();
    error NoVerifierConfigured();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address admin, address _complianceVerifier) {
        if (admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(COMPLIANCE_OFFICER, admin);

        if (_complianceVerifier != address(0)) {
            complianceVerifier = IProofVerifier(_complianceVerifier);
        }
    }

    /*//////////////////////////////////////////////////////////////
                       REPORT GENERATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Generate a new compliance report
     * @param entity Address the report covers
     * @param reportType Type of compliance report
     * @param periodStart Start of the reporting period
     * @param periodEnd End of the reporting period
     * @param reportHash Hash of the encrypted report data (stored off-chain)
     * @param txCount Number of transactions covered in this report
     * @param viewers Initial list of authorized viewers
     * @return reportId Unique report identifier
     */
    function generateReport(
        address entity,
        ReportType reportType,
        uint48 periodStart,
        uint48 periodEnd,
        bytes32 reportHash,
        uint16 txCount,
        address[] calldata viewers
    )
        external
        nonReentrant
        onlyRole(COMPLIANCE_OFFICER)
        returns (bytes32 reportId)
    {
        if (entity == address(0)) revert ZeroAddress();
        if (periodStart >= periodEnd) revert InvalidTimeRange();
        if (periodEnd > block.timestamp) revert InvalidTimeRange();
        if (viewers.length > MAX_VIEWERS_PER_REPORT) revert MaxViewersReached();

        // Generate unique report ID
        reportId = keccak256(
            abi.encodePacked(
                entity,
                reportType,
                periodStart,
                periodEnd,
                reportNonce[entity]++
            )
        );

        if (reports[reportId].createdAt != 0) revert ReportAlreadyExists();

        uint48 expiresAt = uint48(block.timestamp + defaultRetentionPeriod);

        reports[reportId] = ComplianceReport({
            reportId: reportId,
            entity: entity,
            reportType: reportType,
            status: ReportStatus.DRAFT,
            periodStart: periodStart,
            periodEnd: periodEnd,
            createdAt: uint48(block.timestamp),
            expiresAt: expiresAt,
            reportHash: reportHash,
            complianceProofHash: bytes32(0),
            txCount: txCount,
            viewerCount: uint16(viewers.length)
        });

        // Authorize viewers
        for (uint256 i; i < viewers.length; ) {
            if (viewers[i] != address(0)) {
                reportViewers[reportId][viewers[i]] = true;
                emit ReportViewerAdded(reportId, viewers[i]);
            }
            unchecked {
                ++i;
            }
        }

        entityReports[entity].push(reportId);
        unchecked {
            ++totalReports;
        }

        emit ReportGenerated(
            reportId,
            entity,
            reportType,
            periodStart,
            periodEnd,
            txCount
        );
    }

    /**
     * @notice Submit a ZK proof that the report is accurate and compliant
     * @param reportId Report to verify
     * @param proof ZK proof bytes
     * @param publicInputs Public inputs (includes reportHash, entity, time range)
     */
    function verifyReport(
        bytes32 reportId,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external nonReentrant onlyRole(COMPLIANCE_OFFICER) {
        ComplianceReport storage report = reports[reportId];
        if (report.createdAt == 0) revert ReportNotFound();
        if (report.status == ReportStatus.REVOKED) revert ReportIsRevoked();
        if (address(complianceVerifier) == address(0))
            revert NoVerifierConfigured();

        bool valid = complianceVerifier.verifyProof(proof, publicInputs);
        if (!valid) revert InvalidProof();

        report.status = ReportStatus.VERIFIED;
        report.complianceProofHash = keccak256(
            abi.encodePacked(proof, publicInputs)
        );

        emit ReportVerified(reportId, report.complianceProofHash);
    }

    /**
     * @notice Submit a report (move from DRAFT to SUBMITTED without ZK proof)
     * @dev Used when ZK verification is not required or will be done later
     * @param reportId Report to submit
     */
    function submitReport(
        bytes32 reportId
    ) external nonReentrant onlyRole(COMPLIANCE_OFFICER) {
        ComplianceReport storage report = reports[reportId];
        if (report.createdAt == 0) revert ReportNotFound();
        if (report.status != ReportStatus.DRAFT) revert ReportNotFound(); // must be draft

        report.status = ReportStatus.SUBMITTED;
    }

    /*//////////////////////////////////////////////////////////////
                       REPORT ACCESS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Record access to a report (audit trail)
     * @param reportId Report being accessed
     * @param accessProof Optional ZK proof of authorized access
     */
    function recordReportAccess(
        bytes32 reportId,
        bytes32 accessProof
    ) external nonReentrant {
        ComplianceReport storage report = reports[reportId];
        if (report.createdAt == 0) revert ReportNotFound();
        if (report.status == ReportStatus.REVOKED) revert ReportIsRevoked();
        if (report.expiresAt != 0 && block.timestamp >= report.expiresAt)
            revert ReportIsExpired();

        // Check viewer authorization
        if (
            !reportViewers[reportId][msg.sender] &&
            !hasRole(REPORT_AUDITOR, msg.sender)
        ) {
            revert UnauthorizedAccess();
        }

        // Append to bounded audit trail
        ReportAuditEntry[] storage trail = _reportAuditTrail[reportId];
        if (trail.length >= MAX_AUDIT_TRAIL_PER_REPORT)
            revert MaxAuditEntriesReached();

        trail.push(
            ReportAuditEntry({
                accessor: msg.sender,
                accessedAt: uint48(block.timestamp),
                accessProof: accessProof
            })
        );

        emit ReportAccessed(reportId, msg.sender);
    }

    /**
     * @notice Add a viewer to a report
     * @param reportId Report to add viewer to
     * @param viewer Address to authorize
     */
    function addReportViewer(
        bytes32 reportId,
        address viewer
    ) external nonReentrant onlyRole(COMPLIANCE_OFFICER) {
        ComplianceReport storage report = reports[reportId];
        if (report.createdAt == 0) revert ReportNotFound();
        if (viewer == address(0)) revert ZeroAddress();
        if (report.viewerCount >= MAX_VIEWERS_PER_REPORT)
            revert MaxViewersReached();

        if (!reportViewers[reportId][viewer]) {
            reportViewers[reportId][viewer] = true;
            unchecked {
                ++report.viewerCount;
            }
            emit ReportViewerAdded(reportId, viewer);
        }
    }

    /**
     * @notice Remove a viewer from a report
     * @param reportId Report to remove viewer from
     * @param viewer Address to deauthorize
     */
    function removeReportViewer(
        bytes32 reportId,
        address viewer
    ) external nonReentrant onlyRole(COMPLIANCE_OFFICER) {
        ComplianceReport storage report = reports[reportId];
        if (report.createdAt == 0) revert ReportNotFound();

        if (reportViewers[reportId][viewer]) {
            reportViewers[reportId][viewer] = false;
            unchecked {
                --report.viewerCount;
            }
            emit ReportViewerRemoved(reportId, viewer);
        }
    }

    /**
     * @notice Revoke a report
     * @param reportId Report to revoke
     */
    function revokeReport(
        bytes32 reportId
    ) external nonReentrant onlyRole(COMPLIANCE_OFFICER) {
        ComplianceReport storage report = reports[reportId];
        if (report.createdAt == 0) revert ReportNotFound();

        report.status = ReportStatus.REVOKED;
        emit ReportRevoked(reportId, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get a report's details
        /**
     * @notice Returns the report
     * @param reportId The reportId identifier
     * @return The result value
     */
function getReport(
        bytes32 reportId
    ) external view returns (ComplianceReport memory) {
        return reports[reportId];
    }

    /// @notice Check if a viewer can access a report
        /**
     * @notice Can access report
     * @param reportId The reportId identifier
     * @param viewer The viewer
     * @return The result value
     */
function canAccessReport(
        bytes32 reportId,
        address viewer
    ) external view returns (bool) {
        ComplianceReport storage report = reports[reportId];
        if (report.createdAt == 0) return false;
        if (report.status == ReportStatus.REVOKED) return false;
        if (report.expiresAt != 0 && block.timestamp >= report.expiresAt)
            return false;
        return
            reportViewers[reportId][viewer] || hasRole(REPORT_AUDITOR, viewer);
    }

    /// @notice Get all report IDs for an entity
        /**
     * @notice Returns the entity reports
     * @param entity The entity
     * @return The result value
     */
function getEntityReports(
        address entity
    ) external view returns (bytes32[] memory) {
        return entityReports[entity];
    }

    /// @notice Get the audit trail for a report
        /**
     * @notice Returns the report audit trail
     * @param reportId The reportId identifier
     * @return The result value
     */
function getReportAuditTrail(
        bytes32 reportId
    ) external view returns (ReportAuditEntry[] memory) {
        return _reportAuditTrail[reportId];
    }

    /// @notice Check if a report has been ZK-verified
        /**
     * @notice Checks if report verified
     * @param reportId The reportId identifier
     * @return The result value
     */
function isReportVerified(bytes32 reportId) external view returns (bool) {
        return reports[reportId].status == ReportStatus.VERIFIED;
    }

    /// @notice Check if a report is expired
        /**
     * @notice Checks if report expired
     * @param reportId The reportId identifier
     * @return The result value
     */
function isReportExpired(bytes32 reportId) external view returns (bool) {
        ComplianceReport storage report = reports[reportId];
        return report.expiresAt != 0 && block.timestamp >= report.expiresAt;
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Update the compliance proof verifier
        /**
     * @notice Sets the compliance verifier
     * @param newVerifier The new Verifier value
     */
function setComplianceVerifier(
        address newVerifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        address old = address(complianceVerifier);
        complianceVerifier = IProofVerifier(newVerifier);
        emit ComplianceVerifierUpdated(old, newVerifier);
    }

    /// @notice Update the default retention period
        /**
     * @notice Sets the default retention period
     * @param period The period
     */
function setDefaultRetentionPeriod(
        uint256 period
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (period < MIN_RETENTION_PERIOD || period > MAX_RETENTION_PERIOD)
            revert RetentionOutOfRange();
        uint256 old = defaultRetentionPeriod;
        defaultRetentionPeriod = period;
        emit RetentionPeriodUpdated(old, period);
    }

    /// @notice Grant REPORT_AUDITOR role
        /**
     * @notice Authorize auditor
     * @param auditor The auditor
     */
function authorizeAuditor(
        address auditor
    ) external onlyRole(COMPLIANCE_OFFICER) {
        if (auditor == address(0)) revert ZeroAddress();
        _grantRole(REPORT_AUDITOR, auditor);
    }

    /// @notice Revoke REPORT_AUDITOR role
        /**
     * @notice Revokes auditor
     * @param auditor The auditor
     */
function revokeAuditor(
        address auditor
    ) external onlyRole(COMPLIANCE_OFFICER) {
        _revokeRole(REPORT_AUDITOR, auditor);
    }
}
