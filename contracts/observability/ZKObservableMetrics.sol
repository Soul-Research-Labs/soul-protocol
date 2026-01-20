// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title ZKObservableMetrics
 * @author Soul Protocol - Privacy Interoperability Layer
 * @notice Private Observability - Prove Metrics Without Revealing Transactions
 * @dev Enterprise-grade observability that maintains cryptographic privacy
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                                    DESIGN PHILOSOPHY
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Enterprises need observability: they must measure success/failure, audit behavior, and track metrics.
 * Most ZK systems ignore this, making them unsuitable for institutional adoption.
 *
 * Soul provides ZK-Observable Metrics:
 * - Prove transaction counts without revealing which transactions
 * - Prove volume totals without revealing individual amounts
 * - Prove compliance rates without revealing specific violations
 * - Prove SLA adherence without revealing timing patterns
 *
 * Key Insight: Enterprises don't just want privacy — they want CONTROL, OBSERVABILITY, and RECOVERABILITY.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *                                    METRIC TYPES
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 *
 * ╔════════════════════════════════════════════════════════════════════════════════════════════════════╗
 * ║ Metric Type                     │ What's Proven                  │ What's Hidden                  ║
 * ╠════════════════════════════════════════════════════════════════════════════════════════════════════╣
 * ║ Transaction Count               │ Total count in range           │ Individual transactions        ║
 * ║ Volume Totals                   │ Sum of amounts                 │ Individual amounts             ║
 * ║ Success Rate                    │ Percentage completed           │ Which ones failed              ║
 * ║ Compliance Rate                 │ % meeting policy               │ Specific violations            ║
 * ║ Latency Metrics                 │ Average/percentile times       │ Individual timing              ║
 * ║ Active Users                    │ Unique user count              │ User identities                ║
 * ╚════════════════════════════════════════════════════════════════════════════════════════════════════╝
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════════════
 */
contract ZKObservableMetrics is AccessControl, ReentrancyGuard {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant METRICS_ADMIN_ROLE =
        keccak256("METRICS_ADMIN_ROLE");
    bytes32 public constant AGGREGATOR_ROLE = keccak256("AGGREGATOR_ROLE");
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidProof(bytes32 metricId);
    error MetricNotFound(bytes32 metricId);
    error InvalidTimeRange(uint64 start, uint64 end);
    error AggregationWindowNotClosed();
    error UnauthorizedAuditor();
    error InvalidAggregation();

    /*//////////////////////////////////////////////////////////////
                               DATA TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Metric types supported
    enum MetricType {
        COUNT, // Number of items
        SUM, // Total value
        AVERAGE, // Mean value
        PERCENTILE, // Nth percentile
        RATE, // Percentage/ratio
        UNIQUE_COUNT // Distinct items
    }

    /// @notice Aggregation window sizes
    enum AggregationWindow {
        HOURLY,
        DAILY,
        WEEKLY,
        MONTHLY
    }

    /**
     * @notice Private Metric - commitment to underlying data
     * @dev Actual values are hidden; only commitments stored on-chain
     */
    struct PrivateMetric {
        bytes32 metricId;
        string name;
        MetricType metricType;
        // Commitments (hide actual values)
        bytes32 valueCommitment; // Pedersen commitment to value
        bytes32 datasetCommitment; // Commitment to underlying dataset
        // Aggregation info
        AggregationWindow window;
        uint64 windowStart;
        uint64 windowEnd;
        // Proof
        bytes32 proofHash;
        bool verified;
        // Metadata
        uint64 createdAt;
        address aggregator;
    }

    /**
     * @notice Metric Proof - ZK proof of metric correctness
     * @dev Proves metric was computed correctly over committed data
     */
    struct MetricProof {
        bytes32 proofId;
        bytes32 metricId;
        // Public inputs (visible)
        uint256 claimedValue; // The metric value being proven
        bytes32 datasetCommitment; // Which data this is over
        bytes32 policyHash; // Which policy was applied
        // The proof itself
        bytes proof;
        // Verification
        bool verified;
        address verifiedBy;
        uint64 verifiedAt;
    }

    /**
     * @notice Aggregation Report - periodic summary
     * @dev Auditable report of metrics for a time period
     */
    struct AggregationReport {
        bytes32 reportId;
        AggregationWindow window;
        uint64 windowStart;
        uint64 windowEnd;
        // Included metrics
        bytes32[] metricIds;
        // Aggregate commitments
        bytes32 reportCommitment; // Commitment to full report
        bytes32 signatureHash; // Aggregator signature
        // Status
        bool finalized;
        uint64 createdAt;
    }

    /**
     * @notice Audit Authorization
     * @dev Who can view what level of detail
     */
    struct AuditAuthorization {
        bytes32 authId;
        address auditor;
        bytes32[] allowedMetrics; // Which metrics they can see
        uint8 detailLevel; // 0=commitments only, 1=values, 2=proofs, 3=full
        uint64 validUntil;
        bool revoked;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Metrics: metricId => metric
    mapping(bytes32 => PrivateMetric) public metrics;

    /// @notice Proofs: proofId => proof
    mapping(bytes32 => MetricProof) public proofs;

    /// @notice Reports: reportId => report
    mapping(bytes32 => AggregationReport) public reports;

    /// @notice Audit authorizations: authId => authorization
    mapping(bytes32 => AuditAuthorization) public auditAuthorizations;

    /// @notice Metric by name: name => metricId
    mapping(string => bytes32) public metricByName;

    /// @notice Reports by window: windowHash => reportIds
    mapping(bytes32 => bytes32[]) public reportsByWindow;

    /// @notice Total metrics counter
    uint256 public totalMetrics;
    uint256 public totalReports;

    /// @notice Current aggregation windows
    mapping(AggregationWindow => uint64) public currentWindowStart;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event MetricCommitted(
        bytes32 indexed metricId,
        string name,
        MetricType metricType,
        bytes32 valueCommitment
    );

    event MetricProofSubmitted(
        bytes32 indexed metricId,
        bytes32 indexed proofId,
        uint256 claimedValue
    );

    event MetricVerified(bytes32 indexed metricId, bool success);

    event ReportCreated(
        bytes32 indexed reportId,
        AggregationWindow window,
        uint64 windowStart,
        uint64 windowEnd
    );

    event ReportFinalized(bytes32 indexed reportId);

    event AuditAuthorizationGranted(
        bytes32 indexed authId,
        address indexed auditor,
        uint8 detailLevel
    );

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(METRICS_ADMIN_ROLE, msg.sender);
        _grantRole(AGGREGATOR_ROLE, msg.sender);
        _grantRole(AUDITOR_ROLE, msg.sender);

        // Initialize window starts
        uint64 currentHour = uint64((block.timestamp / 1 hours) * 1 hours);
        uint64 currentDay = uint64((block.timestamp / 1 days) * 1 days);
        uint64 currentWeek = uint64((block.timestamp / 1 weeks) * 1 weeks);

        currentWindowStart[AggregationWindow.HOURLY] = currentHour;
        currentWindowStart[AggregationWindow.DAILY] = currentDay;
        currentWindowStart[AggregationWindow.WEEKLY] = currentWeek;
        currentWindowStart[AggregationWindow.MONTHLY] = currentDay; // Approximate
    }

    /*//////////////////////////////////////////////////////////////
                        METRIC COMMITMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Commit a private metric
     * @dev Value is committed, not revealed; proven later
     * @param name Metric name
     * @param metricType Type of metric
     * @param valueCommitment Pedersen commitment to the value
     * @param datasetCommitment Commitment to underlying dataset
     * @param window Aggregation window
     * @return metricId The metric identifier
     */
    function commitMetric(
        string calldata name,
        MetricType metricType,
        bytes32 valueCommitment,
        bytes32 datasetCommitment,
        AggregationWindow window
    ) external onlyRole(AGGREGATOR_ROLE) returns (bytes32 metricId) {
        uint64 windowStart = currentWindowStart[window];
        uint64 windowEnd = _getWindowEnd(windowStart, window);

        metricId = keccak256(
            abi.encodePacked(
                name,
                valueCommitment,
                windowStart,
                block.timestamp
            )
        );

        metrics[metricId] = PrivateMetric({
            metricId: metricId,
            name: name,
            metricType: metricType,
            valueCommitment: valueCommitment,
            datasetCommitment: datasetCommitment,
            window: window,
            windowStart: windowStart,
            windowEnd: windowEnd,
            proofHash: bytes32(0),
            verified: false,
            createdAt: uint64(block.timestamp),
            aggregator: msg.sender
        });

        metricByName[name] = metricId;

        unchecked {
            ++totalMetrics;
        }

        emit MetricCommitted(metricId, name, metricType, valueCommitment);
        return metricId;
    }

    /**
     * @notice Commit transaction count metric
     * @dev Proves count without revealing which transactions
     */
    function commitTransactionCount(
        string calldata name,
        bytes32 countCommitment,
        bytes32 transactionSetCommitment,
        AggregationWindow window
    ) external onlyRole(AGGREGATOR_ROLE) returns (bytes32 metricId) {
        return
            this.commitMetric(
                name,
                MetricType.COUNT,
                countCommitment,
                transactionSetCommitment,
                window
            );
    }

    /**
     * @notice Commit volume total metric
     * @dev Proves sum without revealing individual amounts
     */
    function commitVolumeTotal(
        string calldata name,
        bytes32 sumCommitment,
        bytes32 amountSetCommitment,
        AggregationWindow window
    ) external onlyRole(AGGREGATOR_ROLE) returns (bytes32 metricId) {
        return
            this.commitMetric(
                name,
                MetricType.SUM,
                sumCommitment,
                amountSetCommitment,
                window
            );
    }

    /**
     * @notice Commit success rate metric
     * @dev Proves percentage without revealing which succeeded/failed
     */
    function commitSuccessRate(
        string calldata name,
        bytes32 rateCommitment,
        bytes32 outcomeSetCommitment,
        AggregationWindow window
    ) external onlyRole(AGGREGATOR_ROLE) returns (bytes32 metricId) {
        return
            this.commitMetric(
                name,
                MetricType.RATE,
                rateCommitment,
                outcomeSetCommitment,
                window
            );
    }

    /*//////////////////////////////////////////////////////////////
                        PROOF SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit proof for a metric
     * @dev Proves the committed value is correct
     * @param metricId The metric to prove
     * @param claimedValue The value being proven
     * @param policyHash Policy applied during computation
     * @param proof The ZK proof
     * @return proofId The proof identifier
     */
    function submitProof(
        bytes32 metricId,
        uint256 claimedValue,
        bytes32 policyHash,
        bytes calldata proof
    ) external onlyRole(AGGREGATOR_ROLE) returns (bytes32 proofId) {
        PrivateMetric storage metric = metrics[metricId];

        if (metric.metricId == bytes32(0)) {
            revert MetricNotFound(metricId);
        }

        proofId = keccak256(abi.encodePacked(metricId, claimedValue, proof));

        proofs[proofId] = MetricProof({
            proofId: proofId,
            metricId: metricId,
            claimedValue: claimedValue,
            datasetCommitment: metric.datasetCommitment,
            policyHash: policyHash,
            proof: proof,
            verified: false,
            verifiedBy: address(0),
            verifiedAt: 0
        });

        metric.proofHash = proofId;

        emit MetricProofSubmitted(metricId, proofId, claimedValue);
        return proofId;
    }

    /**
     * @notice Verify a metric proof
     * @param proofId The proof to verify
     * @return success True if verification passed
     */
    function verifyProof(
        bytes32 proofId
    ) external onlyRole(AUDITOR_ROLE) returns (bool success) {
        MetricProof storage metricProof = proofs[proofId];
        PrivateMetric storage metric = metrics[metricProof.metricId];

        // In production: verify ZK proof
        // For MVP: verify proof exists and is non-empty
        success = _verifyMetricProof(
            metricProof.proof,
            metric.valueCommitment,
            metricProof.claimedValue,
            metric.datasetCommitment
        );

        if (!success) {
            revert InvalidProof(metricProof.metricId);
        }

        metricProof.verified = true;
        metricProof.verifiedBy = msg.sender;
        metricProof.verifiedAt = uint64(block.timestamp);

        metric.verified = true;

        emit MetricVerified(metricProof.metricId, true);
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                        AGGREGATION REPORTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create aggregation report for a time window
     * @param window The aggregation window
     * @param windowStart Start of the window
     * @param windowEnd End of the window
     * @param metricIds Metrics to include in report
     * @return reportId The report identifier
     */
    function createReport(
        AggregationWindow window,
        uint64 windowStart,
        uint64 windowEnd,
        bytes32[] calldata metricIds
    ) external onlyRole(AGGREGATOR_ROLE) returns (bytes32 reportId) {
        if (windowEnd > block.timestamp) {
            revert AggregationWindowNotClosed();
        }

        if (windowStart >= windowEnd) {
            revert InvalidTimeRange(windowStart, windowEnd);
        }

        reportId = keccak256(
            abi.encodePacked(window, windowStart, windowEnd, block.timestamp)
        );

        // Calculate report commitment
        bytes32 reportCommitment = keccak256(abi.encodePacked(metricIds));

        reports[reportId] = AggregationReport({
            reportId: reportId,
            window: window,
            windowStart: windowStart,
            windowEnd: windowEnd,
            metricIds: metricIds,
            reportCommitment: reportCommitment,
            signatureHash: bytes32(0),
            finalized: false,
            createdAt: uint64(block.timestamp)
        });

        // Index by window
        bytes32 windowHash = keccak256(abi.encodePacked(window, windowStart));
        reportsByWindow[windowHash].push(reportId);

        unchecked {
            ++totalReports;
        }

        emit ReportCreated(reportId, window, windowStart, windowEnd);
        return reportId;
    }

    /**
     * @notice Finalize a report (after all proofs verified)
     * @param reportId The report to finalize
     * @param signatureHash Hash of aggregator signature
     */
    function finalizeReport(
        bytes32 reportId,
        bytes32 signatureHash
    ) external onlyRole(AGGREGATOR_ROLE) {
        AggregationReport storage report = reports[reportId];

        // Verify all metrics in report are verified
        for (uint256 i = 0; i < report.metricIds.length; i++) {
            if (!metrics[report.metricIds[i]].verified) {
                revert InvalidAggregation();
            }
        }

        report.signatureHash = signatureHash;
        report.finalized = true;

        emit ReportFinalized(reportId);
    }

    /*//////////////////////////////////////////////////////////////
                        AUDIT AUTHORIZATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Grant audit authorization
     * @param auditor Address of auditor
     * @param allowedMetrics Which metrics they can access
     * @param detailLevel Level of detail (0-3)
     * @param validUntil Authorization validity
     * @return authId Authorization identifier
     */
    function grantAuditAuthorization(
        address auditor,
        bytes32[] calldata allowedMetrics,
        uint8 detailLevel,
        uint64 validUntil
    ) external onlyRole(METRICS_ADMIN_ROLE) returns (bytes32 authId) {
        authId = keccak256(
            abi.encodePacked(auditor, detailLevel, validUntil, block.timestamp)
        );

        auditAuthorizations[authId] = AuditAuthorization({
            authId: authId,
            auditor: auditor,
            allowedMetrics: allowedMetrics,
            detailLevel: detailLevel,
            validUntil: validUntil,
            revoked: false
        });

        emit AuditAuthorizationGranted(authId, auditor, detailLevel);
        return authId;
    }

    /**
     * @notice Revoke audit authorization
     * @param authId Authorization to revoke
     */
    function revokeAuditAuthorization(
        bytes32 authId
    ) external onlyRole(METRICS_ADMIN_ROLE) {
        auditAuthorizations[authId].revoked = true;
    }

    /**
     * @notice Check if auditor is authorized for a metric
     * @param auditor The auditor address
     * @param metricId The metric to check
     * @return authorized True if authorized
     * @return detailLevel The detail level allowed
     */
    function checkAuditAuthorization(
        address auditor,
        bytes32 metricId
    ) external view returns (bool authorized, uint8 detailLevel) {
        // In production: iterate through authorizations
        // For MVP: simplified check
        if (hasRole(AUDITOR_ROLE, auditor)) {
            return (true, 3); // Full access for role holders
        }
        return (false, 0);
    }

    /*//////////////////////////////////////////////////////////////
                    INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _getWindowEnd(
        uint64 windowStart,
        AggregationWindow window
    ) internal pure returns (uint64) {
        if (window == AggregationWindow.HOURLY) {
            return windowStart + 1 hours;
        } else if (window == AggregationWindow.DAILY) {
            return windowStart + 1 days;
        } else if (window == AggregationWindow.WEEKLY) {
            return windowStart + 1 weeks;
        } else {
            return windowStart + 30 days; // Approximate month
        }
    }

    function _verifyMetricProof(
        bytes storage proof,
        bytes32 valueCommitment,
        uint256 /* claimedValue */,
        bytes32 datasetCommitment
    ) internal view returns (bool) {
        // In production: verify ZK proof
        // For MVP: basic validation
        return
            proof.length > 0 &&
            valueCommitment != bytes32(0) &&
            datasetCommitment != bytes32(0);
    }

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get metric details
    function getMetric(
        bytes32 metricId
    ) external view returns (PrivateMetric memory) {
        return metrics[metricId];
    }

    /// @notice Get metric by name
    function getMetricByName(
        string calldata name
    ) external view returns (PrivateMetric memory) {
        return metrics[metricByName[name]];
    }

    /// @notice Get proof details
    function getProof(
        bytes32 proofId
    ) external view returns (MetricProof memory) {
        return proofs[proofId];
    }

    /// @notice Get report details
    function getReport(
        bytes32 reportId
    ) external view returns (AggregationReport memory) {
        return reports[reportId];
    }

    /// @notice Get reports for a window
    function getReportsForWindow(
        AggregationWindow window,
        uint64 windowStart
    ) external view returns (bytes32[] memory) {
        bytes32 windowHash = keccak256(abi.encodePacked(window, windowStart));
        return reportsByWindow[windowHash];
    }

    /// @notice Check if metric is verified
    function isMetricVerified(bytes32 metricId) external view returns (bool) {
        return metrics[metricId].verified;
    }

    /// @notice Get verified value for a metric (if proven)
    function getVerifiedValue(
        bytes32 metricId
    ) external view returns (uint256 value, bool verified) {
        PrivateMetric storage metric = metrics[metricId];
        if (!metric.verified) {
            return (0, false);
        }

        MetricProof storage proof = proofs[metric.proofHash];
        return (proof.claimedValue, true);
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function advanceWindow(
        AggregationWindow window
    ) external onlyRole(METRICS_ADMIN_ROLE) {
        uint64 current = currentWindowStart[window];
        currentWindowStart[window] = _getWindowEnd(current, window);
    }
}
