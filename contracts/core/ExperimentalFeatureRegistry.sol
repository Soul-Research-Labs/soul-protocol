// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title ExperimentalFeatureRegistry
 * @notice Manages the status and risk limits of experimental features.
 * @dev Used to gate access to non-production features (FHE, PQC, etc.)
 * @custom:deprecated Use contracts/security/ExperimentalFeatureRegistry.sol instead.
 *         This version lacks: emergency disable, TVL tracking, status transition
 *         validation, custom errors, and timestamps. Kept for backward compatibility only.
 */
contract ExperimentalFeatureRegistry is AccessControl {
    bytes32 public constant FEATURE_ADMIN = keccak256("FEATURE_ADMIN");

    enum FeatureStatus {
        DISABLED,
        EXPERIMENTAL, // Testnet or very limited mainnet
        BETA, // Limited mainnet (risk limits)
        PRODUCTION // Full access
    }

    struct Feature {
        string name;
        FeatureStatus status;
        address implementation;
        uint256 maxValueLocked; // Risk limit (e.g., 10 ETH)
        bool requiresWarning;
        string documentationUrl;
    }

    mapping(bytes32 => Feature) public features;

    // Standard feature identifiers
    bytes32 public constant FHE_OPERATIONS = keccak256("FHE_OPERATIONS");
    bytes32 public constant PQC_SIGNATURES = keccak256("PQC_SIGNATURES");
    bytes32 public constant MPC_THRESHOLD = keccak256("MPC_THRESHOLD");
    bytes32 public constant SERAPHIM_PRIVACY = keccak256("SERAPHIM_PRIVACY");

    event FeatureStatusUpdated(bytes32 indexed featureId, FeatureStatus status);
    event FeatureRegistered(bytes32 indexed featureId, string name);
    event RiskLimitUpdated(bytes32 indexed featureId, uint256 newLimit);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(FEATURE_ADMIN, admin);

        // Initialize experimental features as DISABLED by default for safety
        _registerFeature(
            FHE_OPERATIONS,
            "FHE Operations",
            FeatureStatus.DISABLED,
            address(0),
            1 ether,
            true,
            "https://docs.soul.xyz/experimental/fhe"
        );

        _registerFeature(
            PQC_SIGNATURES,
            "Post-Quantum Signatures",
            FeatureStatus.DISABLED,
            address(0),
            0.1 ether,
            true,
            "https://docs.soul.xyz/experimental/pqc"
        );
    }

    /**
     * @notice Register or update a feature's static metadata.
     */
    function _registerFeature(
        bytes32 featureId,
        string memory name,
        FeatureStatus status,
        address implementation,
        uint256 maxValueLocked,
        bool requiresWarning,
        string memory documentationUrl
    ) internal {
        features[featureId] = Feature({
            name: name,
            status: status,
            implementation: implementation,
            maxValueLocked: maxValueLocked,
            requiresWarning: requiresWarning,
            documentationUrl: documentationUrl
        });
        emit FeatureRegistered(featureId, name);
        emit FeatureStatusUpdated(featureId, status);
    }

    /**
     * @notice Register a new feature (Admin only).
     */
    function registerFeature(
        bytes32 featureId,
        string calldata name,
        FeatureStatus status,
        address implementation,
        uint256 maxValueLocked,
        bool requiresWarning,
        string calldata documentationUrl
    ) external onlyRole(FEATURE_ADMIN) {
        _registerFeature(
            featureId,
            name,
            status,
            implementation,
            maxValueLocked,
            requiresWarning,
            documentationUrl
        );
    }

    /**
     * @notice Update the status of a feature.
     */
    function updateFeatureStatus(
        bytes32 featureId,
        FeatureStatus newStatus
    ) external onlyRole(FEATURE_ADMIN) {
        features[featureId].status = newStatus;
        emit FeatureStatusUpdated(featureId, newStatus);
    }

    /**
     * @notice Update the risk limit (max value locked) for a feature.
     */
    function updateRiskLimit(
        bytes32 featureId,
        uint256 newLimit
    ) external onlyRole(FEATURE_ADMIN) {
        features[featureId].maxValueLocked = newLimit;
        emit RiskLimitUpdated(featureId, newLimit);
    }

    /**
     * @notice Check if a feature is enabled (not DISABLED).
     */
    function isFeatureEnabled(bytes32 featureId) external view returns (bool) {
        return features[featureId].status != FeatureStatus.DISABLED;
    }

    /**
     * @notice Revert if feature is disabled.
     */
    function requireFeatureEnabled(bytes32 featureId) external view {
        require(
            features[featureId].status != FeatureStatus.DISABLED,
            "Feature is disabled"
        );
    }

    /**
     * @notice Revert if feature is not production ready.
     */
    function requireProductionReady(bytes32 featureId) external view {
        require(
            features[featureId].status == FeatureStatus.PRODUCTION,
            "Feature not production-ready"
        );
    }

    /**
     * @notice Get feature details.
     */
    function getFeature(
        bytes32 featureId
    ) external view returns (Feature memory) {
        return features[featureId];
    }
}
