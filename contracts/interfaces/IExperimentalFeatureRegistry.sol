// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IExperimentalFeatureRegistry
 * @notice Interface for managing experimental features with risk limits and graduation paths
 */
interface IExperimentalFeatureRegistry {
    // =========================================================================
    // ENUMS
    // =========================================================================

    enum FeatureStatus {
        DISABLED,
        EXPERIMENTAL,
        BETA,
        PRODUCTION
    }

    // =========================================================================
    // STRUCTS
    // =========================================================================

    struct Feature {
        string name;
        FeatureStatus status;
        address implementation;
        uint256 maxValueLocked;
        uint256 currentValueLocked;
        bool requiresWarning;
        string documentationUrl;
        uint256 createdAt;
        uint256 lastStatusChange;
    }

    // =========================================================================
    // EVENTS
    // =========================================================================

    event FeatureRegistered(
        bytes32 indexed featureId,
        string name,
        FeatureStatus status
    );

    event FeatureStatusUpdated(
        bytes32 indexed featureId,
        FeatureStatus oldStatus,
        FeatureStatus newStatus
    );

    event FeatureValueLocked(
        bytes32 indexed featureId,
        uint256 amount,
        uint256 totalLocked
    );

    event FeatureValueUnlocked(
        bytes32 indexed featureId,
        uint256 amount,
        uint256 totalLocked
    );

    event RiskLimitUpdated(
        bytes32 indexed featureId,
        uint256 oldLimit,
        uint256 newLimit
    );

    event FeatureImplementationUpdated(
        bytes32 indexed featureId,
        address indexed oldImplementation,
        address indexed newImplementation
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error FeatureNotFound(bytes32 featureId);
    error FeatureDisabled(bytes32 featureId);
    error ExceedsRiskLimit(
        bytes32 featureId,
        uint256 requested,
        uint256 available
    );
    error InvalidStatusTransition(FeatureStatus from, FeatureStatus to);
    error FeatureAlreadyExists(bytes32 featureId);

    // =========================================================================
    // CORE FUNCTIONS
    // =========================================================================

    function isFeatureEnabled(
        bytes32 featureId
    ) external view returns (bool enabled);

    function requireFeatureEnabled(bytes32 featureId) external view;

    function requireProductionReady(bytes32 featureId) external view;

    function lockValue(bytes32 featureId, uint256 amount) external;

    function unlockValue(bytes32 featureId, uint256 amount) external;

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================

    function updateFeatureStatus(
        bytes32 featureId,
        FeatureStatus newStatus
    ) external;

    function emergencyDisable(bytes32 featureId) external;

    function updateFeatureImplementation(
        bytes32 featureId,
        address newImplementation
    ) external;

    function updateRiskLimit(bytes32 featureId, uint256 newLimit) external;

    function registerFeature(
        bytes32 featureId,
        string calldata name,
        FeatureStatus status,
        address implementation,
        uint256 maxValueLocked,
        bool requiresWarning,
        string calldata documentationUrl
    ) external;

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    function getFeature(
        bytes32 featureId
    ) external view returns (Feature memory feature);

    function getAllFeatureIds() external view returns (bytes32[] memory ids);

    function getRemainingCapacity(
        bytes32 featureId
    ) external view returns (uint256 remaining);
}
